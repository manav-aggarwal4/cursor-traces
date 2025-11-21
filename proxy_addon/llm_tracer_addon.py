"""
mitmproxy addon to capture and log LLM API calls.
Intercepts HTTP(S) traffic and filters for LLM-related requests.
"""
import json
import re
import time
import uuid
from mitmproxy import http

# Known LLM API hosts - filter only by host to avoid false positives
LLM_HOSTS = {
    "api.openai.com",
    "api.anthropic.com",
    "api.x.ai",
    "api.cursor.sh",
    "api2.cursor.sh",  # Cursor's gRPC API endpoint
    "api.groq.com",
    "api.mistral.ai",
    "api.fireworks.ai",
    "127.0.0.1",       # Local Ollama (Layer 2)
    "localhost",       # Local Ollama alternative
}

# ngrok hostnames (will be added dynamically, but include common patterns)
# ngrok URLs look like: https://xxxx-xx-xx-xx-xx.ngrok-free.app
# We'll match any host ending in .ngrok.io or .ngrok-free.app

# Max body text size to store (1-2 KB as specified)
MAX_BODY_TEXT_SIZE = 2048

# For SSE streams, we'll capture the full stream
MAX_SSE_STREAM_SIZE = 100 * 1024  # 100 KB for SSE streams


class LLMTracer:
    """
    mitmproxy addon to trace LLM API calls and log them to JSONL.
    """

    def __init__(self, output_path: str = "llm_traces.jsonl", default_ollama_model: str = "qwen2.5-coder:7b"):
        """
        Initialize the tracer.

        Args:
            output_path: Path to the JSONL output file (default: llm_traces.jsonl)
            default_ollama_model: Default Ollama model to use when Cursor requests OpenAI models
        """
        self.output_path = output_path
        self.default_ollama_model = default_ollama_model
        
        # Map common OpenAI/Anthropic model names to your Ollama model
        self.model_mapping = {
            "gpt-4": default_ollama_model,
            "gpt-4-turbo": default_ollama_model,
            "gpt-4o": default_ollama_model,
            "gpt-3.5-turbo": default_ollama_model,
            "gpt-3.5-turbo-16k": default_ollama_model,
            "claude-3-opus": default_ollama_model,
            "claude-3-sonnet": default_ollama_model,
            "claude-3-haiku": default_ollama_model,
        }


    def is_llm_request(self, flow: http.HTTPFlow) -> bool:
        """
        Check if a flow looks like an LLM API request.
        Uses only host-based filtering to avoid false positives.

        Args:
            flow: HTTP flow to check

        Returns:
            True if the flow appears to be an LLM request
        """
        if not hasattr(flow, "request") or flow.request is None:
            return False

        host = flow.request.host or ""
        
        # Check exact host match
        if host in LLM_HOSTS:
            return True
        
        # Check for ngrok hostnames (dynamic, so we match patterns)
        if host.endswith(".ngrok.io") or host.endswith(".ngrok-free.app") or host.endswith(".ngrok.app"):
            return True
        
        return False

    def request(self, flow: http.HTTPFlow):
        """
        Hook called when a request is received.
        Maps OpenAI/Anthropic model names to Ollama models.
        """
        if not hasattr(flow, "request") or flow.request is None:
            return
        
        # Only process requests that look like LLM API calls
        if not self.is_llm_request(flow):
            return
        
        # Try to modify the model parameter in JSON requests
        try:
            content_type = flow.request.headers.get("content-type", "").lower()
            if "application/json" in content_type:
                # Get the JSON body
                req_json = self.get_json_body(flow.request)
                if req_json and "model" in req_json:
                    original_model = req_json["model"]
                    # Map to Ollama model if needed
                    if original_model in self.model_mapping:
                        mapped_model = self.model_mapping[original_model]
                        req_json["model"] = mapped_model
                        # Update the request body
                        flow.request.text = json.dumps(req_json)
                        # Log the mapping (optional)
                        # print(f"[MODEL MAP] {original_model} → {mapped_model}")
        except Exception:
            # Silently fail if we can't modify the request
            pass

    def safe_get_conn_info(self, conn):
        """
        Safely extract connection address and port.
        Handles both tuple and object-based connection representations.

        Args:
            conn: Connection object (client_conn or server_conn)

        Returns:
            dict with "address" and "port" keys, or None values if unavailable
        """
        if conn is None:
            return {"address": None, "port": None}

        try:
            # Try tuple format: (address, port)
            if isinstance(conn.address, (tuple, list)) and len(conn.address) >= 2:
                return {"address": conn.address[0], "port": conn.address[1]}
            # Try accessing attributes directly
            elif hasattr(conn, "address"):
                addr = conn.address
                if isinstance(addr, (tuple, list)) and len(addr) >= 2:
                    return {"address": addr[0], "port": addr[1]}
                elif hasattr(conn, "port"):
                    return {"address": str(addr), "port": conn.port}
        except (AttributeError, IndexError, TypeError):
            pass

        # Fallback: try to get address and port as separate attributes
        try:
            address = getattr(conn, "address", None)
            port = getattr(conn, "port", None)
            return {"address": str(address) if address is not None else None, "port": port}
        except Exception:
            return {"address": None, "port": None}

    def get_json_body(self, message):
        """
        Safely extract and parse JSON body from a request or response message.

        Args:
            message: mitmproxy message object (request or response)

        Returns:
            Parsed JSON dict if successful, None otherwise
        """
        if message is None:
            return None

        try:
            content_type = message.headers.get("content-type", "")
            if "application/json" not in content_type.lower():
                return None

            text = message.get_text()
            if not text:
                return None

            return json.loads(text)
        except (json.JSONDecodeError, AttributeError, UnicodeDecodeError):
            return None

    def get_body_text(self, message):
        """
        Get truncated text body from a message.

        Args:
            message: mitmproxy message object (request or response)

        Returns:
            Truncated text string, or None if unavailable
        """
        if message is None:
            return None

        try:
            text = message.get_text()
            if text is None:
                return None

            # Truncate to max size
            if len(text) > MAX_BODY_TEXT_SIZE:
                return text[:MAX_BODY_TEXT_SIZE] + "... (truncated)"
            return text
        except (AttributeError, UnicodeDecodeError):
            return None

    def extract_request_data(self, flow: http.HTTPFlow):
        """
        Extract request data from a flow.

        Args:
            flow: HTTP flow

        Returns:
            dict with request details
        """
        request = flow.request
        if request is None:
            return None

        req_data = {
            "method": request.method or None,
            "scheme": request.scheme or None,
            "host": request.host or None,
            "port": request.port or None,
            "path": request.path or None,
            "headers": dict(request.headers) if request.headers else {},
        }

        # Try to parse JSON body
        req_json = self.get_json_body(request)
        if req_json is not None:
            req_data["json"] = req_json
        else:
            # Fall back to truncated text
            body_text = self.get_body_text(request)
            if body_text:
                req_data["body_text"] = body_text

        return req_data

    def extract_response_data(self, flow: http.HTTPFlow):
        """
        Extract response data from a flow.
        Handles both JSON and SSE (Server-Sent Events) streams.

        Args:
            flow: HTTP flow

        Returns:
            dict with response details, or None if response is unavailable
        """
        if not hasattr(flow, "response") or flow.response is None:
            return None

        response = flow.response

        resp_data = {
            "status_code": response.status_code if hasattr(response, "status_code") else None,
            "headers": dict(response.headers) if response.headers else {},
        }

        # Check if this is an SSE stream
        content_type = response.headers.get("content-type", "").lower()
        is_sse = "text/event-stream" in content_type or "text/event-stream" in str(response.headers).lower()
        
        if is_sse:
            # For SSE streams, capture the full stream (up to limit)
            try:
                text = response.get_text()
                if text:
                    # Truncate if too large
                    if len(text) > MAX_SSE_STREAM_SIZE:
                        resp_data["sse_stream"] = text[:MAX_SSE_STREAM_SIZE] + "... (truncated)"
                        resp_data["sse_stream_length"] = len(text)
                    else:
                        resp_data["sse_stream"] = text
                        resp_data["sse_stream_length"] = len(text)
            except (AttributeError, UnicodeDecodeError):
                pass
        
        # Try to parse JSON body (for non-streaming responses)
        resp_json = self.get_json_body(response)
        if resp_json is not None:
            resp_data["json"] = resp_json
        elif not is_sse:
            # Fall back to truncated text (only if not SSE)
            body_text = self.get_body_text(response)
            if body_text:
                resp_data["body_text"] = body_text

        return resp_data

    def parse_sse_stream(self, sse_text):
        """
        Parse SSE stream and extract events.
        
        Args:
            sse_text: Raw SSE stream text
            
        Returns:
            List of parsed SSE events
        """
        events = []
        for line in sse_text.split('\n'):
            if line.startswith('data: '):
                data = line[6:]  # Remove 'data: ' prefix
                if data.strip() and data.strip() != '[DONE]':
                    try:
                        events.append(json.loads(data))
                    except json.JSONDecodeError:
                        pass
        return events

    def extract_tool_call_from_content(self, content):
        """
        Extract tool call JSON from model's text content.
        Handles various JSON formats and edge cases.
        
        Args:
            content: Text content that may contain tool call JSON
            
        Returns:
            Tool call dict if found, None otherwise
        """
        if not content:
            return None
        
        # Strategy 1: Try to find complete JSON object from first { to last }
        # This handles multi-line JSON that spans tokens
        start_idx = content.find('{')
        end_idx = content.rfind('}')
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            try:
                json_str = content[start_idx:end_idx+1]
                tool_call = json.loads(json_str)
                if isinstance(tool_call, dict) and "name" in tool_call and "arguments" in tool_call:
                    return tool_call
            except (json.JSONDecodeError, ValueError):
                pass
        
        # Strategy 2: Try regex to find JSON objects with name and arguments
        # This handles cases where JSON might be embedded in other text
        json_pattern = r'\{\s*"name"\s*:\s*"[^"]+"\s*,\s*"arguments"\s*:\s*\{[^}]*\}\s*\}'
        matches = re.findall(json_pattern, content, re.DOTALL)
        for match in matches:
            try:
                tool_call = json.loads(match)
                if isinstance(tool_call, dict) and "name" in tool_call and "arguments" in tool_call:
                    return tool_call
            except (json.JSONDecodeError, ValueError):
                continue
        
        # Strategy 3: Try to find nested JSON (arguments as object)
        # Pattern: {"name": "...", "arguments": {...}}
        nested_pattern = r'\{\s*"name"\s*:\s*"([^"]+)"\s*,\s*"arguments"\s*:\s*(\{[^}]*\})\s*\}'
        nested_matches = re.findall(nested_pattern, content, re.DOTALL)
        for name, args_str in nested_matches:
            try:
                args = json.loads(args_str)
                return {"name": name, "arguments": args}
            except (json.JSONDecodeError, ValueError):
                continue
        
        return None

    def transform_to_openai_tool_call(self, tool_call):
        """
        Transform model's tool call format to OpenAI function calling format.
        
        Args:
            tool_call: Dict with "name" and "arguments" keys
            
        Returns:
            OpenAI-formatted tool call dict
        """
        # Generate a unique call ID
        call_id = f"call_{uuid.uuid4().hex[:16]}"
        
        # Ensure arguments is a JSON string
        if isinstance(tool_call["arguments"], dict):
            arguments_str = json.dumps(tool_call["arguments"])
        else:
            arguments_str = str(tool_call["arguments"])
        
        return {
            "id": call_id,
            "type": "function",
            "function": {
                "name": tool_call["name"],
                "arguments": arguments_str
            }
        }

    def transform_sse_response(self, sse_text):
        """
        Transform SSE stream to include tool calls in OpenAI format.
        
        Args:
            sse_text: Original SSE stream text
            
        Returns:
            Transformed SSE stream text with tool_calls
        """
        events = self.parse_sse_stream(sse_text)
        if not events:
            return sse_text
        
        # Accumulate content from all events
        accumulated_content = ""
        tool_call_found = None
        
        for event in events:
            if "choices" in event and len(event["choices"]) > 0:
                delta = event["choices"][0].get("delta", {})
                content = delta.get("content", "")
                if content:
                    accumulated_content += content
        
        # Try to extract tool call from accumulated content
        if accumulated_content:
            tool_call_found = self.extract_tool_call_from_content(accumulated_content)
        
        # Only transform if we found a valid tool call
        if not tool_call_found:
            return sse_text
        
        # Validate the tool call has required fields
        if not isinstance(tool_call_found, dict):
            return sse_text
        if "name" not in tool_call_found or "arguments" not in tool_call_found:
            return sse_text
        if not isinstance(tool_call_found["arguments"], dict):
            # Arguments should be a dict, but if it's a string, that's okay too
            pass
        
        # Check if the last event already has tool_calls (Ollama might have formatted it)
        last_event = events[-1] if events else None
        if last_event and "choices" in last_event and len(last_event["choices"]) > 0:
            delta = last_event["choices"][0].get("delta", {})
            if "tool_calls" in delta:
                # Already has tool_calls, don't transform
                return sse_text
        
        # Transform the last event to include tool_calls
        transformed_events = []
        for i, event in enumerate(events):
            if i == len(events) - 1:  # Last event
                # Create a new event with tool_calls
                # Preserve the index from the original tool_call if it exists
                tool_call_obj = self.transform_to_openai_tool_call(tool_call_found)
                # Set index to 0 for the first (and only) tool call
                tool_call_obj["index"] = 0
                
                new_event = {
                    "id": event.get("id", ""),
                    "object": event.get("object", ""),
                    "created": event.get("created", 0),
                    "model": event.get("model", ""),
                    "system_fingerprint": event.get("system_fingerprint", ""),
                    "choices": [{
                        "index": 0,
                        "delta": {
                            "role": "assistant",
                            "content": None,  # Clear content when tool_calls present
                            "tool_calls": [tool_call_obj]
                        },
                        "finish_reason": "tool_calls"
                    }]
                }
                transformed_events.append(new_event)
            else:
                transformed_events.append(event)
        
        # Reconstruct SSE stream
        sse_lines = []
        for event in transformed_events:
            sse_lines.append(f"data: {json.dumps(event)}")
            sse_lines.append("")  # Empty line between events
        sse_lines.append("data: [DONE]")
        sse_lines.append("")  # Final empty line
        
        return "\n".join(sse_lines)

    def response(self, flow: http.HTTPFlow):
        """
        Hook called when a response is ready.
        Transforms tool calls and logs the flow.

        Args:
            flow: HTTP flow with completed response
        """
        if not self.is_llm_request(flow):
            return

        # Transform SSE responses to include tool calls in OpenAI format
        if hasattr(flow, "response") and flow.response:
            content_type = flow.response.headers.get("content-type", "").lower()
            if "text/event-stream" in content_type:
                try:
                    original_text = flow.response.get_text()
                    if original_text:
                        transformed_text = self.transform_sse_response(original_text)
                        # Update the response with transformed content
                        flow.response.text = transformed_text
                        # Update content-length if present (remove it, let it be chunked)
                        if "content-length" in flow.response.headers:
                            del flow.response.headers["content-length"]
                except Exception:
                    # If transformation fails, keep original
                    pass

        try:
            # Extract flow information (after transformation)
            log_entry = {
                "timestamp": time.time(),
                "flow_id": str(flow.id) if hasattr(flow, "id") else None,
                "client_conn": self.safe_get_conn_info(flow.client_conn) if hasattr(flow, "client_conn") else None,
                "server_conn": self.safe_get_conn_info(flow.server_conn) if hasattr(flow, "server_conn") else None,
                "request": self.extract_request_data(flow),
                "response": self.extract_response_data(flow),
            }

            # Write to JSONL file (append mode, line-buffered)
            with open(self.output_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")

        except Exception as e:
            # Never crash mitmproxy due to logging issues
            # In production, you might want to log this error somewhere
            pass


# Register the addon
addons = [
    LLMTracer(),
]

