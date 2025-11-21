"""
mitmproxy addon to capture and log LLM API calls.
Intercepts HTTP(S) traffic and filters for LLM-related requests.
"""
import json
import time
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
}

# Max body text size to store (1-2 KB as specified)
MAX_BODY_TEXT_SIZE = 2048


class LLMTracer:
    """
    mitmproxy addon to trace LLM API calls and log them to JSONL.
    """

    def __init__(self, output_path: str = "llm_traces.jsonl"):
        """
        Initialize the tracer.

        Args:
            output_path: Path to the JSONL output file (default: llm_traces.jsonl)
        """
        self.output_path = output_path

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
        
        # Simple host-based filtering - catches all LLM API calls for known providers
        # This avoids accidentally matching non-LLM endpoints like ChatGPT's sentinel system
        return host in LLM_HOSTS

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

        # Try to parse JSON body
        resp_json = self.get_json_body(response)
        if resp_json is not None:
            resp_data["json"] = resp_json
        else:
            # Fall back to truncated text
            body_text = self.get_body_text(response)
            if body_text:
                resp_data["body_text"] = body_text

        return resp_data

    def response(self, flow: http.HTTPFlow):
        """
        Hook called when a response is ready.
        This is the primary logging point - we log after the response completes.

        Args:
            flow: HTTP flow with completed response
        """
        if not self.is_llm_request(flow):
            return

        try:
            # Extract flow information
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

