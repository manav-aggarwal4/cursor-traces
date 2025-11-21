#!/usr/bin/env python3
"""
Extract readable text from LLM traces, especially from protobuf-encoded bodies.

This script extracts human-readable text from binary/protobuf data in the traces,
making it easier to see prompts, tool calls, and other meaningful content.
"""
import argparse
import json
import re
from typing import Dict, Any, List, Optional


def extract_readable_text(data: str, min_length: int = 10) -> str:
    """
    Extract readable ASCII text from binary/protobuf data.
    
    Args:
        data: Raw body text (may contain binary/protobuf)
        min_length: Minimum length of readable sequences to keep
        
    Returns:
        Cleaned readable text
    """
    if not data:
        return ""
    
    # Convert to string if needed
    text = data if isinstance(data, str) else str(data)
    
    # Extract sequences of printable ASCII characters
    # Keep newlines, tabs, and spaces
    readable_chars = []
    current_seq = []
    
    for char in text:
        # Printable ASCII: 32-126, plus newline (10), carriage return (13), tab (9)
        if 32 <= ord(char) < 127 or char in '\n\r\t':
            current_seq.append(char)
        else:
            # End of readable sequence
            if len(current_seq) >= min_length:
                readable_chars.extend(current_seq)
                readable_chars.append('\n')  # Add separator
            current_seq = []
    
    # Don't forget the last sequence
    if len(current_seq) >= min_length:
        readable_chars.extend(current_seq)
    
    result = ''.join(readable_chars)
    
    # Clean up: remove excessive whitespace
    result = re.sub(r' +', ' ', result)  # Multiple spaces -> single space
    result = re.sub(r'\n\s*\n\s*\n+', '\n\n', result)  # Multiple newlines -> double newline
    
    return result.strip()


def extract_urls(text: str) -> List[str]:
    """Extract URLs from text."""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(url_pattern, text)


def extract_tool_names(text: str) -> List[str]:
    """Extract tool names from protobuf data."""
    # Look for common tool name patterns
    patterns = [
        r'toolName[^\x00-\x1f]*?([a-z_][a-z0-9_]+)',
        r'([a-z_][a-z0-9_]+_tool)',
        r'(codebase_search|glob_file_search|read_file|grep|list_dir)',
    ]
    tools = set()
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        tools.update(matches)
    return sorted(list(tools))


def extract_prompts(text: str) -> List[str]:
    """Extract potential prompts/instructions from text."""
    # Look for common prompt patterns
    prompts = []
    
    # Look for "You are..." patterns
    you_are_pattern = r'You are[^\x00-\x1f]{20,500}'
    matches = re.findall(you_are_pattern, text, re.DOTALL)
    prompts.extend(matches)
    
    # Look for "Rules:" patterns
    rules_pattern = r'Rules:[^\x00-\x1f]{20,1000}'
    matches = re.findall(rules_pattern, text, re.DOTALL)
    prompts.extend(matches)
    
    # Look for numbered lists (common in prompts)
    numbered_pattern = r'\d+\.\s+[^\x00-\x1f]{20,200}'
    matches = re.findall(numbered_pattern, text)
    prompts.extend(matches)
    
    return prompts


def analyze_trace(trace: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze a single trace and extract readable information.
    
    Args:
        trace: Single trace entry from JSONL
        
    Returns:
        Dictionary with extracted readable information
    """
    result = {
        "timestamp": trace.get("timestamp"),
        "flow_id": trace.get("flow_id"),
        "path": trace.get("request", {}).get("path"),
        "method": trace.get("request", {}).get("method"),
        "host": trace.get("request", {}).get("host"),
        "request_text": "",
        "response_text": "",
        "urls": [],
        "tool_names": [],
        "prompts": [],
    }
    
    # Extract from request body
    request = trace.get("request", {})
    req_body = request.get("body_text", "") or str(request.get("json", ""))
    if req_body:
        readable = extract_readable_text(req_body, min_length=10)
        result["request_text"] = readable
        result["urls"].extend(extract_urls(readable))
        result["tool_names"].extend(extract_tool_names(readable))
        result["prompts"].extend(extract_prompts(readable))
    
    # Extract from response body
    response = trace.get("response")
    if response:
        resp_body = response.get("body_text", "") or str(response.get("json", ""))
        if resp_body:
            readable = extract_readable_text(resp_body, min_length=10)
            result["response_text"] = readable
            result["urls"].extend(extract_urls(readable))
            result["tool_names"].extend(extract_tool_names(readable))
    
    # Deduplicate lists
    result["urls"] = sorted(list(set(result["urls"])))
    result["tool_names"] = sorted(list(set(result["tool_names"])))
    result["prompts"] = list(set(result["prompts"]))
    
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Extract readable text from LLM traces (especially protobuf-encoded data)"
    )
    parser.add_argument(
        "-i", "--input",
        default="llm_traces.jsonl",
        help="Input JSONL file (default: llm_traces.jsonl)"
    )
    parser.add_argument(
        "-o", "--output",
        default="extracted_text.json",
        help="Output JSON file (default: extracted_text.json)"
    )
    parser.add_argument(
        "--text-only",
        action="store_true",
        help="Output only readable text (one file per trace)"
    )
    parser.add_argument(
        "--filter-path",
        help="Only extract traces matching this path pattern (e.g., 'Chat' or 'WarmStream')"
    )
    
    args = parser.parse_args()
    
    traces = []
    with open(args.input, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                trace = json.loads(line)
                
                # Filter by path if requested
                if args.filter_path:
                    path = trace.get("request", {}).get("path", "")
                    if args.filter_path.lower() not in path.lower():
                        continue
                
                analyzed = analyze_trace(trace)
                traces.append(analyzed)
                
            except json.JSONDecodeError as e:
                print(f"Warning: Skipping invalid JSON on line {line_num}: {e}", file=__import__("sys").stderr)
                continue
    
    if args.text_only:
        # Output readable text files
        import os
        os.makedirs("extracted_text", exist_ok=True)
        
        for i, trace in enumerate(traces):
            path_suffix = trace['path'].split('/')[-1] if trace['path'] else 'unknown'
            filename = f"extracted_text/trace_{i:04d}_{path_suffix}.txt"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"=== TRACE {i} ===\n")
                f.write(f"Path: {trace['path']}\n")
                f.write(f"Timestamp: {trace['timestamp']}\n")
                f.write(f"\n=== REQUEST TEXT ===\n")
                f.write(trace['request_text'] or "(no readable text)")
                f.write(f"\n\n=== RESPONSE TEXT ===\n")
                f.write(trace['response_text'] or "(no readable text)")
                f.write(f"\n\n=== EXTRACTED INFO ===\n")
                f.write(f"URLs: {', '.join(trace['urls'])}\n")
                f.write(f"Tools: {', '.join(trace['tool_names'])}\n")
                if trace['prompts']:
                    f.write(f"\n=== PROMPTS ===\n")
                    for prompt in trace['prompts']:
                        f.write(f"\n{prompt}\n")
        
        print(f"Extracted {len(traces)} traces to extracted_text/ directory")
    else:
        # Output JSON
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(traces, f, indent=2, ensure_ascii=False)
        
        print(f"Extracted readable text from {len(traces)} traces")
        print(f"Output written to {args.output}")
        
        # Print summary
        total_prompts = sum(len(t['prompts']) for t in traces)
        total_tools = sum(len(t['tool_names']) for t in traces)
        total_urls = sum(len(t['urls']) for t in traces)
        
        print(f"\nSummary:")
        print(f"  Total prompts found: {total_prompts}")
        print(f"  Total tool names found: {total_tools}")
        print(f"  Total URLs found: {total_urls}")


if __name__ == "__main__":
    main()

