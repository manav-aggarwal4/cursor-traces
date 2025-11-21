#!/usr/bin/env python3
"""
Reconstruct step-by-step reasoning traces from captured LLM traces.

This script groups related requests/responses and tool calls to show the
reasoning flow: initial prompt → tool calls → responses → next steps.
"""
import argparse
import json
import re
from collections import defaultdict
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime


def extract_readable_text(data: str, min_length: int = 10) -> str:
    """Extract readable ASCII text from binary/protobuf data."""
    if not data:
        return ""
    
    text = data if isinstance(data, str) else str(data)
    readable_chars = []
    current_seq = []
    
    for char in text:
        if 32 <= ord(char) < 127 or char in '\n\r\t':
            current_seq.append(char)
        else:
            if len(current_seq) >= min_length:
                readable_chars.extend(current_seq)
                readable_chars.append('\n')
            current_seq = []
    
    if len(current_seq) >= min_length:
        readable_chars.extend(current_seq)
    
    result = ''.join(readable_chars)
    result = re.sub(r' +', ' ', result)
    result = re.sub(r'\n\s*\n\s*\n+', '\n\n', result)
    return result.strip()


def extract_tool_call_info(trace: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extract tool call information from a trace."""
    if 'SubmitToolCallEvents' not in trace.get('request', {}).get('path', ''):
        return None
    
    request = trace.get('request', {})
    body = request.get('body_text', '') or str(request.get('json', ''))
    
    if not body:
        return None
    
    # Extract tool names and session info
    readable = extract_readable_text(body, min_length=5)
    
    # Look for tool names
    tool_patterns = [
        r'(codebase_search|glob_file_search|read_file|grep|list_dir|search_replace|write)',
        r'toolName[^\x00-\x1f]*?([a-z_][a-z0-9_]+)',
    ]
    
    tools = []
    for pattern in tool_patterns:
        matches = re.findall(pattern, readable, re.IGNORECASE)
        if matches:
            tools.extend([m if isinstance(m, str) else m[0] for m in matches])
    
    # Extract session ID if present
    session_match = re.search(r'tool_call_session_(\d+)', readable)
    session_id = session_match.group(1) if session_match else None
    
    # Extract request ID if present
    request_id_match = re.search(r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', readable)
    request_id = request_id_match.group(1) if request_id_match else None
    
    if not tools:
        return None
    
    return {
        'tools': list(set(tools)),
        'session_id': session_id,
        'request_id': request_id,
        'raw_text': readable[:500],  # First 500 chars
    }


def extract_chat_prompt(trace: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extract chat prompt from a trace."""
    if 'Chat' not in trace.get('request', {}).get('path', ''):
        return None
    
    request = trace.get('request', {})
    body = request.get('body_text', '') or str(request.get('json', ''))
    
    if not body:
        return None
    
    readable = extract_readable_text(body, min_length=20)
    
    # Extract prompt
    prompt_match = re.search(r'You are[^\x00-\x1f]{20,2000}', readable, re.DOTALL)
    prompt = prompt_match.group(0) if prompt_match else readable[:1000]
    
    # Extract file paths mentioned
    path_pattern = r'/Users/[^\s\x00-\x1f]{10,200}'
    paths = re.findall(path_pattern, readable)
    
    return {
        'prompt': prompt,
        'file_paths': list(set(paths))[:10],  # Limit to 10 unique paths
        'full_text': readable[:2000],  # First 2000 chars
    }


def classify_trace(trace: Dict[str, Any]) -> str:
    """Classify what type of trace this is."""
    path = trace.get('request', {}).get('path', '')
    
    if 'Chat' in path or 'WarmStream' in path:
        return 'chat_request'
    elif 'ToolCallEvent' in path:
        return 'tool_call'
    elif 'Analytics' in path:
        return 'analytics'
    elif 'Dashboard' in path:
        return 'dashboard'
    else:
        return 'other'


def create_reasoning_step(
    step_num: int,
    trace: Dict[str, Any],
    trace_type: str,
    extracted_info: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Create a reasoning step from a trace."""
    step = {
        'step': step_num,
        'timestamp': trace.get('timestamp'),
        'type': trace_type,
        'path': trace.get('request', {}).get('path'),
        'method': trace.get('request', {}).get('method'),
    }
    
    if extracted_info:
        step.update(extracted_info)
    
    # Add response info if available
    response = trace.get('response')
    if response:
        step['response_status'] = response.get('status_code')
        resp_body = response.get('body_text', '') or str(response.get('json', ''))
        if resp_body:
            readable = extract_readable_text(resp_body, min_length=10)
            if readable:
                step['response_text'] = readable[:500]  # First 500 chars
    
    return step


def group_into_reasoning_flow(traces: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group traces into a reasoning flow showing step-by-step process."""
    # Sort by timestamp
    sorted_traces = sorted(traces, key=lambda t: t.get('timestamp', 0))
    
    # First pass: collect all steps
    all_steps = []
    initial_prompt_step = None
    
    for trace in sorted_traces:
        trace_type = classify_trace(trace)
        
        if trace_type == 'chat_request':
            # Extract prompt
            prompt_info = extract_chat_prompt(trace)
            if prompt_info:
                step = create_reasoning_step(0, trace, 'initial_prompt', prompt_info)
                # Store separately to put it first
                if initial_prompt_step is None or step['timestamp'] < initial_prompt_step['timestamp']:
                    initial_prompt_step = step
        
        elif trace_type == 'tool_call':
            # Extract tool call info
            tool_info = extract_tool_call_info(trace)
            if tool_info:
                step = create_reasoning_step(0, trace, 'tool_call', tool_info)
                all_steps.append(step)
        
        elif trace_type not in ['analytics', 'dashboard']:
            # Other potentially interesting traces
            step = create_reasoning_step(0, trace, trace_type)
            if step.get('response_text') or step.get('path'):
                all_steps.append(step)
    
    # Group tool calls by request_id to show reasoning steps
    from collections import defaultdict
    tool_calls_by_request = defaultdict(list)
    other_steps = []
    
    for step in all_steps:
        if step.get('type') == 'tool_call' and step.get('request_id'):
            tool_calls_by_request[step['request_id']].append(step)
        else:
            other_steps.append(step)
    
    # Create reasoning steps: group tool calls by request_id
    reasoning_flow = []
    step_num = 1
    
    # Put initial prompt first
    if initial_prompt_step:
        initial_prompt_step['step'] = step_num
        initial_prompt_step['reasoning_step'] = 'initial_request'
        reasoning_flow.append(initial_prompt_step)
        step_num += 1
    
    # Group tool calls into reasoning steps
    reasoning_steps = []
    for request_id, tool_calls in tool_calls_by_request.items():
        # Sort tool calls in this group by timestamp
        tool_calls.sort(key=lambda s: s.get('timestamp', 0))
        
        # Create a reasoning step that groups these tool calls
        if tool_calls:
            first_tool = tool_calls[0]
            reasoning_step = {
                'step': 0,  # Will be assigned later
                'reasoning_step': f'reasoning_step_{len(reasoning_steps) + 1}',
                'request_id': request_id,
                'timestamp': first_tool['timestamp'],
                'type': 'reasoning_step',
                'tool_calls': tool_calls,
                'total_tools': len(tool_calls),
                'tools_used': sorted(list(set([t for tc in tool_calls for t in tc.get('tools', [])]))),
                'duration_seconds': tool_calls[-1]['timestamp'] - first_tool['timestamp'] if len(tool_calls) > 1 else 0,
            }
            reasoning_steps.append(reasoning_step)
    
    # Sort reasoning steps by timestamp
    reasoning_steps.sort(key=lambda s: s.get('timestamp', 0))
    
    # Combine initial prompt and reasoning steps, then sort by timestamp
    all_main_steps = []
    if initial_prompt_step:
        all_main_steps.append(initial_prompt_step)
    all_main_steps.extend(reasoning_steps)
    
    # Sort all steps by timestamp to get chronological order
    all_main_steps.sort(key=lambda s: s.get('timestamp', 0))
    
    # Assign step numbers
    for i, step in enumerate(all_main_steps, 1):
        step['step'] = i
        reasoning_flow.append(step)
    
    # Add other steps sorted by timestamp (excluding tool calls that were grouped)
    grouped_request_ids = set(tool_calls_by_request.keys())
    other_steps_filtered = [
        s for s in other_steps 
        if not (s.get('type') == 'tool_call' and s.get('request_id') in grouped_request_ids)
    ]
    other_steps_filtered.sort(key=lambda s: s.get('timestamp', 0))
    for step in other_steps_filtered:
        step['step'] = len(reasoning_flow) + 1
        reasoning_flow.append(step)
    
    # Calculate time gaps between steps
    for i in range(1, len(reasoning_flow)):
        prev_time = reasoning_flow[i-1].get('timestamp', 0)
        curr_time = reasoning_flow[i].get('timestamp', 0)
        if prev_time and curr_time:
            gap = curr_time - prev_time
            reasoning_flow[i]['time_since_previous'] = gap if gap >= 0 else 0  # Don't show negative gaps
    
    return reasoning_flow


def format_reasoning_trace(flow: List[Dict[str, Any]]) -> str:
    """Format reasoning flow as readable text."""
    lines = []
    lines.append("=" * 80)
    lines.append("REASONING TRACE - Step-by-Step Process")
    lines.append("=" * 80)
    lines.append("")
    lines.append("NOTE: This trace shows tool call TELEMETRY events, not actual tool executions.")
    lines.append("Tool arguments and results are not captured (they happen client-side).")
    lines.append("LLM reasoning between steps is not captured (happens server-side).")
    lines.append("")
    
    for step in flow:
        step_num = step.get('step', 0)
        step_type = step.get('type', 'unknown')
        timestamp = step.get('timestamp', 0)
        time_str = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S.%f')[:-3] if timestamp else 'N/A'
        
        # Show time gap if available
        time_gap = step.get('time_since_previous', 0)
        gap_str = f" (+{time_gap:.2f}s)" if time_gap > 0.1 else ""
        
        if step_type == 'reasoning_step':
            # Grouped reasoning step
            lines.append(f"\n[Step {step_num}] REASONING STEP - {time_str}{gap_str}")
            lines.append("-" * 80)
            lines.append(f"Request ID: {step.get('request_id', 'N/A')[:36]}")
            lines.append(f"Duration: {step.get('duration_seconds', 0):.2f} seconds")
            lines.append(f"Total tool calls: {step.get('total_tools', 0)}")
            lines.append(f"Tools used: {', '.join(step.get('tools_used', []))}")
            lines.append("")
            lines.append("Tool Call Sequence:")
            for i, tool_call in enumerate(step.get('tool_calls', []), 1):
                tc_timestamp = tool_call.get('timestamp', 0)
                tc_time = datetime.fromtimestamp(tc_timestamp).strftime('%H:%M:%S.%f')[:-3] if tc_timestamp else 'N/A'
                tools = tool_call.get('tools', [])
                lines.append(f"  {i}. {tc_time} - {', '.join(tools)}")
        
        elif step_type == 'initial_prompt':
            lines.append(f"\n[Step {step_num}] INITIAL PROMPT - {time_str}")
            lines.append("-" * 80)
            prompt = step.get('prompt', '')
            if prompt:
                lines.append("PROMPT:")
                lines.append(prompt[:500])
                if len(prompt) > 500:
                    lines.append("... (truncated)")
            
            file_paths = step.get('file_paths', [])
            if file_paths:
                lines.append(f"\nFILE PATHS MENTIONED ({len(file_paths)}):")
                for path in file_paths[:5]:
                    lines.append(f"  - {path}")
        
        elif step_type == 'tool_call':
            # Individual tool call (shouldn't happen if grouped properly)
            lines.append(f"\n[Step {step_num}] TOOL CALL - {time_str}{gap_str}")
            lines.append("-" * 80)
            tools = step.get('tools', [])
            if tools:
                lines.append(f"TOOLS CALLED: {', '.join(tools)}")
            
            request_id = step.get('request_id')
            if request_id:
                lines.append(f"Request ID: {request_id[:36]}")
        
        else:
            lines.append(f"\n[Step {step_num}] {step_type.upper()} - {time_str}{gap_str}")
            lines.append("-" * 80)
            path = step.get('path', '')
            if path:
                lines.append(f"PATH: {path}")
            
            response_text = step.get('response_text', '')
            if response_text:
                lines.append("\nRESPONSE:")
                lines.append(response_text[:300])
                if len(response_text) > 300:
                    lines.append("... (truncated)")
    
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Reconstruct step-by-step reasoning traces from LLM traces"
    )
    parser.add_argument(
        "-i", "--input",
        default="llm_traces.jsonl",
        help="Input JSONL file (default: llm_traces.jsonl)"
    )
    parser.add_argument(
        "-o", "--output",
        default="reasoning_traces.json",
        help="Output JSON file (default: reasoning_traces.json)"
    )
    parser.add_argument(
        "--text",
        action="store_true",
        help="Also output human-readable text format"
    )
    parser.add_argument(
        "--filter-chat",
        action="store_true",
        help="Only include traces related to chat sessions"
    )
    
    args = parser.parse_args()
    
    # Read traces
    traces = []
    with open(args.input, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                trace = json.loads(line)
                
                # Filter if requested
                if args.filter_chat:
                    path = trace.get('request', {}).get('path', '')
                    if 'Chat' not in path and 'ToolCall' not in path:
                        continue
                
                traces.append(trace)
            except json.JSONDecodeError as e:
                print(f"Warning: Skipping invalid JSON on line {line_num}: {e}", file=__import__("sys").stderr)
                continue
    
    # Group into reasoning flow
    reasoning_flow = group_into_reasoning_flow(traces)
    
    # Create output structure
    output = {
        'total_traces': len(traces),
        'reasoning_steps': len(reasoning_flow),
        'flow': reasoning_flow,
    }
    
    # Write JSON output
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    print(f"Reconstructed {len(reasoning_flow)} reasoning steps from {len(traces)} traces")
    print(f"Output written to {args.output}")
    
    # Write text output if requested
    if args.text:
        text_output = args.output.replace('.json', '.txt')
        with open(text_output, "w", encoding="utf-8") as f:
            f.write(format_reasoning_trace(reasoning_flow))
        print(f"Human-readable text written to {text_output}")
    
    # Print summary
    step_types = defaultdict(int)
    for step in reasoning_flow:
        step_types[step.get('type', 'unknown')] += 1
    
    print("\nStep type summary:")
    for step_type, count in sorted(step_types.items()):
        print(f"  {step_type}: {count}")


if __name__ == "__main__":
    main()

