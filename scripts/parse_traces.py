#!/usr/bin/env python3
"""
Post-processing script to group LLM traces into turn-based sessions.

Reads a JSONL file of LLM API traces and groups them into sessions based on
client address and time windows.
"""
import argparse
import json
from collections import defaultdict
from typing import Dict, List, Any, Optional


def extract_request_info(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract relevant information from request data.

    Args:
        request_data: Request data dict from trace

    Returns:
        dict with extracted request information
    """
    extracted = {
        "host": request_data.get("host"),
        "path": request_data.get("path"),
        "method": request_data.get("method"),
    }

    # Try to extract LLM-specific fields from JSON body
    req_json = request_data.get("json")
    if isinstance(req_json, dict):
        if "model" in req_json:
            extracted["model"] = req_json["model"]
        if "messages" in req_json:
            extracted["messages"] = req_json["messages"]
        if "user" in req_json:
            extracted["user"] = req_json["user"]

    return extracted


def extract_response_info(response_data: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Extract relevant information from response data.

    Args:
        response_data: Response data dict from trace, or None

    Returns:
        dict with extracted response information, or None
    """
    if response_data is None:
        return None

    extracted = {
        "status_code": response_data.get("status_code"),
    }

    # Try to extract usage/token information from JSON body
    resp_json = response_data.get("json")
    if isinstance(resp_json, dict):
        if "usage" in resp_json:
            extracted["usage"] = resp_json["usage"]
        # Preserve the full JSON for reference
        extracted["json"] = resp_json
    elif response_data.get("body_text"):
        # Preserve text body if present
        extracted["body_text"] = response_data.get("body_text")

    return extracted


def create_turn(flow_entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a turn object from a flow entry.

    Args:
        flow_entry: Single flow entry from JSONL

    Returns:
        dict representing a single turn
    """
    turn = {
        "timestamp": flow_entry.get("timestamp"),
        "request": extract_request_info(flow_entry.get("request", {})),
        "response": extract_response_info(flow_entry.get("response")),
    }
    return turn


def group_flows_into_sessions(
    flows: List[Dict[str, Any]], max_gap_seconds: float
) -> List[Dict[str, Any]]:
    """
    Group flows into sessions based on client address and time windows.

    Args:
        flows: List of flow entries
        max_gap_seconds: Maximum time gap (in seconds) between flows in the same session

    Returns:
        List of session objects
    """
    # First, group flows by client address
    flows_by_client = defaultdict(list)
    for flow in flows:
        client_conn = flow.get("client_conn") or {}
        client_address = client_conn.get("address")
        if client_address:
            flows_by_client[client_address].append(flow)
        else:
            # If no client address, use a default group
            flows_by_client["unknown"].append(flow)

    sessions = []

    for client, client_flows in flows_by_client.items():
        # Sort flows by timestamp
        sorted_flows = sorted(client_flows, key=lambda f: f.get("timestamp", 0))

        if not sorted_flows:
            continue

        # Group into sessions based on time gaps
        current_session = [sorted_flows[0]]
        session_start_time = sorted_flows[0].get("timestamp", 0)

        for i in range(1, len(sorted_flows)):
            current_time = sorted_flows[i].get("timestamp", 0)
            last_time = sorted_flows[i - 1].get("timestamp", 0)
            time_gap = current_time - last_time

            if time_gap <= max_gap_seconds:
                # Add to current session
                current_session.append(sorted_flows[i])
            else:
                # Start a new session
                if current_session:
                    session_end_time = current_session[-1].get("timestamp", session_start_time)
                    session = {
                        "session_id": f"{client}_{session_start_time:.3f}",
                        "client": client,
                        "start_time": session_start_time,
                        "end_time": session_end_time,
                        "turns": [create_turn(flow) for flow in current_session],
                    }
                    sessions.append(session)

                # Start new session
                current_session = [sorted_flows[i]]
                session_start_time = current_time

        # Don't forget the last session
        if current_session:
            session_end_time = current_session[-1].get("timestamp", session_start_time)
            session = {
                "session_id": f"{client}_{session_start_time:.3f}",
                "client": client,
                "start_time": session_start_time,
                "end_time": session_end_time,
                "turns": [create_turn(flow) for flow in current_session],
            }
            sessions.append(session)

    return sessions


def parse_traces(input_path: str, output_path: str, max_gap_seconds: float):
    """
    Parse JSONL traces file and generate sessions JSON.

    Args:
        input_path: Path to input JSONL file
        output_path: Path to output JSON file
        max_gap_seconds: Maximum time gap between flows in a session (seconds)
    """
    flows = []

    # Read JSONL file
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    flow_entry = json.loads(line)
                    flows.append(flow_entry)
                except json.JSONDecodeError as e:
                    print(f"Warning: Skipping invalid JSON on line {line_num}: {e}", file=__import__("sys").stderr)
                    continue
    except FileNotFoundError:
        print(f"Error: Input file not found: {input_path}", file=__import__("sys").stderr)
        return
    except Exception as e:
        print(f"Error reading input file: {e}", file=__import__("sys").stderr)
        return

    if not flows:
        print("Warning: No valid flows found in input file", file=__import__("sys").stderr)
        # Create empty sessions list
        sessions = []
    else:
        # Group flows into sessions
        sessions = group_flows_into_sessions(flows, max_gap_seconds)

    # Write output JSON
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sessions, f, indent=2, ensure_ascii=False)
        print(f"Successfully created {len(sessions)} sessions in {output_path}")
    except Exception as e:
        print(f"Error writing output file: {e}", file=__import__("sys").stderr)


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Parse LLM traces JSONL file and group into turn-based sessions."
    )
    parser.add_argument(
        "-i",
        "--input",
        default="llm_traces.jsonl",
        help="Path to input JSONL file (default: llm_traces.jsonl)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="sessions.json",
        help="Path to output JSON file (default: sessions.json)",
    )
    parser.add_argument(
        "-g",
        "--max-gap-seconds",
        type=float,
        default=300.0,
        help="Maximum time gap in seconds between flows in the same session (default: 300.0)",
    )

    args = parser.parse_args()
    parse_traces(args.input, args.output, args.max_gap_seconds)


if __name__ == "__main__":
    main()

