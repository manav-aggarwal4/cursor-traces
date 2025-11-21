# LLM Network Tracer

A tool to capture and analyze LLM network calls from Cursor (or any application) using mitmproxy as a forward proxy. This project intercepts HTTP(S) traffic, filters for LLM-related API calls, and logs them for later analysis in SWE-bench tasks.

## Overview

This project consists of:

1. **mitmproxy addon** (`proxy_addon/llm_tracer_addon.py`): Intercepts HTTP(S) traffic and logs LLM API calls to a JSONL file
2. **Post-processing script** (`scripts/parse_traces.py`): Groups logged traces into turn-based sessions for analysis

The addon runs as a forward proxy and filters traffic from known LLM providers (OpenAI, Anthropic, X.AI, Cursor, Groq) as well as common LLM endpoints.

## Project Structure

```
.
├── proxy_addon/
│   ├── __init__.py
│   └── llm_tracer_addon.py    # Main mitmproxy addon
├── scripts/
│   └── parse_traces.py         # Post-processing script
├── requirements.txt
└── README.md
```

## Setup on macOS

### 1. Install mitmproxy

Install mitmproxy using Homebrew:

```bash
brew install mitmproxy
```

### 2. Install Python Dependencies

Install the required Python packages:

```bash
pip install -r requirements.txt
```

### 3. Run mitmproxy with the Addon

Start mitmproxy with the LLM tracer addon:

```bash
mitmproxy -s proxy_addon/llm_tracer_addon.py --listen-port 8080
```

This will:
- Start mitmproxy on port 8080
- Load the LLM tracer addon
- Begin logging LLM API calls to `llm_traces.jsonl` in the current directory

You can also use `mitmweb` for a web-based UI:

```bash
mitmweb -s proxy_addon/llm_tracer_addon.py --listen-port 8080
```

Then open http://127.0.0.1:8081 in your browser to view the traffic.

### 4. Install mitmproxy's CA Certificate

For HTTPS traffic interception, you need to install mitmproxy's certificate:

1. **Start mitmproxy** (as above)

2. **Visit http://mitm.it** in your browser while the proxy is running

3. **Download the macOS certificate** (click the Apple logo)

4. **Install the certificate:**
   - Double-click the downloaded certificate (`.pem` file)
   - Keychain Access will open
   - Find the certificate named "mitmproxy" under "login" keychain
   - Double-click it to open details
   - Expand "Trust" section
   - Set "When using this certificate" to **"Always Trust"**

5. **Restart your browser** if needed

### 5. Set macOS System HTTP(S) Proxy

Configure macOS to route traffic through mitmproxy:

1. Open **System Settings** (or System Preferences on older macOS)

2. Go to **Network** → **Wi-Fi** (or your active connection)

3. Click **Details** (or "Advanced...")

4. Go to the **Proxies** tab

5. Check **"Web Proxy (HTTP)"** and **"Secure Web Proxy (HTTPS)"**

6. For both, enter:
   - **Server**: `127.0.0.1`
   - **Port**: `8080`

7. Click **OK** and **Apply**

**Note:** You may need to authenticate to save these settings.

## Fetching a SWE-bench Task for Testing

To test the tracer with a single SWE-bench task:

### Option 1: Using the Python script (recommended)

The `fetch_swe_bench_task.py` script can fetch tasks from Hugging Face or use known tasks as fallback:

```bash
# Fetch the first task (default)
python scripts/fetch_swe_bench_task.py -i 0 -o swe_bench_task

# Fetch a different task (e.g., index 1)
python scripts/fetch_swe_bench_task.py -i 1 -o swe_bench_task

# Force re-clone if repository already exists
python scripts/fetch_swe_bench_task.py -i 0 -o swe_bench_task --force
```

**Note:** If the `datasets` library is not installed, the script will fall back to known SWE-bench repositories from GitHub. To use the full Hugging Face dataset:

```bash
pip install datasets
```

### Option 2: Using the shell script

A simpler bash script is also available:

```bash
bash scripts/setup_test_task.sh swe_bench_task
```

This will clone a Django repository as a test task.

## Using with Cursor

Once the system proxy is configured and you have a test task:

1. **Ensure mitmproxy is running** with the addon loaded:
   ```bash
   mitmproxy -s proxy_addon/llm_tracer_addon.py --listen-port 8080
   ```

2. **Verify system proxy is enabled** (as configured above)

3. **Open the fetched SWE-bench repository in Cursor:**
   ```bash
   # If you used the default output directory
   cursor swe_bench_task/django
   ```

4. **Trigger Cursor's agent** or "fix tests" flow:
   - This will cause Cursor to make LLM API calls
   - The calls will be intercepted by mitmproxy
   - They will be logged to `llm_traces.jsonl`

5. **Monitor the output:**
   - Check `llm_traces.jsonl` for new entries as Cursor makes API calls
   - Each line is a JSON object representing one request/response pair

6. **After capturing traces:**
   - You can turn off the system proxy when done
   - Stop mitmproxy (Ctrl+C)

## Post-Processing

After capturing traces, use the post-processing script to group them into turn-based sessions:

```bash
python scripts/parse_traces.py -i llm_traces.jsonl -o sessions.json
```

This will:
- Read all flows from `llm_traces.jsonl`
- Group them into sessions based on:
  - Client IP address
  - Time windows (flows within 5 minutes of each other)
- Extract relevant information:
  - Model name, messages, and user from requests
  - Token usage from responses
- Write a structured JSON file with turn-based sessions

### Post-Processing Options

The script supports several options:

```bash
python scripts/parse_traces.py --help
```

- `-i, --input`: Input JSONL file path (default: `llm_traces.jsonl`)
- `-o, --output`: Output JSON file path (default: `sessions.json`)
- `-g, --max-gap-seconds`: Maximum time gap between flows in the same session, in seconds (default: `300.0`)

Example with custom options:

```bash
python scripts/parse_traces.py -i my_traces.jsonl -o my_sessions.json -g 600
```

This groups flows within 10 minutes (600 seconds) of each other into the same session.

### Extracting Readable Text from Protobuf Data

The traces may contain protobuf-encoded data (especially from Cursor's API). Use `scripts/extract_text.py` to extract human-readable text:

```bash
# Extract all readable text to JSON
python scripts/extract_text.py -i llm_traces.jsonl -o extracted_text.json

# Extract only chat-related traces
python scripts/extract_text.py -i llm_traces.jsonl --filter-path Chat

# Output individual text files for each trace
python scripts/extract_text.py -i llm_traces.jsonl --text-only
```

This script will:
- Extract readable ASCII text from binary/protobuf bodies
- Identify prompts and instructions
- Extract tool names (e.g., `codebase_search`, `glob_file_search`)
- Extract URLs from responses
- Output in JSON or individual text files

### Reconstructing Step-by-Step Reasoning Traces

To see the reasoning flow as a sequence of steps (initial prompt → tool calls → responses), use `scripts/reconstruct_reasoning_traces.py`:

```bash
# Reconstruct reasoning flow from all traces
python scripts/reconstruct_reasoning_traces.py -i llm_traces.jsonl -o reasoning_traces.json --text

# Only include chat-related traces (filters out analytics/dashboard calls)
python scripts/reconstruct_reasoning_traces.py -i llm_traces.jsonl --filter-chat --text
```

This script will:
- Identify the initial prompt/request
- Extract tool calls in sequence (codebase_search, glob_file_search, read_file, etc.)
- Show the step-by-step reasoning process
- Output in JSON format and human-readable text format

The output shows:
- **Step 1**: Initial prompt with the task description
- **Step 2+**: Sequential tool calls showing the reasoning process
- Each step includes timestamp, tool names, and extracted details

## Output Format

### Trace Format (`llm_traces.jsonl`)

Each line in the JSONL file is a JSON object representing one request/response flow:

```json
{
  "timestamp": 1732144000.123,
  "flow_id": "abc123",
  "client_conn": {
    "address": "127.0.0.1",
    "port": 54321
  },
  "server_conn": {
    "address": "api.openai.com",
    "port": 443
  },
  "request": {
    "method": "POST",
    "scheme": "https",
    "host": "api.openai.com",
    "port": 443,
    "path": "/v1/chat/completions",
    "headers": {...},
    "json": {...}
  },
  "response": {
    "status_code": 200,
    "headers": {...},
    "json": {...}
  }
}
```

### Session Format (`sessions.json`)

The post-processed output is a JSON array of session objects:

```json
[
  {
    "session_id": "127.0.0.1_1732144000.123",
    "client": "127.0.0.1",
    "start_time": 1732144000.123,
    "end_time": 1732144050.456,
    "turns": [
      {
        "timestamp": 1732144000.123,
        "request": {
          "host": "api.openai.com",
          "path": "/v1/chat/completions",
          "method": "POST",
          "model": "gpt-4",
          "messages": [...],
          "user": "user-id"
        },
        "response": {
          "status_code": 200,
          "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "total_tokens": 150
          }
        }
      }
    ]
  }
]
```

## Troubleshooting

### No traces are being logged

- Verify mitmproxy is running: Check the terminal for startup messages
- Verify system proxy is enabled: Check System Settings → Network → Proxies
- Test with a browser: Visit a website and check if it appears in mitmproxy
- Check certificate: Ensure the mitmproxy CA cert is installed and trusted
- Check file permissions: Ensure you have write permission in the current directory

### HTTPS connections fail

- Install the mitmproxy CA certificate (see Setup step 4)
- Restart applications after installing the certificate
- Some applications may need explicit proxy configuration

### Too many non-LLM traces

The addon filters for known LLM hosts and endpoints. If you see unrelated traffic, verify:
- The filtering logic in `proxy_addon/llm_tracer_addon.py`
- You can add additional hosts to the `LLM_HOSTS` list
- You can add endpoints to the `LLM_ENDPOINTS` list

### Large file sizes

Traces can grow large. Consider:
- Running the post-processing script periodically
- Truncating or rotating the JSONL file
- Modifying `MAX_BODY_TEXT_SIZE` in the addon to limit body sizes

## Extending

### Adding New LLM Providers

Edit `proxy_addon/llm_tracer_addon.py` and add to the `LLM_HOSTS` list:

```python
LLM_HOSTS = [
    "api.openai.com",
    "api.anthropic.com",
    # Add your provider here
    "api.your-llm-provider.com",
]
```

### Adding New Endpoints

Edit the `LLM_ENDPOINTS` list:

```python
LLM_ENDPOINTS = [
    "/v1/chat/completions",
    # Add your endpoint here
    "/v1/custom-endpoint",
]
```

## License

This project is provided as-is for research and analysis purposes.
