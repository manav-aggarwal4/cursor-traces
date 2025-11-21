#!/bin/bash
# Simple script to set up a test SWE-bench task for testing the LLM tracer

set -e

TASK_DIR="${1:-swe_bench_task}"
REPO_NAME="django"
REPO_URL="https://github.com/django/django.git"
BASE_COMMIT="a1c7e397b203457ff03297a5d2f2a4651df7d369"  # Known SWE-bench task commit

echo "Setting up SWE-bench test task..."
echo "Repository: $REPO_URL"
echo "Base commit: $BASE_COMMIT"
echo "Output directory: $TASK_DIR"

# Create task directory
mkdir -p "$TASK_DIR"
cd "$TASK_DIR"

# Clone repository if it doesn't exist
if [ ! -d "$REPO_NAME" ]; then
    echo "Cloning repository..."
    git clone "$REPO_URL" "$REPO_NAME"
    cd "$REPO_NAME"
else
    echo "Repository already exists, updating..."
    cd "$REPO_NAME"
    git fetch
fi

# Checkout base commit
echo "Checking out base commit: $BASE_COMMIT"
git checkout "$BASE_COMMIT" 2>/dev/null || git checkout -b swe-bench-test "$BASE_COMMIT"

# Create a simple task metadata file
cat > ../task_metadata.json <<EOF
{
  "instance_id": "django__django-00000",
  "repo": "django/django",
  "base_commit": "$BASE_COMMIT",
  "problem_statement": "This is a test SWE-bench task setup for testing the LLM tracer. Open this repository in Cursor and trigger the agent to solve issues.",
  "test_patch": "",
  "patch": ""
}
EOF

cd ../..

echo ""
echo "✓ Test task setup complete!"
echo "  Repository: $TASK_DIR/$REPO_NAME"
echo "  Metadata: $TASK_DIR/task_metadata.json"
echo ""
echo "Next steps:"
echo "  1. Start mitmproxy: mitmproxy -s proxy_addon/llm_tracer_addon.py --listen-port 8080"
echo "  2. Configure system proxy (HTTP/HTTPS: 127.0.0.1:8080)"
echo "  3. Open $TASK_DIR/$REPO_NAME in Cursor"
echo "  4. Trigger Cursor's agent to work on the task"
echo "  5. Check llm_traces.jsonl for captured traces"

