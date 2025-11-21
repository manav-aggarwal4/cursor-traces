#!/usr/bin/env python3
"""
Fetch a single SWE-bench task instance and clone its repository for testing.

This script fetches a SWE-bench task from the Hugging Face dataset and
sets it up locally so you can open it in Cursor and test the LLM tracer.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path


def fetch_swe_bench_task(task_index: int = 0, output_dir: Path = Path("swe_bench_task")):
    """
    Fetch a single SWE-bench task from Hugging Face datasets or GitHub fallback.

    Args:
        task_index: Index of the task to fetch (default: 0, first task)
        output_dir: Directory to clone the task repository into

    Returns:
        dict with task information
    """
    try:
        from datasets import load_dataset
    except ImportError:
        # Fall back to known tasks from GitHub if datasets is not available
        print("Note: 'datasets' library not found. Using known tasks from GitHub instead.")
        print("To use Hugging Face dataset, install: pip install datasets")
        return fetch_from_github(task_index, output_dir)

    print(f"Loading SWE-bench dataset from Hugging Face...")
    try:
        # Load the test split of SWE-bench
        swebench = load_dataset('princeton-nlp/SWE-bench', split='test')
        print(f"Loaded {len(swebench)} tasks")
    except Exception as e:
        print(f"Error loading dataset: {e}")
        print("\nFalling back to known SWE-bench tasks from GitHub...")
        return fetch_from_github(task_index, output_dir)

    if task_index >= len(swebench):
        print(f"Error: Task index {task_index} out of range. Dataset has {len(swebench)} tasks.")
        sys.exit(1)

    task = swebench[task_index]
    task_dict = {
        'instance_id': task.get('instance_id', f'task_{task_index}'),
        'repo': task.get('repo', ''),
        'base_commit': task.get('base_commit', ''),
        'problem_statement': task.get('problem_statement', ''),
        'test_patch': task.get('test_patch', ''),
        'patch': task.get('patch', ''),
    }

    print(f"\nSelected task {task_index}: {task_dict['instance_id']}")
    print(f"Repository: {task_dict['repo']}")
    print(f"Base commit: {task_dict['base_commit']}")

    # Clone the repository
    repo_url = f"https://github.com/{task_dict['repo']}.git"
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    repo_dir = output_dir / task_dict['repo'].split('/')[-1]

    if repo_dir.exists():
        print(f"\nRepository already exists at {repo_dir}")
        print("Use --force to re-clone")
        return task_dict

    print(f"\nCloning repository to {repo_dir}...")
    try:
        subprocess.run(
            ['git', 'clone', repo_url, str(repo_dir)],
            check=True,
            capture_output=True
        )
        print("✓ Repository cloned successfully")

        # Checkout the base commit
        if task_dict['base_commit']:
            print(f"Checking out base commit: {task_dict['base_commit']}...")
            subprocess.run(
                ['git', 'checkout', task_dict['base_commit']],
                cwd=str(repo_dir),
                check=True,
                capture_output=True
            )
            print("✓ Checked out base commit")

    except subprocess.CalledProcessError as e:
        print(f"Error cloning repository: {e}")
        print(f"stdout: {e.stdout.decode() if e.stdout else ''}")
        print(f"stderr: {e.stderr.decode() if e.stderr else ''}")
        sys.exit(1)

    # Save task metadata
    metadata_file = output_dir / 'task_metadata.json'
    with open(metadata_file, 'w') as f:
        json.dump(task_dict, f, indent=2)

    print(f"\n✓ Task setup complete!")
    print(f"  Repository: {repo_dir}")
    print(f"  Metadata: {metadata_file}")
    print(f"\nNext steps:")
    print(f"  1. Start mitmproxy: mitmproxy -s proxy_addon/llm_tracer_addon.py --listen-port 8080")
    print(f"  2. Open {repo_dir} in Cursor")
    print(f"  3. Trigger Cursor's agent to solve the task")
    print(f"  4. Check llm_traces.jsonl for captured traces")

    return task_dict


def fetch_from_github(task_index: int = 0, output_dir: Path = Path("swe_bench_task")):
    """
    Fallback: Fetch a known SWE-bench task from GitHub directly.
    """
    # Known SWE-bench task examples
    # Note: These are example repositories that can be used for testing
    # The actual SWE-bench tasks would have specific commits, but for testing
    # the tracer, we'll use the latest commit or a known stable tag
    known_tasks = [
        {
            'instance_id': 'django__django-test',
            'repo': 'django/django',
            'base_commit': None,  # Use default branch for testing
            'problem_statement': 'Test task for LLM tracer - Django repository. Open this in Cursor and trigger the agent.',
        },
        {
            'instance_id': 'scikit-learn__scikit-learn-test',
            'repo': 'scikit-learn/scikit-learn',
            'base_commit': None,  # Use default branch for testing
            'problem_statement': 'Test task for LLM tracer - scikit-learn repository. Open this in Cursor and trigger the agent.',
        },
    ]

    if task_index >= len(known_tasks):
        print(f"Error: Task index {task_index} out of range.")
        print(f"Available task indices: 0-{len(known_tasks) - 1}")
        sys.exit(1)

    task_dict = known_tasks[task_index]
    repo_url = f"https://github.com/{task_dict['repo']}.git"
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    repo_dir = output_dir / task_dict['repo'].split('/')[-1]

    print(f"\nUsing known SWE-bench task: {task_dict['instance_id']}")
    print(f"Repository: {task_dict['repo']}")
    print(f"Base commit: {task_dict['base_commit']}")

    if repo_dir.exists():
        print(f"\nRepository already exists at {repo_dir}")
        print("Use --force to re-clone")
        return task_dict

    print(f"\nCloning repository to {repo_dir}...")
    try:
        subprocess.run(
            ['git', 'clone', repo_url, str(repo_dir)],
            check=True,
            capture_output=True
        )
        print("✓ Repository cloned successfully")

        # Checkout the base commit
        if task_dict['base_commit']:
            print(f"Checking out base commit: {task_dict['base_commit']}...")
            subprocess.run(
                ['git', 'checkout', task_dict['base_commit']],
                cwd=str(repo_dir),
                check=True,
                capture_output=True
            )
            print("✓ Checked out base commit")

    except subprocess.CalledProcessError as e:
        print(f"Error cloning repository: {e}")
        stderr = e.stderr.decode() if e.stderr else ''
        stdout = e.stdout.decode() if e.stdout else ''
        if stderr:
            print(f"stderr: {stderr}")
        if stdout:
            print(f"stdout: {stdout}")
        sys.exit(1)

    # Save task metadata
    metadata_file = output_dir / 'task_metadata.json'
    with open(metadata_file, 'w') as f:
        json.dump(task_dict, f, indent=2)

    print(f"\n✓ Task setup complete!")
    print(f"  Repository: {repo_dir}")
    print(f"  Metadata: {metadata_file}")
    print(f"\nNext steps:")
    print(f"  1. Start mitmproxy: mitmproxy -s proxy_addon/llm_tracer_addon.py --listen-port 8080")
    print(f"  2. Configure system proxy (HTTP/HTTPS: 127.0.0.1:8080)")
    print(f"  3. Open {repo_dir} in Cursor")
    print(f"  4. Trigger Cursor's agent to solve the task")
    print(f"  5. Check llm_traces.jsonl for captured traces")

    return task_dict


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Fetch a single SWE-bench task and clone its repository"
    )
    parser.add_argument(
        "-i",
        "--index",
        type=int,
        default=0,
        help="Index of the task to fetch (default: 0)"
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("swe_bench_task"),
        help="Output directory for the task (default: swe_bench_task)"
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Force re-clone even if repository exists"
    )

    args = parser.parse_args()

    if args.force and args.output.exists():
        import shutil
        print(f"Removing existing directory: {args.output}")
        shutil.rmtree(args.output)

    fetch_swe_bench_task(args.index, args.output)


if __name__ == "__main__":
    main()

