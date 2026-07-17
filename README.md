# GitHub Actions Vulnerability Detector and Patcher

This repository contains the solution for the "Detect and Fix Vulnerabilities in GitHub Actions" Kaggle challenge.

## Approach
Our solution uses an advanced, robust static analysis approach instead of relying on external Large Language Models (LLMs). This guarantees 100% reproducibility, zero API costs, and blazing fast execution speeds.

We perform comprehensive Taint Tracking on the Abstract Syntax Tree (AST) representations of the GitHub Actions YAML workflows and all of their dependencies (actions and reusable workflows).
1. **Source Detection**: We identify untrusted sources (e.g., `github.head_ref`, `github.event.pull_request.title`, `github.event.issue.body`, etc.).
2. **Taint Tracking**: We track how these untrusted sources propagate through the workflow (e.g. into `env:` variables, into `inputs:` default values, and outputs).
3. **Sink Detection**: When a tainted variable is consumed inline within a `run:` block, we flag it as an exploitable code injection sink.
4. **Patch Generation**: Our patch generator automatically rewrites the vulnerable `run:` block by safely extracting the tainted expressions into environment variables and replacing the inline `${{ ... }}` expressions with safe shell variables (e.g., `$UNTRUSTED_INPUT_0`). It then generates standard unified `diff` patches using Python's `difflib`.

## Requirements
- Python 3.8+
- Standard Python libraries only (no external dependencies required).

## How to Install and Run
No installation is required beyond standard Python. 

To run the detector and patcher:

```bash
python main.py [optional_directory]
```

By default, the script will auto-detect the target directory by checking for `test`, `validation`, and `train` in the current working directory or relative dataset directory. You can optionally pass the exact directory path as a command-line argument.

## Execution Details
Upon execution, the script will:
1. Parse the provided workflows, actions, and reusable workflows from the target directory.
2. Track data flows and identify the start and end points of vulnerabilities.
3. Save the results into `test.csv` in the current working directory, following the exact JSON specification for `vulnerabilities` and `patches` columns.
4. Generate `.patch` files into the `patches/` directory. Each `.patch` is named `<sample_id>.patch` and is a Git-compatible unified diff fixing the entire data flow.
