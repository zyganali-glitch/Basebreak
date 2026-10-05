# Basebreak Isolated Demo Target

This repository is an isolated test target designed specifically for Basebreak causal verification demonstrations.
It is completely outside Basebreak's production codebase.

It contains an intentional defect in `src/demo_target/cli.py` where `format_quiet_output(output, quiet=True)` returns `"verbose: " + output` instead of empty string `""`.
This allows proving that under BUG_FIX semantics:
- BASE world fails (exit 1)
- CANDIDATE world passes (exit 0)
- Verified causally without contaminating Basebreak production source.
