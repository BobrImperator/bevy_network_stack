#!/usr/bin/env bash
# Repository root and scratch directory; sourced, not run.

# Prints the repository root that holds the running script.
workspace::root() {
	git -C "$(dirname "$0")/.." rev-parse --show-toplevel
}

# Sets the global $scratch to a new temporary directory removed when the script exits.
workspace::init_scratch() {
	scratch=$(mktemp -d)
	trap 'rm -rf -- "$scratch"' EXIT
	trap 'exit 130' HUP INT TERM
}
