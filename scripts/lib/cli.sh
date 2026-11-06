#!/usr/bin/env bash
# Command-line helpers; sourced, not run.

# Usage: cli::die <message>...
cli::die() {
	echo "$(basename "$0"): $*" >&2
	exit 1
}

# Usage: cli::crate_arg "$@"; prints the single <crate> argument.
cli::crate_arg() {
	[ $# -eq 1 ] || cli::die "usage: scripts/$(basename "$0") <crate>"
	echo "$1"
}
