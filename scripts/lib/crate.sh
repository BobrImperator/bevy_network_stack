#!/usr/bin/env bash
# Per-crate facts; sourced, not run.

# Usage: crate::test_packages <crate>; prints the cargo package flags that test <crate>.
crate::test_packages() {
	case $1 in
	renet) echo "-p renetcode" ;;
	*) cli::die "no test packages are defined for $1" ;;
	esac
}
