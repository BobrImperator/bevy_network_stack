#!/usr/bin/env bash
# Per-crate facts and the cargo config built from them; sourced, not run.

# Usage: crate::test_packages <crate>; prints the cargo package and feature flags that test <crate>.
crate::test_packages() {
	case $1 in
	renet) echo "-p renetcode" ;;
	moonshine_util) echo "-p moonshine-util" ;;
	moonshine_kind) echo "-p moonshine-kind" ;;
	moonshine_behavior) echo "-p moonshine-behavior" ;;
	bevy_capture) echo "-p bevy_capture --features mp4_ffmpeg_cli_pipe" ;;
	*) cli::die "no test packages are defined for $1" ;;
	esac
}

# Usage: crate::patched_deps <crate>; prints "<package> <crate>" for each crates.io
# dependency of <crate> that this repository also patches.
crate::patched_deps() {
	case $1 in
	moonshine_kind) echo "moonshine-util moonshine_util" ;;
	moonshine_behavior) printf '%s\n' "moonshine-kind moonshine_kind" "moonshine-util moonshine_util" ;;
	esac
}

# Usage: crate::patch_config <root> <crate> <scratch>
# Checks out the generated branch of each patched dependency of <crate> under <scratch>,
# writes a cargo config that patches crates.io with those checkouts and prints its path.
crate::patch_config() {
	local root=$1 crate=$2 scratch=$3 config package dep commit
	config=$scratch/patch.toml
	echo "[patch.crates-io]" >"$config"
	while read -r package dep; do
		commit=$(git::branch_commit "$root" "$dep") ||
			cli::die "branch $dep does not exist; run: scripts/apply $dep"
		git::checkout "$root" "$commit" "$scratch/$dep"
		echo "patching $package with $dep $commit" >&2
		echo "$package = { path = \"$scratch/$dep\" }" >>"$config"
	done < <(crate::patched_deps "$crate")
	echo "$config"
}
