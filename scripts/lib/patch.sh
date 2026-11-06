#!/usr/bin/env bash
# Patch series replay; sourced, not run.

# Usage: patch::apply_one <patches> <name> <work> <scratch> <crate> <base>
# Applies one patch mail as a commit with the author, committer and dates of the mail.
patch::apply_one() {
	local patches=$1 name=$2 work=$3 scratch=$4 crate=$5 base=$6 patch author email
	patch="$patches/$name"
	git mailinfo "$scratch/msg" "$scratch/body" <"$patch" >"$scratch/info"
	author=$(sed -n 's/^Author: //p' "$scratch/info")
	email=$(sed -n 's/^Email: //p' "$scratch/info")
	GIT_COMMITTER_NAME=$author GIT_COMMITTER_EMAIL=$email \
		git -C "$work" am --quiet --no-3way --committer-date-is-author-date "$patch" >&2 ||
		cli::die "patch $name does not apply to upstream/$crate $base; branch $crate left unchanged"
}

# Usage: patch::apply_series <patches> <work> <scratch> <crate> <base>
# Applies every patch listed in <patches>/series, in order.
patch::apply_series() {
	local patches=$1 work=$2 scratch=$3 crate=$4 base=$5 name
	while IFS= read -r name || [ -n "$name" ]; do
		case $name in '' | '#'*) continue ;; esac
		[ -f "$patches/$name" ] || cli::die "series names missing patch $name"
		patch::apply_one "$patches" "$name" "$work" "$scratch" "$crate" "$base"
	done <"$patches/series"
}
