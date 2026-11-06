#!/usr/bin/env bash
# Git helpers; sourced, not run.

# Keeps the caller's repository variables and user configuration out of every git call.
git::isolate_env() {
	unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE
	export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
}

# Usage: git::checkout <repository> <commit> <directory>
git::checkout() {
	git clone --quiet --no-checkout --shared "$1" "$3"
	git -C "$3" checkout --quiet --detach "$2"
}

# Usage: git::pinned_commit <root> <crate>; prints the submodule commit pinned in the index.
git::pinned_commit() {
	git -C "$1" rev-parse --verify --quiet ":upstream/$2"
}

# Usage: git::has_commit <repository> <commit>
git::has_commit() {
	git -C "$1" cat-file -e "$2^{commit}" 2>/dev/null
}

# Usage: git::branch_commit <root> <crate>; prints the commit of branch <crate>.
git::branch_commit() {
	git -C "$1" rev-parse --verify --quiet "refs/heads/$2^{commit}"
}

# Usage: git::publish_branch <root> <work> <crate>; force-points branch <crate> at <work> HEAD.
git::publish_branch() {
	git -C "$1" fetch --quiet --no-tags "$2" "+HEAD:refs/heads/$3"
}
