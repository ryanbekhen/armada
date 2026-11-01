#!/bin/sh
# Checks that every commit subject in a range follows Conventional Commits,
# which the release notes are grouped by (docs/releasing.md).
#
#   sh scripts/check-commits.sh origin/main..HEAD
set -eu

range=${1:?usage: check-commits.sh RANGE}
types='feat|fix|security|perf|docs|deps|refactor|test|ci|build|chore|style|revert'
pattern="^($types)(\\([a-z0-9._/-]+\\))?!?: [^ ].*"

bad=$(git log --format=%s "$range" | grep -Ev "$pattern" | grep -Ev '^Revert "' || true)
if [ -n "$bad" ]; then
	echo "These commit subjects do not follow 'type(scope)!: description':" >&2
	printf '%s\n' "$bad" | sed 's/^/  /' >&2
	echo "Types: $types (see docs/releasing.md)." >&2
	exit 1
fi
echo "All commit subjects follow Conventional Commits."
