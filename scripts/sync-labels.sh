#!/bin/sh
# Creates or updates the repository labels listed in .github/labels.json.
# Labels that are not listed are left alone.
#
#   sh scripts/sync-labels.sh            # needs gh (authenticated) and jq
set -eu

file=${1:-.github/labels.json}
jq -r '.[] | [.name, .color, .description] | @tsv' "$file" |
	while IFS="$(printf '\t')" read -r name color desc; do
		gh label create "$name" --color "$color" --description "$desc" --force >/dev/null
		echo "label: $name"
	done
