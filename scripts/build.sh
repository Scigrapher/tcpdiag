#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
main="$root/cmd/tcpdiag/main.go"
version="$(sed -n 's/.*const version = "\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)".*/\1/p' "$main" | head -n1)"
if [[ -z "$version" ]]; then
    echo "could not find const version = \"x.y.z\" in $main" >&2
    exit 1
fi

mode="bump"
if [[ "${1:-}" == "--no-bump" ]]; then
    mode="keep"
elif [[ "${1:-}" == "--version" ]]; then
    if [[ ! "${2:-}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "--version must look like 1.2.3" >&2
        exit 1
    fi
    version="$2"
    mode="set"
fi

if [[ "$mode" == "bump" ]]; then
    IFS=. read -r major minor patch <<<"$version"
    version="$major.$minor.$((patch + 1))"
fi

backup="$(mktemp)"
tmp="$(mktemp)"
cp "$main" "$backup"
awk -v v="$version" '
    !done && $0 ~ /const version = "[0-9]+\.[0-9]+\.[0-9]+"/ {
        sub(/const version = "[0-9]+\.[0-9]+\.[0-9]+"/, "const version = \"" v "\"")
        done = 1
    }
    { print }
' "$main" >"$tmp"
mv "$tmp" "$main"

mkdir -p "$root/bin"
if ! (cd "$root" && go build -o bin/tcpdiag ./cmd/tcpdiag); then
    mv "$backup" "$main"
    echo "go build failed; restored $main" >&2
    exit 1
fi
rm -f "$backup"
echo "built bin/tcpdiag as tcpdiag $version"
