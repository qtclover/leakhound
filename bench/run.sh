#!/usr/bin/env bash
# Compare leakhound with gitleaks and trufflehog on the full history of a few
# public repositories. Needs leakhound, gitleaks, trufflehog and git on PATH.
#
#   bench/run.sh [WORKDIR]
#
# Repositories are cloned into WORKDIR (a temporary directory by default) and
# reused if already there. Prints a Markdown table: best wall-clock time of
# three runs, and how many findings each tool reported. Verification is off
# for every tool, so this measures scanning only.
set -euo pipefail

work=${1:-$(mktemp -d)}
repos=(BurntSushi/ripgrep pallets/flask django/django)
runs=3

# Best wall-clock time of $runs runs, in seconds.
best() {
    local best=
    for _ in $(seq "$runs"); do
        local start end ms
        start=$(date +%s%N)
        "$@" >/dev/null 2>&1 || true
        end=$(date +%s%N)
        ms=$(((end - start) / 1000000))
        if [ -z "$best" ] || [ "$ms" -lt "$best" ]; then best=$ms; fi
    done
    printf '%d.%02d s' $((best / 1000)) $((best % 1000 / 10))
}

count() { grep -c "$1" || true; }

echo "| Repository | Commits | leakhound | gitleaks | trufflehog |"
echo "| --- | --- | --- | --- | --- |"
for repo in "${repos[@]}"; do
    dir="$work/${repo#*/}"
    [ -d "$dir" ] || git clone -q "https://github.com/$repo.git" "$dir"
    commits=$(git -C "$dir" rev-list --all --count)

    t_lh=$(best leakhound "$dir" --history)
    n_lh=$({ leakhound "$dir" --history --format json 2>/dev/null || true; } | count '"fingerprint"')

    t_gl=$(best gitleaks git "$dir" --no-banner --exit-code 0 --report-path "$work/gitleaks.json")
    n_gl=$(count '"Fingerprint"' <"$work/gitleaks.json")

    t_th=$(best trufflehog git "file://$dir" --no-verification --no-update --json)
    n_th=$({ trufflehog git "file://$dir" --no-verification --no-update --json 2>/dev/null || true; } | count '"SourceMetadata"')

    echo "| $repo | $commits | $t_lh ($n_lh) | $t_gl ($n_gl) | $t_th ($n_th) |"
done
