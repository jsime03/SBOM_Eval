#!/bin/bash
# Resets all cloned repos to their original state

REPO_DIR="/home/jason/SBOM EVal and Validation/repos"

for lang in "$REPO_DIR"/*/; do
    for repo in "$lang"*/; do
        if [ -d "$repo/.git" ]; then
            echo "Resetting $repo..."
            git -C "$repo" checkout -- .
            git -C "$repo" clean -fd
        fi
    done
done

echo "Done."
