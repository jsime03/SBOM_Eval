#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# add_repos.sh
# Clone new repos and create the matching sboms/ directory structure.
#
# Usage: paste repos into the lists below, then run:
#   bash add_repos.sh
#
# Supported formats:
#   https://github.com/owner/repo
#   git@github.com:owner/repo.git
#   owner/repo
# ─────────────────────────────────────────────────────────────────────────────

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
REPOS_DIR="$BASE_DIR/repos"
SBOMS_DIR="$BASE_DIR/sboms"

# ── Paste your repos here ────────────────────────────────────────────────────
PYTHON_REPOS=(
  https://github.com/browser-use/browser-use
  https://github.com/Comfy-Org/ComfyUI
  https://github.com/fastapi/fastapi
  https://github.com/hacksider/Deep-Live-Cam
  https://github.com/huggingface/transformers
  https://github.com/openai/whisper
  https://github.com/TheAlgorithms/Python
  https://github.com/yt-dlp/yt-dlp
  https://github.com/3b1b/manim
  https://github.com/ansible/ansible
  https://github.com/github/spec-kit
  https://github.com/hiyouga/LlamaFactory
  https://github.com/home-assistant/core
  https://github.com/pallets/flask
  https://github.com/sherlock-project/sherlock
  https://github.com/Shubhamsaboo/awesome-llm-apps
  https://github.com/xtekky/gpt4free
  https://github.com/django/django
  https://github.com/donnemartin/system-design-primer
  https://github.com/newton-physics/newton
)

JAVASCRIPT_REPOS=(
  https://github.com/immich-app/immich
  https://github.com/facebook/react
  https://github.com/affaan-m/everything-claude-code
  https://github.com/airbnb/javascript
  https://github.com/axios/axios
  https://github.com/Chalarangelo/30-seconds-of-code
  https://github.com/excalidraw/excalidraw
  https://github.com/iptv-org/iptv
  https://github.com/kamranahmedse/developer-roadmap
  https://github.com/langgenius/dify
  https://github.com/microsoft/vscode
  https://github.com/mrdoob/three.js
  https://github.com/mui/material-ui
  https://github.com/n8n-io/n8n
  https://github.com/openclaw/openclaw
  https://github.com/shadcn-ui/ui
  https://github.com/vuejs/vue
  https://github.com/ant-design/ant-design
  https://github.com/apache/echarts
  https://github.com/cline/cline
  https://github.com/facebook/docusaurus
)
# ─────────────────────────────────────────────────────────────────────────────

# Normalize repo URL to https clone URL and extract repo name
parse_repo() {
  local input="$1"

  if [[ "$input" =~ ^git@github\.com:(.+/.+)\.git$ ]]; then
    echo "https://github.com/${BASH_REMATCH[1]}.git|$(basename "${BASH_REMATCH[1]}")"
  elif [[ "$input" =~ ^https://github\.com/([^/]+)/([^/]+)$ ]]; then
    local name="${BASH_REMATCH[2]%.git}"
    echo "https://github.com/${BASH_REMATCH[1]}/${name}.git|${name}"
  elif [[ "$input" =~ ^([^/]+)/([^/]+)$ ]]; then
    echo "https://github.com/${BASH_REMATCH[1]}/${BASH_REMATCH[2]}.git|${BASH_REMATCH[2]}"
  else
    echo "ERROR: unrecognized format: $input" >&2
    return 1
  fi
}

clone_repo() {
  local repo_input="$1"
  local language="$2"

  [[ -z "$repo_input" ]] && return

  local parsed
  parsed=$(parse_repo "$repo_input") || return
  local clone_url="${parsed%%|*}"
  local repo_name="${parsed##*|}"

  local dest_repo="$REPOS_DIR/$language/$repo_name"
  local dest_sbom="$SBOMS_DIR/$language/$repo_name"

  echo "──────────────────────────────────────────"
  echo "Repo:     $repo_name"
  echo "Language: $language"
  echo "URL:      $clone_url"

  if [[ -d "$dest_repo" ]]; then
    echo "WARNING: $dest_repo already exists — skipping clone."
  else
    echo "Cloning..."
    if ! git clone --depth=1 "$clone_url" "$dest_repo" 2>&1; then
      echo "ERROR: clone failed for $repo_name"
      return
    fi
    echo "Cloned to: $dest_repo"
  fi

  if [[ -d "$dest_sbom" ]]; then
    echo "WARNING: $dest_sbom already exists — skipping."
  else
    mkdir -p "$dest_sbom/raw" "$dest_sbom/diff"
    touch "$dest_sbom/raw/.gitkeep" "$dest_sbom/diff/.gitkeep"
    echo "Created:  $dest_sbom/{raw,diff}"
  fi
}

# ── Main ─────────────────────────────────────────────────────────────────────
if [[ ${#PYTHON_REPOS[@]} -eq 0 && ${#JAVASCRIPT_REPOS[@]} -eq 0 ]]; then
  echo "No repos listed. Add them to PYTHON_REPOS or JAVASCRIPT_REPOS in this script."
  exit 1
fi

for repo in "${PYTHON_REPOS[@]}"; do
  clone_repo "$repo" "python"
done

for repo in "${JAVASCRIPT_REPOS[@]}"; do
  clone_repo "$repo" "javascript"
done

echo ""
echo "Done."
