#!/bin/bash
# Builds all repos in the repos directory

REPO_DIR="/home/jason/SBOM EVal and Validation/repos"

build_python() {
    local repo="$1"
    local repo_name=$(basename "$repo")
    echo "  [Python] Building $repo_name..."

    # Create an isolated venv for this repo
    local venv="$repo/.venv"
    python3 -m venv "$venv"
    local pip="$venv/bin/pip"
    local python="$venv/bin/python"

    # Check for uv-based repos first (hermes-agent, code-graph-rag, AstrBot)
    if [ -f "$repo/uv.lock" ] || ([ -f "$repo/pyproject.toml" ] && grep -q "uv" "$repo/pyproject.toml" 2>/dev/null); then
        (cd "$repo" && uv venv "$venv" --python python3 2>/dev/null; uv pip install --python "$python" -e ".[all]" 2>/dev/null || uv pip install --python "$python" -e .) && echo "  ✅ uv install succeeded" || echo "  ❌ uv install failed"
    elif [ -f "$repo/poetry.lock" ]; then
        (cd "$repo" && VIRTUAL_ENV="$venv" poetry install --no-root) && echo "  ✅ poetry install succeeded" || echo "  ❌ poetry install failed"
    elif [ -f "$repo/requirements.txt" ]; then
        (cd "$repo" && "$pip" install -r requirements.txt) && echo "  ✅ pip install succeeded" || echo "  ❌ pip install failed"
    elif [ -f "$repo/pyproject.toml" ]; then
        (cd "$repo" && "$pip" install -e .) && echo "  ✅ pip install succeeded" || echo "  ❌ pip install failed"
    else
        echo "  ⚠️  No recognized Python build file found, skipping..."
    fi
}

build_javascript() {
    local repo="$1"
    local repo_name=$(basename "$repo")
    echo "  [JavaScript] Building $repo_name..."

    if [ -f "$repo/bun.lock" ] || [ -f "$repo/bun.lockb" ]; then
        (cd "$repo" && bun install) && echo "  ✅ bun install succeeded" || echo "  ❌ bun install failed"
    elif [ -f "$repo/pnpm-lock.yaml" ]; then
        (cd "$repo" && pnpm install --ignore-scripts) && echo "  ✅ pnpm install succeeded" || echo "  ❌ pnpm install failed"
    elif [ -f "$repo/package-lock.json" ]; then
        (cd "$repo" && npm ci --ignore-scripts) && echo "  ✅ npm ci succeeded" || echo "  ❌ npm ci failed"
    elif [ -f "$repo/yarn.lock" ]; then
        (cd "$repo" && yarn install --ignore-scripts) && echo "  ✅ yarn install succeeded" || echo "  ❌ yarn install failed"
    elif [ -f "$repo/package.json" ]; then
        (cd "$repo" && npm install --ignore-scripts) && echo "  ✅ npm install succeeded" || echo "  ❌ npm install failed"
    else
        echo "  ⚠️  No recognized JavaScript build file found, skipping..."
    fi
}

build_rust() {
    local repo="$1"
    local repo_name=$(basename "$repo")
    echo "  [Rust] Building $repo_name..."

    if [ -f "$repo/Cargo.toml" ]; then
        (cd "$repo" && cargo build --release) && echo "  ✅ cargo build succeeded" || echo "  ❌ cargo build failed"
    else
        echo "  ⚠️  No Cargo.toml found, skipping..."
    fi
}

build_go() {
    local repo="$1"
    local repo_name=$(basename "$repo")
    echo "  [Go] Building $repo_name..."

    go_mod_dirs=$(find "$repo" -name "go.mod" -not -path "*/vendor/*" -not -path "*/integration-tests/*" -not -path "*/testdata/*" | xargs -I{} dirname {})
    if [ -z "$go_mod_dirs" ]; then
        echo "  ⚠️  No go.mod found, skipping..."
        return
    fi

    # Per-repo overrides: build_tags and build_target
    build_tags=""
    build_target="./..."
    case "$repo_name" in
        hishtory) build_target="." ;;  # client/ has no main func; root hishtory.go is the binary
    esac

    while IFS= read -r go_mod_dir; do
        module=$(realpath --relative-to="$repo" "$go_mod_dir")
        echo "    Building module: $module..."
        (cd "$go_mod_dir" && go build $build_tags $build_target) && echo "    ✅ succeeded" || echo "    ❌ failed"
    done <<< "$go_mod_dirs"
}

build_ruby() {
    local repo="$1"
    local repo_name=$(basename "$repo")
    echo "  [Ruby] Building $repo_name..."

    if [ -f "$repo/Gemfile" ]; then
        (cd "$repo" && bundle install) && echo "  ✅ bundle install succeeded" || echo "  ❌ bundle install failed"
    else
        echo "  ⚠️  No Gemfile found, skipping..."
    fi
}

build_php() {
    local repo="$1"
    local repo_name=$(basename "$repo")
    echo "  [PHP] Building $repo_name..."

    if [ -f "$repo/composer.json" ]; then
        (cd "$repo" && composer install) && echo "  ✅ composer install succeeded" || echo "  ❌ composer install failed"
    else
        echo "  ⚠️  No composer.json found, skipping..."
    fi
}

for lang_dir in "$REPO_DIR"/*/; do
    lang=$(basename "$lang_dir")
    echo "=== Language: $lang ==="
    for repo in "$lang_dir"*/; do
        [ -d "$repo" ] || continue
        case "$lang" in
            python)     build_python "$repo" ;;
            javascript) build_javascript "$repo" ;;
            rust)       build_rust "$repo" ;;
            go)         build_go "$repo" ;;
            ruby)       build_ruby "$repo" ;;
            php)        build_php "$repo" ;;
            *)          echo "  ⚠️  Unknown language: $lang, skipping..." ;;
        esac
    done
done

echo ""
echo "Done."
