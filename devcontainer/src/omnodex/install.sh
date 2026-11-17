#!/bin/sh
# Installs the omnodex CLI and writes the post-create step that sets up sealed
# capture once the container's environment (secrets included) is available.
set -e

AGENTS="${AGENTS:-claude-code,codex}"
VERSION="${VERSION:-latest}"

if ! command -v npm >/dev/null 2>&1; then
  echo "omnodex feature: npm is required. Add the node feature (ghcr.io/devcontainers/features/node) first." >&2
  exit 1
fi

# Only agent names and a version string are accepted, so nothing else reaches a shell.
case "$AGENTS" in
  *[!a-z,-]*) echo "omnodex feature: agents must be a comma-separated list of agent names" >&2; exit 1 ;;
esac
case "$VERSION" in
  *[!A-Za-z0-9._-]*) echo "omnodex feature: version must be a version number or tag" >&2; exit 1 ;;
esac

npm install -g "omnodex@${VERSION}"

DIR=/usr/local/share/omnodex-feature
mkdir -p "$DIR"
AGENT_ARGS=$(printf '%s' "$AGENTS" | tr ',' ' ')
cat > "$DIR/post-create.sh" <<EOF
#!/bin/sh
# Runs after the container is created, when secrets are in the environment.
# Without capture settings it does nothing, so a container started without
# them still works.
if [ -z "\$OMNODEX_INGEST_PUBLIC_KEY" ] || [ -z "\$OMNODEX_INGEST_SOURCE_ID" ]; then
  echo "omnodex: OMNODEX_INGEST_PUBLIC_KEY and OMNODEX_INGEST_SOURCE_ID are not set; capture is off" >&2
  exit 0
fi
omnodex install --ephemeral ${AGENT_ARGS} || echo "omnodex: capture setup failed; the container works without it" >&2
exit 0
EOF
chmod 755 "$DIR/post-create.sh"
