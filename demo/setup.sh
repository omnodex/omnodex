#!/usr/bin/env bash
#
# Demo setup script. Run from the omnodex root:
#
#   ./demo/setup.sh
#
# What it does:
#   1. Builds Omnodex (npm install + tsc)
#   2. Clears any prior demo data from OMNODEX_HOME
#   3. Installs Omnodex hooks into the demo project
#
# After running this, start the mock API server in a separate terminal:
#
#   node demo/api-server.js
#
# Then open the demo project in Claude Code and give it the demo prompt.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OMNODEX_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DEMO_PROJECT="$SCRIPT_DIR/project"
export OMNODEX_HOME="${OMNODEX_HOME:-$HOME/.omnodex}"

echo "=== Omnodex Demo Setup ==="
echo ""
echo "  Omnodex:      $OMNODEX_DIR"
echo "  Demo project: $DEMO_PROJECT"
echo "  OMNODEX_HOME: $OMNODEX_HOME"
echo ""

# 1. Build
echo "[1/3] Building Omnodex..."
cd "$OMNODEX_DIR"
npm install --silent
npx tsc -b
echo "  done."

# 2. Clear prior demo data
echo "[2/3] Clearing prior demo data..."
node packages/cli/dist/index.js clear --all --confirm
echo "  done."

# 3. Install hooks
echo "[3/3] Installing Omnodex hooks into demo project..."
node packages/cli/dist/index.js init "$DEMO_PROJECT"
echo ""

echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Start the mock API:      node demo/api-server.js"
echo "  2. Open Claude Code:        cd demo/project && claude"
echo "  3. Give it this prompt:"
echo ""
echo '     "Run the customer enrichment pipeline as described in the README."'
echo ""
echo "  4. After the session, view results:"
echo "     node packages/cli/dist/index.js detect"
echo "     node packages/cli/dist/index.js dashboard"
echo "     # Open http://localhost:7890"
