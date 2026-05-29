#!/bin/sh
# Pre-commit hook that runs ai-surface against the staged changes.
#
# Install:
#   cp examples/integrations/pre-commit-hook.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
#
# Or use with the pre-commit framework (https://pre-commit.com).
#
# By default this is informational. Uncomment the `exit 1` line at the bottom
# to block commits that introduce new risk indicators.

set -e

# Require ai-surface to be installed
if ! command -v ai-surface > /dev/null 2>&1; then
    echo "ai-surface not installed. Install with: pipx install git+https://github.com/apisec-inc/AI-Surface@v0.5.3"
    echo "Skipping pre-commit AI surface check."
    exit 0
fi

# Run a quick scan
SUMMARY=$(ai-surface scan . --quiet)
echo "🔍 $SUMMARY"

# Extract numbers from the summary line
SURFACES=$(echo "$SUMMARY" | sed -E 's/.*ai-surface: ([0-9]+) surfaces.*/\1/')
RISKS=$(echo "$SUMMARY" | sed -E 's/.*surfaces, ([0-9]+) risks.*/\1/')

if [ "$RISKS" -gt 0 ]; then
    echo ""
    echo "⚠️  This commit introduces or includes $RISKS AI surface risk indicator(s)."
    echo "Run 'ai-surface scan .' for details."
    echo ""
    # Uncomment to block commits with risks:
    # exit 1
fi

exit 0
