#!/bin/bash
# Coverage verification script for vmrunner-macos-rs.
#
# Runs tarpaulin to generate coverage report and verifies 80%+ target.
#
# Usage:
#   ./scripts/coverage.sh                    # Run coverage check
#   ./scripts/coverage.sh --html            # Generate HTML report
#   ./scripts/coverage.sh --open           # Generate and open HTML report
#
# Requirements:
#   - cargo-tarpaulin: cargo install cargo-tarpaulin
#   - lcov (for HTML reports): brew install lcov

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
OUTPUT_FORMAT="terminal"
OPEN_REPORT=false

for arg in "$@"; do
    case $arg in
        --html)
            OUTPUT_FORMAT="html"
            ;;
        --open)
            OUTPUT_FORMAT="html"
            OPEN_REPORT=true
            ;;
        *)
            echo "Unknown argument: $arg"
            echo "Usage: $0 [--html] [--open]"
            exit 1
            ;;
    esac
done

# Navigate to script directory
cd "$(dirname "$0")/.."

echo "Running coverage analysis for vmrunner-macos-rs..."
echo

# Run tarpaulin
if [ "$OUTPUT_FORMAT" = "html" ]; then
    echo "Generating HTML coverage report..."

    cargo tarpaulin --package vmrunner-macos-rs \
        --out Html \
        --output-dir target/coverage \
        --timeout 300 \
        --exclude-files "*/tests/*" \
        --exclude-files "*/benches/*" \
        --exclude-files "*/src/bin/*" \
        -- --test-threads=1

    echo
    echo "HTML report generated at: target/coverage/index.html"

    if [ "$OPEN_REPORT" = true ]; then
        echo "Opening report in browser..."
        open target/coverage/index.html
    fi
else
    echo "Generating terminal coverage report..."

    COVERAGE_OUTPUT=$(cargo tarpaulin --package vmrunner-macos-rs \
        --out Stdout \
        --timeout 300 \
        --exclude-files "*/tests/*" \
        --exclude-files "*/benches/*" \
        --exclude-files "*/src/bin/*" \
        -- --test-threads=1 2>&1)

    echo "$COVERAGE_OUTPUT"
    echo

    # Extract coverage percentage from output
    COVERAGE_PCT=$(echo "$COVERAGE_OUTPUT" | grep -oP '\d+\.\d+(?=%)' || echo "0.0")

    # Convert to integer for comparison
    COVERAGE_INT=$(echo "$COVERAGE_PCT" | cut -d. -f1)

    echo
    echo "======================================"
    echo "Coverage: ${COVERAGE_PCT}%"
    echo "Target:   80.0%"
    echo "======================================"
    echo

    # Check if coverage meets target
    if [ "$COVERAGE_INT" -lt 80 ]; then
        echo -e "${RED}❌ Coverage below 80% target${NC}"
        echo
        echo "To see detailed coverage:"
        echo "  $0 --html"
        echo
        exit 1
    else
        echo -e "${GREEN}✅ Coverage meets 80% target${NC}"
        echo
        exit 0
    fi
fi
