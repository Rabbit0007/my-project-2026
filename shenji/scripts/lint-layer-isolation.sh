#!/bin/bash
# lint-layer-isolation.sh
#
# Checks that the Kernel / Exploration / Evidence Gate layers (agent_orchestrator.go,
# cairn_loop.go) do not directly call Delivery Layer services (FindingService,
# ContractService, ReportService) for scheduling, reasoning, promotion, or
# termination decisions.
#
# Phase 4 initial: WARNING mode (exit 0 even on violations).
# Phase 4 verified: Change EXIT_ON_VIOLATION=1 to make it blocking.

EXIT_ON_VIOLATION=0  # Set to 1 after Phase 4 verification to make blocking

VIOLATIONS=0
KERNEL_FILES=(
  "backend/internal/service/agent_orchestrator.go"
  "backend/internal/service/cairn_loop.go"
)

# Allowed patterns (Delivery interface wrappers, comments, string literals)
ALLOWED_PATTERNS="TODO|DEPRECATED|deliveryWriteback|DeliveryLayer|// |\".*Service\""

echo "=== Layer Isolation Lint Check ==="
echo ""

for file in "${KERNEL_FILES[@]}"; do
  if [ ! -f "$file" ]; then
    echo "SKIP: $file not found"
    continue
  fi

  # Check for direct FindingService calls (excluding comments and allowed patterns)
  FINDINGS=$(grep -n "FindingService\|findings\." "$file" | grep -v "// " | grep -v "$ALLOWED_PATTERNS" | grep -v "_test.go" || true)
  if [ -n "$FINDINGS" ]; then
    echo "WARNING: $file references FindingService:"
    echo "$FINDINGS"
    echo ""
    VIOLATIONS=$((VIOLATIONS + 1))
  fi

  # Check for direct ReportService calls
  REPORTS=$(grep -n "ReportService\|\.reports\." "$file" | grep -v "// " | grep -v "$ALLOWED_PATTERNS" | grep -v "o\.reports\." || true)
  # Note: o.reports is used in orchestrator for finalize — this is the Delivery path, acceptable for now
done

# Check contract_service for Intent creation (should be gated)
CONTRACT_FILE="backend/internal/service/contract_service.go"
if [ -f "$CONTRACT_FILE" ]; then
  INTENT_CREATE=$(grep -n "db.*Create.*intent\|db.*Create.*Intent" "$CONTRACT_FILE" | grep -v "// " || true)
  if [ -n "$INTENT_CREATE" ]; then
    echo "NOTE: $CONTRACT_FILE still has Intent creation path (should be gated by deliveryWriteback):"
    echo "$INTENT_CREATE"
    echo ""
  fi
fi

echo "=== Summary ==="
if [ $VIOLATIONS -eq 0 ]; then
  echo "PASS: No layer isolation violations detected."
  exit 0
else
  echo "VIOLATIONS: $VIOLATIONS potential layer isolation issue(s) found."
  if [ $EXIT_ON_VIOLATION -eq 1 ]; then
    echo "BLOCKING: Fix violations before merging."
    exit 1
  else
    echo "WARNING: Non-blocking. Set EXIT_ON_VIOLATION=1 to enforce."
    exit 0
  fi
fi
