#!/bin/bash
# Azure Security Remediation Script
# Scans a resource group for common misconfigurations and remediates them
# Usage: ./remediate.sh <resource-group-name>

RG=$1

if [ -z "$RG" ]; then
  echo "Usage: ./remediate.sh <resource-group-name>"
  exit 1
fi

echo "=========================================="
echo "Starting security remediation for: $RG"
echo "=========================================="

# --- 1. Storage Accounts: disable public blob access + enforce HTTPS ---
echo ""
echo "[1/3] Scanning storage accounts..."
STORAGE_ACCOUNTS=$(az storage account list --resource-group "$RG" --query "[].name" -o tsv)

for SA in $STORAGE_ACCOUNTS; do
  PUBLIC_ACCESS=$(az storage account show --name "$SA" --resource-group "$RG" --query "allowBlobPublicAccess" -o tsv)
  HTTPS_ONLY=$(az storage account show --name "$SA" --resource-group "$RG" --query "enableHttpsTrafficOnly" -o tsv)

  if [ "$PUBLIC_ACCESS" == "true" ]; then
    echo "  [FINDING] $SA allows public blob access — remediating..."
    az storage account update --name "$SA" --resource-group "$RG" --allow-blob-public-access false --output none
    echo "  [FIXED] Public blob access disabled on $SA"
  else
    echo "  [OK] $SA — public access already disabled"
  fi

  if [ "$HTTPS_ONLY" == "false" ]; then
    echo "  [FINDING] $SA does not require secure transfer — remediating..."
    az storage account update --name "$SA" --resource-group "$RG" --https-only true --output none
    echo "  [FIXED] Secure transfer enforced on $SA"
  else
    echo "  [OK] $SA — secure transfer already enforced"
  fi
done

# --- 2. NSGs: remove inbound rules open to the internet on 22/3389 ---
echo ""
echo "[2/3] Scanning network security groups..."
NSGS=$(az network nsg list --resource-group "$RG" --query "[].name" -o tsv)

for NSG in $NSGS; do
  RULES=$(az network nsg rule list --resource-group "$RG" --nsg-name "$NSG" \
    --query "[?access=='Allow' && direction=='Inbound' && (destinationPortRange=='22' || destinationPortRange=='3389') && (sourceAddressPrefix=='*' || sourceAddressPrefix=='0.0.0.0/0' || sourceAddressPrefix=='Internet')].name" -o tsv)

  for RULE in $RULES; do
    echo "  [FINDING] $NSG has open management port rule: $RULE — removing..."
    az network nsg rule delete --resource-group "$RG" --nsg-name "$NSG" --name "$RULE"
    echo "  [FIXED] Removed $RULE from $NSG"
  done

  if [ -z "$RULES" ]; then
    echo "  [OK] $NSG — no open management port rules found"
  fi
done

# --- 3. Subscription-level: flag over-privileged role assignments ---
echo ""
echo "[3/3] Scanning for over-privileged role assignments..."
OWNERS=$(az role assignment list --role "Owner" --query "[].principalName" -o tsv)
OWNER_COUNT=$(echo "$OWNERS" | grep -c .)

if [ "$OWNER_COUNT" -gt 1 ]; then
  echo "  [FINDING] $OWNER_COUNT principals hold Owner role at subscription scope (manual review required):"
  echo "$OWNERS" | sed 's/^/    - /'
else
  echo "  [OK] Owner role assignment count within expected range"
fi

echo ""
echo "=========================================="
echo "Remediation scan complete for: $RG"
echo "=========================================="
