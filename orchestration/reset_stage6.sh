#!/usr/bin/env bash
# Reset the Stage 6 VM to its clean snapshot, then start it headless.
# Must run on the machine whose VirtualBox hosts Stage6-VM.
set -euo pipefail
VM="Stage6-VM"
SNAP="clean-state"
command -v VBoxManage >/dev/null || { echo "VBoxManage not found on this machine"; exit 1; }
VBoxManage controlvm "$VM" poweroff 2>/dev/null || true
sleep 3
VBoxManage snapshot "$VM" restore "$SNAP"
VBoxManage startvm "$VM" --type headless
