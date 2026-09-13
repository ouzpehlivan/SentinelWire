# SentinelWire™ Profile Builder v1.1 (One-Command Installer)

This package installs **all SentinelWire™ Wireshark profiles** and automatically personalizes them
using your workstation and router IP/MAC values.

## What this package contains
- `make_ws_profile.bat` — one-command installer + placeholder replacement
- `profiles/` — Wireshark profile template folders (SentinelWire™)
  - UNIVERSAL-DEFENSE
  - MITM-MASTER, ARP-SPOOF
  - DNS-SUSPECT, LONG-DNS
  - SYN-WEIRD, TLS-ANOMALY
  - TO-ME-NONROUTER
  - BEACON-TIME, SMB-LATERAL, LLMNR-SUSPECT

## Requirements
- Windows
- Wireshark installed
- Windows PowerShell available (pre-installed on most systems)

## Install / Run (Windows)
1. Extract the ZIP anywhere (e.g., Desktop)
2. Double-click: `make_ws_profile.bat`
3. Enter:
   - Your workstation IP
   - Router / Default gateway IP
   - Your workstation MAC
   - Router MAC

The installer will:
- Copy profiles into: `%APPDATA%\Wireshark\profiles\`
- Replace placeholders across the profile files:
  - `{{USER_IP}}`, `{{ROUTER_IP}}`, `{{USER_MAC}}`, `{{ROUTER_MAC}}`

## Verify in Wireshark
1. Open Wireshark
2. Go to: **Edit → Configuration Profiles**
3. Select a profile (e.g., `UNIVERSAL-DEFENSE`)
4. Start capture and test the prebuilt display filter presets:
   - **Analyze → Display Filter Expressions** (or use the filter bar)

## Troubleshooting
### ARP table doesn’t show router MAC
Run:
- `ping <router_ip>`
- then `arp -a` and find the entry for your router IP.

### Nothing appears in Wireshark after install
Confirm profiles exist here:
- `%APPDATA%\Wireshark\profiles\UNIVERSAL-DEFENSE\`

### Placeholder values didn’t change
Re-run `make_ws_profile.bat` and ensure all inputs are provided (no blanks).

## Notes
- The profile templates are lightweight and designed for SOC triage + pivoting.
- Coloring rules may be interpreted slightly differently across Wireshark versions; the
  display filter presets remain fully usable.

---
SentinelWire™ — Wireshark-driven SOC investigation workflow.
