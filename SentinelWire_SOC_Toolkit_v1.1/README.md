# SentinelWire™ Wireshark Profiles (v1.1)

This package contains **template Wireshark profile folders** for SentinelWire™.

## Included profiles
- UNIVERSAL-DEFENSE
- MITM-MASTER
- ARP-SPOOF
- DNS-SUSPECT
- LONG-DNS
- SYN-WEIRD
- TLS-ANOMALY
- TO-ME-NONROUTER
- BEACON-TIME
- SMB-LATERAL
- LLMNR-SUSPECT

## Personalization placeholders
Some display filters include placeholders you can replace with your environment values:

- {{USER_IP}}  → Analyst workstation IP
- {{ROUTER_IP}} → Default gateway / router IP
- {{USER_MAC}} → Analyst workstation MAC
- {{ROUTER_MAC}} → Router MAC

> Tip: If you already collected these values via `make_ws_profile.bat`, replace the placeholders globally in the profile files.

## Install (Windows)
1. Close Wireshark
2. Open this folder: `%APPDATA%\Wireshark\profiles\`
3. Copy each profile folder from:
   `profiles\<PROFILE_NAME>`
   into:
   `%APPDATA%\Wireshark\profiles\<PROFILE_NAME>`
4. Re-open Wireshark and select the profile from:
   **Edit → Configuration Profiles**

## Usage (SentinelWire workflow)
1. Start with **UNIVERSAL-DEFENSE** for first-click triage (30–60s capture)
2. Run IOC extractor and review `ioc_scored_top20.txt`
3. Pivot to specialized profiles:
   - MITM indicators → **MITM-MASTER** / **ARP-SPOOF**
   - DNS anomalies → **DNS-SUSPECT** / **LONG-DNS**
   - Recon patterns → **SYN-WEIRD**
   - TLS anomalies → **TLS-ANOMALY**
   - Lateral movement → **SMB-LATERAL** / **LLMNR-SUSPECT**
   - Beaconing candidates → **BEACON-TIME**

## Notes
- Wireshark may ignore color filters if the format differs by version. Display filter presets remain usable.
- These profiles are intentionally lightweight and SOC-friendly.
