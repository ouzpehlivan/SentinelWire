SentinelWire SOC Toolkit v1.0
SentinelWire profiles are not isolated filters - they form a cohesive SOC-grade investigative 
methodology, designed to mirror real incident response workflows.

SentinelWire Wireshark Profiles - Descriptions

1.UNIVERSAL-DEFENSE.profile - What it is
This profile is designed as a: "First-click SOC triage profile"
It serves as the initial analytical lens for any unknown PCAP, surfacing high-confidence 
anomalies before deeper investigation.

It conceptually combines all SentinelWire detection logic:
*MITM indicators
*ARP spoofing behavior
*DNS hijacking & tunneling
*Long DNS / DGA-style domains
*SYN scan anomalies
*TLS / encrypted traffic irregularities

Workflow philosophy:
1.Open PCAP › apply UNIVERSAL-DEFENSE
2.Identify dominant anomaly class
3.Pivot into specialized profiles:
	MITM-MASTER
	DNS-SUSPECT
	ARP-SPOOF
	SYN-WEIRD
	etc.
This profile mirrors Tier-1 SOC triage workflows, prioritizing speed, visibility, and 
escalation accuracy.

2.MITM-MASTER.profile - What it is
This profile is designed as a: "Man-in-the-Middle detection & validation profile"
It focuses on identifying traffic interception, relay, or manipulation occurring within the 
local network.

Key detection themes:
*Suspicious ARP reply patterns
*Traffic routed through unexpected MAC addresses
*TLS sessions with abnormal resets or retransmissions
*Non-router devices acting as transit points

Workflow philosophy:
1.Confirm MITM suspicion from UNIVERSAL-DEFENSE
2.Apply MITM-MASTER
3.Validate attacker position and scope
4.Identify victim - interceptor - gateway relationships
This profile is essential for insider threat, rogue device, and evil twin investigations.

3.ARP-SPOOF.profile - What it is
This profile is designed as a: "Layer-2 ARP poisoning detection profile"
It isolates ARP-level manipulation, often preceding MITM or session hijacking attacks.

Key detection themes:
*Duplicate IP-to-MAC mappings
*Unsolicited ARP replies
*ARP responses claiming router identity
*MAC address churn for critical IPs

Workflow philosophy:
1.Identify ARP anomalies
2.Confirm spoofed IP/MAC relationships
3.Map affected hosts
4.Escalate to MITM-MASTER if traffic interception is observed
This profile is critical for early-stage compromise detection.

4.DNS-SUSPECT.profile - What it is
This profile is designed as a: "DNS hijacking & resolver abuse detection profile"
It focuses on DNS-based redirection, manipulation, and tunneling, which frequently 
enable malware command-and-control.

Key detection themes:
*Unknown or unauthorized DNS resolvers
*Suspicious DNS responses from public resolvers
*DNS replies inconsistent with network policy
*Encrypted DNS misuse indicators

Workflow philosophy:
1.Detect abnormal DNS resolution behavior
2.Validate resolver legitimacy
3.Identify redirection or poisoning attempts
4.Block malicious domains and reset DNS configuration
This profile supports rapid containment of DNS-based threats.

5.LONG-DNS.profile - What it is
This profile is designed as a: "DNS tunneling & data exfiltration detection profile"
It highlights abnormally long DNS query names, commonly associated with covert channels 
and DGA malware.

Key detection themes:
*Excessive DNS query length
*High-entropy subdomains
*Repetitive encoded patterns (Base64-like)
*Unusual DNS query frequency

Workflow philosophy:
1.Identify suspicious DNS payload structures
2.Assess likelihood of tunneling or DGA usage
3.Extract domains for IOC analysis
4.Correlate with endpoint behavior
This profile is essential for stealthy exfiltration detection.

6. SYN-WEIRD.profile - What it is
This profile is designed as a: "TCP anomaly & scanning behavior detection profile"
It focuses on abnormal TCP handshake patterns, often associated with reconnaissance or 
exploitation.

Key detection themes:
*Excessive SYN packets
*Incomplete handshakes
*SYN retransmissions
*Unusual port-scanning behavior

Workflow philosophy:
1.Detect TCP handshake anomalies
2.Identify scanning or probing sources
3.Map targeted services
4.Correlate with external threat intelligence
This profile supports early attack surface discovery.

7. TO-ME-NONROUTER.profile - What it is
This profile is designed as a: "Illicit traffic routing detection profile"
It identifies situations where non-router devices receive traffic that should only reach 
gateways or infrastructure nodes.

Key detection themes:
*Traffic destined for endpoints acting as routers
*Unexpected MAC addresses in routing paths
*Network topology violations
*Lateral movement indicators

Workflow philosophy:
1.Identify non-router traffic interception
2.Validate network role violations
3.Escalate to MITM-MASTER or ARP-SPOOF
4.Contain rogue routing behavior
This profile is powerful for rogue device detection.

