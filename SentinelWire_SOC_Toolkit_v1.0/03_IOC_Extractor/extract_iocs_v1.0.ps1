param(
    [Parameter(Mandatory=$true)]
    [string]$PcapFile
)

# =========================================================
# SentinelWire™ IOC Extractor (PowerShell + tshark)
# v1.1 — Adds:
#  - Run-folder output (run-YYYYMMDD-HHMMSS)
#  - IOC Confidence Scoring (0–100)
#  - Automatic MITRE ATT&CK Mapping (behavior-based)
# =========================================================

# --- Validate input PCAP ---
if (!(Test-Path $PcapFile)) {
    Write-Host "PCAP file not found: $PcapFile"
    exit 1
}

# --- Validate tshark availability ---
try {
    $null = tshark -v 2>$null
} catch {
    Write-Host "ERROR: tshark is not available in PATH."
    Write-Host "Install Wireshark and ensure tshark.exe is added to PATH, then run: tshark -v"
    exit 1
}

# --- Output folder (run-based) ---
$BaseOut = "C:\IOCs"
New-Item -ItemType Directory -Force -Path $BaseOut | Out-Null

$stamp = (Get-Date -Format "yyyyMMdd-HHmmss")
$OutputDir = Join-Path $BaseOut ("run-" + $stamp)
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Write-Host "Extracting IOCs from: $PcapFile"
Write-Host "Output folder:        $OutputDir"
Write-Host ""

# --------------------
# Helper: run tshark and normalize output
# --------------------
function Run-Tshark {
    param([string[]]$Args)

    $result = & tshark @Args 2>$null
    if ($result) {
        $result |
            Where-Object { $_ -and $_.Trim() -ne "" } |
            ForEach-Object { $_.Trim() } |
            Sort-Object -Unique
    }
}

# --------------------
# IPv4 / IPv6 IPs
# --------------------
$ipv4 = Run-Tshark -Args @(
    "-r", $PcapFile,
    "-T", "fields",
    "-e", "ip.src",
    "-e", "ip.dst"
)
if ($ipv4) { $ipv4 | Out-File -Encoding UTF8 "$OutputDir\ipv4_ips.txt" }

$ipv6 = Run-Tshark -Args @(
    "-r", $PcapFile,
    "-T", "fields",
    "-e", "ipv6.src",
    "-e", "ipv6.dst"
)
if ($ipv6) { $ipv6 | Out-File -Encoding UTF8 "$OutputDir\ipv6_ips.txt" }

# --------------------
# DNS queries (supports both udp/tcp DNS in PCAPs)
# --------------------
$dns = Run-Tshark -Args @(
    "-r", $PcapFile,
    "-Y", "dns.qry.name",
    "-T", "fields",
    "-e", "dns.qry.name"
)
if ($dns) { $dns | Out-File -Encoding UTF8 "$OutputDir\dns_queries.txt" }

# --------------------
# HTTP Host & User-Agent (only if cleartext HTTP exists)
# --------------------
$hosts = Run-Tshark -Args @(
    "-r", $PcapFile,
    "-Y", "http.host",
    "-T", "fields",
    "-e", "http.host"
)
if ($hosts) { $hosts | Out-File -Encoding UTF8 "$OutputDir\http_hosts.txt" }

$userAgents = Run-Tshark -Args @(
    "-r", $PcapFile,
    "-Y", "http.user_agent",
    "-T", "fields",
    "-e", "http.user_agent"
)
if ($userAgents) { $userAgents | Out-File -Encoding UTF8 "$OutputDir\http_user_agents.txt" }

# --------------------
# TLS SNI (covers TLS and legacy SSL field name)
# --------------------
$tlsSNI = Run-Tshark -Args @(
    "-r", $PcapFile,
    "-Y", "tls.handshake.extensions_server_name || ssl.handshake.extensions_server_name",
    "-T", "fields",
    "-e", "tls.handshake.extensions_server_name",
    "-e", "ssl.handshake.extensions_server_name"
)
if ($tlsSNI) { $tlsSNI | Out-File -Encoding UTF8 "$OutputDir\tls_sni.txt" }

# --------------------
# JA3 / JA3S fingerprint (only present if your tshark/Wireshark build exposes these fields)
# --------------------
$ja3 = Run-Tshark -Args @(
    "-r", $PcapFile,
    "-Y", "tls.handshake.ja3 || tls.handshake.ja3s",
    "-T", "fields",
    "-e", "tls.handshake.ja3",
    "-e", "tls.handshake.ja3s"
)
if ($ja3) { $ja3 | Out-File -Encoding UTF8 "$OutputDir\ja3_fingerprints.txt" }

# --------------------
# Base64 payload hunting (triage aid; may include false positives)
# --------------------
$base64 = Run-Tshark -Args @(
    "-r", $PcapFile,
    "-Y", "frame contains \"=\"",
    "-T", "fields",
    "-e", "frame"
)

if ($base64) {
    $b64Candidates = $base64 | Where-Object { $_ -match "[A-Za-z0-9+/]{40,}={0,2}" } | Sort-Object -Unique
    if ($b64Candidates) {
        $b64Candidates |
            Select-Object -First 200 |
            Out-File -Encoding UTF8 "$OutputDir\base64_candidates.txt"
    }
}

# =========================================================
# ADIM 1 + ADIM 2: Confidence Scoring + MITRE Mapping
# =========================================================

function ClampScore([int]$s) {
    if ($s -lt 0) { return 0 }
    if ($s -gt 100) { return 100 }
    return $s
}

# Basic allowlist patterns (extend per environment)
$KnownGoodPatterns = @(
  "google", "gstatic", "doubleclick",
  "microsoft", "windows", "office", "live.com",
  "cloudflare", "akama", "akamai", "amazonaws", "apple", "icloud",
  "mozilla", "letsencrypt", "digicert", "globalsign"
)

function IsKnownGood($ioc) {
    $x = $ioc.ToLower()
    foreach ($p in $KnownGoodPatterns) {
        if ($x.Contains($p)) { return $true }
    }
    return $false
}

function ReadLinesIfExists($path) {
    if (Test-Path $path) {
        return Get-Content $path | Where-Object { $_ -and $_.Trim().Length -gt 0 } | ForEach-Object { $_.Trim() }
    }
    return @()
}

function GetMitreMapping($type, $profiles, $signals, $ioc) {
    $p = ($profiles ?? "").ToLower()
    $s = ($signals ?? "").ToLower()
    $i = ($ioc ?? "").ToLower()

    $mitre = New-Object System.Collections.Generic.List[string]

    # MITM / ARP spoof
    if ($p.Contains("mitm") -or $p.Contains("arp") -or $s.Contains("arp")) {
        $mitre.Add("T1557.002 (ARP Cache Poisoning)")
        $mitre.Add("T1040 (Network Sniffing)")
    }

    # DNS tunneling / DNS-based C2
    if ($p.Contains("dns") -or $type -eq "long_domain" -or $s.Contains("longdns")) {
        $mitre.Add("T1071.004 (DNS C2)")
        $mitre.Add("T1568 (Dynamic Resolution)")
        $mitre.Add("T1048.003 (Exfiltration Over Alternative Protocol)")
    }

    # SYN anomalies / scanning
    if ($p.Contains("syn") -or $s.Contains("syn")) {
        $mitre.Add("T1046 (Network Service Scanning)")
        $mitre.Add("T1018 (Remote System Discovery)")
    }

    # TLS / encrypted channel indicators
    if ($p.Contains("tls") -or $s.Contains("tls")) {
        $mitre.Add("T1573 (Encrypted Channel)")
        $mitre.Add("T1071.001 (Web C2)")
    }

    # Universal umbrella
    if ($p.Contains("universal")) {
        $mitre.Add("T1095 (Non-Application Layer Protocol)")
        $mitre.Add("T1557 (Adversary-in-the-Middle)")
    }

    if ($mitre.Count -eq 0) { return "" }
    return ($mitre | Select-Object -Unique) -join "; "
}

# --- Load extracted data for scoring ---
$dnsQueries = ReadLinesIfExists (Join-Path $OutputDir "dns_queries.txt")
$tlsSni     = ReadLinesIfExists (Join-Path $OutputDir "tls_sni.txt")
$ua         = ReadLinesIfExists (Join-Path $OutputDir "http_user_agents.txt")
$ipv4Hosts  = ReadLinesIfExists (Join-Path $OutputDir "ipv4_ips.txt")
$ipv6Hosts  = ReadLinesIfExists (Join-Path $OutputDir "ipv6_ips.txt")
$b64Hits    = ReadLinesIfExists (Join-Path $OutputDir "base64_candidates.txt")

# Frequency map for persistence (domains appear multiple times)
$freq = @{}
foreach ($d in $dnsQueries) {
    if (-not $freq.ContainsKey($d)) { $freq[$d] = 0 }
    $freq[$d]++
}
foreach ($d in $tlsSni) {
    if (-not $freq.ContainsKey($d)) { $freq[$d] = 0 }
    $freq[$d]++
}

$rows = New-Object System.Collections.Generic.List[Object]

function AddIOCRow($ioc, $type, $profiles, $signals) {
    $iocStr = $ioc.Trim()
    if (-not $iocStr) { return }

    $score = 0

    # A) Persistence (0–30)
    $count = 1
    if ($freq.ContainsKey($iocStr)) { $count = [int]$freq[$iocStr] }
    if ($count -ge 10) { $score += 30 }
    elseif ($count -ge 5) { $score += 20 }
    elseif ($count -ge 2) { $score += 10 }

    # B) Profile correlation (0–40)
    $pCount = ($profiles -split ";").Count
    if ($pCount -ge 3) { $score += 40 }
    elseif ($pCount -eq 2) { $score += 25 }
    elseif ($pCount -eq 1) { $score += 10 }

    # C) Type risk (0–20)
    if ($type -eq "long_domain") { $score += 20 }
    elseif ($type -eq "domain")  { $score += 15 }
    elseif ($type -eq "ip")      { $score += 10 }
    elseif ($type -eq "user_agent") { $score += 8 }
    elseif ($type -eq "base64")  { $score += 12 }

    # D) Known-good reduction (-25)
    if (IsKnownGood $iocStr) { $score -= 25 }

    $score = ClampScore $score
    $mitreTags = GetMitreMapping $type $profiles $signals $iocStr

    $rows.Add([PSCustomObject]@{
        IOC      = $iocStr
        Type     = $type
        Score    = $score
        MITRE    = $mitreTags
        Profiles = $profiles
        Signals  = $signals
    }) | Out-Null
}

# Domains from DNS queries
foreach ($d in $dnsQueries) {
    if ($d.Length -gt 50) {
        AddIOCRow $d "long_domain" "DNS-SUSPECT;UNIVERSAL-DEFENSE" "LongDNS;DNSQuery"
    } else {
        AddIOCRow $d "domain" "DNS-SUSPECT" "DNSQuery"
    }
}

# TLS SNI domains
foreach ($s in $tlsSni) {
    AddIOCRow $s "domain" "TLS-ANOMALY;UNIVERSAL-DEFENSE" "TLS_SNI"
}

# IPs
foreach ($ip in $ipv4Hosts) { AddIOCRow $ip "ip" "RAW" "IPv4Host" }
foreach ($ip in $ipv6Hosts) { AddIOCRow $ip "ip" "RAW" "IPv6Host" }

# User agents
foreach ($u in $ua) { AddIOCRow $u "user_agent" "RAW" "UserAgent" }

# Base64 hits (trim long values for readability)
foreach ($b in $b64Hits) {
    $val = $b
    if ($val.Length -gt 140) { $val = $val.Substring(0,140) + "..." }
    AddIOCRow $val "base64" "UNIVERSAL-DEFENSE" "Base64Candidate"
}

# Export scored outputs
$csvPath = Join-Path $OutputDir "ioc_scored.csv"
$topPath = Join-Path $OutputDir "ioc_scored_top20.txt"
$sumPath = Join-Path $OutputDir "ioc_scored_summary.txt"

$rowsSorted = $rows | Sort-Object Score -Descending
$rowsSorted | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPath

$rowsSorted | Select-Object -First 20 | ForEach-Object {
    "$($_.Score)`t$($_.Type)`t$($_.IOC)`t[$($_.Profiles)]`t{$($_.Signals)}`t<MITRE:$($_.MITRE)>"
} | Out-File -Encoding UTF8 $topPath

"SentinelWire IOC Scoring Summary" | Out-File -Encoding UTF8 $sumPath
"--------------------------------" | Add-Content $sumPath
"Source PCAP: $PcapFile" | Add-Content $sumPath
"Output Dir:  $OutputDir" | Add-Content $sumPath
"Total IOCs:  $($rows.Count)" | Add-Content $sumPath
"" | Add-Content $sumPath
"Top 10:" | Add-Content $sumPath
($rowsSorted | Select-Object -First 10 | ForEach-Object { "$($_.Score) - $($_.IOC) - $($_.MITRE)" }) | Add-Content $sumPath

Write-Host ""
Write-Host "---------------------------------------------"
Write-Host "✓ IOC extraction completed."
Write-Host "Raw files (if any data was found):"
Write-Host "  $OutputDir\ipv4_ips.txt"
Write-Host "  $OutputDir\ipv6_ips.txt"
Write-Host "  $OutputDir\dns_queries.txt"
Write-Host "  $OutputDir\http_hosts.txt"
Write-Host "  $OutputDir\http_user_agents.txt"
Write-Host "  $OutputDir\tls_sni.txt"
Write-Host "  $OutputDir\ja3_fingerprints.txt"
Write-Host "  $OutputDir\base64_candidates.txt"
Write-Host ""
Write-Host "Scored outputs:"
Write-Host "  $OutputDir\ioc_scored.csv"
Write-Host "  $OutputDir\ioc_scored_top20.txt"
Write-Host "  $OutputDir\ioc_scored_summary.txt"
Write-Host "---------------------------------------------"
