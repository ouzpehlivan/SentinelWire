param(
    [Parameter(Mandatory=$true)]
    [string]$PcapFile,

    [Parameter(Mandatory=$false)]
    [string]$BaseOut = "C:\IOCs"
)

# =========================================================
# SentinelWire™ IOC Extractor (PowerShell + tshark)
# v1.1.1 — Adds:
#  - Run-folder output (run-YYYYMMDD-HHMMSS)
#  - IOC Confidence Scoring (0–100)
#  - Automatic MITRE ATT&CK Mapping (behavior-based)
#  - Time-Based Beaconing Detection (DNS + TLS SNI)
#  - Lateral Movement Signals (SMB / LLMNR / NBNS)
#
# Compatibility: Windows PowerShell 5.1+ (no PS7-only operators)
# =========================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function SafeStr($x) {
    if ($null -eq $x) { return "" }
    return [string]$x
}

# --- Validate input PCAP ---
if (!(Test-Path $PcapFile)) {
    Write-Host "PCAP file not found: $PcapFile"
    exit 1
}

# --- Validate tshark availability ---
try {
    $null = tshark -v 2>$null
} catch {
    Write-Host "tshark not found. Please install Wireshark (includes tshark) and ensure tshark is in PATH."
    exit 1
}

# --- Output folder (run-based) ---
New-Item -ItemType Directory -Force -Path $BaseOut | Out-Null
$stamp = (Get-Date -Format "yyyyMMdd-HHmmss")
$OutputDir = Join-Path $BaseOut ("run-" + $stamp)
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Write-Host "Extracting IOCs from: $PcapFile"
Write-Host "Output folder:        $OutputDir"
Write-Host ""

# --------------------
# Helpers
# --------------------
function _TrimNonEmpty([string[]]$lines) {
    if (-not $lines) { return @() }
    return $lines | Where-Object { $_ -and $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
}

function Run-TsharkUnique {
    param([string[]]$Args)
    try {
        $result = & tshark @Args 2>$null
        return (_TrimNonEmpty $result) | Sort-Object -Unique
    } catch { return @() }
}

function Run-TsharkRaw {
    param([string[]]$Args)
    try {
        $result = & tshark @Args 2>$null
        return (_TrimNonEmpty $result)
    } catch { return @() }
}

function WriteList([string]$Path, [string[]]$Lines) {
    ($Lines | Sort-Object -Unique) | Out-File -Encoding utf8 -FilePath $Path
}

function ClampScore([int]$n) {
    if ($n -lt 0) { return 0 }
    if ($n -gt 100) { return 100 }
    return $n
}

function IsPrivateIP([string]$ip) {
    if (-not $ip) { return $false }
    $x = $ip.Trim().ToLower()

    # IPv6 ULA
    if ($x.StartsWith("fc") -or $x.StartsWith("fd")) { return $true }

    # IPv4 RFC1918
    if ($x -match '^(10\.)') { return $true }
    if ($x -match '^(192\.168\.)') { return $true }
    if ($x -match '^(172\.(1[6-9]|2\d|3[0-1])\.)') { return $true }

    return $false
}

# --------------------
# Extract core artifacts (unique lists for readability)
# --------------------
# IPv4 / IPv6 endpoints
$ipv4HostsRaw = Run-TsharkUnique @("-r", $PcapFile, "-T", "fields", "-e", "ip.src")
$ipv4DstRaw   = Run-TsharkUnique @("-r", $PcapFile, "-T", "fields", "-e", "ip.dst")
$ipv4Hosts = ($ipv4HostsRaw + $ipv4DstRaw) | Where-Object { $_ -and $_ -notmatch ":" } | Sort-Object -Unique

$ipv6HostsRaw = Run-TsharkUnique @("-r", $PcapFile, "-T", "fields", "-e", "ipv6.src")
$ipv6DstRaw   = Run-TsharkUnique @("-r", $PcapFile, "-T", "fields", "-e", "ipv6.dst")
$ipv6Hosts = ($ipv6HostsRaw + $ipv6DstRaw) | Where-Object { $_ -and $_ -match ":" } | Sort-Object -Unique

# DNS / HTTP / TLS / JA3
$dnsQueriesUnique = Run-TsharkUnique @("-r", $PcapFile, "-Y", "dns.qry.name", "-T", "fields", "-e", "dns.qry.name")
$httpHosts        = Run-TsharkUnique @("-r", $PcapFile, "-Y", "http.host", "-T", "fields", "-e", "http.host")
$httpUserAgents   = Run-TsharkUnique @("-r", $PcapFile, "-Y", "http.user_agent", "-T", "fields", "-e", "http.user_agent")
$tlsSniUnique     = Run-TsharkUnique @("-r", $PcapFile, "-Y", "tls.handshake.extensions_server_name", "-T", "fields", "-e", "tls.handshake.extensions_server_name")

# JA3 is not always available. Keep best-effort.
$ja3 = Run-TsharkUnique @("-r", $PcapFile, "-Y", "tls.handshake", "-T", "fields", "-e", "tls.handshake.ja3")
if (-not $ja3 -or $ja3.Count -eq 0) {
    $ja3 = Run-TsharkUnique @("-r", $PcapFile, "-Y", "tls.handshake", "-T", "fields", "-e", "ja3")
}

# Base64 candidates (heuristic)
$rawPayloads = Run-TsharkRaw @("-r", $PcapFile, "-T", "fields", "-e", "data.data")
$b64Candidates = @()
if ($rawPayloads) {
    foreach ($line in $rawPayloads) {
        try {
            $hex = $line -replace ":", ""
            if ($hex.Length -lt 32 -or $hex.Length -gt 2000) { continue }
            $bytes = for ($i=0; $i -lt $hex.Length; $i+=2) { [Convert]::ToByte($hex.Substring($i,2),16) }
            $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
            if ($ascii -match '([A-Za-z0-9+/]{24,}={0,2})') {
                $hit = $Matches[1]
                if ($hit -and $hit.Length -ge 24) { $b64Candidates += $hit }
            }
        } catch { }
    }
}
$b64Candidates = $b64Candidates | Sort-Object -Unique

# Write raw outputs
WriteList (Join-Path $OutputDir "ipv4_ips.txt") $ipv4Hosts
WriteList (Join-Path $OutputDir "ipv6_ips.txt") $ipv6Hosts
WriteList (Join-Path $OutputDir "dns_queries.txt") $dnsQueriesUnique
WriteList (Join-Path $OutputDir "http_hosts.txt") $httpHosts
WriteList (Join-Path $OutputDir "http_user_agents.txt") $httpUserAgents
WriteList (Join-Path $OutputDir "tls_sni.txt") $tlsSniUnique
WriteList (Join-Path $OutputDir "ja3_fingerprints.txt") $ja3
WriteList (Join-Path $OutputDir "base64_candidates.txt") $b64Candidates

# --------------------
# Time-Based Beaconing Detection (DNS + TLS SNI)
# Build timestamped event stream: "<epoch>\t<dest>"
# --------------------
$beaconEvents = New-Object System.Collections.Generic.List[Object]

# DNS time series
$dnsTimed = Run-TsharkRaw @("-r", $PcapFile, "-Y", "dns.qry.name", "-T", "fields", "-e", "frame.time_epoch", "-e", "dns.qry.name", "-E", "separator=`t")
foreach ($l in $dnsTimed) {
    $parts = $l -split "`t", 2
    if ($parts.Count -ne 2) { continue }
    $t = $parts[0].Trim()
    $d = $parts[1].Trim()
    if (-not $t -or -not $d) { continue }
    [double]$te = 0
    if (-not [double]::TryParse($t, [ref]$te)) { continue }
    $beaconEvents.Add([PSCustomObject]@{ Protocol="DNS"; Destination=$d; TimeEpoch=$te }) | Out-Null
}

# TLS SNI time series
$tlsTimed = Run-TsharkRaw @("-r", $PcapFile, "-Y", "tls.handshake.extensions_server_name", "-T", "fields", "-e", "frame.time_epoch", "-e", "tls.handshake.extensions_server_name", "-E", "separator=`t")
foreach ($l in $tlsTimed) {
    $parts = $l -split "`t", 2
    if ($parts.Count -ne 2) { continue }
    $t = $parts[0].Trim()
    $d = $parts[1].Trim()
    if (-not $t -or -not $d) { continue }
    [double]$te = 0
    if (-not [double]::TryParse($t, [ref]$te)) { continue }
    $beaconEvents.Add([PSCustomObject]@{ Protocol="TLS"; Destination=$d; TimeEpoch=$te }) | Out-Null
}

# Calculate beacon metrics per protocol+destination
$beaconMetrics = @{}  # key: "DNS|dest" or "TLS|dest"
if ($beaconEvents.Count -gt 0) {
    $groups = $beaconEvents | Group-Object Protocol, Destination
    foreach ($g in $groups) {
        $events = $g.Group | Sort-Object TimeEpoch
        $count = $events.Count
        if ($count -lt 5) { continue }  # minimum sample size

        $times = $events | Select-Object -ExpandProperty TimeEpoch

        $intervals = @()
        for ($i=1; $i -lt $times.Count; $i++) {
            $intervals += ([double]$times[$i] - [double]$times[$i-1])
        }
        if ($intervals.Count -lt 1) { continue }

        $avg = ($intervals | Measure-Object -Average).Average
        $sumSq = 0.0
        foreach ($x in $intervals) { $sumSq += (($x - $avg) * ($x - $avg)) }
        $std = [math]::Sqrt($sumSq / $intervals.Count)

        $durationMin = ([double]$times[-1] - [double]$times[0]) / 60.0

        # Beacon scoring (0–100)
        $bScore = 0
        if ($count -ge 10) { $bScore += 30 }
        elseif ($count -ge 5) { $bScore += 20 }

        if ($std -lt 5) { $bScore += 40 }
        elseif ($std -lt 15) { $bScore += 25 }
        elseif ($std -lt 30) { $bScore += 10 }

        if ($durationMin -gt 10) { $bScore += 30 }
        elseif ($durationMin -gt 5) { $bScore += 15 }

        $bScore = ClampScore $bScore
        $flag = ($bScore -ge 70)

        $proto = $events[0].Protocol
        $dest  = $events[0].Destination
        $key = "$proto|$dest"
        $beaconMetrics[$key] = [PSCustomObject]@{
            BeaconScore     = $bScore
            BeaconFlag      = $flag
            AvgIntervalSec  = [math]::Round($avg, 2)
            IntervalStdDev  = [math]::Round($std, 2)
            FirstSeenEpoch  = [math]::Round([double]$times[0], 3)
            LastSeenEpoch   = [math]::Round([double]$times[-1], 3)
            BeaconCount     = $count
        }
    }
}

# --------------------
# Lateral Movement Signals (SMB / LLMNR / NBNS)
# --------------------
$lateral = New-Object System.Collections.Generic.List[Object]

# SMB flows (IPv4 + IPv6 best effort)
$smbFlows4 = Run-TsharkRaw @("-r", $PcapFile, "-Y", "tcp.port==445 && ip.src && ip.dst", "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-E", "separator=`t")
foreach ($l in $smbFlows4) {
    $p = $l -split "`t", 2
    if ($p.Count -ne 2) { continue }
    $src=$p[0].Trim(); $dst=$p[1].Trim()
    if (-not (IsPrivateIP $src) -or -not (IsPrivateIP $dst)) { continue }
    if ($src -eq $dst) { continue }
    $lateral.Add([PSCustomObject]@{ Type="lateral_smb"; IOC="$src->$dst"; Profiles="SMB-LATERAL"; Signals="SMB" }) | Out-Null
}
$smbFlows6 = Run-TsharkRaw @("-r", $PcapFile, "-Y", "tcp.port==445 && ipv6.src && ipv6.dst", "-T", "fields", "-e", "ipv6.src", "-e", "ipv6.dst", "-E", "separator=`t")
foreach ($l in $smbFlows6) {
    $p = $l -split "`t", 2
    if ($p.Count -ne 2) { continue }
    $src=$p[0].Trim(); $dst=$p[1].Trim()
    if (-not (IsPrivateIP $src) -or -not (IsPrivateIP $dst)) { continue }
    if ($src -eq $dst) { continue }
    $lateral.Add([PSCustomObject]@{ Type="lateral_smb"; IOC="$src->$dst"; Profiles="SMB-LATERAL"; Signals="SMB" }) | Out-Null
}

# LLMNR queries
$llmnr = Run-TsharkRaw @("-r", $PcapFile, "-Y", "llmnr.qry.name && ip.src", "-T", "fields", "-e", "ip.src", "-e", "llmnr.qry.name", "-E", "separator=`t")
foreach ($l in $llmnr) {
    $p = $l -split "`t", 2
    if ($p.Count -ne 2) { continue }
    $src=$p[0].Trim(); $q=$p[1].Trim()
    if (-not (IsPrivateIP $src)) { continue }
    if (-not $q) { continue }
    $lateral.Add([PSCustomObject]@{ Type="lateral_llmnr"; IOC="$src|$q"; Profiles="LLMNR-SUSPECT"; Signals="LLMNR" }) | Out-Null
}

# NBNS queries (field names vary; try a couple)
$nbns1 = Run-TsharkRaw @("-r", $PcapFile, "-Y", "nbns && ip.src && nbns.name", "-T", "fields", "-e", "ip.src", "-e", "nbns.name", "-E", "separator=`t")
$nbns2 = Run-TsharkRaw @("-r", $PcapFile, "-Y", "nbns && ip.src && nbns.qry.name", "-T", "fields", "-e", "ip.src", "-e", "nbns.qry.name", "-E", "separator=`t")
$nbnsAll = @()
if ($nbns1) { $nbnsAll += $nbns1 }
if ($nbns2) { $nbnsAll += $nbns2 }

foreach ($l in $nbnsAll) {
    $p = $l -split "`t", 2
    if ($p.Count -ne 2) { continue }
    $src=$p[0].Trim(); $q=$p[1].Trim()
    if (-not (IsPrivateIP $src)) { continue }
    if (-not $q) { continue }
    $lateral.Add([PSCustomObject]@{ Type="lateral_nbns"; IOC="$src|$q"; Profiles="LLMNR-SUSPECT"; Signals="NBNS" }) | Out-Null
}

# --------------------
# Scoring & MITRE mapping helpers
# --------------------
$KnownGoodPatterns = @(
  "google", "gstatic", "microsoft", "msft", "windowsupdate", "office365",
  "cloudflare", "akama", "akamai", "amazonaws", "apple", "icloud",
  "mozilla", "letsencrypt", "digicert", "globalsign"
)

function IsKnownGood($ioc) {
    $x = (SafeStr $ioc).ToLower()
    foreach ($p in $KnownGoodPatterns) {
        if ($x.Contains($p)) { return $true }
    }
    return $false
}

function GetMitreMapping($type, $profiles, $signals, $ioc) {
    $p = (SafeStr $profiles).ToLower()
    $s = (SafeStr $signals).ToLower()
    $i = (SafeStr $ioc).ToLower()

    $mitre = New-Object System.Collections.Generic.List[string]

    # Beaconing / application protocols (behavioral)
    if ($s.Contains("beacon")) {
        $mitre.Add("T1071.001 (Application Layer Protocol: Web)")
        $mitre.Add("T1071.004 (Application Layer Protocol: DNS)")
        $mitre.Add("T1573 (Encrypted Channel)")
    }

    # DNS tunneling / suspicious DNS
    if ($p.Contains("dns") -or $s.Contains("dns")) {
        if ($type -eq "long_domain") { $mitre.Add("T1071.004 (DNS)") }
    }

    # MITM / ARP spoof (profile-driven)
    if ($p.Contains("mitm") -or $p.Contains("arp") -or $s.Contains("arp")) {
        $mitre.Add("T1557.002 (ARP Cache Poisoning)")
        $mitre.Add("T1040 (Network Sniffing)")
    }

    # Scanning patterns
    if ($p.Contains("syn") -or $s.Contains("syn")) {
        $mitre.Add("T1046 (Network Service Discovery)")
    }

    # TLS anomalies / encrypted C2 indicators
    if ($p.Contains("tls") -or $s.Contains("tls")) {
        $mitre.Add("T1573 (Encrypted Channel)")
        $mitre.Add("T1071.001 (Web Protocols)")
    }

    # Lateral movement signals
    if ($type -eq "lateral_smb" -or $s.Contains("smb")) {
        $mitre.Add("T1021.002 (Remote Services: SMB/Windows Admin Shares)")
    }
    if ($type -eq "lateral_llmnr" -or $s.Contains("llmnr") -or $type -eq "lateral_nbns" -or $s.Contains("nbns")) {
        $mitre.Add("T1557.001 (LLMNR/NBT-NS Poisoning and Relay)")
        $mitre.Add("T1046 (Network Service Discovery)")
    }

    return (($mitre | Sort-Object -Unique) -join "; ")
}

# --------------------
# Build frequency maps (true counts)
# --------------------
$freq = @{}

# DNS/TLS counts (for persistence)
$dnsQueriesRaw = Run-TsharkRaw @("-r", $PcapFile, "-Y", "dns.qry.name", "-T", "fields", "-e", "dns.qry.name")
foreach ($d in $dnsQueriesRaw) {
    $x = $d.Trim()
    if (-not $x) { continue }
    if (-not $freq.ContainsKey($x)) { $freq[$x] = 0 }
    $freq[$x]++
}
$tlsSniRaw = Run-TsharkRaw @("-r", $PcapFile, "-Y", "tls.handshake.extensions_server_name", "-T", "fields", "-e", "tls.handshake.extensions_server_name")
foreach ($d in $tlsSniRaw) {
    $x = $d.Trim()
    if (-not $x) { continue }
    if (-not $freq.ContainsKey($x)) { $freq[$x] = 0 }
    $freq[$x]++
}

# Lateral counts
$lateralFreq = @{}  # key = "$type|$ioc"
foreach ($e in $lateral) {
    $k = "$($e.Type)|$($e.IOC)"
    if (-not $lateralFreq.ContainsKey($k)) { $lateralFreq[$k] = 0 }
    $lateralFreq[$k]++
}

# --------------------
# Build IOC rows
# --------------------
$rows = New-Object System.Collections.Generic.List[Object]

function AddIOCRow($ioc, $type, $profiles, $signals, $extra) {
    $iocStr = (SafeStr $ioc).Trim()
    if (-not $iocStr) { return }

    $score = 0

    # A) Persistence / frequency (0–30)
    $count = 1
    if ($freq.ContainsKey($iocStr)) { $count = [int]$freq[$iocStr] }
    if ($type -like "lateral_*") {
        $k = "$type|$iocStr"
        if ($lateralFreq.ContainsKey($k)) { $count = [int]$lateralFreq[$k] }
    }

    if ($count -ge 10) { $score += 30 }
    elseif ($count -ge 5) { $score += 20 }
    elseif ($count -ge 2) { $score += 10 }

    # B) Profile correlation (0–40)
    $profStr = SafeStr $profiles
    $pCount = (($profStr -split ";") | Where-Object { $_ -and $_.Trim() -ne "" } | Measure-Object).Count
    if ($pCount -ge 3) { $score += 40 }
    elseif ($pCount -eq 2) { $score += 25 }
    elseif ($pCount -eq 1) { $score += 10 }

    # C) Type risk (0–25)
    if ($type -eq "long_domain") { $score += 20 }
    elseif ($type -eq "domain")  { $score += 15 }
    elseif ($type -eq "ip")      { $score += 10 }
    elseif ($type -eq "user_agent") { $score += 8 }
    elseif ($type -eq "base64")  { $score += 12 }
    elseif ($type -eq "lateral_smb") { $score += 25 }
    elseif ($type -eq "lateral_llmnr") { $score += 20 }
    elseif ($type -eq "lateral_nbns") { $score += 18 }

    # D) Known-good reduction (-25) (not applied to lateral rows)
    if ($type -notlike "lateral_*") {
        if (IsKnownGood $iocStr) { $score -= 25 }
    }

    # E) Beacon contribution (+0–25)
    $b = $null
    if ($extra -and $extra.ContainsKey("BeaconKey")) {
        $bk = SafeStr $extra["BeaconKey"]
        if ($bk -and $beaconMetrics.ContainsKey($bk)) { $b = $beaconMetrics[$bk] }
    }

    if ($b) {
        $beaconBoost = [int][math]::Round(($b.BeaconScore / 100.0) * 25.0)
        $score += $beaconBoost

        # Tag signals so MITRE mapping can include beacon techniques
        $sig = SafeStr $signals
        if (-not ($sig.ToLower().Contains("beacon"))) {
            if ($sig) { $signals = $sig + ";Beacon" } else { $signals = "Beacon" }
        }
    }

    $score = ClampScore $score
    $mitreTags = GetMitreMapping $type $profiles $signals $iocStr

    # Defaults for optional fields
    $row = [ordered]@{
        IOC          = $iocStr
        Type         = $type
        Score        = $score
        MITRE        = $mitreTags
        Profiles     = $profiles
        Signals      = $signals
        BeaconScore  = ""
        BeaconFlag   = ""
        AvgIntervalSec = ""
        IntervalStdDev = ""
        FirstSeenEpoch = ""
        LastSeenEpoch  = ""
        BeaconCount    = ""
        LateralCount   = ""
    }

    # Attach beacon fields (if present)
    if ($b) {
        $row["BeaconScore"]    = $b.BeaconScore
        $row["BeaconFlag"]     = $b.BeaconFlag
        $row["AvgIntervalSec"] = $b.AvgIntervalSec
        $row["IntervalStdDev"] = $b.IntervalStdDev
        $row["FirstSeenEpoch"] = $b.FirstSeenEpoch
        $row["LastSeenEpoch"]  = $b.LastSeenEpoch
        $row["BeaconCount"]    = $b.BeaconCount
    }

    # Lateral count
    if ($type -like "lateral_*") {
        $row["LateralCount"] = $count
    }

    $rows.Add([PSCustomObject]$row) | Out-Null
}

# Domains from DNS queries
foreach ($d in $dnsQueriesUnique) {
    if (-not $d) { continue }
    $t = "domain"
    $profiles = "DNS-SUSPECT"
    $signals = "DNSQuery"
    if ($d.Length -gt 50) {
        $t = "long_domain"
        $profiles = "DNS-SUSPECT;UNIVERSAL-DEFENSE"
        $signals = "LongDNS;DNSQuery"
    }
    AddIOCRow $d $t $profiles $signals @{ BeaconKey=("DNS|"+$d) }
}

# TLS SNI domains
foreach ($sni in $tlsSniUnique) {
    if (-not $sni) { continue }
    AddIOCRow $sni "domain" "TLS-ANOMALY;UNIVERSAL-DEFENSE" "TLS_SNI" @{ BeaconKey=("TLS|"+$sni) }
}

# HTTP hosts (as domains)
foreach ($h in $httpHosts) {
    AddIOCRow $h "domain" "UNIVERSAL-DEFENSE" "HTTPHost" @{}
}

# IPs
foreach ($ip in $ipv4Hosts) { AddIOCRow $ip "ip" "RAW" "IPv4Host" @{} }
foreach ($ip in $ipv6Hosts) { AddIOCRow $ip "ip" "RAW" "IPv6Host" @{} }

# User agents
foreach ($u in $httpUserAgents) { AddIOCRow $u "user_agent" "RAW" "UserAgent" @{} }

# Base64 hits (trim long values for readability)
foreach ($b64 in $b64Candidates) {
    $val = $b64
    if ($val.Length -gt 140) { $val = $val.Substring(0,140) + "..." }
    AddIOCRow $val "base64" "UNIVERSAL-DEFENSE" "Base64Candidate" @{}
}

# Lateral movement artifacts (unique)
foreach ($k in $lateralFreq.Keys) {
    $parts = $k -split "\|", 2
    if ($parts.Count -ne 2) { continue }
    $t = $parts[0]; $iocStr = $parts[1]
    $sample = $lateral | Where-Object { $_.Type -eq $t -and $_.IOC -eq $iocStr } | Select-Object -First 1
    if ($null -eq $sample) { continue }
    AddIOCRow $iocStr $t $sample.Profiles $sample.Signals @{}
}

# --------------------
# Export scored outputs
# --------------------
$csvPath = Join-Path $OutputDir "ioc_scored.csv"
$topPath = Join-Path $OutputDir "ioc_scored_top20.txt"
$sumPath = Join-Path $OutputDir "ioc_scored_summary.txt"

$sorted = $rows | Sort-Object Score -Descending
$sorted | Export-Csv -NoTypeInformation -Encoding utf8 -Path $csvPath

# Top 20 text
$top20 = $sorted | Select-Object -First 20
$topLines = @()
foreach ($x in $top20) {
    $btxt = "-"
    if ($x.BeaconScore -ne "") { $btxt = [string]$x.BeaconScore }
    $topLines += ("{0}`t{1}`tScore={2}`tBeacon={3}`tMITRE={4}" -f $x.Type, $x.IOC, $x.Score, $btxt, $x.MITRE)
}
$topLines | Out-File -Encoding utf8 -FilePath $topPath

# Summary
$high = $sorted | Where-Object { $_.Score -ge 70 } | Select-Object -First 50
$med  = $sorted | Where-Object { $_.Score -ge 30 -and $_.Score -lt 70 } | Select-Object -First 50

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("SentinelWire™ IOC Summary") | Out-Null
$lines.Add("Run folder: $OutputDir") | Out-Null
$lines.Add("PCAP: $PcapFile") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("High confidence (70–100):") | Out-Null

if ($high -and $high.Count -gt 0) {
    foreach ($x in $high) {
        if ($x.BeaconFlag -eq $true) {
            $lines.Add(("  [HIGH] {0} | {1} | Score={2} | BeaconScore={3} Avg={4}s Std={5}s | MITRE={6}" -f $x.Type, $x.IOC, $x.Score, $x.BeaconScore, $x.AvgIntervalSec, $x.IntervalStdDev, $x.MITRE)) | Out-Null
        } else {
            $lines.Add(("  [HIGH] {0} | {1} | Score={2} | MITRE={3}" -f $x.Type, $x.IOC, $x.Score, $x.MITRE)) | Out-Null
        }
    }
} else {
    $lines.Add("  (none)") | Out-Null
}

$lines.Add("") | Out-Null
$lines.Add("Medium confidence (30–69):") | Out-Null

if ($med -and $med.Count -gt 0) {
    foreach ($x in $med) {
        $lines.Add(("  [MED]  {0} | {1} | Score={2} | MITRE={3}" -f $x.Type, $x.IOC, $x.Score, $x.MITRE)) | Out-Null
    }
} else {
    $lines.Add("  (none)") | Out-Null
}

$lines | Out-File -Encoding utf8 -FilePath $sumPath

Write-Host ""
Write-Host "---------------------------------------------"
Write-Host "Extraction complete."
Write-Host ""
Write-Host "Raw outputs:"
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
