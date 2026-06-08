<#
.SYNOPSIS
    CIS Windows Server Benchmark - Dynamic DC Audit
    Parses any CIS Windows Server benchmark PDF and runs a live compliance
    audit against the current Domain Controller.

.DESCRIPTION
    Extracts all recommendations directly from the supplied PDF at runtime
    using Microsoft Word COM automation (no third-party tools required).
    Supports any CIS Windows Server benchmark version (2012, 2016, 2019,
    2022, 2025, etc.) — just point it at the correct PDF.

    Engines used per control type:
        Registry (HKLM/HKCU)  — Get-ItemProperty
        Password/Lockout       — secedit /export  (read-only)
        User Rights            — secedit /export  (read-only)
        Advanced Audit Policy  — auditpol /get    (read-only)
        Special/multi-value    — flagged Needs Review with page reference

    Output: CSV report, color-coded HTML report, self-audit transcript log.
    READ-ONLY: makes no changes to the system.

.PARAMETER PdfPath
    Full path to the CIS benchmark PDF file.

.PARAMETER OutputDir
    Folder where reports are saved. Default: Desktop\CIS_DC_Audit

.PARAMETER Role
    DC or MS (Domain Controller or Member Server). Default: DC
    Auto-detected from the machine's DomainRole if not specified.

.EXAMPLE
    .\Invoke-CIS-DC-DynamicAudit.ps1 -PdfPath "C:\CIS_WS2022_Benchmark.pdf"

.EXAMPLE
    .\Invoke-CIS-DC-DynamicAudit.ps1 -PdfPath "C:\CIS_WS2019_Benchmark.pdf" -Role DC

.NOTES
    Requirements:
      - Microsoft Word installed (any version 2013+)
      - Run as Administrator (needed for secedit and auditpol reads)
      - PowerShell 5.1 or higher
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$PdfPath,

    [string]$OutputDir = "$env:USERPROFILE\Desktop\CIS_DC_Audit",

    [ValidateSet('DC','MS','Auto')]
    [string]$Role = 'Auto'
)

$ErrorActionPreference = 'Stop'
$script:StartTime = Get-Date
$script:AuditLog   = New-Object System.Collections.Generic.List[string]
$script:Results    = New-Object System.Collections.Generic.List[object]
$script:ParseIssues = New-Object System.Collections.Generic.List[object]

#region ── Logging ──────────────────────────────────────────────────────────
function Write-AuditLog {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "[{0}] [{1}] {2}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff'), $Level, $Message
    $script:AuditLog.Add($line)
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'PARSE' { Write-Host $line -ForegroundColor Magenta }
        default { Write-Verbose $line }
    }
}

function Add-Result {
    param($Id,$Title,$Source,$Expected,$Actual,$Status,$Detail,$Page)
    $script:Results.Add([pscustomobject]@{
        Id=$Id; Title=$Title; Source=$Source; Expected=[string]$Expected
        Actual=[string]$Actual; Status=$Status; Detail=$Detail; BenchmarkPage=$Page })
}

function Add-ParseIssue {
    param($Id,$Title,$Issue,$Page)
    $script:ParseIssues.Add([pscustomobject]@{ Id=$Id; Title=$Title; Issue=$Issue; Page=$Page })
    Write-AuditLog "[PARSE] $Id (p$Page): $Issue" 'PARSE'
}
#endregion

#region ── Environment checks ───────────────────────────────────────────────
Write-AuditLog "=== CIS Dynamic DC Audit started ==="
Write-AuditLog "PDF: $PdfPath"
Write-AuditLog "Host: $env:COMPUTERNAME  User: $env:USERNAME  PS: $($PSVersionTable.PSVersion)"

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-AuditLog "Elevated: $admin"
if (-not $admin) { Write-AuditLog "Not elevated — secedit/auditpol may be unavailable." 'WARN' }

# Resolve role
if ($Role -eq 'Auto') {
    try {
        $dr = (Get-CimInstance Win32_ComputerSystem).DomainRole
        $Role = if ($dr -eq 4 -or $dr -eq 5) { 'DC' } else { 'MS' }
        Write-AuditLog "Auto-detected role: $Role (DomainRole=$dr)"
    } catch { $Role = 'DC'; Write-AuditLog "Could not detect role, defaulting to DC." 'WARN' }
}
#endregion

#region ── PDF Extraction via Word COM ──────────────────────────────────────
function Invoke-WordPdfExtract {
    param([string]$Path)

    Write-Host "Opening PDF in Microsoft Word..." -ForegroundColor Cyan
    Write-AuditLog "Starting Word COM extraction of: $Path"

    $word = $null; $doc = $null
    try {
        $word = New-Object -ComObject Word.Application -ErrorAction Stop
        $word.Visible = $false
        $word.DisplayAlerts = 0   # wdAlertsNone

        # Open PDF — Word converts it to DOCX in memory
        $doc = $word.Documents.Open(
            $Path,       # FileName
            $false,      # ConfirmConversions
            $true,       # ReadOnly
            $false,      # AddToRecentFiles
            '','',$false,'',$false,$false,$false,$false,$false,$false,0,1
        )
        Write-AuditLog "Word opened PDF. Paragraphs: $($doc.Paragraphs.Count)"

        # Extract paragraphs with page numbers
        # wdActiveEndPageNumber = 3
        $paras = New-Object System.Collections.Generic.List[object]
        $total = $doc.Paragraphs.Count
        $step  = [math]::Max(1,[int]($total/50))
        Write-Host "Extracting $total paragraphs..." -ForegroundColor Cyan

        for ($i = 1; $i -le $total; $i++) {
            $para = $doc.Paragraphs($i)
            $text = $para.Range.Text -replace "`r",'' -replace "`v","`n"
            $text = $text.Trim()
            if ($text -eq '') { continue }
            # Get page number every $step paragraphs or when a rec header is likely
            $page = 0
            try { $page = $para.Range.Information(3) } catch {}
            $paras.Add([pscustomobject]@{ Text=$text; Page=$page })

            if ($i % 500 -eq 0) {
                Write-Host "  ...extracted $i / $total paragraphs" -ForegroundColor Gray
            }
        }

        Write-AuditLog "Extracted $($paras.Count) non-empty paragraphs."
        return $paras
    }
    finally {
        if ($doc)  { try { $doc.Close($false)  } catch {} }
        if ($word) { try { $word.Quit()         } catch {} }
        if ($doc)  { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($doc)  | Out-Null }
        if ($word) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null }
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    }
}
#endregion

#region ── Benchmark Parser ─────────────────────────────────────────────────

# Patterns
# Header may carry an optional profile tag like (L1)/(L2)/(BL)/(NG) between the
# ID and "Ensure", and may end in (Automated|Manual) [2016+] or (Scored|Not Scored) [2012 R2].
$recHeader     = [regex]'(?i)^(\d+(?:\.\d+){1,5})\s+(?:\((?:L1|L2|BL|NG|[A-Z0-9]{1,3})\)\s+)?(Ensure\b.*?\((?:Automated|Manual|Scored|Not Scored)\))\s*$'
# Start-of-header (used to stitch titles that Word split across paragraphs)
$recHeaderStart = [regex]'(?i)^(\d+(?:\.\d+){1,5})\s+(?:\((?:L1|L2|BL|NG|[A-Z0-9]{1,3})\)\s+)?(Ensure\b.*)$'
$recHeaderEnd   = [regex]'(?i)\((?:Automated|Manual|Scored|Not Scored)\)'
$regLine   = [regex]'(?i)(HK(?:LM|EY_LOCAL_MACHINE|CU|EY_CURRENT_USER|U)\\[^\n:]+?):([A-Za-z0-9_\-\{\}]+)'
$regDword  = [regex]'(?i)REG_(DWORD|QWORD)\s+value\s+of\s+([0-9a-fA-FxX]+)'
$regType   = [regex]'(?i)REG_(DWORD|SZ|QWORD|MULTI_SZ|EXPAND_SZ)'

function Get-RecommendationBlocks {
    param($Paragraphs, [string]$TargetRole)

    Write-Host "Parsing recommendation blocks..." -ForegroundColor Cyan
    $lines = $Paragraphs   # array of {Text, Page}
    $n     = $lines.Count

    # Find body-section header positions. A header may be split across paragraphs
    # (Word can break a long title), so stitch from the start line until the closing
    # (Automated|Manual|Scored|Not Scored) marker is seen (max 4 paragraphs).
    # A header is valid only if "Profile Applicability:" appears within 8 lines after it.
    $headers = @()
    $i = 0
    while ($i -lt $n) {
        $startM = $recHeaderStart.Match($lines[$i].Text)
        if (-not $startM.Success) { $i++; continue }

        $acc = $lines[$i].Text; $j = $i
        while ($j -lt [math]::Min($i+4,$n) -and -not $recHeaderEnd.IsMatch($acc)) {
            $j++
            if ($j -lt $n) { $acc += ' ' + $lines[$j].Text }
        }
        if (-not $recHeaderEnd.IsMatch($acc)) { $i++; continue }

        $full = $recHeader.Match(($acc -replace '\s+',' '))
        if (-not $full.Success) { $i++; continue }

        $found = $false
        for ($k = $j+1; $k -lt [math]::Min($j+9,$n); $k++) {
            if ($lines[$k].Text -match 'Profile Applicability') { $found=$true; break }
        }
        if ($found) {
            $headers += [pscustomobject]@{ Idx=$i; Id=$full.Groups[1].Value
                Title=($full.Groups[2].Value -replace '\s+',' ').Trim()
                Page=$lines[$i].Page }
            $i = $j + 1; continue
        }
        $i++
    }
    Write-AuditLog "Found $($headers.Count) recommendation headers."

    $blocks = New-Object System.Collections.Generic.List[object]
    for ($h = 0; $h -lt $headers.Count; $h++) {
        $cur  = $headers[$h]
        $startIdx = $cur.Idx
        $endIdx   = if ($h+1 -lt $headers.Count) { $headers[$h+1].Idx } else { $n }

        # Collect text of this block
        $blockLines = $lines[$startIdx..($endIdx-1)]
        $blockText  = ($blockLines | ForEach-Object { $_.Text }) -join "`n"

        # DC/MS applicability
        $titleDcOnly = $cur.Title -match '\(DC only\)'
        $titleMsOnly = $cur.Title -match '\(MS only\)'
        $profDC = $blockText -match 'Domain Controller'
        $profMS = $blockText -match 'Member Server'

        $applies = switch ($TargetRole) {
            'DC' { -not $titleMsOnly -and -not ($profMS -and -not $profDC -and -not $titleDcOnly) }
            'MS' { -not $titleDcOnly -and -not ($profDC -and -not $profMS -and -not $titleMsOnly) }
        }
        if (-not $applies) { continue }

        $auto = ($cur.Title -match '\(Automated\)') -or ($cur.Title -match '\(Scored\)')

        $blocks.Add([pscustomobject]@{
            Id=$cur.Id; Title=$cur.Title; Page=$cur.Page
            Automated=$auto; BlockText=$blockText; BlockLines=$blockLines })
    }
    Write-AuditLog "Applicable blocks for role '$TargetRole': $($blocks.Count)"
    return $blocks
}

function Parse-RegistryCheck {
    param($Block)
    # Isolate Audit section
    $bt = $Block.BlockText
    $ai = $bt.IndexOf('Audit:')
    $ri = $bt.IndexOf('Remediation:')
    $auditText = if ($ai -ge 0 -and $ri -gt $ai) { $bt.Substring($ai, $ri-$ai) }
                 elseif ($ai -ge 0)               { $bt.Substring($ai, [math]::Min(1200,$bt.Length-$ai)) }
                 else                             { $bt.Substring(0,[math]::Min(1200,$bt.Length)) }

    # Join wrapped path lines: find HK start, then join until we have 'path:name'
    $hkIdx = $auditText.IndexOf('HK', [System.StringComparison]::OrdinalIgnoreCase)
    if ($hkIdx -lt 0) { return $null }

    $tail  = $auditText.Substring($hkIdx)
    $endM  = [regex]::Match($tail, '(\n\s*\n|\nRemediation:|\nDefault Value:|\nNote:|\nImpact:)')
    $chunk = if ($endM.Success) { $tail.Substring(0,$endM.Index) } else { $tail.Substring(0,[math]::Min(300,$tail.Length)) }

    # Join wrapped lines (path/name wraps to next line)
    $joined = ($chunk -split '\n' | ForEach-Object { $_.Trim() }) -join ' '
    $joined = $joined -replace '\s{2,}',' '

    $m = $regLine.Match($joined)
    if (-not $m.Success) { return $null }

    $rawPath = $m.Groups[1].Value
    $name    = $m.Groups[2].Value

    # Normalize hive abbreviations
    $path = $rawPath `
        -replace '(?i)^HKEY_LOCAL_MACHINE\\','HKLM\' `
        -replace '(?i)^HKEY_CURRENT_USER\\','HKCU\' `
        -replace '(?i)^HKEY_USERS\\','HKU\' `
        -replace '\s*\\\s*','\'   # remove spaces around backslashes (wrap artifact)

    # Type
    $typeM = $regType.Match($auditText)
    $type  = if ($typeM.Success) { 'REG_' + $typeM.Groups[1].Value } else { 'REG_DWORD' }

    # Expected value
    $expected = $null; $op = 'manual'; $confHigh = $false

    if ($auditText -match '(?i)when set properly a value does not exist') {
        $op = 'absent'; $expected = 'does not exist'; $confHigh = $true
    } else {
        $dm = $regDword.Match($auditText)
        if ($dm.Success) {
            $raw = $dm.Groups[2].Value.Trim()
            $expected = if ($raw -match '^0x') { [int64]('0x'+$raw.Substring(2)) } else { [int64]$raw }
            $confHigh = $true

            # Determine operator from context
            if ($auditText -match '(?i)or more') { $op = 'ge' }
            elseif ($auditText -match '(?i)or (fewer|less)') {
                $op = 'le'
                if ($auditText -match '(?i)but not 0') { $op = 'le_not0' }
            }
            else {
                # check for list: "value of 1 or 2", "value of 1, 2, or 3"
                $listM = [regex]::Matches($auditText, '(?i)REG_(?:DWORD|QWORD)\s+value\s+of\s+([\d,\s]+(?:or\s+\d+)?)')
                if ($listM.Count -gt 0) {
                    $nums = [regex]::Matches($listM[0].Groups[1].Value, '\d+') | ForEach-Object { [int64]$_.Value }
                    if ($nums.Count -gt 1) { $op = 'in'; $expected = $nums }
                    else                   { $op = 'eq' }
                } else { $op = 'eq' }
            }
        } else {
            # No explicit "REG_DWORD value of N" line (common in 2012 R2 and Azure
            # benchmarks). Derive the expected value from the title's "set to 'X'".
            # Since a registry path WAS found, a clear Enabled/Disabled/number is
            # treated as high-confidence; anything else stays Needs Review.
            $tm = [regex]::Match($Block.Title, "set to '([^']+)'")
            if ($tm.Success) {
                $v = $tm.Groups[1].Value.Trim().ToLower()
                switch -Regex ($v) {
                    '^disabled?$'  { $expected = 0; $op = 'eq'; $confHigh = $true }
                    '^enabled?$'   { $expected = 1; $op = 'eq'; $confHigh = $true }
                    '^(\d+)$'      { $expected = [int64]$v; $op = 'eq'; $confHigh = $true }
                    '(\d+)'        { $expected = [int64]([regex]::Match($v,'\d+').Value); $op = 'eq'; $confHigh = $true }
                    default        { $expected = $tm.Groups[1].Value; $op = 'manual' }
                }
            }
        }
    }

    return [pscustomobject]@{
        Path=$path; Name=$name; Type=$type
        Expected=$expected; Op=$op; HighConfidence=$confHigh
    }
}

function Parse-AuditPolCheck {
    param($Block)
    # Extract subcategory name from title
    $m = [regex]::Match($Block.Title, "Ensure '([^']+)'")
    if (-not $m.Success) { return $null }
    $sub  = $m.Groups[1].Value
    $sub  = $sub -replace '^Audit ',''
    $expM = [regex]::Match($Block.Title, "set to (?:include )?'([^']+)'")
    $exp  = if ($expM.Success) { $expM.Groups[1].Value } else { $null }
    return [pscustomobject]@{ Subcategory=$sub; Expected=$exp }
}

function Parse-SeceditCheck {
    param($Block)
    # Section 1.x password/lockout: map known CIS titles to secedit INF keys
    $keyMap = @{
        'Enforce password history'                          = @('PasswordHistorySize','ge',24)
        'Maximum password age'                              = @('MaximumPasswordAge','le_not0',365)
        'Minimum password age'                              = @('MinimumPasswordAge','ge',1)
        'Minimum password length'                           = @('MinimumPasswordLength','ge',14)
        'Password must meet complexity'                     = @('PasswordComplexity','eq',1)
        'Store passwords using reversible encryption'       = @('ClearTextPassword','eq',0)
        'Account lockout duration'                          = @('LockoutDuration','ge',15)
        'Account lockout threshold'                         = @('LockoutBadCount','le_not0',5)
        'Reset account lockout counter'                     = @('ResetLockoutCount','ge',15)
    }
    foreach ($kw in $keyMap.Keys) {
        if ($Block.Title -match [regex]::Escape($kw)) {
            $v = $keyMap[$kw]
            return [pscustomobject]@{ Key=$v[0]; Op=$v[1]; Value=$v[2] }
        }
    }
    return $null
}

function Parse-UserRightCheck {
    param($Block)
    $privMap = @{
        'Access Credential Manager'           = 'SeTrustedCredManAccessPrivilege'
        'Access this computer from the network'= 'SeNetworkLogonRight'
        'Act as part of the operating system' = 'SeTcbPrivilege'
        'Add workstations to domain'          = 'SeMachineAccountPrivilege'
        'Adjust memory quotas'                = 'SeIncreaseQuotaPrivilege'
        'Allow log on locally'                = 'SeInteractiveLogonRight'
        'Allow log on through Remote Desktop' = 'SeRemoteInteractiveLogonRight'
        'Back up files and directories'       = 'SeBackupPrivilege'
        'Change the system time'              = 'SeSystemtimePrivilege'
        'Change the time zone'                = 'SeTimeZonePrivilege'
        'Create a pagefile'                   = 'SeCreatePagefilePrivilege'
        'Create a token object'               = 'SeCreateTokenPrivilege'
        'Create global objects'               = 'SeCreateGlobalPrivilege'
        'Create permanent shared objects'     = 'SeCreatePermanentPrivilege'
        'Create symbolic links'               = 'SeCreateSymbolicLinkPrivilege'
        'Debug programs'                      = 'SeDebugPrivilege'
        'Deny access to this computer from the network' = 'SeDenyNetworkLogonRight'
        'Deny log on as a batch job'          = 'SeDenyBatchLogonRight'
        'Deny log on as a service'            = 'SeDenyServiceLogonRight'
        'Deny log on locally'                 = 'SeDenyInteractiveLogonRight'
        'Deny log on through Remote Desktop'  = 'SeDenyRemoteInteractiveLogonRight'
        'Enable computer and user accounts to be trusted for delegation' = 'SeEnableDelegationPrivilege'
        'Force shutdown from a remote system' = 'SeRemoteShutdownPrivilege'
        'Generate security audits'            = 'SeAuditPrivilege'
        'Impersonate a client after authentication' = 'SeImpersonatePrivilege'
        'Increase scheduling priority'        = 'SeIncreaseBasePriorityPrivilege'
        'Increase a process working set'      = 'SeIncreaseWorkingSetPrivilege'
        'Load and unload device drivers'      = 'SeLoadDriverPrivilege'
        'Lock pages in memory'                = 'SeLockMemoryPrivilege'
        'Log on as a batch job'               = 'SeBatchLogonRight'
        'Manage auditing and security log'    = 'SeSecurityPrivilege'
        'Modify an object label'              = 'SeRelabelPrivilege'
        'Modify firmware environment values'  = 'SeSystemEnvironmentPrivilege'
        'Perform volume maintenance tasks'    = 'SeManageVolumePrivilege'
        'Profile single process'              = 'SeProfileSingleProcessPrivilege'
        'Profile system performance'          = 'SeSystemProfilePrivilege'
        'Replace a process level token'       = 'SeAssignPrimaryTokenPrivilege'
        'Restore files and directories'       = 'SeRestorePrivilege'
        'Shut down the system'                = 'SeShutdownPrivilege'
        'Synchronize directory service data'  = 'SeSyncAgentPrivilege'
        'Take ownership of files'             = 'SeTakeOwnershipPrivilege'
    }
    $expM = [regex]::Match($Block.Title, "set to '([^']+)'|to include '([^']+)'")
    $exp  = if ($expM.Success) { if ($expM.Groups[1].Value) {$expM.Groups[1].Value} else {$expM.Groups[2].Value} } else { '' }
    foreach ($kw in $privMap.Keys) {
        if ($Block.Title -match [regex]::Escape($kw)) {
            return [pscustomobject]@{ Privilege=$privMap[$kw]; Expected=$exp }
        }
    }
    return $null
}

function Classify-Block {
    param($Block)
    $id  = $Block.Id
    $top = ($id -split '\.')[0]

    # Section 17 → auditpol
    if ($top -eq '17') { return 'auditpol' }

    # Section 1 → secedit password/lockout
    if ($top -eq '1') { return 'secedit_password' }

    # Section 2.2 → user rights
    if ($id -match '^2\.2\.') { return 'user_rights' }

    # Try registry extraction (works for sections 2.3, 5, 9, 10, 18, 19, etc.)
    $reg = Parse-RegistryCheck -Block $Block
    if ($reg) { return 'registry' }

    # Fallback
    return 'needs_review'
}
#endregion

#region ── Check Engines ────────────────────────────────────────────────────
function Get-RegValue {
    param([string]$Path,[string]$Name)
    $psPath = $Path -replace '^HKLM\\','HKLM:\' -replace '^HKCU\\','HKCU:\' -replace '^HKU\\','HKU:\'
    if ($psPath -notmatch '^HK(LM|CU|U):\\') { $psPath = 'HKLM:\' + $Path }
    try {
        $item = Get-ItemProperty -LiteralPath $psPath -Name $Name -ErrorAction Stop
        return @{ Exists=$true; Value=$item.$Name }
    } catch { return @{ Exists=$false; Value=$null } }
}

function Test-RegRule {
    param($Check,$Reg)
    if ($Check.Op -eq 'absent') {
        if (-not $Reg.Exists) { return @('Configured','Value absent as required') }
        return @('Not Configured',"Present (=$($Reg.Value)); should not exist")
    }
    if ($Check.Op -eq 'manual') { return @('Needs Review',"Manual check: $($Check.Expected)") }
    if (-not $Reg.Exists)       { return @('Not Configured','Registry value not set') }
    $a = [int64]$Reg.Value
    switch ($Check.Op) {
        'eq'      { if ($a -eq $Check.Expected){return @('Configured',"=$a")} return @('Not Configured',"Actual=$a Expected=$($Check.Expected)") }
        'ge'      { if ($a -ge $Check.Expected){return @('Configured',"$a>=$($Check.Expected)")} return @('Not Configured',"Actual=$a Expected>=$($Check.Expected)") }
        'le'      { if ($a -le $Check.Expected){return @('Configured',"$a<=$($Check.Expected)")} return @('Not Configured',"Actual=$a Expected<=$($Check.Expected)") }
        'le_not0' { $ok=($a -le $Check.Expected -and $a -ne 0); if($ok){return @('Configured',"$a")} return @('Not Configured',"Actual=$a") }
        'in'      { if ($Check.Expected -contains $a){return @('Configured',"=$a (allowed)")} return @('Not Configured',"Actual=$a Allowed=$($Check.Expected -join ',')") }
        default   { return @('Needs Review','Unknown comparator') }
    }
}

function Get-SecEditInf {
    $tmp = Join-Path $env:TEMP "cis_sec_$([guid]::NewGuid().ToString('N')).inf"
    try {
        $null = secedit /export /cfg $tmp /quiet 2>&1
        $content = Get-Content -LiteralPath $tmp -Encoding Unicode -ErrorAction Stop
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        Write-AuditLog "secedit export: $($content.Count) lines"
        return $content
    } catch {
        Write-AuditLog "secedit export failed: $($_.Exception.Message)" 'WARN'
        return $null
    }
}

function Get-AuditPolMap {
    $map = @{}
    try {
        $csv = auditpol /get /category:* /r 2>$null | ConvertFrom-Csv
        foreach ($row in $csv) { if ($row.Subcategory) { $map[$row.Subcategory.Trim()] = $row.'Inclusion Setting' } }
        Write-AuditLog "auditpol: $($map.Count) subcategories"
    } catch { Write-AuditLog "auditpol failed: $($_.Exception.Message)" 'WARN' }
    return $map
}
#endregion

#region ── Main Audit Loop ──────────────────────────────────────────────────
# 1. Extract PDF
$paragraphs = Invoke-WordPdfExtract -Path (Resolve-Path $PdfPath).Path

# 2. Parse blocks
$blocks = Get-RecommendationBlocks -Paragraphs $paragraphs -TargetRole $Role
Write-Host "Parsed $($blocks.Count) applicable recommendations. Running audit..." -ForegroundColor Cyan

# 3. Pre-load shared resources
$inf       = Get-SecEditInf
$auditpol  = Get-AuditPolMap

$counter   = 0
$total     = $blocks.Count

foreach ($blk in $blocks) {
    $counter++
    if ($counter % 25 -eq 0) {
        Write-Host "  ...checking $counter / $total" -ForegroundColor Gray
    }

    $id    = $blk.Id
    $title = $blk.Title -replace '\s+',' '
    $page  = $blk.Page
    $class = Classify-Block -Block $blk

    switch ($class) {

        'registry' {
            $reg = Parse-RegistryCheck -Block $blk
            if (-not $reg) {
                Add-Result $id $title 'Registry' '?' '<parse failed>' 'Needs Review' "Could not extract registry path from PDF. Check p$page." $page
                Add-ParseIssue $id $title 'Registry path not extracted from PDF' $page
                break
            }
            if (-not $reg.HighConfidence) {
                Add-Result $id $title 'Registry' $reg.Expected '<not checked>' 'Needs Review' "Low-confidence extraction — verify on p$page of benchmark." $page
                Add-ParseIssue $id $title "Low-confidence: path=$($reg.Path) name=$($reg.Name) expected=$($reg.Expected)" $page
                break
            }
            $live = Get-RegValue -Path $reg.Path -Name $reg.Name
            $res  = Test-RegRule -Check $reg -Reg $live
            $actual = if ($live.Exists) { $live.Value } else { '<not set>' }
            Write-AuditLog "[$id] $($reg.Path):$($reg.Name) actual='$actual' expected='$($reg.Expected)' => $($res[0])"
            Add-Result $id $title 'Registry' $reg.Expected $actual $res[0] $res[1] $page
        }

        'auditpol' {
            $ap = Parse-AuditPolCheck -Block $blk
            if (-not $ap -or -not $ap.Subcategory) {
                Add-Result $id $title 'auditpol' '?' '<parse failed>' 'Needs Review' "Subcategory not parsed — check p$page." $page
                Add-ParseIssue $id $title 'Audit subcategory not parsed' $page; break
            }
            $actual = $auditpol[$ap.Subcategory]
            if (-not $actual) {
                Add-Result $id $title 'auditpol' $ap.Expected '<not found>' 'Needs Review' "Subcategory '$($ap.Subcategory)' not in auditpol output — check p$page." $page
                break
            }
            $a = $actual.Trim()
            $ok = switch ($ap.Expected) {
                'Success and Failure' { $a -eq 'Success and Failure' }
                'Success'             { $a -eq 'Success' -or $a -eq 'Success and Failure' }
                'Failure'             { $a -eq 'Failure' -or $a -eq 'Success and Failure' }
                default               { $false }
            }
            $status = if ($ok) {'Configured'} else {'Not Configured'}
            Write-AuditLog "[$id] auditpol '$($ap.Subcategory)'='$a' => $status"
            Add-Result $id $title 'auditpol' $ap.Expected $a $status "$($ap.Subcategory): $a" $page
        }

        'secedit_password' {
            $sc = Parse-SeceditCheck -Block $blk
            if (-not $sc) {
                Add-Result $id $title 'secedit' '?' '<parse failed>' 'Needs Review' "secedit key not mapped — check p$page." $page
                Add-ParseIssue $id $title 'secedit key not mapped' $page; break
            }
            if (-not $inf) {
                Add-Result $id $title 'secedit' $sc.Value 'N/A' 'Needs Review' 'secedit export unavailable' $page; break
            }
            $line = $inf | Where-Object { $_ -match "^\s*$($sc.Key)\s*=" } | Select-Object -First 1
            if (-not $line) {
                Add-Result $id $title 'secedit' $sc.Value '<not found>' 'Not Configured' "Key $($sc.Key) not in policy" $page; break
            }
            $val = ($line -split '=')[1].Trim(); $n = 0; [void][int]::TryParse($val,[ref]$n)
            $ok  = switch ($sc.Op) {
                'ge'      { $n -ge $sc.Value }
                'eq'      { $n -eq $sc.Value }
                'le_not0' { $n -le $sc.Value -and $n -ne 0 }
                default   { $false }
            }
            $status = if ($ok) {'Configured'} else {'Not Configured'}
            Write-AuditLog "[$id] secedit $($sc.Key)=$val => $status"
            Add-Result $id $title 'secedit' $sc.Value $val $status "$($sc.Key)=$val" $page
        }

        'user_rights' {
            $ur = Parse-UserRightCheck -Block $blk
            if (-not $ur) {
                Add-Result $id $title 'secedit(URA)' '?' '<parse failed>' 'Needs Review' "Privilege not mapped — check p$page." $page
                Add-ParseIssue $id $title 'User right privilege not mapped' $page; break
            }
            if (-not $inf) {
                Add-Result $id $title 'secedit(URA)' $ur.Expected 'N/A' 'Needs Review' 'secedit export unavailable' $page; break
            }
            $line     = $inf | Where-Object { $_ -match "^\s*$($ur.Privilege)\s*=" } | Select-Object -First 1
            $assigned = if ($line) { ($line -split '=')[1].Trim() } else { '' }
            $status   = 'Needs Review'
            $detail   = "Assigned: '$assigned'. Expected: '$($ur.Expected)'. Verify SID assignments on p$page."
            if ([string]::IsNullOrWhiteSpace($assigned) -and $ur.Expected -match 'No One|nobody') {
                $status='Configured'; $detail='No accounts assigned (= No One).'
            }
            Write-AuditLog "[$id] URA $($ur.Privilege)='$assigned' => $status"
            Add-Result $id $title 'secedit(URA)' $ur.Expected $assigned $status $detail $page
        }

        default {
            Add-Result $id $title 'Manual' 'See benchmark' 'Needs Review' "Special control — review benchmark p$page manually." $page
            Add-ParseIssue $id $title 'Not automatically checkable' $page
        }
    }
}
#endregion

#region ── Summary & Reports ────────────────────────────────────────────────
$configured = ($script:Results | Where-Object Status -eq 'Configured').Count
$notconf    = ($script:Results | Where-Object Status -eq 'Not Configured').Count
$review     = ($script:Results | Where-Object Status -eq 'Needs Review').Count
$totalR     = $script:Results.Count
$assessable = $configured + $notconf
$pct        = if ($assessable) { [math]::Round(($configured/$assessable)*100,1) } else { 0 }
$parseIssues = $script:ParseIssues.Count

Write-AuditLog "=== Summary: $configured Configured / $notconf Not Configured / $review Needs Review / $parseIssues parse issues ==="
Write-Host ''
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host "  CIS Audit: $([System.IO.Path]::GetFileName($PdfPath))" -ForegroundColor Cyan
Write-Host ("  Configured      : {0}" -f $configured) -ForegroundColor Green
Write-Host ("  Not Configured  : {0}" -f $notconf)    -ForegroundColor Red
Write-Host ("  Needs Review    : {0} (see HTML report for page refs)" -f $review) -ForegroundColor Yellow
Write-Host ("  Total checks    : {0}  |  Compliance: {1}% of assessable" -f $totalR,$pct) -ForegroundColor Cyan
if ($parseIssues -gt 0) {
Write-Host ("  Parse issues    : {0} (extraction uncertain — check benchmark PDF)" -f $parseIssues) -ForegroundColor Magenta }
Write-Host '============================================================' -ForegroundColor Cyan

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
$stamp = $script:StartTime.ToString('yyyyMMdd_HHmmss')
$pdfName = [System.IO.Path]::GetFileNameWithoutExtension($PdfPath)
$csvPath  = Join-Path $OutputDir "${pdfName}_${stamp}.csv"
$htmlPath = Join-Path $OutputDir "${pdfName}_${stamp}.html"
$logPath  = Join-Path $OutputDir "${pdfName}_${stamp}_AuditLog.txt"

# CSV
($script:Results | Sort-Object Id) | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-AuditLog "CSV: $csvPath"

# HTML
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
function enc($x) { [System.Web.HttpUtility]::HtmlEncode([string]$x) }
$rows = foreach ($r in ($script:Results | Sort-Object Id)) {
    $cls = switch ($r.Status) { 'Configured'{'ok'} 'Not Configured'{'bad'} default{'rev'} }
    $pg  = if ($r.BenchmarkPage) { "<span class='pg'>p$($r.BenchmarkPage)</span>" } else { '' }
    "<tr class='$cls'><td>$($r.Id)</td><td>$(enc $r.Title) $pg</td><td>$($r.Source)</td><td>$(enc $r.Expected)</td><td>$(enc $r.Actual)</td><td>$($r.Status)</td><td>$(enc $r.Detail)</td></tr>"
}
$parseRows = foreach ($p in $script:ParseIssues) {
    "<tr><td>$($p.Id)</td><td>$(enc $p.Title)</td><td>p$($p.Page)</td><td>$(enc $p.Issue)</td></tr>"
}
$html = @"
<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>CIS Audit - $(enc $pdfName)</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;font-size:13px}
h1{font-size:18px}h2{font-size:15px;margin-top:32px}
.meta{color:#555;margin-bottom:12px}
.cards{display:flex;gap:10px;margin:14px 0;flex-wrap:wrap}
.card{padding:10px 16px;border-radius:7px;color:#fff;font-weight:600;font-size:14px}
.c-ok{background:#2e7d32}.c-bad{background:#c62828}.c-rev{background:#e65100}.c-b{background:#1565c0}.c-warn{background:#6a1b9a}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:5px 7px;text-align:left;vertical-align:top}
th{background:#1565c0;color:#fff;position:sticky;top:0}
tr.ok td{background:#f1f8f1}tr.bad td{background:#fff5f5}tr.rev td{background:#fff8f0}
.pg{font-size:11px;color:#888;font-style:italic}
</style></head><body>
<h1>CIS Benchmark Audit &mdash; $( enc $pdfName )</h1>
<div class='meta'>Host: $env:COMPUTERNAME &nbsp;|&nbsp; Role: $Role &nbsp;|&nbsp; Generated: $($script:StartTime) &nbsp;|&nbsp; $totalR checks</div>
<div class='cards'>
  <div class='card c-ok'>&#10003; Configured: $configured</div>
  <div class='card c-bad'>&#10007; Not Configured: $notconf</div>
  <div class='card c-rev'>&#9888; Needs Review: $review</div>
  <div class='card c-b'>Compliance: $pct%</div>
  $(if($parseIssues){"<div class='card c-warn'>Parse issues: $parseIssues</div>"})
</div>
<h2>Results</h2>
<table><thead><tr><th>ID</th><th>Recommendation</th><th>Source</th><th>Expected</th><th>Actual</th><th>Status</th><th>Detail</th></tr></thead>
<tbody>$($rows -join "`n")</tbody></table>
$(if($parseIssues -gt 0){"
<h2>Parse Issues (extraction uncertain &mdash; verify against PDF)</h2>
<table><thead><tr><th>ID</th><th>Recommendation</th><th>Page</th><th>Issue</th></tr></thead>
<tbody>$($parseRows -join "`n")</tbody></table>"})
</body></html>
"@
$html | Out-File -FilePath $htmlPath -Encoding UTF8
Write-AuditLog "HTML: $htmlPath"

# Self-audit log
$elapsed = (Get-Date) - $script:StartTime
Write-AuditLog "=== Complete in $([math]::Round($elapsed.TotalSeconds,1))s. READ-ONLY run; no system changes made. ==="
@("CIS Dynamic DC Audit — Self-Audit Transcript",
  "PDF: $PdfPath",
  "Host: $env:COMPUTERNAME  Role: $Role",
  "All registry/secedit/auditpol reads are read-only. No system changes were made.",
  ("="*80)) + $script:AuditLog | Out-File -FilePath $logPath -Encoding UTF8

Write-Host ''
Write-Host 'Reports saved to:' -ForegroundColor Cyan
Write-Host "  $csvPath"
Write-Host "  $htmlPath"
Write-Host "  $logPath"
#endregion
