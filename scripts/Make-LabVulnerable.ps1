<#
.SYNOPSIS
    Inject realistic AD misconfigurations into a lab DC so BloodHound / PathHunter
    will find a rich set of attack paths.

.DESCRIPTION
    A fresh AD lab has NO attack paths -- because nothing is broken yet. This script
    deliberately breaks 10 things that mirror real-world findings from BloodHound
    reports, then re-collect with SharpHound to see them all light up in PathHunter.

    What it creates:
      1. svc_sql        -- Kerberoastable service account (has SPN)
      2. svc_backup     -- Kerberoastable service account
      3. svc_web        -- AS-REP-Roastable service account (DONT_REQ_PREAUTH)
      4. HELPDESK group -- with john as a member
      5. john's HELPDESK group -> Account Operators (built-in privilege escalation)
      6. HELPDESK group has GenericAll over svc_backup
      7. adam has ForceChangePassword over Administrator
      8. soc has WriteOwner over Domain Admins group
      9. svc_backup added to Backup Operators (built-in priv group)
     10. soc granted DCSync rights on the domain (GetChanges + GetChangesAll)

    Resulting paths PathHunter should now find:
      john   -> HELPDESK -> Account Operators -> Domain Admins      (~3 hops)
      john   -> HELPDESK -> svc_backup -> Backup Operators -> DC    (~4 hops)
      adam   -> ForceChangePassword -> Administrator -> DA          (~2 hops)
      soc    -> WriteOwner -> Domain Admins                         (1 hop)
      soc    -> DCSync -> Full domain compromise                    (1 hop, Tier 0)

    EVERY change is logged to lab-changes.json so -Cleanup can undo them.

.PARAMETER Apply
    Apply the misconfigurations. Without this flag the script is dry-run only.

.PARAMETER Cleanup
    Reverse every misconfiguration this script created.

.PARAMETER Force
    Skip the "are you sure" prompt.

.EXAMPLE
    # Preview what would change
    .\Make-LabVulnerable.ps1

    # Actually do it
    .\Make-LabVulnerable.ps1 -Apply

    # Undo everything
    .\Make-LabVulnerable.ps1 -Cleanup

.NOTES
    Run on your Domain Controller as a Domain Admin.
    Tested against Server 2019 / 2022 with the default AD-DS role.
    Lab use only -- never run against a production domain.
#>

[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Cleanup,
    [switch]$Force
)

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
$ErrorActionPreference = 'Stop'
$LogFile     = Join-Path $PSScriptRoot 'lab-changes.json'
$TagDesc     = 'PATHHUNTER_LAB_OBJECT'   # tag on created objects for cleanup
$Password    = ConvertTo-SecureString 'Password123!' -AsPlainText -Force

# The 3 users you said you created in the lab.
# Edit these if your sAMAccountNames are different.
$LowUser1    = 'john'
$LowUser2    = 'adam'
$LowUser3    = 'soc'

# --------------------------------------------------------------------------- #
# Pretty output helpers
# --------------------------------------------------------------------------- #
function Step([string]$msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function OK  ([string]$msg) { Write-Host "    OK  $msg" -ForegroundColor Green }
function Skip([string]$msg) { Write-Host "    --  $msg" -ForegroundColor DarkGray }
function Warn([string]$msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Fail([string]$msg) { Write-Host "[X] $msg" -ForegroundColor Red }

function Banner {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host "   PathHunter -- Lab Misconfiguration Injector" -ForegroundColor Red
    Write-Host "   10 deliberate misconfigs to make BloodHound find paths" -ForegroundColor DarkGray
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host ""
}

# --------------------------------------------------------------------------- #
# Pre-flight checks
# --------------------------------------------------------------------------- #
function Test-Preflight {
    Step "Pre-flight checks"
    try { Import-Module ActiveDirectory -ErrorAction Stop } catch {
        Fail "ActiveDirectory PowerShell module not available."
        Fail "Run on a DC, or install RSAT: AD DS Tools."
        exit 1
    }
    OK "ActiveDirectory module loaded"

    $domain = Get-ADDomain
    OK "Domain: $($domain.DNSRoot)  (NetBIOS: $($domain.NetBIOSName))"

    foreach ($u in @($LowUser1,$LowUser2,$LowUser3)) {
        try {
            $null = Get-ADUser $u -ErrorAction Stop
            OK "User '$u' exists"
        } catch {
            Warn "User '$u' not found in domain -- edit the `$LowUser* variables at the top of this script"
            exit 1
        }
    }

    return $domain
}

# --------------------------------------------------------------------------- #
# Change-log helpers (so -Cleanup can undo precisely what -Apply did)
# --------------------------------------------------------------------------- #
function Load-Log {
    if (Test-Path $LogFile) { return Get-Content $LogFile -Raw | ConvertFrom-Json }
    return @()
}
function Save-Log($entries) {
    ($entries | ConvertTo-Json -Depth 6) | Set-Content -Path $LogFile -Encoding UTF8
}
function Add-LogEntry($type, $data) {
    $log = @(Load-Log) + @([PSCustomObject]@{
        type = $type
        data = $data
        when = (Get-Date).ToString('o')
    })
    Save-Log $log
}

# --------------------------------------------------------------------------- #
# Helpers: create accounts / groups, apply ACEs
# --------------------------------------------------------------------------- #
function Ensure-User($sam, [string[]]$spns = @(), [switch]$NoPreauth) {
    if (Get-ADUser -Filter "sAMAccountName -eq '$sam'" -ErrorAction SilentlyContinue) {
        Skip "User '$sam' already exists"
        return Get-ADUser $sam
    }
    if (-not $Apply) { Skip "(dry) would CREATE user $sam"; return $null }
    $u = New-ADUser -Name $sam -SamAccountName $sam `
        -AccountPassword $Password -Enabled $true `
        -Description $TagDesc -PassThru
    if ($spns.Count -gt 0) {
        Set-ADUser $sam -ServicePrincipalNames @{Add=$spns}
    }
    if ($NoPreauth) {
        Set-ADAccountControl $sam -DoesNotRequirePreAuth $true
    }
    Add-LogEntry 'user' @{ sam=$sam }
    OK "Created user '$sam'"
    return $u
}

function Ensure-Group($name) {
    if (Get-ADGroup -Filter "Name -eq '$name'" -ErrorAction SilentlyContinue) {
        Skip "Group '$name' already exists"; return Get-ADGroup $name
    }
    if (-not $Apply) { Skip "(dry) would CREATE group $name"; return $null }
    $g = New-ADGroup -Name $name -GroupScope Global -GroupCategory Security `
        -Description $TagDesc -PassThru
    Add-LogEntry 'group' @{ name=$name }
    OK "Created group '$name'"
    return $g
}

function Ensure-Member($groupName, $memberSam) {
    $g = Get-ADGroup $groupName
    $m = Get-ADObject (Get-ADUser $memberSam -ErrorAction SilentlyContinue).DistinguishedName -ErrorAction SilentlyContinue
    if (-not $m) {
        $m = Get-ADGroup $memberSam -ErrorAction SilentlyContinue
    }
    $existing = Get-ADGroupMember $groupName -ErrorAction SilentlyContinue | Where-Object { $_.SamAccountName -eq $memberSam }
    if ($existing) { Skip "$memberSam already in $groupName"; return }
    if (-not $Apply) { Skip "(dry) would ADD $memberSam -> $groupName"; return }
    Add-ADGroupMember $groupName -Members $memberSam
    Add-LogEntry 'member' @{ group=$groupName; member=$memberSam }
    OK "Added $memberSam -> $groupName"
}

# GUID for ExtendedRight: Reset password ('ForceChangePassword')
$ExtRight_ResetPwd  = [GUID]'00299570-246d-11d0-a768-00aa006e0529'
# GUID for DS-Replication-Get-Changes
$ExtRight_GetChg    = [GUID]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
# GUID for DS-Replication-Get-Changes-All
$ExtRight_GetChgAll = [GUID]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'

function Add-Ace {
    param(
        [string]$TargetDN,                    # the object to grant a right on
        [string]$TrusteeSam,                  # who gets the right
        [string]$Right,                       # GenericAll | WriteOwner | WriteDacl | ExtendedRight
        [GUID]  $ObjectType = [GUID]::Empty   # required for ExtendedRight (the GUID of the right)
    )
    $trustee = Get-ADUser $TrusteeSam -ErrorAction SilentlyContinue
    if (-not $trustee) { $trustee = Get-ADGroup $TrusteeSam }
    $sid = New-Object Security.Principal.SecurityIdentifier $trustee.SID

    if (-not $Apply) {
        Skip "(dry) would grant $Right on $TargetDN to $TrusteeSam"
        return
    }
    $acl = Get-Acl "AD:$TargetDN"
    if ($ObjectType -ne [GUID]::Empty) {
        $ace = New-Object DirectoryServices.ActiveDirectoryAccessRule(
            $sid, $Right, 'Allow', $ObjectType)
    } else {
        $ace = New-Object DirectoryServices.ActiveDirectoryAccessRule(
            $sid, $Right, 'Allow')
    }
    $acl.AddAccessRule($ace)
    Set-Acl -AclObject $acl -Path "AD:$TargetDN"
    Add-LogEntry 'ace' @{ target=$TargetDN; trustee=$TrusteeSam; right=$Right; guid=$ObjectType.ToString() }
    OK "Granted $Right on '$TargetDN' to '$TrusteeSam'"
}

# --------------------------------------------------------------------------- #
# Apply -- the 10 misconfigurations
# --------------------------------------------------------------------------- #
function Apply-Misconfigs {
    $domain = Test-Preflight
    $domDN = $domain.DistinguishedName

    Write-Host ""
    Step "1) Creating Kerberoastable svc_sql  (SPN: MSSQLSvc/sql.$($domain.DNSRoot):1433)"
    Ensure-User -sam 'svc_sql' -spns @("MSSQLSvc/sql.$($domain.DNSRoot):1433") | Out-Null

    Step "2) Creating Kerberoastable svc_backup  (SPN: BACKUP/backup.$($domain.DNSRoot))"
    $svcBackup = Ensure-User -sam 'svc_backup' -spns @("BACKUP/backup.$($domain.DNSRoot)")

    Step "3) Creating AS-REP-Roastable svc_web  (DONT_REQ_PREAUTH set)"
    Ensure-User -sam 'svc_web' -NoPreauth | Out-Null

    Step "4) Creating HELPDESK group  and adding $LowUser1 to it"
    $hd = Ensure-Group 'HELPDESK'
    Ensure-Member 'HELPDESK' $LowUser1

    Step "5) Putting HELPDESK -> Account Operators  (built-in privilege escalation)"
    Ensure-Member 'Account Operators' 'HELPDESK'

    Step "6) Granting HELPDESK GenericAll over svc_backup"
    if ($Apply -and $svcBackup) {
        Add-Ace -TargetDN $svcBackup.DistinguishedName -TrusteeSam 'HELPDESK' -Right 'GenericAll'
    } else { Skip "(dry) would grant GenericAll" }

    Step "7) Granting $LowUser2 ForceChangePassword over Administrator"
    $admin = Get-ADUser Administrator
    Add-Ace -TargetDN $admin.DistinguishedName -TrusteeSam $LowUser2 `
            -Right 'ExtendedRight' -ObjectType $ExtRight_ResetPwd

    Step "8) Granting $LowUser3 WriteOwner over Domain Admins group"
    $da = Get-ADGroup 'Domain Admins'
    Add-Ace -TargetDN $da.DistinguishedName -TrusteeSam $LowUser3 -Right 'WriteOwner'

    Step "9) Adding svc_backup to Backup Operators"
    Ensure-Member 'Backup Operators' 'svc_backup'

    Step "10) Granting $LowUser3 DCSync rights (GetChanges + GetChangesAll) on domain root"
    Add-Ace -TargetDN $domDN -TrusteeSam $LowUser3 -Right 'ExtendedRight' -ObjectType $ExtRight_GetChg
    Add-Ace -TargetDN $domDN -TrusteeSam $LowUser3 -Right 'ExtendedRight' -ObjectType $ExtRight_GetChgAll

    Write-Host ""
    if ($Apply) {
        Write-Host "================================================================" -ForegroundColor Green
        Write-Host "  DONE. 10 misconfigurations applied." -ForegroundColor Green
        Write-Host "================================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Next steps:" -ForegroundColor White
        Write-Host "  1) Re-collect with SharpHound:" -ForegroundColor White
        Write-Host "       .\SharpHound.exe -c All" -ForegroundColor Gray
        Write-Host "  2) Copy the new ZIP to your host, extract." -ForegroundColor White
        Write-Host "  3) Upload to PathHunter at http://localhost:8000/upload" -ForegroundColor White
        Write-Host "  4) Try: Start = '$LowUser1'  Target = 'domain admins'" -ForegroundColor White
        Write-Host ""
        Write-Host "Change log saved to: $LogFile" -ForegroundColor DarkGray
        Write-Host "To undo:  .\Make-LabVulnerable.ps1 -Cleanup" -ForegroundColor DarkGray
    } else {
        Write-Host "================================================================" -ForegroundColor Yellow
        Write-Host "  DRY RUN -- nothing was changed." -ForegroundColor Yellow
        Write-Host "  Re-run with -Apply to actually inject the misconfigurations." -ForegroundColor Yellow
        Write-Host "================================================================" -ForegroundColor Yellow
    }
}

# --------------------------------------------------------------------------- #
# Cleanup -- reverse every change recorded in the log
# --------------------------------------------------------------------------- #
function Cleanup-Misconfigs {
    Test-Preflight | Out-Null
    if (-not (Test-Path $LogFile)) {
        Warn "No change log found at $LogFile -- nothing to undo."
        return
    }
    $log = Load-Log
    Write-Host ""
    Step "Reversing $($log.Count) recorded changes..."

    # Process in reverse order so dependent objects come off first.
    [array]::Reverse($log)
    foreach ($entry in $log) {
        switch ($entry.type) {
            'ace' {
                try {
                    $acl = Get-Acl "AD:$($entry.data.target)"
                    $trustee = Get-ADUser $entry.data.trustee -ErrorAction SilentlyContinue
                    if (-not $trustee) { $trustee = Get-ADGroup $entry.data.trustee }
                    $sid = New-Object Security.Principal.SecurityIdentifier $trustee.SID
                    $toRemove = $acl.Access | Where-Object {
                        $_.IdentityReference -is [Security.Principal.SecurityIdentifier] -and
                        $_.IdentityReference.Value -eq $sid.Value -and
                        $_.ActiveDirectoryRights -match $entry.data.right
                    }
                    foreach ($r in $toRemove) { $acl.RemoveAccessRule($r) | Out-Null }
                    Set-Acl -AclObject $acl -Path "AD:$($entry.data.target)"
                    OK "Removed ACE: $($entry.data.right) on $($entry.data.target) for $($entry.data.trustee)"
                } catch { Warn "ACE remove failed: $_" }
            }
            'member' {
                try {
                    Remove-ADGroupMember -Identity $entry.data.group -Members $entry.data.member -Confirm:$false
                    OK "Removed $($entry.data.member) from $($entry.data.group)"
                } catch { Warn "Remove member failed: $_" }
            }
            'group' {
                try {
                    Remove-ADGroup -Identity $entry.data.name -Confirm:$false
                    OK "Deleted group $($entry.data.name)"
                } catch { Warn "Delete group failed: $_" }
            }
            'user' {
                try {
                    Remove-ADUser -Identity $entry.data.sam -Confirm:$false
                    OK "Deleted user $($entry.data.sam)"
                } catch { Warn "Delete user failed: $_" }
            }
        }
    }
    Remove-Item $LogFile -Force -ErrorAction SilentlyContinue
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "  Cleanup complete. Re-run SharpHound to see the clean graph." -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
}

# --------------------------------------------------------------------------- #
# Confirm prompt for destructive ops
# --------------------------------------------------------------------------- #
function Confirm-Action([string]$verb) {
    if ($Force) { return $true }
    Write-Host ""
    Write-Host "About to $verb misconfigurations against domain:" -ForegroundColor Yellow
    Write-Host "  $((Get-ADDomain).DNSRoot)" -ForegroundColor White
    $ans = Read-Host "Type YES to proceed"
    return ($ans -eq 'YES')
}

# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
Banner

if ($Cleanup) {
    if (-not (Confirm-Action 'REMOVE')) { Warn 'Aborted.'; exit 0 }
    Cleanup-Misconfigs
}
elseif ($Apply) {
    if (-not (Confirm-Action 'APPLY')) { Warn 'Aborted.'; exit 0 }
    Apply-Misconfigs
}
else {
    Warn "No mode flag given -- running in DRY-RUN mode (no changes made)."
    Warn "Use -Apply to actually inject, -Cleanup to undo, -Force to skip prompts."
    Apply-Misconfigs
}
