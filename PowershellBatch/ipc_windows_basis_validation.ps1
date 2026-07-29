param(
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    [Parameter(Mandatory = $true)]
    [string]$ResultJsonPath
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

function Get-ConfigProperty {
    param(
        [object]$Object,
        [string]$Name,
        [object]$Default = $null
    )

    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Name)) {
        return $Default
    }

    $property = $Object.PSObject.Properties | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    if ($null -eq $property) {
        return $Default
    }

    return $property.Value
}

function Convert-ToArray {
    param([object]$Value)

    if ($null -eq $Value) {
        return @()
    }

    if ($Value -is [System.Array]) {
        return @($Value)
    }

    return @($Value)
}

function Join-Text {
    param(
        [object]$Value,
        [string]$Separator = ", "
    )

    if ($null -eq $Value) {
        return ""
    }

    if ($Value -is [System.Array]) {
        return (($Value | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) }) -join $Separator)
    }

    return [string]$Value
}

function Get-RegValue {
    param(
        [string]$Path,
        [string]$Name
    )

    try {
        return Get-ItemPropertyValue -LiteralPath $Path -Name $Name -ErrorAction Stop
    } catch {
        return $null
    }
}

function Add-Check {
    param(
        [string]$Key,
        [int]$Id,
        [string]$Title,
        [ValidateSet("OK", "NOK", "NICHT_PRUEFBAR", "ISTWERT")]
        [string]$Status,
        [string]$Details,
        [object]$Evidence = $null
    )

    $script:Checks[$Key] = [ordered]@{
        id       = $Id
        title    = $Title
        status   = $Status
        details  = $Details
        evidence = $Evidence
    }
}

function Convert-ToDateTimeSafe {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    try {
        return [datetime]::Parse(
            $Value,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AssumeLocal
        )
    } catch {
        return $null
    }
}

function Get-AccountParts {
    param([string]$Account)

    $result = [ordered]@{
        original = $Account
        username = $Account
        domain   = $null
        taskname = $Account
    }

    if ([string]::IsNullOrWhiteSpace($Account)) {
        return [pscustomobject]$result
    }

    if ($Account -match "^([^\\]+)\\(.+)$") {
        $result.domain = $Matches[1]
        $result.username = $Matches[2]
        $result.taskname = $Account
    } elseif ($Account -match "@") {
        $result.domain = $null
        $result.username = $Account
        $result.taskname = $Account
    } else {
        $result.domain = $env:COMPUTERNAME
        $result.username = $Account
        $result.taskname = "$($env:COMPUTERNAME)\$Account"
    }

    return [pscustomobject]$result
}

function Test-WindowsCredential {
    param(
        [string]$Account,
        [string]$Password,
        [int]$LogonType = 2
    )

    $result = [ordered]@{
        success       = $false
        win32_error   = $null
        error_message = ""
        account       = $Account
        logon_type    = $LogonType
    }

    if ([string]::IsNullOrWhiteSpace($Account) -or [string]::IsNullOrEmpty($Password)) {
        $result.error_message = "Benutzername oder Kennwort wurde nicht bereitgestellt."
        return [pscustomobject]$result
    }

    if (-not ("NativeLogonMethods" -as [type])) {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class NativeLogonMethods
{
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUser(
        string lpszUsername,
        string lpszDomain,
        string lpszPassword,
        int dwLogonType,
        int dwLogonProvider,
        out IntPtr phToken);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern bool CloseHandle(IntPtr handle);
}
"@
    }

    $parts = Get-AccountParts -Account $Account
    $token = [IntPtr]::Zero

    try {
        $ok = [NativeLogonMethods]::LogonUser(
            [string]$parts.username,
            [string]$parts.domain,
            $Password,
            $LogonType,
            0,
            [ref]$token
        )

        if ($ok) {
            $result.success = $true
        } else {
            $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $result.win32_error = $errorCode
            $result.error_message = (New-Object ComponentModel.Win32Exception($errorCode)).Message
        }
    } catch {
        $result.error_message = $_.Exception.Message
    } finally {
        if ($token -ne [IntPtr]::Zero) {
            [void][NativeLogonMethods]::CloseHandle($token)
        }
    }

    return [pscustomobject]$result
}

function Resolve-AccountSid {
    param([string]$Account)

    if ([string]::IsNullOrWhiteSpace($Account)) {
        return $null
    }

    $parts = Get-AccountParts -Account $Account
    try {
        $ntAccount = New-Object System.Security.Principal.NTAccount([string]$parts.taskname)
        return ($ntAccount.Translate([System.Security.Principal.SecurityIdentifier])).Value
    } catch {
        return $null
    }
}

function Test-HighestCommandExecution {
    param(
        [string]$Account,
        [string]$Password,
        [int]$TimeoutSeconds = 30
    )

    $result = [ordered]@{
        success          = $false
        task_registered  = $false
        marker_created   = $false
        last_task_result = $null
        error            = ""
    }

    if ([string]::IsNullOrWhiteSpace($Account) -or [string]::IsNullOrEmpty($Password)) {
        $result.error = "Benutzername oder Kennwort wurde nicht bereitgestellt."
        return [pscustomobject]$result
    }

    $parts = Get-AccountParts -Account $Account
    $taskName = "Ansible_IPC_Admin_Test_$([guid]::NewGuid().ToString('N'))"
    $markerPath = Join-Path $env:TEMP "$taskName.txt"
    $service = $null
    $rootFolder = $null

    try {
        $service = New-Object -ComObject "Schedule.Service"
        $service.Connect()
        $rootFolder = $service.GetFolder("\")
        $definition = $service.NewTask(0)

        $definition.RegistrationInfo.Description = "Temporaerer Ansible-Test fuer ID0318"
        $definition.Settings.Enabled = $true
        $definition.Settings.Hidden = $true
        $definition.Settings.StartWhenAvailable = $true
        $definition.Settings.ExecutionTimeLimit = "PT1M"

        # TASK_RUNLEVEL_HIGHEST = 1; TASK_LOGON_PASSWORD = 1
        $definition.Principal.UserId = [string]$parts.taskname
        $definition.Principal.LogonType = 1
        $definition.Principal.RunLevel = 1

        $command = @"
`$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
`$principal = New-Object Security.Principal.WindowsPrincipal(`$identity)
`$isAdmin = `$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
"IsAdmin=`$isAdmin;Identity=`$(`$identity.Name)" | Set-Content -LiteralPath '$($markerPath.Replace("'", "''"))' -Encoding UTF8
if (-not `$isAdmin) { exit 5 }
exit 0
"@
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))

        $action = $definition.Actions.Create(0)
        $action.Path = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $action.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encodedCommand"

        # TASK_CREATE_OR_UPDATE = 6
        [void]$rootFolder.RegisterTaskDefinition(
            $taskName,
            $definition,
            6,
            [string]$parts.taskname,
            $Password,
            1,
            $null
        )
        $result.task_registered = $true

        $task = $rootFolder.GetTask("\$taskName")
        [void]$task.Run($null)

        $deadline = (Get-Date).AddSeconds([math]::Max(5, $TimeoutSeconds))
        do {
            Start-Sleep -Milliseconds 500
            $task = $rootFolder.GetTask("\$taskName")
            $markerExists = Test-Path -LiteralPath $markerPath
            if ($markerExists -and $task.State -ne 4) {
                break
            }
        } while ((Get-Date) -lt $deadline)

        $result.marker_created = Test-Path -LiteralPath $markerPath
        $result.last_task_result = $task.LastTaskResult

        $markerContent = ""
        if ($result.marker_created) {
            $markerContent = Get-Content -LiteralPath $markerPath -Raw -ErrorAction SilentlyContinue
        }

        $result.success = (
            $result.marker_created -and
            $markerContent -match "IsAdmin=True" -and
            [int]$result.last_task_result -eq 0
        )
    } catch {
        $result.error = $_.Exception.Message
    } finally {
        if ($null -ne $rootFolder) {
            try { $rootFolder.DeleteTask($taskName, 0) } catch {}
        }
        Remove-Item -LiteralPath $markerPath -Force -ErrorAction SilentlyContinue
    }

    return [pscustomobject]$result
}

function Get-LocalUserSafe {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $null
    }

    try {
        if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
            return Get-LocalUser -Name $Name -ErrorAction Stop
        }
    } catch {}

    try {
        $user = [ADSI]"WinNT://$env:COMPUTERNAME/$Name,user"
        $flags = [int]$user.UserFlags.Value
        return [pscustomobject]@{
            Name              = $Name
            Enabled           = (($flags -band 2) -eq 0)
            PasswordLastSet   = $null
            ADSI              = $true
        }
    } catch {
        return $null
    }
}

function Test-LocalAdministratorsMembership {
    param([string]$Account)

    $result = [ordered]@{
        is_member   = $false
        account_sid = $null
        members     = @()
        error       = ""
    }

    $accountSid = Resolve-AccountSid -Account $Account
    $result.account_sid = $accountSid

    try {
        if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
            $members = @(Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop)
            $result.members = @($members | ForEach-Object {
                [ordered]@{
                    name = [string]$_.Name
                    sid  = if ($_.SID) { [string]$_.SID.Value } else { "" }
                }
            })

            if (-not [string]::IsNullOrWhiteSpace($accountSid)) {
                $result.is_member = @($members | Where-Object { $_.SID -and $_.SID.Value -eq $accountSid }).Count -gt 0
            } else {
                $result.is_member = @($members | Where-Object { $_.Name -eq $Account -or $_.Name -match "\\$([regex]::Escape($Account))$" }).Count -gt 0
            }
        } else {
            $group = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
            $memberNames = @($group.psbase.Invoke("Members") | ForEach-Object {
                $_.GetType().InvokeMember("AdsPath", "GetProperty", $null, $_, $null)
            })
            $result.members = $memberNames
            $result.is_member = @($memberNames | Where-Object { $_ -match "/$([regex]::Escape($Account))$" }).Count -gt 0
        }
    } catch {
        $result.error = $_.Exception.Message
    }

    return [pscustomobject]$result
}

function Test-RebootAfter {
    param(
        [datetime]$LastBootTime,
        [string]$ExpectedAfter
    )

    if ([string]::IsNullOrWhiteSpace($ExpectedAfter)) {
        return [pscustomobject]@{
            status  = "ISTWERT"
            details = "Kein Mindestzeitpunkt vorgegeben; letzter Systemstart=$($LastBootTime.ToString('yyyy-MM-dd HH:mm:ss K'))."
        }
    }

    $cutoff = Convert-ToDateTimeSafe -Value $ExpectedAfter
    if ($null -eq $cutoff) {
        return [pscustomobject]@{
            status  = "NICHT_PRUEFBAR"
            details = "Der vorgegebene Mindestzeitpunkt '$ExpectedAfter' konnte nicht als Datum interpretiert werden; letzter Systemstart=$($LastBootTime.ToString('yyyy-MM-dd HH:mm:ss K'))."
        }
    }

    $ok = $LastBootTime -ge $cutoff
    return [pscustomobject]@{
        status  = $(if ($ok) { "OK" } else { "NOK" })
        details = "Letzter Systemstart=$($LastBootTime.ToString('yyyy-MM-dd HH:mm:ss K')); gefordert nach=$($cutoff.ToString('yyyy-MM-dd HH:mm:ss K'))."
    }
}

function Get-PartitionRequirementsForHost {
    param(
        [object]$RequirementsByHost,
        [string]$ComputerName,
        [string]$TargetIp
    )

    if ($null -eq $RequirementsByHost) {
        return @()
    }

    foreach ($key in @($ComputerName, $TargetIp, "default")) {
        if ([string]::IsNullOrWhiteSpace($key)) {
            continue
        }

        $value = Get-ConfigProperty -Object $RequirementsByHost -Name $key -Default $null
        if ($null -ne $value) {
            return @(Convert-ToArray -Value $value)
        }
    }

    return @()
}

function Test-Partitions {
    param(
        [object[]]$Requirements,
        [double]$DefaultToleranceGb
    )

    $actualVolumes = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 3" -ErrorAction SilentlyContinue | ForEach-Object {
        [ordered]@{
            drive       = [string]$_.DeviceID
            size_gb     = if ($_.Size) { [math]::Round([double]$_.Size / 1GB, 2) } else { $null }
            free_gb     = if ($_.FreeSpace) { [math]::Round([double]$_.FreeSpace / 1GB, 2) } else { $null }
            volume_name = [string]$_.VolumeName
            file_system = [string]$_.FileSystem
        }
    })

    if ($Requirements.Count -eq 0) {
        return [pscustomobject]@{
            status   = "ISTWERT"
            details  = "Keine hostbezogenen Partitions-Sollwerte hinterlegt."
            evidence = $actualVolumes
        }
    }

    $evidence = @()
    $allOk = $true

    foreach ($requirement in $Requirements) {
        $drive = [string](Get-ConfigProperty -Object $requirement -Name "drive" -Default "")
        $drive = $drive.Trim().ToUpperInvariant()
        if ($drive.Length -eq 1) {
            $drive += ":"
        }

        $required = [bool](Get-ConfigProperty -Object $requirement -Name "required" -Default $true)
        $expectedSize = Get-ConfigProperty -Object $requirement -Name "expected_size_gb" -Default $null
        $minSize = Get-ConfigProperty -Object $requirement -Name "min_size_gb" -Default $null
        $maxSize = Get-ConfigProperty -Object $requirement -Name "max_size_gb" -Default $null
        $tolerance = Get-ConfigProperty -Object $requirement -Name "tolerance_gb" -Default $DefaultToleranceGb

        $actual = $actualVolumes | Where-Object { $_.drive -eq $drive } | Select-Object -First 1
        $ok = $true
        $reason = ""

        if ($null -eq $actual) {
            $ok = -not $required
            $reason = $(if ($required) { "Laufwerk fehlt" } else { "Optionales Laufwerk fehlt" })
        } else {
            $actualSize = [double]$actual.size_gb
            if ($null -ne $expectedSize -and "$expectedSize" -ne "") {
                $lower = [double]$expectedSize - [double]$tolerance
                $upper = [double]$expectedSize + [double]$tolerance
                if ($actualSize -lt $lower -or $actualSize -gt $upper) {
                    $ok = $false
                    $reason = "Groesse ausserhalb Erwartung $expectedSize GB +/- $tolerance GB"
                }
            }
            if ($null -ne $minSize -and "$minSize" -ne "" -and $actualSize -lt [double]$minSize) {
                $ok = $false
                $reason = "Groesse kleiner als Minimum $minSize GB"
            }
            if ($null -ne $maxSize -and "$maxSize" -ne "" -and $actualSize -gt [double]$maxSize) {
                $ok = $false
                $reason = "Groesse groesser als Maximum $maxSize GB"
            }
            if ([string]::IsNullOrWhiteSpace($reason)) {
                $reason = "Sollwert erfuellt"
            }
        }

        if (-not $ok) {
            $allOk = $false
        }

        $evidence += [ordered]@{
            drive            = $drive
            required         = $required
            expected_size_gb = $expectedSize
            min_size_gb      = $minSize
            max_size_gb      = $maxSize
            tolerance_gb     = $tolerance
            actual           = $actual
            ok               = $ok
            reason           = $reason
        }
    }

    return [pscustomobject]@{
        status   = $(if ($allOk) { "OK" } else { "NOK" })
        details  = "Hostbezogene Partitions-Sollwerte wurden mit den vorhandenen lokalen Laufwerken verglichen."
        evidence = $evidence
    }
}

function Get-UserProfileRegistryValue {
    param(
        [string]$Sid,
        [string]$ProfilePath,
        [string]$SubKey,
        [string]$ValueName
    )

    $result = [ordered]@{
        sid          = $Sid
        profile_path = $ProfilePath
        value        = $null
        loaded       = $false
        error        = ""
    }

    if (-not [string]::IsNullOrWhiteSpace($Sid) -and (Test-Path -LiteralPath "Registry::HKEY_USERS\$Sid")) {
        $result.loaded = $true
        $result.value = Get-RegValue -Path "Registry::HKEY_USERS\$Sid\$SubKey" -Name $ValueName
        return [pscustomobject]$result
    }

    $ntUserDat = Join-Path $ProfilePath "NTUSER.DAT"
    if (-not (Test-Path -LiteralPath $ntUserDat)) {
        $result.error = "NTUSER.DAT nicht gefunden"
        return [pscustomobject]$result
    }

    $mountName = "ANSIBLE_IPC_$([guid]::NewGuid().ToString('N'))"
    try {
        & reg.exe load "HKU\$mountName" "$ntUserDat" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            $result.error = "Benutzer-Hive konnte nicht geladen werden; reg.exe RC=$LASTEXITCODE"
            return [pscustomobject]$result
        }
        $result.value = Get-RegValue -Path "Registry::HKEY_USERS\$mountName\$SubKey" -Name $ValueName
    } catch {
        $result.error = $_.Exception.Message
    } finally {
        & reg.exe unload "HKU\$mountName" | Out-Null
    }

    return [pscustomobject]$result
}

function Test-SearchIconProfiles {
    param(
        [int]$ExpectedMode,
        [object[]]$ExpectedProfiles
    )

    $profileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    $profiles = @()

    foreach ($item in @(Get-ChildItem -LiteralPath $profileListPath -ErrorAction SilentlyContinue)) {
        $sid = [string]$item.PSChildName
        if ($sid -notmatch "^S-1-5-21-") {
            continue
        }

        $path = [Environment]::ExpandEnvironmentVariables([string](Get-ItemPropertyValue -LiteralPath $item.PSPath -Name "ProfileImagePath" -ErrorAction SilentlyContinue))
        if ([string]::IsNullOrWhiteSpace($path)) {
            continue
        }

        $profileName = Split-Path -Path $path -Leaf
        if ($ExpectedProfiles.Count -gt 0) {
            $selected = @($ExpectedProfiles | Where-Object {
                [string]$_ -eq $sid -or [string]$_ -ieq $profileName -or [string]$_ -ieq $path
            }).Count -gt 0
            if (-not $selected) {
                continue
            }
        }

        $profiles += [ordered]@{
            sid          = $sid
            profile_name = $profileName
            profile_path = $path
        }
    }

    if ($profiles.Count -eq 0) {
        return [pscustomobject]@{
            status   = "NICHT_PRUEFBAR"
            details  = "Keine passenden lokalen Benutzerprofile fuer die Pruefung gefunden."
            evidence = @()
        }
    }

    $evidence = @()
    $allOk = $true
    foreach ($profile in $profiles) {
        $read = Get-UserProfileRegistryValue `
            -Sid $profile.sid `
            -ProfilePath $profile.profile_path `
            -SubKey "Software\Microsoft\Windows\CurrentVersion\Search" `
            -ValueName "SearchboxTaskbarMode"

        $ok = ($null -ne $read.value -and [int]$read.value -eq $ExpectedMode)
        if (-not $ok) {
            $allOk = $false
        }

        $evidence += [ordered]@{
            sid           = $profile.sid
            profile_name  = $profile.profile_name
            profile_path  = $profile.profile_path
            actual_mode   = $read.value
            expected_mode = $ExpectedMode
            hive_loaded   = $read.loaded
            error         = $read.error
            ok            = $ok
        }
    }

    return [pscustomobject]@{
        status   = $(if ($allOk) { "OK" } else { "NOK" })
        details  = "SearchboxTaskbarMode wurde fuer $($profiles.Count) lokale Benutzerprofile geprueft."
        evidence = $evidence
    }
}

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Konfigurationsdatei nicht gefunden: $ConfigPath"
}

$configText = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8
$Config = $configText | ConvertFrom-Json

$resultDirectory = Split-Path -Path $ResultJsonPath -Parent
if (-not (Test-Path -LiteralPath $resultDirectory)) {
    New-Item -Path $resultDirectory -ItemType Directory -Force | Out-Null
}

$Checks = [ordered]@{}
$computerSystem = Get-CimInstance Win32_ComputerSystem
$operatingSystem = Get-CimInstance Win32_OperatingSystem
$lastBootTime = [datetime]$operatingSystem.LastBootUpTime
$fqdn = ""
try { $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch {}

$targetIp = [string](Get-ConfigProperty -Object $Config -Name "TargetIp" -Default "")
$basisLoginUser = [string](Get-ConfigProperty -Object $Config -Name "BasisLoginUser" -Default "")
$basisLoginPassword = [string]$env:IPC_BASIS_LOGIN_PASSWORD
$adminLUser = [string](Get-ConfigProperty -Object $Config -Name "AdminLUser" -Default "Admin_L")
$adminLPassword = [string]$env:IPC_ADMIN_L_PASSWORD

# ID0017 / ID0022: Passwortbasierte Anmeldung und verwendetes Kennwort pruefen.
$basisCredentialResult = Test-WindowsCredential -Account $basisLoginUser -Password $basisLoginPassword -LogonType 2
$basisStatus = if ([string]::IsNullOrEmpty($basisLoginPassword)) { "NICHT_PRUEFBAR" } elseif ($basisCredentialResult.success) { "OK" } else { "NOK" }
Add-Check `
    -Key "ID0017_Anmelden_mit_Passwort" `
    -Id 17 `
    -Title "Anmelden mit Passwort" `
    -Status $basisStatus `
    -Details "Interaktive Windows-Anmeldevalidierung fuer Benutzer '$basisLoginUser'; Kennwort wird weder ausgegeben noch gespeichert. Erfolg=$($basisCredentialResult.success); Win32Fehler=$($basisCredentialResult.win32_error); Meldung=$($basisCredentialResult.error_message)." `
    -Evidence ([ordered]@{ user = $basisLoginUser; credential_valid = $basisCredentialResult.success; logon_type = 2; password_exposed = $false })

Add-Check `
    -Key "ID0022_Passwort" `
    -Id 22 `
    -Title "Passwort aus Uebergabeliste verwenden" `
    -Status $basisStatus `
    -Details "Das in Semaphore/Vault uebergebene Kennwort fuer '$basisLoginUser' wurde durch LogonUser validiert. Der Kennwortinhalt wird nicht mit der Uebergabeliste verglichen und nicht protokolliert. Erfolg=$($basisCredentialResult.success)." `
    -Evidence ([ordered]@{ user = $basisLoginUser; supplied_password_valid = $basisCredentialResult.success; password_exposed = $false })

# IDs 0023, 0066 und 0314: Neustarts koennen nur gegen einen vorgegebenen Mindestzeitpunkt bewertet werden.
foreach ($rebootDefinition in @(
    [ordered]@{ key = "ID0023_Rechner_neu_starten"; id = 23; title = "Rechner neu starten nach Namensaenderung"; config = "ID0023ExpectedRebootAfter" },
    [ordered]@{ key = "ID0066_Rechner_neu_starten"; id = 66; title = "Rechner neu starten"; config = "ID0066ExpectedRebootAfter" },
    [ordered]@{ key = "ID0314_Rechner_neu_starten"; id = 314; title = "Rechner neu starten"; config = "ID0314ExpectedRebootAfter" }
)) {
    $expectedAfter = [string](Get-ConfigProperty -Object $Config -Name $rebootDefinition.config -Default "")
    $rebootResult = Test-RebootAfter -LastBootTime $lastBootTime -ExpectedAfter $expectedAfter
    Add-Check -Key $rebootDefinition.key -Id $rebootDefinition.id -Title $rebootDefinition.title -Status $rebootResult.status -Details $rebootResult.details -Evidence ([ordered]@{ last_boot_time = $lastBootTime.ToString("o"); expected_after = $expectedAfter })
}

# ID0030: Partitionierung mit hostbezogenen Sollwerten.
$partitionRequirementsByHost = Get-ConfigProperty -Object $Config -Name "ExpectedPartitionsByHost" -Default $null
$partitionRequirements = @(Get-PartitionRequirementsForHost -RequirementsByHost $partitionRequirementsByHost -ComputerName $env:COMPUTERNAME -TargetIp $targetIp)
$partitionTolerance = [double](Get-ConfigProperty -Object $Config -Name "PartitionSizeToleranceGb" -Default 5)
$partitionResult = Test-Partitions -Requirements $partitionRequirements -DefaultToleranceGb $partitionTolerance
Add-Check -Key "ID0030_Festplatte_partitionieren" -Id 30 -Title "Festplatte partitionieren" -Status $partitionResult.status -Details $partitionResult.details -Evidence $partitionResult.evidence

# ID0036: Client fuer Microsoft-Netzwerke und Datei-/Druckerfreigabe auf relevanten Adaptern.
$bindingComponentIds = @(Convert-ToArray (Get-ConfigProperty -Object $Config -Name "ExpectedNetworkBindingComponentIds" -Default @("ms_msclient", "ms_server")))
$adapterNameRegex = [string](Get-ConfigProperty -Object $Config -Name "NetworkAdapterNameRegex" -Default ".*")
$adapterExcludeRegex = [string](Get-ConfigProperty -Object $Config -Name "ExcludedNetworkAdapterNameRegex" -Default "(?i)Loopback|isatap|Teredo|Bluetooth")
$networkAdapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match $adapterNameRegex -and
    $_.Name -notmatch $adapterExcludeRegex -and
    $_.InterfaceDescription -notmatch $adapterExcludeRegex -and
    ($_.HardwareInterface -eq $true -or $null -eq $_.HardwareInterface)
})

$bindingEvidence = @()
$bindingAllOk = $networkAdapters.Count -gt 0
foreach ($adapter in $networkAdapters) {
    foreach ($componentId in $bindingComponentIds) {
        $binding = Get-NetAdapterBinding -Name $adapter.Name -ComponentID ([string]$componentId) -ErrorAction SilentlyContinue
        $enabled = ($null -ne $binding -and [bool]$binding.Enabled)
        if (-not $enabled) { $bindingAllOk = $false }
        $bindingEvidence += [ordered]@{
            adapter       = [string]$adapter.Name
            status        = [string]$adapter.Status
            component_id  = [string]$componentId
            display_name  = if ($binding) { [string]$binding.DisplayName } else { "" }
            enabled       = $enabled
        }
    }
}
$bindingStatus = if ($networkAdapters.Count -eq 0) { "NICHT_PRUEFBAR" } elseif ($bindingAllOk) { "OK" } else { "NOK" }
Add-Check -Key "ID0036_Netzwerkadapter_konfigurieren" -Id 36 -Title "Netzwerkadapter konfigurieren" -Status $bindingStatus -Details "Gepruefte Adapter=$($networkAdapters.Count); erwartete Bindungen=$((Join-Text $bindingComponentIds)); beide Bindungen muessen auf jedem relevanten Adapter aktiviert sein." -Evidence $bindingEvidence

# ID0286: Inaktivitaetsgrenze 600 Sekunden bzw. Sollwert aus Konfiguration.
$expectedInactivity = [int](Get-ConfigProperty -Object $Config -Name "ExpectedInactivityTimeoutSeconds" -Default 600)
$inactivityPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$actualInactivity = Get-RegValue -Path $inactivityPath -Name "InactivityTimeoutSecs"
$inactivityOk = ($null -ne $actualInactivity -and [int]$actualInactivity -eq $expectedInactivity)
Add-Check -Key "ID0286_Bildschirmschoner_Inaktivitaet" -Id 286 -Title "Inaktivitaetsgrenze des Computers konfigurieren" -Status $(if ($inactivityOk) { "OK" } else { "NOK" }) -Details "Registry=$inactivityPath\InactivityTimeoutSecs; Ist=$actualInactivity; Soll=$expectedInactivity Sekunden." -Evidence ([ordered]@{ actual = $actualInactivity; expected = $expectedInactivity })

# ID0287: Neustart-Verknuepfung auf dem gemeinsamen Desktop und als Administrator markiert.
$commonDesktop = [Environment]::GetFolderPath("CommonDesktopDirectory")
$shortcutNameRegex = [string](Get-ConfigProperty -Object $Config -Name "RestartShortcutNameRegex" -Default "(?i)neustart|restart")
$shortcutTargetRegex = [string](Get-ConfigProperty -Object $Config -Name "RestartShortcutTargetRegex" -Default "(?i)(shutdown\.exe|powershell\.exe|cmd\.exe)")
$shortcutArgumentsRegex = [string](Get-ConfigProperty -Object $Config -Name "RestartShortcutArgumentsRegex" -Default "(?i)(/r|Restart-Computer|shutdown\s+/r)")
$shortcutEvidence = @()
$shortcutMatches = @()
$wshShell = New-Object -ComObject WScript.Shell
foreach ($shortcutFile in @(Get-ChildItem -LiteralPath $commonDesktop -Filter "*.lnk" -File -ErrorAction SilentlyContinue)) {
    if ($shortcutFile.BaseName -notmatch $shortcutNameRegex) { continue }
    try {
        $shortcut = $wshShell.CreateShortcut($shortcutFile.FullName)
        $bytes = [System.IO.File]::ReadAllBytes($shortcutFile.FullName)
        $linkFlags = if ($bytes.Length -ge 24) { [BitConverter]::ToUInt32($bytes, 20) } else { 0 }
        $runAsAdministrator = (($linkFlags -band 0x00002000) -ne 0)
        $targetOk = ([string]$shortcut.TargetPath -match $shortcutTargetRegex)
        $argumentsOk = ([string]$shortcut.Arguments -match $shortcutArgumentsRegex)
        $ok = ($runAsAdministrator -and $targetOk -and $argumentsOk)
        $entry = [ordered]@{
            path                 = $shortcutFile.FullName
            target               = [string]$shortcut.TargetPath
            arguments            = [string]$shortcut.Arguments
            run_as_administrator = $runAsAdministrator
            target_ok            = $targetOk
            arguments_ok         = $argumentsOk
            ok                   = $ok
        }
        $shortcutEvidence += $entry
        if ($ok) { $shortcutMatches += $entry }
    } catch {
        $shortcutEvidence += [ordered]@{ path = $shortcutFile.FullName; error = $_.Exception.Message; ok = $false }
    }
}
$shortcutStatus = if ($shortcutEvidence.Count -eq 0) { "NOK" } elseif ($shortcutMatches.Count -gt 0) { "OK" } else { "NOK" }
Add-Check -Key "ID0287_Neustart_nur_Administrator_Verknuepfung" -Id 287 -Title "Neustart nur als Administrator - Verknuepfung" -Status $shortcutStatus -Details "Gemeinsamer Desktop=$commonDesktop; passende und als Administrator markierte Neustart-Verknuepfungen=$($shortcutMatches.Count)." -Evidence $shortcutEvidence

# ID0288: SeShutdownPrivilege darf nur die konfigurierte Administratoren-SID enthalten.
$expectedShutdownSids = @(Convert-ToArray (Get-ConfigProperty -Object $Config -Name "ExpectedShutdownPrivilegeSids" -Default @("*S-1-5-32-544")))
$securityCfgPath = Join-Path $env:TEMP "ansible_ipc_secpol_$([guid]::NewGuid().ToString('N')).inf"
$actualShutdownSids = @()
try {
    & secedit.exe /export /cfg "$securityCfgPath" /areas USER_RIGHTS | Out-Null
    if (Test-Path -LiteralPath $securityCfgPath) {
        $shutdownLine = Get-Content -LiteralPath $securityCfgPath -ErrorAction SilentlyContinue | Where-Object { $_ -match "^\s*SeShutdownPrivilege\s*=" } | Select-Object -First 1
        if ($shutdownLine -match "=\s*(.*)$") {
            $actualShutdownSids = @($Matches[1].Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        }
    }
} finally {
    Remove-Item -LiteralPath $securityCfgPath -Force -ErrorAction SilentlyContinue
}
$expectedNormalized = @($expectedShutdownSids | ForEach-Object { ([string]$_).Trim().TrimStart("*") } | Sort-Object -Unique)
$actualNormalized = @($actualShutdownSids | ForEach-Object { ([string]$_).Trim().TrimStart("*") } | Sort-Object -Unique)
$shutdownPrivilegeOk = ($actualNormalized.Count -eq $expectedNormalized.Count -and (@(Compare-Object -ReferenceObject $expectedNormalized -DifferenceObject $actualNormalized).Count -eq 0))
$shutdownPrivilegeStatus = if ($actualNormalized.Count -eq 0) { "NICHT_PRUEFBAR" } elseif ($shutdownPrivilegeOk) { "OK" } else { "NOK" }
Add-Check -Key "ID0288_Neustart_nur_Administrator_GPO" -Id 288 -Title "Herunterfahren des Systems nur fuer Administratoren" -Status $shutdownPrivilegeStatus -Details "SeShutdownPrivilege Ist=$((Join-Text $actualNormalized)); Soll=$((Join-Text $expectedNormalized))." -Evidence ([ordered]@{ actual = $actualNormalized; expected = $expectedNormalized })

# ID0289: UAC-Stufe 'Immer benachrichtigen'.
$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$expectedConsent = [int](Get-ConfigProperty -Object $Config -Name "ExpectedUacConsentPromptBehaviorAdmin" -Default 2)
$expectedSecureDesktop = [int](Get-ConfigProperty -Object $Config -Name "ExpectedUacPromptOnSecureDesktop" -Default 1)
$expectedEnableLua = [int](Get-ConfigProperty -Object $Config -Name "ExpectedUacEnableLua" -Default 1)
$actualConsent = Get-RegValue -Path $uacPath -Name "ConsentPromptBehaviorAdmin"
$actualSecureDesktop = Get-RegValue -Path $uacPath -Name "PromptOnSecureDesktop"
$actualEnableLua = Get-RegValue -Path $uacPath -Name "EnableLUA"
$uacOk = (
    $null -ne $actualConsent -and [int]$actualConsent -eq $expectedConsent -and
    $null -ne $actualSecureDesktop -and [int]$actualSecureDesktop -eq $expectedSecureDesktop -and
    $null -ne $actualEnableLua -and [int]$actualEnableLua -eq $expectedEnableLua
)
Add-Check -Key "ID0289_UAC_Einstellungen" -Id 289 -Title "UAC auf Immer benachrichtigen konfigurieren" -Status $(if ($uacOk) { "OK" } else { "NOK" }) -Details "ConsentPromptBehaviorAdmin Ist=$actualConsent/Soll=$expectedConsent; PromptOnSecureDesktop Ist=$actualSecureDesktop/Soll=$expectedSecureDesktop; EnableLUA Ist=$actualEnableLua/Soll=$expectedEnableLua." -Evidence ([ordered]@{ ConsentPromptBehaviorAdmin = $actualConsent; PromptOnSecureDesktop = $actualSecureDesktop; EnableLUA = $actualEnableLua })

# ID0290: Energieoptionen im Startmenue entfernen.
$explorerPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$hidePowerOptions = Get-RegValue -Path $explorerPolicyPath -Name "HidePowerOptions"
$legacyNoClose = Get-RegValue -Path $explorerPolicyPath -Name "NoClose"
$expectedHidePowerOptions = [int](Get-ConfigProperty -Object $Config -Name "ExpectedHidePowerOptions" -Default 1)
$acceptLegacyNoClose = [bool](Get-ConfigProperty -Object $Config -Name "AcceptLegacyNoClose" -Default $true)
$powerOptionsOk = (
    ($null -ne $hidePowerOptions -and [int]$hidePowerOptions -eq $expectedHidePowerOptions) -or
    ($acceptLegacyNoClose -and $null -ne $legacyNoClose -and [int]$legacyNoClose -eq 1)
)
Add-Check -Key "ID0290_Power_Optionen_deaktivieren" -Id 290 -Title "Neustart- und Herunterfahren-Optionen deaktivieren" -Status $(if ($powerOptionsOk) { "OK" } else { "NOK" }) -Details "HKLM Explorer-Policy: HidePowerOptions=$hidePowerOptions (Soll=$expectedHidePowerOptions); Legacy NoClose=$legacyNoClose; AcceptLegacyNoClose=$acceptLegacyNoClose." -Evidence ([ordered]@{ HidePowerOptions = $hidePowerOptions; NoClose = $legacyNoClose })

# ID0291: Symbol 'Nur lokaler Zugriff' nicht anzeigen.
$networkConnectionsPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
$actualLocalOnlyIcon = Get-RegValue -Path $networkConnectionsPolicyPath -Name "NC_DoNotShowLocalOnlyIcon"
$expectedLocalOnlyIcon = [int](Get-ConfigProperty -Object $Config -Name "ExpectedLocalOnlyIconPolicy" -Default 1)
$localOnlyIconOk = ($null -ne $actualLocalOnlyIcon -and [int]$actualLocalOnlyIcon -eq $expectedLocalOnlyIcon)
Add-Check -Key "ID0291_Netzwerksymbol" -Id 291 -Title "Netzwerksymbol Nur lokaler Zugriff nicht anzeigen" -Status $(if ($localOnlyIconOk) { "OK" } else { "NOK" }) -Details "Registry=$networkConnectionsPolicyPath\NC_DoNotShowLocalOnlyIcon; Ist=$actualLocalOnlyIcon; Soll=$expectedLocalOnlyIcon." -Evidence ([ordered]@{ actual = $actualLocalOnlyIcon; expected = $expectedLocalOnlyIcon })

# ID0292: Suchsymbol statt Suchfeld fuer lokale Benutzerprofile.
$expectedSearchMode = [int](Get-ConfigProperty -Object $Config -Name "ExpectedSearchboxTaskbarMode" -Default 1)
$expectedSearchProfiles = @(Convert-ToArray (Get-ConfigProperty -Object $Config -Name "ExpectedSearchIconProfiles" -Default @()))
$searchProfileResult = Test-SearchIconProfiles -ExpectedMode $expectedSearchMode -ExpectedProfiles $expectedSearchProfiles
Add-Check -Key "ID0292_Suchsymbol" -Id 292 -Title "Suchsymbol auf der Taskleiste anzeigen" -Status $searchProfileResult.status -Details $searchProfileResult.details -Evidence $searchProfileResult.evidence

# ID0293: Unerwuenschte gemeinsame Desktop-Verknuepfungen muessen fehlen.
$absentShortcutNames = @(Convert-ToArray (Get-ConfigProperty -Object $Config -Name "ExpectedCommonDesktopAbsentShortcuts" -Default @("WSUS Client Connect", "SAS-DC 2024")))
$desktopItems = @(Get-ChildItem -LiteralPath $commonDesktop -Force -ErrorAction SilentlyContinue)
$presentForbiddenItems = @()
foreach ($forbiddenName in $absentShortcutNames) {
    $presentForbiddenItems += @($desktopItems | Where-Object {
        $_.BaseName -ieq [string]$forbiddenName -or $_.Name -ieq [string]$forbiddenName
    } | ForEach-Object { $_.FullName })
}
$desktopShortcutsOk = ($presentForbiddenItems.Count -eq 0)
Add-Check -Key "ID0293_Desktopverknuepfungen_entfernt" -Id 293 -Title "Desktopverknuepfungen entfernen" -Status $(if ($desktopShortcutsOk) { "OK" } else { "NOK" }) -Details "Gemeinsamer Desktop=$commonDesktop; verbotene Namen=$((Join-Text $absentShortcutNames)); noch vorhanden=$((Join-Text $presentForbiddenItems ' | '))." -Evidence ([ordered]@{ expected_absent = $absentShortcutNames; present = $presentForbiddenItems })

# ID0311: LMHOSTS-Abfrage deaktivieren.
$lmhostsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
$actualLmhosts = Get-RegValue -Path $lmhostsPath -Name "EnableLMHOSTS"
$expectedLmhosts = [int](Get-ConfigProperty -Object $Config -Name "ExpectedEnableLmhosts" -Default 0)
$lmhostsOk = ($null -ne $actualLmhosts -and [int]$actualLmhosts -eq $expectedLmhosts)
Add-Check -Key "ID0311_LMHOSTS_deaktiviert" -Id 311 -Title "LMHOSTS-Abfrage deaktivieren" -Status $(if ($lmhostsOk) { "OK" } else { "NOK" }) -Details "Registry=$lmhostsPath\EnableLMHOSTS; Ist=$actualLmhosts; Soll=$expectedLmhosts." -Evidence ([ordered]@{ actual = $actualLmhosts; expected = $expectedLmhosts })

# IDs 0315, 0317 und 0318: Admin_L-Kennwort, Anmeldung und erhoehte CMD-Ausfuehrung.
$adminLocalName = if ($adminLUser -match "\\") { ($adminLUser -split "\\", 2)[1] } else { $adminLUser }
$adminUser = Get-LocalUserSafe -Name $adminLocalName
$adminCredentialResult = Test-WindowsCredential -Account $adminLUser -Password $adminLPassword -LogonType 2
$adminPasswordMinSetDateText = [string](Get-ConfigProperty -Object $Config -Name "AdminLPasswordMinSetDate" -Default "")
$adminPasswordMinSetDate = Convert-ToDateTimeSafe -Value $adminPasswordMinSetDateText
$adminPasswordLastSet = if ($adminUser -and $adminUser.PasswordLastSet) { [datetime]$adminUser.PasswordLastSet } else { $null }
$adminPasswordDateOk = if ($null -eq $adminPasswordMinSetDate) { $true } elseif ($null -eq $adminPasswordLastSet) { $false } else { $adminPasswordLastSet -ge $adminPasswordMinSetDate }

if ([string]::IsNullOrEmpty($adminLPassword)) {
    $adminPasswordStatus = "NICHT_PRUEFBAR"
} elseif ($null -eq $adminUser -or -not [bool]$adminUser.Enabled -or -not $adminCredentialResult.success -or -not $adminPasswordDateOk) {
    $adminPasswordStatus = "NOK"
} else {
    $adminPasswordStatus = "OK"
}
Add-Check -Key "ID0315_Admin_L_Kennwort" -Id 315 -Title "Admin_L Kennwort aendern" -Status $adminPasswordStatus -Details "Benutzer=$adminLUser; vorhanden=$($null -ne $adminUser); aktiviert=$($adminUser.Enabled); Kennwort gueltig=$($adminCredentialResult.success); PasswordLastSet=$adminPasswordLastSet; Mindestdatum=$adminPasswordMinSetDateText. Kennwort wird nicht protokolliert." -Evidence ([ordered]@{ user = $adminLUser; exists = ($null -ne $adminUser); enabled = if ($adminUser) { [bool]$adminUser.Enabled } else { $false }; credential_valid = $adminCredentialResult.success; password_last_set = if ($adminPasswordLastSet) { $adminPasswordLastSet.ToString("o") } else { "" }; expected_min_set_date = $adminPasswordMinSetDateText; password_exposed = $false })

$adminLoginStatus = if ([string]::IsNullOrEmpty($adminLPassword)) { "NICHT_PRUEFBAR" } elseif ($adminCredentialResult.success) { "OK" } else { "NOK" }
Add-Check -Key "ID0317_Admin_L_Anmeldung" -Id 317 -Title "Anmeldung mit Admin_L testen" -Status $adminLoginStatus -Details "Interaktiver LogonUser-Test fuer '$adminLUser'; Erfolg=$($adminCredentialResult.success); Win32Fehler=$($adminCredentialResult.win32_error); Meldung=$($adminCredentialResult.error_message)." -Evidence ([ordered]@{ user = $adminLUser; credential_valid = $adminCredentialResult.success; logon_type = 2; password_exposed = $false })

$adminMembership = Test-LocalAdministratorsMembership -Account $adminLUser
if ([string]::IsNullOrEmpty($adminLPassword)) {
    $adminElevationStatus = "NICHT_PRUEFBAR"
    $adminElevationTest = [pscustomobject]@{ success = $false; task_registered = $false; marker_created = $false; last_task_result = $null; error = "Admin_L-Kennwort nicht bereitgestellt." }
} elseif (-not $adminCredentialResult.success -or -not $adminMembership.is_member) {
    $adminElevationStatus = "NOK"
    $adminElevationTest = [pscustomobject]@{ success = $false; task_registered = $false; marker_created = $false; last_task_result = $null; error = "Kennwort ungueltig oder Benutzer ist kein Mitglied der lokalen Administratoren." }
} else {
    $adminElevationTest = Test-HighestCommandExecution -Account $adminLUser -Password $adminLPassword -TimeoutSeconds 30
    $adminElevationStatus = if ($adminElevationTest.success) { "OK" } else { "NOK" }
}
Add-Check -Key "ID0318_Admin_L_CMD_als_Administrator" -Id 318 -Title "CMD als Administrator Admin_L oeffnen" -Status $adminElevationStatus -Details "Lokale Administratorenmitgliedschaft=$($adminMembership.is_member); erhoehte temporaere Befehlsausfuehrung=$($adminElevationTest.success); TaskResult=$($adminElevationTest.last_task_result); Fehler=$($adminElevationTest.error). Temporaere Aufgabe und Marker werden entfernt." -Evidence ([ordered]@{ user = $adminLUser; administrators_member = $adminMembership.is_member; account_sid = $adminMembership.account_sid; elevated_command_success = $adminElevationTest.success; task_registered = $adminElevationTest.task_registered; marker_created = $adminElevationTest.marker_created; last_task_result = $adminElevationTest.last_task_result; password_exposed = $false })

$result = [ordered]@{
    scan_timestamp     = ""
    target_timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss K")
    ip                 = $targetIp
    ansible_reachable  = $true
    computername       = [string]$computerSystem.Name
    fqdn               = $fqdn
    domain             = if ([bool]$computerSystem.PartOfDomain) { [string]$computerSystem.Domain } else { "" }
    workgroup          = if (-not [bool]$computerSystem.PartOfDomain) { [string]$computerSystem.Workgroup } else { "" }
    part_of_domain     = [bool]$computerSystem.PartOfDomain
    os_caption         = [string]$operatingSystem.Caption
    os_version         = [string]$operatingSystem.Version
    winrm_port         = Get-ConfigProperty -Object $Config -Name "WinRmPort" -Default ""
    winrm_scheme       = Get-ConfigProperty -Object $Config -Name "WinRmScheme" -Default ""
    winrm_open_ports   = Get-ConfigProperty -Object $Config -Name "WinRmOpenPorts" -Default ""
    checks             = $Checks
    error              = ""
}

$result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ResultJsonPath -Encoding UTF8
Write-Output "IPC_WINDOWS_BASIS_RESULT=$ResultJsonPath"
exit 0
