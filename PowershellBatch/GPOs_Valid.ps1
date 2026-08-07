#requires -Version 5.1
<#
.SYNOPSIS
    Read-only snapshot of effective and explicitly configured Windows Group Policy settings (improved v1.1).

.DESCRIPTION
    Collects Group Policy / local policy information without changing the target system and
    writes one JSON result file.

    Environment variables expected from Ansible:
      VALIDATION_RESULT_DIR  - directory in which the JSON file is written
      VALIDATION_TARGET_IP   - target IP used in file name and metadata

    File name:
      <IP>_<ComputerName>_GPOs_Valid_<yyyyMMdd_HHmmss>.json

    Important interpretation:
      Windows does not expose one universal database that maps every policy setting to the
      Microsoft default for every OS build, edition and ADMX version. Therefore this script
      treats settings that are explicitly present in policy stores, security policy, RSOP,
      Group Policy history or GPO-related stores as "explicitly configured / non-default
      candidates". It additionally records selected effective settings that are commonly
      written by Security Policy or Group Policy Preferences outside the Policies registry.

    Design goals:
      - read-only collection; no policy refresh and no configuration changes
      - works on domain-joined and workgroup computers
      - PowerShell 5.1 compatible
      - no dependency on RSAT / GroupPolicy PowerShell module
      - individual collector failures do not abort the complete snapshot
      - sensitive policy values such as passwords, tokens and license data are redacted
      - native command exit codes are reflected in collection status
      - firewall GPO provenance is traced through ActiveStore
      - policies of other currently loaded user hives are inventoried
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:CollectionStatus = [ordered]@{}
$script:StartTime = Get-Date
$script:Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# -----------------------------------------------------------------------------
# Generic helpers
# -----------------------------------------------------------------------------
function Convert-ToSafeFileNamePart {
    param(
        [AllowNull()][string]$Value,
        [string]$Fallback = 'unknown'
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $Fallback }

    $safe = $Value.Trim()
    foreach ($c in [System.IO.Path]::GetInvalidFileNameChars()) {
        $safe = $safe.Replace([string]$c, '-')
    }
    $safe = $safe.Replace(':', '-')
    $safe = $safe.Replace('/', '-')
    $safe = $safe.Replace('\', '-')
    $safe = $safe.Trim([char[]]'. ')

    if ([string]::IsNullOrWhiteSpace($safe)) { return $Fallback }
    return $safe
}

function Invoke-SafeCollection {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock
    )

    $started = Get-Date
    try {
        $data = & $ScriptBlock
        $script:CollectionStatus[$Name] = [ordered]@{
            Status     = 'OK'
            StartedUtc = $started.ToUniversalTime().ToString('o')
            DurationMs = [int]((Get-Date) - $started).TotalMilliseconds
            Error      = $null
        }
        return $data
    }
    catch {
        $script:CollectionStatus[$Name] = [ordered]@{
            Status     = 'ERROR'
            StartedUtc = $started.ToUniversalTime().ToString('o')
            DurationMs = [int]((Get-Date) - $started).TotalMilliseconds
            Error      = [ordered]@{
                Message               = $_.Exception.Message
                ExceptionType         = $_.Exception.GetType().FullName
                FullyQualifiedErrorId = $_.FullyQualifiedErrorId
                Category              = [string]$_.CategoryInfo.Category
                TargetName            = [string]$_.CategoryInfo.TargetName
            }
        }
        return $null
    }
}

function Invoke-NativeReadOnly {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @()
    )

    $commandText = ($FilePath + ' ' + ($Arguments -join ' ')).Trim()

    try {
        $output = & $FilePath @Arguments 2>&1
        $exitCode = $LASTEXITCODE
        $succeeded = ($exitCode -eq 0)

        return [pscustomobject][ordered]@{
            Command   = $commandText
            ExitCode  = $exitCode
            Succeeded = $succeeded
            Output    = @($output | ForEach-Object { [string]$_ })
            Error     = if ($succeeded) { $null } else { "Native command exited with code $exitCode." }
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            Command   = $commandText
            ExitCode  = $null
            Succeeded = $false
            Output    = @()
            Error     = $_.Exception.Message
        }
    }
}

function Set-CollectionResultStatus {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('OK','PARTIAL','ERROR')][string]$Status,
        [AllowNull()][string]$Message,
        [AllowNull()]$Details
    )

    if (-not $script:CollectionStatus.Contains($Name)) { return }

    $entry = $script:CollectionStatus[$Name]
    $entry['Status'] = $Status

    if (-not [string]::IsNullOrWhiteSpace($Message) -or $null -ne $Details) {
        $entry['Error'] = [ordered]@{
            Message = $Message
            Details = $Details
        }
    }
}

function Get-Sha256String {
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) { return $null }

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-Sha256Bytes {
    param([AllowNull()][byte[]]$Value)
    if ($null -eq $Value) { return $null }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($Value))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Test-SensitiveValueName {
    param(
        [string]$Path,
        [string]$Name
    )

    # Match sensitive tokens even when they are embedded in names such as
    # DefaultPassword, VNCPassword, ApiKeyValue or PrivateKeyBlob.
    if ($Name -match '(?i)(password|passwd|pwd|credential|secret|token|private.?key|licen[cs]e.?key|activation.?key|auth.?key|api.?key|cpassword)') {
        return $true
    }

    # Also protect values below obviously sensitive containers.
    if ($Path -match '(?i)\\(secrets?|credentials?)(\\|$)') {
        return $true
    }

    return $false
}

function Convert-RegistryValueForJson {
    param(
        [AllowNull()]$Value,
        [string]$Path,
        [string]$Name
    )

    if (Test-SensitiveValueName -Path $Path -Name $Name) {
        $length = $null
        try {
            if ($Value -is [byte[]]) { $length = $Value.Length }
            elseif ($null -ne $Value) { $length = ([string]$Value).Length }
        }
        catch { }

        return [pscustomobject][ordered]@{
            Redacted = $true
            Reason   = 'Sensitive registry value name'
            Length   = $length
            Value    = '<redacted>'
        }
    }

    if ($Value -is [byte[]]) {
        if ($Value.Length -le 2048) {
            return [pscustomobject][ordered]@{
                DataType     = 'Binary'
                Length       = $Value.Length
                Base64       = [Convert]::ToBase64String($Value)
                Sha256       = Get-Sha256Bytes -Value $Value
                Truncated    = $false
            }
        }
        return [pscustomobject][ordered]@{
            DataType     = 'Binary'
            Length       = $Value.Length
            Base64       = $null
            Sha256       = Get-Sha256Bytes -Value $Value
            Truncated    = $true
        }
    }

    if ($Value -is [string] -and $Value.Length -gt 32768) {
        return [pscustomobject][ordered]@{
            DataType  = 'String'
            Length    = $Value.Length
            Preview   = $Value.Substring(0, 32768)
            Sha256    = Get-Sha256String -Value $Value
            Truncated = $true
        }
    }

    return $Value
}

function Get-RegistryValuesRecursive {
    param(
        [Parameter(Mandatory = $true)][string]$RootPath,
        [Parameter(Mandatory = $true)][string]$Source,
        [int]$MaxEntries = 50000
    )

    $records = New-Object System.Collections.Generic.List[object]

    if (-not (Test-Path -LiteralPath $RootPath)) {
        return @()
    }

    $keys = @()
    try { $keys += Get-Item -LiteralPath $RootPath -ErrorAction Stop } catch { }
    try { $keys += @(Get-ChildItem -LiteralPath $RootPath -Recurse -ErrorAction SilentlyContinue) } catch { }

    foreach ($key in $keys) {
        if ($records.Count -ge $MaxEntries) { break }

        try {
            $valueNames = @($key.GetValueNames())
        }
        catch {
            continue
        }

        foreach ($valueName in $valueNames) {
            if ($records.Count -ge $MaxEntries) { break }

            try {
                $displayName = if ([string]::IsNullOrEmpty($valueName)) { '(Default)' } else { $valueName }
                $kind = $key.GetValueKind($valueName).ToString()
                $raw = $key.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)

                $records.Add([pscustomobject][ordered]@{
                    Source    = $Source
                    Path      = ($key.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', '')
                    Name      = $displayName
                    ValueKind = $kind
                    Value     = Convert-RegistryValueForJson -Value $raw -Path $key.Name -Name $displayName
                })
            }
            catch { }
        }
    }

    return @($records)
}

function Get-SelectedRegistryValues {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Names,
        [string]$Source = 'EffectiveSetting'
    )

    $result = New-Object System.Collections.Generic.List[object]

    if (-not (Test-Path -LiteralPath $Path)) {
        return @()
    }

    try { $key = Get-Item -LiteralPath $Path -ErrorAction Stop } catch { return @() }

    foreach ($name in $Names) {
        try {
            $registryName = if ($name -eq '(Default)') { '' } else { $name }
            if (@($key.GetValueNames()) -notcontains $registryName) { continue }
            $raw = $key.GetValue($registryName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $displayName = if ([string]::IsNullOrEmpty($registryName)) { '(Default)' } else { $registryName }
            $result.Add([pscustomobject][ordered]@{
                Source    = $Source
                Path      = ($key.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', '')
                Name      = $displayName
                ValueKind = $key.GetValueKind($registryName).ToString()
                Value     = Convert-RegistryValueForJson -Value $raw -Path $key.Name -Name $displayName
            })
        }
        catch { }
    }

    return @($result)
}

function Convert-SecurityTemplateToObject {
    param([Parameter(Mandatory = $true)][string]$Path)

    $sections = [ordered]@{}
    $currentSection = $null

    foreach ($lineRaw in @(Get-Content -LiteralPath $Path -ErrorAction Stop)) {
        $line = [string]$lineRaw
        $trim = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trim)) { continue }
        if ($trim.StartsWith(';')) { continue }

        if ($trim -match '^\[(.+)\]$') {
            $currentSection = $Matches[1]
            if (-not $sections.Contains($currentSection)) {
                $sections[$currentSection] = New-Object System.Collections.Generic.List[object]
            }
            continue
        }

        if ($null -eq $currentSection) { continue }

        $name = $trim
        $value = $null
        $idx = $trim.IndexOf('=')
        if ($idx -ge 0) {
            $name = $trim.Substring(0, $idx).Trim()
            $value = $trim.Substring($idx + 1).Trim()
        }

        $sections[$currentSection].Add([pscustomobject][ordered]@{
            Name  = $name
            Value = $value
        })
    }

    $output = [ordered]@{}
    foreach ($sectionName in $sections.Keys) {
        $output[$sectionName] = @($sections[$sectionName])
    }
    return [pscustomobject]$output
}

function Get-SecurityPolicyExport {
    param(
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][bool]$MergedPolicy
    )

    $suffix = if ($MergedPolicy) { 'merged' } else { 'local' }
    $cfgPath = Join-Path $WorkingDirectory ("secpol_{0}_{1}.inf" -f $suffix, [guid]::NewGuid().ToString('N'))

    $args = @('/export', '/cfg', $cfgPath, '/quiet')
    if ($MergedPolicy) { $args += '/mergedpolicy' }
    $args += @('/areas', 'SECURITYPOLICY', 'GROUP_MGMT', 'USER_RIGHTS', 'REGKEYS', 'FILESTORE', 'SERVICES')

    try {
        $native = Invoke-NativeReadOnly -FilePath "$env:SystemRoot\System32\secedit.exe" -Arguments $args
        $parsed = $null
        $fileInfo = $null

        if (Test-Path -LiteralPath $cfgPath) {
            try {
                $fileInfo = Get-Item -LiteralPath $cfgPath -ErrorAction Stop
                $parsed = Convert-SecurityTemplateToObject -Path $cfgPath
            }
            catch { }
        }

        return [pscustomobject][ordered]@{
            Mode       = if ($MergedPolicy) { 'MergedLocalAndDomain' } else { 'LocalSecurityDatabase' }
            ExitCode   = $native.ExitCode
            Command    = $native.Command
            Error      = $native.Error
            FileSize   = if ($fileInfo) { [int64]$fileInfo.Length } else { $null }
            Sections   = $parsed
        }
    }
    finally {
        Remove-Item -LiteralPath $cfgPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-RsopGpos {
    param([Parameter(Mandatory = $true)][ValidateSet('Computer','User')][string]$Scope)

    $namespace = if ($Scope -eq 'Computer') { 'root\RSOP\Computer' } else { 'root\RSOP\User' }
    $result = New-Object System.Collections.Generic.List[object]

    try {
        $gpos = @(Get-CimInstance -Namespace $namespace -ClassName RSOP_GPO -ErrorAction Stop)
        foreach ($gpo in $gpos) {
            $record = [ordered]@{}
            foreach ($propertyName in @(
                'name','guidName','id','accessDenied','enabled','fileSystemPath',
                'filterAllowed','version','SOM','securityDescriptor','WMIFilter'
            )) {
                if ($gpo.PSObject.Properties.Name -contains $propertyName) {
                    $record[$propertyName] = $gpo.$propertyName
                }
            }
            $result.Add([pscustomobject]$record)
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            Available = $false
            Namespace = $namespace
            Error     = $_.Exception.Message
            GPOs      = @()
        }
    }

    return [pscustomobject][ordered]@{
        Available = $true
        Namespace = $namespace
        Error     = $null
        GPOs      = @($result)
    }
}

function Protect-SensitiveTextLines {
    param([AllowNull()][object[]]$Lines)

    $result = New-Object System.Collections.Generic.List[string]
    foreach ($lineObject in @($Lines)) {
        $line = [string]$lineObject
        if ($line -match '(?i)(cpassword|licensekey|licencekey|activationkey|api[_ -]?key|auth[_ -]?key|secret|credential|token)') {
            $idxColon = $line.IndexOf(':')
            $idxEqual = $line.IndexOf('=')
            $idx = -1
            if ($idxColon -ge 0 -and $idxEqual -ge 0) { $idx = [Math]::Min($idxColon, $idxEqual) }
            elseif ($idxColon -ge 0) { $idx = $idxColon }
            elseif ($idxEqual -ge 0) { $idx = $idxEqual }

            if ($idx -ge 0) {
                $result.Add($line.Substring(0, $idx + 1) + ' <redacted>')
            }
            else {
                $result.Add('<redacted sensitive gpresult line>')
            }
        }
        else {
            $result.Add($line)
        }
    }
    return @($result)
}

function Get-GpResultText {
    param([Parameter(Mandatory = $true)][ValidateSet('COMPUTER','USER')][string]$Scope)

    $native = Invoke-NativeReadOnly -FilePath "$env:SystemRoot\System32\gpresult.exe" -Arguments @('/SCOPE', $Scope, '/Z')
    $native.Output = @(Protect-SensitiveTextLines -Lines $native.Output)
    return $native
}

function Get-AdvancedAuditPolicy {
    $native = Invoke-NativeReadOnly -FilePath "$env:SystemRoot\System32\auditpol.exe" -Arguments @('/get', '/category:*', '/r')
    $rows = @()
    $parseSucceeded = $false
    $parseError = $null

    if ($native.Succeeded -and $native.Output.Count -gt 0) {
        try {
            $rows = @($native.Output | ConvertFrom-Csv -Delimiter ',' -ErrorAction Stop)
            $parseSucceeded = $true
        }
        catch {
            $parseError = $_.Exception.Message
        }
    }
    elseif ($native.Succeeded) {
        $parseError = 'auditpol returned no CSV rows.'
    }

    return [pscustomobject][ordered]@{
        ExitCode       = $native.ExitCode
        Succeeded      = $native.Succeeded
        ParseSucceeded = $parseSucceeded
        Error          = $native.Error
        ParseError     = $parseError
        Rows           = $rows
        Raw            = $native.Output
    }
}

function Get-FileInventory {
    param([Parameter(Mandatory = $true)][string[]]$Roots)

    $result = New-Object System.Collections.Generic.List[object]

    foreach ($root in $Roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }

        foreach ($file in @(Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue)) {
            $hash = $null
            try { $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() } catch { }

            $result.Add([pscustomobject][ordered]@{
                Path          = $file.FullName
                Length        = [int64]$file.Length
                LastWriteTime = $file.LastWriteTime.ToString('o')
                Sha256        = $hash
            })
        }
    }

    return @($result)
}

function Get-GroupPolicyOperationalEvents {
    param([int]$MaxEvents = 100)

    $logName = 'Microsoft-Windows-GroupPolicy/Operational'
    try {
        $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
        $events = @()
        if ($log.IsEnabled) {
            $events = @(Get-WinEvent -FilterHashtable @{ LogName = $logName } -MaxEvents $MaxEvents -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    TimeCreated = if ($_.TimeCreated) { $_.TimeCreated.ToString('o') } else { $null }
                    Id          = $_.Id
                    Level       = $_.Level
                    LevelName   = $_.LevelDisplayName
                    Provider    = $_.ProviderName
                    RecordId    = $_.RecordId
                    Message     = $_.Message
                }
            })
        }

        return [pscustomobject][ordered]@{
            LogExists = $true
            Enabled   = $log.IsEnabled
            RecordCount = $log.RecordCount
            Events    = $events
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            LogExists = $false
            Enabled   = $null
            RecordCount = $null
            Error     = $_.Exception.Message
            Events    = @()
        }
    }
}

function Get-GpoFirewallSnapshot {
    $profiles = @()
    $rules = @()
    $errors = New-Object System.Collections.Generic.List[string]
    $profileCmdAvailable = [bool](Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)
    $ruleCmdAvailable = [bool](Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)

    if ($profileCmdAvailable) {
        try {
            $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    Name                    = $_.Name
                    Enabled                 = $_.Enabled
                    DefaultInboundAction    = [string]$_.DefaultInboundAction
                    DefaultOutboundAction   = [string]$_.DefaultOutboundAction
                    AllowInboundRules       = $_.AllowInboundRules
                    AllowLocalFirewallRules = $_.AllowLocalFirewallRules
                    AllowLocalIPsecRules    = $_.AllowLocalIPsecRules
                    NotifyOnListen          = $_.NotifyOnListen
                    LogFileName             = $_.LogFileName
                    LogMaxSizeKilobytes     = $_.LogMaxSizeKilobytes
                    LogAllowed              = $_.LogAllowed
                    LogBlocked              = $_.LogBlocked
                }
            })
        }
        catch {
            $errors.Add('Get-NetFirewallProfile: ' + $_.Exception.Message)
        }
    }
    else {
        $errors.Add('Get-NetFirewallProfile is not available.')
    }

    if ($ruleCmdAvailable) {
        try {
            # -TracePolicyStore is essential here: it resolves the policy source of
            # rules in ActiveStore so GroupPolicy can be identified reliably.
            $candidateRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -ErrorAction Stop | Where-Object {
                ([string]$_.PolicyStoreSourceType -eq 'GroupPolicy')
            })

            foreach ($rule in $candidateRules) {
                $port = $null
                $app = $null
                $addr = $null
                try { $port = $rule | Get-NetFirewallPortFilter -ErrorAction Stop } catch { }
                try { $app = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop } catch { }
                try { $addr = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop } catch { }

                $rules += [pscustomobject][ordered]@{
                    Name                  = $rule.Name
                    DisplayName           = $rule.DisplayName
                    Description           = $rule.Description
                    Enabled               = [string]$rule.Enabled
                    Direction             = [string]$rule.Direction
                    Action                = [string]$rule.Action
                    Profile               = [string]$rule.Profile
                    PolicyStoreSource     = [string]$rule.PolicyStoreSource
                    PolicyStoreSourceType = [string]$rule.PolicyStoreSourceType
                    Protocol              = if ($port) { [string]$port.Protocol } else { $null }
                    LocalPort             = if ($port) { $port.LocalPort } else { $null }
                    RemotePort            = if ($port) { $port.RemotePort } else { $null }
                    Program               = if ($app) { $app.Program } else { $null }
                    LocalAddress          = if ($addr) { $addr.LocalAddress } else { $null }
                    RemoteAddress         = if ($addr) { $addr.RemoteAddress } else { $null }
                }
            }
        }
        catch {
            $errors.Add('Get-NetFirewallRule: ' + $_.Exception.Message)
        }
    }
    else {
        $errors.Add('Get-NetFirewallRule is not available.')
    }

    return [pscustomobject][ordered]@{
        Available            = ($profileCmdAvailable -and $ruleCmdAvailable)
        Errors               = @($errors)
        ActiveProfiles       = $profiles
        GroupPolicyRuleCount = $rules.Count
        GroupPolicyRules     = @($rules)
    }
}

function Get-ServicePolicyRelevantSnapshot {
    $serviceNames = @(
        'CertPropSvc','DPS','pla','bthserv','WdiServiceHost','RmSvc','lfsvc',
        'MapsBroker','PhoneSvc','WalletService','FontCache3.0.0.0','icssvc',
        'wisvc','BTAGService','WMPNetworkSvc','SEMgrSvc'
    )

    $result = @()
    foreach ($name in $serviceNames) {
        try {
            $svc = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $name.Replace("'", "''")) -ErrorAction Stop
            if ($svc) {
                $result += [pscustomobject][ordered]@{
                    Name        = $svc.Name
                    DisplayName = $svc.DisplayName
                    State       = $svc.State
                    StartMode   = $svc.StartMode
                    StartName   = $svc.StartName
                    PathName    = $svc.PathName
                }
            }
            else {
                $result += [pscustomobject][ordered]@{
                    Name        = $name
                    Present     = $false
                }
            }
        }
        catch {
            $result += [pscustomobject][ordered]@{
                Name    = $name
                Present = $false
                Error   = $_.Exception.Message
            }
        }
    }
    return $result
}

function Get-InstallationRelevantEffectiveSettings {
    $items = New-Object System.Collections.Generic.List[object]

    # SMB signing - commonly configured through security policy/GPO.
    foreach ($entry in @(Get-SelectedRegistryValues -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Names @('RequireSecuritySignature','EnableSecuritySignature') -Source 'SMBClientEffective')) { $items.Add($entry) }
    foreach ($entry in @(Get-SelectedRegistryValues -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Names @('RequireSecuritySignature','EnableSecuritySignature') -Source 'SMBServerEffective')) { $items.Add($entry) }

    # Remote Desktop effective state outside Policies.
    foreach ($entry in @(Get-SelectedRegistryValues -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Names @('fDenyTSConnections') -Source 'RDPEffective')) { $items.Add($entry) }
    foreach ($entry in @(Get-SelectedRegistryValues -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Names @('UserAuthentication','SecurityLayer','MinEncryptionLevel') -Source 'RDPSecurityEffective')) { $items.Add($entry) }

    # Winlogon/security options that may be delivered by GPO/security templates.
    foreach ($entry in @(Get-SelectedRegistryValues -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Names @('DisableCAD','DontDisplayLastUserName','ShutdownWithoutLogon') -Source 'WinlogonEffective')) { $items.Add($entry) }
    foreach ($entry in @(Get-SelectedRegistryValues -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Names @('InactivityTimeoutSecs','HideFastUserSwitching','ConsentPromptBehaviorAdmin','PromptOnSecureDesktop','EnableLUA') -Source 'SystemPolicyEffective')) { $items.Add($entry) }

    # BGInfo via Group Policy Preferences commonly writes a normal Run value.
    foreach ($entry in @(Get-SelectedRegistryValues -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Names @('BGInfo','BgInfo') -Source 'GPPRelevantRunValue')) { $items.Add($entry) }

    # User cursor scheme can be delivered through GPP but is not necessarily under Policies.
    foreach ($entry in @(Get-SelectedRegistryValues -Path 'HKCU:\Control Panel\Cursors' -Names @('(Default)','Scheme Source','Arrow','AppStarting','Hand','Help','IBeam','No','NWPen','SizeAll','SizeNESW','SizeNS','SizeNWSE','SizeWE','UpArrow','Wait') -Source 'GPPRelevantCurrentUserCursor')) { $items.Add($entry) }

    # SCHANNEL protocols are often hardened by GPO preference/security templates outside Policies.
    foreach ($entry in @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols' -Source 'SCHANNELEffective' -MaxEntries 5000)) { $items.Add($entry) }

    # LSA settings frequently managed by security baselines/GPO.
    foreach ($entry in @(Get-SelectedRegistryValues -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Names @('LmCompatibilityLevel','NoLMHash','RestrictAnonymous','RestrictAnonymousSAM','LimitBlankPasswordUse','DisableDomainCreds') -Source 'LSAEffective')) { $items.Add($entry) }

    return @($items)
}

function Get-LoadedUserPolicyRegistry {
    param([AllowNull()][string]$CurrentUserSid)

    $users = New-Object System.Collections.Generic.List[object]
    $hkuRoot = 'Registry::HKEY_USERS'

    if (-not (Test-Path -LiteralPath $hkuRoot)) { return @() }

    foreach ($hive in @(Get-ChildItem -LiteralPath $hkuRoot -ErrorAction SilentlyContinue)) {
        $sid = $hive.PSChildName

        # Interactive/local/domain user SIDs. Skip *_Classes companion hives.
        if ($sid -notmatch '^S-1-5-21-(\d+-){3}\d+$') { continue }
        if (-not [string]::IsNullOrWhiteSpace($CurrentUserSid) -and $sid -eq $CurrentUserSid) { continue }

        $accountName = $null
        try {
            $sidObject = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $sid
            $accountName = $sidObject.Translate([System.Security.Principal.NTAccount]).Value
        }
        catch { }

        $values = New-Object System.Collections.Generic.List[object]
        foreach ($root in @(
            [pscustomobject]@{ Path = "Registry::HKEY_USERS\$sid\SOFTWARE\Policies"; Source = "HKU $sid Software Policies" },
            [pscustomobject]@{ Path = "Registry::HKEY_USERS\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"; Source = "HKU $sid CurrentVersion Policies" }
        )) {
            foreach ($entry in @(Get-RegistryValuesRecursive -RootPath $root.Path -Source $root.Source -MaxEntries 25000)) {
                $values.Add($entry)
            }
        }

        $users.Add([pscustomobject][ordered]@{
            Sid         = $sid
            AccountName = $accountName
            ValueCount  = $values.Count
            Values      = @($values)
        })
    }

    return @($users)
}

# -----------------------------------------------------------------------------
# Runtime / result path
# -----------------------------------------------------------------------------
$computerName = $env:COMPUTERNAME
if ([string]::IsNullOrWhiteSpace($computerName)) {
    $computerName = [System.Environment]::MachineName
}

$targetIp = $env:VALIDATION_TARGET_IP
if ([string]::IsNullOrWhiteSpace($targetIp)) {
    try {
        $targetIp = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object {
                $_.IPAddress -ne '127.0.0.1' -and
                $_.IPAddress -notlike '169.254.*' -and
                $_.AddressState -ne 'Duplicate'
            } |
            Sort-Object InterfaceMetric, SkipAsSource |
            Select-Object -First 1 -ExpandProperty IPAddress)
        if ($targetIp -is [array]) { $targetIp = $targetIp | Select-Object -First 1 }
    }
    catch { }
}
if ([string]::IsNullOrWhiteSpace($targetIp)) { $targetIp = 'unknown-ip' }

$resultDirectory = $env:VALIDATION_RESULT_DIR
if ([string]::IsNullOrWhiteSpace($resultDirectory)) {
    $resultDirectory = (Get-Location).Path
}
if (-not (Test-Path -LiteralPath $resultDirectory)) {
    New-Item -Path $resultDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
}

$timestamp = $script:StartTime.ToString('yyyyMMdd_HHmmss')
$safeIp = Convert-ToSafeFileNamePart -Value $targetIp -Fallback 'unknown-ip'
$safeComputerName = Convert-ToSafeFileNamePart -Value $computerName -Fallback 'unknown-host'
$resultFileName = '{0}_{1}_GPOs_Valid_{2}.json' -f $safeIp, $safeComputerName, $timestamp
$resultFilePath = Join-Path $resultDirectory $resultFileName

# -----------------------------------------------------------------------------
# Identity / context
# -----------------------------------------------------------------------------
$identity = Invoke-SafeCollection -Name 'IdentityAndContext' -ScriptBlock {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()

    $fqdn = $computerName
    try {
        $fqdn = [System.Net.Dns]::GetHostEntry($computerName).HostName
    }
    catch { }

    [pscustomobject][ordered]@{
        ComputerName       = $computerName
        DNSName            = $fqdn
        DomainJoined       = [bool]$cs.PartOfDomain
        DomainOrWorkgroup  = $cs.Domain
        DomainRole         = $cs.DomainRole
        CurrentUser        = $currentIdentity.Name
        CurrentUserSid     = if ($currentIdentity.User) { $currentIdentity.User.Value } else { $null }
        OSName             = $os.Caption
        OSVersion          = $os.Version
        OSBuild            = $os.BuildNumber
        ProductType        = $os.ProductType
    }
}

# -----------------------------------------------------------------------------
# Explicitly configured policy registry values
# -----------------------------------------------------------------------------
$policyRegistry = Invoke-SafeCollection -Name 'ExplicitPolicyRegistry' -ScriptBlock {
    $roots = @(
        [pscustomobject]@{ Path = 'HKLM:\SOFTWARE\Policies'; Source = 'HKLM Software Policies' },
        [pscustomobject]@{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies'; Source = 'HKLM CurrentVersion Policies' },
        [pscustomobject]@{ Path = 'HKCU:\SOFTWARE\Policies'; Source = 'HKCU Software Policies' },
        [pscustomobject]@{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies'; Source = 'HKCU CurrentVersion Policies' },
        [pscustomobject]@{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Policies'; Source = 'HKLM System Policies' }
    )

    $all = New-Object System.Collections.Generic.List[object]
    foreach ($root in $roots) {
        foreach ($entry in @(Get-RegistryValuesRecursive -RootPath $root.Path -Source $root.Source)) {
            $all.Add($entry)
        }
    }

    [pscustomobject][ordered]@{
        Interpretation = 'Explicitly present policy registry values; strong non-default/configured candidates.'
        Count          = $all.Count
        Values         = @($all)
    }
}

$loadedUserPolicyRegistry = Invoke-SafeCollection -Name 'LoadedUserPolicyRegistry' -ScriptBlock {
    $currentSid = if ($identity) { $identity.CurrentUserSid } else { $null }
    $users = @(Get-LoadedUserPolicyRegistry -CurrentUserSid $currentSid)
    $valueCount = 0
    foreach ($u in $users) { $valueCount += [int]$u.ValueCount }

    [pscustomobject][ordered]@{
        Interpretation = 'Policy registry values for other currently loaded interactive user hives. Unloaded NTUSER.DAT hives are intentionally not mounted because this collector is read-only.'
        UserCount      = $users.Count
        ValueCount     = $valueCount
        Users          = $users
    }
}

# -----------------------------------------------------------------------------
# Group Policy application / RSOP
# -----------------------------------------------------------------------------
$rsop = Invoke-SafeCollection -Name 'RSOP' -ScriptBlock {
    [pscustomobject][ordered]@{
        Computer = Get-RsopGpos -Scope Computer
        User     = Get-RsopGpos -Scope User
    }
}

$gpResult = Invoke-SafeCollection -Name 'GPResult' -ScriptBlock {
    [pscustomobject][ordered]@{
        Computer = Get-GpResultText -Scope COMPUTER
        User     = Get-GpResultText -Scope USER
    }
}

# -----------------------------------------------------------------------------
# Local + merged effective security policy
# -----------------------------------------------------------------------------
$securityPolicy = Invoke-SafeCollection -Name 'SecurityPolicy' -ScriptBlock {
    [pscustomobject][ordered]@{
        Local  = Get-SecurityPolicyExport -WorkingDirectory $resultDirectory -MergedPolicy $false
        Merged = Get-SecurityPolicyExport -WorkingDirectory $resultDirectory -MergedPolicy $true
    }
}

$advancedAuditPolicy = Invoke-SafeCollection -Name 'AdvancedAuditPolicy' -ScriptBlock {
    Get-AdvancedAuditPolicy
}

# -----------------------------------------------------------------------------
# Group Policy state/history registry
# -----------------------------------------------------------------------------
$groupPolicyState = Invoke-SafeCollection -Name 'GroupPolicyStateAndHistory' -ScriptBlock {
    $roots = @(
        [pscustomobject]@{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History'; Source = 'ComputerGPOHistory' },
        [pscustomobject]@{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State'; Source = 'ComputerGPOState' },
        [pscustomobject]@{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History'; Source = 'UserGPOHistory' },
        [pscustomobject]@{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State'; Source = 'UserGPOState' }
    )

    $values = New-Object System.Collections.Generic.List[object]
    foreach ($root in $roots) {
        foreach ($entry in @(Get-RegistryValuesRecursive -RootPath $root.Path -Source $root.Source -MaxEntries 10000)) {
            $values.Add($entry)
        }
    }

    [pscustomobject][ordered]@{
        Count  = $values.Count
        Values = @($values)
    }
}

# -----------------------------------------------------------------------------
# Local GPO file inventory (hashes only; no potentially sensitive XML content)
# -----------------------------------------------------------------------------
$localGpoFiles = Invoke-SafeCollection -Name 'LocalGPOFiles' -ScriptBlock {
    $roots = @(
        (Join-Path $env:SystemRoot 'System32\GroupPolicy'),
        (Join-Path $env:SystemRoot 'System32\GroupPolicyUsers')
    )

    $files = @(Get-FileInventory -Roots $roots)
    [pscustomobject][ordered]@{
        Roots = $roots
        Count = $files.Count
        Files = $files
    }
}

# -----------------------------------------------------------------------------
# GPO-origin firewall state/rules
# -----------------------------------------------------------------------------
$firewallPolicy = Invoke-SafeCollection -Name 'FirewallGroupPolicy' -ScriptBlock {
    Get-GpoFirewallSnapshot
}

# -----------------------------------------------------------------------------
# Installation-relevant effective settings outside pure Policies branches
# Based on common hardening/GPO practice (SMB, SCHANNEL, RDP, GPP, LSA, etc.).
# -----------------------------------------------------------------------------
$installationRelevantEffective = Invoke-SafeCollection -Name 'InstallationRelevantEffectiveSettings' -ScriptBlock {
    $effective = @(Get-InstallationRelevantEffectiveSettings)

    [pscustomobject][ordered]@{
        Interpretation = 'Observed effective values. Some can be written by local policy, security templates or GPO Preferences; current state alone cannot always prove the originating GPO.'
        Count          = $effective.Count
        Values         = $effective
        ServicesFromReferenceHardening = @(Get-ServicePolicyRelevantSnapshot)
    }
}

# -----------------------------------------------------------------------------
# Selected policy areas from installation / hardening practice
# These are convenience views; the generic registry collector remains authoritative.
# -----------------------------------------------------------------------------
$policyAreas = Invoke-SafeCollection -Name 'PolicyAreaSnapshots' -ScriptBlock {
    [pscustomobject][ordered]@{
        WindowsUpdate = @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Source 'WindowsUpdatePolicy' -MaxEntries 5000)
        Defender      = @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Source 'DefenderPolicy' -MaxEntries 5000)
        Firewall      = @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall' -Source 'FirewallPolicyRegistry' -MaxEntries 5000)
        TerminalServices = @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Source 'TerminalServicesPolicy' -MaxEntries 5000)
        AutoPlay      = @(
            @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Source 'ExplorerComputerPolicy' -MaxEntries 5000)
            @(Get-RegistryValuesRecursive -RootPath 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Source 'ExplorerUserPolicy' -MaxEntries 5000)
        )
        Telemetry     = @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Source 'TelemetryPolicy' -MaxEntries 5000)
        EventLog      = @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog' -Source 'EventLogPolicy' -MaxEntries 5000)
        Cryptography  = @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography' -Source 'CryptographyPolicy' -MaxEntries 5000)
        BitLocker      = @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Source 'BitLockerPolicy' -MaxEntries 5000)
        AppLocker      = @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2' -Source 'AppLockerPolicy' -MaxEntries 5000)
        SoftwareRestrictionPolicies = @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer' -Source 'SoftwareRestrictionPolicy' -MaxEntries 5000)
        DeviceGuard    = @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Source 'DeviceGuardPolicy' -MaxEntries 5000)
        PowerShell     = @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Source 'PowerShellPolicy' -MaxEntries 5000)
        WinRM          = @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM' -Source 'WinRMPolicy' -MaxEntries 5000)
        WindowsInstaller = @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Source 'WindowsInstallerPolicy' -MaxEntries 5000)
        DeviceInstallation = @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall' -Source 'DeviceInstallationPolicy' -MaxEntries 5000)
        RemovableStorage = @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' -Source 'RemovableStoragePolicy' -MaxEntries 5000)
        LAPS = @(
            @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -Source 'WindowsLAPSPolicy' -MaxEntries 5000)
            @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' -Source 'LegacyLAPSPolicy' -MaxEntries 5000)
        )
        Certificates  = @(
            @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates' -Source 'ComputerCertificatePolicy' -MaxEntries 5000)
            @(Get-RegistryValuesRecursive -RootPath 'HKCU:\SOFTWARE\Policies\Microsoft\SystemCertificates' -Source 'UserCertificatePolicy' -MaxEntries 5000)
        )
        InternetSettings = @(
            @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' -Source 'ComputerInternetPolicy' -MaxEntries 5000)
            @(Get-RegistryValuesRecursive -RootPath 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' -Source 'UserInternetPolicy' -MaxEntries 5000)
        )
        RealVNC       = @(Get-RegistryValuesRecursive -RootPath 'HKLM:\SOFTWARE\Policies\RealVNC' -Source 'RealVNCPolicy' -MaxEntries 5000)
        ScreenSaver   = @(Get-RegistryValuesRecursive -RootPath 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -Source 'ScreenSaverUserPolicy' -MaxEntries 5000)
    }
}

# -----------------------------------------------------------------------------
# Group Policy service and operational event history
# -----------------------------------------------------------------------------
$processingHealth = Invoke-SafeCollection -Name 'GroupPolicyProcessingHealth' -ScriptBlock {
    $gpsvc = $null
    try {
        $svc = Get-CimInstance Win32_Service -Filter "Name='gpsvc'" -ErrorAction Stop
        $gpsvc = [pscustomobject][ordered]@{
            Name      = $svc.Name
            State     = $svc.State
            StartMode = $svc.StartMode
            StartName = $svc.StartName
            ProcessId = $svc.ProcessId
        }
    }
    catch { }

    [pscustomobject][ordered]@{
        GroupPolicyClientService = $gpsvc
        OperationalLog          = Get-GroupPolicyOperationalEvents -MaxEvents 100
    }
}

# -----------------------------------------------------------------------------
# Refine collector status for native/soft failures that do not throw exceptions
# -----------------------------------------------------------------------------
if ($gpResult) {
    $gpProblems = @()
    foreach ($scopeName in @('Computer','User')) {
        $nativeResult = $gpResult.$scopeName
        if ($null -eq $nativeResult -or -not $nativeResult.Succeeded) {
            $gpProblems += [pscustomobject]@{
                Scope    = $scopeName
                ExitCode = if ($nativeResult) { $nativeResult.ExitCode } else { $null }
                Error    = if ($nativeResult) { $nativeResult.Error } else { 'No result returned.' }
            }
        }
    }
    if ($gpProblems.Count -gt 0) {
        Set-CollectionResultStatus -Name 'GPResult' -Status 'PARTIAL' -Message 'One or more gpresult scopes failed.' -Details $gpProblems
    }
}

if ($securityPolicy) {
    $seceditProblems = @()
    foreach ($modeName in @('Local','Merged')) {
        $item = $securityPolicy.$modeName
        if ($null -eq $item -or $item.ExitCode -ne 0 -or $null -eq $item.Sections) {
            $seceditProblems += [pscustomobject]@{
                Mode     = $modeName
                ExitCode = if ($item) { $item.ExitCode } else { $null }
                Error    = if ($item) { $item.Error } else { 'No result returned.' }
            }
        }
    }
    if ($seceditProblems.Count -gt 0) {
        Set-CollectionResultStatus -Name 'SecurityPolicy' -Status 'PARTIAL' -Message 'One or more secedit exports were incomplete.' -Details $seceditProblems
    }
}

if ($advancedAuditPolicy -and (-not $advancedAuditPolicy.Succeeded -or -not $advancedAuditPolicy.ParseSucceeded)) {
    Set-CollectionResultStatus -Name 'AdvancedAuditPolicy' -Status 'PARTIAL' -Message 'auditpol collection or CSV parsing was incomplete.' -Details ([pscustomobject]@{
        ExitCode   = $advancedAuditPolicy.ExitCode
        Error      = $advancedAuditPolicy.Error
        ParseError = $advancedAuditPolicy.ParseError
    })
}

if ($rsop) {
    $rsopProblems = @()
    foreach ($scopeName in @('Computer','User')) {
        $scopeResult = $rsop.$scopeName
        if ($scopeResult -and -not $scopeResult.Available) {
            $rsopProblems += [pscustomobject]@{ Scope = $scopeName; Error = $scopeResult.Error }
        }
    }
    if ($rsopProblems.Count -gt 0) {
        Set-CollectionResultStatus -Name 'RSOP' -Status 'PARTIAL' -Message 'One or more RSOP namespaces were unavailable.' -Details $rsopProblems
    }
}

if ($firewallPolicy -and @($firewallPolicy.Errors).Count -gt 0) {
    Set-CollectionResultStatus -Name 'FirewallGroupPolicy' -Status 'PARTIAL' -Message 'Firewall policy collection was incomplete.' -Details @($firewallPolicy.Errors)
}

if ($processingHealth -and $processingHealth.OperationalLog -and -not $processingHealth.OperationalLog.LogExists) {
    Set-CollectionResultStatus -Name 'GroupPolicyProcessingHealth' -Status 'PARTIAL' -Message 'Group Policy operational event log could not be read.' -Details $processingHealth.OperationalLog.Error
}

# -----------------------------------------------------------------------------
# Final JSON
# -----------------------------------------------------------------------------
$script:Stopwatch.Stop()
$partialSections = @($script:CollectionStatus.GetEnumerator() | Where-Object { $_.Value.Status -eq 'PARTIAL' } | ForEach-Object { $_.Key })
$failedSections  = @($script:CollectionStatus.GetEnumerator() | Where-Object { $_.Value.Status -eq 'ERROR' } | ForEach-Object { $_.Key })
$problemSections = @($script:CollectionStatus.GetEnumerator() | Where-Object { $_.Value.Status -ne 'OK' } | ForEach-Object { $_.Key })
$overallStatus = if ($problemSections.Count -eq 0) { 'COMPLETE' } else { 'PARTIAL' }

$summary = [ordered]@{
    DomainJoined                  = if ($identity) { $identity.DomainJoined } else { $null }
    DomainOrWorkgroup             = if ($identity) { $identity.DomainOrWorkgroup } else { $null }
    ExplicitPolicyRegistryValues  = if ($policyRegistry) { $policyRegistry.Count } else { 0 }
    OtherLoadedUserPolicyValues   = if ($loadedUserPolicyRegistry) { $loadedUserPolicyRegistry.ValueCount } else { 0 }
    ComputerRSOPGPOCount          = if ($rsop -and $rsop.Computer -and $rsop.Computer.GPOs) { @($rsop.Computer.GPOs).Count } else { 0 }
    UserRSOPGPOCount              = if ($rsop -and $rsop.User -and $rsop.User.GPOs) { @($rsop.User.GPOs).Count } else { 0 }
    ComputerRSOPGPONames          = if ($rsop -and $rsop.Computer -and $rsop.Computer.GPOs) { @($rsop.Computer.GPOs | ForEach-Object { $_.name }) } else { @() }
    UserRSOPGPONames              = if ($rsop -and $rsop.User -and $rsop.User.GPOs) { @($rsop.User.GPOs | ForEach-Object { $_.name }) } else { @() }
    GroupPolicyFirewallRuleCount  = if ($firewallPolicy) { $firewallPolicy.GroupPolicyRuleCount } else { 0 }
    LocalGPOFileCount             = if ($localGpoFiles) { $localGpoFiles.Count } else { 0 }
    CollectionProblemSections     = $problemSections.Count
    CollectionPartialSections     = $partialSections.Count
    CollectionFailedSections      = $failedSections.Count
}

$result = [ordered]@{
    SchemaVersion = '1.1'
    Metadata = [ordered]@{
        ScriptName            = 'GPOs_Valid.ps1'
        ScriptVersion         = '1.1'
        ValidationType        = 'GPOs_Valid'
        OverallStatus         = $overallStatus
        TargetIPAddress       = $targetIp
        ComputerName          = $computerName
        TimestampLocal        = $script:StartTime.ToString('o')
        TimestampUtc          = $script:StartTime.ToUniversalTime().ToString('o')
        CompletedTimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        DurationMs            = [int64]$script:Stopwatch.ElapsedMilliseconds
        PowerShellVersion     = $PSVersionTable.PSVersion.ToString()
        PowerShellEdition     = if ($PSVersionTable.PSObject.Properties.Name -contains 'PSEdition') { $PSVersionTable.PSEdition } else { 'Desktop' }
        RemoteUser            = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        ResultFileName        = $resultFileName
        ReadOnlyCollection    = $true
        PolicyInterpretation  = 'Explicit policy configuration and effective policy state are collected. A universal Microsoft-default comparison for every ADMX-backed setting is not technically available on Windows without a version-specific baseline/catalog.'
        SensitiveValueHandling = 'Registry values whose names indicate credentials, secrets, tokens or licenses are redacted.'
        ProblemSections       = $problemSections
        PartialSections       = $partialSections
        ErrorSections         = $failedSections
    }
    Summary                               = $summary
    IdentityAndContext                    = $identity
    ExplicitlyConfiguredPolicyRegistry    = $policyRegistry
    OtherLoadedUserPolicyRegistry          = $loadedUserPolicyRegistry
    ResultantSetOfPolicy                  = $rsop
    GPResult                              = $gpResult
    SecurityPolicy                       = $securityPolicy
    AdvancedAuditPolicy                  = $advancedAuditPolicy
    GroupPolicyStateAndHistory           = $groupPolicyState
    LocalGroupPolicyFiles                = $localGpoFiles
    FirewallGroupPolicy                  = $firewallPolicy
    PolicyAreaSnapshots                  = $policyAreas
    InstallationRelevantEffectiveSettings = $installationRelevantEffective
    GroupPolicyProcessingHealth          = $processingHealth
    CollectionStatus                     = $script:CollectionStatus
}

try {
    $json = $result | ConvertTo-Json -Depth 30
    [System.IO.File]::WriteAllText($resultFilePath, $json, (New-Object System.Text.UTF8Encoding($false)))
}
catch {
    Write-Error ("JSON result could not be written to '{0}': {1}" -f $resultFilePath, $_.Exception.Message)
    exit 1
}

Write-Output $resultFilePath
exit 0