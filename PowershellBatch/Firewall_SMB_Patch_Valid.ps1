#requires -Version 5.1
<#
.SYNOPSIS
    Read-only detailed inventory of Windows Firewall, SMB/shares, autoruns/scheduled tasks and patch/servicing state.

.DESCRIPTION
    Collects installation-validation data for effective firewall configuration, SMB client/server
    configuration and shares, startup mechanisms, scheduled tasks, and Windows patch/servicing state.
    One JSON result file is written for later role-specific Soll/Ist comparison.

    Environment variables supplied by the fixed Ansible validation playbook:
      VALIDATION_RESULT_DIR  - directory in which the JSON file is written
      VALIDATION_TARGET_IP   - target IP used in file name and metadata

    File name:
      <IP>_<ComputerName>_Firewall_SMB_Patch_Valid_<yyyyMMdd_HHmmss>.json

    Design goals:
      - strictly read-only collection; no firewall/share/task/update configuration changes
      - PowerShell 5.1 compatible
      - no update scan, download or installation is triggered
      - no recursive NTFS ACL crawl; only share root ACLs are collected
      - task/autorun command strings are redacted when they appear to contain secrets
      - individual collector failures do not abort the complete snapshot
      - structured fields are preferred over raw native-command text for later comparison
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
function Convert-ToIso8601 {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    try { return ([datetime]$Value).ToString('o') } catch { return [string]$Value }
}

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

    try {
        $output = & $FilePath @Arguments 2>&1
        $exitCode = $LASTEXITCODE
        return [pscustomobject][ordered]@{
            Command  = ($FilePath + ' ' + ($Arguments -join ' ')).Trim()
            ExitCode = $exitCode
            Output   = @($output | ForEach-Object { [string]$_ })
            Error    = $null
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            Command  = ($FilePath + ' ' + ($Arguments -join ' ')).Trim()
            ExitCode = $null
            Output   = @()
            Error    = $_.Exception.Message
        }
    }
}

function Get-PrimaryIPv4Address {
    try {
        $defaultRoutes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
            Sort-Object RouteMetric, InterfaceMetric)
        foreach ($route in $defaultRoutes) {
            $candidate = @(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.IPAddress -ne '127.0.0.1' -and
                    $_.IPAddress -notlike '169.254.*' -and
                    $_.AddressState -ne 'Duplicate'
                } |
                Select-Object -First 1)
            if ($candidate.Count -gt 0) { return [string]$candidate[0].IPAddress }
        }
    }
    catch { }

    try {
        $fallback = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop |
            ForEach-Object { @($_.IPAddress) } |
            Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and $_ -ne '127.0.0.1' } |
            Select-Object -First 1)
        if ($fallback.Count -gt 0) { return [string]$fallback[0] }
    }
    catch { }

    return $null
}

function Get-Fqdn {
    param([string]$ComputerName)
    try { return [System.Net.Dns]::GetHostEntry($ComputerName).HostName } catch { return $null }
}

function Test-SensitiveText {
    param([AllowNull()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return [bool]($Value -match '(?i)(password|passwd|pwd|credential|secret|token|psk|api.?key|auth.?key|license.?key|licen[cs]e.?key|product.?key|cpassword|private.?key)')
}

function Protect-SensitiveText {
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) { return $null }
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }

    $text = [string]$Value
    if (-not (Test-SensitiveText -Value $text)) { return $text }

    # Preserve the existence of the command/configuration while avoiding accidental secret export.
    $protected = $text
    $protected = [regex]::Replace($protected, '(?i)(password|passwd|pwd|secret|token|psk|api.?key|auth.?key|license.?key|licen[cs]e.?key|product.?key|cpassword|credential)\s*[:=]\s*([^\s;,&|]+)', '$1=<redacted>')
    $protected = [regex]::Replace($protected, '(?i)(--?|-)(password|passwd|pwd|secret|token|psk|api.?key|auth.?key|license.?key|product.?key)\s+([^\s]+)', '$1$2 <redacted>')

    if ($protected -eq $text) {
        return '<redacted sensitive-looking text>'
    }
    return $protected
}

function Convert-ToJsonSafeValue {
    param([AllowNull()]$Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [string] -or $Value -is [char]) { return [string]$Value }
    if ($Value -is [datetime]) { return $Value.ToString('o') }
    if ($Value -is [timespan]) { return [string]$Value }
    if ($Value -is [bool] -or $Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64] -or $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64] -or $Value -is [single] -or $Value -is [double] -or $Value -is [decimal]) { return $Value }
    if ($Value -is [byte[]]) {
        return [pscustomobject][ordered]@{
            Type   = 'ByteArray'
            Length = $Value.Length
            Hex    = ([BitConverter]::ToString($Value)).Replace('-', '')
        }
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $obj = [ordered]@{}
        foreach ($k in $Value.Keys) { $obj[[string]$k] = Convert-ToJsonSafeValue $Value[$k] }
        return [pscustomobject]$obj
    }
    if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])) {
        return @($Value | ForEach-Object { Convert-ToJsonSafeValue $_ })
    }

    try { return [string]$Value } catch { return $null }
}

function Get-SimplePropertyBag {
    param(
        [AllowNull()]$InputObject,
        [string[]]$Exclude = @()
    )

    if ($null -eq $InputObject) { return $null }
    $defaultExclude = @(
        'CimClass','CimInstanceProperties','CimSystemProperties',
        'PSComputerName','RunspaceId','PSShowComputerName'
    )
    $excluded = @($defaultExclude + $Exclude)
    $bag = [ordered]@{}
    foreach ($p in $InputObject.PSObject.Properties) {
        if ($excluded -contains $p.Name) { continue }
        try { $bag[$p.Name] = Convert-ToJsonSafeValue $p.Value } catch { }
    }
    return [pscustomobject]$bag
}

function Get-RegistryKeySnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject][ordered]@{ Exists=$false; Path=$Path; Values=$null }
    }

    try {
        $item = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
        $values = [ordered]@{}
        foreach ($p in $item.PSObject.Properties) {
            if ($p.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
            $values[$p.Name] = Convert-ToJsonSafeValue $p.Value
        }
        return [pscustomobject][ordered]@{ Exists=$true; Path=$Path; Values=[pscustomobject]$values }
    }
    catch {
        return [pscustomobject][ordered]@{ Exists=$true; Path=$Path; Values=$null; Error=$_.Exception.Message }
    }
}

# -----------------------------------------------------------------------------
# Target / output file
# -----------------------------------------------------------------------------
$computerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
$operatingSystem = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
$computerName = if ($computerSystem.Name) { [string]$computerSystem.Name } else { [string]$env:COMPUTERNAME }
$fqdn = Get-Fqdn -ComputerName $computerName

$targetIp = $env:VALIDATION_TARGET_IP
if ([string]::IsNullOrWhiteSpace($targetIp)) { $targetIp = Get-PrimaryIPv4Address }
if ([string]::IsNullOrWhiteSpace($targetIp)) { $targetIp = 'unknown-ip' }

$resultDir = $env:VALIDATION_RESULT_DIR
if ([string]::IsNullOrWhiteSpace($resultDir)) { $resultDir = (Get-Location).Path }
if (-not (Test-Path -LiteralPath $resultDir -PathType Container)) {
    throw "VALIDATION_RESULT_DIR does not exist: $resultDir"
}

$timestamp = $script:StartTime.ToString('yyyyMMdd_HHmmss')
$safeIp = Convert-ToSafeFileNamePart -Value $targetIp -Fallback 'unknown-ip'
$safeComputerName = Convert-ToSafeFileNamePart -Value $computerName -Fallback 'unknown-host'
$resultFileName = '{0}_{1}_Firewall_SMB_Patch_Valid_{2}.json' -f $safeIp, $safeComputerName, $timestamp
$resultFilePath = Join-Path -Path $resultDir -ChildPath $resultFileName

$identity = Invoke-SafeCollection -Name 'Identity' -ScriptBlock {
    [pscustomobject][ordered]@{
        ComputerName      = $computerName
        DNSName           = $fqdn
        TargetIPAddress   = $targetIp
        Domain            = $computerSystem.Domain
        PartOfDomain      = $computerSystem.PartOfDomain
        Manufacturer      = $computerSystem.Manufacturer
        Model             = $computerSystem.Model
        OSCaption         = $operatingSystem.Caption
        OSVersion         = $operatingSystem.Version
        OSBuildNumber     = $operatingSystem.BuildNumber
        OSArchitecture    = $operatingSystem.OSArchitecture
        CurrentRemoteUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
}

# -----------------------------------------------------------------------------
# 1 - Full effective Windows Firewall state
# -----------------------------------------------------------------------------
function New-FirewallFilterMap {
    param([AllowNull()]$Objects)
    $map = @{}
    foreach ($obj in @($Objects)) {
        $id = [string]$obj.InstanceID
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        if (-not $map.ContainsKey($id)) { $map[$id] = New-Object System.Collections.ArrayList }
        [void]$map[$id].Add($obj)
    }
    return $map
}

$firewall = Invoke-SafeCollection -Name 'Firewall' -ScriptBlock {
    if (-not (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
        throw 'Get-NetFirewallRule is not available on this system.'
    }

    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
        [pscustomobject][ordered]@{
            Name                    = [string]$_.Name
            Enabled                 = $_.Enabled
            DefaultInboundAction    = [string]$_.DefaultInboundAction
            DefaultOutboundAction   = [string]$_.DefaultOutboundAction
            AllowInboundRules       = $_.AllowInboundRules
            AllowLocalFirewallRules = $_.AllowLocalFirewallRules
            AllowLocalIPsecRules    = $_.AllowLocalIPsecRules
            AllowUserApps           = $_.AllowUserApps
            AllowUserPorts          = $_.AllowUserPorts
            AllowUnicastResponseToMulticast = $_.AllowUnicastResponseToMulticast
            NotifyOnListen          = $_.NotifyOnListen
            EnableStealthModeForIPsec = $_.EnableStealthModeForIPsec
            LogFileName             = $_.LogFileName
            LogMaxSizeKilobytes     = $_.LogMaxSizeKilobytes
            LogAllowed              = $_.LogAllowed
            LogBlocked              = $_.LogBlocked
            DisabledInterfaceAliases = @($_.DisabledInterfaceAliases)
        }
    })

    $activeNetworkProfiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject][ordered]@{
            Name             = $_.Name
            InterfaceAlias   = $_.InterfaceAlias
            InterfaceIndex   = $_.InterfaceIndex
            NetworkCategory  = [string]$_.NetworkCategory
            IPv4Connectivity = [string]$_.IPv4Connectivity
            IPv6Connectivity = [string]$_.IPv6Connectivity
        }
    })

    $serviceState = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in @('MpsSvc','BFE') } |
        Sort-Object Name |
        ForEach-Object {
            [pscustomobject][ordered]@{
                Name        = $_.Name
                DisplayName = $_.DisplayName
                State       = $_.State
                StartMode   = $_.StartMode
                StartName   = $_.StartName
                PathName    = $_.PathName
            }
        })

    $rules = @(  
        Get-NetFirewallRule `
        -PolicyStore ActiveStore `
        -TracePolicyStore `
        -ErrorAction Stop |
        Sort-Object DisplayGroup, DisplayName, Name
    )

    $portMap = @{}
    $appMap = @{}
    $addressMap = @{}
    $serviceMap = @{}
    $interfaceMap = @{}
    $interfaceTypeMap = @{}
    $securityMap = @{}

    try { $portMap = New-FirewallFilterMap -Objects @($rules | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue) } catch { }
    try { $appMap = New-FirewallFilterMap -Objects @($rules | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue) } catch { }
    try { $addressMap = New-FirewallFilterMap -Objects @($rules | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue) } catch { }
    try { $serviceMap = New-FirewallFilterMap -Objects @($rules | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue) } catch { }
    try { $interfaceMap = New-FirewallFilterMap -Objects @($rules | Get-NetFirewallInterfaceFilter -ErrorAction SilentlyContinue) } catch { }
    try { $interfaceTypeMap = New-FirewallFilterMap -Objects @($rules | Get-NetFirewallInterfaceTypeFilter -ErrorAction SilentlyContinue) } catch { }
    try { $securityMap = New-FirewallFilterMap -Objects @($rules | Get-NetFirewallSecurityFilter -ErrorAction SilentlyContinue) } catch { }

    $ruleRecords = New-Object System.Collections.Generic.List[object]
    foreach ($rule in $rules) {
        $id = [string]$rule.InstanceID
        $ports = if ($portMap.ContainsKey($id)) { @($portMap[$id]) } else { @() }
        $apps = if ($appMap.ContainsKey($id)) { @($appMap[$id]) } else { @() }
        $addresses = if ($addressMap.ContainsKey($id)) { @($addressMap[$id]) } else { @() }
        $services = if ($serviceMap.ContainsKey($id)) { @($serviceMap[$id]) } else { @() }
        $interfaces = if ($interfaceMap.ContainsKey($id)) { @($interfaceMap[$id]) } else { @() }
        $interfaceTypes = if ($interfaceTypeMap.ContainsKey($id)) { @($interfaceTypeMap[$id]) } else { @() }
        $security = if ($securityMap.ContainsKey($id)) { @($securityMap[$id]) } else { @() }

        $ruleRecords.Add([pscustomobject][ordered]@{
            Name                  = $rule.Name
            InstanceID            = $id
            DisplayName           = $rule.DisplayName
            Description           = $rule.Description
            DisplayGroup          = $rule.DisplayGroup
            Group                 = $rule.Group
            Enabled               = [string]$rule.Enabled
            Profile               = [string]$rule.Profile
            Direction             = [string]$rule.Direction
            Action                = [string]$rule.Action
            EdgeTraversalPolicy   = [string]$rule.EdgeTraversalPolicy
            LooseSourceMapping    = $rule.LooseSourceMapping
            LocalOnlyMapping      = $rule.LocalOnlyMapping
            Owner                 = $rule.Owner
            PrimaryStatus         = [string]$rule.PrimaryStatus
            Status                = [string]$rule.Status
            EnforcementStatus     = [string]$rule.EnforcementStatus
            PolicyStoreSource     = [string]$rule.PolicyStoreSource
            PolicyStoreSourceType = [string]$rule.PolicyStoreSourceType
            PortFilters = @($ports | ForEach-Object {
                [pscustomobject][ordered]@{
                    Protocol      = [string]$_.Protocol
                    LocalPort     = @($_.LocalPort)
                    RemotePort    = @($_.RemotePort)
                    IcmpType      = @($_.IcmpType)
                    DynamicTarget = [string]$_.DynamicTarget
                }
            })
            ApplicationFilters = @($apps | ForEach-Object {
                [pscustomobject][ordered]@{
                    Program = $_.Program
                    Package = $_.Package
                }
            })
            AddressFilters = @($addresses | ForEach-Object {
                [pscustomobject][ordered]@{
                    LocalAddress  = @($_.LocalAddress)
                    RemoteAddress = @($_.RemoteAddress)
                }
            })
            ServiceFilters = @($services | ForEach-Object {
                [pscustomobject][ordered]@{ Service = $_.Service }
            })
            InterfaceFilters = @($interfaces | ForEach-Object {
                [pscustomobject][ordered]@{ InterfaceAlias = @($_.InterfaceAlias) }
            })
            InterfaceTypeFilters = @($interfaceTypes | ForEach-Object {
                [pscustomobject][ordered]@{ InterfaceType = [string]$_.InterfaceType }
            })
            SecurityFilters = @($security | ForEach-Object {
                Get-SimplePropertyBag -InputObject $_
            })
        })
    }

    $allRules = @($ruleRecords)

    $settings = $null
    if (Get-Command Get-NetFirewallSetting -ErrorAction SilentlyContinue) {
        try { $settings = Get-SimplePropertyBag -InputObject (Get-NetFirewallSetting -PolicyStore ActiveStore -ErrorAction Stop) } catch { }
    }

    $ipsecRules = @()
    if (Get-Command Get-NetIPsecRule -ErrorAction SilentlyContinue) {
        try {
            $ipsecRules = @(Get-NetIPsecRule -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    Name                  = $_.Name
                    DisplayName           = $_.DisplayName
                    DisplayGroup          = $_.DisplayGroup
                    Enabled               = [string]$_.Enabled
                    Profile               = [string]$_.Profile
                    Mode                  = [string]$_.Mode
                    InboundSecurity       = [string]$_.InboundSecurity
                    OutboundSecurity      = [string]$_.OutboundSecurity
                    PrimaryStatus         = [string]$_.PrimaryStatus
                    Status                = [string]$_.Status
                    PolicyStoreSource     = [string]$_.PolicyStoreSource
                    PolicyStoreSourceType = [string]$_.PolicyStoreSourceType
                }
            })
        }
        catch { }
    }

    [pscustomobject][ordered]@{
        Services = $serviceState
        Profiles = $profiles
        ActiveNetworkProfiles = $activeNetworkProfiles
        GlobalSettings = $settings
        Summary = [ordered]@{
            TotalRules      = $allRules.Count
            EnabledRules    = @($allRules | Where-Object Enabled -eq 'True').Count
            DisabledRules   = @($allRules | Where-Object Enabled -ne 'True').Count
            InboundRules    = @($allRules | Where-Object Direction -eq 'Inbound').Count
            OutboundRules   = @($allRules | Where-Object Direction -eq 'Outbound').Count
            AllowRules      = @($allRules | Where-Object Action -eq 'Allow').Count
            BlockRules      = @($allRules | Where-Object Action -eq 'Block').Count
            GroupPolicyRules = @($allRules | Where-Object PolicyStoreSourceType -eq 'GroupPolicy').Count
            LocalRules      = @($allRules | Where-Object PolicyStoreSourceType -eq 'Local' ).Count
            ByPolicyStoreSourceType = @($allRules | Group-Object PolicyStoreSourceType | Sort-Object Name | ForEach-Object {
                [pscustomobject]@{ SourceType=$_.Name; Count=$_.Count }
            })
            ByDisplayGroup = @($allRules | Group-Object DisplayGroup | Sort-Object Count -Descending | Select-Object -First 100 | ForEach-Object {
                [pscustomobject]@{ DisplayGroup=$_.Name; Count=$_.Count }
            })
        }
        Rules = $allRules
        CommonRemoteAccessRuleCandidates = @($allRules | Where-Object {
            (($_.DisplayName + ' ' + $_.DisplayGroup + ' ' + $_.Description) -match '(?i)(VNC|Remote Desktop|RDP|WinRM|SQL Server|SMB|File and Printer Sharing)') -or
            (@($_.PortFilters.LocalPort) -contains '5900') -or
            (@($_.PortFilters.LocalPort) -contains '5800') -or
            (@($_.PortFilters.LocalPort) -contains '3389') -or
            (@($_.PortFilters.LocalPort) -contains '445')
        })
        IPsecRules = $ipsecRules
    }
}

# Listening endpoints are runtime evidence and are intentionally separated from firewall rules.
$listeningEndpoints = Invoke-SafeCollection -Name 'ListeningEndpoints' -ScriptBlock {
    $processNames = @{}
    foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
        $processNames[[int]$p.ProcessId] = [pscustomobject]@{ Name=$p.Name; ExecutablePath=$p.ExecutablePath }
    }

    $servicesByPid = @{}
    foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.ProcessId -gt 0 })) {
        $processid = [int]$s.ProcessId
        if (-not $servicesByPid.ContainsKey($processid)) { $servicesByPid[$processid] = New-Object System.Collections.ArrayList }
        [void]$servicesByPid[$processid].Add($s.Name)
    }

    $tcp = @()
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        $tcp = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort, LocalAddress | ForEach-Object {
            $processid = [int]$_.OwningProcess
            [pscustomobject][ordered]@{
                Protocol      = 'TCP'
                LocalAddress  = $_.LocalAddress
                LocalPort     = $_.LocalPort
                State         = [string]$_.State
                OwningProcess = $processid
                ProcessName   = if ($processNames.ContainsKey($processid)) { $processNames[$processid].Name } else { $null }
                ExecutablePath = if ($processNames.ContainsKey($processid)) { $processNames[$processid].ExecutablePath } else { $null }
                Services      = if ($servicesByPid.ContainsKey($processid)) { @($servicesByPid[$processid]) } else { @() }
            }
        })
    }

    $udp = @()
    if (Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
        $udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Sort-Object LocalPort, LocalAddress | ForEach-Object {
            $processid = [int]$_.OwningProcess
            [pscustomobject][ordered]@{
                Protocol      = 'UDP'
                LocalAddress  = $_.LocalAddress
                LocalPort     = $_.LocalPort
                OwningProcess = $processid
                ProcessName   = if ($processNames.ContainsKey($processid)) { $processNames[$processid].Name } else { $null }
                ExecutablePath = if ($processNames.ContainsKey($processid)) { $processNames[$processid].ExecutablePath } else { $null }
                Services      = if ($servicesByPid.ContainsKey($processid)) { @($servicesByPid[$processid]) } else { @() }
            }
        })
    }

    [pscustomobject][ordered]@{
        Interpretation = 'Runtime listener evidence only; a firewall rule can exist without a listener and vice versa.'
        TCP = $tcp
        UDP = $udp
        Summary = [ordered]@{
            TCPListeners = $tcp.Count
            UDPEndpoints = $udp.Count
            CommonPorts = @(
                80,443,135,139,445,1433,2383,3389,5800,5900,5985,5986
            ) | ForEach-Object {
                $port = $_
                [pscustomobject]@{
                    Port = $port
                    TCPListening = (@($tcp | Where-Object LocalPort -eq $port).Count -gt 0)
                    UDPPresent   = (@($udp | Where-Object LocalPort -eq $port).Count -gt 0)
                }
            }
        }
    }
}

# -----------------------------------------------------------------------------
# 2 - SMB server/client configuration, shares and permissions
# -----------------------------------------------------------------------------
function Get-NtfsAclSnapshot {
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject][ordered]@{ Path=$Path; Exists=$false; Reason='NoPath' }
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject][ordered]@{ Path=$Path; Exists=$false; Reason='PathNotFound' }
    }

    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $sddl = $null
        try { $sddl = $acl.Sddl } catch { }
        return [pscustomobject][ordered]@{
            Path               = $Path
            Exists             = $true
            Owner              = [string]$acl.Owner
            Group              = [string]$acl.Group
            AreAccessRulesProtected = $acl.AreAccessRulesProtected
            AreAuditRulesProtected  = $acl.AreAuditRulesProtected
            Sddl               = $sddl
            Access = @($acl.Access | ForEach-Object {
                [pscustomobject][ordered]@{
                    IdentityReference = [string]$_.IdentityReference
                    AccessControlType = [string]$_.AccessControlType
                    FileSystemRights  = [string]$_.FileSystemRights
                    IsInherited       = $_.IsInherited
                    InheritanceFlags  = [string]$_.InheritanceFlags
                    PropagationFlags  = [string]$_.PropagationFlags
                }
            })
            Audit = @($acl.Audit | ForEach-Object {
                [pscustomobject][ordered]@{
                    IdentityReference = [string]$_.IdentityReference
                    AuditFlags        = [string]$_.AuditFlags
                    FileSystemRights  = [string]$_.FileSystemRights
                    IsInherited       = $_.IsInherited
                    InheritanceFlags  = [string]$_.InheritanceFlags
                    PropagationFlags  = [string]$_.PropagationFlags
                }
            })
        }
    }
    catch {
        return [pscustomobject][ordered]@{ Path=$Path; Exists=$true; Error=$_.Exception.Message }
    }
}

$smb = Invoke-SafeCollection -Name 'SMB' -ScriptBlock {
    $serverConfig = $null
    $clientConfig = $null
    if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
        try { $serverConfig = Get-SimplePropertyBag -InputObject (Get-SmbServerConfiguration -ErrorAction Stop) } catch { }
    }
    if (Get-Command Get-SmbClientConfiguration -ErrorAction SilentlyContinue) {
        try { $clientConfig = Get-SimplePropertyBag -InputObject (Get-SmbClientConfiguration -ErrorAction Stop) } catch { }
    }

    $shares = New-Object System.Collections.Generic.List[object]
    if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) {
        foreach ($share in @(Get-SmbShare -ErrorAction Stop | Sort-Object ScopeName, Name)) {
            $access = @()
            try {
                $access = @(Get-SmbShareAccess -Name $share.Name -ScopeName $share.ScopeName -ErrorAction Stop | ForEach-Object {
                    [pscustomobject][ordered]@{
                        Name              = $_.Name
                        ScopeName         = $_.ScopeName
                        AccountName       = $_.AccountName
                        AccessControlType = [string]$_.AccessControlType
                        AccessRight       = [string]$_.AccessRight
                    }
                })
            }
            catch {
                try {
                    $access = @(Get-SmbShareAccess -Name $share.Name -ErrorAction Stop | ForEach-Object {
                        [pscustomobject][ordered]@{
                            Name              = $_.Name
                            ScopeName         = $_.ScopeName
                            AccountName       = $_.AccountName
                            AccessControlType = [string]$_.AccessControlType
                            AccessRight       = [string]$_.AccessRight
                        }
                    })
                }
                catch { }
            }

            $sharePath = [string]$share.Path
            $shares.Add([pscustomobject][ordered]@{
                Name                    = $share.Name
                ScopeName               = $share.ScopeName
                Path                    = $sharePath
                Description             = $share.Description
                ShareState              = [string]$share.ShareState
                ShareType               = [string]$share.ShareType
                AvailabilityType        = [string]$share.AvailabilityType
                CachingMode             = [string]$share.CachingMode
                FolderEnumerationMode   = [string]$share.FolderEnumerationMode
                ContinuouslyAvailable   = $share.ContinuouslyAvailable
                EncryptData             = $share.EncryptData
                CATimeout               = $share.CATimeout
                ConcurrentUserLimit     = $share.ConcurrentUserLimit
                CurrentUsers            = $share.CurrentUsers
                Special                 = $share.Special
                Temporary               = $share.Temporary
                SharePermissions        = $access
                NtfsRootAcl             = Get-NtfsAclSnapshot -Path $sharePath
            })
        }
    }
    else {
        foreach ($share in @(Get-CimInstance Win32_Share -ErrorAction SilentlyContinue | Sort-Object Name)) {
            $shares.Add([pscustomobject][ordered]@{
                Name        = $share.Name
                Path        = $share.Path
                Description = $share.Description
                Type        = $share.Type
                MaximumAllowed = $share.MaximumAllowed
                AllowMaximum = $share.AllowMaximum
                NtfsRootAcl = Get-NtfsAclSnapshot -Path ([string]$share.Path)
                FallbackSource = 'Win32_Share'
            })
        }
    }

    $smbFeatures = [ordered]@{}
    if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
        foreach ($featureName in @('SMB1Protocol','SMB1Protocol-Client','SMB1Protocol-Server','SMBDirect')) {
            try {
                $f = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction Stop
                $smbFeatures[$featureName] = [pscustomobject][ordered]@{
                    FeatureName     = $f.FeatureName
                    State           = [string]$f.State
                    RestartRequired = [string]$f.RestartRequired
                }
            }
            catch {
                $smbFeatures[$featureName] = [pscustomobject][ordered]@{ FeatureName=$featureName; Available=$false; Error=$_.Exception.Message }
            }
        }
    }

    $serverRegistry = Get-RegistryKeySnapshot -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $clientRegistry = Get-RegistryKeySnapshot -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'

    $shareArray = @($shares)
    [pscustomobject][ordered]@{
        ServerConfiguration = $serverConfig
        ClientConfiguration = $clientConfig
        FeatureState        = [pscustomobject]$smbFeatures
        EffectiveRegistry   = [pscustomobject][ordered]@{
            Server = $serverRegistry
            Client = $clientRegistry
        }
        Summary = [ordered]@{
            ShareCount             = $shareArray.Count
            NonSpecialShareCount   = @($shareArray | Where-Object { -not $_.Special }).Count
            EncryptedShares        = @($shareArray | Where-Object EncryptData -eq $true).Count
            SharesWithMissingPath  = @($shareArray | Where-Object { $_.Path -and -not (Test-Path -LiteralPath $_.Path) }).Count
            SMB1ServerEnabled      = if ($serverConfig -and $serverConfig.PSObject.Properties.Name -contains 'EnableSMB1Protocol') { $serverConfig.EnableSMB1Protocol } else { $null }
            SMB2ServerEnabled      = if ($serverConfig -and $serverConfig.PSObject.Properties.Name -contains 'EnableSMB2Protocol') { $serverConfig.EnableSMB2Protocol } else { $null }
            ServerRequireSecuritySignature = if ($serverConfig -and $serverConfig.PSObject.Properties.Name -contains 'RequireSecuritySignature') { $serverConfig.RequireSecuritySignature } else { $null }
            ClientRequireSecuritySignature = if ($clientConfig -and $clientConfig.PSObject.Properties.Name -contains 'RequireSecuritySignature') { $clientConfig.RequireSecuritySignature } else { $null }
        }
        Shares = $shareArray
    }
}

# -----------------------------------------------------------------------------
# 3 - Scheduled tasks and autorun/startup mechanisms
# -----------------------------------------------------------------------------
function Get-ScheduledTaskActionSnapshot {
    param($Action)
    if ($null -eq $Action) { return $null }
    [pscustomobject][ordered]@{
        Type             = $Action.CimClass.CimClassName
        Execute          = $Action.Execute
        Arguments        = Protect-SensitiveText -Value ([string]$Action.Arguments)
        WorkingDirectory = $Action.WorkingDirectory
        ClassId          = $Action.ClassId
        Data             = Protect-SensitiveText -Value ([string]$Action.Data)
        Id               = $Action.Id
    }
}

function Get-ScheduledTaskTriggerSnapshot {
    param($Trigger)
    if ($null -eq $Trigger) { return $null }

    $triggerType = $null
    try { $triggerType = $Trigger.CimClass.CimClassName } catch { $triggerType = $Trigger.GetType().FullName }

    $bag = [ordered]@{
        Type          = $triggerType
        Enabled       = $Trigger.Enabled
        StartBoundary = $Trigger.StartBoundary
        EndBoundary   = $Trigger.EndBoundary
        Delay         = [string]$Trigger.Delay
        RandomDelay   = [string]$Trigger.RandomDelay
        UserId        = $Trigger.UserId
        DaysInterval  = $Trigger.DaysInterval
        WeeksInterval = $Trigger.WeeksInterval
        DaysOfWeek    = Convert-ToJsonSafeValue $Trigger.DaysOfWeek
        MonthsOfYear  = Convert-ToJsonSafeValue $Trigger.MonthsOfYear
        WeeksOfMonth  = Convert-ToJsonSafeValue $Trigger.WeeksOfMonth
        Subscription  = Protect-SensitiveText -Value ([string]$Trigger.Subscription)
        StateChange   = [string]$Trigger.StateChange
        ExecutionTimeLimit = [string]$Trigger.ExecutionTimeLimit
    }
    try {
        if ($Trigger.Repetition) {
            $bag.Repetition = [pscustomobject][ordered]@{
                Interval          = [string]$Trigger.Repetition.Interval
                Duration          = [string]$Trigger.Repetition.Duration
                StopAtDurationEnd = $Trigger.Repetition.StopAtDurationEnd
            }
        }
    }
    catch { }
    [pscustomobject]$bag
}

function Get-AutorunRegistryKey {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Scope,
        [Parameter(Mandatory = $true)][string]$Mechanism
    )

    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    try {
        $item = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
        $records = New-Object System.Collections.Generic.List[object]
        foreach ($p in $item.PSObject.Properties) {
            if ($p.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
            $records.Add([pscustomobject][ordered]@{
                Scope     = $Scope
                Mechanism = $Mechanism
                Path      = $Path
                Name      = $p.Name
                Command   = Protect-SensitiveText -Value ([string]$p.Value)
            })
        }
        return @($records)
    }
    catch { return @([pscustomobject][ordered]@{ Scope=$Scope; Mechanism=$Mechanism; Path=$Path; Error=$_.Exception.Message }) }
}

function Get-StartupFolderSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$Scope,
        [AllowNull()][string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Container)) {
        return [pscustomobject][ordered]@{ Scope=$Scope; Path=$Path; Exists=$false; Items=@() }
    }

    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell } catch { }
    $items = @()
    foreach ($file in @(Get-ChildItem -LiteralPath $Path -File -Force -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $shortcut = $null
        if ($shell -and $file.Extension -ieq '.lnk') {
            try {
                $lnk = $shell.CreateShortcut($file.FullName)
                $shortcut = [pscustomobject][ordered]@{
                    TargetPath       = $lnk.TargetPath
                    Arguments        = Protect-SensitiveText -Value ([string]$lnk.Arguments)
                    WorkingDirectory = $lnk.WorkingDirectory
                    Description      = $lnk.Description
                    IconLocation     = $lnk.IconLocation
                    WindowStyle      = $lnk.WindowStyle
                }
            }
            catch { }
        }

        $items += [pscustomobject][ordered]@{
            Name             = $file.Name
            FullName         = $file.FullName
            Extension        = $file.Extension
            LengthBytes      = $file.Length
            CreationTimeUtc  = $file.CreationTimeUtc.ToString('o')
            LastWriteTimeUtc = $file.LastWriteTimeUtc.ToString('o')
            Shortcut         = $shortcut
        }
    }

    [pscustomobject][ordered]@{ Scope=$Scope; Path=$Path; Exists=$true; Items=$items }
}

$scheduledTasks = Invoke-SafeCollection -Name 'ScheduledTasks' -ScriptBlock {
    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        return [pscustomobject][ordered]@{ Available=$false; Tasks=@(); Summary=[ordered]@{ Total=0 } }
    }

    $records = New-Object System.Collections.Generic.List[object]
    foreach ($task in @(Get-ScheduledTask -ErrorAction Stop | Sort-Object TaskPath, TaskName)) {
        $info = $null
        try { $info = Get-ScheduledTaskInfo -InputObject $task -ErrorAction Stop } catch { }

        $records.Add([pscustomobject][ordered]@{
            TaskName    = $task.TaskName
            TaskPath    = $task.TaskPath
            State       = [string]$task.State
            Author      = $task.Author
            Description = $task.Description
            URI         = $task.URI
            Source      = $task.Source
            Date        = $task.Date
            Version     = $task.Version
            Principal = if ($task.Principal) {
                [pscustomobject][ordered]@{
                    UserId               = $task.Principal.UserId
                    GroupId              = $task.Principal.GroupId
                    DisplayName          = $task.Principal.DisplayName
                    LogonType            = [string]$task.Principal.LogonType
                    RunLevel             = [string]$task.Principal.RunLevel
                    ProcessTokenSidType  = [string]$task.Principal.ProcessTokenSidType
                    RequiredPrivilege    = @($task.Principal.RequiredPrivilege)
                }
            } else { $null }
            Actions  = @($task.Actions | ForEach-Object { Get-ScheduledTaskActionSnapshot $_ })
            Triggers = @($task.Triggers | ForEach-Object { Get-ScheduledTaskTriggerSnapshot $_ })
            Settings = if ($task.Settings) {
                [pscustomobject][ordered]@{
                    AllowDemandStart               = $task.Settings.AllowDemandStart
                    AllowHardTerminate             = $task.Settings.AllowHardTerminate
                    Compatibility                  = [string]$task.Settings.Compatibility
                    DeleteExpiredTaskAfter         = [string]$task.Settings.DeleteExpiredTaskAfter
                    DisallowStartIfOnBatteries     = $task.Settings.DisallowStartIfOnBatteries
                    Enabled                        = $task.Settings.Enabled
                    ExecutionTimeLimit             = [string]$task.Settings.ExecutionTimeLimit
                    Hidden                         = $task.Settings.Hidden
                    IdleSettings                   = Get-SimplePropertyBag -InputObject $task.Settings.IdleSettings
                    MultipleInstances              = [string]$task.Settings.MultipleInstances
                    NetworkSettings                = Get-SimplePropertyBag -InputObject $task.Settings.NetworkSettings
                    Priority                       = $task.Settings.Priority
                    RestartCount                   = $task.Settings.RestartCount
                    RestartInterval                = [string]$task.Settings.RestartInterval
                    RunOnlyIfIdle                  = $task.Settings.RunOnlyIfIdle
                    RunOnlyIfNetworkAvailable      = $task.Settings.RunOnlyIfNetworkAvailable
                    StartWhenAvailable             = $task.Settings.StartWhenAvailable
                    StopIfGoingOnBatteries         = $task.Settings.StopIfGoingOnBatteries
                    WakeToRun                      = $task.Settings.WakeToRun
                }
            } else { $null }
            RuntimeInfo = if ($info) {
                [pscustomobject][ordered]@{
                    LastRunTime        = Convert-ToIso8601 $info.LastRunTime
                    LastTaskResult     = $info.LastTaskResult
                    NextRunTime        = Convert-ToIso8601 $info.NextRunTime
                    NumberOfMissedRuns = $info.NumberOfMissedRuns
                    TaskName           = $info.TaskName
                    TaskPath           = $info.TaskPath
                }
            } else { $null }
        })
    }

    $all = @($records)
    [pscustomobject][ordered]@{
        Available = $true
        Summary = [ordered]@{
            Total         = $all.Count
            Ready         = @($all | Where-Object State -eq 'Ready').Count
            Running       = @($all | Where-Object State -eq 'Running').Count
            Disabled      = @($all | Where-Object State -eq 'Disabled').Count
            Hidden        = @($all | Where-Object { $_.Settings -and $_.Settings.Hidden -eq $true }).Count
            NonMicrosoftCandidates = @($all | Where-Object {
                $_.TaskPath -notlike '\Microsoft\*' -or
                $_.Author -notmatch '(?i)Microsoft'
            }).Count
        }
        NonMicrosoftCandidates = @($all | Where-Object {
            $_.TaskPath -notlike '\Microsoft\*' -or
            $_.Author -notmatch '(?i)Microsoft'
        })
        Tasks = $all
    }
}

$autoruns = Invoke-SafeCollection -Name 'Autoruns' -ScriptBlock {
    $registryEntries = @()
    $sources = @(
        [pscustomobject]@{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Scope='LocalMachine'; Mechanism='Run' },
        [pscustomobject]@{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; Scope='LocalMachine'; Mechanism='RunOnce' },
        [pscustomobject]@{ Path='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Scope='LocalMachine32'; Mechanism='Run' },
        [pscustomobject]@{ Path='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'; Scope='LocalMachine32'; Mechanism='RunOnce' },
        [pscustomobject]@{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'; Scope='LocalMachine'; Mechanism='PoliciesExplorerRun' },
        [pscustomobject]@{ Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Scope='CurrentRemoteUser'; Mechanism='Run' },
        [pscustomobject]@{ Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; Scope='CurrentRemoteUser'; Mechanism='RunOnce' },
        [pscustomobject]@{ Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'; Scope='CurrentRemoteUser'; Mechanism='PoliciesExplorerRun' }
    )
    foreach ($source in $sources) {
        $registryEntries += @(Get-AutorunRegistryKey -Path $source.Path -Scope $source.Scope -Mechanism $source.Mechanism)
    }

    $commonStartup = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonStartup)
    $currentStartup = [Environment]::GetFolderPath([Environment+SpecialFolder]::Startup)

    $winlogon = [pscustomobject][ordered]@{
        Path     = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        Shell    = $null
        Userinit = $null
    }
    try {
        $w = Get-ItemProperty -LiteralPath $winlogon.Path -ErrorAction Stop
        $winlogon.Shell = Protect-SensitiveText -Value ([string]$w.Shell)
        $winlogon.Userinit = Protect-SensitiveText -Value ([string]$w.Userinit)
    }
    catch { }

    $startupApproved = [pscustomobject][ordered]@{
        HKLMRun = Get-RegistryKeySnapshot 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
        HKLMRun32 = Get-RegistryKeySnapshot 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'
        HKCUStartupFolder = Get-RegistryKeySnapshot 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
        HKCURun = Get-RegistryKeySnapshot 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
    }

    [pscustomobject][ordered]@{
        RegistryEntries = @($registryEntries)
        StartupFolders = @(
            (Get-StartupFolderSnapshot -Scope 'CommonStartup' -Path $commonStartup),
            (Get-StartupFolderSnapshot -Scope 'CurrentRemoteUserStartup' -Path $currentStartup)
        )
        Winlogon = $winlogon
        StartupApproved = $startupApproved
        Summary = [ordered]@{
            RegistryAutorunCount = @($registryEntries | Where-Object { $_.Name }).Count
            CommonStartupItems   = @((Get-StartupFolderSnapshot -Scope 'CommonStartup' -Path $commonStartup).Items).Count
            CurrentUserStartupItems = @((Get-StartupFolderSnapshot -Scope 'CurrentRemoteUserStartup' -Path $currentStartup).Items).Count
        }
    }
}

# Permanent WMI subscriptions are another startup/persistence mechanism and are collected read-only.
$wmiPermanentSubscriptions = Invoke-SafeCollection -Name 'WmiPermanentSubscriptions' -ScriptBlock {
    $namespace = 'root\subscription'
    $filters = @()
    $consumers = @()
    $bindings = @()

    try {
        $filters = @(Get-CimInstance -Namespace $namespace -ClassName __EventFilter -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{
                Name           = $_.Name
                EventNamespace = $_.EventNamespace
                QueryLanguage  = $_.QueryLanguage
                Query          = Protect-SensitiveText -Value ([string]$_.Query)
            }
        })
    }
    catch { }

    foreach ($className in @('CommandLineEventConsumer','ActiveScriptEventConsumer','LogFileEventConsumer','NTEventLogEventConsumer','SMTPEventConsumer')) {
        try {
            foreach ($c in @(Get-CimInstance -Namespace $namespace -ClassName $className -ErrorAction Stop)) {
                $bag = Get-SimplePropertyBag -InputObject $c
                foreach ($name in @('CommandLineTemplate','ExecutablePath','ScriptText')) {
                    if ($bag.PSObject.Properties.Name -contains $name) {
                        $bag.$name = Protect-SensitiveText -Value ([string]$bag.$name)
                    }
                }
                $consumers += [pscustomobject][ordered]@{ ConsumerClass=$className; Properties=$bag }
            }
        }
        catch { }
    }

    try {
        $bindings = @(Get-CimInstance -Namespace $namespace -ClassName __FilterToConsumerBinding -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{
                Filter   = [string]$_.Filter
                Consumer = [string]$_.Consumer
            }
        })
    }
    catch { }

    [pscustomobject][ordered]@{
        EventFilters = $filters
        Consumers    = $consumers
        Bindings     = $bindings
        Summary      = [ordered]@{ Filters=$filters.Count; Consumers=$consumers.Count; Bindings=$bindings.Count }
    }
}

# -----------------------------------------------------------------------------
# 4 - Detailed Windows patch / servicing state
# -----------------------------------------------------------------------------
function Get-PendingRebootDetailed {
    $indicators = [ordered]@{}
    $indicators.ComponentBasedServicing = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    $indicators.WindowsUpdate = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    $indicators.PendingFileRenameOperations = $false
    $indicators.PendingComputerRename = $false
    $indicators.UpdateExeVolatile = $false

    try {
        $v = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop).PendingFileRenameOperations
        $indicators.PendingFileRenameOperations = ($null -ne $v -and @($v).Count -gt 0)
    }
    catch { }
    try {
        $active = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -ErrorAction Stop).ComputerName
        $pending = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -ErrorAction Stop).ComputerName
        $indicators.PendingComputerRename = ($active -ne $pending)
    }
    catch { }
    try {
        $volatile = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Updates' -Name UpdateExeVolatile -ErrorAction Stop).UpdateExeVolatile
        $indicators.UpdateExeVolatile = ([int]$volatile -ne 0)
    }
    catch { }

    [pscustomobject][ordered]@{
        RebootPending = [bool]($indicators.Values -contains $true)
        Indicators    = [pscustomobject]$indicators
    }
}

$patchStatus = Invoke-SafeCollection -Name 'PatchStatus' -ScriptBlock {
    $currentVersion = Get-RegistryKeySnapshot -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    $hotfixes = @(Get-HotFix -ErrorAction SilentlyContinue | Sort-Object -Property @{Expression='InstalledOn';Descending=$true}, HotFixID | ForEach-Object {
        [pscustomobject][ordered]@{
            HotFixID    = $_.HotFixID
            Description = $_.Description
            InstalledBy = $_.InstalledBy
            InstalledOn = Convert-ToIso8601 $_.InstalledOn
            Caption     = $_.Caption
            FixComments = $_.FixComments
            ServicePackInEffect = $_.ServicePackInEffect
            Status      = $_.Status
        }
    })

    $updateHistory = [ordered]@{
        Available         = $false
        TotalHistoryCount = $null
        ReturnedEntries   = 0
        MaxEntries        = 1000
        Entries           = @()
        Error             = $null
    }
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $total = $searcher.GetTotalHistoryCount()
        $count = [Math]::Min([int]$total, 1000)
        $history = if ($count -gt 0) { @($searcher.QueryHistory(0, $count)) } else { @() }
        $updateHistory.Available = $true
        $updateHistory.TotalHistoryCount = $total
        $updateHistory.ReturnedEntries = $history.Count
        $updateHistory.Entries = @($history | ForEach-Object {
            $kb = @([regex]::Matches([string]$_.Title, '(?i)KB\d{6,8}') | ForEach-Object { $_.Value.ToUpperInvariant() } | Select-Object -Unique)
            [pscustomobject][ordered]@{
                Date        = Convert-ToIso8601 $_.Date
                Title       = $_.Title
                KBs         = $kb
                Description = $_.Description
                Operation   = [string]$_.Operation
                ResultCode  = [string]$_.ResultCode
                HResult     = $_.HResult
                SupportUrl  = $_.SupportUrl
                UnmappedResultCode = $_.UnmappedResultCode
                ClientApplicationID = $_.ClientApplicationID
            }
        })
    }
    catch {
        $updateHistory.Error = $_.Exception.Message
    }

    $windowsPackages = @()
    if (Get-Command Get-WindowsPackage -ErrorAction SilentlyContinue) {
        try {
            $windowsPackages = @(Get-WindowsPackage -Online -ErrorAction Stop | Sort-Object -Property @{Expression='InstallTime';Descending=$true}, PackageName | ForEach-Object {
                $kbMatches = @([regex]::Matches(([string]$_.PackageName + ' ' + [string]$_.PackageDescription), '(?i)KB\d{6,8}') | ForEach-Object { $_.Value.ToUpperInvariant() } | Select-Object -Unique)
                [pscustomobject][ordered]@{
                    PackageName        = $_.PackageName
                    PackageState       = [string]$_.PackageState
                    ReleaseType        = [string]$_.ReleaseType
                    InstallTime        = Convert-ToIso8601 $_.InstallTime
                    Applicable         = $_.Applicable
                    Copyright          = $_.Copyright
                    Company            = $_.Company
                    CreationTime       = Convert-ToIso8601 $_.CreationTime
                    Description        = $_.Description
                    InstallClient      = $_.InstallClient
                    InstallPackageName = $_.InstallPackageName
                    LastUpdateTime     = Convert-ToIso8601 $_.LastUpdateTime
                    ProductName        = $_.ProductName
                    ProductVersion     = $_.ProductVersion
                    RestartRequired    = [string]$_.RestartRequired
                    SupportInformation = $_.SupportInformation
                    KBs                = $kbMatches
                }
            })
        }
        catch { }
    }

    $dismPackages = Invoke-NativeReadOnly -FilePath 'dism.exe' -Arguments @('/Online','/Get-Packages','/Format:Table','/English')

    $allKb = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($hf in $hotfixes) {
        if ($hf.HotFixID -match '^KB\d+$') { [void]$allKb.Add($hf.HotFixID.ToUpperInvariant()) }
    }
    foreach ($e in @($updateHistory.Entries)) {
        foreach ($kb in @($e.KBs)) { if ($kb) { [void]$allKb.Add([string]$kb) } }
    }
    foreach ($pkg in $windowsPackages) {
        foreach ($kb in @($pkg.KBs)) { if ($kb) { [void]$allKb.Add([string]$kb) } }
        foreach ($m in @([regex]::Matches([string]$pkg.PackageName, '(?i)KB\d{6,8}'))) { [void]$allKb.Add($m.Value.ToUpperInvariant()) }
    }

    $servicingPackages = @($windowsPackages | Where-Object {
        $_.PackageName -match '(?i)(RollupFix|ServicingStack|SSU|LCU|Cumulative)' -or
        $_.ReleaseType -match '(?i)(Security Update|Update|Service Pack|Foundation)'
    })

    $lcuCandidates = @($windowsPackages | Where-Object {
        $_.PackageName -match '(?i)(Package_for_RollupFix|LCU|Cumulative)' -or
        $_.Description -match '(?i)Cumulative Update'
    } | Sort-Object InstallTime -Descending)

    $ssuCandidates = @($windowsPackages | Where-Object {
        $_.PackageName -match '(?i)(ServicingStack|SSU)' -or
        $_.Description -match '(?i)Servicing Stack'
    } | Sort-Object InstallTime -Descending)

    $updateServices = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in @('wuauserv','BITS','UsoSvc','WaaSMedicSvc','TrustedInstaller') } |
        Sort-Object Name |
        ForEach-Object {
            [pscustomobject][ordered]@{
                Name        = $_.Name
                DisplayName = $_.DisplayName
                State       = $_.State
                StartMode   = $_.StartMode
                StartName   = $_.StartName
            }
        })

    $wsusPolicy = [pscustomobject][ordered]@{
        WindowsUpdate = Get-RegistryKeySnapshot 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
        AU            = Get-RegistryKeySnapshot 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    }

    [pscustomobject][ordered]@{
        OSBuildRegistry     = $currentVersion
        HotFixes            = $hotfixes
        WindowsUpdateHistory = [pscustomobject]$updateHistory
        WindowsPackages     = $windowsPackages
        DismPackageTable    = $dismPackages
        ServicingPackageCandidates = $servicingPackages
        LCUPackageCandidates = $lcuCandidates
        SSUPackageCandidates = $ssuCandidates
        DetectedKBs         = @($allKb | Sort-Object)
        PendingReboot       = Get-PendingRebootDetailed
        UpdateServices      = $updateServices
        WSUSPolicy          = $wsusPolicy
        Summary = [ordered]@{
            HotFixCount              = $hotfixes.Count
            DetectedKBCount          = $allKb.Count
            WindowsPackageCount      = $windowsPackages.Count
            InstalledWindowsPackages = @($windowsPackages | Where-Object PackageState -eq 'Installed').Count
            LCUCandidateCount        = $lcuCandidates.Count
            SSUCandidateCount        = $ssuCandidates.Count
            LatestLCUCandidate       = if ($lcuCandidates.Count -gt 0) { $lcuCandidates[0] } else { $null }
            LatestSSUCandidate       = if ($ssuCandidates.Count -gt 0) { $ssuCandidates[0] } else { $null }
            RebootPending            = (Get-PendingRebootDetailed).RebootPending
        }
        Interpretation = @(
            'No Windows Update search/download/install is triggered by this collector.',
            'Get-HotFix alone is not treated as authoritative; CBS/DISM package information and update history are collected as additional evidence.',
            'LCU/SSU candidates are heuristic classifications from package metadata and should be compared using package identity/KB/version rules.'
        )
    }
}

# -----------------------------------------------------------------------------
# Cross-section observations (informational only, not role-specific verdicts)
# -----------------------------------------------------------------------------
$attentionSummary = Invoke-SafeCollection -Name 'AttentionSummary' -ScriptBlock {
    $firewallRules = if ($firewall -and $firewall.Rules) { @($firewall.Rules) } else { @() }
    $shares = if ($smb -and $smb.Shares) { @($smb.Shares) } else { @() }
    $tasks = if ($scheduledTasks -and $scheduledTasks.Tasks) { @($scheduledTasks.Tasks) } else { @() }

    [pscustomobject][ordered]@{
        Firewall = [ordered]@{
            DisabledProfiles = if ($firewall) { @($firewall.Profiles | Where-Object Enabled -ne $true | Select-Object -ExpandProperty Name) } else { @() }
            EnabledInboundAllowRules = @($firewallRules | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' }).Count
            VncRelatedRules = @($firewallRules | Where-Object {
                (($_.DisplayName + ' ' + $_.DisplayGroup + ' ' + $_.Description) -match '(?i)VNC') -or
                (@($_.PortFilters.LocalPort) -contains '5800') -or
                (@($_.PortFilters.LocalPort) -contains '5900')
            } | Select-Object Name, DisplayName, Enabled, Direction, Action, Profile, PolicyStoreSource, PolicyStoreSourceType, PortFilters, ApplicationFilters)
        }
        SMB = [ordered]@{
            SharesWithMissingPath = @($shares | Where-Object { $_.Path -and -not (Test-Path -LiteralPath $_.Path) } | Select-Object Name, Path).Count
            NonSpecialShares      = @($shares | Where-Object { -not $_.Special } | Select-Object Name, Path, EncryptData)
            SMB1ServerEnabled     = if ($smb) { $smb.Summary.SMB1ServerEnabled } else { $null }
            SMB2ServerEnabled     = if ($smb) { $smb.Summary.SMB2ServerEnabled } else { $null }
        }
        Startup = [ordered]@{
            ScheduledTaskCount = $tasks.Count
            NonMicrosoftTaskCandidates = if ($scheduledTasks) { $scheduledTasks.Summary.NonMicrosoftCandidates } else { $null }
            RegistryAutorunCount = if ($autoruns) { $autoruns.Summary.RegistryAutorunCount } else { $null }
            WmiPermanentBindingCount = if ($wmiPermanentSubscriptions) { $wmiPermanentSubscriptions.Summary.Bindings } else { $null }
        }
        Patch = [ordered]@{
            DetectedKBCount = if ($patchStatus) { $patchStatus.Summary.DetectedKBCount } else { $null }
            LatestLCUCandidate = if ($patchStatus) { $patchStatus.Summary.LatestLCUCandidate } else { $null }
            LatestSSUCandidate = if ($patchStatus) { $patchStatus.Summary.LatestSSUCandidate } else { $null }
            RebootPending = if ($patchStatus) { $patchStatus.PendingReboot.RebootPending } else { $null }
        }
        Interpretation = @(
            'This section highlights inventory conditions only and is not an OK/NOK verdict.',
            'Open/listening ports are runtime state and must not be confused with firewall rule configuration.',
            'Administrative SMB shares can be intentional Windows defaults and should be role-aware in the comparator.',
            'Scheduled Microsoft tasks are numerous; later comparison should normally target explicit task names/paths rather than entire task-set equality.',
            'Patch compliance should use a defined approved baseline (KB/package/build/version), not simply newest-available logic.'
        )
    }
}

# -----------------------------------------------------------------------------
# Final JSON document
# -----------------------------------------------------------------------------
$script:Stopwatch.Stop()
$errorSections = @($script:CollectionStatus.GetEnumerator() | Where-Object { $_.Value.Status -ne 'OK' } | ForEach-Object { $_.Key })
$overallStatus = if ($errorSections.Count -eq 0) { 'COMPLETE' } else { 'PARTIAL' }

$result = [ordered]@{
    SchemaVersion = '1.0'
    Metadata = [ordered]@{
        ScriptName             = 'Firewall_SMB_Patch_Valid.ps1'
        ValidationType         = 'Firewall_SMB_Patch_Valid'
        OverallStatus          = $overallStatus
        TargetIPAddress        = $targetIp
        ComputerName           = $computerName
        DNSName                = $fqdn
        TimestampLocal         = $script:StartTime.ToString('o')
        TimestampUtc           = $script:StartTime.ToUniversalTime().ToString('o')
        CompletedTimestampUtc  = (Get-Date).ToUniversalTime().ToString('o')
        DurationMs             = [int64]$script:Stopwatch.ElapsedMilliseconds
        PowerShellVersion      = $PSVersionTable.PSVersion.ToString()
        PowerShellEdition      = if ($PSVersionTable.PSObject.Properties.Name -contains 'PSEdition') { $PSVersionTable.PSEdition } else { 'Desktop' }
        ProcessArchitecture    = if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' }
        OSArchitecture         = if ([Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' }
        RemoteUser             = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        ResultFileName         = $resultFileName
        ReadOnlyCollection     = $true
        UpdateSearchTriggered  = $false
        UpdateInstallTriggered = $false
        RecursiveAclScan       = $false
        SensitiveCommandArgumentsRedacted = $true
        ErrorSections          = $errorSections
    }
    Identity                  = $identity
    Firewall                  = $firewall
    ListeningEndpoints        = $listeningEndpoints
    SMB                       = $smb
    ScheduledTasks            = $scheduledTasks
    Autoruns                  = $autoruns
    WmiPermanentSubscriptions = $wmiPermanentSubscriptions
    PatchStatus               = $patchStatus
    AttentionSummary          = $attentionSummary
    CollectionStatus          = $script:CollectionStatus
}

try {
    $json = $result | ConvertTo-Json -Depth 40
    [System.IO.File]::WriteAllText($resultFilePath, $json, (New-Object System.Text.UTF8Encoding($false)))
}
catch {
    Write-Error ("JSON result could not be written to '{0}': {1}" -f $resultFilePath, $_.Exception.Message)
    exit 1
}

Write-Output $resultFilePath
exit 0