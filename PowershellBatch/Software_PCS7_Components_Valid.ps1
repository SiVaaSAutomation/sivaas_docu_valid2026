#requires -Version 5.1
<#
.SYNOPSIS
    Read-only detailed inventory of installed software and SIMATIC PCS 7 components.

.DESCRIPTION
    Collects installation-relevant software, SIMATIC/PCS 7 component, add-on, runtime,
    SQL and setup evidence and writes one JSON result file.

    Environment variables supplied by the fixed Ansible validation playbook:
      VALIDATION_RESULT_DIR  - directory in which the JSON file is written
      VALIDATION_TARGET_IP   - target IP used in file name and metadata

    File name:
      <IP>_<ComputerName>_Software_PCS7_Components_Valid_<yyyyMMdd_HHmmss>.json

    Design goals:
      - strictly read-only collection; no installation, repair, registration or configuration
      - PowerShell 5.1 compatible
      - no Win32_Product query (avoids MSI consistency checks / self-repair side effects)
      - no license keys, passwords, PSKs, private keys or other secrets are collected
      - individual collector failures do not abort the complete snapshot
      - generic enough for ES, OS Server, OS Client and other Windows systems
      - detailed enough for later role-specific OK/NOK validation
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

function Convert-ToIso8601 {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    try { return ([datetime]$Value).ToString('o') } catch { return [string]$Value }
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

function Test-SensitiveName {
    param([AllowNull()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    return ($Name -match '(?i)(password|passwd|pwd|secret|token|api.?key|auth.?key|private.?key|psk|license.?key|licen[cs]e.?key|serial.?key|product.?key|cpassword|credential|(^|[_ .-])key($|[_ .-])|pin)')
}

function Protect-SensitiveValue {
    param(
        [AllowNull()]$Value,
        [AllowNull()][string]$Name
    )

    if (Test-SensitiveName -Name $Name) {
        $length = $null
        try { if ($null -ne $Value) { $length = ([string]$Value).Length } } catch { }
        return [pscustomobject][ordered]@{
            Redacted = $true
            Reason   = 'Sensitive value name'
            Length   = $length
            Value    = '<redacted>'
        }
    }

    if ($null -eq $Value) { return $null }

    try {
        $sensitiveText = [string]$Value
        if ($sensitiveText -match '(?i)(password|passwd|pwd|secret|token|psk|api.?key|license.?key|product.?key)\s*[:=]') {
            return [pscustomobject][ordered]@{
                Redacted = $true
                Reason   = 'Sensitive-looking value content'
                Length   = $sensitiveText.Length
                Value    = '<redacted>'
            }
        }
    } catch { }

    if ($Value -is [byte[]]) {
        return [pscustomobject][ordered]@{
            Type   = 'ByteArray'
            Length = $Value.Length
            Value  = '<binary not exported>'
        }
    }

    if ($Value -is [array]) {
        return @($Value | ForEach-Object { [string]$_ })
    }

    $text = [string]$Value
    if ($text.Length -gt 4096) {
        return [pscustomobject][ordered]@{
            Truncated      = $true
            OriginalLength = $text.Length
            Value          = $text.Substring(0, 4096)
        }
    }

    return $Value
}

function Get-RegistryKeyValuesSafe {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject][ordered]@{
            Exists = $false
            Path   = $Path
            Values = $null
        }
    }

    $item = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
    $values = [ordered]@{}
    foreach ($property in $item.PSObject.Properties) {
        if ($property.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') {
            $values[$property.Name] = Protect-SensitiveValue -Value $property.Value -Name $property.Name
        }
    }

    return [pscustomobject][ordered]@{
        Exists = $true
        Path   = $Path
        Values = [pscustomobject]$values
    }
}

function Get-FileVersionSignatureSnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)

    $expanded = [Environment]::ExpandEnvironmentVariables($Path.Trim('"'))
    if (-not (Test-Path -LiteralPath $expanded -PathType Leaf)) {
        return [pscustomobject][ordered]@{
            Path   = $expanded
            Exists = $false
        }
    }

    $file = Get-Item -LiteralPath $expanded -ErrorAction Stop
    $vi = $file.VersionInfo
    $signature = $null
    try { $signature = Get-AuthenticodeSignature -LiteralPath $expanded -ErrorAction Stop } catch { }

    [pscustomobject][ordered]@{
        Path             = $file.FullName
        Exists           = $true
        LengthBytes      = $file.Length
        CreationTimeUtc  = $file.CreationTimeUtc.ToString('o')
        LastWriteTimeUtc = $file.LastWriteTimeUtc.ToString('o')
        FileVersion      = $vi.FileVersion
        ProductVersion   = $vi.ProductVersion
        CompanyName      = $vi.CompanyName
        ProductName      = $vi.ProductName
        FileDescription  = $vi.FileDescription
        OriginalFilename = $vi.OriginalFilename
        SignatureStatus  = if ($signature) { [string]$signature.Status } else { $null }
        SignerSubject     = if ($signature -and $signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
        SignerIssuer      = if ($signature -and $signature.SignerCertificate) { $signature.SignerCertificate.Issuer } else { $null }
        SignerThumbprint  = if ($signature -and $signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { $null }
    }
}

# -----------------------------------------------------------------------------
# Target / result file
# -----------------------------------------------------------------------------
$computerName = $env:COMPUTERNAME
if ([string]::IsNullOrWhiteSpace($computerName)) {
    try { $computerName = [System.Net.Dns]::GetHostName() } catch { $computerName = 'unknown' }
}

$fqdn = $null
try { $fqdn = [System.Net.Dns]::GetHostEntry($computerName).HostName } catch { }

$targetIp = $env:VALIDATION_TARGET_IP
if ([string]::IsNullOrWhiteSpace($targetIp)) { $targetIp = Get-PrimaryIPv4Address }
if ([string]::IsNullOrWhiteSpace($targetIp)) { $targetIp = 'unknown-ip' }

$resultDir = $env:VALIDATION_RESULT_DIR
if ([string]::IsNullOrWhiteSpace($resultDir)) { $resultDir = (Get-Location).Path }
if (-not (Test-Path -LiteralPath $resultDir -PathType Container)) {
    throw "VALIDATION_RESULT_DIR does not exist: $resultDir"
}

$timestamp = $script:StartTime.ToString('yyyyMMdd_HHmmss')
$resultFileName = ('{0}_{1}_Software_PCS7_Components_Valid_{2}.json' -f (Convert-ToSafeFileNamePart $targetIp), (Convert-ToSafeFileNamePart $computerName), $timestamp)
$resultFilePath = Join-Path $resultDir $resultFileName

# -----------------------------------------------------------------------------
# Identity / OS context
# -----------------------------------------------------------------------------
$identity = Invoke-SafeCollection -Name 'Identity' -ScriptBlock {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop

    [pscustomobject][ordered]@{
        ComputerName      = $computerName
        DNSName           = $fqdn
        TargetIPAddress   = $targetIp
        Domain            = $cs.Domain
        PartOfDomain      = $cs.PartOfDomain
        Manufacturer      = $cs.Manufacturer
        Model             = $cs.Model
        OSCaption         = $os.Caption
        OSVersion         = $os.Version
        OSBuildNumber     = $os.BuildNumber
        OSArchitecture    = $os.OSArchitecture
        CurrentUser       = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
}

# -----------------------------------------------------------------------------
# Installed software - registry only, never Win32_Product
# -----------------------------------------------------------------------------
function Get-InstalledSoftwareRegistry {
    $roots = @(
        [pscustomobject]@{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; Architecture='64-bit'; Scope='LocalMachine'; Source='HKLM64' },
        [pscustomobject]@{ Path='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; Architecture='32-bit'; Scope='LocalMachine'; Source='HKLM32' },
        [pscustomobject]@{ Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; Architecture='CurrentUser'; Scope='CurrentUser'; Source='HKCU' }
    )

    $items = New-Object System.Collections.Generic.List[object]
    foreach ($root in $roots) {
        $entries = @(Get-ItemProperty -Path $root.Path -ErrorAction SilentlyContinue)
        foreach ($entry in $entries) {
            if ([string]::IsNullOrWhiteSpace([string]$entry.DisplayName)) { continue }

            $keyName = $null
            try { $keyName = Split-Path -Leaf $entry.PSPath } catch { }
            $productCode = $null
            if ($keyName -match '^\{[0-9A-Fa-f-]{36}\}$') { $productCode = $keyName }

            $items.Add([pscustomobject][ordered]@{
                DisplayName          = [string]$entry.DisplayName
                DisplayVersion       = [string]$entry.DisplayVersion
                Publisher            = [string]$entry.Publisher
                InstallDate          = [string]$entry.InstallDate
                InstallLocation      = [Environment]::ExpandEnvironmentVariables([string]$entry.InstallLocation)
                InstallSource        = [Environment]::ExpandEnvironmentVariables([string]$entry.InstallSource)
                UninstallString      = Protect-SensitiveValue -Value $entry.UninstallString -Name 'UninstallString'
                QuietUninstallString = Protect-SensitiveValue -Value $entry.QuietUninstallString -Name 'QuietUninstallString'
                ModifyPath           = Protect-SensitiveValue -Value $entry.ModifyPath -Name 'ModifyPath'
                EstimatedSizeKB      = $entry.EstimatedSize
                Language             = $entry.Language
                VersionMajor         = $entry.VersionMajor
                VersionMinor         = $entry.VersionMinor
                WindowsInstaller     = $entry.WindowsInstaller
                SystemComponent      = $entry.SystemComponent
                ReleaseType          = [string]$entry.ReleaseType
                ParentDisplayName    = [string]$entry.ParentDisplayName
                ProductCode          = $productCode
                RegistryKeyName      = $keyName
                Architecture         = $root.Architecture
                Scope                = $root.Scope
                RegistrySource       = $root.Source
            })
        }
    }

    return @($items | Sort-Object DisplayName, DisplayVersion, Architecture, RegistrySource)
}

$installedSoftware = Invoke-SafeCollection -Name 'InstalledSoftware' -ScriptBlock {
    $all = @(Get-InstalledSoftwareRegistry)
    $siemens = @($all | Where-Object {
        $_.Publisher -match '(?i)Siemens|SIMATIC' -or
        $_.DisplayName -match '(?i)SIMATIC|PCS\s*7|WinCC|STEP\s*7|S7\s*F\s*Systems|SENTRON|SIMOCODE|SITOP|Safety\s*Matrix|PowerControl|Drive\s*ES|PTE400|VersionTrail'
    })

    $runtime = @($all | Where-Object {
        $_.DisplayName -match '(?i)(Microsoft Visual C\+\+.*Redistributable|\.NET|ODBC Driver|SQL Server Native Client|Access Database Engine|WebView2 Runtime|Java|OpenJDK|VC\+\+)'
    })

    [pscustomobject][ordered]@{
        Summary = [ordered]@{
            TotalProducts              = $all.Count
            LocalMachine64             = @($all | Where-Object { $_.RegistrySource -eq 'HKLM64' }).Count
            LocalMachine32             = @($all | Where-Object { $_.RegistrySource -eq 'HKLM32' }).Count
            CurrentUser                = @($all | Where-Object { $_.RegistrySource -eq 'HKCU' }).Count
            SiemensOrPCS7Related       = $siemens.Count
            RuntimeDependencyCandidates = $runtime.Count
        }
        AllProducts          = $all
        SiemensAndPCS7       = $siemens
        RuntimeDependencies  = $runtime
    }
}

# -----------------------------------------------------------------------------
# PCS 7 / Siemens component catalog - detection only, no role-specific verdict
# -----------------------------------------------------------------------------
function Get-ComponentCatalog {
    return @(
        [pscustomobject]@{ Id='PCS7_V10'; Name='SIMATIC PCS 7 V10 / PCS 7 Engineering'; Pattern='(?i)(SIMATIC\s*PCS\s*7|PCS\s*7\s*Engineering|PCS7\s*Engineering).*?(V?10(\.0)?)?' },
        [pscustomobject]@{ Id='SIMATIC_LOGON'; Name='SIMATIC Logon'; Pattern='(?i)SIMATIC\s*Logon' },
        [pscustomobject]@{ Id='SYSTEM_HARDENING'; Name='SIMATIC System Hardening component/evidence'; Pattern='(?i)System\s*Hardening' },
        [pscustomobject]@{ Id='VERSIONTRAIL'; Name='VersionTrail'; Pattern='(?i)Version\s*Trail|VersionTrail' },
        [pscustomobject]@{ Id='WINCC'; Name='SIMATIC WinCC'; Pattern='(?i)WinCC' },
        [pscustomobject]@{ Id='STEP7'; Name='SIMATIC STEP 7'; Pattern='(?i)(STEP\s*7|STEP7)' },
        [pscustomobject]@{ Id='CFC'; Name='SIMATIC CFC'; Pattern='(?i)(^|\s|SIMATIC\s)CFC(\s|$)' },
        [pscustomobject]@{ Id='SFC'; Name='SIMATIC SFC'; Pattern='(?i)(^|\s|SIMATIC\s)SFC(\s|$)' },
        [pscustomobject]@{ Id='SIMATIC_NET'; Name='SIMATIC NET'; Pattern='(?i)SIMATIC\s*NET' },
        [pscustomobject]@{ Id='ALM'; Name='Automation License Manager'; Pattern='(?i)(Automation\s*License\s*Manager|ALM)' },
        [pscustomobject]@{ Id='PCS7_LIB_V71_SP3_UPD4'; Name='SIMATIC PCS 7 Library V7.1 SP3 Update 4'; Pattern='(?i)(PCS\s*7|PCS7).*Lib(rary)?.*V?7[\._ ]?1.*SP3.*(Upd|Update)?\s*4' },
        [pscustomobject]@{ Id='PTE400_V10'; Name='PTE400 V10.0'; Pattern='(?i)PTE\s*400.*V?10([\._ ]?0)?' },
        [pscustomobject]@{ Id='SENTRON_3WL_3VL_V10'; Name='PCS 7 Library SENTRON 3WL/3VL V10.0'; Pattern='(?i)SENTRON.*(3WL.*3VL|3WLVL).*V?10' },
        [pscustomobject]@{ Id='SENTRON_PAC_V10'; Name='PCS 7 Library SENTRON PAC V10.0'; Pattern='(?i)SENTRON.*PAC.*V?10' },
        [pscustomobject]@{ Id='SIMOCODE_PRO_V10'; Name='PCS 7 Library SIMOCODE pro V10.0'; Pattern='(?i)SIMOCODE\s*pro.*V?10' },
        [pscustomobject]@{ Id='SIMOCODE_MIGRATION_LEGACY_V10'; Name='SIMOCODE pro PCS 7 Library Migration Legacy V10.0'; Pattern='(?i)SIMOCODE.*Migration.*Legacy.*V?10' },
        [pscustomobject]@{ Id='S7_F_SYSTEMS_64_SP1'; Name='S7 F Systems V6.4 SP1'; Pattern='(?i)S7[\s-]*F[\s-]*Systems.*V?6[\._ ]?4.*SP1' },
        [pscustomobject]@{ Id='INDUSTRY_LIBRARY_V10'; Name='SIMATIC PCS 7 Industry Library V10.0'; Pattern='(?i)(PCS\s*7|SIMATIC).*Industry\s*Library.*V?10' },
        [pscustomobject]@{ Id='POWERCONTROL_V91'; Name='PowerControl V9.1'; Pattern='(?i)PowerControl.*V?9[\._ ]?1' },
        [pscustomobject]@{ Id='POWERCONTROL_V91_UPD1'; Name='PowerControl V9.1 Update 1'; Pattern='(?i)PowerControl.*V?9[\._ ]?1.*(Upd|Update)\s*1' },
        [pscustomobject]@{ Id='DRIVE_ES_PCS7_APL_V10'; Name='Drive ES PCS 7 APL V10.0'; Pattern='(?i)Drive\s*ES.*PCS\s*7.*APL.*V?10' },
        [pscustomobject]@{ Id='SITOP_PCS7_APL_V40'; Name='SITOP PCS 7 APL V4.0'; Pattern='(?i)SITOP.*PCS\s*7.*APL.*V?4[\._ ]?0' },
        [pscustomobject]@{ Id='SAFETY_MATRIX_63_SP1'; Name='SIMATIC Safety Matrix V6.3 SP1'; Pattern='(?i)Safety\s*Matrix.*V?6[\._ ]?3.*SP1' }
    )
}

function Get-CatalogDetection {
    param(
        [Parameter(Mandatory = $true)][array]$Products,
        [AllowNull()][array]$AdditionalTextEvidence
    )

    $catalog = @(Get-ComponentCatalog)
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($entry in $catalog) {
        $matches = @($Products | Where-Object {
            (($_.DisplayName + ' ' + $_.DisplayVersion + ' ' + $_.Publisher) -match $entry.Pattern)
        })

        $textMatches = @()
        if ($AdditionalTextEvidence) {
            $textMatches = @($AdditionalTextEvidence | Where-Object { [string]$_ -match $entry.Pattern } | Select-Object -First 50)
        }

        $results.Add([pscustomobject][ordered]@{
            ComponentId      = $entry.Id
            ComponentName    = $entry.Name
            DetectionPattern = $entry.Pattern
            Detected         = (($matches.Count + $textMatches.Count) -gt 0)
            ProductMatchCount = $matches.Count
            ProductMatches    = @($matches | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, Architecture, ProductCode)
            AdditionalEvidenceCount = $textMatches.Count
            AdditionalEvidence = @($textMatches)
            Interpretation   = 'Detection evidence only; not a role-specific required/not-required or OK/NOK verdict.'
        })
    }

    return @($results)
}

# -----------------------------------------------------------------------------
# Runtime and prerequisite inventory
# -----------------------------------------------------------------------------
$dotNet = Invoke-SafeCollection -Name 'DotNetAndRuntimePrerequisites' -ScriptBlock {
    $netFx3 = $null
    if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
        try {
            $feature = Get-WindowsOptionalFeature -Online -FeatureName NetFx3 -ErrorAction Stop
            $netFx3 = [pscustomobject][ordered]@{
                FeatureName = $feature.FeatureName
                State       = [string]$feature.State
                RestartRequired = [string]$feature.RestartRequired
            }
        }
        catch { }
    }

    $serverFeature = $null
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        try {
            $sf = Get-WindowsFeature -Name NET-Framework-Core -ErrorAction Stop
            $serverFeature = [pscustomobject][ordered]@{
                Name        = $sf.Name
                DisplayName = $sf.DisplayName
                InstallState = [string]$sf.InstallState
                Installed   = $sf.Installed
            }
        }
        catch { }
    }

    $netFx35Registry = Get-RegistryKeyValuesSafe -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5'
    $netFx4Full = Get-RegistryKeyValuesSafe -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'

    $servicingPolicy = [pscustomobject][ordered]@{
        Standard = Get-RegistryKeyValuesSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing'
        Wow6432  = Get-RegistryKeyValuesSafe -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Servicing'
    }

    $dotnetCli = $null
    $dotnetCmd = Get-Command dotnet.exe -ErrorAction SilentlyContinue
    if ($dotnetCmd) {
        $dotnetCli = [pscustomobject][ordered]@{
            Path         = $dotnetCmd.Source
            Info         = Invoke-NativeReadOnly -FilePath $dotnetCmd.Source -Arguments @('--info')
            Runtimes     = Invoke-NativeReadOnly -FilePath $dotnetCmd.Source -Arguments @('--list-runtimes')
            SDKs         = Invoke-NativeReadOnly -FilePath $dotnetCmd.Source -Arguments @('--list-sdks')
        }
    }

    $allProducts = if ($installedSoftware) { @($installedSoftware.AllProducts) } else { @() }
    $vcRedists = @($allProducts | Where-Object { $_.DisplayName -match '(?i)Microsoft Visual C\+\+.*Redistributable' })
    $vc2010x86 = @($vcRedists | Where-Object {
        $_.DisplayName -match '(?i)2010' -and ($_.Architecture -eq '32-bit' -or $_.DisplayName -match '(?i)x86')
    })

    [pscustomobject][ordered]@{
        NetFx3OptionalFeature = $netFx3
        NetFx3ServerFeature   = $serverFeature
        NetFx35Registry       = $netFx35Registry
        NetFx4FullRegistry    = $netFx4Full
        FeatureSourcePolicy   = $servicingPolicy
        DotNetCLI             = $dotnetCli
        VisualCppRedistributables = $vcRedists
        VisualCpp2010x86Candidates = $vc2010x86
        Observations = [ordered]@{
            NetFx3DetectedEnabled = if ($netFx3) { ([string]$netFx3.State -match 'Enabled') } elseif ($serverFeature) { [bool]$serverFeature.Installed } else { $null }
            VisualCpp2010x86Detected = ($vc2010x86.Count -gt 0)
        }
    }
}

# -----------------------------------------------------------------------------
# PCS 7 setup prerequisite certificate / root update state
# Compact cross-reference only; full certificate detail belongs to script 3.
# -----------------------------------------------------------------------------
$pcs7CertificatePrerequisites = Invoke-SafeCollection -Name 'PCS7CertificatePrerequisites' -ScriptBlock {
    $rootCerts = @(Get-ChildItem -Path Cert:\LocalMachine\Root -ErrorAction Stop)

    function Convert-CertBrief {
        param($Cert)
        if ($null -eq $Cert) { return $null }
        [pscustomobject][ordered]@{
            Subject         = $Cert.Subject
            Issuer          = $Cert.Issuer
            Thumbprint      = $Cert.Thumbprint
            SerialNumber    = $Cert.SerialNumber
            NotBefore       = Convert-ToIso8601 $Cert.NotBefore
            NotAfter        = Convert-ToIso8601 $Cert.NotAfter
            HasPrivateKey   = $Cert.HasPrivateKey
            SignatureAlgorithm = if ($Cert.SignatureAlgorithm) { $Cert.SignatureAlgorithm.FriendlyName } else { $null }
        }
    }

    $quovadis = @($rootCerts | Where-Object {
        $_.Subject -match '(?i)QuoVadis Root CA 2' -or $_.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -match '(?i)QuoVadis Root CA 2'
    })

    $verisign = @($rootCerts | Where-Object {
        $_.Subject -match '(?i)VeriSign Class 3 Public Primary Certification Authority\s*-\s*G5' -or $_.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -match '(?i)VeriSign Class 3 Public Primary Certification Authority\s*-\s*G5'
    })

    $policyPaths = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot',
        'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\SystemCertificates\AuthRoot',
        'HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\SystemCertificates\AuthRoot'
    )

    [pscustomobject][ordered]@{
        TrustedRootStore = 'LocalMachine\\Root'
        QuoVadisRootCA2 = [pscustomobject][ordered]@{
            Detected = ($quovadis.Count -gt 0)
            Count    = $quovadis.Count
            Certificates = @($quovadis | ForEach-Object { Convert-CertBrief $_ })
        }
        VeriSignClass3PublicPrimaryCertificationAuthorityG5 = [pscustomobject][ordered]@{
            Detected = ($verisign.Count -gt 0)
            Count    = $verisign.Count
            Certificates = @($verisign | ForEach-Object { Convert-CertBrief $_ })
        }
        RootAutoUpdateRegistry = @($policyPaths | ForEach-Object { Get-RegistryKeyValuesSafe -Path $_ })
        Interpretation = 'Compact PCS 7 setup prerequisite evidence only. Full certificate inventory is collected by Certificates_Services_Drivers_Valid.ps1; policy details by GPOs_Valid.ps1.'
    }
}

# -----------------------------------------------------------------------------
# SQL Server software / instance inventory without connecting to databases
# -----------------------------------------------------------------------------
$sqlInventory = Invoke-SafeCollection -Name 'SQLServerComponents' -ScriptBlock {
    $instanceSources = @(
        [pscustomobject]@{ Root='HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server'; View='64-bit' },
        [pscustomobject]@{ Root='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server'; View='32-bit' }
    )

    $instances = New-Object System.Collections.Generic.List[object]
    foreach ($source in $instanceSources) {
        $instanceNameKey = Join-Path $source.Root 'Instance Names\SQL'
        if (-not (Test-Path -LiteralPath $instanceNameKey)) { continue }

        $props = Get-ItemProperty -LiteralPath $instanceNameKey -ErrorAction SilentlyContinue
        if (-not $props) { continue }

        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
            $instanceName = $p.Name
            $instanceId = [string]$p.Value
            $setupPath = Join-Path (Join-Path $source.Root $instanceId) 'Setup'
            $currentVersionPath = Join-Path (Join-Path $source.Root $instanceId) 'MSSQLServer\CurrentVersion'

            $instances.Add([pscustomobject][ordered]@{
                InstanceName    = $instanceName
                InstanceId      = $instanceId
                RegistryView    = $source.View
                Setup           = Get-RegistryKeyValuesSafe -Path $setupPath
                CurrentVersion  = Get-RegistryKeyValuesSafe -Path $currentVersionPath
            })
        }
    }

    $products = if ($installedSoftware) {
        @($installedSoftware.AllProducts | Where-Object { $_.DisplayName -match '(?i)(SQL Server|SQL Native Client|ODBC Driver.*SQL|SQL Server Management|SQL LocalDB)' })
    } else { @() }

    [pscustomobject][ordered]@{
        InstalledSQLProducts = $products
        Instances            = @($instances)
        InstanceCount        = $instances.Count
        InstalledInstancesRegistry = @(
            Get-RegistryKeyValuesSafe -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server',
            Get-RegistryKeyValuesSafe -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server'
        )
        Interpretation = 'Software/instance registry inventory only; no SQL login and no database query is performed.'
    }
}

# -----------------------------------------------------------------------------
# Siemens / PCS 7 registry evidence, redacted and keyword-filtered
# -----------------------------------------------------------------------------
function Get-KeywordRegistryEvidence {
    param(
        [Parameter(Mandatory = $true)][string[]]$Roots,
        [Parameter(Mandatory = $true)][string]$KeywordRegex,
        [int]$MaxKeys = 6000,
        [int]$MaxEvidence = 1200
    )

    $evidence = New-Object System.Collections.Generic.List[object]
    $visited = 0

    foreach ($root in $Roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }

        $keys = @()
        try {
            $keys += Get-Item -LiteralPath $root -ErrorAction Stop
            $keys += @(Get-ChildItem -LiteralPath $root -Recurse -ErrorAction SilentlyContinue)
        }
        catch { continue }

        foreach ($key in $keys) {
            $visited++
            if ($visited -gt $MaxKeys -or $evidence.Count -ge $MaxEvidence) { break }

            $path = $key.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
            $includeKey = ($path -match $KeywordRegex)

            $props = $null
            try { $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop } catch { }
            if (-not $props) {
                if ($includeKey) {
                    $evidence.Add([pscustomobject][ordered]@{ Path=$path; ValueName=$null; Value=$null })
                }
                continue
            }

            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
                $valueText = ''
                try { $valueText = [string]$prop.Value } catch { }
                if ($includeKey -or $prop.Name -match $KeywordRegex -or $valueText -match $KeywordRegex) {
                    $protectedValue = $null
                    if ($path -match '(?i)(psk|password|secret|credential|license.?key|licen[cs]e.?data|product.?key|serial.?key|private.?key|keyring|keystore)') {
                        $protectedValue = [pscustomobject][ordered]@{
                            Redacted = $true
                            Reason   = 'Sensitive registry path'
                            Length   = $valueText.Length
                            Value    = '<redacted>'
                        }
                    }
                    else {
                        $protectedValue = Protect-SensitiveValue -Value $prop.Value -Name $prop.Name
                    }
                    $evidence.Add([pscustomobject][ordered]@{
                        Path      = $path
                        ValueName = $prop.Name
                        Value     = $protectedValue
                    })
                    if ($evidence.Count -ge $MaxEvidence) { break }
                }
            }
        }

        if ($visited -gt $MaxKeys -or $evidence.Count -ge $MaxEvidence) { break }
    }

    [pscustomobject][ordered]@{
        Roots          = $Roots
        KeywordRegex   = $KeywordRegex
        KeysVisited    = $visited
        EvidenceCount  = $evidence.Count
        Truncated      = ($visited -gt $MaxKeys -or $evidence.Count -ge $MaxEvidence)
        Evidence       = @($evidence)
    }
}

$siemensRegistryEvidence = Invoke-SafeCollection -Name 'SiemensRegistryEvidence' -ScriptBlock {
    $roots = @(
        'HKLM:\SOFTWARE\Siemens',
        'HKLM:\SOFTWARE\WOW6432Node\Siemens',
        'HKLM:\SOFTWARE\SIMATIC',
        'HKLM:\SOFTWARE\WOW6432Node\SIMATIC'
    )

    Get-KeywordRegistryEvidence -Roots $roots -KeywordRegex '(?i)(PCS\s*7|PCS7|WinCC|STEP\s*7|STEP7|CFC|SFC|SIMATIC|VersionTrail|License\s*Manager|ALM|Shell|Terminalbus|Remote.*Communicat|Remote.*Kommunik|SENTRON|SIMOCODE|SITOP|Safety\s*Matrix|PowerControl|Drive\s*ES|PTE400|Industry\s*Library|F[\s-]*Systems)' -MaxKeys 8000 -MaxEvidence 1600
}

$simaticShellEvidence = Invoke-SafeCollection -Name 'SimaticShellEvidence' -ScriptBlock {
    $roots = @(
        'HKLM:\SOFTWARE\Siemens',
        'HKLM:\SOFTWARE\WOW6432Node\Siemens',
        'HKLM:\SOFTWARE\SIMATIC',
        'HKLM:\SOFTWARE\WOW6432Node\SIMATIC'
    )

    $data = Get-KeywordRegistryEvidence -Roots $roots -KeywordRegex '(?i)(SIMATIC.*Shell|Shell.*SIMATIC|Terminalbus|Terminal.*Bus|Remote.*Communicat|Remote.*Kommunik|Adapter|Interface|PSK)' -MaxKeys 8000 -MaxEvidence 500
    [pscustomobject][ordered]@{
        RegistryEvidence = $data
        SecretHandling = 'PSK/password/key/license-like values are redacted by name and are never intentionally exported.'
        Interpretation = 'Heuristic read-only evidence. Exact SIMATIC Shell storage can vary by installed PCS 7 release/component.'
    }
}

$almEvidence = Invoke-SafeCollection -Name 'AutomationLicenseManagerEvidence' -ScriptBlock {
    $products = if ($installedSoftware) {
        @($installedSoftware.AllProducts | Where-Object { $_.DisplayName -match '(?i)(Automation\s*License\s*Manager|SIMATIC.*License|License\s*Manager)' })
    } else { @() }

    $roots = @(
        'HKLM:\SOFTWARE\Siemens',
        'HKLM:\SOFTWARE\WOW6432Node\Siemens'
    )
    $registry = Get-KeywordRegistryEvidence -Roots $roots -KeywordRegex '(?i)(Automation\s*License|License\s*Manager|ALM|Remote.*License|Remote.*Verbindung|Remote.*Connection)' -MaxKeys 8000 -MaxEvidence 400

    [pscustomobject][ordered]@{
        InstalledProducts = $products
        RegistryEvidence  = $registry
        LicenseMaterialCollected = $false
        Interpretation = 'License files/keys are intentionally not exported. Registry values with secret/license-key-like names are redacted.'
    }
}

# -----------------------------------------------------------------------------
# PCS 7 / Siemens setup logs and installation evidence
# -----------------------------------------------------------------------------
function Get-SetupLogEvidence {
    param([string[]]$CandidateDirectories)

    $existingDirs = @($CandidateDirectories | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) } | Select-Object -Unique)
    $files = New-Object System.Collections.Generic.List[object]
    $highlights = New-Object System.Collections.Generic.List[string]

    foreach ($dir in $existingDirs) {
        $candidateFiles = @(Get-ChildItem -LiteralPath $dir -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -match '^\.(log|txt|xml|ini|csv)$' } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 60)

        foreach ($file in $candidateFiles) {
            $files.Add([pscustomobject][ordered]@{
                FullName         = $file.FullName
                LengthBytes      = $file.Length
                CreationTimeUtc  = $file.CreationTimeUtc.ToString('o')
                LastWriteTimeUtc = $file.LastWriteTimeUtc.ToString('o')
                Extension        = $file.Extension
            })

            if ($file.Length -gt 10MB) { continue }
            try {
                $matches = @(Select-String -LiteralPath $file.FullName -Pattern '(?i)(PCS\s*7|PCS7|SIMATIC|WinCC|STEP\s*7|CFC|SFC|VersionTrail|SENTRON|SIMOCODE|SITOP|Safety\s*Matrix|PowerControl|Drive\s*ES|PTE400|Industry\s*Library|S7[\s-]*F[\s-]*Systems|System\s*Hardening|error|failed|failure|warning|version|package|component)' -ErrorAction SilentlyContinue |
                    Select-Object -First 80)

                foreach ($m in $matches) {
                    if ($highlights.Count -ge 1200) { break }
                    $line = ('{0}:{1}: {2}' -f $file.Name, $m.LineNumber, $m.Line.Trim())
                    if ($line -match '(?i)(password|secret|token|psk|license.?key|product.?key|serial.?key)') {
                        $line = ('{0}:{1}: <redacted sensitive-looking setup log line>' -f $file.Name, $m.LineNumber)
                    }
                    if ($line.Length -gt 1200) { $line = $line.Substring(0, 1200) }
                    $highlights.Add($line)
                }
            }
            catch { }
        }
    }

    [pscustomobject][ordered]@{
        CandidateDirectories = $CandidateDirectories
        ExistingDirectories  = $existingDirs
        LogFileCount         = $files.Count
        Files                = @($files)
        HighlightCount       = $highlights.Count
        Highlights           = @($highlights)
        Truncated            = ($files.Count -ge 60 -or $highlights.Count -ge 1200)
    }
}

$setupLogEvidence = Invoke-SafeCollection -Name 'PCS7SetupLogEvidence' -ScriptBlock {
    $candidates = @(
        'C:\ProgramData\Siemens\Automation\Logfiles\Setup\RS',
        'C:\ProgramData\Siemens\Automation\Logfiles\Setup',
        'C:\ProgramData\Siemens\Automation\Logfiles',
        'C:\ProgramData\Siemens\Logs',
        'C:\ProgramData\SIMATIC\Logs'
    )

    Get-SetupLogEvidence -CandidateDirectories $candidates
}

# -----------------------------------------------------------------------------
# Installation directory inventory and representative binaries
# -----------------------------------------------------------------------------
$installationDirectories = Invoke-SafeCollection -Name 'InstallationDirectories' -ScriptBlock {
    $roots = @(
        'C:\Program Files\Siemens',
        'C:\Program Files (x86)\Siemens',
        'C:\Program Files\SIMATIC',
        'C:\Program Files (x86)\SIMATIC',
        'C:\ProgramData\Siemens',
        'C:\ProgramData\SIMATIC'
    )

    $snapshots = New-Object System.Collections.Generic.List[object]
    foreach ($root in $roots) {
        $exists = Test-Path -LiteralPath $root -PathType Container
        $children = @()
        if ($exists) {
            $children = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
                Sort-Object Name |
                ForEach-Object {
                    [pscustomobject][ordered]@{
                        Name             = $_.Name
                        FullName         = $_.FullName
                        CreationTimeUtc  = $_.CreationTimeUtc.ToString('o')
                        LastWriteTimeUtc = $_.LastWriteTimeUtc.ToString('o')
                    }
                })
        }
        $snapshots.Add([pscustomobject][ordered]@{
            Path      = $root
            Exists    = $exists
            ChildCount = $children.Count
            Children  = $children
        })
    }

    return @($snapshots)
}

function Get-RepresentativeProductBinaries {
    param(
        [Parameter(Mandatory = $true)][array]$Products,
        [int]$MaxLocations = 30,
        [int]$MaxFilesPerLocation = 12
    )

    $locations = @($Products |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_.InstallLocation) } |
        Select-Object -ExpandProperty InstallLocation -Unique |
        Where-Object { Test-Path -LiteralPath $_ -PathType Container } |
        Select-Object -First $MaxLocations)

    $result = New-Object System.Collections.Generic.List[object]
    foreach ($location in $locations) {
        $files = New-Object System.Collections.Generic.List[object]
        try {
            $topFiles = @(Get-ChildItem -LiteralPath $location -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -match '^\.(exe|dll)$' } |
                Sort-Object Name |
                Select-Object -First $MaxFilesPerLocation)

            foreach ($f in $topFiles) {
                $files.Add((Get-FileVersionSignatureSnapshot -Path $f.FullName))
            }

            if ($files.Count -lt $MaxFilesPerLocation) {
                $remaining = $MaxFilesPerLocation - $files.Count
                $childDirs = @(Get-ChildItem -LiteralPath $location -Directory -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -First 12)
                foreach ($dir in $childDirs) {
                    if ($remaining -le 0) { break }
                    $childFiles = @(Get-ChildItem -LiteralPath $dir.FullName -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.Extension -match '^\.(exe|dll)$' } |
                        Sort-Object Name |
                        Select-Object -First $remaining)
                    foreach ($f in $childFiles) {
                        $files.Add((Get-FileVersionSignatureSnapshot -Path $f.FullName))
                        $remaining--
                        if ($remaining -le 0) { break }
                    }
                }
            }
        }
        catch { }

        $result.Add([pscustomobject][ordered]@{
            InstallLocation = $location
            FileCount       = $files.Count
            Files           = @($files)
        })
    }

    return @($result)
}

$representativeBinaries = Invoke-SafeCollection -Name 'RepresentativeBinaries' -ScriptBlock {
    $products = if ($installedSoftware) { @($installedSoftware.SiemensAndPCS7) } else { @() }
    Get-RepresentativeProductBinaries -Products $products -MaxLocations 30 -MaxFilesPerLocation 12
}

# -----------------------------------------------------------------------------
# Additional runtime / add-on categories
# -----------------------------------------------------------------------------
$softwareCategories = Invoke-SafeCollection -Name 'SoftwareCategories' -ScriptBlock {
    $all = if ($installedSoftware) { @($installedSoftware.AllProducts) } else { @() }

    function Select-ProductsByPattern {
        param([string]$Pattern)
        return @($all | Where-Object { (($_.DisplayName + ' ' + $_.Publisher) -match $Pattern) })
    }

    [pscustomobject][ordered]@{
        SiemensSIMATIC     = Select-ProductsByPattern '(?i)(Siemens|SIMATIC|PCS\s*7|WinCC|STEP\s*7)'
        PCS7LibrariesAddOns = Select-ProductsByPattern '(?i)(Library|Faceplate|SENTRON|SIMOCODE|SITOP|Safety\s*Matrix|PowerControl|Drive\s*ES|PTE400|Industry\s*Library|F[\s-]*Systems)'
        Licensing          = Select-ProductsByPattern '(?i)(License|Licensing|Automation\s*License\s*Manager)'
        SQLDatabase        = Select-ProductsByPattern '(?i)(SQL Server|SQL Native Client|ODBC Driver.*SQL|Database Engine)'
        DotNet             = Select-ProductsByPattern '(?i)(\.NET|ASP\.NET)'
        VisualCpp          = Select-ProductsByPattern '(?i)(Visual C\+\+|VC\+\+)'
        Java               = Select-ProductsByPattern '(?i)(Java|JRE|JDK|OpenJDK)'
        WebViewBrowserRuntime = Select-ProductsByPattern '(?i)(WebView2|Edge Runtime)'
        RemoteAccessTools  = Select-ProductsByPattern '(?i)(UltraVNC|RealVNC|TightVNC|VNC Server|Remote Desktop)'
        SecuritySoftware   = Select-ProductsByPattern '(?i)(Trellix|McAfee|Defender|Endpoint Security|ePolicy|ePO)'
        BackupImaging      = Select-ProductsByPattern '(?i)(Veeam|Image.*Partition|Backup)'
    }
}

# -----------------------------------------------------------------------------
# Component catalog detection after all additional evidence is available
# -----------------------------------------------------------------------------
$componentDetection = Invoke-SafeCollection -Name 'PCS7ComponentCatalogDetection' -ScriptBlock {
    $products = if ($installedSoftware) { @($installedSoftware.AllProducts) } else { @() }
    $textEvidence = New-Object System.Collections.Generic.List[string]

    if ($setupLogEvidence -and $setupLogEvidence.Highlights) {
        foreach ($x in @($setupLogEvidence.Highlights)) { $textEvidence.Add([string]$x) }
    }

    if ($siemensRegistryEvidence -and $siemensRegistryEvidence.Evidence) {
        foreach ($x in @($siemensRegistryEvidence.Evidence | Select-Object -First 800)) {
            $textEvidence.Add(('{0} {1} {2}' -f $x.Path, $x.ValueName, ([string]$x.Value)))
        }
    }

    Get-CatalogDetection -Products $products -AdditionalTextEvidence @($textEvidence)
}

# -----------------------------------------------------------------------------
# Compact installation observations / best-practice context (no OK/NOK)
# -----------------------------------------------------------------------------
$installationObservations = Invoke-SafeCollection -Name 'InstallationObservations' -ScriptBlock {
    $detectedCatalog = if ($componentDetection) { @($componentDetection | Where-Object { $_.Detected }) } else { @() }
    $allProducts = if ($installedSoftware) { @($installedSoftware.AllProducts) } else { @() }
    $missingInstallLocations = @($allProducts | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_.InstallLocation) -and -not (Test-Path -LiteralPath $_.InstallLocation)
    })

    $unsignedBinaries = @()
    if ($representativeBinaries) {
        $unsignedBinaries = @($representativeBinaries | ForEach-Object { @($_.Files) } |
            Where-Object { $_.Exists -and $_.SignatureStatus -and $_.SignatureStatus -ne 'Valid' })
    }

    [pscustomobject][ordered]@{
        DetectedCatalogComponents = $detectedCatalog.Count
        DetectedComponentIds      = @($detectedCatalog | Select-Object -ExpandProperty ComponentId)
        ProductsWithMissingInstallLocation = $missingInstallLocations.Count
        MissingInstallLocationProducts = @($missingInstallLocations | Select-Object DisplayName, DisplayVersion, InstallLocation, RegistrySource)
        RepresentativeBinariesWithNonValidSignature = $unsignedBinaries.Count
        NonValidRepresentativeBinaries = @($unsignedBinaries | Select-Object Path, FileVersion, ProductVersion, CompanyName, SignatureStatus, SignerSubject)
        NetFx3DetectedEnabled = if ($dotNet) { $dotNet.Observations.NetFx3DetectedEnabled } else { $null }
        VisualCpp2010x86Detected = if ($dotNet) { $dotNet.Observations.VisualCpp2010x86Detected } else { $null }
        QuoVadisRootCA2Detected = if ($pcs7CertificatePrerequisites) { $pcs7CertificatePrerequisites.QuoVadisRootCA2.Detected } else { $null }
        VeriSignG5Detected = if ($pcs7CertificatePrerequisites) { $pcs7CertificatePrerequisites.VeriSignClass3PublicPrimaryCertificationAuthorityG5.Detected } else { $null }
        Interpretation = @(
            'This section contains observations only and is not a role-specific OK/NOK verdict.',
            'A component can be present without an Uninstall entry; registry and setup-log evidence is therefore collected separately.',
            'A missing InstallLocation registry path can be stale installer metadata and requires context.',
            'Non-valid Authenticode status on a representative binary requires review but does not automatically prove a defective installation.',
            'License keys, PSKs, passwords and private keys are intentionally excluded/redacted.'
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
        ScriptName              = 'Software_PCS7_Components_Valid.ps1'
        ValidationType          = 'Software_PCS7_Components_Valid'
        OverallStatus           = $overallStatus
        TargetIPAddress         = $targetIp
        ComputerName            = $computerName
        DNSName                 = $fqdn
        TimestampLocal          = $script:StartTime.ToString('o')
        TimestampUtc            = $script:StartTime.ToUniversalTime().ToString('o')
        CompletedTimestampUtc   = (Get-Date).ToUniversalTime().ToString('o')
        DurationMs              = [int64]$script:Stopwatch.ElapsedMilliseconds
        PowerShellVersion       = $PSVersionTable.PSVersion.ToString()
        PowerShellEdition       = if ($PSVersionTable.PSObject.Properties.Name -contains 'PSEdition') { $PSVersionTable.PSEdition } else { 'Desktop' }
        ProcessArchitecture     = if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' }
        OSArchitecture          = if ([Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' }
        RemoteUser              = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        ResultFileName          = $resultFileName
        ReadOnlyCollection      = $true
        Win32ProductQueried     = $false
        SoftwareModified        = $false
        LicenseMaterialCollected = $false
        SecretsExported         = $false
        ErrorSections           = $errorSections
    }
    Identity                    = $identity
    InstalledSoftware           = $installedSoftware
    PCS7ComponentCatalogDetection = $componentDetection
    SoftwareCategories          = $softwareCategories
    DotNetAndRuntimePrerequisites = $dotNet
    PCS7CertificatePrerequisites = $pcs7CertificatePrerequisites
    SQLServerComponents         = $sqlInventory
    SiemensRegistryEvidence     = $siemensRegistryEvidence
    SimaticShellEvidence        = $simaticShellEvidence
    AutomationLicenseManagerEvidence = $almEvidence
    PCS7SetupLogEvidence        = $setupLogEvidence
    InstallationDirectories     = $installationDirectories
    RepresentativeBinaries      = $representativeBinaries
    InstallationObservations    = $installationObservations
    CollectionStatus            = $script:CollectionStatus
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