#requires -Version 5.1
<#
.SYNOPSIS
    Read-only detailed inventory of certificates, Windows services and drivers.

.DESCRIPTION
    Collects a detailed installation-validation snapshot for certificates, services and
    device/kernel drivers and writes one JSON result file.

    Environment variables supplied by the fixed Ansible validation playbook:
      VALIDATION_RESULT_DIR  - directory in which the JSON file is written
      VALIDATION_TARGET_IP   - target IP used in file name and metadata

    File name:
      <IP>_<ComputerName>_Certificates_Services_Drivers_Valid_<yyyyMMdd_HHmmss>.json

    Design goals:
      - strictly read-only collection; no configuration changes
      - PowerShell 5.1 compatible
      - no driver installation/removal and no certificate export
      - private keys are never exported or read
      - individual collector failures do not abort the complete snapshot
      - detailed enough for later OK/NOK comparison without hard-coding role-specific
        expected values in this inventory script
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

        $fallback = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object {
                $_.IPAddress -ne '127.0.0.1' -and
                $_.IPAddress -notlike '169.254.*' -and
                $_.AddressState -ne 'Duplicate'
            } |
            Select-Object -First 1)
        if ($fallback.Count -gt 0) { return [string]$fallback[0].IPAddress }
    }
    catch { }
    return $null
}

function Get-Fqdn {
    param([string]$ComputerName)
    try { return [System.Net.Dns]::GetHostEntry($ComputerName).HostName } catch { return $null }
}

function Get-FileSha256Safe {
    param([AllowNull()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { return $null }
}

function Get-AuthenticodeSnapshot {
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject][ordered]@{
            FileExists             = $false
            Status                 = $null
            StatusMessage          = $null
            SignerSubject          = $null
            SignerIssuer           = $null
            SignerThumbprint       = $null
            SignerNotBefore        = $null
            SignerNotAfter         = $null
            TimeStamperSubject     = $null
            TimeStamperThumbprint  = $null
        }
    }

    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        [pscustomobject][ordered]@{
            FileExists             = $true
            Status                 = [string]$signature.Status
            StatusMessage          = [string]$signature.StatusMessage
            SignerSubject          = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
            SignerIssuer           = if ($signature.SignerCertificate) { $signature.SignerCertificate.Issuer } else { $null }
            SignerThumbprint       = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { $null }
            SignerNotBefore        = if ($signature.SignerCertificate) { Convert-ToIso8601 $signature.SignerCertificate.NotBefore } else { $null }
            SignerNotAfter         = if ($signature.SignerCertificate) { Convert-ToIso8601 $signature.SignerCertificate.NotAfter } else { $null }
            TimeStamperSubject     = if ($signature.TimeStamperCertificate) { $signature.TimeStamperCertificate.Subject } else { $null }
            TimeStamperThumbprint  = if ($signature.TimeStamperCertificate) { $signature.TimeStamperCertificate.Thumbprint } else { $null }
        }
    }
    catch {
        [pscustomobject][ordered]@{
            FileExists             = $true
            Status                 = 'Error'
            StatusMessage          = $_.Exception.Message
            SignerSubject          = $null
            SignerIssuer           = $null
            SignerThumbprint       = $null
            SignerNotBefore        = $null
            SignerNotAfter         = $null
            TimeStamperSubject     = $null
            TimeStamperThumbprint  = $null
        }
    }
}

function Get-FileMetadataSnapshot {
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject][ordered]@{ Path = $Path; Exists = $false }
    }

    try { $expanded = [Environment]::ExpandEnvironmentVariables($Path) } catch { $expanded = $Path }

    if (-not (Test-Path -LiteralPath $expanded -PathType Leaf)) {
        return [pscustomobject][ordered]@{
            Path   = $expanded
            Exists = $false
        }
    }

    $file = Get-Item -LiteralPath $expanded -ErrorAction Stop
    $version = $file.VersionInfo
    [pscustomobject][ordered]@{
        Path             = $expanded
        Exists           = $true
        LengthBytes      = $file.Length
        CreationTimeUtc  = $file.CreationTimeUtc.ToString('o')
        LastWriteTimeUtc = $file.LastWriteTimeUtc.ToString('o')
        SHA256           = Get-FileSha256Safe -Path $expanded
        FileVersion      = $version.FileVersion
        ProductVersion   = $version.ProductVersion
        CompanyName      = $version.CompanyName
        ProductName      = $version.ProductName
        FileDescription  = $version.FileDescription
        OriginalFilename = $version.OriginalFilename
        Authenticode     = Get-AuthenticodeSnapshot -Path $expanded
    }
}

function Resolve-CommandExecutablePath {
    param([AllowNull()][string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $expanded = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())

    if ($expanded -match '^\s*"([^"]+\.(?:exe|sys|dll))"') {
        return $matches[1]
    }
    if ($expanded -match '^\s*([^\s]+\.(?:exe|sys|dll))(?:\s|$)') {
        return $matches[1]
    }
    return $null
}

function Resolve-DriverBinaryPath {
    param([AllowNull()][string]$PathName)

    if ([string]::IsNullOrWhiteSpace($PathName)) { return $null }

    $path = [Environment]::ExpandEnvironmentVariables($PathName.Trim().Trim('"'))
    if ($path -match '^\\SystemRoot\\(.+)$') {
        return Join-Path $env:SystemRoot $matches[1]
    }
    if ($path -match '^System32\\(.+)$') {
        return Join-Path $env:SystemRoot $path
    }
    if ($path -match '^\\\?\?\\(.+)$') {
        return $matches[1]
    }
    if ($path -match '^[A-Za-z]:\\') { return $path }

    return Resolve-CommandExecutablePath -CommandLine $path
}

function Get-RegistryValueSafe {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch { return $null }
}

function Test-SensitiveRegistryValueName {
    param([AllowNull()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    return [bool]($Name -match '(?i)(password|passwd|pwd|credential|secret|token|privatekey|licensekey|licencekey|activationkey|authkey|apikey|cpassword)')
}

function Get-RegistryKeyValuesSafe {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject][ordered]@{ Exists = $false; Path = $Path; Values = $null }
    }

    try {
        $item = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
        $values = [ordered]@{}
        foreach ($property in $item.PSObject.Properties) {
            if ($property.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') {
                $value = $property.Value
                if (Test-SensitiveRegistryValueName -Name $property.Name) {
                    $values[$property.Name] = [pscustomobject][ordered]@{
                        Redacted = $true
                        Reason   = 'Sensitive registry value name'
                        Value    = '<redacted>'
                    }
                }
                elseif ($value -is [byte[]]) {
                    $values[$property.Name] = [pscustomobject][ordered]@{
                        Type   = 'Binary'
                        Length = $value.Length
                        Base64 = [Convert]::ToBase64String($value)
                    }
                }
                else {
                    $values[$property.Name] = $value
                }
            }
        }
        return [pscustomobject][ordered]@{ Exists = $true; Path = $Path; Values = $values }
    }
    catch {
        return [pscustomobject][ordered]@{ Exists = $true; Path = $Path; Values = $null; Error = $_.Exception.Message }
    }
}

# -----------------------------------------------------------------------------
# Certificate helpers
# -----------------------------------------------------------------------------
function Get-CertificateExpirationStatus {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $now = Get-Date
    $days = [math]::Floor(($Certificate.NotAfter - $now).TotalDays)

    if ($Certificate.NotBefore -gt $now) { return 'NOT_YET_VALID' }
    if ($Certificate.NotAfter -lt $now) { return 'EXPIRED' }
    if ($days -le 7) { return 'EXPIRING_7_DAYS' }
    if ($days -le 30) { return 'EXPIRING_30_DAYS' }
    if ($days -le 90) { return 'EXPIRING_90_DAYS' }
    return 'VALID'
}

function Get-CertificateDnsNames {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $names = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($extension in $Certificate.Extensions) {
            if ($extension.Oid.Value -eq '2.5.29.17') {
                $formatted = $extension.Format($true)
                foreach ($line in @($formatted -split "`r?`n")) {
                    foreach ($part in @($line -split ',')) {
                        $text = $part.Trim()
                        if ($text -match '(?i)(DNS Name|DNS-Name|DNS)\s*=\s*(.+)$') {
                            $value = $matches[2].Trim()
                            if ($value -and -not $names.Contains($value)) { $names.Add($value) }
                        }
                    }
                }
            }
        }
    }
    catch { }
    return @($names)
}

function Get-CertificateExtensionsSnapshot {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $result = @()
    foreach ($extension in $Certificate.Extensions) {
        $formatted = $null
        try { $formatted = $extension.Format($true) } catch { }
        $result += [pscustomobject][ordered]@{
            OidValue     = $extension.Oid.Value
            OidFriendlyName = $extension.Oid.FriendlyName
            Critical     = $extension.Critical
            Formatted    = $formatted
        }
    }
    return $result
}

function Get-CertificatePublicKeySnapshot {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $keySize = $null
    $algorithm = $Certificate.PublicKey.Oid.FriendlyName
    try { $keySize = $Certificate.PublicKey.Key.KeySize } catch { }

    [pscustomobject][ordered]@{
        AlgorithmFriendlyName = $algorithm
        AlgorithmOid          = $Certificate.PublicKey.Oid.Value
        KeySize               = $keySize
    }
}

function Get-CertificateOfflineChainSnapshot {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    # No revocation lookup is performed. This keeps the collector deterministic and avoids
    # intentional CRL/OCSP network traffic. Windows may still use certificates already cached
    # locally while building the chain.
    try {
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        try {
            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
            $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
            $chain.ChainPolicy.VerificationTime = Get-Date
            try { $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromMilliseconds(1) } catch { }

            $valid = $chain.Build($Certificate)
            return [pscustomobject][ordered]@{
                Mode       = 'Local chain build, revocation disabled'
                IsValid    = $valid
                ChainStatus = @($chain.ChainStatus | ForEach-Object {
                    [pscustomobject][ordered]@{
                        Status            = [string]$_.Status
                        StatusInformation = ([string]$_.StatusInformation).Trim()
                    }
                })
                Elements = @($chain.ChainElements | ForEach-Object {
                    [pscustomobject][ordered]@{
                        Subject    = $_.Certificate.Subject
                        Issuer     = $_.Certificate.Issuer
                        Thumbprint = $_.Certificate.Thumbprint
                        NotBefore  = Convert-ToIso8601 $_.Certificate.NotBefore
                        NotAfter   = Convert-ToIso8601 $_.Certificate.NotAfter
                        Status     = @($_.ChainElementStatus | ForEach-Object { [string]$_.Status })
                    }
                })
            }
        }
        finally { $chain.Dispose() }
    }
    catch {
        return [pscustomobject][ordered]@{
            Mode        = 'Local chain build, revocation disabled'
            IsValid     = $null
            ChainStatus = @()
            Elements    = @()
            Error       = $_.Exception.Message
        }
    }
}

function Get-CertificateSnapshot {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$StoreLocation,
        [string]$StoreName
    )

    $now = Get-Date
    $daysUntilExpiration = [math]::Floor(($Certificate.NotAfter - $now).TotalDays)
    $eku = @()
    try {
        $eku = @($Certificate.EnhancedKeyUsageList | ForEach-Object {
            [pscustomobject][ordered]@{ FriendlyName = $_.FriendlyName; Oid = $_.ObjectId.Value }
        })
    }
    catch {
        foreach ($ext in $Certificate.Extensions) {
            if ($ext.Oid.Value -eq '2.5.29.37') {
                try {
                    $ekuExt = New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($ext, $ext.Critical)
                    $eku = @($ekuExt.EnhancedKeyUsages | ForEach-Object {
                        [pscustomobject][ordered]@{ FriendlyName = $_.FriendlyName; Oid = $_.Value }
                    })
                }
                catch { }
            }
        }
    }

    $simpleName = $null
    $dnsName = $null
    try { $simpleName = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) } catch { }
    try { $dnsName = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::DnsName, $false) } catch { }

    [pscustomobject][ordered]@{
        StoreLocation       = $StoreLocation
        StoreName           = $StoreName
        Subject             = $Certificate.Subject
        SimpleName          = $simpleName
        DNSName             = $dnsName
        DNSNamesSAN         = Get-CertificateDnsNames -Certificate $Certificate
        Issuer              = $Certificate.Issuer
        Thumbprint          = $Certificate.Thumbprint
        SerialNumber        = $Certificate.SerialNumber
        Version             = $Certificate.Version
        FriendlyName        = $Certificate.FriendlyName
        NotBefore           = $Certificate.NotBefore.ToString('o')
        NotAfter            = $Certificate.NotAfter.ToString('o')
        DaysUntilExpiration = [int]$daysUntilExpiration
        ExpirationStatus    = Get-CertificateExpirationStatus -Certificate $Certificate
        IsExpired           = ($Certificate.NotAfter -lt $now)
        IsNotYetValid       = ($Certificate.NotBefore -gt $now)
        HasPrivateKey       = $Certificate.HasPrivateKey
        Archived            = $Certificate.Archived
        SignatureAlgorithm  = [pscustomobject][ordered]@{
            FriendlyName = $Certificate.SignatureAlgorithm.FriendlyName
            Oid          = $Certificate.SignatureAlgorithm.Value
        }
        PublicKey           = Get-CertificatePublicKeySnapshot -Certificate $Certificate
        EnhancedKeyUsage    = $eku
        Extensions          = Get-CertificateExtensionsSnapshot -Certificate $Certificate
        OfflineChain        = Get-CertificateOfflineChainSnapshot -Certificate $Certificate
    }
}

# -----------------------------------------------------------------------------
# Identity / output file preparation
# -----------------------------------------------------------------------------
$computerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
$computerName = if ($computerSystem.Name) { [string]$computerSystem.Name } else { [string]$env:COMPUTERNAME }
$fqdn = Get-Fqdn -ComputerName $computerName

$targetIp = $env:VALIDATION_TARGET_IP
if ([string]::IsNullOrWhiteSpace($targetIp)) { $targetIp = Get-PrimaryIPv4Address }
if ([string]::IsNullOrWhiteSpace($targetIp)) { $targetIp = 'unknown-ip' }

$resultDir = $env:VALIDATION_RESULT_DIR
if ([string]::IsNullOrWhiteSpace($resultDir) -or -not (Test-Path -LiteralPath $resultDir)) {
    $resultDir = (Get-Location).Path
}

$timestampForFile = (Get-Date).ToString('yyyyMMdd_HHmmss')
$safeIp = Convert-ToSafeFileNamePart -Value $targetIp -Fallback 'unknown-ip'
$safeComputerName = Convert-ToSafeFileNamePart -Value $computerName -Fallback 'unknown-host'
$resultFileName = '{0}_{1}_Certificates_Services_Drivers_Valid_{2}.json' -f $safeIp, $safeComputerName, $timestampForFile
$resultFilePath = Join-Path -Path $resultDir -ChildPath $resultFileName

$identity = Invoke-SafeCollection -Name 'Identity' -ScriptBlock {
    [pscustomobject][ordered]@{
        ComputerName      = $computerName
        DNSHostName       = $computerSystem.DNSHostName
        FQDN              = $fqdn
        Manufacturer      = $computerSystem.Manufacturer
        Model             = $computerSystem.Model
        Domain            = $computerSystem.Domain
        PartOfDomain      = $computerSystem.PartOfDomain
        CurrentRemoteUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        TargetIPAddress   = $targetIp
    }
}

# -----------------------------------------------------------------------------
# 1 - Certificates: all LocalMachine and CurrentUser stores
# -----------------------------------------------------------------------------
$certificates = Invoke-SafeCollection -Name 'Certificates' -ScriptBlock {
    $records = New-Object System.Collections.Generic.List[object]

    foreach ($location in @('LocalMachine', 'CurrentUser')) {
        $root = 'Cert:\{0}' -f $location
        if (-not (Test-Path $root)) { continue }

        $stores = @(Get-ChildItem -Path $root -ErrorAction SilentlyContinue)
        foreach ($store in $stores) {
            $storeName = [string]$store.PSChildName
            $storePath = Join-Path $root $storeName
            try {
                $storeCerts = @(Get-ChildItem -Path $storePath -ErrorAction Stop |
                    Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] })

                foreach ($cert in $storeCerts) {
                    $records.Add((Get-CertificateSnapshot -Certificate $cert -StoreLocation $location -StoreName $storeName))
                }
            }
            catch {
                $records.Add([pscustomobject][ordered]@{
                    StoreLocation = $location
                    StoreName     = $storeName
                    CollectionError = $_.Exception.Message
                })
            }
        }
    }

    $all = @($records)
    $normalCerts = @($all | Where-Object { $_.Thumbprint })

    [pscustomobject][ordered]@{
        Summary = [ordered]@{
            Total                  = $normalCerts.Count
            LocalMachine          = @($normalCerts | Where-Object StoreLocation -eq 'LocalMachine').Count
            CurrentUser           = @($normalCerts | Where-Object StoreLocation -eq 'CurrentUser').Count
            Expired                = @($normalCerts | Where-Object ExpirationStatus -eq 'EXPIRED').Count
            NotYetValid            = @($normalCerts | Where-Object ExpirationStatus -eq 'NOT_YET_VALID').Count
            ExpiringWithin7Days    = @($normalCerts | Where-Object ExpirationStatus -eq 'EXPIRING_7_DAYS').Count
            ExpiringWithin30Days   = @($normalCerts | Where-Object ExpirationStatus -eq 'EXPIRING_30_DAYS').Count
            ExpiringWithin90Days   = @($normalCerts | Where-Object ExpirationStatus -eq 'EXPIRING_90_DAYS').Count
            WithPrivateKey         = @($normalCerts | Where-Object HasPrivateKey -eq $true).Count
            OfflineChainInvalid    = @($normalCerts | Where-Object { $_.OfflineChain -and $_.OfflineChain.IsValid -eq $false }).Count
        }
        ExpirationAttention = @($normalCerts | Where-Object { $_.ExpirationStatus -ne 'VALID' } |
            Sort-Object NotAfter |
            Select-Object StoreLocation, StoreName, Subject, Issuer, Thumbprint, NotAfter, DaysUntilExpiration, ExpirationStatus)
        Certificates = $all
    }
}

# Certificate bindings often explain which machine certificates are actively used.
$certificateBindings = Invoke-SafeCollection -Name 'CertificateBindings' -ScriptBlock {
    $rdpThumbprint = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SSLCertificateSHA1Hash'
    if ($rdpThumbprint -is [byte[]]) {
        $rdpThumbprint = ([BitConverter]::ToString($rdpThumbprint)).Replace('-', '')
    }

    [pscustomobject][ordered]@{
        RDP = [pscustomobject][ordered]@{
            SSLCertificateSHA1Hash = $rdpThumbprint
        }
        HTTPSSLBindings = Invoke-NativeReadOnly -FilePath 'netsh.exe' -Arguments @('http', 'show', 'sslcert')
        WinRMListeners  = Invoke-NativeReadOnly -FilePath 'winrm.cmd' -Arguments @('enumerate', 'winrm/config/listener')
    }
}

# -----------------------------------------------------------------------------
# 2 - Services: complete service configuration plus binaries and registry config
# -----------------------------------------------------------------------------
$services = Invoke-SafeCollection -Name 'Services' -ScriptBlock {
    $serviceCim = @(Get-CimInstance Win32_Service -ErrorAction Stop | Sort-Object Name)
    $servicePsByName = @{}
    try {
        foreach ($svc in @(Get-Service -ErrorAction Stop)) { $servicePsByName[$svc.Name] = $svc }
    }
    catch { }

    $records = New-Object System.Collections.Generic.List[object]

    foreach ($svc in $serviceCim) {
        $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\{0}' -f $svc.Name
        $parametersPath = Join-Path $registryPath 'Parameters'
        $registryValues = Get-RegistryKeyValuesSafe -Path $registryPath
        $parameterValues = Get-RegistryKeyValuesSafe -Path $parametersPath

        $imagePathRaw = Get-RegistryValueSafe -Path $registryPath -Name 'ImagePath'
        if ([string]::IsNullOrWhiteSpace([string]$imagePathRaw)) { $imagePathRaw = $svc.PathName }
        $binaryPath = Resolve-CommandExecutablePath -CommandLine ([string]$imagePathRaw)

        $serviceDll = Get-RegistryValueSafe -Path $parametersPath -Name 'ServiceDll'
        if ($serviceDll) { $serviceDll = [Environment]::ExpandEnvironmentVariables([string]$serviceDll) }

        $dependencies = @()
        $dependentServices = @()
        if ($servicePsByName.ContainsKey($svc.Name)) {
            try { $dependencies = @($servicePsByName[$svc.Name].ServicesDependedOn | ForEach-Object { $_.Name }) } catch { }
            try { $dependentServices = @($servicePsByName[$svc.Name].DependentServices | ForEach-Object { $_.Name }) } catch { }
        }

        $startClassification = switch ([string]$svc.StartMode) {
            'Auto'     { 'Automatic' }
            'Manual'   { 'Manual' }
            'Disabled' { 'Disabled' }
            default    { [string]$svc.StartMode }
        }

        $delayedAutoStart = Get-RegistryValueSafe -Path $registryPath -Name 'DelayedAutoStart'
        if ($startClassification -eq 'Automatic' -and $delayedAutoStart -eq 1) {
            $startClassification = 'AutomaticDelayed'
        }

        $failureActions = Get-RegistryValueSafe -Path $registryPath -Name 'FailureActions'
        $failureActionsSnapshot = $null
        if ($failureActions -is [byte[]]) {
            $failureActionsSnapshot = [pscustomobject][ordered]@{
                Present = $true
                Length  = $failureActions.Length
                Base64  = [Convert]::ToBase64String($failureActions)
            }
        }
        else {
            $failureActionsSnapshot = [pscustomobject][ordered]@{ Present = ($null -ne $failureActions); Value = $failureActions }
        }

        $records.Add([pscustomobject][ordered]@{
            Name                     = $svc.Name
            DisplayName              = $svc.DisplayName
            Description              = $svc.Description
            State                    = $svc.State
            Status                   = $svc.Status
            Started                  = $svc.Started
            StartMode                = $svc.StartMode
            StartClassification      = $startClassification
            DelayedAutoStart         = $delayedAutoStart
            ServiceAccount           = $svc.StartName
            PathName                 = $svc.PathName
            ProcessId                = $svc.ProcessId
            ServiceType              = $svc.ServiceType
            DesktopInteract          = $svc.DesktopInteract
            AcceptPause              = $svc.AcceptPause
            AcceptStop               = $svc.AcceptStop
            ExitCode                 = $svc.ExitCode
            ServiceSpecificExitCode  = $svc.ServiceSpecificExitCode
            ErrorControl             = Get-RegistryValueSafe -Path $registryPath -Name 'ErrorControl'
            RequiredPrivileges       = Get-RegistryValueSafe -Path $registryPath -Name 'RequiredPrivileges'
            ServiceSidType           = Get-RegistryValueSafe -Path $registryPath -Name 'ServiceSidType'
            FailureActionsOnNonCrash = Get-RegistryValueSafe -Path $registryPath -Name 'FailureActionsOnNonCrashFailures'
            FailureActions           = $failureActionsSnapshot
            Dependencies             = $dependencies
            DependentServices        = $dependentServices
            Binary                   = Get-FileMetadataSnapshot -Path $binaryPath
            ServiceDll               = if ($serviceDll) { Get-FileMetadataSnapshot -Path $serviceDll } else { $null }
            Registry                 = $registryValues
            ParametersRegistry       = $parameterValues
            TriggerInfoPresent       = Test-Path -LiteralPath (Join-Path $registryPath 'TriggerInfo')
        })
    }

    $all = @($records)
    [pscustomobject][ordered]@{
        Summary = [ordered]@{
            Total              = $all.Count
            Running            = @($all | Where-Object State -eq 'Running').Count
            Stopped            = @($all | Where-Object State -eq 'Stopped').Count
            Automatic          = @($all | Where-Object StartClassification -eq 'Automatic').Count
            AutomaticDelayed   = @($all | Where-Object StartClassification -eq 'AutomaticDelayed').Count
            Manual             = @($all | Where-Object StartClassification -eq 'Manual').Count
            Disabled           = @($all | Where-Object StartClassification -eq 'Disabled').Count
            BinaryMissing      = @($all | Where-Object { $_.Binary -and $_.Binary.Exists -eq $false -and $_.PathName }).Count
            BinaryNotSigned    = @($all | Where-Object { $_.Binary.Authenticode.Status -eq 'NotSigned' }).Count
            BinaryBadSignature = @($all | Where-Object { $_.Binary.Authenticode.Status -in @('HashMismatch','NotTrusted','UnknownError') }).Count
        }
        Services = $all
    }
}

# PCS 7 V10 hardening service focus. This is intentionally descriptive only:
# no OK/NOK verdict is produced because some service names differ by Windows build.
$pcs7HardeningServiceFocus = Invoke-SafeCollection -Name 'PCS7HardeningServiceFocus' -ScriptBlock {
    $allServices = if ($services -and $services.Services) { @($services.Services) } else { @() }

    $patterns = @(
        [pscustomobject]@{ Description = 'Bluetooth-Audiogateway-Dienst'; Regex = '^(BTAGService)$|Bluetooth.*Audio.*Gateway' },
        [pscustomobject]@{ Description = 'Bluetooth-Unterstuetzungsdienst'; Regex = '^(bthserv)$|Bluetooth.*Support|Bluetooth-Unterst' },
        [pscustomobject]@{ Description = 'Bluetooth-Unterstuetzungsdienst fuer Benutzer'; Regex = '^BluetoothUserService(_.*)?$|Bluetooth.*User.*Support' },
        [pscustomobject]@{ Description = 'Diagnosediensthost'; Regex = '^(WdiServiceHost)$|Diagnostic Service Host|Diagnosediensthost' },
        [pscustomobject]@{ Description = 'Diagnoserichtliniendienst'; Regex = '^(DPS)$|Diagnostic Policy|Diagnoserichtlinien' },
        [pscustomobject]@{ Description = 'Funkverwaltungsdienst'; Regex = '^(RmSvc)$|Radio Management|Funkverwaltung' },
        [pscustomobject]@{ Description = 'Geolocation-Dienst'; Regex = '^(lfsvc)$|Geolocation' },
        [pscustomobject]@{ Description = 'Leistungsprotokolle und -warnungen'; Regex = '^(pla)$|Performance Logs|Leistungsprotokolle' },
        [pscustomobject]@{ Description = 'Manager fuer heruntergeladene Karten'; Regex = '^(MapsBroker)$|Downloaded Maps|heruntergeladene Karten' },
        [pscustomobject]@{ Description = 'Telefondienst'; Regex = '^(PhoneSvc|TapiSrv)$|Phone Service|Telephony|Telefondienst' },
        [pscustomobject]@{ Description = 'WalletService'; Regex = '^(WalletService)$' },
        [pscustomobject]@{ Description = 'Windows Media Player-Netzwerkfreigabedienst'; Regex = '^(WMPNetworkSvc)$|Media Player.*Network|Netzwerkfreigabe' },
        [pscustomobject]@{ Description = 'Windows Presentation Foundation-Schriftartcache'; Regex = '^(FontCache3\.0\.0\.0)$|Presentation Foundation.*Font|Schriftartcache' },
        [pscustomobject]@{ Description = 'Windows-Dienst fuer mobile Hotspots'; Regex = '^(icssvc)$|Mobile Hotspot|mobile Hotspots' },
        [pscustomobject]@{ Description = 'Windows-Farbsystem'; Regex = '^(WcsPlugInService)$|Windows Color System|Windows-Farbsystem' },
        [pscustomobject]@{ Description = 'Windows-Insider-Dienst'; Regex = '^(wisvc)$|Windows Insider' },
        [pscustomobject]@{ Description = 'Windows-Sofortverbindung - Konfigurationsregistrierungsstelle'; Regex = '^(Wcncsvc)$|Windows Connect Now|Windows-Sofortverbindung' },
        [pscustomobject]@{ Description = 'Xbox Accessory Management Service'; Regex = '^(XboxGipSvc)$|Xbox Accessory' },
        [pscustomobject]@{ Description = 'Xbox Live Authentifizierungs-Manager'; Regex = '^(XblAuthManager)$|Xbox Live.*Auth' },
        [pscustomobject]@{ Description = 'Xbox Live-Netzwerkservice'; Regex = '^(XboxNetApiSvc)$|Xbox Live.*Network|Xbox Live-Netzwerk' },
        [pscustomobject]@{ Description = 'Xbox Live-Spiele speichern'; Regex = '^(XblGameSave)$|Xbox Live.*Game Save|Xbox Live-Spiele' },
        [pscustomobject]@{ Description = 'Zahlungs- und NFC/SE-Manager'; Regex = '^(SEMgrSvc)$|Payments|NFC|SE-Manager|Zahlungs' },
        [pscustomobject]@{ Description = 'Zertifikatverteilung'; Regex = '^(CertPropSvc)$|Certificate Propagation|Zertifikatverteilung' }
    )

    @($patterns | ForEach-Object {
        $pattern = $_
        $matches = @($allServices | Where-Object {
            $_.Name -match $pattern.Regex -or $_.DisplayName -match $pattern.Regex
        })
        [pscustomobject][ordered]@{
            HardeningDescription = $pattern.Description
            MatchRegex           = $pattern.Regex
            Found                = ($matches.Count -gt 0)
            MatchingServices     = @($matches | Select-Object Name, DisplayName, State, StartClassification, ServiceAccount, PathName)
        }
    })
}

# -----------------------------------------------------------------------------
# 3 - Drivers: PnP, kernel/system drivers, driver store and device health
# -----------------------------------------------------------------------------
$pnpDrivers = Invoke-SafeCollection -Name 'PnPDrivers' -ScriptBlock {
    $devicesById = @{}
    foreach ($device in @(Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue)) {
        if ($device.PNPDeviceID) { $devicesById[[string]$device.PNPDeviceID] = $device }
    }

    $records = @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction Stop |
        Sort-Object DeviceClass, DeviceName, DriverVersion |
        ForEach-Object {
            $device = $null
            if ($_.DeviceID -and $devicesById.ContainsKey([string]$_.DeviceID)) { $device = $devicesById[[string]$_.DeviceID] }

            $driverPath = $null
            if ($_.DriverName) {
                $candidate = Join-Path (Join-Path $env:SystemRoot 'System32\drivers') ([string]$_.DriverName)
                if (Test-Path -LiteralPath $candidate -PathType Leaf) { $driverPath = $candidate }
            }

            [pscustomobject][ordered]@{
                DeviceName              = $_.DeviceName
                DeviceID                = $_.DeviceID
                DeviceClass             = $_.DeviceClass
                FriendlyName            = $_.FriendlyName
                Manufacturer            = $_.Manufacturer
                DriverProviderName      = $_.DriverProviderName
                DriverVersion           = $_.DriverVersion
                DriverDate              = Convert-ToIso8601 $_.DriverDate
                DriverName              = $_.DriverName
                InfName                 = $_.InfName
                IsSigned                = $_.IsSigned
                Signer                  = $_.Signer
                HardWareID              = @($_.HardWareID)
                CompatID                = @($_.CompatID)
                PDO                     = $_.PDO
                Started                 = $_.Started
                ConfigManagerErrorCode  = if ($device) { $device.ConfigManagerErrorCode } else { $null }
                PnPStatus               = if ($device) { $device.Status } else { $null }
                PnPService              = if ($device) { $device.Service } else { $null }
                PnPClassGuid            = if ($device) { $device.ClassGuid } else { $null }
                Present                 = if ($device -and $device.PSObject.Properties.Name -contains 'Present') { $device.Present } else { $null }
                DriverBinary            = if ($driverPath) { Get-FileMetadataSnapshot -Path $driverPath } else { $null }
            }
        })

    [pscustomobject][ordered]@{
        Summary = [ordered]@{
            Total                   = $records.Count
            Signed                  = @($records | Where-Object IsSigned -eq $true).Count
            Unsigned                = @($records | Where-Object IsSigned -eq $false).Count
            DevicesWithErrorCode    = @($records | Where-Object { $null -ne $_.ConfigManagerErrorCode -and $_.ConfigManagerErrorCode -ne 0 }).Count
            MicrosoftProvided       = @($records | Where-Object DriverProviderName -match '^Microsoft').Count
            ThirdPartyProvided      = @($records | Where-Object { $_.DriverProviderName -and $_.DriverProviderName -notmatch '^Microsoft' }).Count
        }
        Attention = @($records | Where-Object {
            $_.IsSigned -eq $false -or
            ($null -ne $_.ConfigManagerErrorCode -and $_.ConfigManagerErrorCode -ne 0) -or
            ($_.DriverBinary -and $_.DriverBinary.Authenticode.Status -in @('NotSigned','HashMismatch','NotTrusted','UnknownError'))
        })
        Drivers = $records
    }
}

$systemDrivers = Invoke-SafeCollection -Name 'SystemDrivers' -ScriptBlock {
    $records = @(Get-CimInstance Win32_SystemDriver -ErrorAction Stop |
        Sort-Object Name |
        ForEach-Object {
            $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\{0}' -f $_.Name
            $resolvedPath = Resolve-DriverBinaryPath -PathName ([string]$_.PathName)

            [pscustomobject][ordered]@{
                Name                    = $_.Name
                DisplayName             = $_.DisplayName
                Description             = $_.Description
                State                   = $_.State
                Status                  = $_.Status
                Started                 = $_.Started
                StartMode               = $_.StartMode
                ServiceType             = $_.ServiceType
                PathName                = $_.PathName
                ProcessId               = $_.ProcessId
                AcceptPause             = $_.AcceptPause
                AcceptStop              = $_.AcceptStop
                ErrorControl            = Get-RegistryValueSafe -Path $registryPath -Name 'ErrorControl'
                Group                   = Get-RegistryValueSafe -Path $registryPath -Name 'Group'
                Tag                     = Get-RegistryValueSafe -Path $registryPath -Name 'Tag'
                DependOnService         = Get-RegistryValueSafe -Path $registryPath -Name 'DependOnService'
                DependOnGroup           = Get-RegistryValueSafe -Path $registryPath -Name 'DependOnGroup'
                RequiredPrivileges      = Get-RegistryValueSafe -Path $registryPath -Name 'RequiredPrivileges'
                Binary                  = Get-FileMetadataSnapshot -Path $resolvedPath
                Registry                = Get-RegistryKeyValuesSafe -Path $registryPath
            }
        })

    [pscustomobject][ordered]@{
        Summary = [ordered]@{
            Total              = $records.Count
            Running            = @($records | Where-Object State -eq 'Running').Count
            Stopped            = @($records | Where-Object State -eq 'Stopped').Count
            Auto               = @($records | Where-Object StartMode -eq 'Auto').Count
            Manual             = @($records | Where-Object StartMode -eq 'Manual').Count
            Disabled           = @($records | Where-Object StartMode -eq 'Disabled').Count
            MissingBinary      = @($records | Where-Object { $_.Binary -and $_.Binary.Exists -eq $false -and $_.PathName }).Count
            NotSignedBinary    = @($records | Where-Object { $_.Binary.Authenticode.Status -eq 'NotSigned' }).Count
            BadSignatureBinary = @($records | Where-Object { $_.Binary.Authenticode.Status -in @('HashMismatch','NotTrusted','UnknownError') }).Count
        }
        Attention = @($records | Where-Object {
            ($_.Binary -and $_.Binary.Exists -eq $false -and $_.PathName) -or
            ($_.Binary -and $_.Binary.Authenticode.Status -in @('NotSigned','HashMismatch','NotTrusted','UnknownError'))
        })
        Drivers = $records
    }
}

$driverStore = Invoke-SafeCollection -Name 'DriverStore' -ScriptBlock {
    $windowsDrivers = @()
    if (Get-Command Get-WindowsDriver -ErrorAction SilentlyContinue) {
        try {
            $windowsDrivers = @(Get-WindowsDriver -Online -All -ErrorAction Stop |
                Sort-Object ClassName, ProviderName, PublishedName |
                ForEach-Object {
                    [pscustomobject][ordered]@{
                        Driver              = $_.Driver
                        PublishedName       = $_.PublishedName
                        OriginalFileName    = $_.OriginalFileName
                        Inbox               = $_.Inbox
                        ClassName           = $_.ClassName
                        ClassDescription    = $_.ClassDescription
                        ClassGuid           = $_.ClassGuid
                        ProviderName        = $_.ProviderName
                        Date                = Convert-ToIso8601 $_.Date
                        Version             = [string]$_.Version
                        BootCritical        = $_.BootCritical
                        CatalogFile         = $_.CatalogFile
                        Signature           = [string]$_.Signature
                    }
                })
        }
        catch { }
    }

    [pscustomobject][ordered]@{
        WindowsDriverCmdletAvailable = [bool](Get-Command Get-WindowsDriver -ErrorAction SilentlyContinue)
        WindowsDrivers               = $windowsDrivers
        PnPUtilEnumDrivers           = Invoke-NativeReadOnly -FilePath 'pnputil.exe' -Arguments @('/enum-drivers')
        DriverQueryVerbose           = Invoke-NativeReadOnly -FilePath 'driverquery.exe' -Arguments @('/V', '/FO', 'CSV')
        FilterDrivers                = Invoke-NativeReadOnly -FilePath 'fltmc.exe' -Arguments @('filters')
    }
}

$deviceHealth = Invoke-SafeCollection -Name 'DeviceHealth' -ScriptBlock {
    $all = @(Get-CimInstance Win32_PnPEntity -ErrorAction Stop |
        Sort-Object ConfigManagerErrorCode, PNPClass, Name |
        ForEach-Object {
            [pscustomobject][ordered]@{
                Name                   = $_.Name
                Caption                = $_.Caption
                PNPDeviceID            = $_.PNPDeviceID
                PNPClass               = $_.PNPClass
                ClassGuid              = $_.ClassGuid
                Manufacturer           = $_.Manufacturer
                Service                = $_.Service
                Status                 = $_.Status
                ConfigManagerErrorCode = $_.ConfigManagerErrorCode
                Present                = if ($_.PSObject.Properties.Name -contains 'Present') { $_.Present } else { $null }
                HardwareID             = @($_.HardwareID)
                CompatibleID           = @($_.CompatibleID)
            }
        })

    [pscustomobject][ordered]@{
        Summary = [ordered]@{
            Total            = $all.Count
            WithErrorCode    = @($all | Where-Object { $null -ne $_.ConfigManagerErrorCode -and $_.ConfigManagerErrorCode -ne 0 }).Count
            StatusNotOK      = @($all | Where-Object { $_.Status -and $_.Status -ne 'OK' }).Count
        }
        ProblemDevices = @($all | Where-Object {
            ($null -ne $_.ConfigManagerErrorCode -and $_.ConfigManagerErrorCode -ne 0) -or
            ($_.Status -and $_.Status -ne 'OK')
        })
        Devices = $all
    }
}

# -----------------------------------------------------------------------------
# 4 - Recent service / driver health events (read-only diagnostic context)
# -----------------------------------------------------------------------------
$recentServiceDriverEvents = Invoke-SafeCollection -Name 'RecentServiceDriverEvents' -ScriptBlock {
    $startTime = (Get-Date).AddDays(-30)

    function Convert-WinEventRecord {
        param($Event)
        [pscustomobject][ordered]@{
            TimeCreated   = Convert-ToIso8601 $Event.TimeCreated
            LogName       = $Event.LogName
            ProviderName  = $Event.ProviderName
            Id            = $Event.Id
            Level         = $Event.Level
            LevelDisplayName = $Event.LevelDisplayName
            RecordId      = $Event.RecordId
            MachineName   = $Event.MachineName
            Message       = $Event.Message
        }
    }

    $scm = @()
    try {
        $scm = @(Get-WinEvent -FilterHashtable @{
            LogName='System'; ProviderName='Service Control Manager'; StartTime=$startTime
        } -MaxEvents 200 -ErrorAction Stop |
            Where-Object { $_.Level -in @(2,3) } |
            ForEach-Object { Convert-WinEventRecord $_ })
    }
    catch { }

    $kernelPnp = @()
    try {
        $kernelPnp = @(Get-WinEvent -FilterHashtable @{
            LogName='System'; ProviderName='Microsoft-Windows-Kernel-PnP'; StartTime=$startTime
        } -MaxEvents 200 -ErrorAction Stop |
            Where-Object { $_.Level -in @(2,3) } |
            ForEach-Object { Convert-WinEventRecord $_ })
    }
    catch { }

    $codeIntegrity = @()
    try {
        $codeIntegrity = @(Get-WinEvent -FilterHashtable @{
            LogName='Microsoft-Windows-CodeIntegrity/Operational'; StartTime=$startTime
        } -MaxEvents 200 -ErrorAction Stop |
            Where-Object { $_.Level -in @(2,3) } |
            ForEach-Object { Convert-WinEventRecord $_ })
    }
    catch { }

    $driverFramework = @()
    try {
        $driverFramework = @(Get-WinEvent -FilterHashtable @{
            LogName='Microsoft-Windows-DriverFrameworks-UserMode/Operational'; StartTime=$startTime
        } -MaxEvents 200 -ErrorAction Stop |
            Where-Object { $_.Level -in @(2,3) } |
            ForEach-Object { Convert-WinEventRecord $_ })
    }
    catch { }

    [pscustomobject][ordered]@{
        WindowDays = 30
        ServiceControlManagerWarningsErrors = $scm
        KernelPnPWarningsErrors              = $kernelPnp
        CodeIntegrityWarningsErrors          = $codeIntegrity
        DriverFrameworkWarningsErrors        = $driverFramework
    }
}

# -----------------------------------------------------------------------------
# Cross-section best-practice attention summary (informational, no role verdict)
# -----------------------------------------------------------------------------
$attentionSummary = Invoke-SafeCollection -Name 'AttentionSummary' -ScriptBlock {
    [pscustomobject][ordered]@{
        Certificates = [pscustomobject][ordered]@{
            Expired              = if ($certificates) { $certificates.Summary.Expired } else { $null }
            NotYetValid          = if ($certificates) { $certificates.Summary.NotYetValid } else { $null }
            ExpiringWithin7Days  = if ($certificates) { $certificates.Summary.ExpiringWithin7Days } else { $null }
            ExpiringWithin30Days = if ($certificates) { $certificates.Summary.ExpiringWithin30Days } else { $null }
            ExpiringWithin90Days = if ($certificates) { $certificates.Summary.ExpiringWithin90Days } else { $null }
            OfflineChainInvalid  = if ($certificates) { $certificates.Summary.OfflineChainInvalid } else { $null }
        }
        Services = [pscustomobject][ordered]@{
            BinaryMissing       = if ($services) { $services.Summary.BinaryMissing } else { $null }
            BinaryNotSigned     = if ($services) { $services.Summary.BinaryNotSigned } else { $null }
            BinaryBadSignature  = if ($services) { $services.Summary.BinaryBadSignature } else { $null }
        }
        Drivers = [pscustomobject][ordered]@{
            PnPUnsigned              = if ($pnpDrivers) { $pnpDrivers.Summary.Unsigned } else { $null }
            PnPDevicesWithErrorCode  = if ($pnpDrivers) { $pnpDrivers.Summary.DevicesWithErrorCode } else { $null }
            SystemDriverMissingBinary = if ($systemDrivers) { $systemDrivers.Summary.MissingBinary } else { $null }
            SystemDriverNotSigned     = if ($systemDrivers) { $systemDrivers.Summary.NotSignedBinary } else { $null }
            DeviceHealthErrors        = if ($deviceHealth) { $deviceHealth.Summary.WithErrorCode } else { $null }
        }
        Interpretation = @(
            'This section highlights inventory conditions only and is not a role-specific OK/NOK verdict.',
            'Expired or soon-expiring certificates may be intentional in unused stores and require context.',
            'Stopped services are not automatically errors; trigger-start and on-demand services are normal on Windows.',
            'Unsigned/unknown driver signatures and PnP error codes deserve manual review, especially for third-party OT drivers.'
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
        ScriptName             = 'Certificates_Services_Drivers_Valid.ps1'
        ValidationType         = 'Certificates_Services_Drivers_Valid'
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
        PrivateKeysExported    = $false
        OnlineRevocationChecks = $false
        ErrorSections          = $errorSections
    }
    Identity                  = $identity
    Certificates              = $certificates
    CertificateBindings       = $certificateBindings
    Services                  = $services
    PCS7HardeningServiceFocus = $pcs7HardeningServiceFocus
    PnPDrivers                = $pnpDrivers
    SystemDrivers             = $systemDrivers
    DriverStore               = $driverStore
    DeviceHealth              = $deviceHealth
    RecentServiceDriverEvents = $recentServiceDriverEvents
    AttentionSummary          = $attentionSummary
    CollectionStatus          = $script:CollectionStatus
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