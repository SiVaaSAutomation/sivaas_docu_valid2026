#requires -Version 5.1
<#
.SYNOPSIS
    Read-only inventory/validation snapshot for IPC ES systems.

.DESCRIPTION
    Collects installation-relevant system information and writes one JSON file.
    The script is designed for execution by the fixed Ansible validation playbook.

    Preferred environment variables supplied by Ansible:
      VALIDATION_RESULT_DIR  - directory in which the JSON file is written
      VALIDATION_TARGET_IP   - target IP used in file name and metadata

    File name:
      <IP>_<ComputerName>_Initial_Valid_<yyyyMMdd_HHmmss>.json

    Design goals:
      - read-only collection; no configuration changes
      - PowerShell 5.1 compatible
      - individual collector failures do not abort the complete inventory
      - no Win32_Product query (avoids possible MSI self-repair side effects)
      - no loading of the Default User NTUSER.DAT hive (keeps registry untouched)
#>

[CmdletBinding()]
param()

# Deliberately no strict mode: Windows cmdlet properties vary between OS builds.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:CollectionStatus = [ordered]@{}
$script:StartTime = Get-Date
$script:Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

function Convert-ToIso8601 {
    param([AllowNull()]$Value)

    if ($null -eq $Value) { return $null }
    try {
        return ([datetime]$Value).ToString('o')
    }
    catch {
        return [string]$Value
    }
}

function Convert-ToSafeFileNamePart {
    param(
        [AllowNull()]
        [string]$Value,
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
            Status      = 'OK'
            StartedUtc  = $started.ToUniversalTime().ToString('o')
            DurationMs  = [int]((Get-Date) - $started).TotalMilliseconds
            Error       = $null
        }
        return $data
    }
    catch {
        $script:CollectionStatus[$Name] = [ordered]@{
            Status      = 'ERROR'
            StartedUtc  = $started.ToUniversalTime().ToString('o')
            DurationMs  = [int]((Get-Date) - $started).TotalMilliseconds
            Error       = [ordered]@{
                Message              = $_.Exception.Message
                ExceptionType        = $_.Exception.GetType().FullName
                FullyQualifiedErrorId = $_.FullyQualifiedErrorId
                Category             = [string]$_.CategoryInfo.Category
                TargetName           = [string]$_.CategoryInfo.TargetName
            }
        }
        return $null
    }
}

function Get-RegistryKeySnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return [ordered]@{
            Exists = $false
            Path   = $Path
            Values = $null
        }
    }

    $item = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
    $values = [ordered]@{}
    foreach ($property in $item.PSObject.Properties) {
        if ($property.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') {
            $values[$property.Name] = $property.Value
        }
    }

    return [ordered]@{
        Exists = $true
        Path   = $Path
        Values = $values
    }
}

function Get-RegistryTreeSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$MaxDepth = 2,
        [int]$CurrentDepth = 0
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return [ordered]@{
            Exists      = $false
            Path        = $Path
            Values      = $null
            SubKeys     = @()
        }
    }

    $snapshot = Get-RegistryKeySnapshot -Path $Path
    $children = @()

    if ($CurrentDepth -lt $MaxDepth) {
        foreach ($child in @(Get-ChildItem -LiteralPath $Path -ErrorAction SilentlyContinue)) {
            $children += Get-RegistryTreeSnapshot -Path $child.PSPath -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1)
        }
    }

    return [ordered]@{
        Exists  = $snapshot.Exists
        Path    = $Path
        Values  = $snapshot.Values
        SubKeys = $children
    }
}

function Invoke-NativeReadOnly {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $false)][string[]]$Arguments = @()
    )

    try {
        $output = & $FilePath @Arguments 2>&1
        $exitCode = $LASTEXITCODE
        return [ordered]@{
            Command  = ($FilePath + ' ' + ($Arguments -join ' ')).Trim()
            ExitCode = $exitCode
            Output   = @($output | ForEach-Object { [string]$_ })
        }
    }
    catch {
        return [ordered]@{
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

    try {
        return [System.Net.Dns]::GetHostEntry($ComputerName).HostName
    }
    catch {
        return $null
    }
}

function Get-LocalAccountsSnapshot {
    $result = [ordered]@{
        Source = $null
        Users  = @()
        Groups = @()
    }

    if ((Get-Command Get-LocalUser -ErrorAction SilentlyContinue) -and
        (Get-Command Get-LocalGroup -ErrorAction SilentlyContinue) -and
        (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue)) {

        $result.Source = 'Microsoft.PowerShell.LocalAccounts'
        $groups = @(Get-LocalGroup -ErrorAction Stop | Sort-Object Name)
        $membershipBySid = @{}
        $groupObjects = @()

        foreach ($group in $groups) {
            $members = @()
            try {
                $members = @(Get-LocalGroupMember -Group $group.Name -ErrorAction Stop | ForEach-Object {
                    $sid = if ($_.SID) { $_.SID.Value } else { $null }
                    if ($sid) {
                        if (-not $membershipBySid.ContainsKey($sid)) {
                            $membershipBySid[$sid] = New-Object System.Collections.ArrayList
                        }
                        [void]$membershipBySid[$sid].Add($group.Name)
                    }
                    [pscustomobject][ordered]@{
                        Name            = $_.Name
                        SID             = $sid
                        ObjectClass     = [string]$_.ObjectClass
                        PrincipalSource = [string]$_.PrincipalSource
                    }
                })
            }
            catch {
                $members = @([pscustomobject][ordered]@{
                    Name            = $null
                    SID             = $null
                    ObjectClass     = $null
                    PrincipalSource = $null
                    Error           = $_.Exception.Message
                })
            }

            $groupObjects += [pscustomobject][ordered]@{
                Name        = $group.Name
                SID         = if ($group.SID) { $group.SID.Value } else { $null }
                Description = $group.Description
                Members     = $members
            }
        }

        $userObjects = @(Get-LocalUser -ErrorAction Stop | Sort-Object Name | ForEach-Object {
            $sid = if ($_.SID) { $_.SID.Value } else { $null }
            $memberOf = @()
            if ($sid -and $membershipBySid.ContainsKey($sid)) {
                $memberOf = @($membershipBySid[$sid] | Sort-Object -Unique)
            }

            [pscustomobject][ordered]@{
                Name                 = $_.Name
                FullName             = $_.FullName
                SID                  = $sid
                Enabled              = $_.Enabled
                Description          = $_.Description
                PasswordRequired     = $_.PasswordRequired
                PasswordExpires      = $_.PasswordExpires
                UserMayChangePassword = $_.UserMayChangePassword
                AccountExpires       = Convert-ToIso8601 $_.AccountExpires
                LastLogon            = Convert-ToIso8601 $_.LastLogon
                PasswordLastSet      = Convert-ToIso8601 $_.PasswordLastSet
                LocalGroups          = $memberOf
            }
        })

        $result.Users = $userObjects
        $result.Groups = $groupObjects
        return [pscustomobject]$result
    }

    # Read-only ADSI fallback for systems without Microsoft.PowerShell.LocalAccounts.
    $result.Source = 'ADSI WinNT Provider'
    $computer = [ADSI]("WinNT://{0},computer" -f $env:COMPUTERNAME)
    $children = @($computer.psbase.Children)

    $groups = @($children | Where-Object { $_.SchemaClassName -eq 'group' })
    $users = @($children | Where-Object { $_.SchemaClassName -eq 'user' })

    $groupObjects = @()
    $membershipByName = @{}
    foreach ($group in $groups) {
        $groupName = [string]$group.Name
        $members = @()
        try {
            $members = @($group.psbase.Invoke('Members') | ForEach-Object {
                $member = $_
                $name = $member.GetType().InvokeMember('Name', 'GetProperty', $null, $member, $null)
                $class = $member.GetType().InvokeMember('Class', 'GetProperty', $null, $member, $null)
                $adsPath = $member.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $member, $null)
                if (-not $membershipByName.ContainsKey([string]$name)) {
                    $membershipByName[[string]$name] = New-Object System.Collections.ArrayList
                }
                [void]$membershipByName[[string]$name].Add($groupName)
                [pscustomobject][ordered]@{
                    Name        = [string]$name
                    ObjectClass = [string]$class
                    ADSPath     = [string]$adsPath
                }
            })
        }
        catch {
            $members = @([pscustomobject][ordered]@{ Error = $_.Exception.Message })
        }

        $groupObjects += [pscustomobject][ordered]@{
            Name    = $groupName
            ADSPath = [string]$group.Path
            Members = $members
        }
    }

    $userObjects = @($users | ForEach-Object {
        $name = [string]$_.Name
        [pscustomobject][ordered]@{
            Name        = $name
            ADSPath     = [string]$_.Path
            LocalGroups = if ($membershipByName.ContainsKey($name)) { @($membershipByName[$name]) } else { @() }
        }
    })

    $result.Users = $userObjects
    $result.Groups = $groupObjects
    return [pscustomobject]$result
}

function Get-CertificateSnapshot {
    param([Parameter(Mandatory = $true)][string]$RootPath)

    $certificates = @()
    foreach ($cert in @(Get-ChildItem -Path $RootPath -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] })) {

        $eku = @()
        try {
            $eku = @($cert.EnhancedKeyUsageList | ForEach-Object {
                [pscustomobject][ordered]@{
                    FriendlyName = $_.FriendlyName
                    ObjectId     = $_.ObjectId.Value
                }
            })
        }
        catch { }

        $storePath = $null
        try {
            $storePath = [string]$cert.PSParentPath
            $storePath = $storePath -replace '^Microsoft\.PowerShell\.Security\\Certificate::', ''
        }
        catch { }

        $certificates += [pscustomobject][ordered]@{
            StorePath        = $storePath
            Subject          = $cert.Subject
            Issuer           = $cert.Issuer
            Thumbprint       = $cert.Thumbprint
            SerialNumber     = $cert.SerialNumber
            FriendlyName     = $cert.FriendlyName
            NotBefore        = Convert-ToIso8601 $cert.NotBefore
            NotAfter         = Convert-ToIso8601 $cert.NotAfter
            HasPrivateKey    = $cert.HasPrivateKey
            SignatureAlgorithm = if ($cert.SignatureAlgorithm) { $cert.SignatureAlgorithm.FriendlyName } else { $null }
            PublicKeyAlgorithm = if ($cert.PublicKey -and $cert.PublicKey.Oid) { $cert.PublicKey.Oid.FriendlyName } else { $null }
            EnhancedKeyUsage = $eku
        }
    }

    return @($certificates | Sort-Object StorePath, Subject, Thumbprint)
}

function Get-PendingRebootSnapshot {
    $checks = [ordered]@{}
    $checks.ComponentBasedServicing = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    $checks.WindowsUpdate = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    $checks.PendingFileRenameOperations = $false
    try {
        $value = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop).PendingFileRenameOperations
        $checks.PendingFileRenameOperations = ($null -ne $value -and @($value).Count -gt 0)
    }
    catch { }

    $checks.PendingComputerRename = $false
    try {
        $activeName = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -ErrorAction Stop).ComputerName
        $pendingName = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -ErrorAction Stop).ComputerName
        $checks.PendingComputerRename = ($activeName -ne $pendingName)
    }
    catch { }

    return [pscustomobject][ordered]@{
        RebootPending = [bool]($checks.ComponentBasedServicing -or $checks.WindowsUpdate -or $checks.PendingFileRenameOperations -or $checks.PendingComputerRename)
        Indicators    = $checks
    }
}

# -----------------------------------------------------------------------------
# Basic identity / output file preparation
# -----------------------------------------------------------------------------
$computerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
$operatingSystem = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
$computerName = if ($computerSystem.Name) { [string]$computerSystem.Name } else { [string]$env:COMPUTERNAME }
$fqdn = Get-Fqdn -ComputerName $computerName

$targetIp = $env:VALIDATION_TARGET_IP
if ([string]::IsNullOrWhiteSpace($targetIp)) {
    $targetIp = Get-PrimaryIPv4Address
}
if ([string]::IsNullOrWhiteSpace($targetIp)) {
    $targetIp = 'unknown-ip'
}

$resultDir = $env:VALIDATION_RESULT_DIR
if ([string]::IsNullOrWhiteSpace($resultDir) -or -not (Test-Path -LiteralPath $resultDir)) {
    $resultDir = (Get-Location).Path
}

$timestampForFile = (Get-Date).ToString('yyyyMMdd_HHmmss')
$safeIp = Convert-ToSafeFileNamePart -Value $targetIp -Fallback 'unknown-ip'
$safeComputerName = Convert-ToSafeFileNamePart -Value $computerName -Fallback 'unknown-host'
$resultFileName = '{0}_{1}_Initial_Valid_{2}.json' -f $safeIp, $safeComputerName, $timestampForFile
$resultFilePath = Join-Path -Path $resultDir -ChildPath $resultFileName

# -----------------------------------------------------------------------------
# 0 - Identity
# -----------------------------------------------------------------------------
$identity = Invoke-SafeCollection -Name 'Identity' -ScriptBlock {
    [pscustomobject][ordered]@{
        ComputerName       = $computerName
        DNSHostName        = $computerSystem.DNSHostName
        FQDN               = $fqdn
        Manufacturer       = $computerSystem.Manufacturer
        Model              = $computerSystem.Model
        SystemType         = $computerSystem.SystemType
        DomainRole         = $computerSystem.DomainRole
        CurrentRemoteUser  = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        TargetIPAddress    = $targetIp
    }
}

# -----------------------------------------------------------------------------
# 1 - All IPv4 / IPv6 addresses
# -----------------------------------------------------------------------------
$ipAddresses = Invoke-SafeCollection -Name 'IPAddresses' -ScriptBlock {
    @(Get-NetIPAddress -ErrorAction Stop |
        Sort-Object InterfaceIndex, AddressFamily, IPAddress |
        ForEach-Object {
            [pscustomobject][ordered]@{
                InterfaceAlias    = $_.InterfaceAlias
                InterfaceIndex    = $_.InterfaceIndex
                AddressFamily     = [string]$_.AddressFamily
                IPAddress         = $_.IPAddress
                PrefixLength      = $_.PrefixLength
                Type              = [string]$_.Type
                PrefixOrigin      = [string]$_.PrefixOrigin
                SuffixOrigin      = [string]$_.SuffixOrigin
                AddressState      = [string]$_.AddressState
                SkipAsSource      = $_.SkipAsSource
                ValidLifetime     = [string]$_.ValidLifetime
                PreferredLifetime = [string]$_.PreferredLifetime
            }
        })
}

# -----------------------------------------------------------------------------
# 2 / 3 / 4 - Language, current user, welcome screen, region / Geo-ID
# -----------------------------------------------------------------------------
$languageAndRegion = Invoke-SafeCollection -Name 'LanguageAndRegion' -ScriptBlock {
    $systemLocale = $null
    if (Get-Command Get-WinSystemLocale -ErrorAction SilentlyContinue) {
        $systemLocale = Get-WinSystemLocale -ErrorAction Stop
    }

    $userLanguages = @()
    if (Get-Command Get-WinUserLanguageList -ErrorAction SilentlyContinue) {
        $userLanguages = @(Get-WinUserLanguageList -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{
                LanguageTag     = $_.LanguageTag
                Autonym         = $_.Autonym
                EnglishName     = $_.EnglishName
                LocalizedName   = $_.LocalizedName
                ScriptName      = $_.ScriptName
                InputMethodTips = @($_.InputMethodTips)
                Spellchecking   = $_.Spellchecking
                Handwriting     = $_.Handwriting
            }
        })
    }

    $homeLocation = $null
    if (Get-Command Get-WinHomeLocation -ErrorAction SilentlyContinue) {
        $homeLocation = Get-WinHomeLocation -ErrorAction SilentlyContinue
    }

    $uiOverride = $null
    if (Get-Command Get-WinUILanguageOverride -ErrorAction SilentlyContinue) {
        try { $uiOverride = Get-WinUILanguageOverride -ErrorAction Stop } catch { }
    }

    $inputOverride = $null
    if (Get-Command Get-WinDefaultInputMethodOverride -ErrorAction SilentlyContinue) {
        try { $inputOverride = Get-WinDefaultInputMethodOverride -ErrorAction Stop } catch { }
    }

    $installedUiLanguages = @()
    $muiPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\MUI\UILanguages'
    if (Test-Path $muiPath) {
        $installedUiLanguages = @(Get-ChildItem $muiPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName)
    }

    $currentCulture = Get-Culture
    $currentUiCulture = Get-UICulture
    $regionInfo = New-Object System.Globalization.RegionInfo($currentCulture.Name)

    [pscustomobject][ordered]@{
        WindowsSystemLocale = if ($systemLocale) {
            [pscustomobject][ordered]@{
                Name        = $systemLocale.Name
                DisplayName = $systemLocale.DisplayName
                LCID        = $systemLocale.LCID
            }
        } else { $null }
        CurrentCulture = [pscustomobject][ordered]@{
            Name              = $currentCulture.Name
            DisplayName       = $currentCulture.DisplayName
            EnglishName       = $currentCulture.EnglishName
            NativeName        = $currentCulture.NativeName
            LCID              = $currentCulture.LCID
            DateTimeFormat    = [pscustomobject][ordered]@{
                ShortDatePattern = $currentCulture.DateTimeFormat.ShortDatePattern
                LongDatePattern  = $currentCulture.DateTimeFormat.LongDatePattern
                ShortTimePattern = $currentCulture.DateTimeFormat.ShortTimePattern
                LongTimePattern  = $currentCulture.DateTimeFormat.LongTimePattern
                FirstDayOfWeek   = [string]$currentCulture.DateTimeFormat.FirstDayOfWeek
            }
            NumberFormat      = [pscustomobject][ordered]@{
                DecimalSeparator = $currentCulture.NumberFormat.NumberDecimalSeparator
                GroupSeparator   = $currentCulture.NumberFormat.NumberGroupSeparator
                CurrencySymbol   = $currentCulture.NumberFormat.CurrencySymbol
            }
        }
        CurrentUICulture = [pscustomobject][ordered]@{
            Name        = $currentUiCulture.Name
            DisplayName = $currentUiCulture.DisplayName
            EnglishName = $currentUiCulture.EnglishName
            NativeName  = $currentUiCulture.NativeName
            LCID        = $currentUiCulture.LCID
        }
        UserUILanguageOverride       = if ($uiOverride) { [string]$uiOverride } else { $null }
        DefaultInputMethodOverride   = if ($inputOverride) { [string]$inputOverride.InputMethodTip } else { $null }
        CurrentUserLanguageList      = $userLanguages
        InstalledUILanguages         = $installedUiLanguages
        Region = [pscustomobject][ordered]@{
            Name                   = $regionInfo.Name
            EnglishName            = $regionInfo.EnglishName
            NativeName             = $regionInfo.NativeName
            TwoLetterISORegionName = $regionInfo.TwoLetterISORegionName
            ThreeLetterISORegionName = $regionInfo.ThreeLetterISORegionName
            GeoId                  = if ($homeLocation) { $homeLocation.GeoId } else { $null }
        }
        CurrentUser = [pscustomobject][ordered]@{
            Identity       = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            International  = Get-RegistryKeySnapshot 'HKCU:\Control Panel\International'
            Geo            = Get-RegistryKeySnapshot 'HKCU:\Control Panel\International\Geo'
            KeyboardPreload = Get-RegistryKeySnapshot 'HKCU:\Keyboard Layout\Preload'
            KeyboardSubstitutes = Get-RegistryKeySnapshot 'HKCU:\Keyboard Layout\Substitutes'
        }
        WelcomeScreenSystemAccount = [pscustomobject][ordered]@{
            Note            = 'HKEY_USERS\.DEFAULT represents the system/welcome-screen account, not the Default User profile.'
            International   = Get-RegistryKeySnapshot 'Registry::HKEY_USERS\.DEFAULT\Control Panel\International'
            Geo             = Get-RegistryKeySnapshot 'Registry::HKEY_USERS\.DEFAULT\Control Panel\International\Geo'
            KeyboardPreload = Get-RegistryKeySnapshot 'Registry::HKEY_USERS\.DEFAULT\Keyboard Layout\Preload'
            KeyboardSubstitutes = Get-RegistryKeySnapshot 'Registry::HKEY_USERS\.DEFAULT\Keyboard Layout\Substitutes'
        }
        DefaultUserProfile = [pscustomobject][ordered]@{
            HivePath = 'C:\Users\Default\NTUSER.DAT'
            Exists   = Test-Path 'C:\Users\Default\NTUSER.DAT'
            SettingsRead = $false
            Reason   = 'The Default User hive is normally not loaded. This script deliberately does not load/unload NTUSER.DAT because the validation is strictly read-only.'
        }
        SystemNls = [pscustomobject][ordered]@{
            Language = Get-RegistryKeySnapshot 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language'
            Locale   = Get-RegistryKeySnapshot 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Locale'
        }
        DismOnlineInternational = Invoke-NativeReadOnly -FilePath 'dism.exe' -Arguments @('/Online','/Get-Intl','/English')
    }
}

# -----------------------------------------------------------------------------
# 5 - Local/UTC time, time zone, Windows Time service
# -----------------------------------------------------------------------------
$timeConfiguration = Invoke-SafeCollection -Name 'TimeConfiguration' -ScriptBlock {
    $now = Get-Date
    $tz = Get-TimeZone -ErrorAction Stop
    $w32Service = Get-CimInstance Win32_Service -Filter "Name='W32Time'" -ErrorAction SilentlyContinue

    [pscustomobject][ordered]@{
        LocalTime = $now.ToString('o')
        UtcTime   = $now.ToUniversalTime().ToString('o')
        TimeZone  = [pscustomobject][ordered]@{
            Id                   = $tz.Id
            DisplayName          = $tz.DisplayName
            StandardName         = $tz.StandardName
            DaylightName         = $tz.DaylightName
            BaseUtcOffset        = [string]$tz.BaseUtcOffset
            SupportsDaylightSavingTime = $tz.SupportsDaylightSavingTime
        }
        WindowsTimeService = if ($w32Service) {
            [pscustomobject][ordered]@{
                Name      = $w32Service.Name
                State     = $w32Service.State
                StartMode = $w32Service.StartMode
                StartName = $w32Service.StartName
                PathName  = $w32Service.PathName
                ProcessId = $w32Service.ProcessId
            }
        } else { $null }
        W32tmStatus        = Invoke-NativeReadOnly 'w32tm.exe' @('/query','/status','/verbose')
        W32tmConfiguration = Invoke-NativeReadOnly 'w32tm.exe' @('/query','/configuration')
        W32tmPeers         = Invoke-NativeReadOnly 'w32tm.exe' @('/query','/peers')
        TimeServiceRegistry = [pscustomobject][ordered]@{
            Parameters = Get-RegistryKeySnapshot 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
            NtpClient  = Get-RegistryKeySnapshot 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient'
            NtpServer  = Get-RegistryKeySnapshot 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer'
        }
    }
}

# -----------------------------------------------------------------------------
# 6 - OS, build, CPU, RAM, mainboard, GPU, updates
# -----------------------------------------------------------------------------
$systemInformation = Invoke-SafeCollection -Name 'SystemInformation' -ScriptBlock {
    $processors = @(Get-CimInstance Win32_Processor -ErrorAction Stop | ForEach-Object {
        [pscustomobject][ordered]@{
            DeviceId                  = $_.DeviceID
            Name                      = $_.Name
            Manufacturer              = $_.Manufacturer
            Architecture              = $_.Architecture
            AddressWidth              = $_.AddressWidth
            NumberOfCores             = $_.NumberOfCores
            NumberOfLogicalProcessors = $_.NumberOfLogicalProcessors
            MaxClockSpeedMHz          = $_.MaxClockSpeed
            CurrentClockSpeedMHz      = $_.CurrentClockSpeed
            ProcessorId               = $_.ProcessorId
            SocketDesignation         = $_.SocketDesignation
        }
    })

    $baseBoards = @(Get-CimInstance Win32_BaseBoard -ErrorAction Stop | ForEach-Object {
        [pscustomobject][ordered]@{
            Manufacturer = $_.Manufacturer
            Product      = $_.Product
            Version      = $_.Version
            SerialNumber = $_.SerialNumber
        }
    })

    $gpus = @(Get-CimInstance Win32_VideoController -ErrorAction Stop | ForEach-Object {
        [pscustomobject][ordered]@{
            Name                    = $_.Name
            AdapterCompatibility    = $_.AdapterCompatibility
            AdapterRAMBytes         = $_.AdapterRAM
            DriverVersion           = $_.DriverVersion
            DriverDate              = Convert-ToIso8601 $_.DriverDate
            VideoProcessor          = $_.VideoProcessor
            CurrentHorizontalResolution = $_.CurrentHorizontalResolution
            CurrentVerticalResolution   = $_.CurrentVerticalResolution
            CurrentRefreshRate      = $_.CurrentRefreshRate
            PNPDeviceID             = $_.PNPDeviceID
            Status                  = $_.Status
        }
    })

    $hotFixes = @(Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | ForEach-Object {
        [pscustomobject][ordered]@{
            HotFixID    = $_.HotFixID
            Description = $_.Description
            InstalledBy = $_.InstalledBy
            InstalledOn = Convert-ToIso8601 $_.InstalledOn
        }
    })

    $updateHistory = [ordered]@{
        Available         = $false
        TotalHistoryCount = $null
        ReturnedEntries   = 0
        MaxEntries        = 200
        Entries           = @()
        Error             = $null
    }
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $total = $searcher.GetTotalHistoryCount()
        $count = [Math]::Min([int]$total, 200)
        $history = if ($count -gt 0) { @($searcher.QueryHistory(0, $count)) } else { @() }
        $updateHistory.Available = $true
        $updateHistory.TotalHistoryCount = $total
        $updateHistory.ReturnedEntries = $history.Count
        $updateHistory.Entries = @($history | ForEach-Object {
            [pscustomobject][ordered]@{
                Date        = Convert-ToIso8601 $_.Date
                Title       = $_.Title
                Description = $_.Description
                Operation   = [string]$_.Operation
                ResultCode  = [string]$_.ResultCode
                HResult     = $_.HResult
                SupportUrl  = $_.SupportUrl
            }
        })
    }
    catch {
        $updateHistory.Error = $_.Exception.Message
    }

    [pscustomobject][ordered]@{
        OperatingSystem = [pscustomobject][ordered]@{
            Caption              = $operatingSystem.Caption
            Version              = $operatingSystem.Version
            BuildNumber          = $operatingSystem.BuildNumber
            OSArchitecture       = $operatingSystem.OSArchitecture
            ProductType          = $operatingSystem.ProductType
            InstallDate          = Convert-ToIso8601 $operatingSystem.InstallDate
            LastBootUpTime       = Convert-ToIso8601 $operatingSystem.LastBootUpTime
            UptimeSeconds        = [int64]((Get-Date) - $operatingSystem.LastBootUpTime).TotalSeconds
            SystemDrive          = $operatingSystem.SystemDrive
            WindowsDirectory     = $operatingSystem.WindowsDirectory
            SystemDirectory      = $operatingSystem.SystemDirectory
            Locale               = $operatingSystem.Locale
            MUILanguages         = @($operatingSystem.MUILanguages)
            FreePhysicalMemoryKB = $operatingSystem.FreePhysicalMemory
            TotalVisibleMemoryKB = $operatingSystem.TotalVisibleMemorySize
        }
        ComputerSystem = [pscustomobject][ordered]@{
            Manufacturer           = $computerSystem.Manufacturer
            Model                  = $computerSystem.Model
            SystemFamily           = $computerSystem.SystemFamily
            SystemSKUNumber        = $computerSystem.SystemSKUNumber
            TotalPhysicalMemoryBytes = [uint64]$computerSystem.TotalPhysicalMemory
            NumberOfProcessors     = $computerSystem.NumberOfProcessors
            NumberOfLogicalProcessors = $computerSystem.NumberOfLogicalProcessors
            HypervisorPresent      = $computerSystem.HypervisorPresent
        }
        CPU        = $processors
        Mainboard  = $baseBoards
        Graphics   = $gpus
        HotFixes   = $hotFixes
        WindowsUpdateHistory = $updateHistory
    }
}

# -----------------------------------------------------------------------------
# 7 - Disks, partitions, volumes
# -----------------------------------------------------------------------------
$storage = Invoke-SafeCollection -Name 'Storage' -ScriptBlock {
    $disks = @()
    if (Get-Command Get-Disk -ErrorAction SilentlyContinue) {
        $disks = @(Get-Disk -ErrorAction Stop | Sort-Object Number | ForEach-Object {
            [pscustomobject][ordered]@{
                Number              = $_.Number
                FriendlyName        = $_.FriendlyName
                SerialNumber        = $_.SerialNumber
                Manufacturer        = $_.Manufacturer
                Model               = $_.Model
                BusType             = [string]$_.BusType
                PartitionStyle      = [string]$_.PartitionStyle
                OperationalStatus   = @($_.OperationalStatus | ForEach-Object { [string]$_ })
                HealthStatus        = [string]$_.HealthStatus
                SizeBytes           = $_.Size
                AllocatedSizeBytes  = $_.AllocatedSize
                LargestFreeExtentBytes = $_.LargestFreeExtent
                IsBoot              = $_.IsBoot
                IsSystem            = $_.IsSystem
                IsOffline           = $_.IsOffline
                IsReadOnly          = $_.IsReadOnly
                LogicalSectorSize   = $_.LogicalSectorSize
                PhysicalSectorSize  = $_.PhysicalSectorSize
            }
        })
    }

    $partitions = @()
    if (Get-Command Get-Partition -ErrorAction SilentlyContinue) {
        $partitions = @(Get-Partition -ErrorAction Stop | Sort-Object DiskNumber, PartitionNumber | ForEach-Object {
            [pscustomobject][ordered]@{
                DiskNumber      = $_.DiskNumber
                PartitionNumber = $_.PartitionNumber
                DriveLetter     = if ($_.DriveLetter) { [string]$_.DriveLetter } else { $null }
                Type            = [string]$_.Type
                SizeBytes       = $_.Size
                OffsetBytes     = $_.Offset
                IsActive        = $_.IsActive
                IsBoot          = $_.IsBoot
                IsSystem        = $_.IsSystem
                IsHidden        = $_.IsHidden
                IsReadOnly      = $_.IsReadOnly
                GptType         = [string]$_.GptType
                MbrType         = [string]$_.MbrType
                AccessPaths     = @($_.AccessPaths)
            }
        })
    }

    $volumes = @()
    if (Get-Command Get-Volume -ErrorAction SilentlyContinue) {
        $volumes = @(Get-Volume -ErrorAction Stop | Sort-Object DriveLetter, FileSystemLabel | ForEach-Object {
            [pscustomobject][ordered]@{
                DriveLetter      = if ($_.DriveLetter) { [string]$_.DriveLetter } else { $null }
                FileSystemLabel  = $_.FileSystemLabel
                FileSystem       = $_.FileSystem
                DriveType        = [string]$_.DriveType
                HealthStatus     = [string]$_.HealthStatus
                OperationalStatus = @($_.OperationalStatus | ForEach-Object { [string]$_ })
                SizeBytes        = $_.Size
                SizeRemainingBytes = $_.SizeRemaining
                Path             = $_.Path
                AllocationUnitSize = $_.AllocationUnitSize
            }
        })
    }

    [pscustomobject][ordered]@{
        Disks      = $disks
        Partitions = $partitions
        Volumes    = $volumes
    }
}

# -----------------------------------------------------------------------------
# 8 / 9 - Local users + groups + memberships
# -----------------------------------------------------------------------------
$localAccounts = Invoke-SafeCollection -Name 'LocalAccounts' -ScriptBlock {
    Get-LocalAccountsSnapshot
}

# -----------------------------------------------------------------------------
# 10 - Complete network-adapter snapshot
# -----------------------------------------------------------------------------
$networkAdapters = Invoke-SafeCollection -Name 'NetworkAdapters' -ScriptBlock {
    $adapterConfigurations = @(Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue)
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Sort-Object ifIndex, Name)

    @($adapters | ForEach-Object {
        $adapter = $_
        $ifIndex = $adapter.ifIndex
        $cimConfig = @($adapterConfigurations | Where-Object { $_.InterfaceIndex -eq $ifIndex } | Select-Object -First 1)

        $addresses = @(Get-NetIPAddress -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject][ordered]@{
                AddressFamily = [string]$_.AddressFamily
                IPAddress     = $_.IPAddress
                PrefixLength  = $_.PrefixLength
                PrefixOrigin  = [string]$_.PrefixOrigin
                SuffixOrigin  = [string]$_.SuffixOrigin
                AddressState  = [string]$_.AddressState
                SkipAsSource  = $_.SkipAsSource
            }
        })

        $dnsServers = @(Get-DnsClientServerAddress -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject][ordered]@{
                AddressFamily = [string]$_.AddressFamily
                ServerAddresses = @($_.ServerAddresses)
            }
        })

        $dnsClient = @(Get-DnsClient -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue | Select-Object -First 1)

        $routes = @(Get-NetRoute -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue |
            Sort-Object AddressFamily, DestinationPrefix, RouteMetric |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    AddressFamily    = [string]$_.AddressFamily
                    DestinationPrefix = $_.DestinationPrefix
                    NextHop          = $_.NextHop
                    RouteMetric      = $_.RouteMetric
                    Protocol         = [string]$_.Protocol
                    Publish          = [string]$_.Publish
                    State            = [string]$_.State
                    Store            = [string]$_.Store
                }
            })

        $bindings = @(Get-NetAdapterBinding -Name $adapter.Name -AllBindings -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject][ordered]@{
                DisplayName = $_.DisplayName
                ComponentID = $_.ComponentID
                Enabled     = $_.Enabled
            }
        })

        $advancedProperties = @(Get-NetAdapterAdvancedProperty -Name $adapter.Name -AllProperties -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject][ordered]@{
                DisplayName     = $_.DisplayName
                DisplayValue    = $_.DisplayValue
                RegistryKeyword = $_.RegistryKeyword
                RegistryValue   = @($_.RegistryValue)
            }
        })

        $profiles = @(Get-NetConnectionProfile -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject][ordered]@{
                Name             = $_.Name
                InterfaceAlias   = $_.InterfaceAlias
                NetworkCategory  = [string]$_.NetworkCategory
                IPv4Connectivity = [string]$_.IPv4Connectivity
                IPv6Connectivity = [string]$_.IPv6Connectivity
            }
        })

        $ipInterfaces = @(Get-NetIPInterface -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject][ordered]@{
                AddressFamily          = [string]$_.AddressFamily
                Dhcp                   = [string]$_.Dhcp
                ConnectionState        = [string]$_.ConnectionState
                NlMtuBytes             = $_.NlMtu
                InterfaceMetric        = $_.InterfaceMetric
                AutomaticMetric        = [string]$_.AutomaticMetric
                Forwarding             = [string]$_.Forwarding
                WeakHostSend           = [string]$_.WeakHostSend
                WeakHostReceive        = [string]$_.WeakHostReceive
                Advertising            = [string]$_.Advertising
                RouterDiscovery        = [string]$_.RouterDiscovery
            }
        })

        $powerManagement = $null
        if (Get-Command Get-NetAdapterPowerManagement -ErrorAction SilentlyContinue) {
            try {
                $pm = Get-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction Stop
                $powerManagement = [pscustomobject][ordered]@{
                    AllowComputerToTurnOffDevice = [string]$pm.AllowComputerToTurnOffDevice
                    D0PacketCoalescing           = [string]$pm.D0PacketCoalescing
                    DeviceSleepOnDisconnect      = [string]$pm.DeviceSleepOnDisconnect
                    ArpOffload                   = [string]$pm.ArpOffload
                    NSOffload                    = [string]$pm.NSOffload
                    RsnRekeyOffload              = [string]$pm.RsnRekeyOffload
                    SelectiveSuspend             = [string]$pm.SelectiveSuspend
                    WakeOnMagicPacket            = [string]$pm.WakeOnMagicPacket
                    WakeOnPattern                = [string]$pm.WakeOnPattern
                }
            }
            catch { }
        }

        [pscustomobject][ordered]@{
            Name                  = $adapter.Name
            InterfaceDescription  = $adapter.InterfaceDescription
            InterfaceIndex        = $ifIndex
            InterfaceGuid         = [string]$adapter.InterfaceGuid
            Status                = [string]$adapter.Status
            MediaConnectionState  = [string]$adapter.MediaConnectionState
            MacAddress            = $adapter.MacAddress
            LinkSpeed             = [string]$adapter.LinkSpeed
            MediaType             = [string]$adapter.MediaType
            PhysicalMediaType     = [string]$adapter.PhysicalMediaType
            Virtual               = $adapter.Virtual
            HardwareInterface     = $adapter.HardwareInterface
            ConnectorPresent      = $adapter.ConnectorPresent
            DriverInformation     = $adapter.DriverInformation
            DriverFileName        = $adapter.DriverFileName
            DriverVersion         = $adapter.DriverVersion
            DriverDate            = Convert-ToIso8601 $adapter.DriverDate
            PnPDeviceID           = $adapter.PnPDeviceID
            IPAddresses           = $addresses
            DnsServers            = $dnsServers
            DnsClient             = if ($dnsClient.Count -gt 0) {
                [pscustomobject][ordered]@{
                    ConnectionSpecificSuffix = $dnsClient[0].ConnectionSpecificSuffix
                    RegisterThisConnectionsAddress = $dnsClient[0].RegisterThisConnectionsAddress
                    UseSuffixWhenRegistering = $dnsClient[0].UseSuffixWhenRegistering
                }
            } else { $null }
            Gateway = if ($cimConfig.Count -gt 0) { @($cimConfig[0].DefaultIPGateway) } else { @() }
            DHCP = if ($cimConfig.Count -gt 0) {
                [pscustomobject][ordered]@{
                    DHCPEnabled     = $cimConfig[0].DHCPEnabled
                    DHCPServer      = $cimConfig[0].DHCPServer
                    DHCPLeaseObtained = Convert-ToIso8601 $cimConfig[0].DHCPLeaseObtained
                    DHCPLeaseExpires  = Convert-ToIso8601 $cimConfig[0].DHCPLeaseExpires
                }
            } else { $null }
            WINS = if ($cimConfig.Count -gt 0) {
                [pscustomobject][ordered]@{
                    PrimaryServer          = $cimConfig[0].WINSPrimaryServer
                    SecondaryServer        = $cimConfig[0].WINSSecondaryServer
                    EnableLMHostsLookup    = $cimConfig[0].WINSEnableLMHostsLookup
                    EnableDNS              = $cimConfig[0].DNSEnabledForWINSResolution
                    TcpipNetbiosOptions     = $cimConfig[0].TcpipNetbiosOptions
                }
            } else { $null }
            DnsDomain = if ($cimConfig.Count -gt 0) { $cimConfig[0].DNSDomain } else { $null }
            DnsDomainSuffixSearchOrder = if ($cimConfig.Count -gt 0) { @($cimConfig[0].DNSDomainSuffixSearchOrder) } else { @() }
            IPInterfaces          = $ipInterfaces
            Routes                = $routes
            Bindings              = $bindings
            AdvancedProperties    = $advancedProperties
            NetworkProfiles       = $profiles
            PowerManagement       = $powerManagement
        }
    })
}

# -----------------------------------------------------------------------------
# 11 / 12 / 13 / 14 - Domain membership, computer DN and OU
# -----------------------------------------------------------------------------
$domainInformation = Invoke-SafeCollection -Name 'DomainInformation' -ScriptBlock {
    $computerDn = $null
    $parentDn = $null
    $computerOu = $null
    $organizationalUnits = @()
    $directoryError = $null
    $defaultNamingContext = $null
    $dnSource = $null

    if ($computerSystem.PartOfDomain) {
        # Preferred source: locally cached Group Policy state. This avoids a WinRM/NTLM second hop.
        try {
            $gpStatePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine'
            if (Test-Path -LiteralPath $gpStatePath) {
                $gpState = Get-ItemProperty -LiteralPath $gpStatePath -ErrorAction Stop
                $cachedDn = $gpState.'Distinguished-Name'
                if (-not [string]::IsNullOrWhiteSpace([string]$cachedDn)) {
                    $computerDn = [string]$cachedDn
                    $dnSource = 'Local Group Policy state registry'
                }
            }
        }
        catch { }

        # Fallback: LDAP lookup. May fail with NTLM remoting due to the second-hop limitation.
        if ([string]::IsNullOrWhiteSpace($computerDn)) {
            try {
                $rootDse = [ADSI]'LDAP://RootDSE'
                $defaultNamingContext = [string]$rootDse.defaultNamingContext
                $domainRoot = [ADSI]("LDAP://{0}" -f $defaultNamingContext)
                $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainRoot)
                $searcher.Filter = '(&(objectCategory=computer)(sAMAccountName=' + $computerName + '$))'
                [void]$searcher.PropertiesToLoad.Add('distinguishedName')
                $searcher.PageSize = 1000
                $match = $searcher.FindOne()
                if ($match -and $match.Properties['distinguishedname'].Count -gt 0) {
                    $computerDn = [string]$match.Properties['distinguishedname'][0]
                    $dnSource = 'LDAP'
                }
            }
            catch {
                $directoryError = $_.Exception.Message
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($computerDn) -and $computerDn -match '^[^,]+,(.+)$') {
            $parentDn = $Matches[1]
            $organizationalUnits = @([regex]::Matches($parentDn, '(?i)(?:^|,)OU=([^,]+)') | ForEach-Object { $_.Groups[1].Value })
            if ($organizationalUnits.Count -gt 0) {
                $computerOu = $parentDn
            }
        }
    }

    [pscustomobject][ordered]@{
        PartOfDomain          = $computerSystem.PartOfDomain
        Domain                = $computerSystem.Domain
        Workgroup             = if (-not $computerSystem.PartOfDomain) { $computerSystem.Workgroup } else { $null }
        DomainRole            = $computerSystem.DomainRole
        ComputerAccountDN     = $computerDn
        ComputerAccountParentDN = $parentDn
        ComputerAccountOU     = $computerOu
        OrganizationalUnits   = $organizationalUnits
        DistinguishedNameSource = $dnSource
        DefaultNamingContext  = $defaultNamingContext
        DirectoryLookupError  = $directoryError
    }
}

# -----------------------------------------------------------------------------
# 15 - BIOS
# -----------------------------------------------------------------------------
$biosInformation = Invoke-SafeCollection -Name 'BIOS' -ScriptBlock {
    $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop
    [pscustomobject][ordered]@{
        Manufacturer        = $bios.Manufacturer
        Name                = $bios.Name
        Version             = $bios.Version
        SMBIOSBIOSVersion   = $bios.SMBIOSBIOSVersion
        SMBIOSMajorVersion  = $bios.SMBIOSMajorVersion
        SMBIOSMinorVersion  = $bios.SMBIOSMinorVersion
        SerialNumber        = $bios.SerialNumber
        ReleaseDate         = Convert-ToIso8601 $bios.ReleaseDate
        PrimaryBIOS         = $bios.PrimaryBIOS
        Status              = $bios.Status
        BIOSCharacteristics = @($bios.BiosCharacteristics)
    }
}

# -----------------------------------------------------------------------------
# 16 - Windows Defender Firewall
# -----------------------------------------------------------------------------
$firewall = Invoke-SafeCollection -Name 'WindowsDefenderFirewall' -ScriptBlock {
    $service = Get-CimInstance Win32_Service -Filter "Name='MpsSvc'" -ErrorAction SilentlyContinue
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
        [pscustomobject][ordered]@{
            Name                  = $_.Name
            Enabled               = $_.Enabled
            DefaultInboundAction  = [string]$_.DefaultInboundAction
            DefaultOutboundAction = [string]$_.DefaultOutboundAction
            AllowInboundRules     = [string]$_.AllowInboundRules
            AllowLocalFirewallRules = [string]$_.AllowLocalFirewallRules
            AllowLocalIPsecRules  = [string]$_.AllowLocalIPsecRules
            NotifyOnListen        = $_.NotifyOnListen
            LogFileName           = $_.LogFileName
            LogMaxSizeKilobytes   = $_.LogMaxSizeKilobytes
            LogAllowed            = $_.LogAllowed
            LogBlocked            = $_.LogBlocked
        }
    })

    $networkProfiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject][ordered]@{
            Name             = $_.Name
            InterfaceAlias   = $_.InterfaceAlias
            InterfaceIndex   = $_.InterfaceIndex
            NetworkCategory  = [string]$_.NetworkCategory
            IPv4Connectivity = [string]$_.IPv4Connectivity
            IPv6Connectivity = [string]$_.IPv6Connectivity
        }
    })

    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)
    $ruleSummary = [pscustomobject][ordered]@{
        Total      = $rules.Count
        Enabled    = @($rules | Where-Object { $_.Enabled -eq 'True' }).Count
        Disabled   = @($rules | Where-Object { $_.Enabled -ne 'True' }).Count
        ByDirection = @($rules | Group-Object Direction | Sort-Object Name | ForEach-Object {
            [pscustomobject]@{ Direction = $_.Name; Count = $_.Count }
        })
        ByAction = @($rules | Group-Object Action | Sort-Object Name | ForEach-Object {
            [pscustomobject]@{ Action = $_.Name; Count = $_.Count }
        })
        ByProfile = @($rules | Group-Object { [string]$_.Profile } | Sort-Object Name | ForEach-Object {
            [pscustomobject]@{ Profile = $_.Name; Count = $_.Count }
        })
    }

    $dlls = @()
    foreach ($dllPath in @(
        (Join-Path $env:SystemRoot 'System32\FirewallAPI.dll'),
        (Join-Path $env:SystemRoot 'System32\mpssvc.dll')
    )) {
        if (Test-Path $dllPath) {
            $vi = (Get-Item $dllPath -ErrorAction Stop).VersionInfo
            $dlls += [pscustomobject][ordered]@{
                Path           = $dllPath
                FileVersion    = $vi.FileVersion
                ProductVersion = $vi.ProductVersion
            }
        }
    }

    [pscustomobject][ordered]@{
        Service = if ($service) {
            [pscustomobject][ordered]@{
                Name      = $service.Name
                DisplayName = $service.DisplayName
                State     = $service.State
                StartMode = $service.StartMode
                StartName = $service.StartName
                PathName  = $service.PathName
                ProcessId = $service.ProcessId
            }
        } else { $null }
        Profiles               = $profiles
        ActiveNetworkProfiles  = $networkProfiles
        RuleSummary            = $ruleSummary
        FirewallDllVersions    = $dlls
    }
}

# -----------------------------------------------------------------------------
# 17 - Microsoft Defender
# -----------------------------------------------------------------------------
$defender = Invoke-SafeCollection -Name 'MicrosoftDefender' -ScriptBlock {
    $status = $null
    $preferences = $null
    $statusError = $null
    $preferencesError = $null

    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try { $status = Get-MpComputerStatus -ErrorAction Stop } catch { $statusError = $_.Exception.Message }
    }
    if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
        try { $preferences = Get-MpPreference -ErrorAction Stop } catch { $preferencesError = $_.Exception.Message }
    }

    $defenderServiceNames = @('WinDefend','WdNisSvc','Sense','SecurityHealthService')
    $defenderServices = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $defenderServiceNames -contains $_.Name } |
        Sort-Object Name |
        ForEach-Object {
            [pscustomobject][ordered]@{
                Name      = $_.Name
                DisplayName = $_.DisplayName
                State     = $_.State
                StartMode = $_.StartMode
                StartName = $_.StartName
                PathName  = $_.PathName
                ProcessId = $_.ProcessId
            }
        })

    [pscustomobject][ordered]@{
        Available = [bool](Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)
        StatusError = $statusError
        PreferenceError = $preferencesError
        ComputerStatus = if ($status) {
            [pscustomobject][ordered]@{
                AMServiceEnabled              = $status.AMServiceEnabled
                AMServiceVersion              = $status.AMServiceVersion
                AntivirusEnabled              = $status.AntivirusEnabled
                AntispywareEnabled            = $status.AntispywareEnabled
                BehaviorMonitorEnabled        = $status.BehaviorMonitorEnabled
                IoavProtectionEnabled         = $status.IoavProtectionEnabled
                NISEnabled                    = $status.NISEnabled
                OnAccessProtectionEnabled     = $status.OnAccessProtectionEnabled
                RealTimeProtectionEnabled     = $status.RealTimeProtectionEnabled
                IsTamperProtected             = $status.IsTamperProtected
                AntivirusSignatureVersion     = $status.AntivirusSignatureVersion
                AntivirusSignatureAge         = $status.AntivirusSignatureAge
                AntivirusSignatureLastUpdated = Convert-ToIso8601 $status.AntivirusSignatureLastUpdated
                AntispywareSignatureVersion   = $status.AntispywareSignatureVersion
                AntispywareSignatureAge       = $status.AntispywareSignatureAge
                AntispywareSignatureLastUpdated = Convert-ToIso8601 $status.AntispywareSignatureLastUpdated
                NISSignatureVersion            = $status.NISSignatureVersion
                NISSignatureAge                = $status.NISSignatureAge
                NISSignatureLastUpdated        = Convert-ToIso8601 $status.NISSignatureLastUpdated
                QuickScanAge                  = $status.QuickScanAge
                QuickScanStartTime            = Convert-ToIso8601 $status.QuickScanStartTime
                QuickScanEndTime              = Convert-ToIso8601 $status.QuickScanEndTime
                FullScanAge                   = $status.FullScanAge
                FullScanStartTime             = Convert-ToIso8601 $status.FullScanStartTime
                FullScanEndTime               = Convert-ToIso8601 $status.FullScanEndTime
                RebootRequired                = $status.RebootRequired
                ComputerState                 = $status.ComputerState
            }
        } else { $null }
        Preferences = if ($preferences) {
            [pscustomobject][ordered]@{
                DisableRealtimeMonitoring       = $preferences.DisableRealtimeMonitoring
                DisableBehaviorMonitoring       = $preferences.DisableBehaviorMonitoring
                DisableIOAVProtection            = $preferences.DisableIOAVProtection
                DisableScriptScanning            = $preferences.DisableScriptScanning
                DisableArchiveScanning           = $preferences.DisableArchiveScanning
                DisableEmailScanning             = $preferences.DisableEmailScanning
                DisableRemovableDriveScanning    = $preferences.DisableRemovableDriveScanning
                DisableScanningMappedNetworkDrivesForFullScan = $preferences.DisableScanningMappedNetworkDrivesForFullScan
                DisableScanningNetworkFiles      = $preferences.DisableScanningNetworkFiles
                PUAProtection                    = $preferences.PUAProtection
                MAPSReporting                    = $preferences.MAPSReporting
                SubmitSamplesConsent             = $preferences.SubmitSamplesConsent
                SignatureUpdateInterval          = $preferences.SignatureUpdateInterval
                ExclusionPath                    = @($preferences.ExclusionPath)
                ExclusionExtension               = @($preferences.ExclusionExtension)
                ExclusionProcess                 = @($preferences.ExclusionProcess)
                ExclusionIpAddress               = @($preferences.ExclusionIpAddress)
            }
        } else { $null }
        Services = $defenderServices
        Policies = [pscustomobject][ordered]@{
            Main            = Get-RegistryKeySnapshot 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
            RealTimeProtection = Get-RegistryKeySnapshot 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
            Spynet          = Get-RegistryKeySnapshot 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
            SignatureUpdates = Get-RegistryKeySnapshot 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates'
            Exclusions      = Get-RegistryTreeSnapshot 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions' -MaxDepth 2
        }
    }
}

# -----------------------------------------------------------------------------
# 18 - Installed programs (registry only; deliberately no Win32_Product)
# -----------------------------------------------------------------------------
$installedPrograms = Invoke-SafeCollection -Name 'InstalledPrograms' -ScriptBlock {
    $locations = @(
        [pscustomobject]@{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; Scope = 'LocalMachine'; Architecture = '64-bit/native' },
        [pscustomobject]@{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; Scope = 'LocalMachine'; Architecture = '32-bit' },
        [pscustomobject]@{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; Scope = 'CurrentUser'; Architecture = 'CurrentUser' }
    )

    $programs = @()
    foreach ($location in $locations) {
        foreach ($entry in @(Get-ItemProperty -Path $location.Path -ErrorAction SilentlyContinue)) {
            if ([string]::IsNullOrWhiteSpace([string]$entry.DisplayName)) { continue }
            $programs += [pscustomobject][ordered]@{
                DisplayName     = $entry.DisplayName
                DisplayVersion  = $entry.DisplayVersion
                Publisher       = $entry.Publisher
                InstallDate     = $entry.InstallDate
                InstallLocation = $entry.InstallLocation
                InstallSource   = $entry.InstallSource
                WindowsInstaller = $entry.WindowsInstaller
                SystemComponent = $entry.SystemComponent
                ReleaseType     = $entry.ReleaseType
                ParentDisplayName = $entry.ParentDisplayName
                Scope           = $location.Scope
                Architecture    = $location.Architecture
                RegistryKey     = $entry.PSChildName
            }
        }
    }

    @($programs | Sort-Object DisplayName, DisplayVersion, Scope, Architecture)
}

# -----------------------------------------------------------------------------
# 19 / 20 - Optional features, capabilities, server roles
# -----------------------------------------------------------------------------
$windowsComponents = Invoke-SafeCollection -Name 'WindowsComponents' -ScriptBlock {
    $optionalFeatures = @()
    if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
        $optionalFeatures = @(Get-WindowsOptionalFeature -Online -ErrorAction Stop | Sort-Object FeatureName | ForEach-Object {
            [pscustomobject][ordered]@{
                FeatureName     = $_.FeatureName
                State           = [string]$_.State
                RestartRequired = $_.RestartRequired
            }
        })
    }

    $capabilities = @()
    if (Get-Command Get-WindowsCapability -ErrorAction SilentlyContinue) {
        try {
            $capabilities = @(Get-WindowsCapability -Online -ErrorAction Stop | Sort-Object Name | ForEach-Object {
                [pscustomobject][ordered]@{
                    Name        = $_.Name
                    State       = [string]$_.State
                    DisplayName = $_.DisplayName
                    Description = $_.Description
                    DownloadSize = $_.DownloadSize
                    InstallSize  = $_.InstallSize
                }
            })
        }
        catch {
            $capabilities = @([pscustomobject][ordered]@{ Error = $_.Exception.Message })
        }
    }

    $serverRoles = [ordered]@{
        Available = $false
        Features  = @()
        Error     = $null
    }
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        try {
            $serverRoles.Available = $true
            $serverRoles.Features = @(Get-WindowsFeature -ErrorAction Stop | Sort-Object Name | ForEach-Object {
                [pscustomobject][ordered]@{
                    Name         = $_.Name
                    DisplayName  = $_.DisplayName
                    Installed    = $_.Installed
                    InstallState = [string]$_.InstallState
                    FeatureType  = [string]$_.FeatureType
                    Parent       = $_.Parent
                    Depth        = $_.Depth
                }
            })
        }
        catch {
            $serverRoles.Error = $_.Exception.Message
        }
    }

    [pscustomobject][ordered]@{
        OptionalFeatures = $optionalFeatures
        WindowsCapabilities = $capabilities
        ServerRolesAndFeatures = $serverRoles
    }
}

# -----------------------------------------------------------------------------
# 21 - AppX packages + provisioned packages
# -----------------------------------------------------------------------------
$appxPackages = Invoke-SafeCollection -Name 'AppXPackages' -ScriptBlock {
    $result = [ordered]@{
        CurrentUser = @()
        AllUsers = @()
        Provisioned = @()
        Errors = @()
    }

    if (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue) {
        try {
            $result.CurrentUser = @(Get-AppxPackage -ErrorAction Stop | Sort-Object Name, Version | ForEach-Object {
                [pscustomobject][ordered]@{
                    Name              = $_.Name
                    PackageFullName   = $_.PackageFullName
                    PackageFamilyName = $_.PackageFamilyName
                    Version           = [string]$_.Version
                    Publisher         = $_.Publisher
                    Architecture      = [string]$_.Architecture
                    InstallLocation   = $_.InstallLocation
                    IsFramework       = $_.IsFramework
                    NonRemovable      = $_.NonRemovable
                    SignatureKind     = [string]$_.SignatureKind
                    Status            = [string]$_.Status
                }
            })
        }
        catch { $result.Errors += 'CurrentUser: ' + $_.Exception.Message }

        try {
            $result.AllUsers = @(Get-AppxPackage -AllUsers -ErrorAction Stop | Sort-Object Name, Version | ForEach-Object {
                [pscustomobject][ordered]@{
                    Name              = $_.Name
                    PackageFullName   = $_.PackageFullName
                    PackageFamilyName = $_.PackageFamilyName
                    Version           = [string]$_.Version
                    Publisher         = $_.Publisher
                    Architecture      = [string]$_.Architecture
                    InstallLocation   = $_.InstallLocation
                    IsFramework       = $_.IsFramework
                    NonRemovable      = $_.NonRemovable
                    SignatureKind     = [string]$_.SignatureKind
                    Status            = [string]$_.Status
                }
            })
        }
        catch { $result.Errors += 'AllUsers: ' + $_.Exception.Message }
    }

    if (Get-Command Get-AppxProvisionedPackage -ErrorAction SilentlyContinue) {
        try {
            $result.Provisioned = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop | Sort-Object DisplayName, Version | ForEach-Object {
                [pscustomobject][ordered]@{
                    DisplayName  = $_.DisplayName
                    PackageName  = $_.PackageName
                    Version      = [string]$_.Version
                    Architecture = [string]$_.Architecture
                    ResourceId   = $_.ResourceId
                    InstallLocation = $_.InstallLocation
                }
            })
        }
        catch { $result.Errors += 'Provisioned: ' + $_.Exception.Message }
    }

    [pscustomobject]$result
}

# -----------------------------------------------------------------------------
# 22 - Certificates from LocalMachine and the WinRM current user account
# -----------------------------------------------------------------------------
$certificates = Invoke-SafeCollection -Name 'Certificates' -ScriptBlock {
    [pscustomobject][ordered]@{
        CurrentUserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        LocalMachine        = Get-CertificateSnapshot -RootPath 'Cert:\LocalMachine'
        CurrentUser         = Get-CertificateSnapshot -RootPath 'Cert:\CurrentUser'
        Note                = 'Private key material is never exported. HasPrivateKey only indicates presence.'
    }
}

# -----------------------------------------------------------------------------
# 23 - All services
# -----------------------------------------------------------------------------
$services = Invoke-SafeCollection -Name 'Services' -ScriptBlock {
    @(Get-CimInstance Win32_Service -ErrorAction Stop | Sort-Object Name | ForEach-Object {
        $svc = $_
        $delayedAutoStart = $false
        try {
            $reg = Get-ItemProperty -LiteralPath ("HKLM:\SYSTEM\CurrentControlSet\Services\{0}" -f $svc.Name) -Name DelayedAutoStart -ErrorAction Stop
            $delayedAutoStart = ([int]$reg.DelayedAutoStart -eq 1)
        }
        catch { }

        $classification = switch ($svc.StartMode) {
            'Auto' {
                if ($delayedAutoStart) { 'Automatisch (verzoegert)' } else { 'Automatisch' }
            }
            'Manual'   { 'Manuell' }
            'Disabled' { 'Deaktiviert' }
            default    { [string]$svc.StartMode }
        }

        [pscustomobject][ordered]@{
            Name             = $svc.Name
            DisplayName      = $svc.DisplayName
            Description      = $svc.Description
            State            = $svc.State
            Status           = $svc.Status
            Started          = $svc.Started
            StartMode        = $svc.StartMode
            StartClassification = $classification
            DelayedAutoStart = $delayedAutoStart
            ServiceAccount   = $svc.StartName
            PathName         = $svc.PathName
            ProcessId        = $svc.ProcessId
            ServiceType      = $svc.ServiceType
            DesktopInteract  = $svc.DesktopInteract
            ExitCode         = $svc.ExitCode
            SystemName       = $svc.SystemName
        }
    })
}

# -----------------------------------------------------------------------------
# Additional best-practice installation checks (read-only)
# -----------------------------------------------------------------------------
$installationBestPractice = Invoke-SafeCollection -Name 'InstallationBestPractice' -ScriptBlock {
    $activation = @()
    try {
        $activation = @(Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey IS NOT NULL" -ErrorAction Stop |
            Where-Object { $_.Name -like 'Windows*' } |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    Name              = $_.Name
                    Description       = $_.Description
                    LicenseStatus     = $_.LicenseStatus
                    LicenseStatusReason = $_.LicenseStatusReason
                    PartialProductKey = $_.PartialProductKey
                    GracePeriodRemainingMinutes = $_.GracePeriodRemaining
                }
            })
    }
    catch { }

    $secureBoot = [ordered]@{
        Supported = $null
        Enabled   = $null
        Error     = $null
    }
    if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
        try {
            $secureBoot.Enabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
            $secureBoot.Supported = $true
        }
        catch {
            $secureBoot.Error = $_.Exception.Message
            if ($_.Exception.Message -match 'not supported|Cmdlet not supported') {
                $secureBoot.Supported = $false
            }
        }
    }

    $tpm = $null
    if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
        try {
            $t = Get-Tpm -ErrorAction Stop
            $tpm = [pscustomobject][ordered]@{
                TpmPresent          = $t.TpmPresent
                TpmReady            = $t.TpmReady
                TpmEnabled          = $t.TpmEnabled
                TpmActivated        = $t.TpmActivated
                TpmOwned            = $t.TpmOwned
                RestartPending      = $t.RestartPending
                ManufacturerIdTxt   = $t.ManufacturerIdTxt
                ManufacturerVersion = $t.ManufacturerVersion
                ManagedAuthLevel    = [string]$t.ManagedAuthLevel
                AutoProvisioning    = [string]$t.AutoProvisioning
                LockedOut           = $t.LockedOut
            }
        }
        catch { }
    }

    $bitLocker = @()
    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        try {
            $bitLocker = @(Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    MountPoint           = $_.MountPoint
                    VolumeType           = [string]$_.VolumeType
                    CapacityGB           = $_.CapacityGB
                    VolumeStatus         = [string]$_.VolumeStatus
                    EncryptionPercentage = $_.EncryptionPercentage
                    KeyProtectorTypes    = @($_.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType })
                    LockStatus           = [string]$_.LockStatus
                    ProtectionStatus     = [string]$_.ProtectionStatus
                    EncryptionMethod     = [string]$_.EncryptionMethod
                    AutoUnlockEnabled    = $_.AutoUnlockEnabled
                }
            })
        }
        catch { }
    }

    $powerPlan = $null
    try {
        $powerPlan = Get-CimInstance -Namespace root\cimv2\power -ClassName Win32_PowerPlan -Filter "IsActive=True" -ErrorAction Stop |
            Select-Object -First 1 |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    ElementName  = $_.ElementName
                    InstanceID   = $_.InstanceID
                    IsActive     = $_.IsActive
                }
            }
    }
    catch { }

    $problemDevices = @()
    try {
        $problemDevices = @(Get-CimInstance Win32_PnPEntity -ErrorAction Stop |
            Where-Object { ($null -ne $_.ConfigManagerErrorCode) -and ($_.ConfigManagerErrorCode -ne 0) } |
            Sort-Object ConfigManagerErrorCode, Name |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    Name                   = $_.Name
                    PNPDeviceID            = $_.PNPDeviceID
                    Manufacturer           = $_.Manufacturer
                    Service                = $_.Service
                    Status                 = $_.Status
                    ConfigManagerErrorCode = $_.ConfigManagerErrorCode
                }
            })
    }
    catch { }

    $pageFiles = @(Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject][ordered]@{
            Name                 = $_.Name
            AllocatedBaseSizeMB  = $_.AllocatedBaseSize
            CurrentUsageMB       = $_.CurrentUsage
            PeakUsageMB          = $_.PeakUsage
            TempPageFile         = $_.TempPageFile
        }
    })

    [pscustomobject][ordered]@{
        WindowsActivation = $activation
        PendingReboot     = Get-PendingRebootSnapshot
        SecureBoot        = [pscustomobject]$secureBoot
        TPM               = $tpm
        BitLocker         = $bitLocker
        ActivePowerPlan   = $powerPlan
        PageFiles         = $pageFiles
        DevicesWithErrors = $problemDevices
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
        ScriptName          = 'Initial_Valid.ps1'
        ValidationType      = 'Initial_Valid'
        OverallStatus       = $overallStatus
        TargetIPAddress     = $targetIp
        ComputerName        = $computerName
        DNSName             = $fqdn
        TimestampLocal      = $script:StartTime.ToString('o')
        TimestampUtc        = $script:StartTime.ToUniversalTime().ToString('o')
        CompletedTimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        DurationMs          = [int64]$script:Stopwatch.ElapsedMilliseconds
        PowerShellVersion   = $PSVersionTable.PSVersion.ToString()
        PowerShellEdition   = if ($PSVersionTable.PSObject.Properties.Name -contains 'PSEdition') { $PSVersionTable.PSEdition } else { 'Desktop' }
        ProcessArchitecture = if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' }
        OSArchitecture      = if ([Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' }
        RemoteUser          = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        ResultFileName      = $resultFileName
        ReadOnlyCollection  = $true
        ErrorSections       = $errorSections
    }
    Identity                  = $identity
    IPAddresses               = $ipAddresses
    LanguageAndRegion         = $languageAndRegion
    TimeConfiguration         = $timeConfiguration
    SystemInformation         = $systemInformation
    Storage                   = $storage
    LocalUsers                = if ($localAccounts) { $localAccounts.Users } else { $null }
    LocalGroups               = if ($localAccounts) { $localAccounts.Groups } else { $null }
    LocalAccountSource        = if ($localAccounts) { $localAccounts.Source } else { $null }
    NetworkAdapters           = $networkAdapters
    DomainInformation         = $domainInformation
    BIOS                      = $biosInformation
    WindowsDefenderFirewall   = $firewall
    MicrosoftDefender         = $defender
    InstalledPrograms         = $installedPrograms
    WindowsComponents         = $windowsComponents
    AppXPackages              = $appxPackages
    Certificates              = $certificates
    Services                  = $services
    InstallationBestPractice  = $installationBestPractice
    CollectionStatus          = $script:CollectionStatus
}

try {
    $json = $result | ConvertTo-Json -Depth 20
    [System.IO.File]::WriteAllText($resultFilePath, $json, (New-Object System.Text.UTF8Encoding($false)))
}
catch {
    Write-Error ("JSON result could not be written to '{0}': {1}" -f $resultFilePath, $_.Exception.Message)
    exit 1
}

# Keep stdout small; Ansible only needs the JSON file itself.
Write-Output $resultFilePath
exit 0