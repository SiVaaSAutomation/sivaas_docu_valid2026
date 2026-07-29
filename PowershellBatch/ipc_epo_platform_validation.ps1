[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    [Parameter(Mandatory = $true)]
    [string]$ResultJsonPath
)

$ErrorActionPreference = 'Stop'

function Convert-ToArray {
    param([object]$Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Array]) { return @($Value) }
    return @($Value)
}

function Get-ConfigValue {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [object]$Default = $null
    )

    $Property = $Object.PSObject.Properties[$Name]
    if ($null -eq $Property) { return $Default }
    return $Property.Value
}

function Get-MapValue {
    param(
        [object]$Map,
        [string[]]$Keys,
        [object]$Default = $null
    )

    if ($null -eq $Map) { return $Default }

    foreach ($Key in $Keys) {
        if ([string]::IsNullOrWhiteSpace($Key)) { continue }
        $Property = $Map.PSObject.Properties | Where-Object {
            $_.Name -ieq $Key
        } | Select-Object -First 1
        if ($null -ne $Property) {
            return $Property.Value
        }
    }

    $DefaultProperty = $Map.PSObject.Properties | Where-Object {
        $_.Name -ieq 'default'
    } | Select-Object -First 1

    if ($null -ne $DefaultProperty) {
        return $DefaultProperty.Value
    }

    return $Default
}

function Add-Check {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [Parameter(Mandatory = $true)]
        [int]$Id,
        [Parameter(Mandatory = $true)]
        [string]$Title,
        [Parameter(Mandatory = $true)]
        [ValidateSet('OK', 'NOK', 'INDIREKT', 'NICHT_PRUEFBAR', 'NICHT_ERFORDERLICH', 'ISTWERT')]
        [string]$Status,
        [string]$Details = '',
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

function Add-NotRequired {
    param(
        [string]$Key,
        [int]$Id,
        [string]$Title,
        [string]$Reason
    )

    Add-Check -Key $Key -Id $Id -Title $Title -Status 'NICHT_ERFORDERLICH' -Details $Reason
}

function Test-MatchesAnyPattern {
    param(
        [string[]]$Values,
        [object[]]$Patterns
    )

    foreach ($PatternObject in (Convert-ToArray $Patterns)) {
        $Pattern = [string]$PatternObject
        if ([string]::IsNullOrWhiteSpace($Pattern)) { continue }

        foreach ($Value in $Values) {
            if ([string]::IsNullOrWhiteSpace($Value)) { continue }
            try {
                if ($Value -match $Pattern) { return $true }
            }
            catch {
                if ($Value -ieq $Pattern) { return $true }
            }
        }
    }

    return $false
}

function Get-UninstallPrograms {
    $Roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    $Programs = @()
    foreach ($Root in $Roots) {
        if (-not (Test-Path -LiteralPath $Root)) { continue }

        try {
            $Programs += @(Get-ChildItem -LiteralPath $Root -ErrorAction Stop | ForEach-Object {
                $Properties = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                if (-not [string]::IsNullOrWhiteSpace([string]$Properties.DisplayName)) {
                    [ordered]@{
                        name             = [string]$Properties.DisplayName
                        version          = [string]$Properties.DisplayVersion
                        publisher        = [string]$Properties.Publisher
                        install_location = [string]$Properties.InstallLocation
                        install_date     = [string]$Properties.InstallDate
                        uninstall_key    = [string]$_.PSChildName
                    }
                }
            })
        }
        catch {}
    }

    return @($Programs)
}

function Convert-VersionSafe {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $Match = [regex]::Match($Value, '\d+(?:\.\d+){1,3}')
    if (-not $Match.Success) { return $null }

    try {
        return [version]$Match.Value
    }
    catch {
        return $null
    }
}

function Test-VersionAtLeast {
    param(
        [string]$Actual,
        [string]$Expected
    )

    $ActualVersion = Convert-VersionSafe $Actual
    $ExpectedVersion = Convert-VersionSafe $Expected
    if ($null -eq $ActualVersion -or $null -eq $ExpectedVersion) { return $false }
    return ($ActualVersion -ge $ExpectedVersion)
}

function Get-ServiceEvidence {
    param([string]$Regex)

    try {
        return @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Where-Object {
            ([string]$_.Name -match $Regex) -or ([string]$_.DisplayName -match $Regex)
        } | ForEach-Object {
            [ordered]@{
                name       = [string]$_.Name
                display    = [string]$_.DisplayName
                state      = [string]$_.State
                start_mode = [string]$_.StartMode
                path       = [string]$_.PathName
            }
        })
    }
    catch {
        return @()
    }
}

function Get-RegValueSafe {
    param(
        [string]$Path,
        [string]$Name
    )

    try {
        return Get-ItemPropertyValue -LiteralPath $Path -Name $Name -ErrorAction Stop
    }
    catch {
        return $null
    }
}

function Get-ListeningPortEvidence {
    param([int[]]$Ports)

    $Evidence = @()
    foreach ($Port in $Ports) {
        $Listening = $false
        $Processes = @()

        try {
            $Connections = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop)
            $Listening = ($Connections.Count -gt 0)
            $Processes = @($Connections | ForEach-Object {
                $ProcessName = ''
                try {
                    $ProcessName = (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName
                }
                catch {}

                [ordered]@{
                    local_address = [string]$_.LocalAddress
                    local_port    = [int]$_.LocalPort
                    process_id    = [int]$_.OwningProcess
                    process_name  = $ProcessName
                }
            })
        }
        catch {
            try {
                $NetstatLines = @(netstat -ano -p tcp | Select-String -Pattern "LISTENING\s+\d+$" | ForEach-Object {
                    $_.Line.Trim()
                })
                $PortRegex = "[:\.]$Port\s+.*LISTENING"
                $Matches = @($NetstatLines | Where-Object { $_ -match $PortRegex })
                $Listening = ($Matches.Count -gt 0)
                $Processes = $Matches
            }
            catch {}
        }

        $Evidence += [ordered]@{
            port      = $Port
            listening = $Listening
            listeners = $Processes
        }
    }

    return $Evidence
}

function Convert-ToUrlEncoded {
    param([string]$Value)
    return [System.Uri]::EscapeDataString($Value)
}

function Invoke-EpoApiCommand {
    param(
        [string]$BaseUrl,
        [string]$Username,
        [string]$Password,
        [bool]$ValidateCertificate,
        [int]$TimeoutSeconds,
        [string]$Command,
        [hashtable]$Parameters = @{}
    )

    $Result = [ordered]@{
        success      = $false
        command      = $Command
        uri          = ''
        status_code  = $null
        raw          = ''
        error        = ''
    }

    if ([string]::IsNullOrWhiteSpace($BaseUrl) -or
        [string]::IsNullOrWhiteSpace($Username) -or
        [string]::IsNullOrWhiteSpace($Password) -or
        [string]::IsNullOrWhiteSpace($Command)) {
        $Result.error = 'API-Basis-URL, Benutzer, Kennwort oder Kommando fehlt.'
        return $Result
    }

    $QueryParts = @()
    foreach ($Key in $Parameters.Keys) {
        $QueryParts += ("{0}={1}" -f (Convert-ToUrlEncoded ([string]$Key)), (Convert-ToUrlEncoded ([string]$Parameters[$Key])))
    }
    $QueryParts += ':output=json'

    $Uri = $BaseUrl.TrimEnd('/') + '/remote/' + $Command + '?' + ($QueryParts -join '&')
    $Result.uri = ($BaseUrl.TrimEnd('/') + '/remote/' + $Command)

    $AuthorizationBytes = [Text.Encoding]::ASCII.GetBytes("$Username`:$Password")
    $Headers = @{
        Authorization = 'Basic ' + [Convert]::ToBase64String($AuthorizationBytes)
    }

    $OldCertificateCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        if (-not $ValidateCertificate) {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        }

        $Response = Invoke-WebRequest `
            -UseBasicParsing `
            -Uri $Uri `
            -Headers $Headers `
            -Method Get `
            -TimeoutSec $TimeoutSeconds `
            -ErrorAction Stop

        $Raw = [string]$Response.Content
        $Result.status_code = [int]$Response.StatusCode
        $Result.raw = $Raw

        if ($Raw -match '^\s*(ERROR|ERR|UNAUTHORIZED|FORBIDDEN)') {
            $Result.error = ($Raw.Substring(0, [Math]::Min($Raw.Length, 500)))
        }
        else {
            $Result.success = $true
        }
    }
    catch {
        $Result.error = $_.Exception.Message
    }
    finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $OldCertificateCallback
    }

    return $Result
}

function Get-TextSnippet {
    param(
        [string]$Text,
        [int]$MaximumLength = 1200
    )

    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $Normalized = ($Text -replace '\s+', ' ').Trim()
    if ($Normalized.Length -le $MaximumLength) { return $Normalized }
    return $Normalized.Substring(0, $MaximumLength) + '...'
}

function Invoke-ConfiguredApiCheck {
    param(
        [object]$CheckConfig,
        [string]$ApiBaseUrl,
        [string]$ApiUsername,
        [string]$ApiPassword,
        [bool]$ApiValidateCertificate,
        [int]$ApiTimeoutSeconds
    )

    $Id = [int](Get-ConfigValue -Object $CheckConfig -Name 'Id' -Default 0)
    $Key = [string](Get-ConfigValue -Object $CheckConfig -Name 'Key' -Default '')
    $Title = [string](Get-ConfigValue -Object $CheckConfig -Name 'Title' -Default $Key)
    $Commands = @(Convert-ToArray (Get-ConfigValue -Object $CheckConfig -Name 'CandidateCommands' -Default @()))
    $ArgumentName = [string](Get-ConfigValue -Object $CheckConfig -Name 'ArgumentName' -Default 'searchText')
    $UseSearchParameter = [bool](Get-ConfigValue -Object $CheckConfig -Name 'UseSearchParameter' -Default $true)
    $SearchTerms = @(Convert-ToArray (Get-ConfigValue -Object $CheckConfig -Name 'SearchTerms' -Default @()))
    $RequiredRegex = [string](Get-ConfigValue -Object $CheckConfig -Name 'RequiredRegex' -Default '')
    $StrictRequiredRegex = [bool](Get-ConfigValue -Object $CheckConfig -Name 'StrictRequiredRegex' -Default $false)
    $SuccessStatus = [string](Get-ConfigValue -Object $CheckConfig -Name 'SuccessStatus' -Default 'OK')
    $PartialStatus = [string](Get-ConfigValue -Object $CheckConfig -Name 'PartialStatus' -Default 'INDIREKT')

    $Evidence = [ordered]@{
        candidate_commands = $Commands
        search_terms       = $SearchTerms
        required_regex     = $RequiredRegex
        results            = @()
    }

    if ($Id -le 0 -or [string]::IsNullOrWhiteSpace($Key)) {
        return
    }

    if ([string]::IsNullOrWhiteSpace($ApiUsername) -or [string]::IsNullOrWhiteSpace($ApiPassword)) {
        Add-Check -Key $Key -Id $Id -Title $Title -Status 'NICHT_PRUEFBAR' `
            -Details 'ePO-Web-API-Zugangsdaten fehlen. Die lokale Plattformpruefung laeuft weiter, dieser ePO-Konfigurationsnachweis ist jedoch nicht moeglich.' `
            -Evidence $Evidence
        return
    }

    if ($Commands.Count -eq 0 -or $SearchTerms.Count -eq 0) {
        Add-Check -Key $Key -Id $Id -Title $Title -Status 'NICHT_PRUEFBAR' `
            -Details 'Fuer diese ID sind keine API-Kommandos oder erwarteten Suchbegriffe konfiguriert.' `
            -Evidence $Evidence
        return
    }

    $FoundTerms = 0
    $RequiredMatchedTerms = 0
    $AnySuccessfulApiCall = $false

    foreach ($TermObject in $SearchTerms) {
        $Term = [string]$TermObject
        if ([string]::IsNullOrWhiteSpace($Term)) { continue }

        $TermFound = $false
        $RequiredMatched = [string]::IsNullOrWhiteSpace($RequiredRegex)
        $UsedCommand = ''
        $LastError = ''
        $Snippet = ''

        foreach ($CommandObject in $Commands) {
            $Command = [string]$CommandObject
            if ([string]::IsNullOrWhiteSpace($Command)) { continue }

            $Parameters = @{}
            if ($UseSearchParameter) {
                $Parameters[$ArgumentName] = $Term
            }

            $ApiResult = Invoke-EpoApiCommand `
                -BaseUrl $ApiBaseUrl `
                -Username $ApiUsername `
                -Password $ApiPassword `
                -ValidateCertificate $ApiValidateCertificate `
                -TimeoutSeconds $ApiTimeoutSeconds `
                -Command $Command `
                -Parameters $Parameters

            if ($ApiResult.success) {
                $AnySuccessfulApiCall = $true
                $UsedCommand = $Command
                $Raw = [string]$ApiResult.raw
                $Snippet = Get-TextSnippet $Raw

                if ($UseSearchParameter) {
                    # Ein erfolgreich gefiltertes find-Kommando gilt nur als Treffer,
                    # wenn keine leere Ergebnisliste bzw. bekannte No-result-Antwort vorliegt.
                    $TermFound = -not (
                        $Raw -match '^\s*(OK:\s*)?\[\s*\]\s*$' -or
                        $Raw -match '(?i)\b(no results?|not found|0 results?)\b'
                    )
                }
                else {
                    $TermFound = ($Raw -match [regex]::Escape($Term))
                }

                if ($TermFound -and -not [string]::IsNullOrWhiteSpace($RequiredRegex)) {
                    try {
                        $RequiredMatched = ($Raw -match $RequiredRegex)
                    }
                    catch {
                        $RequiredMatched = $false
                        $LastError = "Ungueltiger RequiredRegex: $($_.Exception.Message)"
                    }
                }

                if ($TermFound) { break }
            }
            else {
                $LastError = [string]$ApiResult.error
            }
        }

        if ($TermFound) { $FoundTerms++ }
        if ($TermFound -and $RequiredMatched) { $RequiredMatchedTerms++ }

        $Evidence.results += [ordered]@{
            term              = $Term
            found             = $TermFound
            required_matched  = $RequiredMatched
            command           = $UsedCommand
            response_snippet  = $Snippet
            error             = $LastError
        }
    }

    $ExpectedCount = @($SearchTerms | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count

    if (-not $AnySuccessfulApiCall) {
        Add-Check -Key $Key -Id $Id -Title $Title -Status 'NICHT_PRUEFBAR' `
            -Details 'Keines der konfigurierten ePO-Web-API-Kommandos war mit diesem Benutzer verfuegbar. Siehe Evidence fuer Kommando- und Berechtigungsfehler.' `
            -Evidence $Evidence
    }
    elseif ($FoundTerms -lt $ExpectedCount) {
        Add-Check -Key $Key -Id $Id -Title $Title -Status 'NOK' `
            -Details "Nicht alle erwarteten ePO-Objekte wurden gefunden: Gefunden=$FoundTerms, Erwartet=$ExpectedCount." `
            -Evidence $Evidence
    }
    elseif (-not [string]::IsNullOrWhiteSpace($RequiredRegex) -and $RequiredMatchedTerms -lt $ExpectedCount) {
        if ($StrictRequiredRegex) {
            Add-Check -Key $Key -Id $Id -Title $Title -Status 'NOK' `
                -Details "Die Objekte wurden gefunden, aber die erwartete Version bzw. Einstellung konnte nicht fuer alle Treffer bestaetigt werden: Bestaetigt=$RequiredMatchedTerms, Erwartet=$ExpectedCount." `
                -Evidence $Evidence
        }
        else {
            Add-Check -Key $Key -Id $Id -Title $Title -Status $PartialStatus `
                -Details "Die Objekte wurden gefunden. Die Detailausgabe der verfuegbaren API-Kommandos bestaetigt die erwartete Einstellung jedoch nicht vollstaendig: Bestaetigt=$RequiredMatchedTerms, Erwartet=$ExpectedCount." `
                -Evidence $Evidence
        }
    }
    else {
        Add-Check -Key $Key -Id $Id -Title $Title -Status $SuccessStatus `
            -Details "Alle erwarteten ePO-Objekte wurden ueber die Web API gefunden: $ExpectedCount." `
            -Evidence $Evidence
    }
}

function Get-ContentEvidence {
    param(
        [object[]]$RegistryPaths,
        [object[]]$FilePaths
    )

    $RegistryEvidence = @()
    $DateCandidates = @()
    $VersionCandidates = @()

    foreach ($PathObject in (Convert-ToArray $RegistryPaths)) {
        $Path = [string]$PathObject
        if (-not (Test-Path -LiteralPath $Path)) { continue }

        try {
            $Keys = @((Get-Item -LiteralPath $Path -ErrorAction Stop))
            $Keys += @(Get-ChildItem -LiteralPath $Path -Recurse -ErrorAction SilentlyContinue | Select-Object -First 250)

            foreach ($Key in $Keys) {
                $Properties = Get-ItemProperty -LiteralPath $Key.PSPath -ErrorAction SilentlyContinue
                if ($null -eq $Properties) { continue }

                foreach ($Property in $Properties.PSObject.Properties) {
                    if ($Property.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
                    if ($Property.Name -notmatch '(?i)(dat|content|amcore|version|date|update)') { continue }

                    $ValueText = [string]$Property.Value
                    $RegistryEvidence += [ordered]@{
                        path  = [string]$Key.Name
                        name  = [string]$Property.Name
                        value = $ValueText
                    }

                    if ($Property.Name -match '(?i)(date|time|update)') {
                        $ParsedDate = [datetime]::MinValue
                        if ([datetime]::TryParse($ValueText, [ref]$ParsedDate)) {
                            $DateCandidates += $ParsedDate
                        }
                    }

                    if ($Property.Name -match '(?i)(version|dat|content|amcore)') {
                        if (-not [string]::IsNullOrWhiteSpace($ValueText)) {
                            $VersionCandidates += $ValueText
                        }
                    }
                }
            }
        }
        catch {}
    }

    $FileEvidence = @()
    foreach ($PathObject in (Convert-ToArray $FilePaths)) {
        $Path = [string]$PathObject
        if (-not (Test-Path -LiteralPath $Path)) { continue }

        try {
            $LatestFiles = @(Get-ChildItem -LiteralPath $Path -File -Recurse -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 20)

            foreach ($File in $LatestFiles) {
                $FileEvidence += [ordered]@{
                    path            = [string]$File.FullName
                    last_write_time = $File.LastWriteTime.ToString('yyyy-MM-ddTHH:mm:sszzz')
                    version         = [string]$File.VersionInfo.FileVersion
                }
                $DateCandidates += $File.LastWriteTime
                if (-not [string]::IsNullOrWhiteSpace([string]$File.VersionInfo.FileVersion)) {
                    $VersionCandidates += [string]$File.VersionInfo.FileVersion
                }
            }
        }
        catch {}
    }

    $LatestDate = $null
    if ($DateCandidates.Count -gt 0) {
        $LatestDate = ($DateCandidates | Sort-Object -Descending | Select-Object -First 1)
    }

    return [ordered]@{
        registry_values = $RegistryEvidence
        files           = $FileEvidence
        latest_date     = $LatestDate
        versions        = @($VersionCandidates | Select-Object -Unique)
    }
}

try {
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "Konfigurationsdatei nicht gefunden: $ConfigPath"
    }

    $Config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $Checks = [ordered]@{}

    $TargetIp = [string](Get-ConfigValue -Object $Config -Name 'TargetIp' -Default '')
    $WinRmPort = [string](Get-ConfigValue -Object $Config -Name 'WinRmPort' -Default '')
    $WinRmScheme = [string](Get-ConfigValue -Object $Config -Name 'WinRmScheme' -Default '')
    $WinRmOpenPorts = [string](Get-ConfigValue -Object $Config -Name 'WinRmOpenPorts' -Default '')

    $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
    $ComputerName = [string]$env:COMPUTERNAME
    $HostValues = @($ComputerName, $TargetIp)

    $EpoServerHostPatterns = @(Convert-ToArray (Get-ConfigValue -Object $Config -Name 'EpoServerHostPatterns' -Default @()))
    $EnsEndpointHostPatterns = @(Convert-ToArray (Get-ConfigValue -Object $Config -Name 'EnsEndpointHostPatterns' -Default @()))

    $IsEpoServer = Test-MatchesAnyPattern -Values $HostValues -Patterns $EpoServerHostPatterns
    $IsEnsEndpoint = Test-MatchesAnyPattern -Values $HostValues -Patterns $EnsEndpointHostPatterns

    $Programs = @(Get-UninstallPrograms)

    # ------------------------------------------------------------------
    # ePO-Serverrolle: IDs 0191 bis 0275
    # ------------------------------------------------------------------
    if ($IsEpoServer) {
        # Historische Aktionen werden gemaess dem vereinbarten Pruefkonzept
        # nicht erneut ausgefuehrt oder aus Anmeldedaten rekonstruiert.
        Add-NotRequired -Key 'ID0191_Rechner_neu_starten' -Id 191 -Title 'Rechner neu starten' `
            -Reason 'Historischer Neustart wird gemaess Pruefkonzept nicht bewertet. Geprueft wird der resultierende ePO-/SQL-Sollzustand.'
        Add-NotRequired -Key 'ID0192_Anmeldung_SecurityAdmin' -Id 192 -Title 'Anmeldung als SecurityAdmin' `
            -Reason 'Eine Benutzeranmeldung wird nicht automatisiert nachgestellt. Der lokale Benutzerbestand wird bereits durch 0010Inital_Valid.yml dokumentiert.'

        # SQL-Instanz bestimmen.
        $SqlInstanceMap = Get-ConfigValue -Object $Config -Name 'SqlInstanceByHost' -Default $null
        $SqlInstanceName = [string](Get-MapValue -Map $SqlInstanceMap -Keys @($ComputerName, $TargetIp) -Default 'EPO01')
        $ExpectedSqlTcpPort = [int](Get-ConfigValue -Object $Config -Name 'ExpectedSqlTcpPort' -Default 1433)
        $ExpectedSqlEditionRegex = [string](Get-ConfigValue -Object $Config -Name 'ExpectedSqlEditionRegex' -Default '(?i)Express')
        $ExpectedSqlMajorVersion = [int](Get-ConfigValue -Object $Config -Name 'ExpectedSqlMajorVersion' -Default 16)
        $ExpectedNtfs8dot3Value = [int](Get-ConfigValue -Object $Config -Name 'ExpectedNtfs8dot3Value' -Default 0)
        $SqlNativeClientProgramRegex = [string](Get-ConfigValue -Object $Config -Name 'SqlNativeClientProgramRegex' -Default '(?i)SQL.*Native Client')

        $SqlInstanceId = [string](Get-RegValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -Name $SqlInstanceName)
        $SqlServiceName = 'MSSQL$' + $SqlInstanceName
        $SqlService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$SqlServiceName'" -ErrorAction SilentlyContinue
        $SqlBrowserService = Get-CimInstance -ClassName Win32_Service -Filter "Name='SQLBrowser'" -ErrorAction SilentlyContinue

        $SqlSetupPath = ''
        $SqlServerPath = ''
        $SqlTcpPath = ''
        if (-not [string]::IsNullOrWhiteSpace($SqlInstanceId)) {
            $SqlSetupPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$SqlInstanceId\Setup"
            $SqlServerPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$SqlInstanceId\MSSQLServer"
            $SqlTcpPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$SqlInstanceId\MSSQLServer\SuperSocketNetLib\Tcp"
        }

        $SqlEdition = [string](Get-RegValueSafe -Path $SqlSetupPath -Name 'Edition')
        $SqlVersionText = [string](Get-RegValueSafe -Path $SqlSetupPath -Name 'Version')
        if ([string]::IsNullOrWhiteSpace($SqlVersionText)) {
            $SqlVersionText = [string](Get-RegValueSafe -Path $SqlSetupPath -Name 'PatchLevel')
        }
        $SqlLoginMode = Get-RegValueSafe -Path $SqlServerPath -Name 'LoginMode'
        $TcpEnabled = Get-RegValueSafe -Path $SqlTcpPath -Name 'Enabled'
        $TcpPort = [string](Get-RegValueSafe -Path ($SqlTcpPath + '\IPAll') -Name 'TcpPort')
        $TcpDynamicPorts = [string](Get-RegValueSafe -Path ($SqlTcpPath + '\IPAll') -Name 'TcpDynamicPorts')

        $SqlVersion = Convert-VersionSafe $SqlVersionText
        $SqlMajorOk = ($null -ne $SqlVersion -and $SqlVersion.Major -eq $ExpectedSqlMajorVersion)
        $SqlEditionOk = (-not [string]::IsNullOrWhiteSpace($SqlEdition) -and $SqlEdition -match $ExpectedSqlEditionRegex)
        $SqlServiceOk = ($null -ne $SqlService -and $SqlService.State -eq 'Running' -and $SqlService.StartMode -eq 'Auto')
        $SqlBrowserOk = ($null -ne $SqlBrowserService -and $SqlBrowserService.State -eq 'Running' -and $SqlBrowserService.StartMode -eq 'Auto')
        $MixedModeOk = ($null -ne $SqlLoginMode -and [int]$SqlLoginMode -eq 2)

        $SqlEvidence = [ordered]@{
            instance_name = $SqlInstanceName
            instance_id   = $SqlInstanceId
            service       = if ($null -ne $SqlService) {
                [ordered]@{ name=$SqlService.Name; state=$SqlService.State; start_mode=$SqlService.StartMode; path=$SqlService.PathName }
            } else { $null }
            browser       = if ($null -ne $SqlBrowserService) {
                [ordered]@{ name=$SqlBrowserService.Name; state=$SqlBrowserService.State; start_mode=$SqlBrowserService.StartMode; path=$SqlBrowserService.PathName }
            } else { $null }
            edition       = $SqlEdition
            version       = $SqlVersionText
            login_mode    = $SqlLoginMode
            tcp_enabled   = $TcpEnabled
            tcp_port      = $TcpPort
            dynamic_ports = $TcpDynamicPorts
        }

        $Id193Ok = (
            -not [string]::IsNullOrWhiteSpace($SqlInstanceId) -and
            $SqlServiceOk -and
            $SqlBrowserOk -and
            $SqlEditionOk -and
            $SqlMajorOk -and
            $MixedModeOk
        )
        Add-Check -Key 'ID0193_SQLServer_2022_Express' -Id 193 -Title 'SQL Server 2022 Express Installation und Konfiguration' `
            -Status $(if ($Id193Ok) { 'OK' } else { 'NOK' }) `
            -Details "Instanz=$SqlInstanceName; Instanz-ID=$SqlInstanceId; Edition=$SqlEdition; Version=$SqlVersionText; SQL-Dienst=$($SqlService.State)/$($SqlService.StartMode); Browser=$($SqlBrowserService.State)/$($SqlBrowserService.StartMode); LoginMode=$SqlLoginMode (Soll=2)." `
            -Evidence $SqlEvidence

        $TcpOk = (
            -not [string]::IsNullOrWhiteSpace($SqlInstanceId) -and
            [int]$TcpEnabled -eq 1 -and
            $TcpPort -eq [string]$ExpectedSqlTcpPort -and
            [string]::IsNullOrWhiteSpace($TcpDynamicPorts) -and
            $SqlServiceOk
        )
        Add-Check -Key 'ID0194_SQLServer_TCP_1433' -Id 194 -Title 'SQL Server 2022 Express Nachkonfiguration' `
            -Status $(if ($TcpOk) { 'OK' } else { 'NOK' }) `
            -Details "TCP/IP Enabled=$TcpEnabled; statischer Port=$TcpPort (Soll=$ExpectedSqlTcpPort); dynamische Ports='$TcpDynamicPorts'; SQL-Dienst=$($SqlService.State)." `
            -Evidence $SqlEvidence

        $Ntfs8dot3 = Get-RegValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'NtfsDisable8dot3NameCreation'
        $NativeClientPrograms = @($Programs | Where-Object { [string]$_.name -match $SqlNativeClientProgramRegex })
        $Id195Ok = (
            $SqlBrowserOk -and
            $null -ne $Ntfs8dot3 -and
            [int]$Ntfs8dot3 -eq $ExpectedNtfs8dot3Value -and
            $NativeClientPrograms.Count -gt 0
        )
        Add-Check -Key 'ID0195_ePO_Voraussetzungen' -Id 195 -Title 'ePO 5.10.0 Installationsvoraussetzungen' `
            -Status $(if ($Id195Ok) { 'OK' } else { 'NOK' }) `
            -Details "SQLBrowser=$($SqlBrowserService.State)/$($SqlBrowserService.StartMode); NtfsDisable8dot3NameCreation=$Ntfs8dot3 (Soll=$ExpectedNtfs8dot3Value); SQL-Native-Client-Installationen=$($NativeClientPrograms.Count)." `
            -Evidence ([ordered]@{ sql_browser=$SqlEvidence.browser; ntfs_8dot3=$Ntfs8dot3; native_client_programs=$NativeClientPrograms })

        $EpoInstallDirectories = @(Convert-ToArray (Get-ConfigValue -Object $Config -Name 'EpoInstallDirectories' -Default @()))
        $EpoServiceRegex = [string](Get-ConfigValue -Object $Config -Name 'EpoServiceNameRegex' -Default '(?i)ePolicy|MCAFEEAPACHESRV|MCAFEE_TOMCATSRV')
        $RequiredListeningPorts = @((Convert-ToArray (Get-ConfigValue -Object $Config -Name 'EpoRequiredListeningPorts' -Default @(8080,8443))) | ForEach-Object { [int]$_ })
        $EpoProductRegex = [string](Get-ConfigValue -Object $Config -Name 'EpoProductNameRegex' -Default '(?i)ePolicy Orchestrator')
        $ExpectedEpoVersionRegex = [string](Get-ConfigValue -Object $Config -Name 'ExpectedEpoProductVersionRegex' -Default '(?i)^5\.10\.0')
        $ExpectedFinalUpdateRegex = [string](Get-ConfigValue -Object $Config -Name 'ExpectedFinalUpdateRegex' -Default '(?i)Update\s*5|11818|UP5')
        $SsmsProgramRegex = [string](Get-ConfigValue -Object $Config -Name 'SsmsProgramRegex' -Default '(?i)(SQL Server Management Studio|SSMS)')
        $SsmsMinVersion = [string](Get-ConfigValue -Object $Config -Name 'SsmsMinVersion' -Default '20.2.1')

        $ExistingEpoDirectories = @($EpoInstallDirectories | Where-Object { Test-Path -LiteralPath ([string]$_) })
        $EpoServices = @(Get-ServiceEvidence -Regex $EpoServiceRegex)
        $RunningEpoServices = @($EpoServices | Where-Object { $_.state -eq 'Running' })
        $PortEvidence = @(Get-ListeningPortEvidence -Ports $RequiredListeningPorts)
        $MissingListeningPorts = @($PortEvidence | Where-Object { -not $_.listening })
        $EpoPrograms = @($Programs | Where-Object { [string]$_.name -match $EpoProductRegex })

        $EpoVersionValues = @()
        $EpoVersionValues += @($EpoPrograms | ForEach-Object { [string]$_.version })
        foreach ($RegistryRoot in @(
            'HKLM:\SOFTWARE\WOW6432Node\Network Associates\ePolicy Orchestrator',
            'HKLM:\SOFTWARE\WOW6432Node\McAfee\ePolicy Orchestrator',
            'HKLM:\SOFTWARE\WOW6432Node\Trellix\ePolicy Orchestrator'
        )) {
            if (-not (Test-Path -LiteralPath $RegistryRoot)) { continue }
            try {
                $RegistryKeys = @((Get-Item -LiteralPath $RegistryRoot))
                $RegistryKeys += @(Get-ChildItem -LiteralPath $RegistryRoot -Recurse -ErrorAction SilentlyContinue | Select-Object -First 250)
                foreach ($RegistryKey in $RegistryKeys) {
                    $RegistryValues = Get-ItemProperty -LiteralPath $RegistryKey.PSPath -ErrorAction SilentlyContinue
                    foreach ($Property in $RegistryValues.PSObject.Properties) {
                        if ($Property.Name -match '(?i)(version|build|update|patch)' -and
                            -not [string]::IsNullOrWhiteSpace([string]$Property.Value)) {
                            $EpoVersionValues += [string]$Property.Value
                        }
                    }
                }
            }
            catch {}
        }
        $EpoVersionValues = @($EpoVersionValues | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)

        $EpoBaseVersionOk = (@($EpoVersionValues | Where-Object { $_ -match $ExpectedEpoVersionRegex }).Count -gt 0)
        $EpoInstallOk = (
            $ExistingEpoDirectories.Count -gt 0 -and
            $EpoServices.Count -gt 0 -and
            $RunningEpoServices.Count -gt 0 -and
            $MissingListeningPorts.Count -eq 0 -and
            $EpoBaseVersionOk
        )

        $ApiBaseUrl = [string](Get-ConfigValue -Object $Config -Name 'EpoApiBaseUrl' -Default 'https://localhost:8443')
        $ApiUsername = [string](Get-ConfigValue -Object $Config -Name 'EpoApiUsername' -Default '')
        $ApiPassword = [string](Get-ConfigValue -Object $Config -Name 'EpoApiPassword' -Default '')
        $ApiValidateCertificate = [bool](Get-ConfigValue -Object $Config -Name 'EpoApiValidateCertificate' -Default $false)
        $ApiTimeoutSeconds = [int](Get-ConfigValue -Object $Config -Name 'EpoApiTimeoutSeconds' -Default 60)

        $ApiHelpResult = $null
        $ApiVersionEvidence = @()
        if (-not [string]::IsNullOrWhiteSpace($ApiUsername) -and -not [string]::IsNullOrWhiteSpace($ApiPassword)) {
            $ApiHelpResult = Invoke-EpoApiCommand `
                -BaseUrl $ApiBaseUrl `
                -Username $ApiUsername `
                -Password $ApiPassword `
                -ValidateCertificate $ApiValidateCertificate `
                -TimeoutSeconds $ApiTimeoutSeconds `
                -Command 'core.help'

            foreach ($VersionCommand in @('core.getVersion', 'core.version', 'core.getServerVersion')) {
                $ApiVersionResult = Invoke-EpoApiCommand `
                    -BaseUrl $ApiBaseUrl `
                    -Username $ApiUsername `
                    -Password $ApiPassword `
                    -ValidateCertificate $ApiValidateCertificate `
                    -TimeoutSeconds $ApiTimeoutSeconds `
                    -Command $VersionCommand

                $ApiVersionEvidence += [ordered]@{
                    command = $VersionCommand
                    success = $ApiVersionResult.success
                    snippet = Get-TextSnippet $ApiVersionResult.raw
                    error   = $ApiVersionResult.error
                }

                if ($ApiVersionResult.success) {
                    $EpoVersionValues += [string]$ApiVersionResult.raw
                    break
                }
            }
        }

        $EpoVersionValues = @($EpoVersionValues | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
        $EpoBaseVersionOk = (@($EpoVersionValues | Where-Object { $_ -match $ExpectedEpoVersionRegex }).Count -gt 0)
        $EpoInstallOk = (
            $ExistingEpoDirectories.Count -gt 0 -and
            $EpoServices.Count -gt 0 -and
            $RunningEpoServices.Count -gt 0 -and
            $MissingListeningPorts.Count -eq 0 -and
            $EpoBaseVersionOk
        )

        Add-Check -Key 'ID0196_ePO_Installation' -Id 196 -Title 'ePO 5.10.0 Installation' `
            -Status $(if ($EpoInstallOk) { 'OK' } else { 'NOK' }) `
            -Details "Installationsverzeichnisse=$($ExistingEpoDirectories.Count); ePO-Dienste=$($EpoServices.Count); laufend=$($RunningEpoServices.Count); fehlende Listen-Ports=$($MissingListeningPorts.Count); Versionen=$($EpoVersionValues -join ', '); API erreichbar=$($ApiHelpResult.success)." `
            -Evidence ([ordered]@{
                install_directories=$ExistingEpoDirectories
                services=$EpoServices
                ports=$PortEvidence
                programs=$EpoPrograms
                version_values=$EpoVersionValues
                api=[ordered]@{
                    base_url=$ApiBaseUrl
                    success=if($null -ne $ApiHelpResult){$ApiHelpResult.success}else{$false}
                    error=if($null -ne $ApiHelpResult){$ApiHelpResult.error}else{'Keine API-Zugangsdaten'}
                    help_snippet=if($null -ne $ApiHelpResult){Get-TextSnippet $ApiHelpResult.raw 1500}else{''}
                    version_commands=$ApiVersionEvidence
                }
            })

        $SsmsPrograms = @($Programs | Where-Object { [string]$_.name -match $SsmsProgramRegex })
        $SsmsVersionOk = (@($SsmsPrograms | Where-Object { Test-VersionAtLeast -Actual ([string]$_.version) -Expected $SsmsMinVersion }).Count -gt 0)
        Add-Check -Key 'ID0197_SSMS_20_2_1' -Id 197 -Title 'SQL Server Management Studio 20.2.1 installieren' `
            -Status $(if ($SsmsVersionOk) { 'OK' } else { 'NOK' }) `
            -Details "Gefundene SSMS-Installationen=$($SsmsPrograms.Count); Mindestversion=$SsmsMinVersion." `
            -Evidence $SsmsPrograms

        $FinalUpdateOk = (@($EpoVersionValues | Where-Object { $_ -match $ExpectedFinalUpdateRegex }).Count -gt 0)
        $UpdateEvidence = [ordered]@{
            expected_final_update_regex = $ExpectedFinalUpdateRegex
            version_values              = $EpoVersionValues
            base_installation_ok        = $EpoInstallOk
        }

        foreach ($HistoricalUpdate in @(
            [ordered]@{ Key='ID0201_ePO_SP1_UP3'; Id=201; Title='ePO 5.10.0 SP1 Update 3 installiert' },
            [ordered]@{ Key='ID0202_ePO_SP1_UP4_Vorbereitung'; Id=202; Title='Vorbereitung fuer ePO SP1 Update 4' },
            [ordered]@{ Key='ID0203_ePO_SP1_UP4'; Id=203; Title='ePO 5.10.0 SP1 Update 4 installiert' }
        )) {
            if ($FinalUpdateOk) {
                Add-Check -Key $HistoricalUpdate.Key -Id $HistoricalUpdate.Id -Title $HistoricalUpdate.Title `
                    -Status 'INDIREKT' `
                    -Details 'Der historische Installationsschritt wird nicht rekonstruiert. Der geforderte finale ePO-SP1-Update-5-Stand ist vorhanden und weist die abgeschlossene Updatekette indirekt nach.' `
                    -Evidence $UpdateEvidence
            }
            else {
                Add-Check -Key $HistoricalUpdate.Key -Id $HistoricalUpdate.Id -Title $HistoricalUpdate.Title `
                    -Status 'NOK' `
                    -Details 'Der finale erwartete ePO-SP1-Update-5-Stand wurde nicht erkannt; damit ist auch die vorherige Updatekette nicht nachgewiesen.' `
                    -Evidence $UpdateEvidence
            }
        }

        Add-Check -Key 'ID0204_ePO_SP1_UP5' -Id 204 -Title 'ePO 5.10.0 SP1 Update 5 installiert' `
            -Status $(if ($FinalUpdateOk) { 'OK' } else { 'NOK' }) `
            -Details "Finaler Update-Regex=$ExpectedFinalUpdateRegex; erkannte Versions-/Buildwerte=$($EpoVersionValues -join ', ')." `
            -Evidence $UpdateEvidence

        # Konfigurationsobjekte ueber die ePO-Web-API pruefen.
        $ApiChecks = @(Convert-ToArray (Get-ConfigValue -Object $Config -Name 'EpoApiChecks' -Default @()))
        foreach ($ApiCheck in $ApiChecks) {
            Invoke-ConfiguredApiCheck `
                -CheckConfig $ApiCheck `
                -ApiBaseUrl $ApiBaseUrl `
                -ApiUsername $ApiUsername `
                -ApiPassword $ApiPassword `
                -ApiValidateCertificate $ApiValidateCertificate `
                -ApiTimeoutSeconds $ApiTimeoutSeconds
        }

        # ID 0241: Systemstruktur und verwaltete Systeme.
        $ManagedSystemNames = @(Convert-ToArray (Get-ConfigValue -Object $Config -Name 'EpoManagedSystemNames' -Default @()))
        $SystemEvidence = [ordered]@{
            expected_systems = $ManagedSystemNames
            results = @()
        }
        $ManagedFound = 0
        $AnySystemApiCall = $false

        if ([string]::IsNullOrWhiteSpace($ApiUsername) -or [string]::IsNullOrWhiteSpace($ApiPassword)) {
            Add-Check -Key 'ID0241_Systemstruktur' -Id 241 -Title 'Systemstruktur anlegen und Agentinstallation durchfuehren' `
                -Status 'NICHT_PRUEFBAR' `
                -Details 'ePO-Web-API-Zugangsdaten fehlen; Systemstruktur und verwaltete Systeme konnten nicht abgefragt werden.' `
                -Evidence $SystemEvidence
        }
        elseif ($ManagedSystemNames.Count -eq 0) {
            Add-Check -Key 'ID0241_Systemstruktur' -Id 241 -Title 'Systemstruktur anlegen und Agentinstallation durchfuehren' `
                -Status 'NICHT_PRUEFBAR' `
                -Details 'Es sind keine erwarteten verwalteten Systemnamen konfiguriert.' `
                -Evidence $SystemEvidence
        }
        else {
            foreach ($ManagedSystemObject in $ManagedSystemNames) {
                $ManagedSystem = [string]$ManagedSystemObject
                $ApiSystemResult = Invoke-EpoApiCommand `
                    -BaseUrl $ApiBaseUrl `
                    -Username $ApiUsername `
                    -Password $ApiPassword `
                    -ValidateCertificate $ApiValidateCertificate `
                    -TimeoutSeconds $ApiTimeoutSeconds `
                    -Command 'system.find' `
                    -Parameters @{ searchText = $ManagedSystem }

                $Found = $false
                if ($ApiSystemResult.success) {
                    $AnySystemApiCall = $true
                    $Raw = [string]$ApiSystemResult.raw
                    $Found = (
                        $Raw -match [regex]::Escape($ManagedSystem) -and
                        $Raw -notmatch '^\s*(OK:\s*)?\[\s*\]\s*$'
                    )
                }
                if ($Found) { $ManagedFound++ }

                $SystemEvidence.results += [ordered]@{
                    system   = $ManagedSystem
                    found    = $Found
                    snippet  = Get-TextSnippet $ApiSystemResult.raw
                    error    = $ApiSystemResult.error
                }
            }

            if (-not $AnySystemApiCall) {
                Add-Check -Key 'ID0241_Systemstruktur' -Id 241 -Title 'Systemstruktur anlegen und Agentinstallation durchfuehren' `
                    -Status 'NICHT_PRUEFBAR' `
                    -Details 'Das Web-API-Kommando system.find war nicht verfuegbar oder nicht berechtigt.' `
                    -Evidence $SystemEvidence
            }
            elseif ($ManagedFound -eq $ManagedSystemNames.Count) {
                Add-Check -Key 'ID0241_Systemstruktur' -Id 241 -Title 'Systemstruktur anlegen und Agentinstallation durchfuehren' `
                    -Status 'OK' `
                    -Details "Alle erwarteten verwalteten Systeme wurden gefunden: $ManagedFound von $($ManagedSystemNames.Count)." `
                    -Evidence $SystemEvidence
            }
            else {
                Add-Check -Key 'ID0241_Systemstruktur' -Id 241 -Title 'Systemstruktur anlegen und Agentinstallation durchfuehren' `
                    -Status 'NOK' `
                    -Details "Nicht alle erwarteten Systeme sind in ePO auffindbar: $ManagedFound von $($ManagedSystemNames.Count)." `
                    -Evidence $SystemEvidence
            }
        }

        # ID 0206 ist ein historischer Bereinigungsschritt. Nach dem spaeteren
        # Einchecken der Sollpakete kann nur der finale Repository-Zustand
        # indirekt bewertet werden.
        $RepositoryKeys = @(
            'ID0210_Trellix_Agent_Extension',
            'ID0212_ePO_Agent_Key_Updater',
            'ID0214_MsgBus_Cert_Updater',
            'ID0216_Trellix_Agent_Windows',
            'ID0218_Application_Control',
            'ID0219_ePO_Management_Extension',
            'ID0221_Endpoint_Upgrade_Assistant',
            'ID0223_MER_ePO_Extension',
            'ID0225_MER_ePO_Paket',
            'ID0245_ENS_Platform_Paket',
            'ID0247_ENS_Threat_Prevention_Paket',
            'ID0248_AMCore_Content_Paket',
            'ID0249_Exploit_Prevention_Content',
            'ID0251_ENS_Common_Extension',
            'ID0253_ENS_Threat_Prevention_Extension'
        )

        $RepositoryStatuses = @($RepositoryKeys | ForEach-Object {
            if ($Checks.Contains($_)) { [string]$Checks[$_].status } else { 'NICHT_PRUEFBAR' }
        })

        if (@($RepositoryStatuses | Where-Object { $_ -eq 'NOK' }).Count -gt 0) {
            $RepositoryCleanupStatus = 'NOK'
            $RepositoryCleanupDetails = 'Der historische Bereinigungsschritt ist nicht direkt beweisbar und der finale Repository-Sollbestand ist unvollstaendig.'
        }
        elseif (@($RepositoryStatuses | Where-Object { $_ -eq 'NICHT_PRUEFBAR' }).Count -gt 0) {
            $RepositoryCleanupStatus = 'NICHT_PRUEFBAR'
            $RepositoryCleanupDetails = 'Der historische Bereinigungsschritt ist nicht direkt beweisbar; zudem konnten nicht alle nachfolgend erwarteten Repository-Objekte abgefragt werden.'
        }
        else {
            $RepositoryCleanupStatus = 'INDIREKT'
            $RepositoryCleanupDetails = 'Der historische leere Zwischenzustand des Master-Repositorys ist nach spaeteren Paket-Check-ins nicht direkt rekonstruierbar. Der erwartete finale Repository-Bestand ist jedoch nachgewiesen.'
        }

        Add-Check -Key 'ID0206_MasterRepository_bereinigt' -Id 206 -Title 'ePO Master-Repository bereinigen' `
            -Status $RepositoryCleanupStatus `
            -Details $RepositoryCleanupDetails `
            -Evidence ([ordered]@{ repository_check_keys=$RepositoryKeys; statuses=$RepositoryStatuses })
    }
    else {
        $EpoOnlyChecks = @(
            @(191,'ID0191_Rechner_neu_starten','Rechner neu starten'),
            @(192,'ID0192_Anmeldung_SecurityAdmin','Anmeldung als SecurityAdmin'),
            @(193,'ID0193_SQLServer_2022_Express','SQL Server 2022 Express Installation und Konfiguration'),
            @(194,'ID0194_SQLServer_TCP_1433','SQL Server 2022 Express Nachkonfiguration'),
            @(195,'ID0195_ePO_Voraussetzungen','ePO Installationsvoraussetzungen'),
            @(196,'ID0196_ePO_Installation','ePO Installation'),
            @(197,'ID0197_SSMS_20_2_1','SQL Server Management Studio'),
            @(201,'ID0201_ePO_SP1_UP3','ePO SP1 Update 3'),
            @(202,'ID0202_ePO_SP1_UP4_Vorbereitung','ePO SP1 Update 4 Vorbereitung'),
            @(203,'ID0203_ePO_SP1_UP4','ePO SP1 Update 4'),
            @(204,'ID0204_ePO_SP1_UP5','ePO SP1 Update 5'),
            @(205,'ID0205_ServerTasks_deaktiviert','ePO Server-Tasks deaktiviert'),
            @(206,'ID0206_MasterRepository_bereinigt','Master-Repository bereinigt'),
            @(210,'ID0210_Trellix_Agent_Extension','Trellix Agent Extension'),
            @(212,'ID0212_ePO_Agent_Key_Updater','ePO Agent Key Updater'),
            @(214,'ID0214_MsgBus_Cert_Updater','MsgBus Cert Updater'),
            @(216,'ID0216_Trellix_Agent_Windows','Trellix Agent for Windows'),
            @(218,'ID0218_Application_Control','Trellix Application Control'),
            @(219,'ID0219_ePO_Management_Extension','ePO Management Extension'),
            @(221,'ID0221_Endpoint_Upgrade_Assistant','Endpoint Upgrade Assistant'),
            @(223,'ID0223_MER_ePO_Extension','MER for ePO Extension'),
            @(225,'ID0225_MER_ePO_Paket','MER for ePO Paket'),
            @(226,'ID0226_Solidcore_Lizenz','Solidcore-Lizenz'),
            @(227,'ID0227_GTI_Synchronisierung','GTI Synchronisierung deaktiviert'),
            @(234,'ID0234_SC_CLI_Passwort','Solidcore CLI-Passwort'),
            @(237,'ID0237_Abfragen_importiert','Abfragen importiert'),
            @(238,'ID0238_Berichte_importiert','Berichte importiert'),
            @(241,'ID0241_Systemstruktur','Systemstruktur und Agenten'),
            @(245,'ID0245_ENS_Platform_Paket','ENS Platform Paket'),
            @(247,'ID0247_ENS_Threat_Prevention_Paket','ENS Threat Prevention Paket'),
            @(248,'ID0248_AMCore_Content_Paket','AMCore Content Paket'),
            @(249,'ID0249_Exploit_Prevention_Content','Exploit Prevention Content'),
            @(251,'ID0251_ENS_Common_Extension','ENS Common Extension'),
            @(253,'ID0253_ENS_Threat_Prevention_Extension','ENS Threat Prevention Extension'),
            @(255,'ID0255_Tag_Katalog','Tag-Katalog'),
            @(258,'ID0258_Trellix_Agent_Richtlinien','Trellix Agent Richtlinien'),
            @(259,'ID0259_ENS_Common_Richtlinien','ENS Common Richtlinien'),
            @(260,'ID0260_ENS_TP_Richtlinien','ENS TP Richtlinien'),
            @(261,'ID0261_Solidcore_Richtlinien','Solidcore Richtlinien'),
            @(263,'ID0263_Richtlinienzuweisungsregeln','Richtlinienzuweisungsregeln'),
            @(265,'ID0265_Richtlinienzuweisungen','Richtlinienzuweisungen'),
            @(266,'ID0266_ENS_CLI_Passwort','ENS CLI-Passwort'),
            @(267,'ID0267_ENS_Abfragen','ENS Abfragen'),
            @(269,'ID0269_Solidcore_Regeln','Solidcore Regeln'),
            @(271,'ID0271_Dashboards','Dashboards'),
            @(273,'ID0273_ServerTasks','Server-Tasks'),
            @(274,'ID0274_AV_Download_Task','AV-Download-Task'),
            @(275,'ID0275_ClientTask_Katalog','Client-Task-Katalog')
        )

        foreach ($CheckDefinition in $EpoOnlyChecks) {
            Add-NotRequired -Id ([int]$CheckDefinition[0]) -Key ([string]$CheckDefinition[1]) -Title ([string]$CheckDefinition[2]) `
                -Reason 'Diese Pruefung gilt nur fuer einen ePO-Server. Der Host entspricht keinem konfigurierten ePO-Server-Pattern.'
        }
    }

    # ------------------------------------------------------------------
    # ENS-Endpointrolle: IDs 0278 bis 0280
    # ------------------------------------------------------------------
    if ($IsEnsEndpoint) {
        $EnsPlatformProgramRegex = [string](Get-ConfigValue -Object $Config -Name 'EnsPlatformProgramRegex' -Default '(?i)Endpoint Security Platform')
        $EnsPlatformVersionRegex = [string](Get-ConfigValue -Object $Config -Name 'EnsPlatformVersionRegex' -Default '(?i)10\.7\.19')
        $EnsThreatProgramRegex = [string](Get-ConfigValue -Object $Config -Name 'EnsThreatPreventionProgramRegex' -Default '(?i)Threat Prevention')
        $EnsThreatVersionRegex = [string](Get-ConfigValue -Object $Config -Name 'EnsThreatPreventionVersionRegex' -Default '(?i)10\.7\.19')
        $EnsServiceRegex = [string](Get-ConfigValue -Object $Config -Name 'EnsServiceRegex' -Default '(?i)(mfemms|mfetp|Endpoint Security|Threat Prevention)')
        $EnsContentRegistryPaths = @(Convert-ToArray (Get-ConfigValue -Object $Config -Name 'EnsContentRegistryPaths' -Default @()))
        $EnsContentPaths = @(Convert-ToArray (Get-ConfigValue -Object $Config -Name 'EnsContentPaths' -Default @()))
        $EnsContentMaxAgeDays = [int](Get-ConfigValue -Object $Config -Name 'EnsContentMaxAgeDays' -Default 14)

        $EnsPlatformPrograms = @($Programs | Where-Object { [string]$_.name -match $EnsPlatformProgramRegex })
        $EnsThreatPrograms = @($Programs | Where-Object { [string]$_.name -match $EnsThreatProgramRegex })
        $EnsServices = @(Get-ServiceEvidence -Regex $EnsServiceRegex)
        $RunningEnsServices = @($EnsServices | Where-Object { $_.state -eq 'Running' })

        $EnsInstalledOk = (
            $EnsPlatformPrograms.Count -gt 0 -and
            $EnsThreatPrograms.Count -gt 0 -and
            $RunningEnsServices.Count -gt 0
        )

        Add-Check -Key 'ID0278_ENS_installiert' -Id 278 -Title 'ENS auf den Zielsystemen installieren' `
            -Status $(if ($EnsInstalledOk) { 'OK' } else { 'NOK' }) `
            -Details "ENS-Platform-Installationen=$($EnsPlatformPrograms.Count); Threat-Prevention-Installationen=$($EnsThreatPrograms.Count); laufende ENS-Dienste=$($RunningEnsServices.Count)." `
            -Evidence ([ordered]@{ platform_programs=$EnsPlatformPrograms; threat_programs=$EnsThreatPrograms; services=$EnsServices })

        $ContentEvidence = Get-ContentEvidence -RegistryPaths $EnsContentRegistryPaths -FilePaths $EnsContentPaths
        $LatestContentDate = $ContentEvidence.latest_date
        $ContentAgeDays = $null
        if ($null -ne $LatestContentDate) {
            $ContentAgeDays = [math]::Floor(((Get-Date) - $LatestContentDate).TotalDays)
        }

        if ($null -eq $LatestContentDate) {
            $ContentStatus = 'NICHT_PRUEFBAR'
            $ContentDetails = 'Es wurde kein belastbarer ENS-/AMCore-Content-Zeitstempel gefunden.'
        }
        elseif ($ContentAgeDays -le $EnsContentMaxAgeDays) {
            $ContentStatus = 'OK'
            $ContentDetails = "Neuester erkannter ENS-/AMCore-Content-Zeitstempel=$($LatestContentDate.ToString('yyyy-MM-ddTHH:mm:sszzz')); Alter=$ContentAgeDays Tage; maximal erlaubt=$EnsContentMaxAgeDays Tage."
        }
        else {
            $ContentStatus = 'NOK'
            $ContentDetails = "ENS-/AMCore-Content ist zu alt: Zeitstempel=$($LatestContentDate.ToString('yyyy-MM-ddTHH:mm:sszzz')); Alter=$ContentAgeDays Tage; maximal erlaubt=$EnsContentMaxAgeDays Tage."
        }

        Add-Check -Key 'ID0279_Sicherheit_aktualisiert' -Id 279 -Title 'Sicherheit aktualisieren' `
            -Status $ContentStatus `
            -Details $ContentDetails `
            -Evidence $ContentEvidence

        $PlatformVersionOk = (@($EnsPlatformPrograms | Where-Object { [string]$_.version -match $EnsPlatformVersionRegex }).Count -gt 0)
        $ThreatVersionOk = (@($EnsThreatPrograms | Where-Object { [string]$_.version -match $EnsThreatVersionRegex }).Count -gt 0)
        $EnsVersionOk = ($PlatformVersionOk -and $ThreatVersionOk)

        Add-Check -Key 'ID0280_ENS_Version' -Id 280 -Title 'Kontrolle ENS Version' `
            -Status $(if ($EnsVersionOk) { 'OK' } else { 'NOK' }) `
            -Details "Platform-Version-Regex=$EnsPlatformVersionRegex; Treffer=$PlatformVersionOk; Threat-Prevention-Version-Regex=$EnsThreatVersionRegex; Treffer=$ThreatVersionOk." `
            -Evidence ([ordered]@{ platform_programs=$EnsPlatformPrograms; threat_programs=$EnsThreatPrograms })
    }
    else {
        Add-NotRequired -Key 'ID0278_ENS_installiert' -Id 278 -Title 'ENS auf den Zielsystemen installieren' `
            -Reason 'Der Host ist nicht als ENS-Zielsystem konfiguriert.'
        Add-NotRequired -Key 'ID0279_Sicherheit_aktualisiert' -Id 279 -Title 'Sicherheit aktualisieren' `
            -Reason 'Der Host ist nicht als ENS-Zielsystem konfiguriert.'
        Add-NotRequired -Key 'ID0280_ENS_Version' -Id 280 -Title 'Kontrolle ENS Version' `
            -Reason 'Der Host ist nicht als ENS-Zielsystem konfiguriert.'
    }

    # Sicherheitsnetz: Jede angeforderte ID muss im Report vorkommen.
    $RequiredCheckDefinitions = @(
        @(191,'ID0191_Rechner_neu_starten','Rechner neu starten'),
        @(192,'ID0192_Anmeldung_SecurityAdmin','Anmeldung als SecurityAdmin'),
        @(193,'ID0193_SQLServer_2022_Express','SQL Server 2022 Express'),
        @(194,'ID0194_SQLServer_TCP_1433','SQL TCP 1433'),
        @(195,'ID0195_ePO_Voraussetzungen','ePO Installationsvoraussetzungen'),
        @(196,'ID0196_ePO_Installation','ePO Installation'),
        @(197,'ID0197_SSMS_20_2_1','SQL Server Management Studio'),
        @(201,'ID0201_ePO_SP1_UP3','ePO SP1 Update 3'),
        @(202,'ID0202_ePO_SP1_UP4_Vorbereitung','ePO SP1 Update 4 Vorbereitung'),
        @(203,'ID0203_ePO_SP1_UP4','ePO SP1 Update 4'),
        @(204,'ID0204_ePO_SP1_UP5','ePO SP1 Update 5'),
        @(205,'ID0205_ServerTasks_deaktiviert','Server-Tasks deaktiviert'),
        @(206,'ID0206_MasterRepository_bereinigt','Master-Repository bereinigt'),
        @(210,'ID0210_Trellix_Agent_Extension','Trellix Agent Extension'),
        @(212,'ID0212_ePO_Agent_Key_Updater','ePO Agent Key Updater'),
        @(214,'ID0214_MsgBus_Cert_Updater','MsgBus Cert Updater'),
        @(216,'ID0216_Trellix_Agent_Windows','Trellix Agent Windows'),
        @(218,'ID0218_Application_Control','Application Control'),
        @(219,'ID0219_ePO_Management_Extension','ePO Management Extension'),
        @(221,'ID0221_Endpoint_Upgrade_Assistant','Endpoint Upgrade Assistant'),
        @(223,'ID0223_MER_ePO_Extension','MER ePO Extension'),
        @(225,'ID0225_MER_ePO_Paket','MER ePO Paket'),
        @(226,'ID0226_Solidcore_Lizenz','Solidcore-Lizenz'),
        @(227,'ID0227_GTI_Synchronisierung','GTI Synchronisierung'),
        @(234,'ID0234_SC_CLI_Passwort','SC CLI-Passwort'),
        @(237,'ID0237_Abfragen_importiert','Abfragen importiert'),
        @(238,'ID0238_Berichte_importiert','Berichte importiert'),
        @(241,'ID0241_Systemstruktur','Systemstruktur'),
        @(245,'ID0245_ENS_Platform_Paket','ENS Platform Paket'),
        @(247,'ID0247_ENS_Threat_Prevention_Paket','ENS Threat Prevention Paket'),
        @(248,'ID0248_AMCore_Content_Paket','AMCore Content Paket'),
        @(249,'ID0249_Exploit_Prevention_Content','Exploit Prevention Content'),
        @(251,'ID0251_ENS_Common_Extension','ENS Common Extension'),
        @(253,'ID0253_ENS_Threat_Prevention_Extension','ENS TP Extension'),
        @(255,'ID0255_Tag_Katalog','Tag-Katalog'),
        @(258,'ID0258_Trellix_Agent_Richtlinien','Trellix Agent Richtlinien'),
        @(259,'ID0259_ENS_Common_Richtlinien','ENS Common Richtlinien'),
        @(260,'ID0260_ENS_TP_Richtlinien','ENS TP Richtlinien'),
        @(261,'ID0261_Solidcore_Richtlinien','Solidcore Richtlinien'),
        @(263,'ID0263_Richtlinienzuweisungsregeln','Richtlinienzuweisungsregeln'),
        @(265,'ID0265_Richtlinienzuweisungen','Richtlinienzuweisungen'),
        @(266,'ID0266_ENS_CLI_Passwort','ENS CLI-Passwort'),
        @(267,'ID0267_ENS_Abfragen','ENS Abfragen'),
        @(269,'ID0269_Solidcore_Regeln','Solidcore Regeln'),
        @(271,'ID0271_Dashboards','Dashboards'),
        @(273,'ID0273_ServerTasks','Server-Tasks'),
        @(274,'ID0274_AV_Download_Task','AV-Download-Task'),
        @(275,'ID0275_ClientTask_Katalog','Client-Task-Katalog'),
        @(278,'ID0278_ENS_installiert','ENS installiert'),
        @(279,'ID0279_Sicherheit_aktualisiert','Sicherheit aktualisiert'),
        @(280,'ID0280_ENS_Version','ENS Version')
    )

    foreach ($Definition in $RequiredCheckDefinitions) {
        $Key = [string]$Definition[1]
        if (-not $Checks.Contains($Key)) {
            Add-Check -Key $Key -Id ([int]$Definition[0]) -Title ([string]$Definition[2]) `
                -Status 'NICHT_PRUEFBAR' `
                -Details 'Fuer diese ID wurde aufgrund fehlender Konfiguration oder eines internen Abfragefehlers kein Ergebnis erzeugt.'
        }
    }

    $Fqdn = ''
    try {
        $Fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
    }
    catch {}

    $Workgroup = ''
    if (-not [bool]$ComputerSystem.PartOfDomain) {
        $Workgroup = [string]$ComputerSystem.Workgroup
    }

    $Result = [ordered]@{
        target_timestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
        ip                = $TargetIp
        ansible_reachable = $true
        computername      = $ComputerName
        fqdn              = $Fqdn
        domain            = [string]$ComputerSystem.Domain
        workgroup         = $Workgroup
        part_of_domain    = [bool]$ComputerSystem.PartOfDomain
        os_caption        = [string]$OperatingSystem.Caption
        os_version        = [string]$OperatingSystem.Version
        winrm_port        = $WinRmPort
        winrm_scheme      = $WinRmScheme
        winrm_open_ports  = $WinRmOpenPorts
        roles             = [ordered]@{
            epo_server   = $IsEpoServer
            ens_endpoint = $IsEnsEndpoint
        }
        checks            = $Checks
        error             = $null
    }

    $Json = $Result | ConvertTo-Json -Depth 50 -Compress
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($ResultJsonPath, $Json, $Utf8NoBom)

    Write-Output "IPC_EPO_PLATFORM_RESULT_JSON=$ResultJsonPath"
    exit 0
}
catch {
    $ErrorResult = [ordered]@{
        target_timestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
        ip                = ''
        ansible_reachable = $true
        computername      = $env:COMPUTERNAME
        fqdn              = ''
        domain            = ''
        workgroup         = ''
        part_of_domain    = ''
        os_caption        = ''
        os_version        = ''
        winrm_port        = ''
        winrm_scheme      = ''
        winrm_open_ports  = ''
        roles             = @{}
        checks            = @{}
        error             = $_.Exception.Message
    }

    try {
        $Json = $ErrorResult | ConvertTo-Json -Depth 20 -Compress
        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($ResultJsonPath, $Json, $Utf8NoBom)
    }
    catch {}

    Write-Error $_.Exception.Message
    exit 1
}
