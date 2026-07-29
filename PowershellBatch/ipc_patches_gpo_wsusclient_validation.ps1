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

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    return $property.Value
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
        [ValidateSet('OK', 'NOK', 'INDIREKT', 'NICHT_PRUEFBAR', 'ISTWERT')]
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

function Normalize-Thumbprint {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    return (($Value -replace '\s', '').ToUpperInvariant())
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

    # ------------------------------------------------------------------
    # IDs 0070 und 0171: gleicher technischer Zielzustand
    # WSUS-Zertifikat im lokalen Zertifikatspeicher vorhanden.
    # ------------------------------------------------------------------
    $CertificateStoreLocation = [string](Get-ConfigValue -Object $Config -Name 'CertificateStoreLocation' -Default 'LocalMachine')
    $CertificateStoreName = [string](Get-ConfigValue -Object $Config -Name 'CertificateStoreName' -Default 'Root')
    $CertificateSubjectRegex = [string](Get-ConfigValue -Object $Config -Name 'CertificateSubjectRegex' -Default '(?i)CN=WSUS01(?:,|$)')
    $CertificateThumbprint = Normalize-Thumbprint ([string](Get-ConfigValue -Object $Config -Name 'CertificateThumbprint' -Default ''))
    $CertificateMinValidUntilText = [string](Get-ConfigValue -Object $Config -Name 'CertificateMinValidUntil' -Default '')

    $CertificateStatus = 'NICHT_PRUEFBAR'
    $CertificateDetails = ''
    $CertificateEvidence = [ordered]@{
        store_path       = "Cert:\$CertificateStoreLocation\$CertificateStoreName"
        subject_regex    = $CertificateSubjectRegex
        thumbprint       = $CertificateThumbprint
        min_valid_until  = $CertificateMinValidUntilText
        matching_certs   = @()
    }

    try {
        $CertificateStorePath = "Cert:\$CertificateStoreLocation\$CertificateStoreName"
        if (-not (Test-Path -LiteralPath $CertificateStorePath)) {
            throw "Zertifikatsspeicher nicht gefunden: $CertificateStorePath"
        }

        $MatchingCertificates = @(Get-ChildItem -LiteralPath $CertificateStorePath -ErrorAction Stop | Where-Object {
            $SubjectMatches = $true
            if (-not [string]::IsNullOrWhiteSpace($CertificateSubjectRegex)) {
                $SubjectMatches = ([string]$_.Subject -match $CertificateSubjectRegex)
            }

            $ThumbprintMatches = $true
            if (-not [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
                $ThumbprintMatches = ((Normalize-Thumbprint ([string]$_.Thumbprint)) -eq $CertificateThumbprint)
            }

            $SubjectMatches -and $ThumbprintMatches
        })

        $CertificateEvidence.matching_certs = @($MatchingCertificates | ForEach-Object {
            [ordered]@{
                subject       = [string]$_.Subject
                issuer        = [string]$_.Issuer
                thumbprint    = Normalize-Thumbprint ([string]$_.Thumbprint)
                not_before    = $_.NotBefore.ToString('yyyy-MM-ddTHH:mm:sszzz')
                not_after     = $_.NotAfter.ToString('yyyy-MM-ddTHH:mm:sszzz')
                has_private_key = [bool]$_.HasPrivateKey
            }
        })

        if ($MatchingCertificates.Count -eq 0) {
            $CertificateStatus = 'NOK'
            $CertificateDetails = "Kein passendes Zertifikat in $CertificateStorePath gefunden."
        }
        else {
            $Now = Get-Date
            $MinimumValidUntil = $null
            if (-not [string]::IsNullOrWhiteSpace($CertificateMinValidUntilText)) {
                $ParsedDate = [datetime]::MinValue
                if ([datetime]::TryParse($CertificateMinValidUntilText, [ref]$ParsedDate)) {
                    $MinimumValidUntil = $ParsedDate
                }
                else {
                    throw "CertificateMinValidUntil ist kein gueltiges Datum: $CertificateMinValidUntilText"
                }
            }

            $ValidCertificates = @($MatchingCertificates | Where-Object {
                $DateValid = ($_.NotBefore -le $Now -and $_.NotAfter -gt $Now)
                $MinimumDateValid = ($null -eq $MinimumValidUntil -or $_.NotAfter -ge $MinimumValidUntil)
                $DateValid -and $MinimumDateValid
            })

            if ($ValidCertificates.Count -gt 0) {
                $CertificateStatus = 'OK'
                $CertificateDetails = "Passendes und zeitlich gueltiges WSUS-Zertifikat gefunden; Anzahl=$($ValidCertificates.Count)."
            }
            else {
                $CertificateStatus = 'NOK'
                $CertificateDetails = 'Passendes Zertifikat gefunden, aber Gueltigkeitszeitraum bzw. Mindestablaufdatum entspricht nicht dem Soll.'
            }
        }
    }
    catch {
        $CertificateStatus = 'NICHT_PRUEFBAR'
        $CertificateDetails = "Zertifikatspruefung fehlgeschlagen: $($_.Exception.Message)"
        $CertificateEvidence['error'] = $_.Exception.Message
    }

    Add-Check -Key 'ID0070_WSUS_Zertifikat' -Id 70 -Title 'WSUS-Zertifikat in Zertifikatspeicher aufnehmen' -Status $CertificateStatus -Details $CertificateDetails -Evidence $CertificateEvidence
    Add-Check -Key 'ID0171_SSL_Zertifikat' -Id 171 -Title 'SSL-Zertifikat importieren' -Status $CertificateStatus -Details ("Gleicher technischer Nachweis wie ID 0070. " + $CertificateDetails) -Evidence $CertificateEvidence

    # ------------------------------------------------------------------
    # IDs 0072 und 0075: konkrete KBs. Es wird keine allgemeine
    # Windows-Update-Suche aus 0030 wiederholt.
    # ------------------------------------------------------------------
    $ExpectedHotfixes = @(Convert-ToArray (Get-ConfigValue -Object $Config -Name 'ExpectedHotfixes' -Default @()))
    $QfeEntries = @()
    $CbsPackageNames = @()
    $HotfixCollectionError = ''

    try {
        $QfeEntries = @(Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop | ForEach-Object {
            [ordered]@{
                hotfix_id   = [string]$_.HotFixID
                description = [string]$_.Description
                installed_on = [string]$_.InstalledOn
                installed_by = [string]$_.InstalledBy
            }
        })
    }
    catch {
        $HotfixCollectionError = "Win32_QuickFixEngineering: $($_.Exception.Message)"
    }

    try {
        $CbsPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages'
        if (Test-Path -LiteralPath $CbsPath) {
            $CbsPackageNames = @(Get-ChildItem -LiteralPath $CbsPath -ErrorAction Stop | Select-Object -ExpandProperty PSChildName)
        }
    }
    catch {
        if (-not [string]::IsNullOrWhiteSpace($HotfixCollectionError)) {
            $HotfixCollectionError += ' | '
        }
        $HotfixCollectionError += "CBS-Packages: $($_.Exception.Message)"
    }

    foreach ($ExpectedHotfix in $ExpectedHotfixes) {
        $CheckId = [int](Get-ConfigValue -Object $ExpectedHotfix -Name 'Id' -Default 0)
        $Kb = ([string](Get-ConfigValue -Object $ExpectedHotfix -Name 'Kb' -Default '')).Trim().ToUpperInvariant()
        $Title = [string](Get-ConfigValue -Object $ExpectedHotfix -Name 'Title' -Default $Kb)
        $CheckKey = [string](Get-ConfigValue -Object $ExpectedHotfix -Name 'CheckKey' -Default ("ID{0:D4}_{1}" -f $CheckId, $Kb))

        if ($CheckId -le 0 -or [string]::IsNullOrWhiteSpace($Kb)) {
            continue
        }

        $QfeMatches = @($QfeEntries | Where-Object { ([string]$_.hotfix_id).ToUpperInvariant() -eq $Kb })
        $CbsMatches = @($CbsPackageNames | Where-Object { ([string]$_).ToUpperInvariant() -match [regex]::Escape($Kb) })
        $Installed = ($QfeMatches.Count -gt 0 -or $CbsMatches.Count -gt 0)

        $HotfixEvidence = [ordered]@{
            expected_kb      = $Kb
            qfe_matches      = $QfeMatches
            cbs_matches      = $CbsMatches
            collection_error = $HotfixCollectionError
        }

        if ($QfeEntries.Count -eq 0 -and $CbsPackageNames.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($HotfixCollectionError)) {
            Add-Check -Key $CheckKey -Id $CheckId -Title $Title -Status 'NICHT_PRUEFBAR' -Details "Installationsstatus von $Kb konnte nicht ausgelesen werden." -Evidence $HotfixEvidence
        }
        elseif ($Installed) {
            Add-Check -Key $CheckKey -Id $CheckId -Title $Title -Status 'OK' -Details "$Kb ist installiert bzw. im Component-Based-Servicing registriert." -Evidence $HotfixEvidence
        }
        else {
            Add-Check -Key $CheckKey -Id $CheckId -Title $Title -Status 'NOK' -Details "$Kb wurde weder in Win32_QuickFixEngineering noch in den CBS-Paketen gefunden." -Evidence $HotfixEvidence
        }
    }

    # ------------------------------------------------------------------
    # ID 0176: wirksamer Registry-Zustand der lokalen/domainbasierten GPO.
    # Deaktiviert entspricht ElevateNonAdmins = 0.
    # ------------------------------------------------------------------
    $UpdatePolicyRegistryPath = [string](Get-ConfigValue -Object $Config -Name 'UpdatePolicyRegistryPath' -Default 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate')
    $UpdatePolicyValueName = [string](Get-ConfigValue -Object $Config -Name 'UpdatePolicyValueName' -Default 'ElevateNonAdmins')
    $ExpectedUpdatePolicyValue = [int](Get-ConfigValue -Object $Config -Name 'ExpectedUpdatePolicyValue' -Default 0)

    $ActualUpdatePolicyValue = Get-RegValueSafe -Path $UpdatePolicyRegistryPath -Name $UpdatePolicyValueName
    $UpdatePolicyEvidence = [ordered]@{
        registry_path = $UpdatePolicyRegistryPath
        value_name    = $UpdatePolicyValueName
        expected      = $ExpectedUpdatePolicyValue
        actual        = $ActualUpdatePolicyValue
    }

    if ($null -eq $ActualUpdatePolicyValue) {
        $UpdatePolicyStatus = 'NOK'
        $UpdatePolicyDetails = "GPO-Registrywert $UpdatePolicyValueName ist nicht gesetzt. Erwartet=$ExpectedUpdatePolicyValue (explizit deaktiviert)."
    }
    elseif ([int]$ActualUpdatePolicyValue -eq $ExpectedUpdatePolicyValue) {
        $UpdatePolicyStatus = 'OK'
        $UpdatePolicyDetails = "Updatebenachrichtigungen fuer Nichtadministratoren entsprechen dem Soll: Ist=$ActualUpdatePolicyValue, Soll=$ExpectedUpdatePolicyValue."
    }
    else {
        $UpdatePolicyStatus = 'NOK'
        $UpdatePolicyDetails = "Updatebenachrichtigungen fuer Nichtadministratoren entsprechen nicht dem Soll: Ist=$ActualUpdatePolicyValue, Soll=$ExpectedUpdatePolicyValue."
    }

    Add-Check -Key 'ID0176_Updatebenachrichtigungen_Nichtadministratoren' -Id 176 -Title 'Lokale GPO fuer Updatebenachrichtigungen konfigurieren' -Status $UpdatePolicyStatus -Details $UpdatePolicyDetails -Evidence $UpdatePolicyEvidence

    # ------------------------------------------------------------------
    # IDs 0173 und 0178: gpupdate /force ist eine historische Aktion.
    # Kein erneutes gpupdate. Indirekter Nachweis ueber wirksamen Sollzustand
    # aus ID 0176 und letzten Group-Policy-Verarbeitungszeitpunkt.
    # ------------------------------------------------------------------
    $GroupPolicyOperationalLogName = [string](Get-ConfigValue -Object $Config -Name 'GroupPolicyOperationalLogName' -Default 'Microsoft-Windows-GroupPolicy/Operational')
    $LatestGroupPolicyEvent = $null
    $GroupPolicyEventError = ''

    try {
        $LatestEvent = Get-WinEvent -LogName $GroupPolicyOperationalLogName -MaxEvents 1 -ErrorAction Stop
        if ($null -ne $LatestEvent) {
            $LatestGroupPolicyEvent = [ordered]@{
                log_name      = $GroupPolicyOperationalLogName
                event_id      = [int]$LatestEvent.Id
                time_created  = $LatestEvent.TimeCreated.ToString('yyyy-MM-ddTHH:mm:sszzz')
                provider_name = [string]$LatestEvent.ProviderName
                level         = [string]$LatestEvent.LevelDisplayName
            }
        }
    }
    catch {
        $GroupPolicyEventError = $_.Exception.Message
    }

    $GpUpdateEvidence = [ordered]@{
        direct_execution_checked = $false
        effective_policy_status  = $UpdatePolicyStatus
        effective_policy         = $UpdatePolicyEvidence
        latest_group_policy_event = $LatestGroupPolicyEvent
        event_log_error          = $GroupPolicyEventError
    }

    if ($UpdatePolicyStatus -eq 'OK') {
        $GpUpdateStatus = 'INDIREKT'
        $GpUpdateDetails = 'gpupdate /force wird nicht erneut ausgefuehrt und ist historisch nicht direkt beweisbar. Die geforderte Richtlinie aus ID 0176 ist jedoch wirksam.'
        if ($null -ne $LatestGroupPolicyEvent) {
            $GpUpdateDetails += " Letzte Gruppenrichtlinienverarbeitung: $($LatestGroupPolicyEvent.time_created), Ereignis-ID $($LatestGroupPolicyEvent.event_id)."
        }
    }
    elseif ($UpdatePolicyStatus -eq 'NOK') {
        $GpUpdateStatus = 'NOK'
        $GpUpdateDetails = 'Der geforderte resultierende GPO-Zustand aus ID 0176 ist nicht wirksam; deshalb kann der gpupdate-Schritt nicht als erfolgreich nachgewiesen werden.'
    }
    else {
        $GpUpdateStatus = 'NICHT_PRUEFBAR'
        $GpUpdateDetails = 'Die Wirksamkeit der zu aktualisierenden GPO konnte nicht bewertet werden.'
    }

    Add-Check -Key 'ID0173_gpupdate_force' -Id 173 -Title 'gpupdate /force ausfuehren' -Status $GpUpdateStatus -Details $GpUpdateDetails -Evidence $GpUpdateEvidence
    Add-Check -Key 'ID0178_gpupdate_force' -Id 178 -Title 'gpupdate /force ausfuehren' -Status $GpUpdateStatus -Details ("Gleicher indirekter Nachweis wie ID 0173. " + $GpUpdateDetails) -Evidence $GpUpdateEvidence

    $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem

    $Fqdn = $null
    try {
        $Fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
    }
    catch {}

    $Workgroup = $null
    if (-not [bool]$ComputerSystem.PartOfDomain) {
        $Workgroup = [string]$ComputerSystem.Workgroup
    }

    $Result = [ordered]@{
        target_timestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
        ip                = $TargetIp
        ansible_reachable = $true
        computername      = $env:COMPUTERNAME
        fqdn              = $Fqdn
        domain            = [string]$ComputerSystem.Domain
        workgroup         = $Workgroup
        part_of_domain    = [bool]$ComputerSystem.PartOfDomain
        os_caption        = [string]$OperatingSystem.Caption
        os_version        = [string]$OperatingSystem.Version
        winrm_port        = $WinRmPort
        winrm_scheme      = $WinRmScheme
        winrm_open_ports  = $WinRmOpenPorts
        checks            = $Checks
        error             = $null
    }

    $Json = $Result | ConvertTo-Json -Depth 30 -Compress
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($ResultJsonPath, $Json, $Utf8NoBom)

    Write-Output "IPC_PATCHES_GPO_WSUSCLIENT_RESULT_JSON=$ResultJsonPath"
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
