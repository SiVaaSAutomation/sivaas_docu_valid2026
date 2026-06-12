$ErrorActionPreference = "SilentlyContinue"

$ResultJsonPath = {{ remote_validation_json | to_json }}
$ResultDir = Split-Path -Path $ResultJsonPath -Parent

if (-not (Test-Path $ResultDir)) {
    New-Item -Path $ResultDir -ItemType Directory -Force | Out-Null
}

trap {
    $err = $_

    $fallbackResult = [ordered]@{
        scan_timestamp = "{{ hostvars['localhost']['report_timestamp_iso'] | default('') }}"
        target_timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
        ip = "{{ inventory_hostname }}"
        ansible_reachable = $true
        computername = $env:COMPUTERNAME
        fqdn = ""
        domain = ""
        workgroup = ""
        part_of_domain = $false
        os_caption = ""
        os_version = ""
        winrm_port = "{{ ansible_port | default('') }}"
        winrm_scheme = "{{ ansible_winrm_scheme | default('') }}"
        winrm_open_ports = "{{ discovered_winrm_open_ports | default('') }}"
        checks = [ordered]@{}
        error = "PowerShell-Pruefskript abgebrochen: $($err.Exception.Message); Zeile=$($err.InvocationInfo.ScriptLineNumber)"
    }

    $json = $fallbackResult | ConvertTo-Json -Depth 20 -Compress
    $Utf8NoBom = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText($ResultJsonPath, $json, $Utf8NoBom)

    Write-Output "OS_SERVER_ERROR_JSON=$ResultJsonPath"
    exit 2
}

function Convert-JsonVar {
param([string]$Json)
if ([string]::IsNullOrWhiteSpace($Json)) { return $null }
return ($Json | ConvertFrom-Json)
}

$ExpectedPresentAdapters = @(Convert-JsonVar '{{ expected_present_adapters | to_json }}')
$ExpectedAbsentAdapters = @(Convert-JsonVar '{{ expected_absent_adapters | to_json }}')
$AllowedEnabledAdapterNames = @(Convert-JsonVar '{{ allowed_enabled_adapter_names | to_json }}')
$ExpectedVncIniPaths = @(Convert-JsonVar '{{ expected_vnc_ini_paths | to_json }}')
$ExpectedBgInfoPaths = @(Convert-JsonVar '{{ expected_bginfo_paths | to_json }}')
$ExpectedPcs7Groups = @(Convert-JsonVar '{{ expected_pcs7_groups | to_json }}')
$ExpectedNtpWizardPaths = @(Convert-JsonVar '{{ expected_ntp_wizard_paths | to_json }}')
$ExpectedHotfixIds = @(Convert-JsonVar '{{ expected_hotfix_ids | to_json }}')
$ExpectedHostsLmhostsEntries = @(Convert-JsonVar '{{ expected_hosts_lmhosts_entries | to_json }}')

$ExpectedTimeZoneId = {{ expected_timezone_id | to_json }}
$ExpectedPasswordComplexity = [int]{{ expected_password_complexity }}
$ExpectedMinPasswordLength = [int]{{ expected_min_password_length }}
$ExpectedMaxPasswordAgeDays = [int]{{ expected_max_password_age_days }}
$ExpectedMinPasswordAgeDays = [int]{{ expected_min_password_age_days }}
$ExpectedEventlogMaxBytes = [int64]{{ expected_eventlog_max_kb }} * 1024
$ExpectedScreenWidth = [int]{{ expected_screen_width }}
$ExpectedScreenHeight = [int]{{ expected_screen_height }}
$ExpectedPowerPlanRegex = {{ expected_power_plan_regex | to_json }}
$HostsLmhostsRequired = ${{ hosts_lmhosts_required | bool | ternary('true','false') }}
$ExpectedHostsLmhostsMinDate109 = {{ expected_hosts_lmhosts_min_date_109 | to_json }}
$ExpectedHostsLmhostsMinDate112 = {{ expected_hosts_lmhosts_min_date_112 | to_json }}
$ExpectedBgInfoRunContains = {{ expected_bginfo_run_contains | to_json }}
$ExpectedPcs7User = {{ expected_pcs7_user | to_json }}
$ExpectedProjectFolder = {{ expected_project_folder | to_json }}
$ExpectedProjectShare = {{ expected_project_share | to_json }}
$NtpWizardRequired = ${{ ntp_wizard_required | bool | ternary('true','false') }}
$ExpectedWsusServer = {{ expected_wsus_server | to_json }}
$ExpectedWsusTargetGroup = {{ expected_wsus_target_group | to_json }}
$ExpectedEdgeVersion = {{ expected_edge_version | to_json }}
$PerformWindowsUpdateSearch = ${{ perform_windows_update_search | bool | ternary('true','false') }}

$checks = [ordered]@{}

function Add-Check {
param(
    [string]$Key,
    [int]$Id,
    [string]$Title,
    [string]$Status,
    [string]$Details,
    [object]$Evidence = $null
)
$script:checks[$Key] = [ordered]@{
    id = $Id
    title = $Title
    status = $Status
    details = $Details
    evidence = $Evidence
}
}

function Join-Text {
param([object]$Value, [string]$Sep = ", ")
if ($null -eq $Value) { return "" }
if ($Value -is [array]) { return (($Value | Where-Object { $_ -ne $null -and "$($_)" -ne "" }) -join $Sep) }
return [string]$Value
}

function Get-RegValue {
param([string]$Path, [string]$Name)
try { return (Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop) } catch { return $null }
}

function Get-UninstallPrograms {
$roots = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)
foreach ($root in $roots) {
    if (Test-Path $root) {
    Get-ChildItem -Path $root | ForEach-Object {
        $props = Get-ItemProperty -Path $_.PSPath
        if ($props.DisplayName) {
        [pscustomobject]@{
            Name = [string]$props.DisplayName
            Version = [string]$props.DisplayVersion
            Publisher = [string]$props.Publisher
            InstallLocation = [string]$props.InstallLocation
        }
        }
    }
    }
}
}

function Test-FirewallLocalPort {
param([int]$Port)
$matches = @()
$rules = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue)
foreach ($rule in $rules) {
    $pf = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
    foreach ($p in @($pf)) {
    $local = [string]$p.LocalPort
    $proto = [string]$p.Protocol
    if (($proto -eq "TCP" -or $proto -eq "Any") -and ($local -eq "$Port" -or $local -eq "Any")) {
        $matches += [pscustomobject]@{ DisplayName = $rule.DisplayName; Profile = [string]$rule.Profile; LocalPort = $local; Protocol = $proto }
    }
    }
}
return $matches
}

function Get-NormalizedFileLines {
param([string]$Path)
if (-not (Test-Path $Path)) { return @() }
return @(Get-Content -Path $Path -ErrorAction SilentlyContinue |
    ForEach-Object { ($_ -replace "\s+#.*$", "").Trim() } |
    Where-Object { $_ -ne "" -and -not $_.StartsWith("#") })
}

function Test-HostsLmhosts {
param([string]$MinDateIso = "")
$hostsPath = "$env:WINDIR\System32\drivers\etc\hosts"
$lmhostsPath = "$env:WINDIR\System32\drivers\etc\lmhosts"
if (-not (Test-Path $lmhostsPath) -and (Test-Path "$lmhostsPath.sam")) {
    $lmhostsPath = "$lmhostsPath.sam"
}

$hostsExists = Test-Path $hostsPath
$lmhostsExists = Test-Path $lmhostsPath
$hostsLines = @(Get-NormalizedFileLines $hostsPath)
$lmhostsLines = @(Get-NormalizedFileLines $lmhostsPath)
$sameContent = (($hostsLines -join "|") -eq ($lmhostsLines -join "|"))
$entriesOk = $true
$missingEntries = @()
foreach ($entry in $ExpectedHostsLmhostsEntries) {
    if (($hostsLines -join "`n") -notmatch [regex]::Escape([string]$entry) -and ($lmhostsLines -join "`n") -notmatch [regex]::Escape([string]$entry)) {
    $entriesOk = $false
    $missingEntries += [string]$entry
    }
}

$dateOk = $true
$dateText = ""
if (-not [string]::IsNullOrWhiteSpace($MinDateIso)) {
    $minDate = [datetime]$MinDateIso
    $hostDate = if ($hostsExists) { (Get-Item $hostsPath).LastWriteTime } else { $null }
    $lmDate = if ($lmhostsExists) { (Get-Item $lmhostsPath).LastWriteTime } else { $null }
    $dateOk = ($hostDate -ge $minDate) -and ($lmDate -ge $minDate)
    $dateText = "Mindestdatum=$MinDateIso; hosts=$hostDate; lmhosts=$lmDate"
}

[pscustomobject]@{
    HostsPath = $hostsPath
    LmhostsPath = $lmhostsPath
    HostsExists = $hostsExists
    LmhostsExists = $lmhostsExists
    SameContent = $sameContent
    EntriesOk = $entriesOk
    MissingEntries = $missingEntries
    DateOk = $dateOk
    DateText = $dateText
    Ok = ($hostsExists -and $lmhostsExists -and $sameContent -and $entriesOk -and $dateOk)
}
}

$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$programs = @(Get-UninstallPrograms)

$fqdn = $null
try { $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch {}

# 21 Kennwortrichtlinie
$securityCfg = Join-Path $env:TEMP "ansible_secpol_export.inf"
secedit /export /cfg $securityCfg | Out-Null
$secLines = @{}
if (Test-Path $securityCfg) {
Get-Content $securityCfg | ForEach-Object {
    if ($_ -match "^\s*([^=]+?)\s*=\s*(.*?)\s*$") { $secLines[$Matches[1].Trim()] = $Matches[2].Trim() }
}
}
$pwComplexity = [int]($secLines["PasswordComplexity"] | ForEach-Object { if ($_ -ne $null) { $_ } else { -1 } })
$minPwLen = [int]($secLines["MinimumPasswordLength"] | ForEach-Object { if ($_ -ne $null) { $_ } else { -1 } })
$maxPwAge = [int]($secLines["MaximumPasswordAge"] | ForEach-Object { if ($_ -ne $null) { $_ } else { -1 } })
$minPwAge = [int]($secLines["MinimumPasswordAge"] | ForEach-Object { if ($_ -ne $null) { $_ } else { -1 } })
$ok21 = ($pwComplexity -eq $ExpectedPasswordComplexity -and $minPwLen -eq $ExpectedMinPasswordLength -and $maxPwAge -eq $ExpectedMaxPasswordAgeDays -and $minPwAge -eq $ExpectedMinPasswordAgeDays)
Add-Check "ID21_Kennwortrichtlinie" 21 "Kennwortrichtlinie anpassen" $(if($ok21){"OK"}else{"NOK"}) "PasswordComplexity=$pwComplexity; MinimumPasswordLength=$minPwLen; MaximumPasswordAge=$maxPwAge; MinimumPasswordAge=$minPwAge"

# 23 lokaler Administrator SID-500
$admin500 = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" | Where-Object { $_.SID -match "-500$" } | Select-Object -First 1
$ok23 = ($admin500 -and -not $admin500.Disabled -and -not $admin500.PasswordExpires)
Add-Check "ID23_Admin_Konto" 23 "Bestehendes Administrator-Konto aktivieren und Passwort vergeben" $(if($ok23){"OK"}else{"NOK"}) "Name=$($admin500.Name); Disabled=$($admin500.Disabled); PasswordExpires=$($admin500.PasswordExpires)"

# 30 Shutdown Event Tracker deaktiviert
$shutdownReasonOn = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" "ShutdownReasonOn"
$shutdownReasonUI = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" "ShutdownReasonUI"
$ok30 = (($shutdownReasonOn -eq 0 -or $null -eq $shutdownReasonOn) -and ($shutdownReasonUI -eq 0 -or $null -eq $shutdownReasonUI))
Add-Check "ID30_Shutdown_Eventlog" 30 "Ereignisprotokollierung fuer Herunterfahren" $(if($ok30){"OK"}else{"NOK"}) "ShutdownReasonOn=$shutdownReasonOn; ShutdownReasonUI=$shutdownReasonUI"

# 31 Windows-Zeitgeber
$w32 = Get-Service W32Time -ErrorAction SilentlyContinue
$w32reg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time" -ErrorAction SilentlyContinue
$ok31 = ($w32 -and $w32.Status -eq "Running" -and $w32.StartType -eq "Automatic" -and $w32reg.DelayedAutoStart -eq 1)
Add-Check "ID31_Windows_Zeitgeber" 31 "Windows-Zeitgeber" $(if($ok31){"OK"}else{"NOK"}) "Status=$($w32.Status); StartType=$($w32.StartType); DelayedAutoStart=$($w32reg.DelayedAutoStart)"

# 32 Eventlog-Groesse
$logNames = @("Application","System","Security")
$logInfo = @()
$smallLogs = @()
foreach ($ln in $logNames) {
$li = Get-WinEvent -ListLog $ln -ErrorAction SilentlyContinue
$logInfo += "$ln=$($li.MaximumSizeInBytes)"
if ($li.MaximumSizeInBytes -lt $ExpectedEventlogMaxBytes) { $smallLogs += $ln }
}
Add-Check "ID32_Eventlog_Groesse" 32 "Maximale Ereignisprotokollgroesse" $(if($smallLogs.Count -eq 0){"OK"}else{"NOK"}) (($logInfo -join "; ") + "; Erwartet_min_Bytes=$ExpectedEventlogMaxBytes")

# 33 Lifebeat Monitoring / DCOM-Berechtigungen
$dcomCandidate = Get-ChildItem "Registry::HKEY_CLASSES_ROOT\AppID" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "CCDmRtChannelHost" } | Select-Object -First 1
Add-Check "ID33_Lifebeat_DCOM" 33 "Lifebeat Monitoring" "NICHT_PRUEFBAR" "DCOM-Berechtigungs-ACLs sind binaer gespeichert und werden hier nicht belastbar bewertet; AppID-Kandidat=$($dcomCandidate.Name)"

# 35 Zeitzone
$tz = Get-TimeZone
$ok35 = ($tz.Id -eq $ExpectedTimeZoneId)
Add-Check "ID35_Zeitzone" 35 "Zeitzone" $(if($ok35){"OK"}else{"NOK"}) "Ist=$($tz.Id); Erwartet=$ExpectedTimeZoneId"

# 36 Starten und Wiederherstellen
$autoReboot = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" "AutoReboot"
$bootMgr = (bcdedit /enum '{bootmgr}' 2>$null) -join " | "
$ok36 = ($autoReboot -eq 1)
Add-Check "ID36_Starten_Wiederherstellen" 36 "Starten und Wiederherstellen anpassen" $(if($ok36){"TEILWEISE"}else{"NOK"}) "Automatischer Neustart=$autoReboot; BCD-Auszug=$bootMgr; GUI-Optionen werden nur teilweise automatisch bewertet"

# 37 Netzwerkidentifikation
$profiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)
$nonPrivate = @($profiles | Where-Object { $_.NetworkCategory -ne "Private" })
$ok37 = ($profiles.Count -gt 0 -and $nonPrivate.Count -eq 0)
Add-Check "ID37_Netzwerkidentifikation" 37 "Netzwerkidentifikation einstellen" $(if($ok37){"OK"}else{"NOK"}) ("Profile=" + (($profiles | ForEach-Object { "$($_.Name):$($_.NetworkCategory)" }) -join ", "))

# Netzwerkadapter / SIMATIC Shell-nahe Pruefungen
$adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue)
$adapterNames = @($adapters | ForEach-Object { $_.Name })
$missingPresent = @($ExpectedPresentAdapters | Where-Object { $adapterNames -notcontains $_ })
$presentAbsent = @($ExpectedAbsentAdapters | Where-Object { $adapterNames -contains $_ })
$enabledHardwareAdapters = @($adapters | Where-Object { $_.Status -ne "Disabled" -and $_.HardwareInterface })
$unexpectedEnabled = @()
if ($AllowedEnabledAdapterNames.Count -gt 0) {
$unexpectedEnabled = @($enabledHardwareAdapters | Where-Object { $AllowedEnabledAdapterNames -notcontains $_.Name } | ForEach-Object { $_.Name })
}
Add-Check "ID38_Terminalbus_SimaticShell" 38 "Terminalbus in Simatic Shell" $(if($ExpectedPresentAdapters -contains "Terminalbus" -and $adapterNames -contains "Terminalbus"){"TEILWEISE"}else{"NOK"}) "Adapter Terminalbus vorhanden; SIMATIC-Shell-Farbe wird nicht automatisiert bewertet"
Add-Check "ID40_Redundanzbus_SimaticShell" 40 "Redundanzbus in Simatic Shell" $(if($ExpectedPresentAdapters -contains "Redundanzbus" -and $adapterNames -contains "Redundanzbus"){"TEILWEISE"}else{"NOK"}) "Adapter Redundanzbus vorhanden; SIMATIC-Shell-Konfiguration wird nicht automatisiert bewertet"
Add-Check "ID43_Ueberfluessige_NICs" 43 "Ueberfluessige Netzwerkkarten entfernen" $(if($unexpectedEnabled.Count -eq 0){"OK"}else{"NOK"}) "Aktive Hardwareadapter=$((Join-Text ($enabledHardwareAdapters | ForEach-Object {$_.Name}))); Nicht erlaubt=$((Join-Text $unexpectedEnabled)); Erlaubt=$((Join-Text $AllowedEnabledAdapterNames))"
Add-Check "ID44_Anlagenbus_entfernen" 44 "Anlagenbus entfernen" $(if($presentAbsent.Count -eq 0){"OK"}else{"NOK"}) "Soll fehlen=$((Join-Text $ExpectedAbsentAdapters)); Gefunden=$((Join-Text $presentAbsent))"
Add-Check "ID45_Ueberfluessige_NICs_Anlagenbus" 45 "Ueberfluessige Netzwerkkarten entfernen" $(if($presentAbsent.Count -eq 0 -and $unexpectedEnabled.Count -eq 0){"OK"}else{"NOK"}) "Unerwuenschte Adapter=$((Join-Text ($presentAbsent + $unexpectedEnabled)))"

# 47/109/112 HOSTS/LMHOSTS
$hosts47 = Test-HostsLmhosts ""
if (-not $HostsLmhostsRequired -and $cs.PartOfDomain) {
Add-Check "ID47_HOSTS_LMHOSTS" 47 "HOSTS/LMHOSTS anpassen bzw. aktualisieren" "NICHT_ERFORDERLICH" "Domaenenmitglied; laut Tabelle bei Domaene nicht erforderlich"
} else {
Add-Check "ID47_HOSTS_LMHOSTS" 47 "HOSTS/LMHOSTS anpassen bzw. aktualisieren" $(if($hosts47.Ok){"OK"}else{"NOK"}) "HostsExists=$($hosts47.HostsExists); LmhostsExists=$($hosts47.LmhostsExists); SameContent=$($hosts47.SameContent); Missing=$((Join-Text $hosts47.MissingEntries))"
}
$hosts109 = Test-HostsLmhosts $ExpectedHostsLmhostsMinDate109
Add-Check "ID109_HOSTS_LMHOSTS" 109 "Hosts/LmHosts aktualisieren" $(if($hosts109.Ok){"OK"}else{"NOK"}) "Zeitstempelpruefung ID109: $($hosts109.DateText); SameContent=$($hosts109.SameContent)"
$hosts112 = Test-HostsLmhosts $ExpectedHostsLmhostsMinDate112
Add-Check "ID112_HOSTS_LMHOSTS" 112 "Hosts/LmHosts aktualisieren" $(if($hosts112.Ok){"OK"}else{"NOK"}) "Zeitstempelpruefung ID112: $($hosts112.DateText); SameContent=$($hosts112.SameContent)"

# 48 Bildschirmaufloesung
$video = Get-CimInstance Win32_VideoController | Select-Object -First 1
if ($ExpectedScreenWidth -gt 0 -and $ExpectedScreenHeight -gt 0) {
$ok48 = ($video.CurrentHorizontalResolution -eq $ExpectedScreenWidth -and $video.CurrentVerticalResolution -eq $ExpectedScreenHeight)
Add-Check "ID48_Bildschirmaufloesung" 48 "Bildschirmaufloesung einstellen" $(if($ok48){"OK"}else{"NOK"}) "Ist=$($video.CurrentHorizontalResolution)x$($video.CurrentVerticalResolution); Erwartet=${ExpectedScreenWidth}x${ExpectedScreenHeight}"
} else {
Add-Check "ID48_Bildschirmaufloesung" 48 "Bildschirmaufloesung einstellen" "NICHT_PRUEFBAR" "expected_screen_width/expected_screen_height nicht gesetzt; Ist=$($video.CurrentHorizontalResolution)x$($video.CurrentVerticalResolution)"
}

# 49 STRG+ALT+ENTF deaktivieren
$disableCad = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD"
Add-Check "ID49_CTRL_ALT_DEL" 49 "STRG+ALT+ENTF deaktivieren" $(if($disableCad -eq 1){"OK"}else{"NOK"}) "DisableCAD=$disableCad; Erwartet=1"

# 50/51 Internetoptionen fuer geladenen Benutzerkontext
$certRevocation = Get-RegValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" "CertificateRevocation"
$zone3FileDownload = Get-RegValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" "1803"
Add-Check "ID50_IE_Zertifikatpruefung" 50 "Internetoptionen des Internet-Explorers" $(if($certRevocation -eq 0){"TEILWEISE"}else{"NOK"}) "HKCU CertificateRevocation=$certRevocation; Bewertung nur fuer aktuellen WinRM-Benutzer bzw. geladene Policies"
Add-Check "ID51_IE_Sicherheitszone" 51 "Internetoptionen" $(if($zone3FileDownload -eq 0){"TEILWEISE"}else{"NOK"}) "Zone 3 / 1803 Dateidownload=$zone3FileDownload; 0=aktiviert; Bewertung nur fuer aktuellen WinRM-Benutzer"

# 55/56/57 UltraVNC
$vncService = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "(?i)(uvnc|vnc)" -or $_.DisplayName -match "(?i)(UltraVNC|VNC)" } | Select-Object -First 1
$vncIni = $ExpectedVncIniPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
$vnc5900 = @(Test-FirewallLocalPort 5900)
$vnc5800 = @(Test-FirewallLocalPort 5800)
$vncProgramRules = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match "(?i)(UltraVNC|VNC)" })
$ok55 = ($vncService -and $vncService.Status -eq "Running" -and ($vncProgramRules.Count -gt 0 -or $vnc5900.Count -gt 0))
Add-Check "ID55_UltraVNC_Firewall" 55 "UltraVNC + Firewall Regeln" $(if($ok55){"OK"}else{"NOK"}) "Service=$($vncService.Name)/$($vncService.Status); VNC-Regeln=$($vncProgramRules.Count); Port5900-Regeln=$($vnc5900.Count)"
$iniContent = if ($vncIni) { Get-Content $vncIni -Raw -ErrorAction SilentlyContinue } else { "" }
$ok56 = ($vncIni -and $iniContent -match "(?im)^\s*MSLogonRequired\s*=\s*1" -and $iniContent -match "(?im)^\s*NewMSLogon\s*=\s*1")
Add-Check "ID56_VNC_Server_Config" 56 "VNC-Server konfigurieren" $(if($ok56){"OK"}else{"NOK"}) "INI=$vncIni; Erwartet MSLogonRequired=1 und NewMSLogon=1"
$listeners = @(Get-NetTCPConnection -State Listen -LocalPort 5900 -ErrorAction SilentlyContinue)
Add-Check "ID57_VNC_Verbindungstest" 57 "VNC-Verbindungstest" $(if($listeners.Count -gt 0){"TEILWEISE"}else{"NOK"}) "Lokaler Listener Port 5900=$($listeners.Count); externer Verbindungstest vom Controller nicht enthalten"
Add-Check "ID89_VNC5800" 89 "Kontrolle VNC Firewallregeln - VNC5800" $(if($vnc5800.Count -gt 0){"OK"}else{"NOK"}) "Inbound-Allow-Regeln fuer TCP/5800=$($vnc5800.Count)"
Add-Check "ID89_VNC5900" 89 "Kontrolle VNC Firewallregeln - VNC5900" $(if($vnc5900.Count -gt 0){"OK"}else{"NOK"}) "Inbound-Allow-Regeln fuer TCP/5900=$($vnc5900.Count)"

# 67 BGInfo
$bgPath = $ExpectedBgInfoPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
$runKeys = @(
"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
)
$bgRun = @()
foreach ($rk in $runKeys) {
if (Test-Path $rk) {
    $props = Get-ItemProperty $rk
    $props.PSObject.Properties | Where-Object { $_.Value -match [regex]::Escape($ExpectedBgInfoRunContains) } | ForEach-Object { $bgRun += "$rk\$($_.Name)=$($_.Value)" }
}
}
Add-Check "ID67_BGInfo" 67 "BGInfo" $(if($bgPath -and $bgRun.Count -gt 0){"OK"}else{"NOK"}) "Pfad=$bgPath; RunKeys=$((Join-Text $bgRun ' | '))"

# 74 PCS 7 Benutzergruppen
$groupMissing = @()
$userExists = $false
try { $userExists = $null -ne (Get-LocalUser -Name $ExpectedPcs7User -ErrorAction Stop) } catch { $userExists = $false }
foreach ($grp in $ExpectedPcs7Groups) {
$members = @(Get-LocalGroupMember -Group $grp -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
if (-not ($members -match "\\$ExpectedPcs7User$|^$ExpectedPcs7User$")) { $groupMissing += $grp }
}
Add-Check "ID74_PCS7_Benutzer" 74 "Einstellungen fuer PCS 7 Benutzer durchfuehren" $(if($userExists -and $groupMissing.Count -eq 0){"OK"}else{"NOK"}) "User=$ExpectedPcs7User Exists=$userExists; Fehlende Gruppen=$((Join-Text $groupMissing))"

# 75 Projektordner / Freigabe
$folderExists = Test-Path $ExpectedProjectFolder
$share = Get-SmbShare -Name $ExpectedProjectShare -ErrorAction SilentlyContinue
$shareOk = ($share -and ($share.Path -eq $ExpectedProjectFolder))
Add-Check "ID75_Projektordner_Freigabe" 75 "Projektordner erstellen und Freigabe einrichten" $(if($folderExists -and $shareOk){"OK"}else{"NOK"}) "Ordner=$ExpectedProjectFolder Exists=$folderExists; Share=$ExpectedProjectShare Path=$($share.Path)"

# 76 NTP Wizard
$ntpWizardFound = @()
foreach ($p in $ExpectedNtpWizardPaths) {
if (Test-Path $p) {
    $ntpWizardFound += @(Get-ChildItem -Path $p -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "(?i)ntp.*(wizard|\.exe|\.ini)" } | Select-Object -First 5 | ForEach-Object { $_.FullName })
}
}
if ($NtpWizardRequired) {
Add-Check "ID76_NTP_Wizard" 76 "NTP Wizard" $(if($ntpWizardFound.Count -gt 0){"TEILWEISE"}else{"NOK"}) "Gefundene NTP-Wizard-Dateien=$((Join-Text $ntpWizardFound ' | ')); W32Time wird separat in ID31 bewertet"
} else {
Add-Check "ID76_NTP_Wizard" 76 "NTP Wizard" "NICHT_ERFORDERLICH" "ntp_wizard_required=false; bei Domaene laut Tabelle ggf. nicht notwendig"
}

# 79 SMB Signierung
$wkReq = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature"
$srvReq = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature"
$srvEnable = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "EnableSecuritySignature"
$ok79 = ($wkReq -eq 1 -and $srvReq -eq 1 -and $srvEnable -eq 1)
Add-Check "ID79_SMB_Signierung" 79 "SMB Signierung aktivieren" $(if($ok79){"OK"}else{"NOK"}) "Workstation.Require=$wkReq; Server.Require=$srvReq; Server.Enable=$srvEnable"

# 81 SMBv3 Verschluesselung
$smbCfg = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
Add-Check "ID81_SMBv3_Verschluesselung" 81 "SMBv3-Verschluesselung" $(if($smbCfg.EncryptData -eq $true){"OK"}else{"NOK"}) "Get-SmbServerConfiguration.EncryptData=$($smbCfg.EncryptData)"

# 86 ALM als Lizenzserver
$almPrograms = @($programs | Where-Object { $_.Name -match "(?i)(Automation License Manager|ALM)" })
Add-Check "ID86_ALM_Lizenzserver" 86 "ALM als Lizenzserver konfigurieren" $(if($almPrograms.Count -gt 0){"TEILWEISE"}else{"NOK"}) "ALM-Installation gefunden=$($almPrograms.Count); Remote-Lizenzserver-Option ist ohne Siemens-spezifischen Registry-/Dateipfad nicht belastbar bewertet"

# 87 Energieoptionen
$activePlanRaw = (powercfg /getactivescheme) -join " "
$ok87 = ($activePlanRaw -match $ExpectedPowerPlanRegex)
Add-Check "ID87_Energieoptionen" 87 "Energieoptionen auf Hoechstleistung setzen" $(if($ok87){"OK"}else{"NOK"}) "Aktiver Plan=$activePlanRaw; Erwarteter Regex=$ExpectedPowerPlanRegex"

# 88 Security Controller
$secCtrlPrograms = @($programs | Where-Object { $_.Name -match "(?i)(Security Controller|PCS 7 Security|SIMATIC Security)" })
Add-Check "ID88_Security_Controller" 88 "Security Controller" $(if($secCtrlPrograms.Count -gt 0){"TEILWEISE"}else{"NICHT_PRUEFBAR"}) "Installationsnachweis=$($secCtrlPrograms.Count); Bestaetigung waehrend PCS7-Setup nicht nachtraeglich eindeutig pruefbar"

# 91 AutoRun / AutoPlay
$explorerPol = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$noDriveType = Get-RegValue $explorerPol "NoDriveTypeAutoRun"
$noAutorun = Get-RegValue $explorerPol "NoAutorun"
$ok91 = (($noDriveType -eq 255 -or $noDriveType -eq 0xFF) -and ($noAutorun -eq 1 -or $null -eq $noAutorun))
Add-Check "ID91_AutoRun_AutoPlay" 91 "AutoRun / AutoPlay deaktivieren" $(if($ok91){"OK"}else{"NOK"}) "NoDriveTypeAutoRun=$noDriveType; NoAutorun=$noAutorun; Erwartet NoDriveTypeAutoRun=255"

# 93 WSUS
$wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$auPath = "$wuPath\AU"
$wuServer = Get-RegValue $wuPath "WUServer"
$wuStatusServer = Get-RegValue $wuPath "WUStatusServer"
$targetGroup = Get-RegValue $wuPath "TargetGroup"
$auOptions = Get-RegValue $auPath "AUOptions"
$wsusServerOk = if ([string]::IsNullOrWhiteSpace($ExpectedWsusServer)) { -not [string]::IsNullOrWhiteSpace($wuServer) } else { ($wuServer -match [regex]::Escape($ExpectedWsusServer) -and $wuStatusServer -match [regex]::Escape($ExpectedWsusServer)) }
$targetGroupOk = if ([string]::IsNullOrWhiteSpace($ExpectedWsusTargetGroup)) { $true } else { $targetGroup -eq $ExpectedWsusTargetGroup }
Add-Check "ID93_WSUS" 93 "WSUS-Server konfigurieren" $(if($wsusServerOk -and $targetGroupOk){"OK"}else{"NOK"}) "WUServer=$wuServer; WUStatusServer=$wuStatusServer; TargetGroup=$targetGroup; AUOptions=$auOptions"

# 95-98 Hotfixes
foreach ($kb in $ExpectedHotfixIds) {
$hotfix = Get-HotFix -Id $kb -ErrorAction SilentlyContinue
$key = "ID" + (95 + [array]::IndexOf($ExpectedHotfixIds, $kb)) + "_" + $kb
$idNum = 95 + [array]::IndexOf($ExpectedHotfixIds, $kb)
Add-Check $key $idNum "Windows Patches/Hotfix installieren $kb" $(if($hotfix){"OK"}else{"NOK"}) "InstalledOn=$($hotfix.InstalledOn); Description=$($hotfix.Description)"
}

# 99 Edge-Version
$edgeVersion = $null
$edgePaths = @(
"HKLM:\SOFTWARE\Microsoft\Edge\BLBeacon",
"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Edge\BLBeacon"
)
foreach ($ep in $edgePaths) {
if (-not $edgeVersion) { $edgeVersion = Get-RegValue $ep "version" }
}
$ok99 = $false
try { $ok99 = ([version]$edgeVersion -ge [version]$ExpectedEdgeVersion) } catch {}
Add-Check "ID99_Edge_Update" 99 "Windows Patches/Hotfix installieren Microsoft Edge" $(if($ok99){"OK"}else{"NOK"}) "EdgeVersion=$edgeVersion; Erwartet_min=$ExpectedEdgeVersion"

# 100 PolicyDefinitions / rsop.msc Fehlerbehebung
$policyDefinitions = "$env:WINDIR\PolicyDefinitions"
$policyDefinitionsBackup = "$env:WINDIR\PolicyDefinitions_backup"
Add-Check "ID100_RSOP_PolicyDefinitions" 100 "rsop.msc Fehlerbehebung" $(if(Test-Path $policyDefinitions){"TEILWEISE"}else{"NOK"}) "PolicyDefinitionsExists=$(Test-Path $policyDefinitions); BackupExists=$(Test-Path $policyDefinitionsBackup); rsop.msc GUI-Fehler wird nicht interaktiv geprueft"

# 101 Firewall aktivieren
$fwProfiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
$disabledFw = @($fwProfiles | Where-Object { $_.Enabled -ne $true })
Add-Check "ID101_Firewall_aktiv" 101 "Firewall aktivieren" $(if($fwProfiles.Count -gt 0 -and $disabledFw.Count -eq 0){"OK"}else{"NOK"}) ("Profile=" + (($fwProfiles | ForEach-Object { "$($_.Name):$($_.Enabled)" }) -join ", "))

# 104 Bildschirmeinstellungen / visuelle Effekte
$visualFx = Get-RegValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting"
Add-Check "ID104_Bildschirmeinstellungen" 104 "Bildschirmeinstellungen" $(if($visualFx -eq 2){"TEILWEISE"}else{"NOK"}) "HKCU VisualFXSetting=$visualFx; 2=optimale Leistung; nur aktueller Benutzerkontext"

# 105 Autologon
$winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$autoAdmin = Get-RegValue $winlogon "AutoAdminLogon"
$defaultUser = Get-RegValue $winlogon "DefaultUserName"
$defaultDomain = Get-RegValue $winlogon "DefaultDomainName"
Add-Check "ID105_Autologon" 105 "Autologon aktivieren" $(if($autoAdmin -eq "1" -and -not [string]::IsNullOrWhiteSpace($defaultUser)){"OK"}else{"NOK"}) "AutoAdminLogon=$autoAdmin; DefaultUserName=$defaultUser; DefaultDomainName=$defaultDomain"

# 107 Windows-Fehlerberichterstattung UI deaktivieren
$werPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
$werDisabled = Get-RegValue $werPath "Disabled"
$werDontShowUI = Get-RegValue $werPath "DontShowUI"
Add-Check "ID107_Fehlerberichte" 107 "OS-Server Fehlerberichte deaktivieren" $(if($werDisabled -eq 1 -or $werDontShowUI -eq 1){"OK"}else{"NOK"}) "WER Disabled=$werDisabled; DontShowUI=$werDontShowUI"

# 111 Windows Updates verfuegbar?
if ($PerformWindowsUpdateSearch) {
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $pending = $searcher.Search("IsInstalled=0 and Type='Software'")
    Add-Check "ID111_Windows_Updates" 111 "Kontrolle Windows-Updates" $(if($pending.Updates.Count -eq 0){"OK"}else{"NOK"}) "Nicht installierte Software-Updates=$($pending.Updates.Count)"
} catch {
    Add-Check "ID111_Windows_Updates" 111 "Kontrolle Windows-Updates" "NICHT_PRUEFBAR" "Windows-Update-Suche fehlgeschlagen: $($_.Exception.Message)"
}
} else {
Add-Check "ID111_Windows_Updates" 111 "Kontrolle Windows-Updates" "NICHT_PRUEFBAR" "perform_windows_update_search=false; Suche kann lange dauern und wird daher nur optional ausgefuehrt"
}

# 114 SIMATIC Logon
$simaticLogon = @($programs | Where-Object { $_.Name -match "(?i)SIMATIC Logon" })
Add-Check "ID114_SIMATIC_Logon" 114 "SIMATIC Logon konfigurieren" $(if($simaticLogon.Count -gt 0){"TEILWEISE"}else{"NOK"}) "SIMATIC Logon Installation=$($simaticLogon.Count); konkrete Auto-Abmeldeoption ohne bekannten Siemens-Konfigurationspfad nicht eindeutig bewertet"

$workgroupValue = $null
try {
if ($cs -and -not [bool]$cs.PartOfDomain) {
    $workgroupValue = [string]$cs.Workgroup
}
} catch {
$workgroupValue = $null
}



$result = [ordered]@{
scan_timestamp = "{{ hostvars['localhost']['report_timestamp_iso'] | default('') }}"
target_timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
ip = "{{ inventory_hostname }}"
ansible_reachable = $true
computername = $env:COMPUTERNAME
fqdn = $fqdn
domain = $cs.Domain
workgroup = $workgroupValue
part_of_domain = [bool]$cs.PartOfDomain
os_caption = $os.Caption
os_version = $os.Version
winrm_port = "{{ ansible_port | default('') }}"
winrm_scheme = "{{ ansible_winrm_scheme | default('') }}"
winrm_open_ports = "{{ discovered_winrm_open_ports | default('') }}"
checks = $checks
error = $null
}

# $ResultJsonPath = {{ remote_validation_json | to_json }}

$json = $result | ConvertTo-Json -Depth 20 -Compress

$Utf8NoBom = New-Object System.Text.UTF8Encoding -ArgumentList $false
[System.IO.File]::WriteAllText($ResultJsonPath, $json, $Utf8NoBom)

Write-Output "OS_SERVER_RESULT_JSON=$ResultJsonPath"
exit 0