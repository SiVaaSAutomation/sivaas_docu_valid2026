<#
.SYNOPSIS
    Konfiguriert einen Windows-Rechner als Ansible Managed Node über WinRM.

.DESCRIPTION
    Das Skript richtet die für eine Verwaltung durch Ansible notwendigen
    Windows-Komponenten ein:

    1. Prüft, ob das Skript mit Administratorrechten ausgeführt wird.
    2. Aktiviert PowerShell-Remoting / WinRM.
    3. Stellt den automatischen Start des WinRM-Dienstes sicher.
    4. Erstellt eine eingehende Firewallregel für WinRM über TCP 5985.
    5. Erlaubt optional die Verwendung lokaler Administratorkonten über WinRM.
    6. Verändert bewusst NICHT:
       - WinRM Basic Authentication
       - WinRM AllowUnencrypted
       da für die vorgesehene Verbindung NTLM verwendet werden kann.
    7. Prüft die resultierende Konfiguration.

    Vorgesehene Ansible-Konfiguration:
        ansible_connection: winrm
        ansible_winrm_transport: ntlm
        ansible_port: 5985

    WICHTIG:
    Für die Anmeldung muss ein vorhandener Windows-Benutzer mit ausreichenden
    Rechten verwendet werden. Standardmäßig dürfen PowerShell-Remoting-
    Verbindungen nur durch Mitglieder der lokalen Administratorengruppe
    hergestellt werden.

.PARAMETER AllowedRemoteAddress
    Legt fest, welche Quelladressen die WinRM-Firewallregel verwenden dürfen.

    Standard:
        LocalSubnet

    Beispiele:
        -AllowedRemoteAddress "192.168.210.0/24"
        -AllowedRemoteAddress "192.168.210.10"
        -AllowedRemoteAddress "192.168.210.10","192.168.210.11"

    "Any" sollte nur in kontrollierten Netzen verwendet werden.

.PARAMETER EnableLocalAccountAccess
    Wenn $true, wird LocalAccountTokenFilterPolicy = 1 gesetzt.
    Dies ist erforderlich bzw. relevant, wenn ein lokales Administratorkonto
    für die WinRM-Verbindung verwendet wird.

    Bei ausschließlicher Verwendung von Domänenkonten kann der Parameter auf
    $false gesetzt werden.

.NOTES
    Quellenbasis:

    [Q1] Ansible Community Documentation:
         "Windows Remote Management"
         - WinRM-Listener
         - Enable-PSRemoting
         - Firewall TCP 5985
         - LocalAccountTokenFilterPolicy
         - NTLM als standardmäßig aktivierte Authentifizierung

    [Q2] Microsoft Learn:
         "Enable-PSRemoting"
         - Aktivierung von PowerShell-Remoting
         - Start/Starttyp des WinRM-Dienstes
         - Listener und Firewallausnahme

    [Q3] Microsoft Learn:
         "Security considerations for PowerShell Remoting using WinRM"
         - Standardports 5985/5986
         - Administratorrechte
         - Verschlüsselungsverhalten
         - Firewallverhalten

    [Q4] Microsoft Learn:
         "Installation and configuration for Windows Remote Management"
         - WinRM-Standardauthentifizierung
         - Basic standardmäßig deaktiviert
         - Kerberos/Negotiate standardmäßig aktiviert
         - Standardports

    [Q5] Microsoft Learn:
         "New-NetFirewallRule" / "Set-NetFirewallRule"
         - Erstellung und Änderung eingehender Windows-Firewallregeln
         - Einschränkung über RemoteAddress, Protocol und LocalPort

    [Q6] Microsoft Learn:
         "Test-WSMan"
         - Prüfung, ob der WinRM-/WS-Management-Dienst antwortet

    [Q7] Microsoft Learn:
         "User Account Control and remote restrictions"
         - Wirkung von LocalAccountTokenFilterPolicy
         - Wert 1 erzeugt für berechtigte lokale Administratoren ein
           erhöhtes Token; Sicherheitsauswirkungen sind zu berücksichtigen

    Das Skript sollte in Windows PowerShell als Administrator ausgeführt werden.
#>

[CmdletBinding()]
param(
    [string[]]$AllowedRemoteAddress = @("LocalSubnet"),

    [bool]$EnableLocalAccountAccess = $true
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "============================================================"
Write-Host " Ansible / WinRM - Konfiguration des Windows Managed Node"
Write-Host "============================================================"
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Administratorrechte prüfen
# ---------------------------------------------------------------------------
# Enable-PSRemoting und Änderungen an Firewall, Dienst und Registry benötigen
# erhöhte Rechte. [Q2]
# ---------------------------------------------------------------------------

$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentIdentity)
$IsAdministrator = $Principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $IsAdministrator) {
    throw "Dieses Skript muss als Administrator ausgeführt werden."
}

Write-Host "[OK] Administratorrechte vorhanden."


# ---------------------------------------------------------------------------
# 2. PowerShell-Remoting und WinRM aktivieren
# ---------------------------------------------------------------------------
# Enable-PSRemoting konfiguriert den Computer so, dass Remotebefehle über
# WS-Management empfangen werden können. Dabei wird unter anderem WinRM
# aktiviert und ein Listener eingerichtet. [Q1][Q2]
#
# -SkipNetworkProfileCheck ermöglicht die Remoting-Konfiguration auch dann,
# wenn Windows ein Netzwerk als 'Öffentlich' klassifiziert hat.
#
# Da Enable-PSRemoting selbst Windows-Firewallregeln für WinRM anlegt, werden
# diese vorhandenen Regeln im nächsten Schritt ebenfalls auf die angegebenen
# Quelladressen eingeschränkt. [Q2][Q3]
# ---------------------------------------------------------------------------

Write-Host "[INFO] Aktiviere PowerShell-Remoting / WinRM ..."

Enable-PSRemoting -Force -SkipNetworkProfileCheck

Write-Host "[OK] PowerShell-Remoting ist aktiviert."


# ---------------------------------------------------------------------------
# 2a. Durch Enable-PSRemoting erzeugte WinRM-Firewallregeln einschränken
# ---------------------------------------------------------------------------
# Microsoft dokumentiert die standardmäßigen WinRM-Regeln mit Namen, die mit
# "WINRM" beginnen. Damit eine zusätzlich angelegte eingeschränkte Regel nicht
# durch eine weiter gefasste Standardregel umgangen wird, werden auch diese
# vorhandenen Regeln auf AllowedRemoteAddress begrenzt. [Q2][Q5]
# ---------------------------------------------------------------------------

$BuiltInWinRMRules = Get-NetFirewallRule `
    -Name "WINRM*" `
    -ErrorAction SilentlyContinue

if ($BuiltInWinRMRules) {
    $BuiltInWinRMRules | Set-NetFirewallRule `
        -RemoteAddress $AllowedRemoteAddress

    Write-Host "[OK] Vorhandene WinRM-Firewallregeln wurden auf die erlaubten Quelladressen begrenzt."
}


# ---------------------------------------------------------------------------
# 3. WinRM-Dienst auf automatischen Start konfigurieren
# ---------------------------------------------------------------------------
# Enable-PSRemoting führt diese Konfiguration normalerweise bereits durch.
# Die Einstellung wird hier zusätzlich explizit gesetzt, damit der gewünschte
# Zustand eindeutig und idempotent hergestellt wird. [Q2]
# ---------------------------------------------------------------------------

Write-Host "[INFO] Konfiguriere WinRM-Dienst ..."

Set-Service -Name "WinRM" -StartupType Automatic

if ((Get-Service -Name "WinRM").Status -ne "Running") {
    Start-Service -Name "WinRM"
}

Write-Host "[OK] WinRM-Dienst läuft und startet automatisch."


# ---------------------------------------------------------------------------
# 4. Firewallzugriff für WinRM über HTTP / TCP 5985 konfigurieren
# ---------------------------------------------------------------------------
# WinRM verwendet standardmäßig:
#   HTTP  -> TCP 5985
#   HTTPS -> TCP 5986
#
# Für die hier vorgesehene NTLM-Verbindung wird HTTP auf TCP 5985 verwendet.
# Die eingehende Verbindung wird auf die mit AllowedRemoteAddress angegebenen
# Quelladressen beschränkt. [Q1][Q3][Q4]
# ---------------------------------------------------------------------------

$FirewallRuleName = "Ansible-WinRM-HTTP-5985"

Write-Host "[INFO] Konfiguriere Firewallregel '$FirewallRuleName' ..."

$ExistingFirewallRule = Get-NetFirewallRule `
    -DisplayName $FirewallRuleName `
    -ErrorAction SilentlyContinue

if ($ExistingFirewallRule) {

    # Existierende Regel auf den gewünschten Zustand bringen.
    # Set-NetFirewallRule kann sowohl die allgemeinen Eigenschaften der Regel
    # als auch Adress-, Protokoll- und Portbedingungen ändern.
    Set-NetFirewallRule `
        -DisplayName $FirewallRuleName `
        -Enabled True `
        -Direction Inbound `
        -Action Allow `
        -Profile Any `
        -RemoteAddress $AllowedRemoteAddress `
        -Protocol TCP `
        -LocalPort 5985
}
else {

    New-NetFirewallRule `
        -DisplayName $FirewallRuleName `
        -Description "Erlaubt Ansible den WinRM-Zugriff auf TCP 5985." `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort 5985 `
        -RemoteAddress $AllowedRemoteAddress `
        -Profile Any | Out-Null
}

Write-Host "[OK] Firewallregel für TCP 5985 ist eingerichtet."
Write-Host "     Erlaubte Quelladresse(n): $($AllowedRemoteAddress -join ', ')"


# ---------------------------------------------------------------------------
# 5. Zugriff mit lokalem Administratorkonto ermöglichen
# ---------------------------------------------------------------------------
# Bei lokalen Administratorkonten kann Remote UAC dazu führen, dass für eine
# Remoteverbindung ein gefiltertes Zugriffstoken verwendet wird.
#
# Die Ansible-Dokumentation verwendet hierfür; Microsoft dokumentiert
# denselben Registrywert für Remote-UAC-Einschränkungen:
#
# HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
# LocalAccountTokenFilterPolicy = 1
#
# Wird ausschließlich ein Domänenkonto verwendet, ist diese Änderung für
# Ansible nicht erforderlich. Das Deaktivieren der Remote-UAC-Filterung hat
# Sicherheitsauswirkungen und sollte deshalb nur gesetzt werden, wenn lokale
# Administratorkonten für die Verwaltung tatsächlich benötigt werden.
# [Q1][Q7]
# ---------------------------------------------------------------------------

$PolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$PolicyName = "LocalAccountTokenFilterPolicy"

if ($EnableLocalAccountAccess) {

    Write-Host "[INFO] Aktiviere WinRM-Zugriff für lokale Administratorkonten ..."

    New-ItemProperty `
        -Path $PolicyPath `
        -Name $PolicyName `
        -Value 1 `
        -PropertyType DWORD `
        -Force | Out-Null

    Write-Host "[OK] LocalAccountTokenFilterPolicy = 1 gesetzt."
}
else {
    Write-Host "[INFO] LocalAccountTokenFilterPolicy wird nicht verändert."
}


# ---------------------------------------------------------------------------
# 6. Authentifizierung bewusst NICHT unsicher erweitern
# ---------------------------------------------------------------------------
# Für die vorgesehene Ansible-Verbindung wird NTLM genutzt.
# NTLM ist auf dem WinRM-Dienst standardmäßig aktiviert und kann sowohl mit
# lokalen als auch mit Domänenkonten verwendet werden. [Q1]
#
# Deshalb werden folgende Einstellungen NICHT aktiviert:
#
#   WSMan:\localhost\Service\Auth\Basic
#   WSMan:\localhost\Service\AllowUnencrypted
#
# Basic Authentication ist standardmäßig deaktiviert. [Q4]
# ---------------------------------------------------------------------------

Write-Host "[INFO] Lese WinRM-Authentifizierungseinstellungen ..."

$WinRMServiceConfig = Get-Item -Path "WSMan:\localhost\Service"

Write-Host "[INFO] Basic Authentication und AllowUnencrypted werden nicht aktiviert."


# ---------------------------------------------------------------------------
# 7. WinRM-Konfiguration testen
# ---------------------------------------------------------------------------
# Test-WSMan prüft, ob der lokale WS-Management-Endpunkt antwortet. [Q6]
# Zusätzlich werden Listener, Dienst, Firewallregel und Registrywert ausgegeben.
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "============================================================"
Write-Host " Prüfung der Konfiguration"
Write-Host "============================================================"

try {
    Test-WSMan -ComputerName localhost | Out-Null
    Write-Host "[OK] Test-WSMan localhost erfolgreich."
}
catch {
    Write-Host "[FEHLER] Der lokale WinRM-Endpunkt antwortet nicht."
    throw
}


# WinRM-Dienst prüfen
$WinRMService = Get-Service -Name "WinRM"

Write-Host ""
Write-Host "WinRM-Dienst:"
Write-Host "  Status    : $($WinRMService.Status)"
Write-Host "  Starttyp  : $((Get-CimInstance Win32_Service -Filter "Name='WinRM'").StartMode)"


# Listener ausgeben
Write-Host ""
Write-Host "WinRM-Listener:"

$Listeners = Get-ChildItem -Path "WSMan:\localhost\Listener"

foreach ($Listener in $Listeners) {
    $Keys = @{}

    foreach ($Key in $Listener.Keys) {
        $Parts = $Key -split "="
        if ($Parts.Count -eq 2) {
            $Keys[$Parts[0]] = $Parts[1]
        }
    }

    Write-Host "  Transport : $($Keys['Transport'])"
    Write-Host "  Address   : $($Keys['Address'])"

    try {
        $Port = (Get-Item "$($Listener.PSPath)\Port").Value
        Write-Host "  Port      : $Port"
    }
    catch {
        # Einige Windows-Versionen stellen den Port nicht an dieser Stelle dar.
    }

    Write-Host ""
}


# Firewallregel prüfen
$FinalFirewallRule = Get-NetFirewallRule `
    -DisplayName $FirewallRuleName `
    -ErrorAction SilentlyContinue

if ($FinalFirewallRule) {
    $AddressFilter = $FinalFirewallRule | Get-NetFirewallAddressFilter
    $PortFilter    = $FinalFirewallRule | Get-NetFirewallPortFilter

    Write-Host "Firewall:"
    Write-Host "  Regel         : $FirewallRuleName"
    Write-Host "  Aktiv         : $($FinalFirewallRule.Enabled)"
    Write-Host "  Aktion        : $($FinalFirewallRule.Action)"
    Write-Host "  RemoteAddress : $($AddressFilter.RemoteAddress -join ', ')"
    Write-Host "  Protokoll     : $($PortFilter.Protocol)"
    Write-Host "  Port          : $($PortFilter.LocalPort)"
}


# Registrywert prüfen
if ($EnableLocalAccountAccess) {

    $LocalAccountPolicy = Get-ItemProperty `
        -Path $PolicyPath `
        -Name $PolicyName `
        -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "Lokale Konten:"
    Write-Host "  LocalAccountTokenFilterPolicy : $($LocalAccountPolicy.$PolicyName)"
}


# ---------------------------------------------------------------------------
# 8. Ergebnis und erforderliche Ansible-Variablen ausgeben
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "============================================================"
Write-Host " Konfiguration abgeschlossen"
Write-Host "============================================================"
Write-Host ""
Write-Host "Der Rechner ist nun für eine Ansible-Verbindung über WinRM vorbereitet."
Write-Host ""
Write-Host "Passende Ansible-Verbindungsparameter:"
Write-Host ""
Write-Host "  ansible_connection: winrm"
Write-Host "  ansible_winrm_transport: ntlm"
Write-Host "  ansible_port: 5985"
Write-Host ""
Write-Host "Zusätzlich müssen auf dem Ansible-Control-Node Benutzername und Passwort"
Write-Host "für ein berechtigtes Windows-Konto hinterlegt werden."
Write-Host ""
Write-Host "Empfohlener Verbindungstest auf dem Ansible-Control-Node:"
Write-Host ""
Write-Host "  ansible <hostname-oder-gruppe> -m ansible.windows.win_ping"
Write-Host ""
