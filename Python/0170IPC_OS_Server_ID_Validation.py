#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

BACKSLASH = chr(92)

def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]

def as_dict(value):
    return value if isinstance(value, dict) else {}

def text(value):
    return "" if value is None else str(value)

def bool_value(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    value_text = text(value).strip().lower()
    if value_text in {"true", "1", "yes", "enabled", "enable", "on"}:
        return True
    if value_text in {"false", "0", "no", "disabled", "disable", "off"}:
        return False
    return None

def int_value(value):
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip(), 0)
    except Exception:
        try:
            return int(float(str(value).strip()))
        except Exception:
            return None

def ip_sort_key(value):
    try:
        return (0, int(ipaddress.ip_address(str(value))))
    except ValueError:
        return (1, str(value))

def id_sort_key(value):
    match = re.fullmatch(r"IPC(\d+)", text(value).strip(), re.IGNORECASE)
    if match:
        return (0, int(match.group(1)), text(value))
    return (1, text(value))

def regex_search(pattern, value):
    try:
        return re.search(str(pattern), text(value), re.IGNORECASE) is not None
    except re.error:
        return False

def library_section(host, area, validation_type, section_name):
    return (
        as_dict(host.get("bereiche"))
        .get(area, {})
        .get(validation_type, {})
        .get(section_name)
    )

def make_check(task_id, task_name, state, soll, ist, source, soll_source=None, note=None):
    if state is True:
        status = "OK"
    elif state is False:
        status = "NOK"
    else:
        status = "NICHT_PRUEFBAR"
    result = {
        "id": task_id,
        "aufgabe": task_name,
        "pruefart": "SOLLWERT",
        "status": status,
        "soll": soll,
        "ist": ist,
        "quelle": source,
    }
    if soll_source:
        result["sollwertquelle"] = soll_source
    if note:
        result["hinweis"] = note
    return result


def make_information(task_id, task_name, information, source, note=None):
    available = information not in (None, "", [], {})
    result = {
        "id": task_id,
        "aufgabe": task_name,
        "pruefart": "INFORMATION",
        "status": "INFORMATION" if available else "NICHT_PRUEFBAR",
        "ist": information if available else None,
        "quelle": source,
    }
    if note:
        result["hinweis"] = note
    return result


def missing_check(task_id, task_name, soll, source, soll_source=None, note=None):
    return make_check(
        task_id,
        task_name,
        None,
        soll,
        None,
        source,
        soll_source,
        note or "Die aktuelle Informationsbibliothek enthaelt keinen belastbaren Endzustand fuer diese Sollwertpruefung.",
    )


def make_not_testable(task_id, task_name, note, source="0170-Prueflogik"):
    return make_check(task_id, task_name, None, None, None, source, None, note)


def referenced_check(task_id, task_name, source_id, source_check, note=None):
    if not isinstance(source_check, dict):
        return make_not_testable(task_id, task_name, f"Referenzpruefung {source_id} ist nicht vorhanden.")
    result = dict(source_check)
    result["id"] = task_id
    result["aufgabe"] = task_name
    result["quelle"] = f"Referenz auf {source_id}: {source_check.get('quelle', '')}".strip()
    if note:
        result["hinweis"] = note
    return result


def is_german(value):
    value = text(value).strip().lower()
    return value == "de" or value.startswith("de-")

def german_language_snapshot(language):
    language = as_dict(language)
    return {
        "WindowsSystemLocale": as_dict(language.get("WindowsSystemLocale")).get("Name"),
        "CurrentUICulture": as_dict(language.get("CurrentUICulture")).get("Name"),
        "CurrentCulture": as_dict(language.get("CurrentCulture")).get("Name"),
    }

def registry_records(value):
    if isinstance(value, dict) and isinstance(value.get("Values"), list):
        return value["Values"]
    return as_list(value)

def registry_matches(records, name=None, path_contains=None):
    matches = []
    wanted_name = None if name is None else text(name).lower()
    wanted_path = None if path_contains is None else text(path_contains).replace("/", BACKSLASH).lower()
    for row in as_list(records):
        if not isinstance(row, dict):
            continue
        row_name = text(row.get("Name")).lower()
        row_path = text(row.get("Path")).replace("/", BACKSLASH).lower()
        if wanted_name is not None and row_name != wanted_name:
            continue
        if wanted_path is not None and wanted_path not in row_path:
            continue
        matches.append(row)
    return matches

def first_registry_value(records, name=None, path_contains=None):
    matches = registry_matches(records, name=name, path_contains=path_contains)
    if not matches:
        return None, []
    return matches[0].get("Value"), matches

def software_products(software):
    return as_list(as_dict(software).get("AllProducts"))

def product_matches(products, name_pattern, version_pattern=None):
    matches = []
    for product in as_list(products):
        if not isinstance(product, dict):
            continue
        display_name = text(product.get("DisplayName"))
        display_version = text(product.get("DisplayVersion"))
        if not regex_search(name_pattern, display_name):
            continue
        if version_pattern and not regex_search(version_pattern, display_version):
            continue
        matches.append({
            "DisplayName": product.get("DisplayName"),
            "DisplayVersion": product.get("DisplayVersion"),
            "Publisher": product.get("Publisher"),
        })
    return matches

def software_presence_check(task_id, task_name, installed_software, name_pattern, version_pattern, soll):
    products = software_products(installed_software)
    if not products:
        return missing_check(
            task_id, task_name, soll,
            "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts",
            "Aufgabenliste",
        )
    matches = product_matches(products, name_pattern, version_pattern)
    return make_check(
        task_id, task_name, bool(matches), soll, matches,
        "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts",
        "Aufgabenliste",
    )

def service_rows(service_inventory):
    return as_list(as_dict(service_inventory).get("Services"))

def matching_services(service_inventory, pattern):
    result = []
    for service in service_rows(service_inventory):
        if not isinstance(service, dict):
            continue
        haystack = " ".join(text(service.get(k)) for k in ("Name", "DisplayName", "Description", "PathName"))
        if regex_search(pattern, haystack):
            result.append({
                "Name": service.get("Name"),
                "DisplayName": service.get("DisplayName"),
                "State": service.get("State"),
                "StartMode": service.get("StartMode"),
                "StartClassification": service.get("StartClassification"),
                "PathName": service.get("PathName"),
            })
    return result

def profile_is_all(profile):
    value = text(profile).strip().lower()
    if value in {"any", "all", "alle"}:
        return True
    return all(token in value for token in ("domain", "private", "public"))

def firewall_rule_matches(rules, pattern):
    matched = []
    for rule in as_list(rules):
        if not isinstance(rule, dict):
            continue
        haystack = " ".join(text(rule.get(key)) for key in ("Name", "DisplayName", "Description", "DisplayGroup"))
        if regex_search(pattern, haystack):
            matched.append(rule)
    return matched

def smb_config_value(configuration, registry_snapshot, key):
    config = as_dict(configuration)
    if key in config:
        return config.get(key)
    values = as_dict(as_dict(registry_snapshot).get("Values"))
    return values.get(key)

def check_disabled_services(service_data, patterns):
    if not isinstance(service_data, dict) or "Services" not in service_data:
        return False, [{"status": "DATEN_FEHLEN", "ok": False}]
    services = as_list(service_data.get("Services"))
    details = []
    overall = True
    for pattern in as_list(patterns):
        matches = []
        for service in services:
            if not isinstance(service, dict):
                continue
            haystack = text(service.get("Name")) + " " + text(service.get("DisplayName"))
            if regex_search(pattern, haystack):
                matches.append(service)
        if not matches:
            details.append({"pattern": pattern, "status": "NICHT_VORHANDEN", "ok": True, "matches": []})
            continue
        states = []
        pattern_ok = True
        for service in matches:
            disabled = (
                text(service.get("StartClassification")).lower() == "disabled"
                or text(service.get("StartMode")).lower() == "disabled"
            )
            pattern_ok = pattern_ok and disabled
            states.append({
                "Name": service.get("Name"),
                "DisplayName": service.get("DisplayName"),
                "StartClassification": service.get("StartClassification"),
                "StartMode": service.get("StartMode"),
                "ok": disabled,
            })
        overall = overall and pattern_ok
        details.append({"pattern": pattern, "status": "GEFUNDEN", "ok": pattern_ok, "matches": states})
    return overall, details

def schannel_state(records, protocol, side):
    path_fragment = (
        BACKSLASH + "SYSTEM" + BACKSLASH + "CurrentControlSet" + BACKSLASH
        + "Control" + BACKSLASH + "SecurityProviders" + BACKSLASH + "SCHANNEL"
        + BACKSLASH + "Protocols" + BACKSLASH + protocol + BACKSLASH + side
    )
    enabled, enabled_rows = first_registry_value(records, name="Enabled", path_contains=path_fragment)
    dbd, dbd_rows = first_registry_value(records, name="DisabledByDefault", path_contains=path_fragment)
    return {
        "protocol": protocol,
        "side": side,
        "Enabled": enabled,
        "DisabledByDefault": dbd,
        "evidence_found": bool(enabled_rows or dbd_rows),
    }

def check_schannel_protocols(records, disabled_protocols, enabled_protocols):
    details = []
    overall = True
    for protocol in as_list(disabled_protocols):
        for side in ("Client", "Server"):
            state = schannel_state(records, text(protocol), side)
            state["expected"] = {"Enabled": 0, "DisabledByDefault": 1}
            state["ok"] = int_value(state.get("Enabled")) == 0 and int_value(state.get("DisabledByDefault")) == 1
            overall = overall and state["ok"]
            details.append(state)
    for protocol in as_list(enabled_protocols):
        for side in ("Client", "Server"):
            state = schannel_state(records, text(protocol), side)
            enabled = int_value(state.get("Enabled"))
            state["expected"] = {"Enabled": "1 oder 0xFFFFFFFF", "DisabledByDefault": 0}
            state["ok"] = enabled in {1, 4294967295, -1} and int_value(state.get("DisabledByDefault")) == 0
            overall = overall and state["ok"]
            details.append(state)
    return overall, details

def startup_matches(autoruns, pattern):
    result = []
    autoruns = as_dict(autoruns)
    for item in as_list(autoruns.get("RegistryEntries")):
        if isinstance(item, dict):
            haystack = " ".join(text(item.get(k)) for k in ("Path", "Name", "Value", "Command"))
            if regex_search(pattern, haystack):
                result.append({"type": "Registry", "item": item})
    for folder in as_list(autoruns.get("StartupFolders")):
        folder = as_dict(folder)
        for item in as_list(folder.get("Items")):
            if not isinstance(item, dict):
                continue
            shortcut = as_dict(item.get("Shortcut"))
            haystack = " ".join([
                text(item.get("Name")), text(item.get("FullName")),
                text(shortcut.get("TargetPath")), text(shortcut.get("Arguments")),
            ])
            if regex_search(pattern, haystack):
                result.append({"type": folder.get("Scope"), "folder": folder.get("Path"), "item": item})
    return result

def registry_evidence_matches(evidence_section, pattern):
    result = []
    for item in as_list(as_dict(evidence_section).get("Evidence")):
        if not isinstance(item, dict):
            continue
        haystack = " ".join(text(item.get(k)) for k in ("Path", "ValueName", "Value"))
        if regex_search(pattern, haystack):
            result.append(item)
    return result

def current_kb_evidence(patch_status, installed_software, kb):
    kb = text(kb).upper()
    patch_status = as_dict(patch_status)
    evidence = {"HotFixes": [], "InstalledWindowsPackages": [], "InstalledSoftware": []}
    for item in as_list(patch_status.get("HotFixes")):
        if isinstance(item, dict) and text(item.get("HotFixID")).upper() == kb:
            evidence["HotFixes"].append(item)
    for item in as_list(patch_status.get("WindowsPackages")):
        if not isinstance(item, dict):
            continue
        state = text(item.get("PackageState")).lower()
        haystack = " ".join([
            text(item.get("PackageName")), text(item.get("Description")),
            " ".join(text(x) for x in as_list(item.get("KBs"))),
        ]).upper()
        if state == "installed" and kb in haystack:
            evidence["InstalledWindowsPackages"].append(item)
    evidence["InstalledSoftware"] = product_matches(software_products(installed_software), re.escape(kb), None)
    return any(bool(v) for v in evidence.values()), evidence

def normalize_windows_path(value):
    return text(value).strip().replace("/", BACKSLASH).rstrip(BACKSLASH).lower()

def project_share_state(smb, expected_folder, expected_share):
    target_folder = normalize_windows_path(expected_folder)
    target_share = text(expected_share).strip().lower()
    matches = []
    for share in as_list(as_dict(smb).get("Shares")):
        if not isinstance(share, dict):
            continue
        share_path = normalize_windows_path(share.get("Path"))
        share_name = text(share.get("Name")).strip().lower()
        if share_path == target_folder or share_name == target_share:
            acl = as_dict(share.get("NtfsRootAcl"))
            matches.append({
                "Name": share.get("Name"),
                "Path": share.get("Path"),
                "ShareState": share.get("ShareState"),
                "SharePermissions": share.get("SharePermissions"),
                "NtfsRootAcl": share.get("NtfsRootAcl"),
                "FolderExists": bool_value(acl.get("Exists")),
            })
    folder_confirmed = any(item.get("FolderExists") is True for item in matches)
    return folder_confirmed, bool(matches), matches

def matrix_information_value(item):
    item = as_dict(item)
    if item.get("status") != "INFORMATION":
        return "NICHT_PRUEFBAR"
    value = item.get("ist")
    if value is None:
        return "KEINE_INFORMATION"
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

TASK_IDS = [
    "IPC0007",
    "IPC0008",
    "IPC0009",
    "IPC0013",
    "IPC0015",
    "IPC0019",
    "IPC0024",
    "IPC0025",
    "IPC0026",
    "IPC0027",
    "IPC0028",
    "IPC0036",
    "IPC0038",
    "IPC0043",
    "IPC0044",
    "IPC0045",
    "IPC0046",
    "IPC0047",
    "IPC0048",
    "IPC0049",
    "IPC0050",
    "IPC0051",
    "IPC0052",
    "IPC0053",
    "IPC0054",
    "IPC0055",
    "IPC0056",
    "IPC0059",
    "IPC0060",
    "IPC0063",
    "IPC0065",
    "IPC0066",
    "IPC0070",
    "IPC0072",
    "IPC0073",
    "IPC0074",
    "IPC0075",
    "IPC0076",
    "IPC0077",
    "IPC0078",
    "IPC0079",
    "IPC0080",
    "IPC0081",
    "IPC0082",
    "IPC0083",
    "IPC0087",
    "IPC0088",
    "IPC0089",
    "IPC0091",
    "IPC0092",
    "IPC0093",
    "IPC0094",
    "IPC0095",
    "IPC0104",
    "IPC0108",
    "IPC0112",
    "IPC0113",
    "IPC0114",
    "IPC0115",
    "IPC0117",
    "IPC0118",
    "IPC0119",
    "IPC0120",
    "IPC0121",
    "IPC0122",
    "IPC0123",
    "IPC0124",
    "IPC0126",
    "IPC0127",
    "IPC0128",
    "IPC0129",
    "IPC0130",
    "IPC0131",
    "IPC0132",
    "IPC0139",
    "IPC0140",
    "IPC0141",
    "IPC0142",
    "IPC0144",
    "IPC0145",
    "IPC0146",
    "IPC0147",
    "IPC0149",
    "IPC0150",
    "IPC0151",
    "IPC0153",
    "IPC0154",
    "IPC0155",
    "IPC0156",
    "IPC0159",
    "IPC0160",
    "IPC0161",
    "IPC0162",
    "IPC0165",
    "IPC0166",
    "IPC0167",
    "IPC0168",
    "IPC0180",
    "IPC0182",
    "IPC0183",
    "IPC0184",
    "IPC0185",
    "IPC0187",
    "IPC0188",
    "IPC0189",
    "IPC0190",
    "IPC0191",
    "IPC0200",
    "IPC0202",
    "IPC0203",
    "IPC0204",
    "IPC0205",
    "IPC0207",
    "IPC0208",
    "IPC0209",
    "IPC0224",
    "IPC0225",
    "IPC0226",
    "IPC0227",
    "IPC0228",
    "IPC0231",
    "IPC0232",
    "IPC0233",
    "IPC0234",
    "IPC0245",
    "IPC0246",
    "IPC0247",
    "IPC0250",
    "IPC0251",
    "IPC0252",
    "IPC0263",
    "IPC0264",
    "IPC0265",
    "IPC0267",
    "IPC0268",
    "IPC0269",
    "IPC0270",
    "IPC0271",
]

TASK_NAMES = {
    "IPC0007": 'Sprache auswählen (Deutsch)',
    "IPC0008": 'Region auswählen (Deutschland)',
    "IPC0009": 'Tastatur (Deutsch), keine zweite',
    "IPC0013": 'Lokalen Benutzer User konfigurieren',
    "IPC0015": 'Rechnernamen anpassen',
    "IPC0019": 'SIMATIC Management Agent',
    "IPC0024": 'IP-Adresseinstellungen',
    "IPC0025": 'Bios Versionsprüfung',
    "IPC0026": 'UltraVNC 1.4.3.6 installieren',
    "IPC0027": 'Windows Firewall Regeln für VNC anpassen',
    "IPC0028": 'Registry Eintrag für VEEAM setzen',
    "IPC0036": 'Bestehendes Administrator-Konto umkonfigurieren',
    "IPC0038": 'lokalen Benutzer Administrator umbenennen',
    "IPC0043": 'Date and Time',
    "IPC0044": 'Language',
    "IPC0045": 'Sprachen entfernen?',
    "IPC0046": 'Hot-Keys abschalten (auswahl: Keine)',
    "IPC0047": 'Tastenkombination für Eingabesprachen deaktivieren',
    "IPC0048": 'Region',
    "IPC0049": 'Netzwerkadapter umbenennen',
    "IPC0050": 'Terminalbus-Adresse einstellen',
    "IPC0051": 'Terminalbus Gateway korrigieren',
    "IPC0052": 'Anlagenbus-Adresse einstellen',
    "IPC0053": 'Redundanzbus-Adresse einstellen',
    "IPC0054": 'Nicht benötigte Netzwerkadapter deaktivieren',
    "IPC0055": 'DNS und WINS-Server eintragen',
    "IPC0056": 'LMHOSTS-Abfrage deaktivieren',
    "IPC0059": 'Rechner in die Domäne aufnehmen',
    "IPC0060": 'Rechner in der OU einsortieren',
    "IPC0063": 'Sichtbarkeit im Netzwerk',
    "IPC0065": 'VNC-Gruppe einstellen',
    "IPC0066": 'VNC-Einstellungen konfigurieren',
    "IPC0070": 'UltraVNC Viewer installieren',
    "IPC0072": 'Partition (C: 100GB; D "Rest")',
    "IPC0073": 'Restore Image löschen',
    "IPC0074": 'Taskleiste',
    "IPC0075": 'Lupe zur Suche in Taskleiste',
    "IPC0076": 'Desktop: Computer, Netzwerk, Papierkorb / Verknuepfungen bereinigen',
    "IPC0077": 'Microsoft Edge Verknüpfung löschen',
    "IPC0078": 'HUP installieren',
    "IPC0079": 'Einstellungen Netzwerkkarte überprüfen (1000MBit/s, Automatisch)',
    "IPC0080": 'Energiesparoptionen für Netzwerkkarten deaktivieren',
    "IPC0081": 'Microsoft .NET Framework 3.5 aktivieren',
    "IPC0082": 'Microsoft Message Queue (MSMQ) Server aktivieren',
    "IPC0083": 'Bildschirmschoner aktivieren (SE + ES)',
    "IPC0087": 'Energieoptionen auf "Höchstleistung" setzen',
    "IPC0088": 'Kontrolle Energieoptionen',
    "IPC0089": 'Starten und Wiederherstellen anpassen',
    "IPC0091": '.NET Framework 3.5 SP1 installieren',
    "IPC0092": 'Zertifikat installieren',
    "IPC0093": 'Zertifikat installieren',
    "IPC0094": 'Zertifikataktualisierung muss zugelassen werden',
    "IPC0095": 'Zertifikataktualisierung muss zugelassen werden',
    "IPC0104": 'SIMATIC_PCS7_Faceplates_V7_1_SP3_Upd1 installieren',
    "IPC0108": 'Zertifikat installieren',
    "IPC0112": 'SENTRON 3WL/3VL V10',
    "IPC0113": 'SENTRON PAC V10',
    "IPC0114": 'SIMOCODE pro PCS7 V10.0',
    "IPC0115": 'SIMOCODE pro PCS 7 Library Migration (Legacy) V10.0',
    "IPC0117": 'S7 F Systems V6.4 SP1',
    "IPC0118": 'S7 F Systems V6.4 SP1 Nachinstallationsaufgabe',
    "IPC0119": 'Industry Library V10.0',
    "IPC0120": 'PowerControl V9.1',
    "IPC0121": 'PowerControl V9.1 Update 1',
    "IPC0122": 'DriveES PCS 7 APL V10.0',
    "IPC0123": 'SITOP PCS 7 APL V4.0',
    "IPC0124": 'SIMATIC Safety Matrix V6.3 SP1',
    "IPC0126": 'PCS 7 V10 UC02 Installieren',
    "IPC0127": 'PCS7 V10 SP1 installieren (aktualisierung)',
    "IPC0128": 'Industry Library 10.0 Upd1 aktualisieren',
    "IPC0129": 'SENTRON 3WL/3VL V10.0SP1 (vorher V10 ohne SP deinstallieren)',
    "IPC0130": 'SENTRON PAC V10.0SP1 (vorher V10 ohne SP deinstallieren',
    "IPC0131": 'SIMOCODE pro PCS7 V10.0 SP1',
    "IPC0132": 'SIMOCODE pro PCS 7 Library Migration (Legacy) V10.0SP1 (vorher V10 ohne SP deinstallieren)',
    "IPC0139": 'WinCC OPCServer V3.9 SP12 Upd5',
    "IPC0140": 'Orcla installieren Setupdatei ausführen',
    "IPC0141": 'Setupdatei ausführen',
    "IPC0142": 'Watchdog und OPC UA server',
    "IPC0144": 'Zertifikate austauschen',
    "IPC0145": 'Zertifikate austauschen - WinCC OPC UA Client / ORCLA OPC UA Server',
    "IPC0146": 'Zertifikate austauschen - Online-Modus',
    "IPC0147": 'Zugriffsskript ausführen',
    "IPC0149": 'Deinstallieren von Windows-Komponenten',
    "IPC0150": 'BitLocker Aktivierung',
    "IPC0151": 'Deaktivieren von Diensten',
    "IPC0153": 'Einstellung von Datenschutz- und Telemetriedaten in Windows 10 Teil 2',
    "IPC0154": 'SMB Signierung',
    "IPC0155": 'SMBv3-Verschlüsselung',
    "IPC0156": 'Remote Desktop Security Einstellung',
    "IPC0159": 'Deaktivierung von veralteten SSL-/TLS-Kommunikationsverfahren',
    "IPC0160": 'Verwendung von sicheren Cipher Suites',
    "IPC0161": 'Verwendung von sicheren Cipher Suites',
    "IPC0162": 'Parametrierung des ALM als Lizenzserver',
    "IPC0165": 'Security Controller',
    "IPC0166": 'Windows-Firewall',
    "IPC0167": 'D:\\Projekt',
    "IPC0168": 'Ordner freigeben',
    "IPC0180": 'SQL Server MGMT Studio',
    "IPC0182": 'BGInfo/BGSiVaaS',
    "IPC0183": 'BGInfo/BGSiVaaS',
    "IPC0184": 'Hintergrundbild anpassen',
    "IPC0185": 'Kontrolle mit WinCC_RT Benutzer',
    "IPC0187": 'VNC',
    "IPC0188": 'host/lmhost',
    "IPC0189": 'Arbeitsgruppe einstellen',
    "IPC0190": 'VNC Verbindung',
    "IPC0191": 'Lokalen Administrator umbenennen',
    "IPC0200": 'WSUSClientManager ablegen',
    "IPC0202": 'SIMATIC Logon installieren',
    "IPC0203": 'SIMATIC Logon aktualisieren',
    "IPC0204": 'SIMATIC Logon konfigurieren',
    "IPC0205": 'PM-Logon V2.6 Update 4 installieren',
    "IPC0207": 'PM-Logon RT Konfiguration',
    "IPC0208": 'PM-Logon Konfiguration verteilen',
    "IPC0209": 'PM-Logon Konfiguration anpassen',
    "IPC0224": 'KB5055526',
    "IPC0225": 'KB5050187',
    "IPC0226": 'KB5046860',
    "IPC0227": 'KB5054833',
    "IPC0228": 'Nicht in Patch-Liste enthalten',
    "IPC0231": 'SQL-Server neu installiert',
    "IPC0232": 'KB5058385',
    "IPC0233": 'KB5046859',
    "IPC0234": 'Auslagerungsdatei konfigurieren',
    "IPC0245": 'VNC-Viewer Firewallregel prüfen',
    "IPC0246": 'Firewall für alle Profile aktiviert',
    "IPC0247": 'Defender Einstellungen korrigieren',
    "IPC0250": 'Defender Einstellungen korrigieren',
    "IPC0251": 'Defender Sicherheitsstatus i.O.',
    "IPC0252": 'UltraVNC-Viewer nachinstallieren',
    "IPC0263": 'USB Boot deaktiviert lassen',
    "IPC0264": 'WLAN deaktivieren',
    "IPC0265": 'Super IO Configuration',
    "IPC0267": 'Zugang über Passwort schützen',
    "IPC0268": 'Start bei "Strom ein',
    "IPC0269": 'Aufwecken über Netzwerk',
    "IPC0270": 'Num Lock ON bei Start',
    "IPC0271": 'Festplatte als erstes Start-Medium einstellen',
}

ROLE_EXCLUDED_IDS = [
    "IPC0097", "IPC0103", "IPC0105", "IPC0109", "IPC0133", "IPC0134", "IPC0135",
    "IPC0143", "IPC0148", "IPC0152", "IPC0171", "IPC0177",
    "IPC0178", "IPC0179", "IPC0186", "IPC0222", "IPC0223", "IPC0248", "IPC0249", "IPC0254",
]


def normalize_expected_config(raw_expected):
    """
    Akzeptiert sowohl die alte flache 0170-Sollwertstruktur als auch den
    gemeinsamen ipc_es_validation_expected-Block von 0160.

    Es werden nur eindeutig ableitbare OS-Server-Werte uebernommen. Fehlt
    ein projektspezifischer Sollwert, bleibt er absichtlich leer, damit
    daraus spaeter NICHT_PRUEFBAR statt eines erfundenen NOK entsteht.
    """
    raw = as_dict(raw_expected)
    if isinstance(raw.get("ipc_es_validation_expected"), dict):
        block = as_dict(raw.get("ipc_es_validation_expected"))
    elif isinstance(raw.get("ipc_os_server_validation_expected"), dict):
        block = as_dict(raw.get("ipc_os_server_validation_expected"))
    else:
        block = raw

    normalized = dict(block)

    network = as_dict(block.get("network"))
    adapter_policy = as_dict(network.get("adapter_policy"))
    terminalbus = as_dict(network.get("terminalbus"))
    anlagenbus = as_dict(network.get("anlagenbus"))
    redundanzbus = as_dict(network.get("redundanzbus"))

    allowed_names = [text(x) for x in as_list(adapter_policy.get("allowed_names")) if text(x)]
    if "present_adapters" not in normalized and allowed_names:
        normalized["present_adapters"] = allowed_names

    if "terminalbus_adapter_regex" not in normalized:
        normalized["terminalbus_adapter_regex"] = terminalbus.get("name_regex") or r"^Terminalbus$"

    if "network_adapter_name_regex" not in normalized:
        role_regexes = [
            text(terminalbus.get("name_regex")),
            text(anlagenbus.get("name_regex")),
            text(redundanzbus.get("name_regex")),
        ]
        role_regexes = [value for value in role_regexes if value]
        if role_regexes:
            normalized["network_adapter_name_regex"] = "(?:" + "|".join(role_regexes) + ")"

    normalized.setdefault("terminalbus_gateway", terminalbus.get("gateway"))
    normalized.setdefault("terminalbus_dns_servers", as_list(terminalbus.get("dns_servers")))
    normalized.setdefault("terminalbus_wins_servers", as_list(terminalbus.get("wins_servers")))
    normalized.setdefault("enable_lmhosts", 0)

    # Nicht aus allowed_names ableiten: "vorhanden" und "aktiv erlaubt" sind
    # unterschiedliche Anforderungen.
    normalized.setdefault("absent_adapters", [])
    normalized.setdefault("allowed_enabled_adapter_names", [])

    domain = as_dict(block.get("domain"))
    if "computer_ou_regex" not in normalized and domain.get("ou_regex"):
        normalized["computer_ou_regex"] = domain.get("ou_regex")

    normalized.setdefault("admin_l_user", as_dict(block.get("builtin_admin")).get("name") or "Admin_L")
    normalized.setdefault("timezone_id", as_dict(block.get("time")).get("timezone_id") or "W. Europe Standard Time")
    normalized.setdefault("keyboard", as_dict(block.get("keyboard")))

    vnc_rules = [
        text(as_dict(item).get("name_regex"))
        for item in as_list(as_dict(block.get("vnc_firewall")).get("rules"))
        if text(as_dict(item).get("name_regex"))
    ]
    if "firewall_rule_name_patterns" not in normalized and vnc_rules:
        normalized["firewall_rule_name_patterns"] = vnc_rules

    power_os = as_dict(as_dict(as_dict(block.get("power")).get("by_type")).get("OS_Server"))
    if "power_plan_regex" not in normalized and power_os.get("active_plan_name_regex"):
        normalized["power_plan_regex"] = power_os.get("active_plan_name_regex")
    normalized.setdefault("display_timeout_ac_minutes", power_os.get("display_timeout_ac_minutes"))
    normalized.setdefault("disk_timeout_ac_minutes", power_os.get("disk_timeout_ac_minutes"))

    hardening = as_dict(block.get("hardening"))
    disabled_service_patterns = [
        text(as_dict(item).get("name_regex"))
        for item in as_list(as_dict(hardening.get("services")).get("disabled"))
        if text(as_dict(item).get("name_regex"))
    ]
    if "disabled_service_patterns" not in normalized and disabled_service_patterns:
        normalized["disabled_service_patterns"] = disabled_service_patterns

    protocol_config = as_dict(as_dict(hardening.get("tls")).get("protocols"))
    disabled_protocols = []
    enabled_protocols = []
    for protocol_name, requirement in protocol_config.items():
        enabled = bool_value(as_dict(requirement).get("enabled"))
        if enabled is False:
            disabled_protocols.append(protocol_name)
        elif enabled is True:
            enabled_protocols.append(protocol_name)
    if "disabled_schannel_protocols" not in normalized and disabled_protocols:
        normalized["disabled_schannel_protocols"] = disabled_protocols
    if "enabled_schannel_protocols" not in normalized and enabled_protocols:
        normalized["enabled_schannel_protocols"] = enabled_protocols

    project_share = as_dict(as_dict(block.get("filesystem")).get("project_share"))
    if "project_folder" not in normalized and project_share.get("path"):
        normalized["project_folder"] = project_share.get("path")
    if "project_share" not in normalized and project_share.get("share_name"):
        normalized["project_share"] = project_share.get("share_name")

    normalized["_shared_expected"] = block
    return normalized


def component_records(windows_components):
    rows = []
    components = as_dict(windows_components)
    for item in as_list(components.get("OptionalFeatures")):
        if isinstance(item, dict):
            rows.append({"Name": item.get("FeatureName"), "DisplayName": item.get("FeatureName"), "Enabled": text(item.get("State")).lower().startswith("enabled"), "Raw": item})
    server = as_dict(components.get("ServerRolesAndFeatures"))
    for item in as_list(server.get("Features")):
        if isinstance(item, dict):
            installed = bool_value(item.get("Installed"))
            rows.append({"Name": item.get("Name"), "DisplayName": item.get("DisplayName"), "Enabled": installed is True, "Raw": item})
    return rows


def component_matches(rows, pattern):
    return [row for row in as_list(rows) if isinstance(row, dict) and regex_search(pattern, " ".join([text(row.get("Name")), text(row.get("DisplayName"))]))]


def cert_prereq_state(cert_prereq, key):
    if not isinstance(cert_prereq, dict):
        return None, None
    row = as_dict(cert_prereq.get(key))
    return bool_value(row.get("Detected")) is True, row if row else None


def evaluate_os_server(host, expected):
    checks = {}
    info = {}

    identity = library_section(host, "system_und_hardware", "Initial_Valid", "Identity")
    language = library_section(host, "sprache_und_region", "Initial_Valid", "LanguageAndRegion")
    time_config = library_section(host, "zeitkonfiguration", "Initial_Valid", "TimeConfiguration")
    local_users = library_section(host, "benutzer_und_gruppen", "Initial_Valid", "LocalUsers")
    network_adapters = library_section(host, "netzwerk_und_domaene", "Initial_Valid", "NetworkAdapters")
    domain_info = library_section(host, "netzwerk_und_domaene", "Initial_Valid", "DomainInformation")
    bios = library_section(host, "system_und_hardware", "Initial_Valid", "BIOS")
    storage = library_section(host, "system_und_hardware", "Initial_Valid", "Storage")
    defender = library_section(host, "sicherheit", "Initial_Valid", "MicrosoftDefender")
    best_practice = library_section(host, "hinweise_und_beobachtungen", "Initial_Valid", "InstallationBestPractice")

    firewall = library_section(host, "firewall_smb_und_endpunkte", "Firewall_SMB_Patch_Valid", "Firewall")
    smb = library_section(host, "firewall_smb_und_endpunkte", "Firewall_SMB_Patch_Valid", "SMB")
    autoruns = library_section(host, "autostart_und_tasks", "Firewall_SMB_Patch_Valid", "Autoruns")
    patch_status = library_section(host, "patchstand", "Firewall_SMB_Patch_Valid", "PatchStatus")

    explicit_policy = library_section(host, "gruppenrichtlinien", "GPOs_Valid", "ExplicitlyConfiguredPolicyRegistry")
    policy_areas = library_section(host, "gruppenrichtlinien", "GPOs_Valid", "PolicyAreaSnapshots")
    effective_policy = library_section(host, "gruppenrichtlinien", "GPOs_Valid", "InstallationRelevantEffectiveSettings")

    services = library_section(host, "dienste_treiber_und_geraete", "Certificates_Services_Drivers_Valid", "Services")
    certificates = library_section(host, "zertifikate_und_bindings", "Certificates_Services_Drivers_Valid", "Certificates")
    certificate_bindings = library_section(host, "zertifikate_und_bindings", "Certificates_Services_Drivers_Valid", "CertificateBindings")

    installed_software = library_section(host, "software_und_pcs7", "Software_PCS7_Components_Valid", "InstalledSoftware")
    siemens_registry = library_section(host, "software_und_pcs7", "Software_PCS7_Components_Valid", "SiemensRegistryEvidence")
    simatic_shell = library_section(host, "software_und_pcs7", "Software_PCS7_Components_Valid", "SimaticShellEvidence")
    alm_evidence = library_section(host, "software_und_pcs7", "Software_PCS7_Components_Valid", "AutomationLicenseManagerEvidence")
    sql_components = library_section(host, "software_und_pcs7", "Software_PCS7_Components_Valid", "SQLServerComponents")
    setup_logs = library_section(host, "software_und_pcs7", "Software_PCS7_Components_Valid", "PCS7SetupLogEvidence")
    windows_components = library_section(host, "windows_software_und_features", "Initial_Valid", "WindowsComponents")
    dotnet_prereq = library_section(host, "software_und_pcs7", "Software_PCS7_Components_Valid", "DotNetAndRuntimePrerequisites")
    cert_prereq = library_section(host, "software_und_pcs7", "Software_PCS7_Components_Valid", "PCS7CertificatePrerequisites")

    products = software_products(installed_software)

    # IPC0003 / IPC0007 / IPC0008 - Sprache und Region.
    snapshot = german_language_snapshot(language)
    checks["IPC0003"] = make_check(
        "IPC0003", "Ersteinrichtung (Deutsch)",
        is_german(snapshot.get("WindowsSystemLocale")) and is_german(snapshot.get("CurrentUICulture")),
        "Deutsch / de-DE", snapshot,
        "Initial_Valid.LanguageAndRegion", "Aufgabenliste",
    ) if isinstance(language, dict) else missing_check(
        "IPC0003", "Ersteinrichtung (Deutsch)", "Deutsch / de-DE",
        "Initial_Valid.LanguageAndRegion", "Aufgabenliste",
    )
    checks["IPC0007"] = make_check(
        "IPC0007", "Sprache auswählen (Deutsch)",
        all(is_german(snapshot.get(key)) for key in ("WindowsSystemLocale", "CurrentUICulture", "CurrentCulture")),
        "Deutsch / de-DE", snapshot,
        "Initial_Valid.LanguageAndRegion", "Aufgabenliste",
    ) if isinstance(language, dict) else missing_check(
        "IPC0007", "Sprache auswählen (Deutsch)", "Deutsch / de-DE",
        "Initial_Valid.LanguageAndRegion", "Aufgabenliste",
    )
    region = as_dict(as_dict(language).get("Region"))
    checks["IPC0008"] = make_check(
        "IPC0008", "Region auswählen (Deutschland)",
        text(region.get("TwoLetterISORegionName")).upper() == "DE",
        "Deutschland (ISO-Region DE)", region,
        "Initial_Valid.LanguageAndRegion.Region", "Aufgabenliste",
    )

    # IPC0015 - Rechnername indirekt.
    info["IPC0015"] = make_information(
        "IPC0015", "Rechnernamen anpassen",
        {
            "ComputerName": as_dict(identity).get("ComputerName"),
            "DNSHostName": as_dict(identity).get("DNSHostName"),
            "FQDN": as_dict(identity).get("FQDN"),
        } if isinstance(identity, dict) else None,
        "Initial_Valid.Identity",
        "Rechnername fuer den Abgleich mit der OS-Server-Projektliste.",
    )

    # IPC0019 - SIMATIC Management Agent vorhanden.
    sma_products = product_matches(products, r"SIMATIC.*Management.*Agent|Management.*Agent")
    sma_services = matching_services(services, r"SIMATIC.*Management.*Agent|Management.*Agent")
    checks["IPC0019"] = make_check(
        "IPC0019", "SIMATIC Management Agent", bool(sma_products or sma_services),
        "SIMATIC Management Agent installiert/vorhanden",
        {"InstalledSoftware": sma_products, "Services": sma_services},
        "InstalledSoftware + Services", "Aufgabenliste",
    )

    # IPC0024 / 0025 - Informationsausgaben.
    info["IPC0024"] = make_information(
        "IPC0024", "IP-Adresseinstellungen", network_adapters,
        "Initial_Valid.NetworkAdapters",
        "Alle Netzwerkadapter mit IP, Gateway, DNS, WINS, Bindings, Treiber- und Power-Management-Informationen.",
    )
    info["IPC0025"] = make_information(
        "IPC0025", "Bios Versionsprüfung", bios,
        "Initial_Valid.BIOS", "BIOS-Version und ReleaseDate fuer den manuellen Vergleich.",
    )

    # IPC0026 - UltraVNC 1.4.3.6.
    vnc_matches = product_matches(products, r"UltraVNC|uvnc", r"^1\.4\.3\.6(?:\D|$)")
    checks["IPC0026"] = make_check(
        "IPC0026", "UltraVNC 1.4.3.6 installieren", bool(vnc_matches),
        "UltraVNC Version 1.4.3.6", vnc_matches,
        "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts", "Aufgabenliste",
    )

    # IPC0027 - VNC-Firewallregeln auf allen Profilen.
    firewall_rules = as_list(as_dict(firewall).get("Rules"))
    pattern_results = []
    vnc_fw_ok = bool(firewall_rules)
    for pattern in as_list(expected.get("firewall_rule_name_patterns")):
        matches = firewall_rule_matches(firewall_rules, pattern)
        compliant = [
            rule for rule in matches
            if bool_value(rule.get("Enabled")) is True
            and text(rule.get("Direction")).lower() == "inbound"
            and text(rule.get("Action")).lower() == "allow"
            and profile_is_all(rule.get("Profile"))
        ]
        pattern_ok = bool(compliant)
        vnc_fw_ok = vnc_fw_ok and pattern_ok
        pattern_results.append({"pattern": pattern, "ok": pattern_ok, "matching_compliant_rules": compliant})
    checks["IPC0027"] = make_check(
        "IPC0027", "Windows Firewall Regeln für VNC anpassen", vnc_fw_ok,
        {"Enabled": True, "Direction": "Inbound", "Action": "Allow", "Profile": "Alle Profile"},
        pattern_results,
        "Firewall_SMB_Patch_Valid.Firewall.Rules",
        "Semaphore: expected_firewall_rule_name_patterns + Aufgabenliste",
    )

    # IPC0028 - LocalAccountTokenFilterPolicy = 1.
    policy_records = registry_records(explicit_policy)
    latfp, latfp_rows = first_registry_value(
        policy_records,
        name="LocalAccountTokenFilterPolicy",
        path_contains="SOFTWARE/Microsoft/Windows/CurrentVersion/Policies/System",
    )
    checks["IPC0028"] = make_check(
        "IPC0028", "Registry Eintrag für VEEAM setzen", int_value(latfp) == 1,
        {"Name": "LocalAccountTokenFilterPolicy", "Value": 1},
        latfp_rows if latfp_rows else "Wert nicht gefunden",
        "GPOs_Valid.ExplicitlyConfiguredPolicyRegistry", "Aufgabenliste",
    )

    # IPC0036 / IPC0038 - integriertes Administratorkonto.
    users = as_list(local_users)
    builtin_admin = None
    for user in users:
        if isinstance(user, dict) and text(user.get("SID")).endswith("-500"):
            builtin_admin = user
            break
    checks["IPC0036"] = make_check(
        "IPC0036", "Bestehendes Administrator-Konto umkonfigurieren",
        isinstance(builtin_admin, dict) and bool_value(builtin_admin.get("PasswordExpires")) is False,
        "RID-500-Administratorkonto: PasswordExpires=false",
        builtin_admin if builtin_admin else "RID-500-Konto nicht gefunden",
        "Initial_Valid.LocalUsers", "Aufgabenliste",
    )
    checks["IPC0038"] = make_check(
        "IPC0038", "lokalen Benutzer Administrator umbenennen",
        isinstance(builtin_admin, dict) and text(builtin_admin.get("Name")).lower() == text(expected.get("admin_l_user")).lower(),
        {"RID": 500, "Name": expected.get("admin_l_user")},
        builtin_admin if builtin_admin else "RID-500-Konto nicht gefunden",
        "Initial_Valid.LocalUsers", "Semaphore: admin_l_user",
    )

    # IPC0043 / IPC0044.
    timezone_data = as_dict(as_dict(time_config).get("TimeZone"))
    checks["IPC0043"] = make_check(
        "IPC0043", "Date and Time",
        text(timezone_data.get("Id")) == text(expected.get("timezone_id")),
        expected.get("timezone_id"), timezone_data,
        "Initial_Valid.TimeConfiguration.TimeZone", "Semaphore: expected_timezone_id",
    )
    user_languages = as_list(as_dict(language).get("CurrentUserLanguageList"))
    first_language = as_dict(user_languages[0]).get("LanguageTag") if user_languages else None
    ui_culture = as_dict(as_dict(language).get("CurrentUICulture")).get("Name")
    checks["IPC0044"] = make_check(
        "IPC0044", "Language", is_german(first_language) and is_german(ui_culture),
        "Deutsch als primaere Sprache", {"FirstLanguage": first_language, "CurrentUICulture": ui_culture},
        "Initial_Valid.LanguageAndRegion", "Aufgabenliste",
    )

    # IPC0048 - Region/System/Welcome Screen indirekt.
    lang = as_dict(language)
    welcome = as_dict(lang.get("WelcomeScreenSystemAccount"))
    welcome_values = as_dict(as_dict(welcome.get("International")).get("Values"))
    info["IPC0048"] = make_information(
        "IPC0048", "Region / Copy Settings",
        {
            "WindowsSystemLocale": as_dict(lang.get("WindowsSystemLocale")).get("Name"),
            "CurrentCulture": as_dict(lang.get("CurrentCulture")).get("Name"),
            "CurrentUICulture": as_dict(lang.get("CurrentUICulture")).get("Name"),
            "CurrentUserLanguageList": lang.get("CurrentUserLanguageList"),
            "Region": lang.get("Region"),
            "WelcomeScreen": welcome,
            "WelcomeScreenLocale": welcome_values.get("LocaleName") or welcome_values.get("Locale"),
            "DefaultUserProfile": lang.get("DefaultUserProfile"),
        } if isinstance(language, dict) else None,
        "Initial_Valid.LanguageAndRegion",
        "Default-User-Hive wird vom read-only Collector nicht geladen; neue Benutzer daher nur teilweise nachweisbar.",
    )

    # IPC0049 - fuer OS Server gelten die Semaphore-Rollenwerte.
    adapter_names = [text(x.get("Name")) for x in as_list(network_adapters) if isinstance(x, dict)]
    missing_present = [
        wanted for wanted in as_list(expected.get("present_adapters"))
        if not any(text(name).lower() == text(wanted).lower() for name in adapter_names)
    ]
    present_adapters_expected = [text(x) for x in as_list(expected.get("present_adapters")) if text(x)]
    ipc0049_state = None if not present_adapters_expected else not missing_present
    checks["IPC0049"] = make_check(
        "IPC0049", "Netzwerkadapter umbenennen", ipc0049_state,
        {"ExpectedPresentAdapters": present_adapters_expected},
        {"AdapterNames": adapter_names, "Missing": missing_present},
        "Initial_Valid.NetworkAdapters[].Name",
        "Semaphore: network.adapter_policy.allowed_names / expected_present_adapters",
        "Ohne konfigurierte Sollnamen wird kein NOK aus einer leeren Sollwertliste abgeleitet.",
    )

    # IPC0050 / IPC0052 - komplette Adapterinformationen.
    for task_id, task_name in (
        ("IPC0050", "Terminalbus-Adresse einstellen"),
        ("IPC0052", "Anlagenbus-Adresse einstellen"),
    ):
        info[task_id] = make_information(
            task_id, task_name, network_adapters,
            "Initial_Valid.NetworkAdapters",
            "Vollstaendige Adapterinformationen fuer den manuellen Abgleich.",
        )

    # IPC0055 - zentrale DNS-/WINS-Sollwerte plus Snapshot-Evidenz.
    # WINS ist je Collector-Version nicht vollstaendig normalisiert; deshalb
    # bleibt die Bibliotheksauswertung INFORMATION und erfindet kein NOK.
    terminalbus_for_name_servers = [
        adapter for adapter in as_list(network_adapters)
        if isinstance(adapter, dict)
        and regex_search(expected.get("terminalbus_adapter_regex"), adapter.get("Name"))
    ]
    name_server_evidence = []
    for adapter in terminalbus_for_name_servers:
        dns_actual = (
            adapter.get("DNSServers")
            or adapter.get("DnsServers")
            or as_dict(adapter.get("DNS")).get("Servers")
            or as_dict(adapter.get("DNS")).get("ServerAddresses")
        )
        wins_data = as_dict(adapter.get("WINS"))
        wins_actual = (
            wins_data.get("NameServerList")
            or wins_data.get("Servers")
            or wins_data.get("WINSServers")
        )
        name_server_evidence.append({
            "Name": adapter.get("Name"),
            "DNS": dns_actual,
            "WINS": wins_actual,
            "RawWINS": wins_data,
        })
    info["IPC0055"] = make_information(
        "IPC0055", "DNS und WINS-Server eintragen",
        {
            "ExpectedDNS": as_list(expected.get("terminalbus_dns_servers")),
            "ExpectedWINS": as_list(expected.get("terminalbus_wins_servers")),
            "Adapters": name_server_evidence,
        } if isinstance(network_adapters, list) else None,
        "Initial_Valid.NetworkAdapters",
        (
            "DNS/WINS-Sollwerte stammen aus der gemeinsamen Semaphore-Struktur. "
            "Die vollstaendige NetBT-NameServerList ist im Snapshot nicht fuer jede "
            "Collector-Version garantiert; eine direkte Livepruefung kann diese "
            "Information spaeter zu OK/NOK verfeinern."
        ),
    )

    # IPC0051 - finaler Terminalbus-Gatewaywert 192.168.210.254.
    terminalbus = [
        adapter for adapter in as_list(network_adapters)
        if isinstance(adapter, dict) and regex_search(expected.get("terminalbus_adapter_regex"), adapter.get("Name"))
    ]
    gateway_details = [
        {"Name": adapter.get("Name"), "Gateway": as_list(adapter.get("Gateway"))}
        for adapter in terminalbus
    ]
    expected_gateway = text(expected.get("terminalbus_gateway")) or "192.168.210.254"
    gateway_ok = bool(terminalbus) and any(
        expected_gateway in [text(x) for x in as_list(adapter.get("Gateway"))]
        for adapter in terminalbus
    )
    checks["IPC0051"] = make_check(
        "IPC0051", "Terminalbus Gateway korrigieren", gateway_ok,
        expected_gateway, gateway_details,
        "Initial_Valid.NetworkAdapters[].Routes",
        "Semaphore: network.terminalbus.gateway / Aufgabenliste",
    )

    # IPC0053 - Redundanzbus 192.168.230.x.
    redundancy_details = []
    redundancy_ok = False
    for adapter in as_list(network_adapters):
        if not isinstance(adapter, dict) or not regex_search(r"Redundanzbus", adapter.get("Name")):
            continue
        ips = [
            item for item in as_list(adapter.get("IPAddresses"))
            if isinstance(item, dict) and text(item.get("AddressFamily")).lower() in {"ipv4", "2"}
        ]
        matched = [item for item in ips if text(item.get("IPAddress")).startswith("192.168.230.")]
        redundancy_ok = redundancy_ok or bool(matched)
        redundancy_details.append({"Name": adapter.get("Name"), "IPv4": ips, "Matched": matched})
    checks["IPC0053"] = make_check(
        "IPC0053", "Redundanzbus-Adresse einstellen", redundancy_ok,
        "Redundanzbus IPv4 192.168.230.x", redundancy_details,
        "Initial_Valid.NetworkAdapters", "Aufgabenliste",
    )

    # IPC0054 - OS-Server-spezifisch: unnoetige Adapter aus/abwesend.
    absent_results = []
    absent_ok = True
    for wanted in as_list(expected.get("absent_adapters")):
        matches = [
            adapter for adapter in as_list(network_adapters)
            if isinstance(adapter, dict) and text(wanted).lower() in text(adapter.get("Name")).lower()
        ]
        item_ok = not matches or all(text(adapter.get("Status")).lower() not in {"up", "connected"} for adapter in matches)
        absent_ok = absent_ok and item_ok
        absent_results.append({"Pattern": wanted, "OK": item_ok, "Matches": matches})
    enabled_hardware = [
        adapter for adapter in as_list(network_adapters)
        if isinstance(adapter, dict)
        and text(adapter.get("Status")).lower() in {"up", "connected"}
        and bool_value(adapter.get("Virtual")) is not True
    ]
    allowed_enabled = [text(x) for x in as_list(expected.get("allowed_enabled_adapter_names")) if text(x)]
    disallowed_enabled = [
        adapter for adapter in enabled_hardware
        if allowed_enabled
        and text(adapter.get("Name")).lower() not in {name.lower() for name in allowed_enabled}
    ]
    adapter_policy_configured = bool(as_list(expected.get("absent_adapters")) or allowed_enabled)
    ipc0054_state = (
        bool(as_list(network_adapters)) and absent_ok and not disallowed_enabled
        if adapter_policy_configured
        else None
    )
    checks["IPC0054"] = make_check(
        "IPC0054", "Nicht benötigte Netzwerkadapter deaktivieren",
        ipc0054_state,
        {
            "AbsentOrDisabled": expected.get("absent_adapters"),
            "AllowedEnabledAdapters": allowed_enabled,
        },
        {
            "AbsentChecks": absent_results,
            "EnabledHardwareAdapters": enabled_hardware,
            "DisallowedEnabledAdapters": disallowed_enabled,
        },
        "Initial_Valid.NetworkAdapters",
        "Semaphore: rollenabhaengige Adapter-Policy",
        "Ohne explizite OS-Server-Policy fuer deaktivierte/erlaubte aktive Adapter wird kein NOK erfunden.",
    )

    # IPC0056 - LMHOSTS deaktiviert.
    lmhosts_states = []
    lmhosts_ok = bool(terminalbus)
    for adapter in terminalbus:
        wins = as_dict(adapter.get("WINS"))
        state = wins.get("EnableLMHostsLookup")
        lmhosts_states.append({"Name": adapter.get("Name"), "EnableLMHostsLookup": state})
        lmhosts_ok = lmhosts_ok and int_value(state) == int_value(expected.get("enable_lmhosts"))
    checks["IPC0056"] = make_check(
        "IPC0056", "LMHOSTS-Abfrage deaktivieren", lmhosts_ok,
        {"EnableLMHostsLookup": expected.get("enable_lmhosts")}, lmhosts_states,
        "Initial_Valid.NetworkAdapters[].WINS.EnableLMHostsLookup",
        "Semaphore: expected_enable_lmhosts",
    )

    # IPC0059 - Domain oder Arbeitsgruppe ausgeben.
    domain = as_dict(domain_info)
    domain_state = None
    if domain:
        domain_state = (
            {"Modus": "DOMAENE", "Domain": domain.get("Domain"), "ComputerAccountDN": domain.get("ComputerAccountDN")}
            if bool_value(domain.get("PartOfDomain")) is True
            else {"Modus": "ARBEITSGRUPPE", "Workgroup": domain.get("Workgroup")}
        )
    info["IPC0059"] = make_information(
        "IPC0059", "Rechner in die Domäne aufnehmen", domain_state,
        "Initial_Valid.DomainInformation", "Domainname bzw. Arbeitsgruppe wird ausgegeben.",
    )

    # IPC0060 - OU gegen Semaphore-Regex.
    ou_text = " ".join([
        text(domain.get("ComputerAccountDN")), text(domain.get("ComputerAccountParentDN")),
        text(domain.get("ComputerAccountOU")), " ".join(text(x) for x in as_list(domain.get("OrganizationalUnits"))),
    ])
    ou_regex = text(expected.get("computer_ou_regex"))
    ipc0060_state = (
        bool(ou_text.strip()) and regex_search(ou_regex, ou_text)
        if ou_regex
        else None
    )
    checks["IPC0060"] = make_check(
        "IPC0060", "Rechner in der OU einsortieren",
        ipc0060_state,
        ou_regex or "projektspezifischer OU-Sollwert nicht konfiguriert", domain,
        "Initial_Valid.DomainInformation",
        "Semaphore: domain.ou_regex / expected_computer_ou_regex",
        "Ohne projektspezifischen OU-Sollwert wird kein NOK erzeugt.",
    )

    # IPC0065 / IPC0066 - vorhandene UltraVNC-Evidenz ausgeben; genaue
    # MS-Logon-/File-Transfer-Optionen werden vom Snapshot nicht normalisiert.
    vnc_products_all = product_matches(products, r"UltraVNC|uvnc")
    vnc_services = matching_services(services, r"UltraVNC|uvnc|winvnc")
    for task_id, task_name in (
        ("IPC0065", "VNC-Gruppe einstellen"),
        ("IPC0066", "VNC-Einstellungen konfigurieren"),
    ):
        info[task_id] = make_information(
            task_id, task_name,
            {"InstalledSoftware": vnc_products_all, "Services": vnc_services},
            "InstalledSoftware + Services",
            "UltraVNC-Präsenz ist nachweisbar; konkrete Admin-Optionen/Gruppen bleiben manuell zu vergleichen.",
        )

    # IPC0072 - Partitionen ausgeben.
    info["IPC0072"] = make_information(
        "IPC0072", "Partition (C: 100GB; D Rest)", storage,
        "Initial_Valid.Storage", "Disks, Partitions und Volumes inkl. SizeBytes.",
    )

    # IPC0079 - Speed & Duplex Auto Negotiation.
    target_adapters = [
        adapter for adapter in as_list(network_adapters)
        if isinstance(adapter, dict)
        and regex_search(expected.get("network_adapter_name_regex"), adapter.get("Name"))
        and not regex_search(expected.get("excluded_network_adapter_name_regex"), adapter.get("Name"))
        and bool_value(adapter.get("Virtual")) is not True
    ]
    speed_details = []
    speed_ok = bool(target_adapters)
    for adapter in target_adapters:
        candidates = []
        for prop in as_list(adapter.get("AdvancedProperties")):
            if not isinstance(prop, dict):
                continue
            haystack = text(prop.get("DisplayName")) + " " + text(prop.get("RegistryKeyword"))
            if regex_search(r"Speed.*Duplex|Duplex|LinkSpeed", haystack):
                candidates.append(prop)
        candidate_ok = bool(candidates) and any(
            regex_search(r"Auto|Automatisch", text(prop.get("DisplayValue")))
            for prop in candidates
        )
        speed_ok = speed_ok and candidate_ok
        speed_details.append({"Name": adapter.get("Name"), "Candidates": candidates, "OK": candidate_ok})
    checks["IPC0079"] = make_check(
        "IPC0079", "Einstellungen Netzwerkkarte überprüfen (1000MBit/s, Automatisch)", speed_ok,
        "Speed & Duplex = Auto Negotiation", speed_details,
        "Initial_Valid.NetworkAdapters[].AdvancedProperties", "Aufgabenliste",
    )

    # IPC0080 - Adapter-Energiesparen aus.
    power_details = []
    power_ok = bool(target_adapters)
    for adapter in target_adapters:
        pm = as_dict(adapter.get("PowerManagement"))
        allow = pm.get("AllowComputerToTurnOffDevice")
        item_ok = bool_value(allow) is False
        power_ok = power_ok and item_ok
        power_details.append({"Name": adapter.get("Name"), "AllowComputerToTurnOffDevice": allow, "OK": item_ok})
    checks["IPC0080"] = make_check(
        "IPC0080", "Energiesparoptionen für Netzwerkkarten deaktivieren", power_ok,
        "AllowComputerToTurnOffDevice = false", power_details,
        "Initial_Valid.NetworkAdapters[].PowerManagement", "Aufgabenliste",
    )

    # IPC0088 - aktiver Energieplan.
    active_power_plan = as_dict(as_dict(best_practice).get("ActivePowerPlan"))
    plan_name = text(active_power_plan.get("ElementName"))
    checks["IPC0088"] = make_check(
        "IPC0088", "Kontrolle Energieoptionen",
        bool(plan_name) and regex_search(expected.get("power_plan_regex"), plan_name),
        expected.get("power_plan_regex"), active_power_plan,
        "Initial_Valid.InstallationBestPractice.ActivePowerPlan",
        "Semaphore: expected_power_plan_regex",
    )
    # IPC0087 - Energie-Endzustand soweit der Snapshot ihn belegt.
    expected_display = int_value(expected.get("display_timeout_ac_minutes"))
    expected_disk = int_value(expected.get("disk_timeout_ac_minutes"))
    display_actual = (
        active_power_plan.get("DisplayTimeoutAcMinutes")
        if "DisplayTimeoutAcMinutes" in active_power_plan
        else as_dict(best_practice).get("DisplayTimeoutAcMinutes")
    )
    disk_actual = (
        active_power_plan.get("DiskTimeoutAcMinutes")
        if "DiskTimeoutAcMinutes" in active_power_plan
        else as_dict(best_practice).get("DiskTimeoutAcMinutes")
    )
    plan_ok_0087 = (
        regex_search(expected.get("power_plan_regex"), plan_name)
        if plan_name and expected.get("power_plan_regex")
        else None
    )
    timeout_states = []
    if expected_display is not None and display_actual is not None:
        timeout_states.append(int_value(display_actual) == expected_display)
    if expected_disk is not None and disk_actual is not None:
        timeout_states.append(int_value(disk_actual) == expected_disk)
    ipc0087_state = None
    if plan_ok_0087 is False or any(state is False for state in timeout_states):
        ipc0087_state = False
    elif plan_ok_0087 is True and len(timeout_states) == 2 and all(timeout_states):
        ipc0087_state = True
    checks["IPC0087"] = make_check(
        "IPC0087", 'Energieoptionen auf "Höchstleistung" setzen',
        ipc0087_state,
        {
            "ActivePlanNameRegex": expected.get("power_plan_regex"),
            "DisplayTimeoutAcMinutes": expected_display,
            "DiskTimeoutAcMinutes": expected_disk,
        },
        {
            "ActivePowerPlan": active_power_plan,
            "DisplayTimeoutAcMinutes": display_actual,
            "DiskTimeoutAcMinutes": disk_actual,
        },
        "Initial_Valid.InstallationBestPractice",
        "Semaphore: power.by_type.OS_Server",
        (
            "OK wird nur vergeben, wenn Plan und beide AC-Timeouts belastbar vorliegen. "
            "Fehlende Timeout-Felder fuehren zu NICHT_PRUEFBAR statt zu einem erfundenen OK/NOK."
        ),
    )

    # IPC0102 - Redundanzbus / SIMATIC Shell indirekt.
    info["IPC0102"] = make_information(
        "IPC0102", "SIMATIC Shell Redundanzbus",
        {"SimaticShellEvidence": simatic_shell, "NetworkAdapters": network_adapters},
        "Software_PCS7_Components_Valid.SimaticShellEvidence + Initial_Valid.NetworkAdapters",
        "Partneradresse ist dynamisch/projektspezifisch; vorhandene Shell-/Redundanzbus-Evidenz wird ausgegeben.",
    )

    # PCS-7-/Library-Komponenten fuer OS Server.
    component_specs = [
        ("IPC0111", "PTE400 V10.0", r"PTE\s*400.*V?10", None, "PTE400 V10.0 installiert"),
        ("IPC0112", "SENTRON 3WL/3VL V10", r"SENTRON.*(3WL.*3VL|3WLVL).*V?10", None, "SENTRON 3WL/3VL V10.0 OS-Komponente vorhanden"),
        ("IPC0113", "SENTRON PAC V10", r"SENTRON.*PAC.*V?10", None, "SENTRON PAC V10.0 OS-Komponente vorhanden"),
        ("IPC0114", "SIMOCODE pro PCS7 V10.0", r"SIMOCODE\s*pro.*V?10", None, "SIMOCODE pro V10.0 OS-Komponente vorhanden"),
        ("IPC0115", "SIMOCODE Migration Legacy V10.0", r"SIMOCODE.*Migration.*Legacy.*V?10", None, "SIMOCODE Migration Legacy V10.0 OS-Komponente vorhanden"),
        ("IPC0117", "S7 F Systems V6.4 SP1", r"S7[\s-]*F[\s-]*Systems.*V?6[\._ ]?4.*SP1", None, "S7 F Systems V6.4 SP1 Runtime/HMI vorhanden"),
        ("IPC0119", "Industry Library V10.0", r"Industry\s*Library.*V?10", None, "Industry Library V10.0 OS-Komponente vorhanden"),
        ("IPC0120", "PowerControl V9.1", r"PowerControl.*V?9[\._ ]?1", None, "PowerControl V9.1 OS-Komponente vorhanden"),
        ("IPC0121", "PowerControl V9.1 Update 1", r"PowerControl.*V?9[\._ ]?1.*(Upd|Update)\s*1", None, "PowerControl V9.1 Update 1 vorhanden"),
        ("IPC0122", "DriveES PCS 7 APL V10.0", r"Drive\s*ES.*PCS\s*7.*APL.*V?10", None, "Drive ES PCS7 APL V10 OS-Komponente vorhanden"),
        ("IPC0123", "SITOP PCS 7 APL V4.0", r"SITOP.*PCS\s*7.*APL.*V?4[\._ ]?0", None, "SITOP PCS7 APL V4.0 OS-Komponente vorhanden"),
        ("IPC0124", "SIMATIC Safety Matrix V6.3 SP1", r"Safety\s*Matrix.*V?6[\._ ]?3.*SP1", None, "Safety Matrix V6.3 SP1 Runtime/Viewer vorhanden"),
    ]
    for task_id, task_name, name_rx, version_rx, soll in component_specs:
        checks[task_id] = software_presence_check(task_id, task_name, installed_software, name_rx, version_rx, soll)

    # IPC0125 - Lizenz-/ALM-Evidenz ohne Schluesselmaterial.
    info["IPC0125"] = make_information(
        "IPC0125", "PCS 7 Lizenzen zuweisen", alm_evidence,
        "Software_PCS7_Components_Valid.AutomationLicenseManagerEvidence",
        "ALM-/Lizenz-Evidenz wird ausgegeben; Lizenzschluessel werden absichtlich nicht exportiert.",
    )

    # IPC0126 - UC02: Setup-/Software-Evidenz, kein eigener sicherer Detector.
    uc02_products = product_matches(products, r"PCS\s*7.*(UC\s*0?2|Update.*Collection.*0?2)")
    info["IPC0126"] = make_information(
        "IPC0126", "PCS 7 V10 UC02 Installieren",
        {"InstalledSoftwareMatches": uc02_products, "SetupLogEvidence": setup_logs},
        "InstalledSoftware + PCS7SetupLogEvidence",
        "UC02 wird mangels normalisiertem eindeutigen Detektor als Evidenz ausgegeben.",
    )

    # SP1/Add-ons nach aktuellem installierten Zustand.
    sp1_specs = [
        ("IPC0127", "PCS7 V10 SP1 installieren", r"(SIMATIC\s*PCS\s*7|PCS\s*7).*V?10(?:\.0)?.*SP\s*1", None, "PCS 7 V10.0 SP1 installiert"),
        ("IPC0128", "Industry Library 10.0 Upd1 aktualisieren", r"Industry\s*Library.*V?10(?:\.0)?.*(Upd|Update)\s*1", None, "Industry Library V10.0 Update 1 installiert"),
        ("IPC0129", "SENTRON 3WL/3VL V10.0 SP1", r"SENTRON.*(3WL.*3VL|3WLVL).*V?10(?:\.0)?.*SP\s*1", None, "SENTRON 3WL/3VL V10.0 SP1 installiert"),
        ("IPC0130", "SENTRON PAC V10.0 SP1", r"SENTRON.*PAC.*V?10(?:\.0)?.*SP\s*1", None, "SENTRON PAC V10.0 SP1 installiert"),
        ("IPC0131", "SIMOCODE pro PCS7 V10.0 SP1", r"SIMOCODE\s*pro.*V?10(?:\.0)?.*SP\s*1", None, "SIMOCODE pro V10.0 SP1 installiert"),
        ("IPC0132", "SIMOCODE Migration Legacy V10.0 SP1", r"SIMOCODE.*Migration.*Legacy.*V?10(?:\.0)?.*SP\s*1", None, "SIMOCODE Migration Legacy V10.0 SP1 installiert"),
    ]
    for task_id, task_name, name_rx, version_rx, soll in sp1_specs:
        checks[task_id] = software_presence_check(task_id, task_name, installed_software, name_rx, version_rx, soll)

    # IPC0136 / 0254 - SIMATIC Shell Proxy Evidenz.
    for task_id, task_name in (
        ("IPC0136", "SIMATIC SHELL Multicast Proxy Konfig"),
        ("IPC0254", "SIMATIC SHELL Proxy ergänzen"),
    ):
        info[task_id] = make_information(
            task_id, task_name, simatic_shell,
            "Software_PCS7_Components_Valid.SimaticShellEvidence",
            "Proxy-/Remote-Kommunikations-Evidenz wird ausgegeben; vollstaendige Stationsliste ist nicht garantiert normalisiert.",
        )

    # IPC0139 - WinCC/OPC-Server Evidenz; Aufgabenbeschreibung hat widerspruechliche Versionsangaben.
    info["IPC0139"] = make_information(
        "IPC0139", "WinCC OPCServer", product_matches(products, r"WinCC.*OPC|OPC.*Server"),
        "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts",
        "Wegen widerspruechlicher Versionsangaben in Titel/Pfad kein automatisches OK/NOK.",
    )

    # IPC0140 - ORCLA installiert.
    checks["IPC0140"] = software_presence_check(
        "IPC0140", "ORCLA installieren", installed_software, r"ORCLA", None, "ORCLA installiert"
    )

    # IPC0141 - Maintenance-Funktionen indirekt.
    info["IPC0141"] = make_information(
        "IPC0141", "PCS 7 Maintenance Funktionen für OS installieren",
        product_matches(products, r"(PCS\s*7|SIMATIC).*Maintenance|Maintenance.*(PCS\s*7|SIMATIC)"),
        "InstalledSoftware.AllProducts",
        "Installierte Maintenance-Komponenten werden ausgegeben; Rahmensetup-Auswahl ist historisch nicht beweisbar.",
    )

    # IPC0142 - ORCLA Watchdog + OPC UA Dienste vorhanden/nicht deaktiviert.
    watchdog = matching_services(services, r"ORCLA.*Watchdog|Watchdog.*ORCLA")
    opcua = matching_services(services, r"ORCLA.*OPC.*UA|OPC.*UA.*ORCLA")
    watchdog_ok = bool(watchdog) and any(text(x.get("StartClassification")).lower() != "disabled" for x in watchdog)
    opcua_ok = bool(opcua) and any(text(x.get("StartClassification")).lower() != "disabled" for x in opcua)
    checks["IPC0142"] = make_check(
        "IPC0142", "Watchdog und OPC UA server", watchdog_ok and opcua_ok,
        "ORCLA Watchdog und ORCLA OPC-UA-Dienst vorhanden und nicht deaktiviert",
        {"Watchdog": watchdog, "OPCUA": opcua},
        "Certificates_Services_Drivers_Valid.Services", "Aufgabenliste",
    )

    # IPC0143-0146 - lokale Zertifikat-/Binding-Evidenz.
    # IPC0145/0146 bleiben fuer OS Server im Scope, weil ORCLA/OPC-UA auf
    # dem OS Server betrieben wird. Ohne eindeutige Trust-Store-
    # Normalisierung bleibt die Bewertung bewusst INFORMATION.
    cert_info = {"Certificates": certificates, "Bindings": certificate_bindings}
    for task_id in ("IPC0143", "IPC0144", "IPC0145", "IPC0146"):
        info[task_id] = make_information(
            task_id, TASK_NAMES.get(task_id, "Zertifikate austauschen"), cert_info,
            "Certificates_Services_Drivers_Valid.Certificates/CertificateBindings",
            (
                "Lokale Zertifikate und Bindings werden ausgegeben. Der Austausch "
                "zwischen Kommunikationspartnern ist aus der lokalen Snapshotquelle "
                "nicht vollstaendig beweisbar."
            ),
        )

    # IPC0150 - BitLocker Systemvolume C:.
    bitlocker_rows = as_list(as_dict(best_practice).get("BitLocker"))
    system_bitlocker = [row for row in bitlocker_rows if isinstance(row, dict) and text(row.get("MountPoint")).upper().startswith("C:")]
    bitlocker_ok = bool(system_bitlocker) and any(
        text(row.get("ProtectionStatus")).lower() in {"on", "1", "enabled"}
        and (int_value(row.get("EncryptionPercentage")) or 0) >= 100
        for row in system_bitlocker
    )
    checks["IPC0150"] = make_check(
        "IPC0150", "BitLocker Aktivierung", bitlocker_ok,
        "C: ProtectionStatus=On und EncryptionPercentage=100", system_bitlocker,
        "Initial_Valid.InstallationBestPractice.BitLocker", "Aufgabenliste",
    )

    # IPC0151 - Hardening-Dienste deaktiviert.
    service_ok, service_details = check_disabled_services(services, expected.get("disabled_service_patterns"))
    checks["IPC0151"] = make_check(
        "IPC0151", "Deaktivieren von Diensten", service_ok,
        {"ServicePatterns": expected.get("disabled_service_patterns"), "StartMode": "Disabled"},
        service_details,
        "Certificates_Services_Drivers_Valid.Services.Services",
        "Semaphore: expected_disabled_service_patterns",
    )

    # IPC0153 - Telemetrie 0.
    telemetry = as_list(as_dict(policy_areas).get("Telemetry"))
    telemetry_value, telemetry_rows = first_registry_value(telemetry, name="AllowTelemetry")
    if telemetry_value is None:
        telemetry_value, telemetry_rows = first_registry_value(telemetry, name="AllowDiagnosticData")
    checks["IPC0153"] = make_check(
        "IPC0153", "Einstellung von Datenschutz- und Telemetriedaten in Windows 10 Teil 2",
        int_value(telemetry_value) == 0,
        "Telemetrie / Diagnosedaten = 0", telemetry_rows,
        "GPOs_Valid.PolicyAreaSnapshots.Telemetry", "Aufgabenliste",
    )

    # IPC0154 / IPC0155 - SMB.
    smb_dict = as_dict(smb)
    server_cfg = as_dict(smb_dict.get("ServerConfiguration"))
    client_cfg = as_dict(smb_dict.get("ClientConfiguration"))
    effective_registry = as_dict(smb_dict.get("EffectiveRegistry"))
    server_registry = as_dict(effective_registry.get("Server"))
    client_registry = as_dict(effective_registry.get("Client"))
    server_require = smb_config_value(server_cfg, server_registry, "RequireSecuritySignature")
    server_enable = smb_config_value(server_cfg, server_registry, "EnableSecuritySignature")
    client_require = smb_config_value(client_cfg, client_registry, "RequireSecuritySignature")
    checks["IPC0154"] = make_check(
        "IPC0154", "SMB Signierung",
        bool_value(server_require) is True and bool_value(server_enable) is True and bool_value(client_require) is True,
        {
            "Server.RequireSecuritySignature": True,
            "Server.EnableSecuritySignature": True,
            "Client.RequireSecuritySignature": True,
        },
        {
            "Server.RequireSecuritySignature": server_require,
            "Server.EnableSecuritySignature": server_enable,
            "Client.RequireSecuritySignature": client_require,
        },
        "Firewall_SMB_Patch_Valid.SMB", "Aufgabenliste",
    )
    encrypt_data = smb_config_value(server_cfg, server_registry, "EncryptData")
    checks["IPC0155"] = make_check(
        "IPC0155", "SMBv3-Verschlüsselung", bool_value(encrypt_data) is True,
        {"SmbServerConfiguration.EncryptData": True}, {"EncryptData": encrypt_data},
        "Firewall_SMB_Patch_Valid.SMB.ServerConfiguration", "Aufgabenliste",
    )

    # IPC0156 - RDP deaktiviert.
    effective_values = as_list(as_dict(effective_policy).get("Values"))
    terminal_service_policy = as_list(as_dict(policy_areas).get("TerminalServices"))
    rdp_value, rdp_rows = first_registry_value(effective_values, name="fDenyTSConnections")
    if rdp_value is None:
        rdp_value, rdp_rows = first_registry_value(terminal_service_policy, name="fDenyTSConnections")
    checks["IPC0156"] = make_check(
        "IPC0156", "Remote Desktop Security Einstellung", int_value(rdp_value) == 1,
        {"fDenyTSConnections": 1}, rdp_rows,
        "GPOs_Valid.InstallationRelevantEffectiveSettings / PolicyAreaSnapshots.TerminalServices", "Aufgabenliste",
    )

    # IPC0159 - Schannel.
    schannel_ok, schannel_details = check_schannel_protocols(
        effective_values,
        expected.get("disabled_schannel_protocols"),
        expected.get("enabled_schannel_protocols"),
    )
    checks["IPC0159"] = make_check(
        "IPC0159", "Deaktivierung von veralteten SSL-/TLS-Kommunikationsverfahren", schannel_ok,
        {
            "deaktiviert": expected.get("disabled_schannel_protocols"),
            "aktiviert": expected.get("enabled_schannel_protocols"),
        },
        schannel_details,
        "GPOs_Valid.InstallationRelevantEffectiveSettings.Values (SCHANNEL)",
        "Semaphore: expected_disabled_schannel_protocols/expected_enabled_schannel_protocols",
    )

    # IPC0162 / IPC0163 - ALM indirekt.
    info["IPC0162"] = make_information(
        "IPC0162", "Parametrierung des ALM als Lizenzserver", alm_evidence,
        "Software_PCS7_Components_Valid.AutomationLicenseManagerEvidence",
        "Remote-Lizenzserver-Evidenz wird ausgegeben; ohne normalisierten eindeutigen ALM-Schalter kein automatisches OK/NOK.",
    )
    info["IPC0163"] = make_information(
        "IPC0163", "ALM Spracheinstellung", alm_evidence,
        "Software_PCS7_Components_Valid.AutomationLicenseManagerEvidence",
        "ALM-Evidenz wird ausgegeben; die UI-Sprache ist im Snapshot nicht als festes Feld normalisiert.",
    )

    # IPC0166 - Firewallprofile aktiv + aktive Netzwerke privat.
    fw_profiles = as_list(as_dict(firewall).get("Profiles"))
    active_profiles = as_list(as_dict(firewall).get("ActiveNetworkProfiles"))
    required_names = {"domain", "private", "public"}
    seen = {text(x.get("Name")).lower() for x in fw_profiles if isinstance(x, dict)}
    profiles_ok = required_names.issubset(seen) and all(
        bool_value(x.get("Enabled")) is True
        for x in fw_profiles
        if isinstance(x, dict) and text(x.get("Name")).lower() in required_names
    )
    private_ok = bool(active_profiles) and all(
        text(x.get("NetworkCategory")).lower() == "private"
        for x in active_profiles if isinstance(x, dict)
    )
    checks["IPC0166"] = make_check(
        "IPC0166", "Windows-Firewall", profiles_ok and private_ok,
        {"FirewallProfiles": {"Domain": True, "Private": True, "Public": True}, "ActiveNetworkCategory": "Private"},
        {"Profiles": fw_profiles, "ActiveNetworkProfiles": active_profiles},
        "Firewall_SMB_Patch_Valid.Firewall", "Aufgabenliste",
    )

    # IPC0168 - Projektordner + Freigabe aus Snapshot.
    folder_ok, share_ok, project_shares = project_share_state(
        smb, expected.get("project_folder"), expected.get("project_share")
    )
    checks["IPC0168"] = make_check(
        "IPC0168", "Ordner freigeben", folder_ok and share_ok,
        {"Folder": expected.get("project_folder"), "Share": expected.get("project_share"), "FolderExists": True, "ShareExists": True},
        project_shares if project_shares else "Keine passende Projektfreigabe gefunden",
        "Firewall_SMB_Patch_Valid.SMB.Shares",
        "Semaphore: expected_project_folder/expected_project_share",
    )

    # IPC0180 - SSMS 20.2.1.
    checks["IPC0180"] = software_presence_check(
        "IPC0180", "SQL Server MGMT Studio", installed_software,
        r"SQL\s*Server\s*Management\s*Studio|SSMS", r"^20\.2\.1(?:\D|$)",
        "SQL Server Management Studio 20.2.1 installiert",
    )

    # IPC0182 / 0183 / 0184 - BGSiVaaS.
    shared_tools = as_dict(as_dict(expected.get("_shared_expected")).get("tools"))
    bgsivaas_expected = as_dict(shared_tools.get("bgsivaas"))
    bg_pattern = bgsivaas_expected.get("startup_target_regex") or r"BGSiVaaS|BGInfo"
    bg_matches = startup_matches(autoruns, bg_pattern)
    checks["IPC0182"] = make_check(
        "IPC0182", "BGInfo/BGSiVaaS",
        bool(bg_matches) if isinstance(autoruns, dict) else None,
        {
            "StartupRequired": bool_value(bgsivaas_expected.get("startup_required")) if bgsivaas_expected else True,
            "TargetRegex": bg_pattern,
            "ExecutablePath": bgsivaas_expected.get("executable_path"),
        },
        bg_matches if isinstance(autoruns, dict) else None,
        "Firewall_SMB_Patch_Valid.Autoruns",
        "Semaphore: tools.bgsivaas / Aufgabenliste",
    )
    info["IPC0183"] = make_information(
        "IPC0183", "BGInfo/BGSiVaaS - Als Administrator ausführen", bg_matches,
        "Firewall_SMB_Patch_Valid.Autoruns.StartupFolders",
        "Shortcut-Evidenz wird ausgegeben; RunAsAdmin-Flag wird nicht separat erfasst.",
    )
    info["IPC0184"] = make_information(
        "IPC0184", "Hintergrundbild anpassen", bg_matches,
        "Firewall_SMB_Patch_Valid.Autoruns",
        "BGSiVaaS-Start-Evidenz wird ausgegeben; visuelles Endergebnis des Hintergrundbilds ist kein Snapshotfeld.",
    )

    # IPC0202 / IPC0203 - SIMATIC Logon.
    checks["IPC0202"] = software_presence_check(
        "IPC0202", "SIMATIC Logon installieren", installed_software,
        r"SIMATIC\s*Logon", r"^2\.0", "SIMATIC Logon V2.0 installiert",
    )
    simatic_upd = product_matches(products, r"SIMATIC\s*Logon.*(Upd|Update)\s*1")
    if not simatic_upd:
        simatic_upd = product_matches(products, r"SIMATIC\s*Logon", r"^2\.0(?:\.\d+)*\.1(?:\D|$)")
    checks["IPC0203"] = make_check(
        "IPC0203", "SIMATIC Logon aktualisieren", bool(simatic_upd),
        "SIMATIC Logon V2.0 Update 1 installiert", simatic_upd,
        "InstalledSoftware.AllProducts", "Aufgabenliste",
    )

    simatic_logon_registry = registry_evidence_matches(
        siemens_registry, r"SIMATIC.*Logon|Logon.*SIMATIC|Automatic.*Log|Auto.*Log"
    )
    info["IPC0204"] = make_information(
        "IPC0204", "SIMATIC Logon konfigurieren", simatic_logon_registry,
        "Software_PCS7_Components_Valid.SiemensRegistryEvidence",
        "SIMATIC-Logon-Evidenz fuer automatisches Abmelden wird ausgegeben; Checkbox ist nicht als festes Feld normalisiert.",
    )

    # IPC0210 - WinCC Explorer Sprache indirekt.
    wincc_language = registry_evidence_matches(
        siemens_registry, r"WinCC.*(Language|Sprache|Locale)|(?:Language|Sprache|Locale).*WinCC"
    )
    info["IPC0210"] = make_information(
        "IPC0210", "WinCC Explorer Sprache auf Deutsch ändern", wincc_language,
        "Software_PCS7_Components_Valid.SiemensRegistryEvidence",
        "Gefundene WinCC-Sprach-/Locale-Evidenz wird ausgegeben; ohne normiertes Feld kein automatisches OK/NOK.",
    )

    # OS-Server-Patches.
    for task_id, kb, task_name in (
        ("IPC0224", "KB5055526", "KB5055526"),
        ("IPC0225", "KB5050187", "KB5050187"),
        ("IPC0226", "KB5046860", "KB5046860"),
        ("IPC0227", "KB5054833", "KB5054833"),
    ):
        present, evidence = current_kb_evidence(patch_status, installed_software, kb)
        checks[task_id] = make_check(
            task_id, task_name, present, kb + " aktuell installiert", evidence,
            "Firewall_SMB_Patch_Valid.PatchStatus + InstalledSoftware", "Aufgabenliste",
        )
    checks["IPC0228"] = software_presence_check(
        "IPC0228", "Microsoft Edge Stable 137.0.3296.83", installed_software,
        r"^Microsoft\s*Edge(?:\s|$)", r"^137\.0\.3296\.83(?:\D|$)",
        "Microsoft Edge 137.0.3296.83 installiert",
    )

    # IPC0234 - Pagefiles: Snapshot-Evidenz plus zentraler Sollwert.
    shared_system = as_dict(as_dict(expected.get("_shared_expected")).get("system"))
    pagefile_expected = as_dict(shared_system.get("pagefile"))
    pagefiles_actual = as_dict(best_practice).get("PageFiles")
    info["IPC0234"] = make_information(
        "IPC0234", "Auslagerungsdatei konfigurieren",
        {
            "Expected": pagefile_expected,
            "ActualPageFiles": pagefiles_actual,
        } if (pagefile_expected or pagefiles_actual is not None) else None,
        "Initial_Valid.InstallationBestPractice.PageFiles",
        (
            "Soll- und Istwerte werden gemeinsam ausgegeben. Automatisches OK/NOK "
            "erst bei eindeutig normalisierten SystemManaged-/AutomaticManaged-Feldern."
        ),
    )

    # IPC0235 / IPC0238 - WinCC Autostart und Service-Mode Evidenz.
    wincc_registry = registry_evidence_matches(
        siemens_registry, r"WinCC.*(Auto|Start|Runtime|Project|Service)|Runtime.*(Start|Project|Service)"
    )
    wincc_autoruns = startup_matches(autoruns, r"WinCC|Runtime")
    info["IPC0235"] = make_information(
        "IPC0235", "WinCC Autostart konfigurieren",
        {"SiemensRegistryEvidence": wincc_registry, "Autoruns": wincc_autoruns},
        "SiemensRegistryEvidence + Autoruns",
        "WinCC-Runtime-/Autostart-Evidenz wird ausgegeben; Tray-UI-Konfiguration ist nicht vollstaendig normalisiert.",
    )
    service_mode = registry_evidence_matches(
        siemens_registry, r"WinCC.*Service.*Mode|Service.*Mode.*WinCC|WinCC_RT|Runtime.*Service"
    )
    info["IPC0238"] = make_information(
        "IPC0238", "Kontrolle Service-Mode", service_mode,
        "Software_PCS7_Components_Valid.SiemensRegistryEvidence",
        "OS-Server-Service-Mode-/WinCC_RT-Evidenz wird ausgegeben; ohne eindeutiges normiertes Feld manuelle Bewertung.",
    )

    # IPC0245 / IPC0246 - Firewall.
    checks["IPC0245"] = make_check(
        "IPC0245", "VNC-Viewer Firewallregel prüfen", vnc_fw_ok,
        "VNC-Regeln aktiviert, Inbound Allow, alle Profile", pattern_results,
        "Firewall_SMB_Patch_Valid.Firewall.Rules",
        "Semaphore: expected_firewall_rule_name_patterns + Aufgabenliste",
    )
    required = {"domain", "private", "public"}
    profile_map = {text(x.get("Name")).lower(): x for x in fw_profiles if isinstance(x, dict)}
    fw_all_ok = all(name in profile_map and bool_value(profile_map[name].get("Enabled")) is True for name in required)
    checks["IPC0246"] = make_check(
        "IPC0246", "Firewall für alle Profile aktiviert", fw_all_ok,
        {"Domain": True, "Private": True, "Public": True}, fw_profiles,
        "Firewall_SMB_Patch_Valid.Firewall.Profiles", "Aufgabenliste",
    )

    # IPC0247 - Defender Manipulationsschutz aus.
    defender_status = as_dict(as_dict(defender).get("ComputerStatus"))
    tamper = defender_status.get("IsTamperProtected")
    checks["IPC0247"] = make_check(
        "IPC0247", "Defender Einstellungen korrigieren - Manipulationsschutz",
        bool_value(tamper) is False,
        "IsTamperProtected = false", {"IsTamperProtected": tamper},
        "Initial_Valid.MicrosoftDefender.ComputerStatus.IsTamperProtected", "Aufgabenliste",
    )

    info["IPC0250"] = make_information(
        "IPC0250", "Defender Zuverlässigkeitsbasierter Schutz / Downloads", defender,
        "Initial_Valid.MicrosoftDefender",
        "Defender-Status/Preferences fuer manuellen Abgleich; konkrete UI-Option ist nicht normiert.",
    )
    info["IPC0251"] = make_information(
        "IPC0251", "Defender Sicherheitsstatus i.O.", defender,
        "Initial_Valid.MicrosoftDefender", "Vollstaendiger vorhandener Defender-Status.",
    )

    # ------------------------------------------------------------------
    # Zusaetzliche OS-Server-ID-Pruefungen, aus 0160-Prueflogik abgeleitet.
    # ------------------------------------------------------------------
    keyboard = as_dict(expected.get("keyboard"))
    current_user = as_dict(as_dict(language).get("CurrentUser"))
    preload = as_dict(current_user.get("KeyboardPreload"))
    preload_values = as_dict(preload.get("Values"))
    if preload_values:
        layouts = [text(v).lower().replace("0x", "").lstrip("0") or "0" for _, v in sorted(preload_values.items())]
        allowed = {text(v).lower().replace("0x", "").lstrip("0") or "0" for v in as_list(keyboard.get("allowed_layout_ids"))}
        exact = int_value(keyboard.get("exact_layout_count"))
        keyboard_state = exact is not None and len(layouts) == exact and all(v in allowed for v in layouts)
        keyboard_ist = {"Layouts": layouts, "Count": len(layouts)}
    else:
        keyboard_state = None
        keyboard_ist = None
    checks["IPC0009"] = make_check(
        "IPC0009", TASK_NAMES["IPC0009"], keyboard_state,
        {"AllowedLayoutIds": as_list(keyboard.get("allowed_layout_ids")), "ExactLayoutCount": int_value(keyboard.get("exact_layout_count"))},
        keyboard_ist, "Initial_Valid.LanguageAndRegion.CurrentUser.KeyboardPreload", "Semaphore: ipc_os_server_validation_expected.keyboard",
    )

    user_account = next((u for u in as_list(local_users) if isinstance(u, dict) and text(u.get("Name")).lower() == text(expected.get("initial_user_name", "User")).lower()), None)
    info["IPC0013"] = make_information(
        "IPC0013", TASK_NAMES["IPC0013"], user_account,
        "Initial_Valid.LocalUsers",
        "Benutzerexistenz und Kontoeigenschaften sind pruefbar; Klartext-Passwort und Password-Hint werden aus Sicherheitsgruenden nicht ausgelesen.",
    )

    language_list = as_list(as_dict(language).get("CurrentUserLanguageList"))
    language_tags = [text(as_dict(x).get("LanguageTag")) for x in language_list]
    checks["IPC0045"] = make_check(
        "IPC0045", TASK_NAMES["IPC0045"],
        (len(language_tags) == 1 and is_german(language_tags[0])) if language_tags else None,
        {"AllowedLanguages": ["de-DE"], "ExactCount": 1},
        language_tags if language_tags else None,
        "Initial_Valid.LanguageAndRegion.CurrentUserLanguageList", "Aufgabenliste",
    )

    checks["IPC0070"] = software_presence_check(
        "IPC0070", TASK_NAMES["IPC0070"], installed_software,
        r"UltraVNC|uvnc", None, "UltraVNC Viewer installiert",
    )
    # Uninstall-Inventar kann Server/Viewer nicht immer getrennt ausweisen; Live-Pruefung ueberschreibt diesen Eintrag, sofern verfuegbar.

    hup_matches = product_matches(products, text(expected.get("hup_name_regex") or r"\bHUP\b")) if products else []
    checks["IPC0078"] = make_check(
        "IPC0078", TASK_NAMES["IPC0078"], bool(hup_matches) if products else None,
        {"NameRegex": text(expected.get("hup_name_regex") or r"\bHUP\b"), "Installed": True}, hup_matches if products else None,
        "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts", "Semaphore/Aufgabenliste",
    )

    comp_rows = component_records(windows_components)
    netfx = component_matches(comp_rows, r"^(NET-Framework-Core|NetFx3)(?:\s|$)")
    wcf = component_matches(comp_rows, r"^(NET-WCF-HTTP-Activation|NET-WCF-NonHTTP-Activ|WCF-HTTP-Activation|WCF-NonHTTP-Activation)(?:\s|$)")
    netfx_state = None if not comp_rows else (bool(netfx) and any(x.get("Enabled") is True for x in netfx) and all(x.get("Enabled") is not True for x in wcf))
    checks["IPC0081"] = make_check("IPC0081", TASK_NAMES["IPC0081"], netfx_state, {"NETFramework35": "aktiviert", "WCFActivation35": "nicht aktiviert"}, {"NetFx35": netfx, "WCFActivation35": wcf} if comp_rows else None, "Initial_Valid.WindowsComponents", "Aufgabenliste")
    msmq = component_matches(comp_rows, r"^MSMQ-Server(?:\s|$)")
    checks["IPC0082"] = make_check("IPC0082", TASK_NAMES["IPC0082"], None if not comp_rows else (bool(msmq) and any(x.get("Enabled") is True for x in msmq)), {"MSMQ-Server": "aktiviert"}, msmq if comp_rows else None, "Initial_Valid.WindowsComponents", "Aufgabenliste")

    observations = as_dict(as_dict(dotnet_prereq).get("Observations"))
    netfx3_detected = bool_value(observations.get("NetFx3DetectedEnabled"))
    checks["IPC0091"] = make_check("IPC0091", TASK_NAMES["IPC0091"], None if not isinstance(dotnet_prereq, dict) else (netfx3_detected is True), {"NetFx3DetectedEnabled": True}, as_dict(dotnet_prereq) if isinstance(dotnet_prereq, dict) else None, "Software_PCS7_Components_Valid.DotNetAndRuntimePrerequisites", "Aufgabenliste")

    qv_state, qv_evidence = cert_prereq_state(cert_prereq, "QuoVadisRootCA2")
    vs_state, vs_evidence = cert_prereq_state(cert_prereq, "VeriSignClass3PublicPrimaryCertificationAuthorityG5")
    checks["IPC0092"] = make_check("IPC0092", TASK_NAMES["IPC0092"], qv_state if isinstance(cert_prereq, dict) else None, {"Certificate": "QuoVadis Root CA 2", "Detected": True}, qv_evidence, "Software_PCS7_Components_Valid.PCS7CertificatePrerequisites.QuoVadisRootCA2", "Aufgabenliste")
    checks["IPC0093"] = make_check("IPC0093", TASK_NAMES["IPC0093"], vs_state if isinstance(cert_prereq, dict) else None, {"Certificate": "VeriSign Class 3 Public Primary Certification Authority - G5", "Detected": True}, vs_evidence, "Software_PCS7_Components_Valid.PCS7CertificatePrerequisites.VeriSignClass3PublicPrimaryCertificationAuthorityG5", "Aufgabenliste")
    checks["IPC0108"] = referenced_check("IPC0108", TASK_NAMES["IPC0108"], "IPC0093", checks.get("IPC0093"), "Identischer Zertifikat-Endzustand wie IPC0093.")

    cert_policy_values = registry_records(explicit_policy)
    disable_root, disable_root_rows = first_registry_value(cert_policy_values, name="DisableRootAutoUpdate", path_contains="Policies/Microsoft/SystemCertificates/AuthRoot")
    checks["IPC0095"] = make_check("IPC0095", TASK_NAMES["IPC0095"], None if disable_root is None else int_value(disable_root) == 0, {"DisableRootAutoUpdate": 0}, disable_root_rows if disable_root_rows else None, "GPOs_Valid.ExplicitlyConfiguredPolicyRegistry", "Aufgabenliste")
    info["IPC0094"] = make_information("IPC0094", TASK_NAMES["IPC0094"], [r for r in cert_policy_values if regex_search(r"Certificate|Cert|AuthRoot|Chain", " ".join([text(r.get("Path")), text(r.get("Name"))]))], "GPOs_Valid.ExplicitlyConfiguredPolicyRegistry", "Die vorhandene Certificate-Path-/AuthRoot-Policy-Evidenz wird ausgegeben; ohne eindeutigen normalisierten Einzelwert keine erfundene OK/NOK-Bewertung.")

    checks["IPC0104"] = software_presence_check("IPC0104", TASK_NAMES["IPC0104"], installed_software, r"PCS\s*7.*Faceplates.*V?7[._ ]?1.*SP\s*3.*(Upd|Update)\s*1|Faceplates.*7[._ ]?1.*SP\s*3.*(Upd|Update)\s*1", None, "SIMATIC PCS 7 Faceplates V7.1 SP3 Update 1 installiert")

    vc2010 = bool_value(observations.get("VisualCpp2010x86Detected"))
    checks["IPC0118"] = make_check("IPC0118", TASK_NAMES["IPC0118"], None if not isinstance(dotnet_prereq, dict) else (vc2010 is True), {"VisualCpp2010x86Detected": True}, {"VisualCpp2010x86Detected": observations.get("VisualCpp2010x86Detected")} if isinstance(dotnet_prereq, dict) else None, "Software_PCS7_Components_Valid.DotNetAndRuntimePrerequisites.Observations", "Aufgabenliste", "Geprueft wird der aktuelle Redistributable-Endzustand; die historische Reparaturaktion ist nicht nachweisbar.")

    active_features = [x for x in comp_rows if x.get("Enabled") is True]
    info["IPC0149"] = make_information("IPC0149", TASK_NAMES["IPC0149"], active_features if isinstance(windows_components, dict) else None, "Initial_Valid.WindowsComponents", "Alle aktuell aktiven Windows-Features werden dokumentiert. Ohne projektspezifische Negativliste kein pauschales OK/NOK.")

    access = as_dict(host.get("zugriff"))
    checks["IPC0147"] = make_check("IPC0147", TASK_NAMES["IPC0147"], bool(access.get("ansible_access")) if access else None, {"AnsibleAccess": True}, access if access else None, "0150.zugriff", "Endzustand des Enable_Ansible_Access-Schritts", "Der konkrete historische Skriptaufruf ist nicht beweisbar; bewertet wird der erreichbare Ansible/WinRM-Endzustand.")

    info["IPC0165"] = make_information("IPC0165", TASK_NAMES["IPC0165"], setup_logs, "Software_PCS7_Components_Valid.PCS7SetupLogEvidence", "Security-Controller-/Rahmensetup-Evidenz wird ausgegeben; der historische fehlerfreie Dialogdurchlauf ist nicht eindeutig als Einzelwert normalisiert.")

    info["IPC0185"] = make_information("IPC0185", TASK_NAMES["IPC0185"], {"BGInfoAutoruns": bg_matches, "LocalUsers": [u for u in as_list(local_users) if isinstance(u, dict) and regex_search(r"WinCC_RT", u.get("Name"))]}, "Firewall_SMB_Patch_Valid.Autoruns + Initial_Valid.LocalUsers", "Das visuelle Hintergrundbild im WinCC_RT-Benutzerprofil kann aus den vorhandenen Snapshots nicht belastbar bewertet werden.")
    checks["IPC0187"] = referenced_check("IPC0187", TASK_NAMES["IPC0187"], "IPC0027", checks.get("IPC0027"), "Wiederholungspruefung derselben VNC-Firewall-Endzustaende.")
    info["IPC0188"] = make_information("IPC0188", TASK_NAMES["IPC0188"], network_adapters, "Initial_Valid.NetworkAdapters", "hosts/lmhosts-Dateiinhalte sind im aktuellen Snapshot nicht als eigener normalisierter Abschnitt enthalten; Netzwerk-/WINS-Evidenz wird ausgegeben.")
    info["IPC0189"] = make_information("IPC0189", TASK_NAMES["IPC0189"], domain_info, "Initial_Valid.DomainInformation", "WORKGROUP war ein Zwischenzustand vor dem Domain-Join. Der aktuelle OS-Server-Endzustand ist Domainmitgliedschaft; der historische WORKGROUP-Schritt ist nachtraeglich nicht beweisbar.")
    info["IPC0190"] = make_information("IPC0190", TASK_NAMES["IPC0190"], vnc_services, "Certificates_Services_Drivers_Valid.Services", "Ein Neustart der VNC-Verbindung ist ein historischer Vorgang; dokumentiert wird der aktuelle UltraVNC-Dienstzustand.")
    checks["IPC0191"] = referenced_check("IPC0191", TASK_NAMES["IPC0191"], "IPC0038", checks.get("IPC0038"), "Identischer Endzustand des integrierten RID-500-Administratorkontos.")

    pm_matches = product_matches(products, r"PM[\s-]*Logon") if products else []
    pm26u4 = [x for x in pm_matches if regex_search(r"2[._ ]?6.*(Upd|Update)?[\s._-]*4|2\.6\.4", " ".join([text(x.get("DisplayName")), text(x.get("DisplayVersion"))]))]
    checks["IPC0205"] = make_check("IPC0205", TASK_NAMES["IPC0205"], bool(pm26u4) if products else None, {"PM-Logon": "V2.6 Update 4 Runtime"}, pm26u4 if products else None, "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts", "Aufgabenliste")
    pm_registry = registry_evidence_matches(siemens_registry, r"PM[\s-]*Logon|Webservice|Logon Devices|User Repositories|SIMATIC Logon")
    for tid in ("IPC0207", "IPC0208", "IPC0209"):
        info[tid] = make_information(tid, TASK_NAMES[tid], {"InstalledSoftware": pm_matches, "RegistryEvidence": pm_registry}, "Software_PCS7_Components_Valid.InstalledSoftware/SiemensRegistryEvidence", "PM-Logon-Installations- und Registry-Evidenz wird ausgegeben; credentials/Passwoerter werden nicht exportiert und die vollstaendige GUI-Konfiguration ist nicht normalisiert.")

    for task_id, kb in (("IPC0232", "KB5058385"), ("IPC0233", "KB5046859")):
        present, evidence = current_kb_evidence(patch_status, installed_software, kb)
        checks[task_id] = make_check(task_id, TASK_NAMES[task_id], present if isinstance(patch_status, dict) or isinstance(installed_software, dict) else None, {"RequiredKB": kb, "Installed": True}, evidence, "Firewall_SMB_Patch_Valid.PatchStatus + InstalledSoftware", "Aufgabenliste")

    sql2019 = product_matches(products, r"SQL\s*Server.*2019|Microsoft\s*SQL\s*Server\s*2019") if products else []
    wincc8 = product_matches(products, r"WinCC.*(?:V?8(?:\.0)?|8\.0)") if products else []
    checks["IPC0231"] = make_check("IPC0231", TASK_NAMES["IPC0231"], (bool(sql2019) and bool(wincc8)) if products else None, {"SQLServer2019": True, "WinCCV8": True}, {"SQLServer2019": sql2019, "WinCCV8": wincc8, "SQLServerComponents": sql_components}, "Software_PCS7_Components_Valid.InstalledSoftware/SQLServerComponents", "Aufgabenliste", "Geprueft wird der aktuelle Endzustand; die historische Deinstallation/Neuinstallation selbst ist nicht beweisbar.")

    checks["IPC0252"] = software_presence_check("IPC0252", TASK_NAMES["IPC0252"], installed_software, r"UltraVNC|uvnc", None, "UltraVNC Viewer installiert")

    # Fehlende Snapshot-Quellen duerfen nicht zu einem Konfigurations-NOK werden.
    # Das ist relevant, wenn eines der fuenf 0120-PowerShell-Skripte auf einem
    # ansonsten erreichbaren Host keinen verwertbaren Abschnitt liefern konnte.
    def downgrade_missing_source(task_ids, source_available, source_name):
        if source_available:
            return
        for task_id in task_ids:
            item = checks.get(task_id)
            if isinstance(item, dict) and item.get("status") == "NOK":
                checks[task_id] = make_not_testable(
                    task_id,
                    TASK_NAMES.get(task_id, task_id),
                    f"Snapshotquelle {source_name} fehlt; aus fehlenden Daten wird kein NOK abgeleitet.",
                    source_name,
                )

    downgrade_missing_source(
        ["IPC0007", "IPC0008", "IPC0009", "IPC0044", "IPC0045"],
        isinstance(language, dict),
        "Initial_Valid.LanguageAndRegion",
    )
    downgrade_missing_source(
        ["IPC0043"],
        isinstance(time_config, dict),
        "Initial_Valid.TimeConfiguration",
    )
    downgrade_missing_source(
        ["IPC0013", "IPC0036", "IPC0038", "IPC0191"],
        isinstance(local_users, list),
        "Initial_Valid.LocalUsers",
    )
    downgrade_missing_source(
        ["IPC0024", "IPC0049", "IPC0050", "IPC0051", "IPC0052", "IPC0053", "IPC0054", "IPC0055", "IPC0056", "IPC0079", "IPC0080", "IPC0188"],
        isinstance(network_adapters, list),
        "Initial_Valid.NetworkAdapters",
    )
    downgrade_missing_source(
        ["IPC0059", "IPC0060", "IPC0189"],
        isinstance(domain_info, dict),
        "Initial_Valid.DomainInformation",
    )
    downgrade_missing_source(
        ["IPC0081", "IPC0082"],
        isinstance(windows_components, dict),
        "Initial_Valid.WindowsComponents",
    )
    downgrade_missing_source(
        ["IPC0088", "IPC0150", "IPC0234"],
        isinstance(best_practice, dict),
        "Initial_Valid.InstallationBestPractice",
    )
    downgrade_missing_source(
        ["IPC0182"],
        isinstance(autoruns, dict),
        "Firewall_SMB_Patch_Valid.Autoruns",
    )
    downgrade_missing_source(
        ["IPC0247"],
        isinstance(defender, dict),
        "Initial_Valid.MicrosoftDefender",
    )
    downgrade_missing_source(
        ["IPC0091", "IPC0118"],
        isinstance(dotnet_prereq, dict),
        "Software_PCS7_Components_Valid.DotNetAndRuntimePrerequisites",
    )
    downgrade_missing_source(
        ["IPC0092", "IPC0093", "IPC0108"],
        isinstance(cert_prereq, dict),
        "Software_PCS7_Components_Valid.PCS7CertificatePrerequisites",
    )
    software_source_available = isinstance(installed_software, dict) and "AllProducts" in installed_software
    downgrade_missing_source(
        ["IPC0019", "IPC0026", "IPC0070", "IPC0078", "IPC0104", "IPC0112", "IPC0113", "IPC0114", "IPC0115", "IPC0117", "IPC0119", "IPC0120", "IPC0121", "IPC0122", "IPC0123", "IPC0124", "IPC0127", "IPC0128", "IPC0129", "IPC0130", "IPC0131", "IPC0132", "IPC0140", "IPC0180", "IPC0202", "IPC0203", "IPC0205", "IPC0228", "IPC0231", "IPC0252"],
        software_source_available,
        "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts",
    )
    downgrade_missing_source(
        ["IPC0142", "IPC0151", "IPC0190"],
        isinstance(services, dict),
        "Certificates_Services_Drivers_Valid.Services",
    )
    downgrade_missing_source(
        ["IPC0027", "IPC0166", "IPC0187", "IPC0245", "IPC0246"],
        isinstance(firewall, dict),
        "Firewall_SMB_Patch_Valid.Firewall",
    )
    downgrade_missing_source(
        ["IPC0154", "IPC0155", "IPC0168"],
        isinstance(smb, dict),
        "Firewall_SMB_Patch_Valid.SMB",
    )
    downgrade_missing_source(
        ["IPC0028", "IPC0094", "IPC0095"],
        explicit_policy is not None,
        "GPOs_Valid.ExplicitlyConfiguredPolicyRegistry",
    )
    downgrade_missing_source(
        ["IPC0153", "IPC0156", "IPC0159"],
        policy_areas is not None or effective_policy is not None,
        "GPOs_Valid.PolicyAreaSnapshots/InstallationRelevantEffectiveSettings",
    )
    downgrade_missing_source(
        ["IPC0224", "IPC0225", "IPC0226", "IPC0227", "IPC0232", "IPC0233"],
        isinstance(patch_status, dict) or software_source_available,
        "Firewall_SMB_Patch_Valid.PatchStatus + InstalledSoftware",
    )

    # Alle OS-Server-relevanten IDs bleiben sichtbar. Nicht belastbar ableitbare
    # Schritte werden explizit NICHT_PRUEFBAR statt still weggelassen oder als NOK erfunden.
    for task_id in TASK_IDS:
        if task_id not in checks and task_id not in info:
            checks[task_id] = make_not_testable(
                task_id,
                TASK_NAMES.get(task_id, task_id),
                "Der Installationsschritt ist fuer OS Server relevant, aber mit den vorhandenen 0120/0150-Snapshots bzw. den aktuell implementierten read-only Livequellen nicht eindeutig als Endzustand beweisbar.",
            )

    return (
        {key: checks[key] for key in TASK_IDS if key in checks},
        {key: info[key] for key in TASK_IDS if key in info and key not in checks},
    )

# Legacy constants and legacy CLI removed below; 0170 uses the same external
# build/merge pattern as 0160.

DIRECT_IDS = [
    "IPC0046", "IPC0047", "IPC0063", "IPC0070", "IPC0073", "IPC0076",
    "IPC0083", "IPC0089", "IPC0160", "IPC0161", "IPC0167", "IPC0200",
    "IPC0252", "IPC0263", "IPC0264", "IPC0265", "IPC0267", "IPC0268",
    "IPC0269", "IPC0270", "IPC0271",
]
DIRECT_INFORMATION_IDS = ["IPC0077"]


def write_json_atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(str(tmp), str(path))


def csv_information_value(item):
    item = as_dict(item)
    if item.get("status") != "INFORMATION":
        return item.get("status") or "NICHT_PRUEFBAR"
    value = item.get("ist")
    if value is None:
        return "NICHT_PRUEFBAR"
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def write_csv(output, csv_path):
    hosts = as_dict(output.get("hosts"))
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = csv_path.with_name(csv_path.name + ".tmp")
    with tmp.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle, delimiter=";", quoting=csv.QUOTE_MINIMAL)
        writer.writerow(["IP-Adresse", "Rechnername", "Computerart", "Ansible-Zugriff", *TASK_IDS])
        for ip in sorted(hosts, key=ip_sort_key):
            host = as_dict(hosts[ip])
            row = [ip, host.get("computer_name") or "", "OS Server", "JA" if host.get("ansible_access") else "NEIN"]
            checks = as_dict(host.get("pruefungen"))
            information = as_dict(host.get("informationen"))
            for task_id in TASK_IDS:
                if task_id in checks:
                    row.append(as_dict(checks[task_id]).get("status") or "NICHT_PRUEFBAR")
                elif task_id in information:
                    row.append(csv_information_value(information[task_id]))
                else:
                    row.append("NICHT_PRUEFBAR")
            writer.writerow(row)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(str(tmp), str(csv_path))


def summarize(output):
    ok = nok = nt = info = 0
    for host in as_dict(output.get("hosts")).values():
        for item in as_dict(as_dict(host).get("pruefungen")).values():
            status = as_dict(item).get("status")
            ok += status == "OK"
            nok += status == "NOK"
            nt += status == "NICHT_PRUEFBAR"
        for item in as_dict(as_dict(host).get("informationen")).values():
            if as_dict(item).get("status") == "INFORMATION":
                info += 1
            else:
                nt += 1
    return {
        "os_server_hosts_total": len(as_dict(output.get("hosts"))),
        "checks_ok_total": int(ok),
        "checks_nok_total": int(nok),
        "checks_not_testable_total": int(nt),
        "information_total": int(info),
    }


def run_build(args):
    library_path = Path(args.library)
    expected_path = Path(args.expected)
    output_path = Path(args.output)
    csv_path = Path(args.csv)

    with library_path.open("r", encoding="utf-8-sig") as handle:
        library = json.load(handle)
    with expected_path.open("r", encoding="utf-8-sig") as handle:
        expected = normalize_expected_config(json.load(handle))

    if not isinstance(library, dict) or library.get("library_type") != "IPC_Information_Library":
        raise RuntimeError("Die Eingabedatei ist keine gueltige IPC_Information_Library von 0150.")

    output_hosts = {}
    for ip in sorted(as_dict(library.get("hosts")), key=ip_sort_key):
        source_host = as_dict(as_dict(library.get("hosts"))[ip])
        if text(source_host.get("classification")) != "OS_Server":
            continue
        access = as_dict(source_host.get("zugriff"))
        if access and bool(access.get("ansible_access")) is False:
            checks = {
                task_id: make_not_testable(
                    task_id,
                    TASK_NAMES.get(task_id, task_id),
                    "Der OS Server war fuer die 0120-Snapshotaufnahme nicht per Ansible/WinRM erreichbar. Es wird kein Konfigurations-NOK aus fehlenden Daten abgeleitet.",
                    "0150.zugriff",
                )
                for task_id in TASK_IDS
            }
            information = {}
        else:
            checks, information = evaluate_os_server(source_host, expected)
        output_hosts[ip] = {
            "ip_address": ip,
            "computer_name": source_host.get("computer_name"),
            "classification": "OS_Server",
            "ansible_access": bool(access.get("ansible_access")),
            "data_quality": source_host.get("datenqualitaet"),
            "pruefungen": checks,
            "informationen": information,
        }

    output = {
        "schema_version": "2.0",
        "validation_type": "IPC_OS_Server_ID_Validation",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": {
            "included_classifications": ["OS_Server"],
            "ignored_classifications": ["ES", "OS_Client", "Kein_Zugriff"],
            "ids": TASK_IDS,
            "role_excluded_ids": ROLE_EXCLUDED_IDS,
            "live_validation_ids": DIRECT_IDS,
            "live_information_ids": DIRECT_INFORMATION_IDS,
        },
        "sources": {
            "information_library": str(library_path),
            "source_playbooks_unchanged": [
                "0000IPC_Discovery_Classification",
                "0120IPC_OS_Server_Initial_Installation",
                "0150IPC_Information_Library",
            ],
        },
        "hosts": output_hosts,
    }
    output["summary"] = summarize(output)
    write_json_atomic(output_path, output)
    write_csv(output, csv_path)
    print(json.dumps({"json": str(output_path), "csv": str(csv_path), "summary": output["summary"]}, ensure_ascii=False))


def missing_live_check(task_id):
    return make_not_testable(
        task_id,
        TASK_NAMES.get(task_id, task_id),
        "Direkte read-only Livepruefung konnte fuer diesen OS Server nicht ausgefuehrt oder nicht als gueltiges JSON eingelesen werden. Dies ist kein Konfigurations-NOK.",
        "0170 Live-WinRM",
    )


def run_merge(args):
    output_path = Path(args.output)
    csv_path = Path(args.csv)
    live_dir = Path(args.live_dir)
    with output_path.open("r", encoding="utf-8-sig") as handle:
        output = json.load(handle)
    hosts = as_dict(output.get("hosts"))

    for ip, host in hosts.items():
        checks = as_dict(host.get("pruefungen"))
        information = as_dict(host.get("informationen"))
        live_path = live_dir / f"{ip}.json"
        live = None
        if live_path.exists():
            try:
                live = json.loads(live_path.read_text(encoding="utf-8-sig"))
            except Exception:
                live = None
        live_checks = as_dict(as_dict(live).get("checks")) if isinstance(live, dict) else {}
        live_info = as_dict(as_dict(live).get("informationen")) if isinstance(live, dict) else {}

        for task_id in DIRECT_IDS:
            item = live_checks.get(task_id)
            if isinstance(item, dict):
                item = dict(item)
                item.setdefault("id", task_id)
                item.setdefault("pruefart", "SOLLWERT")
                checks[task_id] = item
            else:
                checks[task_id] = missing_live_check(task_id)
        for task_id in DIRECT_INFORMATION_IDS:
            item = live_info.get(task_id)
            if isinstance(item, dict):
                item = dict(item)
                item.setdefault("id", task_id)
                item.setdefault("pruefart", "INFORMATION")
                if "information" in item and "ist" not in item:
                    item["ist"] = item.pop("information")
                if item.get("status") == "KEINE_INFORMATION":
                    item["status"] = "NICHT_PRUEFBAR"
                information[task_id] = item
                checks.pop(task_id, None)
            elif task_id not in information:
                information[task_id] = make_information(task_id, TASK_NAMES.get(task_id, task_id), None, "0170 Live-WinRM", "Direkte Informationsausgabe war nicht verfuegbar.")

        host["pruefungen"] = {tid: checks[tid] for tid in TASK_IDS if tid in checks}
        host["informationen"] = {tid: information[tid] for tid in TASK_IDS if tid in information and tid not in checks}

    output["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    output.setdefault("scope", {})["live_validation_ids"] = DIRECT_IDS
    output.setdefault("scope", {})["live_information_ids"] = DIRECT_INFORMATION_IDS
    output["summary"] = summarize(output)
    write_json_atomic(output_path, output)
    write_csv(output, csv_path)
    print(json.dumps({"json": str(output_path), "csv": str(csv_path), "summary": output["summary"]}, ensure_ascii=False))


def parse_args():
    parser = argparse.ArgumentParser(description="0170 IPC OS Server ID Validation")
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", help="Bibliotheksbasierte 0170-Vorpruefung erzeugen")
    build.add_argument("--library", required=True)
    build.add_argument("--output", required=True)
    build.add_argument("--csv", required=True)
    build.add_argument("--expected", required=True)
    build.set_defaults(func=run_build)
    merge = sub.add_parser("merge", help="Direkte Read-only-Ergebnisse in 0170-Protokolle uebernehmen")
    merge.add_argument("--output", required=True)
    merge.add_argument("--csv", required=True)
    merge.add_argument("--live-dir", required=True)
    merge.set_defaults(func=run_merge)
    return parser.parse_args()


def main():
    args = parse_args()
    args.func(args)


if __name__ == "__main__":
    main()