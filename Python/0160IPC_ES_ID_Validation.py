#!/usr/bin/env python3

import argparse
import csv
import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path


def run_build(args):
    library_path = Path(args.library)
    output_path = Path(args.output)
    csv_path = Path(args.csv)
    expected_path = Path(args.expected)

    with expected_path.open("r", encoding="utf-8-sig") as handle:
        expected = json.load(handle)

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
        "IPC0084",
        "IPC0085",
        "IPC0087",
        "IPC0088",
        "IPC0089",
        "IPC0090",
        "IPC0091",
        "IPC0092",
        "IPC0093",
        "IPC0094",
        "IPC0095",
        "IPC0097",
        "IPC0103",
        "IPC0104",
        "IPC0105",
        "IPC0108",
        "IPC0109",
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
        "IPC0133",
        "IPC0134",
        "IPC0135",
        "IPC0137",
        "IPC0139",
        "IPC0140",
        "IPC0141",
        "IPC0142",
        "IPC0143",
        "IPC0144",
        "IPC0145",
        "IPC0146",
        "IPC0147",
        "IPC0148",
        "IPC0149",
        "IPC0150",
        "IPC0151",
        "IPC0152",
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
        "IPC0171",
        "IPC0177",
        "IPC0178",
        "IPC0179",
        "IPC0180",
        "IPC0182",
        "IPC0183",
        "IPC0184",
        "IPC0185",
        "IPC0186",
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
        "IPC0222",
        "IPC0223",
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
        "IPC0248",
        "IPC0249",
        "IPC0250",
        "IPC0251",
        "IPC0252",
        "IPC0254",
        "IPC0263",
        "IPC0264",
        "IPC0265",
        "IPC0267",
        "IPC0268",
        "IPC0269",
        "IPC0270",
        "IPC0271",
    ]

    def as_dict(value):
        return value if isinstance(value, dict) else {}

    def as_list(value):
        if value is None:
            return []
        return value if isinstance(value, list) else [value]

    def text(value):
        return "" if value is None else str(value)

    def ip_sort_key(value):
        try:
            return (0, int(ipaddress.ip_address(str(value))))
        except ValueError:
            return (1, str(value))

    def section(host, area, validation_type, section_name):
        return (
            as_dict(
                as_dict(
                    as_dict(host.get("bereiche")).get(area)
                ).get(validation_type)
            ).get(section_name)
        )

    def make_check(task_id, task_name, state, soll, ist, source, note=None):
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
        if note:
            result["hinweis"] = note
        return result

    def make_information(task_id, task_name, value, source, note=None):
        result = {
            "id": task_id,
            "aufgabe": task_name,
            "pruefart": "INFORMATION",
            "status": "INFORMATION" if value is not None else "NICHT_PRUEFBAR",
            "ist": value,
            "quelle": source,
        }
        if note:
            result["hinweis"] = note
        return result

    def make_ignored(task_id, task_name, reason, source=None):
        return {
            "id": task_id,
            "aufgabe": task_name,
            "pruefart": "IGNORIERT",
            "status": "IGNORIERT",
            "soll": None,
            "ist": None,
            "quelle": source or "0160-Prueflogik",
            "hinweis": reason,
        }

    def bool_value(value):
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        normalized = text(value).strip().lower()
        if normalized in {"true", "1", "yes", "enabled", "enable", "on"}:
            return True
        if normalized in {"false", "0", "no", "disabled", "disable", "off"}:
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

    def regex_match(pattern, value):
        try:
            return re.search(str(pattern), text(value), re.IGNORECASE) is not None
        except re.error:
            return False

    def locale_equal(actual, wanted):
        return text(actual).strip().lower() == text(wanted).strip().lower()

    def normalize_keyboard_layout(value):
        raw = text(value).strip().lower()
        if raw.startswith("0x"):
            raw = raw[2:]
        raw = raw.lstrip("0")
        return raw or "0"

    def software_products(installed_software):
        if not isinstance(installed_software, dict):
            return None
        raw_products = installed_software.get("AllProducts")
        if not isinstance(raw_products, list):
            return None
        return [
            item
            for item in raw_products
            if isinstance(item, dict)
        ]

    def normalize_install_date(value):
        raw = text(value).strip()
        if re.fullmatch(r"\\d{8}", raw):
            return f"{raw[0:4]}-{raw[4:6]}-{raw[6:8]}"
        return raw

    def software_inventory(installed_software, key):
        if not isinstance(installed_software, dict) or key not in installed_software:
            return None

        result = []
        seen = set()

        for product in as_list(installed_software.get(key)):
            if not isinstance(product, dict):
                continue

            name = text(product.get("DisplayName")).strip()
            if not name:
                continue

            item = {
                "name": name,
                "version": text(product.get("DisplayVersion")).strip(),
                "install_date": normalize_install_date(product.get("InstallDate")),
                "publisher": text(product.get("Publisher")).strip(),
            }

            dedupe_key = (
                item["name"].casefold(),
                item["version"].casefold(),
                item["install_date"].casefold(),
                item["publisher"].casefold(),
            )
            if dedupe_key in seen:
                continue

            seen.add(dedupe_key)
            result.append(item)

        result.sort(
            key=lambda item: (
                item["name"].casefold(),
                item["version"].casefold(),
                item["publisher"].casefold(),
                item["install_date"].casefold(),
            )
        )
        return result

    def software_inventory_csv_value(items):
        if items is None:
            return "NICHT_PRUEFBAR"
        if not items:
            return "KEINE_EINTRAEGE"

        return "\\n".join(
            "{name} | Version={version} | Installiert={install_date}".format(
                name=item.get("name") or "-",
                version=item.get("version") or "-",
                install_date=item.get("install_date") or "-",
            )
            for item in items
        )

    def find_products(products, name_regex, version_regex=None):
        matches = []
        for product in as_list(products):
            if not regex_match(name_regex, product.get("DisplayName")):
                continue
            if version_regex and not regex_match(version_regex, product.get("DisplayVersion")):
                continue
            matches.append({
                "DisplayName": product.get("DisplayName"),
                "DisplayVersion": product.get("DisplayVersion"),
                "Publisher": product.get("Publisher"),
                "Architecture": product.get("Architecture"),
                "RegistrySource": product.get("RegistrySource"),
            })
        return matches

    def catalog_component_records(component_detection):
        return [
            item
            for item in as_list(component_detection)
            if isinstance(item, dict)
        ]

    def component_by_id(component_detection, component_id):
        wanted = text(component_id).strip().lower()
        for item in catalog_component_records(component_detection):
            if text(item.get("ComponentId")).strip().lower() == wanted:
                return item
        return None

    def evaluate_component_requirement(component_detection, component_ids, expected_installed):
        ids = [text(value) for value in as_list(component_ids) if text(value)]
        if expected_installed is None or not ids:
            return None, []

        if component_detection is None:
            return None, [
                {
                    "ComponentId": component_id,
                    "Detected": None,
                    "Evidence": None,
                    "SourceAvailable": False,
                }
                for component_id in ids
            ]

        details = []
        states = []
        for component_id in ids:
            record = component_by_id(component_detection, component_id)
            detected = bool_value(as_dict(record).get("Detected")) if record else False
            details.append({
                "ComponentId": component_id,
                "Detected": detected is True,
                "Evidence": record,
            })
            states.append(detected is True)

        if expected_installed is True:
            return all(states), details
        return not any(states), details

    def evaluate_software_requirement(products, specification):
        spec = as_dict(specification)
        expected_installed = bool_value(spec.get("expected_installed"))
        name_regex = text(spec.get("name_regex"))
        version_regex = text(spec.get("version_regex"))

        if expected_installed is None or not name_regex:
            return None, {
                "ExpectedInstalled": expected_installed,
                "NameRegex": name_regex,
                "VersionRegex": version_regex,
                "SourceAvailable": products is not None,
                "MatchingProducts": [],
            }

        if products is None:
            return None, {
                "ExpectedInstalled": expected_installed,
                "NameRegex": name_regex,
                "VersionRegex": version_regex,
                "SourceAvailable": False,
                "MatchingProducts": [],
                "VersionCompliantProducts": [],
            }

        matching = []
        version_compliant = []
        for product in as_list(products):
            if not isinstance(product, dict):
                continue
            display_name = text(product.get("DisplayName"))
            display_version = text(product.get("DisplayVersion"))
            if not regex_match(name_regex, display_name):
                continue

            compact = {
                "DisplayName": product.get("DisplayName"),
                "DisplayVersion": product.get("DisplayVersion"),
                "Publisher": product.get("Publisher"),
                "Architecture": product.get("Architecture"),
                "RegistrySource": product.get("RegistrySource"),
            }
            matching.append(compact)

            if (
                not version_regex
                or regex_match(version_regex, display_version)
                or regex_match(version_regex, display_name + " " + display_version)
            ):
                version_compliant.append(compact)

        if expected_installed is True:
            state = bool(version_compliant if version_regex else matching)
        else:
            state = not bool(matching)

        return state, {
            "ExpectedInstalled": expected_installed,
            "NameRegex": name_regex,
            "VersionRegex": version_regex,
            "SourceAvailable": True,
            "MatchingProducts": matching,
            "VersionCompliantProducts": version_compliant,
        }

    def product_regex_matches(products, pattern):
        if not text(pattern):
            return []
        matches = []
        for product in as_list(products):
            if not isinstance(product, dict):
                continue
            searchable = " ".join([
                text(product.get("DisplayName")),
                text(product.get("DisplayVersion")),
                text(product.get("Publisher")),
            ])
            if regex_match(pattern, searchable):
                matches.append({
                    "DisplayName": product.get("DisplayName"),
                    "DisplayVersion": product.get("DisplayVersion"),
                    "Publisher": product.get("Publisher"),
                    "Architecture": product.get("Architecture"),
                    "RegistrySource": product.get("RegistrySource"),
                })
        return matches

    def evaluate_package_spec(component_detection, products, specification):
        spec = as_dict(specification)
        expected_installed = bool_value(spec.get("expected_installed"))
        if expected_installed is None:
            return None, {"ExpectedInstalled": None}

        evidence = {
            "ExpectedInstalled": expected_installed,
            "ComponentId": spec.get("component_id"),
            "NameRegex": spec.get("name_regex"),
            "VersionRegex": spec.get("version_regex"),
            "RequiredNameRegexes": as_list(spec.get("required_name_regexes")),
            "ForbiddenNameRegexes": as_list(spec.get("forbidden_name_regexes")),
            "ComponentSourceAvailable": component_detection is not None,
            "SoftwareSourceAvailable": products is not None,
        }

        component_id = text(spec.get("component_id")).strip()
        required_patterns = [
            text(x) for x in as_list(spec.get("required_name_regexes")) if text(x)
        ]

        if component_id:
            state, component_evidence = evaluate_component_requirement(
                component_detection,
                [component_id],
                expected_installed,
            )
            evidence["ComponentEvidence"] = component_evidence
        elif required_patterns:
            required_results = []
            if products is None:
                for pattern in required_patterns:
                    required_results.append({
                        "Regex": pattern,
                        "MatchingProducts": [],
                        "Found": None,
                    })
                state = None
            else:
                for pattern in required_patterns:
                    found = product_regex_matches(products, pattern)
                    required_results.append({
                        "Regex": pattern,
                        "MatchingProducts": found,
                        "Found": bool(found),
                    })
                if expected_installed is True:
                    state = all(item["Found"] for item in required_results)
                else:
                    state = not any(item["Found"] for item in required_results)
            evidence["RequiredEvidence"] = required_results
        else:
            state, simple_evidence = evaluate_software_requirement(products, spec)
            evidence["SoftwareEvidence"] = simple_evidence

        forbidden_results = []
        for pattern in [
            text(x) for x in as_list(spec.get("forbidden_name_regexes")) if text(x)
        ]:
            if products is None:
                forbidden_results.append({
                    "Regex": pattern,
                    "MatchingProducts": [],
                    "Found": None,
                })
            else:
                found = product_regex_matches(products, pattern)
                forbidden_results.append({
                    "Regex": pattern,
                    "MatchingProducts": found,
                    "Found": bool(found),
                })
        evidence["ForbiddenEvidence"] = forbidden_results

        if expected_installed is True:
            if any(item["Found"] is True for item in forbidden_results):
                state = False
            elif forbidden_results and products is None and state is True:
                # Positiver Nachweis aus dem Komponentenkatalog reicht nicht aus,
                # um zusätzlich geforderte "alte Version darf nicht vorhanden sein"-
                # Bedingungen ohne Softwareinventar sicher zu bestätigen.
                state = None

        return state, evidence

    def service_records(service_snapshot):
        if not isinstance(service_snapshot, dict):
            return []
        return [
            item
            for item in as_list(service_snapshot.get("Services"))
            if isinstance(item, dict)
        ]

    def find_services(services, pattern):
        matches = []
        for service in services:
            searchable = " ".join([
                text(service.get("Name")),
                text(service.get("DisplayName")),
                text(service.get("PathName")),
            ])
            if not regex_match(pattern, searchable):
                continue
            binary = as_dict(service.get("Binary"))
            matches.append({
                "Name": service.get("Name"),
                "DisplayName": service.get("DisplayName"),
                "State": service.get("State"),
                "StartMode": service.get("StartMode"),
                "PathName": service.get("PathName"),
                "BinaryFileVersion": binary.get("FileVersion"),
                "BinaryProductVersion": binary.get("ProductVersion"),
            })
        return matches

    def profile_is_all(value):
        normalized = text(value).strip().lower()
        if normalized in {"any", "all", "alle", "all profiles", "alle profile"}:
            return True

        tokens = {
            token.strip()
            for token in re.split(r"[,;|+]", normalized)
            if token.strip()
        }
        return {"domain", "private", "public"}.issubset(tokens)

    def firewall_rule_has_port(rule, expected_port):
        expected_port = text(expected_port).strip()
        if not expected_port:
            return True

        for port_filter in as_list(rule.get("PortFilters")):
            if not isinstance(port_filter, dict):
                continue
            for local_port in as_list(port_filter.get("LocalPort")):
                if text(local_port).strip() == expected_port:
                    return True
        return False

    def registry_values(registry_snapshot):
        if isinstance(registry_snapshot, dict):
            return [
                row
                for row in as_list(registry_snapshot.get("Values"))
                if isinstance(row, dict)
            ]
        return [
            row
            for row in as_list(registry_snapshot)
            if isinstance(row, dict)
        ]

    def registry_record_matches(record, name=None, path_regex=None):
        if not isinstance(record, dict):
            return False
        if name is not None and text(record.get("Name")).lower() != text(name).lower():
            return False
        if path_regex and not regex_match(path_regex, record.get("Path")):
            return False
        return True

    def first_registry_record(records, name=None, path_regex=None):
        for record in as_list(records):
            if registry_record_matches(record, name=name, path_regex=path_regex):
                return record
        return None

    def first_registry_value(records, name=None, path_regex=None):
        record = first_registry_record(records, name=name, path_regex=path_regex)
        if record is None:
            return None, None
        return record.get("Value"), record

    def windows_feature_rows(windows_components):
        rows = []
        components = as_dict(windows_components)

        for item in as_list(components.get("OptionalFeatures")):
            if not isinstance(item, dict):
                continue
            rows.append({
                "Source": "OptionalFeature",
                "Name": item.get("FeatureName"),
                "DisplayName": item.get("FeatureName"),
                "Enabled": text(item.get("State")).lower().startswith("enabled"),
                "State": item.get("State"),
                "Raw": item,
            })

        server_roles = as_dict(components.get("ServerRolesAndFeatures"))
        for item in as_list(server_roles.get("Features")):
            if not isinstance(item, dict):
                continue
            installed = bool_value(item.get("Installed"))
            rows.append({
                "Source": "ServerRoleOrFeature",
                "Name": item.get("Name"),
                "DisplayName": item.get("DisplayName"),
                "Enabled": installed is True,
                "State": item.get("InstallState"),
                "Raw": item,
            })

        return rows

    def smb_configuration_value(configuration, registry_snapshot, name):
        config = as_dict(configuration)
        if name in config:
            return config.get(name)

        registry = as_dict(registry_snapshot)
        values = as_dict(registry.get("Values"))
        if name in values:
            return values.get(name)
        return None

    def evaluate_boolean_requirements(requirements):
        known = [value for value in requirements if value is not None]
        if any(value is False for value in known):
            return False
        if len(known) != len(requirements):
            return None
        return all(known)

    def normalize_drive_letter(value):
        raw = text(value).strip().upper()
        if raw and not raw.endswith(":"):
            raw += ":"
        return raw

    def is_windows_10(system_info):
        caption = text(as_dict(as_dict(system_info).get("OperatingSystem")).get("Caption"))
        return bool(re.search(r"\bWindows\s+10\b", caption, re.IGNORECASE))

    def check_schannel_protocols(records, protocol_expectations):
        rows = as_list(records)
        details = []
        states = []

        for protocol_name, requirement in as_dict(protocol_expectations).items():
            req = as_dict(requirement)
            expected_enabled = bool_value(req.get("enabled"))
            expected_disabled_by_default = bool_value(req.get("disabled_by_default"))

            for side in ("Client", "Server"):
                escaped_protocol = re.escape(text(protocol_name))
                escaped_side = re.escape(side)
                suffix_regex = (
                    r"(?i)\\SCHANNEL\\Protocols\\"
                    + escaped_protocol
                    + r"\\"
                    + escaped_side
                    + r"$"
                )
                enabled_value, enabled_row = first_registry_value(
                    rows,
                    name="Enabled",
                    path_regex=suffix_regex,
                )
                disabled_default_value, disabled_default_row = first_registry_value(
                    rows,
                    name="DisabledByDefault",
                    path_regex=suffix_regex,
                )

                actual_enabled = bool_value(enabled_value)
                actual_disabled_by_default = bool_value(disabled_default_value)

                enabled_ok = (
                    actual_enabled == expected_enabled
                    if expected_enabled is not None and actual_enabled is not None
                    else None
                )
                disabled_default_ok = (
                    actual_disabled_by_default == expected_disabled_by_default
                    if expected_disabled_by_default is not None and actual_disabled_by_default is not None
                    else None
                )

                side_state = evaluate_boolean_requirements(
                    [enabled_ok, disabled_default_ok]
                )
                states.append(side_state)
                details.append({
                    "Protocol": protocol_name,
                    "Side": side,
                    "ExpectedEnabled": expected_enabled,
                    "ActualEnabled": actual_enabled,
                    "ExpectedDisabledByDefault": expected_disabled_by_default,
                    "ActualDisabledByDefault": actual_disabled_by_default,
                    "EnabledEvidence": enabled_row,
                    "DisabledByDefaultEvidence": disabled_default_row,
                    "Compliant": side_state,
                })

        return evaluate_boolean_requirements(states), details

    def normalize_windows_path(value):
        return text(value).strip().replace("/", "\\").rstrip("\\").lower()

    def identity_matches(pattern, identity):
        return regex_match(pattern, text(identity))

    def rights_contain(actual_rights, required_right):
        normalized_actual = re.sub(r"[\s_]", "", text(actual_rights)).lower()
        normalized_required = re.sub(r"[\s_]", "", text(required_right)).lower()
        if normalized_required in normalized_actual:
            return True
        # "Modify" umfasst unter Windows die typischen Lesen/Schreiben/
        # Löschen-Rechte und kann als "Modify, Synchronize" erscheinen.
        return False

    def project_share_evaluation(smb_snapshot, specification):
        spec = as_dict(specification)
        if not isinstance(smb_snapshot, dict):
            return None, None

        wanted_path = normalize_windows_path(spec.get("path"))
        wanted_name = text(spec.get("share_name")).strip().lower()
        shares = [
            row for row in as_list(smb_snapshot.get("Shares"))
            if isinstance(row, dict)
            and (
                normalize_windows_path(row.get("Path")) == wanted_path
                or text(row.get("Name")).strip().lower() == wanted_name
            )
        ]
        if not shares:
            return False, {"MatchingShares": []}

        share = shares[0]
        share_results = []
        for requirement in as_list(spec.get("share_permissions")):
            req = as_dict(requirement)
            matches = [
                ace for ace in as_list(share.get("SharePermissions"))
                if isinstance(ace, dict)
                and text(ace.get("AccessControlType")).lower() != "deny"
                and identity_matches(req.get("identity_regex"), ace.get("AccountName"))
                and text(ace.get("AccessRight")).lower() == text(req.get("access_right")).lower()
            ]
            share_results.append({
                "Requirement": req,
                "Matches": matches,
                "Compliant": bool(matches),
            })

        ntfs_acl = as_dict(share.get("NtfsRootAcl"))
        ntfs_results = []
        for requirement in as_list(spec.get("ntfs_permissions")):
            req = as_dict(requirement)
            matches = [
                ace for ace in as_list(ntfs_acl.get("Access"))
                if isinstance(ace, dict)
                and text(ace.get("AccessControlType")).lower() == "allow"
                and identity_matches(req.get("identity_regex"), ace.get("IdentityReference"))
            ]
            compliant = bool(matches) and any(
                all(
                    rights_contain(ace.get("FileSystemRights"), required)
                    for required in as_list(req.get("required_rights"))
                )
                for ace in matches
            )
            ntfs_results.append({
                "Requirement": req,
                "Matches": matches,
                "Compliant": compliant,
            })

        state = (
            normalize_windows_path(share.get("Path")) == wanted_path
            and text(share.get("Name")).strip().lower() == wanted_name
            and all(row["Compliant"] for row in share_results)
            and all(row["Compliant"] for row in ntfs_results)
        )
        return state, {
            "Share": share,
            "SharePermissionEvaluation": share_results,
            "NtfsPermissionEvaluation": ntfs_results,
        }

    def autorun_matches(autorun_snapshot, pattern):
        if not isinstance(autorun_snapshot, dict):
            return []
        matches = []

        for item in as_list(autorun_snapshot.get("RegistryEntries")):
            if not isinstance(item, dict):
                continue
            searchable = " ".join([
                text(item.get("Name")),
                text(item.get("Command")),
                text(item.get("Path")),
            ])
            if regex_match(pattern, searchable):
                matches.append({"Source": "RegistryEntry", **item})

        for folder in as_list(autorun_snapshot.get("StartupFolders")):
            if not isinstance(folder, dict):
                continue
            for item in as_list(folder.get("Items")):
                if not isinstance(item, dict):
                    continue
                shortcut = as_dict(item.get("Shortcut"))
                searchable = " ".join([
                    text(item.get("Name")),
                    text(item.get("FullName")),
                    text(shortcut.get("TargetPath")),
                    text(shortcut.get("Arguments")),
                ])
                if regex_match(pattern, searchable):
                    matches.append({
                        "Source": "StartupFolder",
                        "Scope": folder.get("Scope"),
                        **item,
                    })
        return matches

    def current_kb_evidence(patch_snapshot, installed_software_snapshot, kb):
        wanted = text(kb).upper()
        evidence = {
            "HotFixes": [],
            "InstalledWindowsPackages": [],
            "InstalledSoftware": [],
        }
        if isinstance(patch_snapshot, dict):
            evidence["HotFixes"] = [
                row for row in as_list(patch_snapshot.get("HotFixes"))
                if isinstance(row, dict)
                and text(row.get("HotFixID")).upper() == wanted
            ]
            evidence["InstalledWindowsPackages"] = [
                row for row in as_list(patch_snapshot.get("WindowsPackages"))
                if isinstance(row, dict)
                and text(row.get("PackageState")).lower() == "installed"
                and (
                    wanted in [text(x).upper() for x in as_list(row.get("KBs"))]
                    or wanted in text(row.get("PackageName")).upper()
                    or wanted in text(row.get("Description")).upper()
                )
            ]

        products_for_kb = software_products(installed_software_snapshot)
        evidence["InstalledSoftware"] = [
            product for product in as_list(products_for_kb)
            if wanted in (
                text(product.get("DisplayName")) + " "
                + text(product.get("DisplayVersion"))
            ).upper()
        ]
        present = any(bool(value) for value in evidence.values())
        return present, evidence

    def check_status_to_state(check):
        item = as_dict(check)
        status = text(item.get("status")).upper()
        if status == "OK":
            return True
        if status == "NOK":
            return False
        return None

    def referenced_check(task_id, task_name, source_id, source_check, note=None):
        source = as_dict(source_check)
        return make_check(
            task_id,
            task_name,
            check_status_to_state(source),
            {
                "ReferenzId": source_id,
                "ReferencedSoll": source.get("soll"),
            },
            {
                "ReferenzId": source_id,
                "ReferencedStatus": source.get("status"),
                "ReferencedIst": source.get("ist"),
            },
            f"Referenz auf {source_id}",
            note,
        )

    def recursive_scalar_text(value):
        parts = []
        if isinstance(value, dict):
            for key, item in value.items():
                parts.append(text(key))
                parts.extend(recursive_scalar_text(item))
        elif isinstance(value, list):
            for item in value:
                parts.extend(recursive_scalar_text(item))
        elif value is not None:
            parts.append(text(value))
        return parts

    def compact_users(users):
        parts = []
        for user in as_list(users):
            if not isinstance(user, dict):
                continue
            groups = ",".join(text(x) for x in as_list(user.get("LocalGroups")) if text(x))
            parts.append(
                "{name} [Enabled={enabled}; PasswordExpires={expires}; Groups={groups}]".format(
                    name=text(user.get("Name")) or "?",
                    enabled=text(user.get("Enabled")) or "?",
                    expires=text(user.get("PasswordExpires")) or "?",
                    groups=groups or "-",
                )
            )
        return " | ".join(parts)

    def compact_network(adapters):
        parts = []
        for adapter in as_list(adapters):
            if not isinstance(adapter, dict):
                continue

            ipv4 = []
            for address in as_list(adapter.get("IPAddresses")):
                if not isinstance(address, dict):
                    continue
                if text(address.get("AddressFamily")).lower() not in {"ipv4", "2"}:
                    continue
                ip = text(address.get("IPAddress"))
                prefix = text(address.get("PrefixLength"))
                if ip:
                    ipv4.append(ip + ("/" + prefix if prefix else ""))

            dns = []
            for dns_record in as_list(adapter.get("DnsServers")):
                if not isinstance(dns_record, dict):
                    continue
                if text(dns_record.get("AddressFamily")).lower() not in {"ipv4", "2"}:
                    continue
                dns.extend(text(x) for x in as_list(dns_record.get("ServerAddresses")) if text(x))

            gateways = [text(x) for x in as_list(adapter.get("Gateway")) if text(x)]
            parts.append(
                "{name} [Status={status}; IPv4={ipv4}; Gateway={gateway}; DNS={dns}; MAC={mac}]".format(
                    name=text(adapter.get("Name")) or "?",
                    status=text(adapter.get("Status")) or "?",
                    ipv4=",".join(ipv4) or "-",
                    gateway=",".join(gateways) or "-",
                    dns=",".join(dns) or "-",
                    mac=text(adapter.get("MacAddress")) or "-",
                )
            )
        return " | ".join(parts)

    def physical_network_adapters(adapters):
        selected = []
        for adapter in as_list(adapters):
            if not isinstance(adapter, dict):
                continue
            if bool_value(adapter.get("Virtual")) is True:
                continue
            if adapter.get("HardwareInterface") is not None and bool_value(adapter.get("HardwareInterface")) is False:
                continue
            selected.append(adapter)
        return selected

    def adapter_is_enabled(adapter):
        status = text(as_dict(adapter).get("Status")).strip().lower()
        if not status:
            return None
        return status not in {"disabled", "deaktiviert", "not present", "nicht vorhanden"}

    def find_adapters_by_name_regex(adapters, pattern):
        return [
            adapter
            for adapter in as_list(adapters)
            if isinstance(adapter, dict) and regex_match(pattern, adapter.get("Name"))
        ]

    def binding_matches(adapter, component_id=None, display_regex=None):
        matches = []
        for binding in as_list(as_dict(adapter).get("Bindings")):
            if not isinstance(binding, dict):
                continue
            if component_id is not None and text(binding.get("ComponentID")).strip().lower() != text(component_id).strip().lower():
                continue
            if display_regex is not None and not regex_match(display_regex, binding.get("DisplayName")):
                continue
            matches.append(binding)
        return matches

    def ordered_string_list(values):
        return [text(value).strip() for value in as_list(values) if text(value).strip()]

    def normalize_domain(value):
        return text(value).strip().rstrip(".").lower()

    def bytes_to_gb(value):
        try:
            return float(value) / (1024.0 ** 3)
        except (TypeError, ValueError):
            return None

    def component_enabled(item):
        item = as_dict(item)
        if "Installed" in item:
            value = bool_value(item.get("Installed"))
            if value is not None:
                return value
        state = text(item.get("State") or item.get("InstallState")).strip().lower()
        if state in {"enabled", "enabled pending", "installed", "install pending"}:
            return True
        if state in {"disabled", "disabled with payload removed", "available", "removed"}:
            return False
        return None

    def component_records(windows_components):
        components = as_dict(windows_components)
        rows = []
        for item in as_list(components.get("OptionalFeatures")):
            if isinstance(item, dict):
                row = dict(item)
                row["Source"] = "OptionalFeatures"
                rows.append(row)
        server = as_dict(components.get("ServerRolesAndFeatures"))
        for item in as_list(server.get("Features")):
            if isinstance(item, dict):
                row = dict(item)
                row["Source"] = "ServerRolesAndFeatures"
                rows.append(row)
        return rows

    def component_matches(records, pattern):
        return [
            row for row in as_list(records)
            if isinstance(row, dict) and regex_match(
                pattern,
                "{0} {1}".format(text(row.get("Name") or row.get("FeatureName")), text(row.get("DisplayName")))
            )
        ]

    def compact_info(task_id, value):
        if value is None:
            return "NICHT_PRUEFBAR"

        if task_id == "IPC0013":
            return compact_users(value)

        if task_id == "IPC0015":
            identity = as_dict(value)
            return text(identity.get("ComputerName") or identity.get("DNSHostName") or identity.get("FQDN"))

        if task_id == "IPC0019":
            data = as_dict(value)
            installed = "JA" if data.get("Installed") else "NEIN"
            versions = [
                text(item.get("DisplayVersion"))
                for item in as_list(data.get("Products"))
                if isinstance(item, dict) and text(item.get("DisplayVersion"))
            ]
            return "Installiert: {0}; Version: {1}".format(
                installed,
                ",".join(sorted(set(versions))) if versions else "-"
            )

        if task_id == "IPC0024":
            return compact_network(value)

        if task_id in {"IPC0050", "IPC0053"}:
            return compact_network(value)

        if task_id == "IPC0060":
            data = as_dict(value)
            if not data:
                return "NICHT_PRUEFBAR"
            return "Domain={domain}; OU={ou}; DN={dn}".format(
                domain=text(data.get("Domain")) or "-",
                ou=text(data.get("ComputerAccountOU") or data.get("ComputerAccountParentDN")) or "-",
                dn=text(data.get("ComputerAccountDN")) or "-",
            )

        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    def evaluate_es(host):
        checks = {}
        information = {}

        identity = section(host, "system_und_hardware", "Initial_Valid", "Identity")
        language = section(host, "sprache_und_region", "Initial_Valid", "LanguageAndRegion")
        time_config = section(host, "zeitkonfiguration", "Initial_Valid", "TimeConfiguration")
        system_info = section(host, "system_und_hardware", "Initial_Valid", "SystemInformation")
        bios = section(host, "system_und_hardware", "Initial_Valid", "BIOS")
        local_users = section(host, "benutzer_und_gruppen", "Initial_Valid", "LocalUsers")
        network_adapters = section(host, "netzwerk_und_domaene", "Initial_Valid", "NetworkAdapters")
        domain_info = section(host, "netzwerk_und_domaene", "Initial_Valid", "DomainInformation")
        storage = section(host, "system_und_hardware", "Initial_Valid", "Storage")
        windows_components = section(host, "windows_software_und_features", "Initial_Valid", "WindowsComponents")
        initial_best_practice = section(host, "hinweise_und_beobachtungen", "Initial_Valid", "InstallationBestPractice")
        installed_software = section(host, "software_und_pcs7", "Software_PCS7_Components_Valid", "InstalledSoftware")
        component_detection = section(host, "software_und_pcs7", "Software_PCS7_Components_Valid", "PCS7ComponentCatalogDetection")
        setup_log_evidence = section(host, "software_und_pcs7", "Software_PCS7_Components_Valid", "PCS7SetupLogEvidence")
        dotnet_prereq = section(host, "software_und_pcs7", "Software_PCS7_Components_Valid", "DotNetAndRuntimePrerequisites")
        cert_prereq = section(host, "software_und_pcs7", "Software_PCS7_Components_Valid", "PCS7CertificatePrerequisites")
        services_snapshot = section(host, "dienste_treiber_und_geraete", "Certificates_Services_Drivers_Valid", "Services")
        firewall = section(host, "firewall_smb_und_endpunkte", "Firewall_SMB_Patch_Valid", "Firewall")
        smb = section(host, "firewall_smb_und_endpunkte", "Firewall_SMB_Patch_Valid", "SMB")
        explicit_policy = section(host, "gruppenrichtlinien", "GPOs_Valid", "ExplicitlyConfiguredPolicyRegistry")
        policy_areas = section(host, "gruppenrichtlinien", "GPOs_Valid", "PolicyAreaSnapshots")
        effective_policy = section(host, "gruppenrichtlinien", "GPOs_Valid", "InstallationRelevantEffectiveSettings")
        siemens_registry_evidence = section(host, "software_und_pcs7", "Software_PCS7_Components_Valid", "SiemensRegistryEvidence")
        simatic_shell_evidence = section(host, "software_und_pcs7", "Software_PCS7_Components_Valid", "SimaticShellEvidence")
        patch_status = section(host, "patchstand", "Firewall_SMB_Patch_Valid", "PatchStatus")

        # --------------------------------------------------------------
        # IPC0007 - Sprache Deutsch
        # --------------------------------------------------------------
        wanted_language = text(as_dict(expected.get("language")).get("tag"))
        if isinstance(language, dict):
            language_ist = {
                "WindowsSystemLocale": as_dict(language.get("WindowsSystemLocale")).get("Name"),
                "CurrentCulture": as_dict(language.get("CurrentCulture")).get("Name"),
                "CurrentUICulture": as_dict(language.get("CurrentUICulture")).get("Name"),
                "CurrentUserLanguageList": language.get("CurrentUserLanguageList"),
            }
            required_values = [
                language_ist["WindowsSystemLocale"],
                language_ist["CurrentCulture"],
                language_ist["CurrentUICulture"],
            ]
            state = all(locale_equal(value, wanted_language) for value in required_values)
        else:
            language_ist = None
            state = None

        checks["IPC0007"] = make_check(
            "IPC0007",
            "Sprache auswählen (Deutsch)",
            state,
            wanted_language,
            language_ist,
            "Initial_Valid.LanguageAndRegion",
        )

        # --------------------------------------------------------------
        # IPC0008 - Region Deutschland
        # --------------------------------------------------------------
        wanted_region = text(as_dict(expected.get("region")).get("iso")).upper()
        if isinstance(language, dict):
            region = as_dict(language.get("Region"))
            actual_region = text(region.get("TwoLetterISORegionName")).upper()
            region_ist = {
                "Name": region.get("Name"),
                "EnglishName": region.get("EnglishName"),
                "TwoLetterISORegionName": region.get("TwoLetterISORegionName"),
                "GeoId": region.get("GeoId"),
            }
            state = actual_region == wanted_region
        else:
            region_ist = None
            state = None

        checks["IPC0008"] = make_check(
            "IPC0008",
            "Region auswählen (Deutschland)",
            state,
            {"TwoLetterISORegionName": wanted_region},
            region_ist,
            "Initial_Valid.LanguageAndRegion.Region",
        )

        # --------------------------------------------------------------
        # IPC0009 - genau eine deutsche Tastatur
        # --------------------------------------------------------------
        keyboard_expected = as_dict(expected.get("keyboard"))
        allowed_layouts = {
            normalize_keyboard_layout(value)
            for value in as_list(keyboard_expected.get("allowed_layout_ids"))
        }
        exact_layout_count = int_value(keyboard_expected.get("exact_layout_count"))

        keyboard_ist = None
        keyboard_state = None
        if isinstance(language, dict):
            current_user = as_dict(language.get("CurrentUser"))
            preload = as_dict(current_user.get("KeyboardPreload"))
            values = as_dict(preload.get("Values"))
            if preload.get("Exists") is True and isinstance(values, dict):
                layouts = [text(value) for _, value in sorted(values.items())]
                normalized = [normalize_keyboard_layout(value) for value in layouts]
                keyboard_ist = {
                    "RegistryPath": preload.get("Path"),
                    "Layouts": layouts,
                    "NormalizedLayouts": normalized,
                    "Count": len(layouts),
                }
                keyboard_state = (
                    exact_layout_count is not None
                    and len(layouts) == exact_layout_count
                    and all(value in allowed_layouts for value in normalized)
                )

        checks["IPC0009"] = make_check(
            "IPC0009",
            "Tastatur (Deutsch), keine zweite",
            keyboard_state,
            {
                "AllowedLayoutIds": as_list(keyboard_expected.get("allowed_layout_ids")),
                "ExactLayoutCount": exact_layout_count,
            },
            keyboard_ist,
            "Initial_Valid.LanguageAndRegion.CurrentUser.KeyboardPreload",
        )

        # --------------------------------------------------------------
        # IPC0013 - alle lokalen Benutzer ausgeben
        # --------------------------------------------------------------
        information["IPC0013"] = make_information(
            "IPC0013",
            "User Name / Password / Password Hint",
            local_users if isinstance(local_users, list) else None,
            "Initial_Valid.LocalUsers",
            (
                "Windows stellt bestehende Kennwoerter nicht im Klartext bereit. "
                "Daher werden Benutzer, Status, Gruppen und vorhandene "
                "Kennwort-Metadaten ausgegeben; das geforderte Passwort selbst "
                "wird nicht ausgelesen."
            ),
        )

        # --------------------------------------------------------------
        # IPC0015 - Rechnername ausgeben
        # --------------------------------------------------------------
        identity_info = None
        if isinstance(identity, dict):
            identity_info = {
                "ComputerName": identity.get("ComputerName"),
                "DNSHostName": identity.get("DNSHostName"),
                "FQDN": identity.get("FQDN"),
            }

        information["IPC0015"] = make_information(
            "IPC0015",
            "Rechnernamen anpassen",
            identity_info,
            "Initial_Valid.Identity",
        )

        # --------------------------------------------------------------
        # IPC0019 - SIMATIC Management Agent inkl. Version ausgeben
        # --------------------------------------------------------------
        products = software_products(installed_software)
        services = service_records(services_snapshot)
        sma_products = find_products(
            products,
            r"SIMATIC.*Management.*Agent|Management.*Agent",
        )
        sma_services = find_services(
            services,
            r"SIMATIC.*Management.*Agent|Management.*Agent",
        )

        if isinstance(installed_software, dict) or isinstance(services_snapshot, dict):
            sma_info = {
                "Installed": bool(sma_products or sma_services),
                "Products": sma_products,
                "Services": sma_services,
            }
        else:
            sma_info = None

        information["IPC0019"] = make_information(
            "IPC0019",
            "SIMATIC Management Agent",
            sma_info,
            (
                "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts + "
                "Certificates_Services_Drivers_Valid.Services"
            ),
        )

        # --------------------------------------------------------------
        # IPC0024 - alle Netzwerkadapter inkl. IP/Subnetz/DNS usw.
        # --------------------------------------------------------------
        information["IPC0024"] = make_information(
            "IPC0024",
            "IP-Adresseinstellungen",
            network_adapters if isinstance(network_adapters, list) else None,
            "Initial_Valid.NetworkAdapters",
        )

        # --------------------------------------------------------------
        # IPC0025 - Chipset-/Firmware-Sollwert pruefen
        # --------------------------------------------------------------
        chipset_regex = text(as_dict(expected.get("chipset")).get("regex"))
        chipset_evidence = None
        chipset_state = None

        if isinstance(bios, dict) or isinstance(system_info, dict):
            mainboards = as_list(as_dict(system_info).get("Mainboard"))
            chipset_evidence = {
                "BIOS": {
                    "Manufacturer": as_dict(bios).get("Manufacturer"),
                    "Name": as_dict(bios).get("Name"),
                    "Version": as_dict(bios).get("Version"),
                    "SMBIOSBIOSVersion": as_dict(bios).get("SMBIOSBIOSVersion"),
                    "ReleaseDate": as_dict(bios).get("ReleaseDate"),
                },
                "Mainboard": mainboards,
            }
            searchable = json.dumps(chipset_evidence, ensure_ascii=False)
            try:
                chipset_state = re.search(chipset_regex, searchable, re.IGNORECASE) is not None
            except re.error:
                chipset_state = None

        checks["IPC0025"] = make_check(
            "IPC0025",
            "Bios Versionsprüfung / Chipset",
            chipset_state,
            {"ChipsetRegex": chipset_regex},
            chipset_evidence,
            "Initial_Valid.BIOS + Initial_Valid.SystemInformation.Mainboard",
            (
                "Der Sollwert wird gegen die ausgelesenen BIOS- und "
                "Mainboard-Felder geprüft. Dadurch ist die Prüfung robust "
                "gegen unterschiedliche Feldbezeichnungen des Herstellers."
            ),
        )

        # --------------------------------------------------------------
        # IPC0026 - UltraVNC installiert / Version
        # --------------------------------------------------------------
        software_expected = as_dict(expected.get("software"))
        ultravnc_expected = as_dict(software_expected.get("ultravnc_server"))
        ultravnc_required = bool_value(ultravnc_expected.get("expected_installed"))
        ultravnc_matches = None
        ultravnc_state = None

        if isinstance(installed_software, dict):
            name_matches = find_products(
                products,
                ultravnc_expected.get("name_regex"),
            )
            version_matches = find_products(
                products,
                ultravnc_expected.get("name_regex"),
                ultravnc_expected.get("version_regex"),
            )
            ultravnc_matches = {
                "Installed": bool(name_matches),
                "Products": name_matches,
                "VersionCompliantProducts": version_matches,
            }

            if ultravnc_required is True:
                ultravnc_state = bool(version_matches)
            elif ultravnc_required is False:
                ultravnc_state = not bool(name_matches)

        checks["IPC0026"] = make_check(
            "IPC0026",
            "UltraVNC installieren",
            ultravnc_state,
            {
                "ExpectedInstalled": ultravnc_required,
                "NameRegex": ultravnc_expected.get("name_regex"),
                "VersionRegex": ultravnc_expected.get("version_regex"),
            },
            ultravnc_matches,
            "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts",
        )

        # --------------------------------------------------------------
        # IPC0027 - VNC5800 / VNC5900: aktiviert, Inbound, Allow, alle Profile
        # --------------------------------------------------------------
        firewall_expected = as_dict(expected.get("vnc_firewall"))
        expected_rules = as_list(firewall_expected.get("rules"))
        firewall_state = None
        firewall_ist = None

        if isinstance(firewall, dict):
            actual_rules = [
                rule for rule in as_list(firewall.get("Rules"))
                if isinstance(rule, dict)
            ]
            rule_results = []
            overall = True

            for rule_spec in expected_rules:
                rule_spec = as_dict(rule_spec)
                name_pattern = text(rule_spec.get("name_regex"))
                local_port = text(rule_spec.get("local_port"))

                candidates = []
                compliant = []
                for rule in actual_rules:
                    name_text = "{0} {1}".format(
                        text(rule.get("Name")),
                        text(rule.get("DisplayName")),
                    )
                    if not regex_match(name_pattern, name_text):
                        continue

                    candidates.append(rule)
                    ok = (
                        bool_value(rule.get("Enabled")) is True
                        and text(rule.get("Direction")).strip().lower() == "inbound"
                        and text(rule.get("Action")).strip().lower() == "allow"
                        and profile_is_all(rule.get("Profile"))
                        and firewall_rule_has_port(rule, local_port)
                    )
                    if ok:
                        compliant.append({
                            "Name": rule.get("Name"),
                            "DisplayName": rule.get("DisplayName"),
                            "Enabled": rule.get("Enabled"),
                            "Direction": rule.get("Direction"),
                            "Action": rule.get("Action"),
                            "Profile": rule.get("Profile"),
                            "PortFilters": rule.get("PortFilters"),
                        })

                rule_ok = bool(compliant)
                overall = overall and rule_ok
                rule_results.append({
                    "Expected": rule_spec,
                    "MatchingRules": len(candidates),
                    "CompliantRules": compliant,
                    "OK": rule_ok,
                })

            firewall_state = overall
            firewall_ist = rule_results

        checks["IPC0027"] = make_check(
            "IPC0027",
            "Windows Firewall Regeln für VNC anpassen",
            firewall_state,
            {
                "Rules": expected_rules,
                "Enabled": True,
                "Direction": "Inbound",
                "Action": "Allow",
                "Profiles": "Domain + Private + Public / Any",
            },
            firewall_ist,
            "Firewall_SMB_Patch_Valid.Firewall.Rules",
        )

        # --------------------------------------------------------------
        # IPC0028 - LocalAccountTokenFilterPolicy
        # --------------------------------------------------------------
        wanted_token_filter = int_value(expected.get("local_account_token_filter_policy"))
        token_filter_state = None
        token_filter_ist = None

        if explicit_policy is not None:
            rows = registry_values(explicit_policy)
            matches = []
            for row in rows:
                path = text(row.get("Path")).replace("/", "\\").lower()
                name = text(row.get("Name")).strip().lower()
                if (
                    name == "localaccounttokenfilterpolicy"
                    and path.endswith(
                        r"\software\microsoft\windows\currentversion\policies\system"
                    )
                ):
                    matches.append(row)

            token_filter_ist = matches if matches else "Registrywert nicht gefunden"
            token_filter_state = bool(matches) and any(
                int_value(row.get("Value")) == wanted_token_filter
                for row in matches
            )

        checks["IPC0028"] = make_check(
            "IPC0028",
            "Registry Eintrag für VEEAM setzen",
            token_filter_state,
            {
                "Path": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "Name": "LocalAccountTokenFilterPolicy",
                "Value": wanted_token_filter,
            },
            token_filter_ist,
            "GPOs_Valid.ExplicitlyConfiguredPolicyRegistry",
        )

        # --------------------------------------------------------------
        # IPC0036 - integriertes Administratorkonto: Kennwort laeuft nie ab
        # --------------------------------------------------------------
        wanted_password_expires = bool_value(
            as_dict(expected.get("builtin_admin")).get("password_expires")
        )
        admin_state = None
        admin_ist = None

        if isinstance(local_users, list):
            admin_candidates = [
                user
                for user in local_users
                if isinstance(user, dict)
                and text(user.get("SID")).endswith("-500")
            ]

            admin_ist = [
                {
                    "Name": user.get("Name"),
                    "SID": user.get("SID"),
                    "Enabled": user.get("Enabled"),
                    "PasswordExpires": user.get("PasswordExpires"),
                    "PasswordLastSet": user.get("PasswordLastSet"),
                }
                for user in admin_candidates
            ]

            if admin_candidates and all(
                "PasswordExpires" in user
                for user in admin_candidates
            ):
                admin_state = all(
                    bool_value(user.get("PasswordExpires")) == wanted_password_expires
                    for user in admin_candidates
                )

        checks["IPC0036"] = make_check(
            "IPC0036",
            "Bestehendes Administrator-Konto umkonfigurieren",
            admin_state,
            {"BuiltinAdministratorPasswordExpires": wanted_password_expires},
            admin_ist,
            "Initial_Valid.LocalUsers",
            (
                "Das integrierte Administratorkonto wird robust ueber die "
                "SID-Endung -500 identifiziert; ein spaeter umbenannter "
                "Kontoname beeinflusst die Prüfung dadurch nicht."
            ),
        )

        # --------------------------------------------------------------
        # IPC0038 - lokaler Benutzer Admin_L vorhanden
        # --------------------------------------------------------------
        admin_l_ist = []
        admin_l_state = None
        if isinstance(local_users, list):
            admin_l_ist = [
                {
                    "Name": user.get("Name"),
                    "SID": user.get("SID"),
                    "Enabled": user.get("Enabled"),
                }
                for user in local_users
                if isinstance(user, dict)
                and text(user.get("Name")).strip().lower() == "admin_l"
            ]
            admin_l_state = len(admin_l_ist) > 0

        checks["IPC0038"] = make_check(
            "IPC0038",
            "Lokalen Benutzer Administrator umbenennen",
            admin_l_state,
            {"LocalUserName": "Admin_L"},
            admin_l_ist,
            "Initial_Valid.LocalUsers",
            "Es wird gemaess Vorgabe nur geprueft, ob ein lokaler Benutzer mit dem Namen Admin_L existiert.",
        )

        # --------------------------------------------------------------
        # IPC0043 - Zeitzone Berlin
        # Fester technischer Windows-Sollwert: W. Europe Standard Time.
        # Keine Semaphore-Variable erforderlich.
        # --------------------------------------------------------------
        timezone = as_dict(as_dict(time_config).get("TimeZone"))
        timezone_id = text(timezone.get("Id"))
        timezone_state = None if not timezone else timezone_id.lower() == "w. europe standard time"
        checks["IPC0043"] = make_check(
            "IPC0043",
            "Date and Time",
            timezone_state,
            {"TimeZoneId": "W. Europe Standard Time", "Region": "Berlin"},
            {
                "Id": timezone.get("Id"),
                "DisplayName": timezone.get("DisplayName"),
                "StandardName": timezone.get("StandardName"),
                "BaseUtcOffset": timezone.get("BaseUtcOffset"),
            } if timezone else None,
            "Initial_Valid.TimeConfiguration.TimeZone",
            "Die Uhrzeit selbst wird dokumentiert, aber nicht gegen eine feste Uhrzeit verglichen; der belastbare Sollwert ist die Zeitzone.",
        )

        # --------------------------------------------------------------
        # IPC0044 - Deutsch als primaere Sprache / an erster Stelle
        # --------------------------------------------------------------
        user_languages = as_list(as_dict(language).get("CurrentUserLanguageList"))
        language_tags = [
            text(as_dict(item).get("LanguageTag"))
            for item in user_languages
            if isinstance(item, dict) and text(as_dict(item).get("LanguageTag"))
        ]
        first_language = language_tags[0] if language_tags else None
        ui_culture = text(as_dict(as_dict(language).get("CurrentUICulture")).get("Name"))
        ipc0044_state = None
        if isinstance(language, dict) and language_tags:
            ipc0044_state = (
                text(first_language).lower().startswith("de")
                and ui_culture.lower().startswith("de")
            )
        checks["IPC0044"] = make_check(
            "IPC0044",
            "Language",
            ipc0044_state,
            {"PrimaryLanguage": "Deutsch", "FirstLanguageTag": "de-*"},
            {
                "FirstUserLanguage": first_language,
                "CurrentUICulture": ui_culture or None,
                "LanguageList": language_tags,
            } if isinstance(language, dict) else None,
            "Initial_Valid.LanguageAndRegion",
        )

        # --------------------------------------------------------------
        # IPC0045 - nicht benoetigte Benutzersprachen entfernt
        # Es werden bewusst die in der Aufgabenliste genannten Sprachen
        # geprueft und nicht installierte Windows-MUI-Pakete bewertet.
        # --------------------------------------------------------------
        forbidden_language_prefixes = ("en", "fr", "es", "it", "ja", "zh")
        forbidden_found = [
            tag for tag in language_tags
            if tag.lower().split("-")[0] in forbidden_language_prefixes
        ]
        ipc0045_state = None
        if isinstance(language, dict) and language_tags:
            ipc0045_state = (
                any(tag.lower().startswith("de") for tag in language_tags)
                and len(forbidden_found) == 0
            )
        checks["IPC0045"] = make_check(
            "IPC0045",
            "Sprachen entfernen",
            ipc0045_state,
            {
                "RequiredLanguage": "Deutsch",
                "ForbiddenLanguages": [
                    "Englisch", "Franzoesisch", "Spanisch", "Italienisch", "Japanisch", "Chinesisch"
                ],
            },
            {
                "CurrentUserLanguageList": language_tags,
                "ForbiddenLanguagesFound": forbidden_found,
            } if isinstance(language, dict) else None,
            "Initial_Valid.LanguageAndRegion.CurrentUserLanguageList",
            "Installierte MUI-Sprachpakete werden hier bewusst nicht als Fehler bewertet; relevant ist die aktive Benutzersprachenliste.",
        )

        # --------------------------------------------------------------
        # IPC0049 - alle relevanten physischen Adapter tragen nur die
        # freigegebenen Rollennamen. Virtuelle/Softwareadapter werden
        # bewusst nicht als Hardware-NICs bewertet.
        # --------------------------------------------------------------
        network_expected = as_dict(expected.get("network"))
        adapter_policy = as_dict(network_expected.get("adapter_policy"))
        allowed_adapter_names = [
            text(name).strip()
            for name in as_list(adapter_policy.get("allowed_names"))
            if text(name).strip()
        ]
        allowed_adapter_names_normalized = {name.lower() for name in allowed_adapter_names}
        physical_adapters = physical_network_adapters(network_adapters)

        ipc0049_state = None
        ipc0049_ist = None
        if isinstance(network_adapters, list):
            ipc0049_ist = [
                {
                    "Name": adapter.get("Name"),
                    "Status": adapter.get("Status"),
                    "HardwareInterface": adapter.get("HardwareInterface"),
                    "Virtual": adapter.get("Virtual"),
                    "AllowedName": text(adapter.get("Name")).strip().lower() in allowed_adapter_names_normalized,
                }
                for adapter in physical_adapters
            ]
            ipc0049_state = bool(physical_adapters) and all(
                text(adapter.get("Name")).strip().lower() in allowed_adapter_names_normalized
                for adapter in physical_adapters
            )

        checks["IPC0049"] = make_check(
            "IPC0049",
            "Netzwerkadapter umbenennen",
            ipc0049_state,
            {"AllowedPhysicalAdapterNames": allowed_adapter_names},
            ipc0049_ist,
            "Initial_Valid.NetworkAdapters",
            "Nur physische Hardwareadapter werden bewertet; virtuelle/Softwareadapter werden nicht als Fehler gewertet.",
        )

        terminalbus_expected = as_dict(network_expected.get("terminalbus"))
        anlagenbus_expected = as_dict(network_expected.get("anlagenbus"))
        redundanzbus_expected = as_dict(network_expected.get("redundanzbus"))
        terminalbus = find_adapters_by_name_regex(network_adapters, terminalbus_expected.get("name_regex"))
        anlagenbus = find_adapters_by_name_regex(network_adapters, anlagenbus_expected.get("name_regex"))
        redundanzbus = find_adapters_by_name_regex(network_adapters, redundanzbus_expected.get("name_regex"))

        # --------------------------------------------------------------
        # IPC0050 - Terminalbus-Informationen ausgeben. Die IP-Adresse
        # wird bewusst nicht als Sollwert bewertet; IPv4/IPv6, Gateway,
        # DNS, WINS, Bindings, Routen usw. bleiben im Istwert sichtbar.
        # --------------------------------------------------------------
        information["IPC0050"] = make_information(
            "IPC0050",
            "Terminalbus-Adresse einstellen",
            terminalbus if terminalbus else None,
            "Initial_Valid.NetworkAdapters",
            "Ausgabe des vollstaendigen Terminalbus-Adapters; keine IP-Sollwertpruefung in dieser ID.",
        )

        # --------------------------------------------------------------
        # IPC0051 - finaler Terminalbus-Gatewaywert.
        # Projekt-/kundenspezifischer Wert aus Semaphore.
        # --------------------------------------------------------------
        wanted_gateway = text(terminalbus_expected.get("gateway")).strip()
        ipc0051_state = None
        ipc0051_ist = None
        if isinstance(network_adapters, list):
            ipc0051_ist = [
                {
                    "Name": adapter.get("Name"),
                    "Gateway": ordered_string_list(adapter.get("Gateway")),
                }
                for adapter in terminalbus
            ]
            ipc0051_state = bool(terminalbus) and all(
                wanted_gateway in ordered_string_list(adapter.get("Gateway"))
                for adapter in terminalbus
            )
        checks["IPC0051"] = make_check(
            "IPC0051",
            "Terminalbus Gateway korrigieren",
            ipc0051_state,
            {"Gateway": wanted_gateway},
            ipc0051_ist,
            "Initial_Valid.NetworkAdapters[].Gateway",
        )

        # --------------------------------------------------------------
        # IPC0052 - Anlagenbus-Informationen + feste Binding-Sollwerte.
        # ms_msclient und ms_server muessen deaktiviert sein;
        # SIMATIC Industrial Ethernet (ISO) muss aktiviert sein.
        # --------------------------------------------------------------
        ipc0052_state = None
        ipc0052_ist = None
        if isinstance(network_adapters, list):
            adapter_results = []
            all_ok = bool(anlagenbus)
            for adapter in anlagenbus:
                client_bindings = binding_matches(adapter, component_id="ms_msclient")
                server_bindings = binding_matches(adapter, component_id="ms_server")
                simatic_bindings = binding_matches(
                    adapter,
                    display_regex=r"SIMATIC.*Industrial.*Ethernet.*\(ISO\)|SIMATIC.*Industrial.*Ethernet.*ISO",
                )
                client_ok = bool(client_bindings) and all(
                    bool_value(binding.get("Enabled")) is False for binding in client_bindings
                )
                server_ok = bool(server_bindings) and all(
                    bool_value(binding.get("Enabled")) is False for binding in server_bindings
                )
                simatic_ok = bool(simatic_bindings) and any(
                    bool_value(binding.get("Enabled")) is True for binding in simatic_bindings
                )
                adapter_ok = client_ok and server_ok and simatic_ok
                all_ok = all_ok and adapter_ok
                adapter_results.append({
                    "Adapter": adapter,
                    "BindingCheck": {
                        "ClientForMicrosoftNetworks": {"OK": client_ok, "Matches": client_bindings},
                        "FileAndPrinterSharingForMicrosoftNetworks": {"OK": server_ok, "Matches": server_bindings},
                        "SIMATICIndustrialEthernetISO": {"OK": simatic_ok, "Matches": simatic_bindings},
                    },
                })
            ipc0052_state = all_ok
            ipc0052_ist = adapter_results

        checks["IPC0052"] = make_check(
            "IPC0052",
            "Anlagenbus-Adresse einstellen",
            ipc0052_state,
            {
                "AdapterInformation": "ausgeben",
                "Bindings": {
                    "ms_msclient": False,
                    "ms_server": False,
                    "SIMATIC Industrial Ethernet (ISO)": True,
                },
            },
            ipc0052_ist,
            "Initial_Valid.NetworkAdapters[].Bindings",
            "Die Anlagenbus-IP wird gemaess Vorgabe nur dokumentiert; OK/NOK dieser ID bezieht sich auf die drei Binding-Einstellungen.",
        )

        # --------------------------------------------------------------
        # IPC0053 - Redundanzbus-Informationen ausgeben.
        # --------------------------------------------------------------
        information["IPC0053"] = make_information(
            "IPC0053",
            "Redundanzbus-Adresse einstellen",
            redundanzbus if redundanzbus else None,
            "Initial_Valid.NetworkAdapters",
            "Ausgabe des vollstaendigen Redundanzbus-Adapters; keine IP-Sollwertpruefung in dieser ID.",
        )

        # --------------------------------------------------------------
        # IPC0054 - nicht benoetigte physische Adapter deaktivieren.
        # Ein physisch vorhandener, aber deaktivierter Adapter ist erlaubt.
        # Fuer ES wird die maximal erlaubte Zahl aktivierter Hardware-NICs
        # ueber Semaphore vorgegeben.
        # --------------------------------------------------------------
        max_enabled = int_value(adapter_policy.get("max_enabled_physical_adapters"))
        ipc0054_state = None
        ipc0054_ist = None
        if isinstance(network_adapters, list) and physical_adapters:
            enabled_physical = [
                adapter for adapter in physical_adapters
                if adapter_is_enabled(adapter) is True
            ]
            ipc0054_ist = {
                "PhysicalAdapters": [
                    {
                        "Name": adapter.get("Name"),
                        "Status": adapter.get("Status"),
                        "EnabledByStatus": adapter_is_enabled(adapter),
                    }
                    for adapter in physical_adapters
                ],
                "EnabledPhysicalAdapterCount": len(enabled_physical),
            }
            ipc0054_state = (
                max_enabled is not None
                and len(enabled_physical) <= max_enabled
                and all(
                    text(adapter.get("Name")).strip().lower() in allowed_adapter_names_normalized
                    for adapter in enabled_physical
                )
            )

        checks["IPC0054"] = make_check(
            "IPC0054",
            "Nicht benoetigte Netzwerkadapter deaktivieren",
            ipc0054_state,
            {
                "MaxEnabledPhysicalAdapters": max_enabled,
                "AllowedNames": allowed_adapter_names,
            },
            ipc0054_ist,
            "Initial_Valid.NetworkAdapters",
            "Status 'Disabled' gilt als deaktiviert; ein vorhandener deaktivierter Hardwareadapter fuehrt nicht zu NOK.",
        )

        # IPC0055 wird nachfolgend direkt/read-only geprueft, damit neben
        # DNS auch die vollstaendige NetBT NameServerList fuer WINS
        # ausgewertet werden kann.

        # --------------------------------------------------------------
        # IPC0056 - LMHOSTS-Abfrage am Terminalbus deaktiviert.
        # Fester technischer Sollwert, daher keine zusaetzliche Semaphore-
        # Variable: EnableLMHostsLookup = false.
        # --------------------------------------------------------------
        ipc0056_state = None
        ipc0056_ist = None
        if isinstance(network_adapters, list):
            lmhosts_rows = []
            for adapter in terminalbus:
                wins = as_dict(adapter.get("WINS"))
                lmhosts_rows.append({
                    "Name": adapter.get("Name"),
                    "EnableLMHostsLookup": wins.get("EnableLMHostsLookup") if wins else None,
                })
            ipc0056_ist = lmhosts_rows
            if terminalbus and all(row.get("EnableLMHostsLookup") is not None for row in lmhosts_rows):
                ipc0056_state = all(
                    bool_value(row.get("EnableLMHostsLookup")) is False
                    for row in lmhosts_rows
                )

        checks["IPC0056"] = make_check(
            "IPC0056",
            "LMHOSTS-Abfrage deaktivieren",
            ipc0056_state,
            {"EnableLMHostsLookup": False},
            ipc0056_ist,
            "Initial_Valid.NetworkAdapters[].WINS.EnableLMHostsLookup",
        )

        # --------------------------------------------------------------
        # IPC0059 - Domainmitgliedschaft und Domainname.
        # Domainname ist kunden-/projektspezifisch und kommt aus Semaphore.
        # --------------------------------------------------------------
        domain_expected = as_dict(expected.get("domain"))
        wanted_domain = text(domain_expected.get("name")).strip()
        domain = as_dict(domain_info)
        ipc0059_state = None
        ipc0059_ist = None
        if domain:
            part_of_domain = bool_value(domain.get("PartOfDomain"))
            actual_domain = text(domain.get("Domain")).strip()
            ipc0059_ist = {
                "PartOfDomain": domain.get("PartOfDomain"),
                "Domain": domain.get("Domain"),
                "Workgroup": domain.get("Workgroup"),
                "ComputerAccountDN": domain.get("ComputerAccountDN"),
            }
            ipc0059_state = (
                part_of_domain is True
                and normalize_domain(actual_domain) == normalize_domain(wanted_domain)
            )

        checks["IPC0059"] = make_check(
            "IPC0059",
            "Rechner in die Domaene aufnehmen",
            ipc0059_state,
            {"PartOfDomain": True, "Domain": wanted_domain},
            ipc0059_ist,
            "Initial_Valid.DomainInformation",
        )

        # --------------------------------------------------------------
        # IPC0060 - OU nur als Information ausgeben, sofern ermittelbar.
        # 0110 bevorzugt den lokal gecachten Group-Policy-DN und nutzt
        # LDAP nur als Fallback; 0160 wertet ausschliesslich das Ergebnis aus.
        # --------------------------------------------------------------
        ou_info = None
        if domain:
            ou_info = {
                "PartOfDomain": domain.get("PartOfDomain"),
                "Domain": domain.get("Domain"),
                "ComputerAccountDN": domain.get("ComputerAccountDN"),
                "ComputerAccountParentDN": domain.get("ComputerAccountParentDN"),
                "ComputerAccountOU": domain.get("ComputerAccountOU"),
                "OrganizationalUnits": domain.get("OrganizationalUnits"),
                "DistinguishedNameSource": domain.get("DistinguishedNameSource"),
                "DirectoryLookupError": domain.get("DirectoryLookupError"),
            }
        information["IPC0060"] = make_information(
            "IPC0060",
            "Rechner in der OU einsortieren",
            ou_info,
            "Initial_Valid.DomainInformation",
            "OU/DN wird nur dokumentiert; fuer IPC0060 ist aktuell kein OU-Sollwert definiert.",
        )

        # --------------------------------------------------------------
        # IPC0065 - VNC-Gruppe / New MS-Logon ACL.
        # Der geforderte Endzustand umfasst die konkrete Gruppe sowie
        # FullControl/Interact/View. Diese ACL wird durch die aktuellen
        # 0110-Snapshots nicht belastbar erfasst. Eine Teilpruefung nur der
        # INI-Schalter waere fuer diese ID fachlich unvollstaendig.
        # --------------------------------------------------------------
        checks["IPC0065"] = make_ignored(
            "IPC0065",
            "VNC-Gruppe einstellen",
            (
                "IGNORIERT: Die konkrete New-MS-Logon-ACL inklusive Gruppenname und "
                "FullControl/Interact/View wird von den vorhandenen Snapshots nicht "
                "belastbar erfasst. Eine reine Schalterpruefung waere kein Nachweis "
                "des geforderten Endzustands."
            ),
            "UltraVNC New MS-Logon ACL",
        )

        # --------------------------------------------------------------
        # IPC0072 - Partitionen. C: muss mindestens die projektweit
        # definierte Mindestgroesse besitzen. D: ist rechnertypabhaengig
        # und wird fuer diese Ausbaustufe ausschliesslich fuer ES bewertet.
        # --------------------------------------------------------------
        storage_expected = as_dict(expected.get("storage"))
        system_drive_expected = as_dict(storage_expected.get("system_drive"))
        data_drive_expected = as_dict(storage_expected.get("data_drive"))
        c_min_gb = float(system_drive_expected.get("minimum_size_gb"))
        d_expected_by_type = as_dict(data_drive_expected.get("expected_size_gb_by_type"))
        d_expected_gb = float(d_expected_by_type.get("ES"))
        d_tolerance_gb = float(data_drive_expected.get("tolerance_gb"))

        ipc0072_state = None
        ipc0072_ist = None
        if isinstance(storage, dict):
            volumes = [row for row in as_list(storage.get("Volumes")) if isinstance(row, dict)]
            c_rows = [row for row in volumes if text(row.get("DriveLetter")).upper() == "C"]
            d_rows = [row for row in volumes if text(row.get("DriveLetter")).upper() == "D"]
            c_gb = bytes_to_gb(c_rows[0].get("SizeBytes")) if c_rows else None
            d_gb = bytes_to_gb(d_rows[0].get("SizeBytes")) if d_rows else None
            ipc0072_ist = {
                "C": {"SizeGB": round(c_gb, 2) if c_gb is not None else None, "Raw": c_rows[0] if c_rows else None},
                "D": {"SizeGB": round(d_gb, 2) if d_gb is not None else None, "Raw": d_rows[0] if d_rows else None},
            }
            if c_gb is not None and d_gb is not None:
                ipc0072_state = (
                    c_gb >= c_min_gb
                    and abs(d_gb - d_expected_gb) <= d_tolerance_gb
                )

        checks["IPC0072"] = make_check(
            "IPC0072",
            "Partition (C: mindestens 100 GB; D Rest)",
            ipc0072_state,
            {
                "ComputerType": "ES",
                "C_MinimumSizeGB": c_min_gb,
                "D_ExpectedSizeGB": d_expected_gb,
                "D_ToleranceGB": d_tolerance_gb,
            },
            ipc0072_ist,
            "Initial_Valid.Storage.Volumes",
            "C: wird als Mindestgroesse bewertet; D: gegen den ES-Sollwert mit Toleranz.",
        )

        # --------------------------------------------------------------
        # IPC0077 - Microsoft-Edge-Verknuepfung loeschen.
        # Der 0110/0150-Snapshot enthaelt keinen vollstaendigen Desktop-
        # Dateibestand. Die ID bleibt trotzdem in der ES-Matrix sichtbar;
        # aus fehlender Evidenz wird bewusst kein NOK abgeleitet.
        # --------------------------------------------------------------
        information["IPC0077"] = make_information(
            "IPC0077",
            "Microsoft Edge Verknuepfung loeschen",
            None,
            "0110/0150: kein normalisierter Desktop-Dateibestand",
            (
                "Der Endzustand der Edge-Desktopverknuepfung ist aus den vorhandenen "
                "Snapshots nicht belastbar ableitbar. Eine direkte read-only "
                "Desktop/CommonDesktop-Pruefung kann spaeter im 0160-YAML ergaenzt werden."
            ),
        )

        # --------------------------------------------------------------
        # IPC0078 - HUP nur pruefen, wenn in Semaphore mindestens ein
        # erwartetes Produktregex hinterlegt wurde. Leere Liste = bewusst
        # ignoriert, nicht NOK und nicht NICHT_PRUEFBAR.
        # --------------------------------------------------------------
        software_expected = as_dict(expected.get("software"))
        hup_expected = as_dict(software_expected.get("hup"))
        hup_expected_installed = bool_value(hup_expected.get("expected_installed"))
        hup_patterns = [text(x) for x in as_list(hup_expected.get("expected_name_regexes")) if text(x).strip()]
        if hup_expected_installed is None:
            checks["IPC0078"] = make_ignored(
                "IPC0078",
                "HUP installieren",
                "IGNORIERT: expected_installed ist in Semaphore auf null gesetzt.",
                "Semaphore: ipc_es_validation_expected.software.hup",
            )
        elif not hup_patterns:
            checks["IPC0078"] = make_check(
                "IPC0078",
                "HUP installieren",
                None,
                {"ExpectedInstalled": hup_expected_installed, "ExpectedNameRegexes": []},
                None,
                "Semaphore: ipc_es_validation_expected.software.hup",
                "Fuer eine belastbare Softwarepruefung muss mindestens ein Produktname/Regex konfiguriert sein.",
            )
        elif products is not None:
            per_pattern = []
            all_found = True
            any_found = False
            for pattern in hup_patterns:
                matches = find_products(products, pattern)
                found = bool(matches)
                all_found = all_found and found
                any_found = any_found or found
                per_pattern.append({"ExpectedNameRegex": pattern, "Matches": matches, "Found": found})
            overall_hup = all_found if hup_expected_installed is True else (not any_found)
            checks["IPC0078"] = make_check(
                "IPC0078",
                "HUP installieren",
                overall_hup,
                {"ExpectedInstalled": hup_expected_installed, "ExpectedNameRegexes": hup_patterns},
                per_pattern,
                "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts",
            )
        else:
            checks["IPC0078"] = make_check(
                "IPC0078",
                "HUP installieren",
                None,
                {"ExpectedInstalled": hup_expected_installed, "ExpectedNameRegexes": hup_patterns},
                None,
                "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts",
            )

        # --------------------------------------------------------------
        # IPC0079 - Speed & Duplex auf Auto Negotiation fuer alle
        # aktivierten physischen Netzwerkadapter.
        # --------------------------------------------------------------
        ipc0079_state = None
        ipc0079_ist = None
        if isinstance(network_adapters, list):
            active_physical = [a for a in physical_adapters if adapter_is_enabled(a) is True]
            details = []
            explicit_failure = False
            missing_property = False
            for adapter in active_physical:
                candidates = []
                for prop in as_list(as_dict(adapter).get("AdvancedProperties")):
                    if not isinstance(prop, dict):
                        continue
                    searchable = "{0} {1}".format(text(prop.get("DisplayName")), text(prop.get("RegistryKeyword")))
                    if regex_match(r"speed.*duplex|geschwindigkeit.*duplex|\*?speedduplex", searchable):
                        candidates.append(prop)
                if not candidates:
                    missing_property = True
                    adapter_ok = None
                else:
                    adapter_ok = any(
                        regex_match(r"^(auto|automatisch|auto negotiation|automatische aushandlung)$", text(prop.get("DisplayValue")).strip())
                        or any(text(v).strip() == "0" for v in as_list(prop.get("RegistryValue")))
                        for prop in candidates
                    )
                    if adapter_ok is False:
                        explicit_failure = True
                details.append({"Name": adapter.get("Name"), "Properties": candidates, "OK": adapter_ok})
            ipc0079_ist = details
            if active_physical:
                if explicit_failure:
                    ipc0079_state = False
                elif missing_property:
                    ipc0079_state = None
                else:
                    ipc0079_state = True

        checks["IPC0079"] = make_check(
            "IPC0079",
            "Einstellungen Netzwerkkarte ueberpruefen (Speed & Duplex)",
            ipc0079_state,
            {"SpeedAndDuplex": "Auto Negotiation"},
            ipc0079_ist,
            "Initial_Valid.NetworkAdapters[].AdvancedProperties",
        )

        # --------------------------------------------------------------
        # IPC0080 - Energiesparoption der aktivierten physischen NICs.
        # Disabled/False sowie Unsupported gelten als nicht aktivierte
        # Abschaltfunktion. Ein explizites Enabled ergibt NOK.
        # --------------------------------------------------------------
        ipc0080_state = None
        ipc0080_ist = None
        if isinstance(network_adapters, list):
            active_physical = [a for a in physical_adapters if adapter_is_enabled(a) is True]
            details = []
            explicit_failure = False
            unknown = False
            for adapter in active_physical:
                pm = as_dict(adapter.get("PowerManagement"))
                raw = pm.get("AllowComputerToTurnOffDevice") if pm else None
                normalized = text(raw).strip().lower()
                if normalized in {"disabled", "false", "0", "unsupported", "not supported", "nicht unterstuetzt"}:
                    adapter_ok = True
                elif normalized in {"enabled", "true", "1"}:
                    adapter_ok = False
                    explicit_failure = True
                else:
                    adapter_ok = None
                    unknown = True
                details.append({"Name": adapter.get("Name"), "AllowComputerToTurnOffDevice": raw, "OK": adapter_ok})
            ipc0080_ist = details
            if active_physical:
                if explicit_failure:
                    ipc0080_state = False
                elif unknown:
                    ipc0080_state = None
                else:
                    ipc0080_state = True

        checks["IPC0080"] = make_check(
            "IPC0080",
            "Energiesparoptionen fuer Netzwerkkarten deaktivieren",
            ipc0080_state,
            {"AllowComputerToTurnOffDevice": False},
            ipc0080_ist,
            "Initial_Valid.NetworkAdapters[].PowerManagement.AllowComputerToTurnOffDevice",
        )

        # --------------------------------------------------------------
        # IPC0081 / IPC0082 - Windows Features. 0110 sammelt sowohl
        # OptionalFeatures als auch ServerRolesAndFeatures, daher kann die
        # Pruefung ohne zusaetzlichen Live-Zugriff erfolgen.
        # --------------------------------------------------------------
        component_rows = component_records(windows_components)
        netfx35 = component_matches(component_rows, r"^(NET-Framework-Core|NetFx3)(?:\s|$)")
        wcf35 = component_matches(
            component_rows,
            r"^(NET-WCF-HTTP-Activation|NET-WCF-NonHTTP-Activ|WCF-HTTP-Activation|WCF-NonHTTP-Activation)(?:\s|$)",
        )
        netfx_known = bool(netfx35)
        netfx_ok = netfx_known and any(component_enabled(row) is True for row in netfx35)
        wcf_ok = all(component_enabled(row) is not True for row in wcf35)
        ipc0081_state = (netfx_ok and wcf_ok) if netfx_known else None
        checks["IPC0081"] = make_check(
            "IPC0081",
            "Microsoft .NET Framework 3.5 aktivieren",
            ipc0081_state,
            {"NETFramework35": "aktiviert", "WCFActivation35": "nicht aktiviert"},
            {"NetFx35": netfx35, "WCFActivation35": wcf35},
            "Initial_Valid.WindowsComponents",
        )

        msmq = component_matches(component_rows, r"^MSMQ-Server(?:\s|$)")
        ipc0082_state = None if not component_rows else (bool(msmq) and any(component_enabled(row) is True for row in msmq))
        checks["IPC0082"] = make_check(
            "IPC0082",
            "Microsoft Message Queue (MSMQ) Server aktivieren",
            ipc0082_state,
            {"MSMQ-Server": "aktiviert"},
            msmq if msmq else None,
            "Initial_Valid.WindowsComponents",
        )

        # --------------------------------------------------------------
        # IPC0084 / IPC0085 - aktuell nicht fuer ES relevant.
        # IPC0084 ist explizit ein CL-Endzustand; IPC0085 ebenfalls nur CL.
        # OS Client wird in dieser Ausbaustufe bewusst nicht bewertet.
        # --------------------------------------------------------------
        checks["IPC0084"] = make_ignored(
            "IPC0084",
            "Bildschirmschoner deaktivieren (CL)",
            "IGNORIERT: Die Vorgabe gilt fuer Clients; 0160 bewertet aktuell ausschliesslich IPC ES.",
            "Aufgabenliste / aktueller 0160-Scope ES",
        )
        checks["IPC0085"] = make_ignored(
            "IPC0085",
            "Mauszeiger auf Windows Schwarz (sehr gross) (CL)",
            "IGNORIERT: Die Vorgabe gilt fuer Clients; 0160 bewertet aktuell ausschliesslich IPC ES.",
            "Aufgabenliste / aktueller 0160-Scope ES",
        )

        # IPC0088 - aktiver Energiesparplan gemaess Rechnertyp.
        power_expected = as_dict(as_dict(expected.get("power")).get("by_type"))
        es_power_expected = as_dict(power_expected.get("ES"))
        active_plan = as_dict(as_dict(initial_best_practice).get("ActivePowerPlan"))
        plan_regex = text(es_power_expected.get("active_plan_name_regex"))
        plan_name = text(active_plan.get("ElementName"))
        ipc0088_state = None
        if active_plan and plan_regex:
            ipc0088_state = regex_match(plan_regex, plan_name)
        checks["IPC0088"] = make_check(
            "IPC0088", "Kontrolle Energieoptionen", ipc0088_state,
            {"ComputerType": "ES", "ActivePlanNameRegex": plan_regex},
            active_plan if active_plan else None,
            "Initial_Valid.InstallationBestPractice.ActivePowerPlan",
            "Der Plannamen-Sollwert ist rechnertypabhaengig in Semaphore hinterlegt.",
        )

        # IPC0090 - 7-Zip als konfigurierbare Software-Sollwertpruefung.
        seven_zip_expected = as_dict(software_expected.get("seven_zip"))
        seven_zip_should_exist = bool_value(seven_zip_expected.get("expected_installed"))
        seven_zip_name_regex = text(seven_zip_expected.get("name_regex"))
        seven_zip_version_regex = text(seven_zip_expected.get("version_regex"))
        seven_zip_state = None
        seven_zip_ist = None
        if products is not None and seven_zip_should_exist is not None:
            seven_zip_name_matches = find_products(products, seven_zip_name_regex)
            seven_zip_version_matches = find_products(products, seven_zip_name_regex, seven_zip_version_regex if seven_zip_version_regex else None)
            seven_zip_ist = {"NameMatches": seven_zip_name_matches, "VersionCompliantMatches": seven_zip_version_matches}
            if seven_zip_should_exist:
                seven_zip_state = bool(seven_zip_version_matches if seven_zip_version_regex else seven_zip_name_matches)
            else:
                seven_zip_state = not bool(seven_zip_name_matches)
        checks["IPC0090"] = make_check(
            "IPC0090", "7Zip installieren", seven_zip_state,
            {"ExpectedInstalled": seven_zip_should_exist, "NameRegex": seven_zip_name_regex, "VersionRegex": seven_zip_version_regex},
            seven_zip_ist,
            "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts",
            "Software-Sollwerte werden zentral unter ipc_es_validation_expected.software verwaltet.",
        )

        # IPC0091 - .NET Framework 3.5 muss aktiviert sein.
        dotnet_observations = as_dict(as_dict(dotnet_prereq).get("Observations"))
        netfx3_detected = bool_value(dotnet_observations.get("NetFx3DetectedEnabled"))
        ipc0091_state = None if not isinstance(dotnet_prereq, dict) else (netfx3_detected is True)
        checks["IPC0091"] = make_check(
            "IPC0091", ".NET Framework 3.5 SP1 installieren", ipc0091_state,
            {"NetFx3DetectedEnabled": True},
            {"NetFx3DetectedEnabled": dotnet_observations.get("NetFx3DetectedEnabled"), "NetFx3OptionalFeature": as_dict(dotnet_prereq).get("NetFx3OptionalFeature"), "NetFx3ServerFeature": as_dict(dotnet_prereq).get("NetFx3ServerFeature")} if isinstance(dotnet_prereq, dict) else None,
            "Software_PCS7_Components_Valid.DotNetAndRuntimePrerequisites",
        )

        # IPC0092 / IPC0093 - benoetigte Root-Zertifikate.
        quo_vadis = as_dict(as_dict(cert_prereq).get("QuoVadisRootCA2"))
        ipc0092_state = None if not isinstance(cert_prereq, dict) else (bool_value(quo_vadis.get("Detected")) is True)
        checks["IPC0092"] = make_check(
            "IPC0092", "Zertifikat installieren - QuoVadis Root CA 2", ipc0092_state,
            {"Store": "LocalMachine\\Root", "Certificate": "QuoVadis Root CA 2", "Detected": True},
            quo_vadis if quo_vadis else None,
            "Software_PCS7_Components_Valid.PCS7CertificatePrerequisites.QuoVadisRootCA2",
        )
        verisign = as_dict(as_dict(cert_prereq).get("VeriSignClass3PublicPrimaryCertificationAuthorityG5"))
        ipc0093_state = None if not isinstance(cert_prereq, dict) else (bool_value(verisign.get("Detected")) is True)
        checks["IPC0093"] = make_check(
            "IPC0093", "Zertifikat installieren - VeriSign Class 3 Public Primary Certification Authority - G5", ipc0093_state,
            {"Store": "LocalMachine\\Root", "Certificate": "VeriSign Class 3 Public Primary Certification Authority - G5", "Detected": True},
            verisign if verisign else None,
            "Software_PCS7_Components_Valid.PCS7CertificatePrerequisites.VeriSignClass3PublicPrimaryCertificationAuthorityG5",
        )

        # IPC0094 - Certificate Path Validation Settings im Computer-Kontext definiert.
        certificate_policy = as_list(as_dict(policy_areas).get("Certificates"))
        chain_policy_matches = []
        for row in certificate_policy:
            if not isinstance(row, dict):
                continue
            path = text(row.get("Path")).replace("/", "\\").lower()
            if "\\software\\policies\\microsoft\\systemcertificates\\chainengine\\config" in path:
                chain_policy_matches.append(row)
        ipc0094_state = None if not isinstance(policy_areas, dict) else bool(chain_policy_matches)
        checks["IPC0094"] = make_check(
            "IPC0094", "Zertifikataktualisierung muss zugelassen werden - Certificate Path Validation Settings definiert", ipc0094_state,
            {"PolicyDefined": True, "RegistryPathContains": r"SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\ChainEngine\\Config"},
            chain_policy_matches if chain_policy_matches else None,
            "GPOs_Valid.PolicyAreaSnapshots.Certificates",
            "Es wird der definierte Computer-Policy-Endzustand geprueft; einzelne Netzwerkabruf-Unteroptionen werden nicht erfunden.",
        )

        # IPC0095 - DisableRootAutoUpdate muss explizit 0 sein.
        root_update_entries = as_list(as_dict(cert_prereq).get("RootAutoUpdateRegistry"))
        root_update_evidence = []
        root_update_state = None
        if isinstance(cert_prereq, dict):
            root_update_state = False
            for entry in root_update_entries:
                if not isinstance(entry, dict):
                    continue
                values = as_dict(entry.get("Values"))
                if "DisableRootAutoUpdate" not in values:
                    continue
                value = int_value(values.get("DisableRootAutoUpdate"))
                root_update_evidence.append({"Path": entry.get("Path"), "Value": value})
                if value == 0:
                    root_update_state = True
        checks["IPC0095"] = make_check(
            "IPC0095", "Zertifikataktualisierung muss zugelassen werden - DisableRootAutoUpdate", root_update_state,
            {"DisableRootAutoUpdate": 0},
            root_update_evidence if root_update_evidence else None,
            "Software_PCS7_Components_Valid.PCS7CertificatePrerequisites.RootAutoUpdateRegistry",
        )

        # --------------------------------------------------------------
        # IPC0097 - PCS 7 V10 Engineering inkl. geforderter Optionen.
        # Der vorhandene PCS7-Komponentenkatalog kombiniert Produkt- und
        # weitere Installations-Evidenz und ist daher robuster als ein
        # einzelner Uninstall-Registry-Name.
        # --------------------------------------------------------------
        pcs7_engineering_expected = as_dict(software_expected.get("pcs7_engineering"))
        pcs7_engineering_required = bool_value(pcs7_engineering_expected.get("expected_installed"))
        pcs7_engineering_ids = as_list(pcs7_engineering_expected.get("required_component_ids"))
        ipc0097_state, ipc0097_evidence = evaluate_component_requirement(
            component_detection,
            pcs7_engineering_ids,
            pcs7_engineering_required,
        )
        checks["IPC0097"] = make_check(
            "IPC0097",
            "PCS 7 V10 Installieren (ES)",
            ipc0097_state,
            {
                "ExpectedInstalled": pcs7_engineering_required,
                "RequiredComponentIds": pcs7_engineering_ids,
            },
            ipc0097_evidence,
            "Software_PCS7_Components_Valid.PCS7ComponentCatalogDetection",
            (
                "Geprueft wird der aktuelle installierte Endzustand der geforderten "
                "PCS-7-Engineering-Komponenten. Der historische Installationsvorgang "
                "selbst wird nicht bewertet."
            ),
        )

        # --------------------------------------------------------------
        # IPC0103 - SIMATIC PCS 7 Library V7.1 SP3 Update 4.
        # --------------------------------------------------------------
        pcs7_lib_expected = as_dict(software_expected.get("pcs7_library_v71_sp3_upd4"))
        pcs7_lib_required = bool_value(pcs7_lib_expected.get("expected_installed"))
        pcs7_lib_component_id = text(pcs7_lib_expected.get("component_id"))
        ipc0103_state, ipc0103_evidence = evaluate_component_requirement(
            component_detection,
            [pcs7_lib_component_id],
            pcs7_lib_required,
        )
        checks["IPC0103"] = make_check(
            "IPC0103",
            "SIMATIC_PCS7_Lib_V7_1_SP3_Upd4 installieren (ESen)",
            ipc0103_state,
            {
                "ExpectedInstalled": pcs7_lib_required,
                "ComponentId": pcs7_lib_component_id,
            },
            ipc0103_evidence,
            "Software_PCS7_Components_Valid.PCS7ComponentCatalogDetection",
            "Der Sollwert wird zentral unter ipc_es_validation_expected.software verwaltet.",
        )

        # --------------------------------------------------------------
        # IPC0104 - PCS 7 Faceplates V7.1 SP3 Update 1.
        # --------------------------------------------------------------
        faceplates_expected = as_dict(software_expected.get("pcs7_faceplates_v71_sp3_upd1"))
        ipc0104_state, ipc0104_evidence = evaluate_software_requirement(
            products,
            faceplates_expected,
        )
        checks["IPC0104"] = make_check(
            "IPC0104",
            "SIMATIC_PCS7_Faceplates_V7_1_SP3_Upd1 installieren",
            ipc0104_state,
            {
                "ExpectedInstalled": bool_value(faceplates_expected.get("expected_installed")),
                "NameRegex": faceplates_expected.get("name_regex"),
                "VersionRegex": faceplates_expected.get("version_regex"),
            },
            ipc0104_evidence,
            "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts",
            "Produktname/Version sind projektseitig ueber den zentralen Software-Block in Semaphore anpassbar.",
        )

        # --------------------------------------------------------------
        # IPC0105 - PCS 7 Basis Library V10.0.
        # "erneut installieren" ist historisch nicht beweisbar; geprueft
        # wird der geforderte installierte Endzustand.
        # --------------------------------------------------------------
        basis_library_expected = as_dict(software_expected.get("pcs7_basis_library_v10"))
        ipc0105_state, ipc0105_evidence = evaluate_software_requirement(
            products,
            basis_library_expected,
        )
        checks["IPC0105"] = make_check(
            "IPC0105",
            "PCS7 Bib erneut ueber Rahmensetup installieren",
            ipc0105_state,
            {
                "ExpectedInstalled": bool_value(basis_library_expected.get("expected_installed")),
                "NameRegex": basis_library_expected.get("name_regex"),
                "VersionRegex": basis_library_expected.get("version_regex"),
            },
            ipc0105_evidence,
            "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts",
            (
                "Es wird belastbar geprueft, ob die PCS 7 Basis Library V10 im "
                "Endzustand installiert ist. Eine 'erneute' Installation laesst "
                "sich aus dem Endzustand nicht beweisen."
            ),
        )

        # --------------------------------------------------------------
        # IPC0108 - identischer Zertifikat-Sollwert wie IPC0093.
        # Keine zusaetzliche Semaphore-Variable, da derselbe feste
        # technische Zertifikats-Endzustand gefordert ist.
        # --------------------------------------------------------------
        ipc0108_state = None if not isinstance(cert_prereq, dict) else (
            bool_value(verisign.get("Detected")) is True
        )
        checks["IPC0108"] = make_check(
            "IPC0108",
            "Zertifikat installieren - VeriSign Class 3 Public Primary Certification Authority - G5",
            ipc0108_state,
            {
                "Store": "LocalMachine\\Root",
                "Certificate": "VeriSign Class 3 Public Primary Certification Authority - G5",
                "Detected": True,
            },
            verisign if verisign else None,
            "Software_PCS7_Components_Valid.PCS7CertificatePrerequisites.VeriSignClass3PublicPrimaryCertificationAuthorityG5",
            "Identischer Zertifikat-Sollwert wie IPC0093.",
        )

        # --------------------------------------------------------------
        # IPC0109 - STEP 7 V5.7 SP2 Update 2.
        # Der aktuelle installierte Versionsstand ist pruefbar; ob das
        # Setup historisch 'erneut' ausgefuehrt wurde, ist nicht beweisbar.
        # --------------------------------------------------------------
        step7_expected = as_dict(software_expected.get("step7"))
        ipc0109_state, ipc0109_evidence = evaluate_software_requirement(
            products,
            step7_expected,
        )
        checks["IPC0109"] = make_check(
            "IPC0109",
            "Erneute STEP 7 Installation",
            ipc0109_state,
            {
                "ExpectedInstalled": bool_value(step7_expected.get("expected_installed")),
                "NameRegex": step7_expected.get("name_regex"),
                "VersionRegex": step7_expected.get("version_regex"),
            },
            ipc0109_evidence,
            "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts",
            (
                "Geprueft wird der installierte STEP-7-Endzustand inklusive der "
                "konfigurierten Versionsanforderung. Der historische Vorgang "
                "'erneut installiert' ist aus einem Snapshot nicht nachweisbar."
            ),
        )

        # --------------------------------------------------------------
        # IPC0112-IPC0135 - PCS-7-Add-ons / Updates.
        # Erwartungswerte liegen zentral unter software.pcs7_addons.
        # --------------------------------------------------------------
        pcs7_addons = as_dict(software_expected.get("pcs7_addons"))
        addon_tasks = [
            ("IPC0112", "SENTRON 3WL/3VL V10", "sentron_3wl_3vl_v10"),
            ("IPC0113", "SENTRON PAC V10", "sentron_pac_v10"),
            ("IPC0114", "SIMOCODE pro PCS7 V10.0", "simocode_pro_v10"),
            ("IPC0115", "SIMOCODE pro PCS 7 Library Migration (Legacy) V10.0", "simocode_migration_legacy_v10"),
            ("IPC0117", "S7 F Systems V6.4 SP1", "s7_f_systems_v64_sp1"),
            ("IPC0119", "Industry Library V10.0", "industry_library_v10"),
            ("IPC0120", "PowerControl V9.1", "powercontrol_v91"),
            ("IPC0121", "PowerControl V9.1 Update 1", "powercontrol_v91_upd1"),
            ("IPC0122", "DriveES PCS 7 APL V10.0", "drive_es_pcs7_apl_v10"),
            ("IPC0123", "SITOP PCS 7 APL V4.0", "sitop_pcs7_apl_v40"),
            ("IPC0124", "SIMATIC Safety Matrix V6.3 SP1", "safety_matrix_v63_sp1"),
            ("IPC0127", "PCS7 V10 SP1 installieren (Aktualisierung)", "pcs7_v10_sp1"),
            ("IPC0128", "Industry Library 10.0 Upd1 aktualisieren", "industry_library_v10_upd1"),
            ("IPC0129", "SENTRON 3WL/3VL V10.0 SP1", "sentron_3wl_3vl_v10_sp1"),
            ("IPC0130", "SENTRON PAC V10.0 SP1", "sentron_pac_v10_sp1"),
            ("IPC0131", "SIMOCODE pro PCS7 V10.0 SP1", "simocode_pro_v10_sp1"),
            ("IPC0132", "SIMOCODE pro PCS 7 Library Migration (Legacy) V10.0 SP1", "simocode_migration_legacy_v10_sp1"),
            ("IPC0133", "Loher Dynavert PCS7 V10", "loher_dynavert_pcs7_v10"),
            ("IPC0134", "SIMATIC PCS 7 Basis Library V10.0 SP1 Upd1", "pcs7_basis_library_v10_sp1_upd1"),
            ("IPC0135", "Loher Dynavert / modbus-master318 / CP_Ptp_Param_V5.1.15", "loher_dynavert_toolset"),
        ]
        for task_id, task_name, config_key in addon_tasks:
            spec = as_dict(pcs7_addons.get(config_key))
            expected_installed = bool_value(spec.get("expected_installed"))
            if expected_installed is None:
                checks[task_id] = make_ignored(
                    task_id,
                    task_name,
                    "Software-Sollwert ist in Semaphore nicht aktiviert.",
                    "Semaphore: ipc_es_validation_expected.software.pcs7_addons",
                )
                continue

            state, evidence = evaluate_package_spec(
                component_detection,
                products,
                spec,
            )
            checks[task_id] = make_check(
                task_id,
                task_name,
                state,
                {
                    "ExpectedInstalled": expected_installed,
                    "ConfigurationKey": config_key,
                    "ComponentId": spec.get("component_id"),
                    "NameRegex": spec.get("name_regex"),
                    "RequiredNameRegexes": as_list(spec.get("required_name_regexes")),
                    "ForbiddenNameRegexes": as_list(spec.get("forbidden_name_regexes")),
                },
                evidence,
                (
                    "Software_PCS7_Components_Valid.PCS7ComponentCatalogDetection + "
                    "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts"
                ),
                (
                    "Geprueft wird der aktuelle installierte Endzustand. Historische "
                    "Installations-/Deinstallationsvorgaenge werden nur soweit bewertet, "
                    "wie ihr Endzustand technisch erkennbar ist."
                ),
            )

        # --------------------------------------------------------------
        # IPC0118 - Visual C++ 2010 x86 Redistributable vorhanden.
        # Die Reparaturaktion 'urspruenglichen Status wiederherstellen'
        # ist historisch nicht beweisbar; der resultierende Installations-
        # zustand ist dagegen vorhanden.
        # --------------------------------------------------------------
        prereq_expected = as_dict(software_expected.get("prerequisites"))
        vc2010_expected = as_dict(prereq_expected.get("visual_cpp_2010_x86"))
        vc2010_required = bool_value(vc2010_expected.get("expected_installed"))
        dotnet_observations = as_dict(as_dict(dotnet_prereq).get("Observations"))
        vc2010_detected = bool_value(dotnet_observations.get("VisualCpp2010x86Detected"))
        if vc2010_required is None:
            checks["IPC0118"] = make_ignored(
                "IPC0118",
                "S7 F Systems Nachinstallationsaufgabe - Visual C++ 2010 x86",
                "Software-Sollwert ist in Semaphore nicht aktiviert.",
                "Semaphore: software.prerequisites.visual_cpp_2010_x86",
            )
        else:
            vc2010_state = None if vc2010_detected is None else (
                vc2010_detected == vc2010_required
            )
            checks["IPC0118"] = make_check(
                "IPC0118",
                "S7 F Systems Nachinstallationsaufgabe - Visual C++ 2010 x86",
                vc2010_state,
                {"ExpectedInstalled": vc2010_required},
                {
                    "VisualCpp2010x86Detected": vc2010_detected,
                    "RepairActionHistoricallyVerifiable": False,
                },
                "Software_PCS7_Components_Valid.DotNetAndRuntimePrerequisites.Observations",
                "Der aktuelle Redistributable-Endzustand wird geprueft; die historische Reparaturaktion selbst nicht.",
            )

        # --------------------------------------------------------------
        # IPC0126 - PCS 7 V10 UC02 installieren.
        # Der historische SMC-Installationsvorgang ist nicht beweisbar.
        # Vorhandene Software- und Setup-Log-Evidenz wird deshalb als
        # INFORMATION ausgegeben.
        # --------------------------------------------------------------
        uc02_products = product_regex_matches(
            products,
            r"(?i)PCS\s*7.*(UC\s*0?2|Update.*Collection.*0?2)",
        )
        uc02_log_hits = [
            text(value)
            for value in as_list(as_dict(setup_log_evidence).get("Highlights"))
            if regex_match(r"(?i)(UC\s*0?2|Update.*Collection.*0?2)", value)
        ]
        information["IPC0126"] = make_information(
            "IPC0126",
            "PCS 7 V10 UC02 installieren",
            {
                "InstalledSoftwareMatches": uc02_products,
                "SetupLogMatches": uc02_log_hits[:100],
            } if (products is not None or isinstance(setup_log_evidence, dict)) else None,
            (
                "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts + "
                "Software_PCS7_Components_Valid.PCS7SetupLogEvidence"
            ),
            (
                "UC02 wird mangels eindeutig normalisiertem Detektor als Evidenz "
                "ausgegeben; ein fehlender Treffer wird nicht als NOK interpretiert."
            ),
        )

        # --------------------------------------------------------------
        # IPC0137 - Autostart deaktivieren.
        # Ohne konkrete Anwendung/Run-Key/Task ist keine belastbare
        # Sollwertpruefung moeglich. Eine pauschale leere Autostartliste
        # waere technisch falsch.
        # --------------------------------------------------------------
        checks["IPC0137"] = make_ignored(
            "IPC0137",
            "Autostart deaktivieren",
            (
                "Die Aufgabenbeschreibung nennt nicht, welcher Autostart-Eintrag "
                "deaktiviert werden soll. Deshalb keine pauschale Windows-Startup-Pruefung."
            ),
            "Aufgabenliste",
        )

        # --------------------------------------------------------------
        # IPC0139 - WinCC OPC Server.
        # Titel und Setup-Pfad nennen unterschiedliche Versionsstaende.
        # expected_installed=null bedeutet daher bewusst IGNORIERT, bis
        # der autoritative Sollwert in Semaphore festgelegt wurde.
        # --------------------------------------------------------------
        wincc_opc_expected = as_dict(software_expected.get("wincc_opc_server"))
        wincc_opc_required = bool_value(wincc_opc_expected.get("expected_installed"))
        if wincc_opc_required is None:
            checks["IPC0139"] = make_ignored(
                "IPC0139",
                "WinCC OPCServer",
                (
                    "Versionsangabe in Titel und Setup-Pfad ist widerspruechlich. "
                    "Setze software.wincc_opc_server.expected_installed und "
                    "version_regex erst nach Festlegung des gueltigen Sollwertes."
                ),
                "Semaphore: software.wincc_opc_server",
            )
        else:
            ipc0139_state, ipc0139_evidence = evaluate_software_requirement(
                products,
                wincc_opc_expected,
            )
            checks["IPC0139"] = make_check(
                "IPC0139",
                "WinCC OPCServer",
                ipc0139_state,
                {
                    "ExpectedInstalled": wincc_opc_required,
                    "NameRegex": wincc_opc_expected.get("name_regex"),
                    "VersionRegex": wincc_opc_expected.get("version_regex"),
                },
                ipc0139_evidence,
                "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts",
            )

        # --------------------------------------------------------------
        # IPC0140 - ORCLA installiert.
        # --------------------------------------------------------------
        orcla_expected = as_dict(software_expected.get("orcla"))
        orcla_required = bool_value(orcla_expected.get("expected_installed"))
        orcla_state, orcla_evidence = evaluate_software_requirement(
            products,
            orcla_expected,
        )
        if orcla_required is None:
            checks["IPC0140"] = make_ignored(
                "IPC0140",
                "ORCLA installieren",
                "ORCLA-Sollwert ist in Semaphore nicht aktiviert.",
                "Semaphore: software.orcla",
            )
            orcla_present = False
        else:
            checks["IPC0140"] = make_check(
                "IPC0140",
                "ORCLA installieren",
                orcla_state,
                {
                    "ExpectedInstalled": orcla_required,
                    "NameRegex": orcla_expected.get("name_regex"),
                },
                orcla_evidence,
                "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts",
            )
            if products is None:
                orcla_present = None
            else:
                orcla_present = bool(
                    product_regex_matches(products, orcla_expected.get("name_regex"))
                )

        # --------------------------------------------------------------
        # IPC0141 - Maintenance-Funktionen fuer OS.
        # Diese Funktionen muessen nicht zwingend als eigener Uninstall-
        # Eintrag erscheinen. Deshalb Produkt- und PCS7-Setup-Log-Evidenz.
        # Fehlt belastbare Evidenz, wird nicht faelschlich NOK erzeugt.
        # --------------------------------------------------------------
        maintenance_expected = as_dict(orcla_expected.get("maintenance_functions"))
        maintenance_required = bool_value(maintenance_expected.get("expected_installed"))
        maintenance_regex = text(maintenance_expected.get("evidence_regex"))
        if orcla_present is False:
            checks["IPC0141"] = make_ignored(
                "IPC0141",
                "Maintenance Funktionen fuer OS installieren",
                "Nur relevant, wenn ORCLA auf diesem ES installiert ist.",
                "IPC0140",
            )
        elif orcla_present is None:
            checks["IPC0141"] = make_check(
                "IPC0141",
                "Maintenance Funktionen fuer OS installieren",
                None,
                {"Prerequisite": "IPC0140 muss bestimmbar/erfüllt sein"},
                None,
                "IPC0140",
                "ORCLA-Installationszustand ist nicht belastbar bestimmbar.",
            )
        elif maintenance_required is None:
            checks["IPC0141"] = make_ignored(
                "IPC0141",
                "Maintenance Funktionen fuer OS installieren",
                "Maintenance-Sollwert ist in Semaphore nicht aktiviert.",
                "Semaphore: software.orcla.maintenance_functions",
            )
        else:
            maintenance_products = product_regex_matches(products, maintenance_regex)
            maintenance_log_hits = [
                text(x)
                for x in as_list(as_dict(setup_log_evidence).get("Highlights"))
                if regex_match(maintenance_regex, x)
            ]
            maintenance_found = bool(maintenance_products or maintenance_log_hits)
            if maintenance_required is False:
                maintenance_state = not maintenance_found
            elif maintenance_found:
                maintenance_state = True
            else:
                maintenance_state = None
            checks["IPC0141"] = make_check(
                "IPC0141",
                "Maintenance Funktionen fuer OS installieren",
                maintenance_state,
                {
                    "ExpectedInstalled": maintenance_required,
                    "EvidenceRegex": maintenance_regex,
                },
                {
                    "ProductMatches": maintenance_products,
                    "SetupLogMatches": maintenance_log_hits[:50],
                },
                (
                    "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts + "
                    "Software_PCS7_Components_Valid.PCS7SetupLogEvidence"
                ),
                (
                    "Fehlende Evidenz ergibt NICHT_PRUEFBAR statt NOK, weil die "
                    "Rahmensetup-Funktion nicht zwingend als separates Produkt registriert wird."
                ),
            )

        # --------------------------------------------------------------
        # IPC0142 - ORCLA Watchdog + OPC UA Server.
        # OPC-UA-Server ist als Windows-Dienst belastbar pruefbar.
        # Watchdog wird nur OK bewertet, wenn ein eindeutiger Dienst-
        # indikator vorhanden ist; andernfalls NICHT_PRUEFBAR.
        # --------------------------------------------------------------
        if orcla_present is False:
            checks["IPC0142"] = make_ignored(
                "IPC0142",
                "Watchdog und OPC UA Server",
                "Nur relevant, wenn ORCLA auf diesem ES installiert ist.",
                "IPC0140",
            )
        elif orcla_present is None:
            checks["IPC0142"] = make_check(
                "IPC0142",
                "Watchdog und OPC UA Server",
                None,
                {"Prerequisite": "IPC0140 muss bestimmbar/erfüllt sein"},
                None,
                "IPC0140",
                "ORCLA-Installationszustand ist nicht belastbar bestimmbar.",
            )
        else:
            all_services = service_records(services_snapshot)
            opc_service_name = text(orcla_expected.get("opcua_service_name"))
            watchdog_regex = text(orcla_expected.get("watchdog_service_regex"))
            opc_services = [
                service for service in all_services
                if text(service.get("Name")).lower() == opc_service_name.lower()
            ]
            watchdog_services = [
                service for service in all_services
                if regex_match(
                    watchdog_regex,
                    " ".join([
                        text(service.get("Name")),
                        text(service.get("DisplayName")),
                        text(service.get("PathName")),
                    ]),
                )
            ]
            opc_running = bool(opc_services) and all(
                text(service.get("State")).lower() == "running"
                for service in opc_services
            )
            watchdog_known = bool(watchdog_services)
            watchdog_running = watchdog_known and all(
                text(service.get("State")).lower() == "running"
                for service in watchdog_services
            )
            if not isinstance(services_snapshot, dict) or not all_services:
                ipc0142_state = None
            elif not opc_running:
                ipc0142_state = False
            elif watchdog_known:
                ipc0142_state = watchdog_running
            else:
                ipc0142_state = None
            checks["IPC0142"] = make_check(
                "IPC0142",
                "Watchdog und OPC UA server",
                ipc0142_state,
                {
                    "OpcUaServerService": {"Name": opc_service_name, "State": "Running"},
                    "Watchdog": "aktiviert",
                },
                {
                    "OpcUaServices": opc_services,
                    "WatchdogServiceCandidates": watchdog_services,
                },
                "Certificates_Services_Drivers_Valid.Services",
                (
                    "Der OPC-UA-Dienst ist eindeutig pruefbar. Wenn Watchdog keinen "
                    "separaten Service-Indikator liefert, bleibt die Gesamtpruefung "
                    "NICHT_PRUEFBAR statt den Zustand zu erraten."
                ),
            )

        # --------------------------------------------------------------
        # IPC0147 - Enable_Ansible_Access.ps1 / erreichbarer Endzustand.
        # Der historische Skriptaufruf selbst ist nicht beweisbar; bewertet
        # wird der aktuelle Ansible-/WinRM-Zugriff aus der Bibliothek.
        # --------------------------------------------------------------
        access_state = as_dict(host.get("zugriff"))
        ipc0147_state = (
            bool(access_state.get("ansible_access"))
            if access_state and "ansible_access" in access_state
            else None
        )
        checks["IPC0147"] = make_check(
            "IPC0147",
            "Zugriffsskript Enable_Ansible_Access.ps1",
            ipc0147_state,
            {"AnsibleAccess": True},
            access_state if access_state else None,
            "0150.zugriff",
            (
                "Geprueft wird der aktuelle erreichbare Endzustand. Der historische "
                "Aufruf des Skripts selbst kann nachtraeglich nicht bewiesen werden."
            ),
        )

        # --------------------------------------------------------------
        # IPC0149 - Windows-Funktionen.
        # Keine projektspezifische Sollwertliste mehr. Es werden immer
        # alle aktuell aktiven Windows-Funktionen dokumentiert.
        # --------------------------------------------------------------
        hardening_expected = as_dict(expected.get("hardening"))
        feature_rows = windows_feature_rows(windows_components)
        active_features = [
            row
            for row in feature_rows
            if row.get("Enabled") is True
        ]
        information["IPC0149"] = make_information(
            "IPC0149",
            "Deinstallieren von Windows-Komponenten",
            active_features if isinstance(windows_components, dict) else None,
            "Initial_Valid.WindowsComponents",
            (
                "Reine Informationsausgabe aller aktuell aktiven Windows-Funktionen; "
                "kein Sollwertvergleich."
            ),
        )

        # --------------------------------------------------------------
        # IPC0150 - BitLocker auf dem Systemlaufwerk.
        # --------------------------------------------------------------
        bitlocker_expected = as_dict(
            as_dict(hardening_expected.get("bitlocker")).get("system_drive")
        )
        expected_bitlocker_enabled = bool_value(
            bitlocker_expected.get("expected_enabled")
        )
        minimum_encryption = int_value(
            bitlocker_expected.get("minimum_encryption_percentage")
        )
        system_drive = normalize_drive_letter(
            as_dict(as_dict(expected.get("storage")).get("system_drive")).get("letter")
        )
        bitlocker_rows = as_list(as_dict(initial_best_practice).get("BitLocker"))
        system_bitlocker = [
            row
            for row in bitlocker_rows
            if isinstance(row, dict)
            and normalize_drive_letter(row.get("MountPoint")) == system_drive
        ]

        bitlocker_state = None
        if system_bitlocker:
            protection_states = [
                bool_value(row.get("ProtectionStatus"))
                for row in system_bitlocker
            ]
            encryption_values = [
                int_value(row.get("EncryptionPercentage"))
                for row in system_bitlocker
            ]
            if expected_bitlocker_enabled is True:
                bitlocker_state = any(
                    protection is True
                    and encryption is not None
                    and minimum_encryption is not None
                    and encryption >= minimum_encryption
                    for protection, encryption in zip(
                        protection_states,
                        encryption_values,
                    )
                )
            elif expected_bitlocker_enabled is False:
                known_protection_states = [
                    protection
                    for protection in protection_states
                    if protection is not None
                ]
                bitlocker_state = (
                    all(protection is False for protection in known_protection_states)
                    if known_protection_states
                    else None
                )

        checks["IPC0150"] = make_check(
            "IPC0150",
            "BitLocker Aktivierung",
            bitlocker_state,
            {
                "Drive": system_drive,
                "ExpectedEnabled": expected_bitlocker_enabled,
                "MinimumEncryptionPercentage": minimum_encryption,
            },
            system_bitlocker if system_bitlocker else bitlocker_rows,
            "Initial_Valid.InstallationBestPractice.BitLocker",
        )

        # --------------------------------------------------------------
        # IPC0151 - PCS-7-System-Hardening-Dienste.
        # Ein nicht vorhandener Dienst ist ebenfalls compliant; ein
        # vorhandener Dienst muss StartClassification=Disabled haben.
        # --------------------------------------------------------------
        service_requirements = as_list(
            as_dict(hardening_expected.get("services")).get("disabled")
        )
        all_services = service_records(services_snapshot)
        if not isinstance(services_snapshot, dict) or not all_services:
            service_state = None
            service_details = None
        else:
            service_details = []
            service_states = []
            for requirement in service_requirements:
                req = as_dict(requirement)
                pattern = text(req.get("name_regex"))
                matching = []
                for service in all_services:
                    searchable = " ".join([
                        text(service.get("Name")),
                        text(service.get("DisplayName")),
                    ])
                    if regex_match(pattern, searchable):
                        matching.append(service)

                compliant = (
                    not matching
                    or all(
                        text(service.get("StartClassification") or service.get("StartMode")).lower()
                        == "disabled"
                        for service in matching
                    )
                )
                service_states.append(compliant)
                service_details.append({
                    "Description": req.get("description"),
                    "NameRegex": pattern,
                    "Found": bool(matching),
                    "MatchingServices": [
                        {
                            "Name": service.get("Name"),
                            "DisplayName": service.get("DisplayName"),
                            "State": service.get("State"),
                            "StartMode": service.get("StartMode"),
                            "StartClassification": service.get("StartClassification"),
                        }
                        for service in matching
                    ],
                    "Compliant": compliant,
                })
            service_state = all(service_states) if service_states else None

        checks["IPC0151"] = make_check(
            "IPC0151",
            "Deaktivieren von Diensten",
            service_state,
            {"DisabledServices": service_requirements},
            service_details,
            "Certificates_Services_Drivers_Valid.Services",
            (
                "Nicht installierte Dienste gelten als compliant. Vorhandene Dienste "
                "muessen auf Starttyp Disabled stehen."
            ),
        )

        # --------------------------------------------------------------
        # IPC0153 - Telemetrie 0.
        # --------------------------------------------------------------
        telemetry_expected = int_value(
            as_dict(hardening_expected.get("telemetry")).get("allowed_level")
        )
        telemetry_records = as_list(as_dict(policy_areas).get("Telemetry"))
        telemetry_value, telemetry_row = first_registry_value(
            telemetry_records,
            name="AllowTelemetry",
        )
        if telemetry_value is None:
            telemetry_value, telemetry_row = first_registry_value(
                telemetry_records,
                name="AllowDiagnosticData",
            )

        checks["IPC0153"] = make_check(
            "IPC0153",
            "Einstellung von Datenschutz- und Telemetriedaten in Windows 10 Teil 2",
            (
                None
                if telemetry_value is None
                else int_value(telemetry_value) == telemetry_expected
            ),
            {"AllowTelemetryOrDiagnosticData": telemetry_expected},
            telemetry_row,
            "GPOs_Valid.PolicyAreaSnapshots.Telemetry",
        )

        # --------------------------------------------------------------
        # IPC0154 / IPC0155 - SMB Signierung und SMBv3-Verschluesselung.
        # --------------------------------------------------------------
        smb_dict = as_dict(smb)
        server_cfg = as_dict(smb_dict.get("ServerConfiguration"))
        client_cfg = as_dict(smb_dict.get("ClientConfiguration"))
        effective_registry = as_dict(smb_dict.get("EffectiveRegistry"))
        server_registry = as_dict(effective_registry.get("Server"))
        client_registry = as_dict(effective_registry.get("Client"))

        smb_signing_expected = as_dict(
            as_dict(hardening_expected.get("smb")).get("signing")
        )
        client_require = bool_value(
            smb_configuration_value(
                client_cfg,
                client_registry,
                "RequireSecuritySignature",
            )
        )
        server_require = bool_value(
            smb_configuration_value(
                server_cfg,
                server_registry,
                "RequireSecuritySignature",
            )
        )
        server_enable = bool_value(
            smb_configuration_value(
                server_cfg,
                server_registry,
                "EnableSecuritySignature",
            )
        )

        ipc0154_requirements = [
            (
                None
                if client_require is None
                else client_require
                == bool_value(smb_signing_expected.get("client_require_security_signature"))
            ),
            (
                None
                if server_require is None
                else server_require
                == bool_value(smb_signing_expected.get("server_require_security_signature"))
            ),
            (
                None
                if server_enable is None
                else server_enable
                == bool_value(smb_signing_expected.get("server_enable_security_signature"))
            ),
        ]
        checks["IPC0154"] = make_check(
            "IPC0154",
            "SMB Signierung",
            evaluate_boolean_requirements(ipc0154_requirements),
            smb_signing_expected,
            {
                "ClientRequireSecuritySignature": client_require,
                "ServerRequireSecuritySignature": server_require,
                "ServerEnableSecuritySignature": server_enable,
            },
            "Firewall_SMB_Patch_Valid.SMB",
        )

        smb_encryption_expected = bool_value(
            as_dict(as_dict(hardening_expected.get("smb")).get("encryption")).get(
                "server_encrypt_data"
            )
        )
        server_encrypt_data = bool_value(
            smb_configuration_value(
                server_cfg,
                server_registry,
                "EncryptData",
            )
        )
        checks["IPC0155"] = make_check(
            "IPC0155",
            "SMBv3-Verschlüsselung",
            (
                None
                if server_encrypt_data is None
                else server_encrypt_data == smb_encryption_expected
            ),
            {"ServerEncryptData": smb_encryption_expected},
            {"ServerEncryptData": server_encrypt_data},
            "Firewall_SMB_Patch_Valid.SMB.ServerConfiguration",
        )

        # --------------------------------------------------------------
        # IPC0156 - Remote Desktop deaktiviert.
        # --------------------------------------------------------------
        effective_values = as_list(as_dict(effective_policy).get("Values"))
        terminal_service_policy = as_list(as_dict(policy_areas).get("TerminalServices"))
        rdp_value, rdp_row = first_registry_value(
            effective_values,
            name="fDenyTSConnections",
        )
        if rdp_value is None:
            rdp_value, rdp_row = first_registry_value(
                terminal_service_policy,
                name="fDenyTSConnections",
            )

        allow_remote = bool_value(
            as_dict(hardening_expected.get("rdp")).get("allow_remote_connections")
        )
        expected_fdeny = 0 if allow_remote is True else 1
        checks["IPC0156"] = make_check(
            "IPC0156",
            "Remote Desktop Security Einstellung",
            (
                None
                if rdp_value is None
                else int_value(rdp_value) == expected_fdeny
            ),
            {
                "AllowRemoteConnections": allow_remote,
                "fDenyTSConnections": expected_fdeny,
            },
            rdp_row,
            (
                "GPOs_Valid.InstallationRelevantEffectiveSettings + "
                "GPOs_Valid.PolicyAreaSnapshots.TerminalServices"
            ),
        )

        # --------------------------------------------------------------
        # IPC0159 - SSL/TLS-Protokolle.
        # --------------------------------------------------------------
        tls_expected = as_dict(hardening_expected.get("tls"))
        ipc0159_state, ipc0159_details = check_schannel_protocols(
            effective_values,
            tls_expected.get("protocols"),
        )
        checks["IPC0159"] = make_check(
            "IPC0159",
            "Deaktivierung von veralteten SSL-/TLS-Kommunikationsverfahren",
            ipc0159_state,
            tls_expected.get("protocols"),
            ipc0159_details,
            "GPOs_Valid.InstallationRelevantEffectiveSettings.Values (SCHANNEL)",
        )

        # --------------------------------------------------------------
        # IPC0162 - ALM Remote-Verbindungen.
        # Collector liefert nur heuristische Siemens-Registry-Evidenz,
        # aber keinen stabil normalisierten booleschen ALM-Schalter.
        # --------------------------------------------------------------
        checks["IPC0162"] = make_ignored(
            "IPC0162",
            "Parametrierung des ALM als Lizenzserver",
            (
                "Der vorhandene Collector erkennt ALM-Produkte und relevante "
                "Registry-Evidenz, aber keinen belastbar normalisierten Wert fuer "
                "'Verbindungen von remote erlauben'. Entsprechend der Vorgabe "
                "'falls moeglich ansonsten ignorieren' wird kein OK/NOK erfunden."
            ),
            "Software_PCS7_Components_Valid.AutomationLicenseManagerEvidence",
        )

        # --------------------------------------------------------------
        # IPC0165 - Security Controller.
        # Benutzerfreigabe: Wenn der Rechner Domain-Mitglied ist UND
        # Security-Controller-Ausfuehrung/Evidenz erkennbar ist, gilt der
        # Schritt als OK.
        # --------------------------------------------------------------
        security_controller_evidence = []

        if isinstance(setup_log_evidence, dict):
            for value in as_list(setup_log_evidence.get("Highlights")):
                if regex_match(r"(?i)Security[\s_-]*Controller", value):
                    security_controller_evidence.append({
                        "Source": "PCS7SetupLogEvidence",
                        "Value": value,
                    })

        if isinstance(siemens_registry_evidence, dict):
            for row in as_list(siemens_registry_evidence.get("Evidence")):
                if not isinstance(row, dict):
                    continue
                searchable = " ".join([
                    text(row.get("Path")),
                    text(row.get("ValueName")),
                    text(row.get("Value")),
                ])
                if regex_match(r"(?i)Security[\s_-]*Controller", searchable):
                    security_controller_evidence.append({
                        "Source": "SiemensRegistryEvidence",
                        "Value": row,
                    })

        ipc0165_domain = bool_value(as_dict(domain_info).get("PartOfDomain"))
        if ipc0165_domain is False:
            ipc0165_state = False
        elif ipc0165_domain is True and security_controller_evidence:
            ipc0165_state = True
        else:
            ipc0165_state = None

        checks["IPC0165"] = make_check(
            "IPC0165",
            "Security Controller",
            ipc0165_state,
            {
                "PartOfDomain": True,
                "SecurityControllerExecutedOrDetected": True,
            },
            {
                "DomainInformation": domain_info,
                "SecurityControllerEvidence": security_controller_evidence,
            },
            (
                "Initial_Valid.DomainInformation + "
                "Software_PCS7_Components_Valid.PCS7SetupLogEvidence/"
                "SiemensRegistryEvidence"
            ),
            (
                "OK bedeutet: Domaenenmitgliedschaft plus vorhandene "
                "Security-Controller-Evidenz. Ohne Evidenz bleibt der Schritt "
                "NICHT_PRUEFBAR."
            ),
        )

        # --------------------------------------------------------------
        # IPC0166 - Firewall alle Profile aktiv + aktive Netzwerke Privat.
        # --------------------------------------------------------------
        firewall_expected = as_dict(hardening_expected.get("firewall"))
        required_firewall_profiles = [
            text(value)
            for value in as_list(firewall_expected.get("required_profiles_enabled"))
            if text(value)
        ]
        wanted_network_category = text(
            firewall_expected.get("active_network_category")
        )

        fw_profiles = as_list(as_dict(firewall).get("Profiles"))
        active_network_profiles = as_list(
            as_dict(firewall).get("ActiveNetworkProfiles")
        )
        ipc0166_state = None
        if isinstance(firewall, dict) and fw_profiles:
            profile_details = []
            profile_states = []
            for wanted_profile in required_firewall_profiles:
                matches = [
                    profile
                    for profile in fw_profiles
                    if isinstance(profile, dict)
                    and text(profile.get("Name")).lower() == wanted_profile.lower()
                ]
                if not matches:
                    profile_states.append(False)
                else:
                    profile_states.append(
                        all(bool_value(profile.get("Enabled")) is True for profile in matches)
                    )
                profile_details.append({
                    "Profile": wanted_profile,
                    "Matches": matches,
                })

            if active_network_profiles:
                network_private = all(
                    text(profile.get("NetworkCategory")).lower()
                    == wanted_network_category.lower()
                    for profile in active_network_profiles
                    if isinstance(profile, dict)
                )
            else:
                network_private = None

            ipc0166_state = evaluate_boolean_requirements(
                profile_states + [network_private]
            )
        else:
            profile_details = None
            network_private = None

        checks["IPC0166"] = make_check(
            "IPC0166",
            "Windows-Firewall",
            ipc0166_state,
            {
                "RequiredProfilesEnabled": required_firewall_profiles,
                "ActiveNetworkCategory": wanted_network_category,
            },
            {
                "FirewallProfiles": fw_profiles,
                "ActiveNetworkProfiles": active_network_profiles,
                "ProfileEvaluation": profile_details,
                "ActiveNetworksCompliant": network_private,
            } if isinstance(firewall, dict) else None,
            "Firewall_SMB_Patch_Valid.Firewall",
        )

        # --------------------------------------------------------------
        # IPC0168 - D:\Projekt als SMB-Freigabe inkl. Share- und NTFS-ACL.
        # --------------------------------------------------------------
        filesystem_expected = as_dict(expected.get("filesystem"))
        project_share_expected = as_dict(filesystem_expected.get("project_share"))
        ipc0168_state, ipc0168_evidence = project_share_evaluation(
            smb,
            project_share_expected,
        )
        checks["IPC0168"] = make_check(
            "IPC0168",
            "Ordner D:\\Projekt freigeben",
            ipc0168_state,
            project_share_expected,
            ipc0168_evidence,
            "Firewall_SMB_Patch_Valid.SMB.Shares + NtfsRootAcl",
            (
                "Geprueft werden die geforderten Berechtigungen mindestens. "
                "Zusaetzliche geerbte Standard-ACEs fuehren nicht automatisch zu NOK."
            ),
        )

        # --------------------------------------------------------------
        # Softwarepruefungen IPC0171/0177/0179/0180.
        # --------------------------------------------------------------
        software_tasks = [
            ("IPC0171", "PDF-XChange Editor V10", "pdf_xchange_editor"),
            ("IPC0177", "Greenshot installieren", "greenshot"),
            ("IPC0179", "WinSCP", "winscp"),
            ("IPC0180", "SQL Server Management Studio", "ssms"),
        ]
        for task_id, task_name, config_key in software_tasks:
            spec = as_dict(software_expected.get(config_key))
            required = bool_value(spec.get("expected_installed"))
            if required is None:
                checks[task_id] = make_ignored(
                    task_id,
                    task_name,
                    "Software-Sollwert ist in Semaphore nicht aktiviert.",
                    f"Semaphore: software.{config_key}",
                )
                continue

            state, evidence = evaluate_package_spec(
                component_detection,
                products,
                spec,
            )
            note = None
            if task_id == "IPC0171":
                note = (
                    "Zusaetzlich wird geprueft, dass kein separat registrierter "
                    "PDF-XChange-Updater gefunden wird. Desktop-Icon und Browser-"
                    "Integration werden vom aktuellen Collector nicht belastbar normalisiert."
                )
            elif task_id == "IPC0177":
                note = (
                    "Sprache, Lizenzdialog und 'Kompakte Installation' sind "
                    "Installationsvorgaenge und werden nicht aus dem Endzustand erfunden."
                )
            elif task_id == "IPC0179":
                note = (
                    "Installierte Version wird geprueft. Die Commander-Oberflaeche "
                    "ist benutzerspezifische WinSCP-Konfiguration und wird in diesem "
                    "Snapshot nicht automatisch als OK/NOK bewertet."
                )

            checks[task_id] = make_check(
                task_id,
                task_name,
                state,
                {
                    "ExpectedInstalled": required,
                    "NameRegex": spec.get("name_regex"),
                    "VersionRegex": spec.get("version_regex"),
                    "ForbiddenNameRegexes": as_list(spec.get("forbidden_name_regexes")),
                },
                evidence,
                "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts",
                note,
            )

        # --------------------------------------------------------------
        # IPC0187 - VNC-Firewallregel nur bei Workgroup-Rechnern.
        # --------------------------------------------------------------
        part_of_domain = bool_value(as_dict(domain_info).get("PartOfDomain"))
        if part_of_domain is True:
            checks["IPC0187"] = make_ignored(
                "IPC0187",
                "VNC-Firewallregel fuer Arbeitsgruppe",
                "Nur relevant, wenn der Rechner keiner Domaene angehoert.",
                "Initial_Valid.DomainInformation",
            )
        elif part_of_domain is None:
            checks["IPC0187"] = make_check(
                "IPC0187",
                "VNC-Firewallregel fuer Arbeitsgruppe",
                None,
                {"Profiles": ["Domain", "Private", "Public"]},
                None,
                "Initial_Valid.DomainInformation + Firewall_SMB_Patch_Valid.Firewall",
            )
        else:
            fw_rules = [
                row for row in as_list(as_dict(firewall).get("Rules"))
                if isinstance(row, dict)
            ]
            candidates = []
            for rule in fw_rules:
                searchable = " ".join([
                    text(rule.get("Name")),
                    text(rule.get("DisplayName")),
                    text(rule.get("DisplayGroup")),
                    text(rule.get("Description")),
                ])
                if not regex_match(r"(?i)VNC", searchable):
                    continue
                if text(rule.get("Enabled")).lower() not in {"true", "1"}:
                    continue
                if text(rule.get("Direction")).lower() != "inbound":
                    continue
                if text(rule.get("Action")).lower() != "allow":
                    continue

                profile_text = text(rule.get("Profile"))
                normalized_profiles = profile_text.lower()
                all_profiles = (
                    normalized_profiles in {"any", "all"}
                    or all(
                        profile.lower() in normalized_profiles
                        for profile in ("Domain", "Private", "Public")
                    )
                )
                if all_profiles:
                    candidates.append(rule)

            checks["IPC0187"] = make_check(
                "IPC0187",
                "VNC-Firewallregel fuer Arbeitsgruppe",
                bool(candidates) if isinstance(firewall, dict) else None,
                {
                    "DomainMember": False,
                    "VncInboundAllow": True,
                    "Profiles": ["Domain", "Private", "Public"],
                },
                candidates,
                "Firewall_SMB_Patch_Valid.Firewall.Rules",
            )

        # --------------------------------------------------------------
        # IPC0189 - Arbeitsgruppe nur bei nicht-domainjoined ES.
        # --------------------------------------------------------------
        workgroup_expected = text(
            as_dict(expected.get("workgroup")).get("expected_name")
        )
        if part_of_domain is True:
            checks["IPC0189"] = make_ignored(
                "IPC0189",
                "Arbeitsgruppe einstellen",
                "Nur relevant, wenn der Rechner keiner Domaene angehoert.",
                "Initial_Valid.DomainInformation",
            )
        elif isinstance(domain_info, dict):
            actual_workgroup = text(domain_info.get("Workgroup"))
            checks["IPC0189"] = make_check(
                "IPC0189",
                "Arbeitsgruppe einstellen",
                actual_workgroup.lower() == workgroup_expected.lower(),
                {"Workgroup": workgroup_expected},
                {"Workgroup": actual_workgroup},
                "Initial_Valid.DomainInformation",
            )
        else:
            checks["IPC0189"] = make_check(
                "IPC0189",
                "Arbeitsgruppe einstellen",
                None,
                {"Workgroup": workgroup_expected},
                None,
                "Initial_Valid.DomainInformation",
            )

        # --------------------------------------------------------------
        # IPC0190 - VNC-Verbindung neu starten.
        # Der Neustart ist ein historischer Vorgang. Als belastbare
        # Endzustands-Evidenz wird der aktuelle UltraVNC-Dienstzustand
        # dokumentiert.
        # --------------------------------------------------------------
        vnc_runtime_services = find_services(
            services,
            r"(?i)UltraVNC|uvnc|winvnc",
        )
        information["IPC0190"] = make_information(
            "IPC0190",
            "VNC Verbindung",
            vnc_runtime_services if isinstance(services_snapshot, dict) else None,
            "Certificates_Services_Drivers_Valid.Services",
            (
                "Der historische Neustart ist nicht beweisbar. Dokumentiert wird "
                "der aktuelle UltraVNC-Dienstzustand."
            ),
        )

        # --------------------------------------------------------------
        # IPC0191 - Admin_L nur bei Workgroup-Rechnern.
        # --------------------------------------------------------------
        if part_of_domain is True:
            checks["IPC0191"] = make_ignored(
                "IPC0191",
                "Lokalen Administrator umbenennen",
                "Nur relevant, wenn der Rechner keiner Domaene angehoert.",
                "Initial_Valid.DomainInformation",
            )
        elif isinstance(local_users, list):
            admin_l_matches = [
                user for user in local_users
                if isinstance(user, dict)
                and text(user.get("Name")).lower() == "admin_l"
            ]
            checks["IPC0191"] = make_check(
                "IPC0191",
                "Lokalen Administrator umbenennen",
                bool(admin_l_matches),
                {"LocalUser": "Admin_L"},
                admin_l_matches,
                "Initial_Valid.LocalUsers",
            )
        else:
            checks["IPC0191"] = make_check(
                "IPC0191",
                "Lokalen Administrator umbenennen",
                None,
                {"LocalUser": "Admin_L"},
                None,
                "Initial_Valid.LocalUsers",
            )

        # --------------------------------------------------------------
        # IPC0202 / IPC0203 - SIMATIC Logon.
        # --------------------------------------------------------------
        simatic_logon_expected = as_dict(software_expected.get("simatic_logon"))
        simatic_logon_required = bool_value(
            simatic_logon_expected.get("expected_installed")
        )
        base_matches = find_products(
            products,
            simatic_logon_expected.get("name_regex"),
            simatic_logon_expected.get("base_version_regex"),
        )
        if simatic_logon_required is None:
            checks["IPC0202"] = make_ignored(
                "IPC0202",
                "SIMATIC Logon installieren",
                "Software-Sollwert ist in Semaphore nicht aktiviert.",
                "Semaphore: software.simatic_logon",
            )
        else:
            base_state = (
                bool(base_matches)
                if simatic_logon_required is True
                else not bool(find_products(products, simatic_logon_expected.get("name_regex")))
            )
            checks["IPC0202"] = make_check(
                "IPC0202",
                "SIMATIC Logon installieren",
                base_state if products is not None else None,
                {
                    "ExpectedInstalled": simatic_logon_required,
                    "VersionBranch": "2.0",
                },
                base_matches,
                "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts",
            )

        update1_by_name = find_products(
            products,
            simatic_logon_expected.get("update1_name_regex"),
        )
        update1_by_version = find_products(
            products,
            simatic_logon_expected.get("name_regex"),
            simatic_logon_expected.get("update1_version_regex"),
        )
        update1_matches = update1_by_name + [
            item for item in update1_by_version
            if item not in update1_by_name
        ]
        if simatic_logon_required is None:
            checks["IPC0203"] = make_ignored(
                "IPC0203",
                "SIMATIC Logon aktualisieren",
                "Software-Sollwert ist in Semaphore nicht aktiviert.",
                "Semaphore: software.simatic_logon",
            )
        else:
            checks["IPC0203"] = make_check(
                "IPC0203",
                "SIMATIC Logon aktualisieren",
                (
                    bool(update1_matches)
                    if simatic_logon_required is True and products is not None
                    else (None if products is None else not bool(update1_matches))
                ),
                {
                    "ExpectedInstalled": simatic_logon_required,
                    "RequiredUpdate": "V2.0 Update 1",
                },
                update1_matches,
                "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts",
            )

        # IPC0204 - SIMATIC Logon konfigurieren.
        # Benutzerfreigabe: Fuer die automatische Bewertung reicht der
        # Nachweis, dass SIMATIC Logon installiert/verwendet wird.
        # Die konkrete GUI-Einstellung bleibt als Hinweis nicht pruefbar.
        simatic_logon_registry_matches = []
        if isinstance(siemens_registry_evidence, dict):
            for row in as_list(siemens_registry_evidence.get("Evidence")):
                if not isinstance(row, dict):
                    continue
                searchable = " ".join([
                    text(row.get("Path")),
                    text(row.get("ValueName")),
                    text(row.get("Value")),
                ])
                if regex_match(
                    r"(?i)(SIMATIC.*Logon|Logon.*SIMATIC|Automatic.*Log|Auto.*Log)",
                    searchable,
                ):
                    simatic_logon_registry_matches.append(row)

        simatic_logon_any_matches = find_products(
            products,
            simatic_logon_expected.get("name_regex"),
        )
        if simatic_logon_any_matches or simatic_logon_registry_matches:
            ipc0204_state = True
        elif products is not None:
            ipc0204_state = False
        else:
            ipc0204_state = None

        checks["IPC0204"] = make_check(
            "IPC0204",
            "SIMATIC Logon konfigurieren - automatisches Abmelden deaktivieren",
            ipc0204_state,
            {
                "SimaticLogonInstalledOrDetected": True,
                "GuiAutomaticLogoffSetting": "NICHT_PRUEFBAR",
            },
            {
                "InstalledSoftware": simatic_logon_any_matches,
                "RegistryEvidence": simatic_logon_registry_matches,
            },
            (
                "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts + "
                "SiemensRegistryEvidence"
            ),
            "GUI Einstellungen nicht Pruefbar.",
        )

        # --------------------------------------------------------------
        # IPC0205 - PM-Logon V2.6 Update 4.
        # --------------------------------------------------------------
        pm_expected = as_dict(software_expected.get("pm_logon"))
        pm_required = bool_value(pm_expected.get("expected_installed"))
        pm_state, pm_evidence = evaluate_software_requirement(
            products,
            {
                "expected_installed": pm_required,
                "name_regex": pm_expected.get("name_regex"),
                "version_regex": pm_expected.get("version_regex"),
            },
        )
        hostname = text(as_dict(identity).get("ComputerName"))
        configurator_required = any(
            regex_match(pattern, hostname)
            for pattern in as_list(pm_expected.get("configurator_required_hostname_regexes"))
        )
        configurator_matches = product_regex_matches(
            products,
            pm_expected.get("configurator_name_regex"),
        )
        if pm_state is True and configurator_required and not configurator_matches:
            # Da der Konfigurator nicht zwingend ein separater Uninstall-Eintrag
            # sein muss, bleibt der Gesamtzustand NICHT_PRUEFBAR statt NOK.
            pm_state = None

        checks["IPC0205"] = make_check(
            "IPC0205",
            "PM-Logon V2.6 Update 4 installieren",
            pm_state,
            {
                "ExpectedInstalled": pm_required,
                "Version": "2.6 Update 4",
                "ConfiguratorRequiredForHost": configurator_required,
            },
            {
                "SoftwareEvidence": pm_evidence,
                "ConfiguratorMatches": configurator_matches,
            },
            "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts",
            (
                "Runtime/Version werden bewertet. Falls der Hostname auf ES02 passt, "
                "wird nach separater Konfigurator-Evidenz gesucht; fehlt diese, wird "
                "nicht faelschlich NOK erzeugt."
            ),
        )

        pm_prerequisite_ok = checks["IPC0205"].get("status") == "OK"
        if simatic_logon_any_matches or simatic_logon_registry_matches:
            simatic_logon_for_pm = True
        elif products is not None:
            simatic_logon_for_pm = False
        else:
            simatic_logon_for_pm = None

        if not pm_prerequisite_ok:
            for task_id, task_name in (
                ("IPC0207", "PM-Logon RT Konfiguration"),
                ("IPC0208", "PM-Logon Konfiguration verteilen"),
                ("IPC0209", "PM-Logon Konfiguration anpassen"),
            ):
                checks[task_id] = make_ignored(
                    task_id,
                    task_name,
                    "Nur relevant, wenn IPC0205 erfolgreich ist.",
                    "IPC0205",
                )
        else:
            for task_id, task_name in (
                ("IPC0207", "PM-Logon RT Konfiguration"),
                ("IPC0208", "PM-Logon Konfiguration verteilen"),
                ("IPC0209", "PM-Logon Konfiguration anpassen"),
            ):
                checks[task_id] = make_check(
                    task_id,
                    task_name,
                    simatic_logon_for_pm,
                    {
                        "IPC0205": "OK",
                        "SimaticLogonInstalledOrDetected": True,
                        "ConfigurationDetails": "NICHT_PRUEFBAR",
                    },
                    {
                        "IPC0205Status": checks["IPC0205"].get("status"),
                        "SimaticLogonInstalledSoftware": simatic_logon_any_matches,
                        "SimaticLogonRegistryEvidence": simatic_logon_registry_matches,
                    },
                    (
                        "IPC0205 + "
                        "Software_PCS7_Components_Valid.InstalledSoftware/"
                        "SiemensRegistryEvidence"
                    ),
                    "Konfigurationseinstellungen nicht Pruefbar.",
                )

        # --------------------------------------------------------------
        # IPC0222-IPC0233 - aktuelle KB-/Edge-Sollwerte.
        # Server-spezifische IDs bleiben im aktuellen ES-Scope IGNORIERT.
        # --------------------------------------------------------------
        kb_by_id = as_dict(as_dict(expected.get("updates")).get("required_kbs_by_id"))
        server_only_ids = {
            "IPC0224",
            "IPC0225",
            "IPC0232",
        }

        for task_id in (
            "IPC0222", "IPC0223", "IPC0224", "IPC0225",
            "IPC0226", "IPC0227", "IPC0232", "IPC0233",
        ):
            kb = text(kb_by_id.get(task_id))
            if task_id in server_only_ids:
                checks[task_id] = make_ignored(
                    task_id,
                    f"{kb} installiert",
                    "Windows-Server-spezifische Aufgabe; OS Server werden aktuell ignoriert.",
                    "Aktueller ES-only Scope",
                )
                continue

            if not kb:
                checks[task_id] = make_check(
                    task_id,
                    "Windows-/SQL-Update",
                    None,
                    {"RequiredKB": None},
                    None,
                    "Semaphore: updates.required_kbs_by_id",
                )
                continue

            present, evidence = current_kb_evidence(
                patch_status,
                installed_software,
                kb,
            )
            state = present if isinstance(patch_status, dict) or isinstance(installed_software, dict) else None
            checks[task_id] = make_check(
                task_id,
                f"{kb} installiert",
                state,
                {"RequiredKB": kb, "Installed": True},
                evidence,
                (
                    "Firewall_SMB_Patch_Valid.PatchStatus.HotFixes/"
                    "WindowsPackages + Software_PCS7_Components_Valid.InstalledSoftware"
                ),
                (
                    "Die Windows-Update-Historie allein gilt nicht als Nachweis "
                    "des aktuellen Installationszustands."
                ),
            )

        edge_expected = as_dict(software_expected.get("edge"))
        edge_state, edge_evidence = evaluate_software_requirement(
            products,
            edge_expected,
        )
        checks["IPC0228"] = make_check(
            "IPC0228",
            "Microsoft Edge Stable",
            edge_state,
            {
                "ExpectedInstalled": bool_value(edge_expected.get("expected_installed")),
                "VersionRegex": edge_expected.get("version_regex"),
            },
            edge_evidence,
            "Software_PCS7_Components_Valid.InstalledSoftware.AllProducts",
            (
                "IPC0228 steht zweimal in der Aufgabenliste, beschreibt aber denselben "
                "Edge-Build und wird deshalb nur einmal als Matrixspalte gefuehrt."
            ),
        )

        checks["IPC0231"] = make_ignored(
            "IPC0231",
            "SQL-Server neu installiert",
            (
                "Die Aufgabe fordert explizit die Auswahl 'OS-Server' im "
                "PCS-7-Rahmensetup. OS Server werden in dieser Ausbaustufe ignoriert."
            ),
            "Aktueller ES-only Scope",
        )

        # --------------------------------------------------------------
        # IPC0245 - Wiederholungsprüfung der VNC-Firewallregeln.
        # Exakt derselbe Sollwert wie IPC0027, daher keine doppelte
        # Semaphore-Konfiguration.
        # --------------------------------------------------------------
        checks["IPC0245"] = referenced_check(
            "IPC0245",
            "VNC-Viewer Firewallregel prüfen",
            "IPC0027",
            checks.get("IPC0027"),
            "Wiederholungsprüfung; Sollwert und Evidenz werden aus IPC0027 übernommen.",
        )

        # --------------------------------------------------------------
        # IPC0246 - Firewall für alle Profile aktiviert.
        # Referenz auf IPC0166, aber bewusst nur der Profil-Teil, weil
        # IPC0166 zusätzlich die Netzwerkkategorie 'Private' bewertet.
        # --------------------------------------------------------------
        ipc0246_profiles = as_list(as_dict(firewall).get("Profiles"))
        ipc0246_required = {"domain", "private", "public"}
        ipc0246_found = {
            text(item.get("Name")).strip().lower(): item
            for item in ipc0246_profiles
            if isinstance(item, dict)
        }
        if not isinstance(firewall, dict) or not ipc0246_profiles:
            ipc0246_state = None
        else:
            ipc0246_state = all(
                name in ipc0246_found
                and bool_value(ipc0246_found[name].get("Enabled")) is True
                for name in ipc0246_required
            )

        checks["IPC0246"] = make_check(
            "IPC0246",
            "Firewall für alle Profile aktiviert",
            ipc0246_state,
            {
                "ReferenzId": "IPC0166",
                "Domain": True,
                "Private": True,
                "Public": True,
            },
            [
                {
                    "Name": item.get("Name"),
                    "Enabled": item.get("Enabled"),
                }
                for item in ipc0246_profiles
                if isinstance(item, dict)
            ],
            "Firewall_SMB_Patch_Valid.Firewall.Profiles / Referenz IPC0166",
            "Nur der Firewallprofil-Anteil von IPC0166 wird für IPC0246 bewertet.",
        )

        # IPC0248/IPC0249 sind explizit OS-Client-Aufgaben.
        for task_id, task_name in (
            ("IPC0248", "Defender - Cloudbasierter Schutz"),
            ("IPC0249", "Defender - Automatische Übermittlung von Beispielen"),
        ):
            checks[task_id] = make_ignored(
                task_id,
                task_name,
                "OS-Client-spezifische Aufgabe; OS Clients werden aktuell ignoriert.",
                "Aktueller ES-only Scope",
            )

        # --------------------------------------------------------------
        # IPC0254 - SIMATIC SHELL Proxy.
        # Der Collector liefert heuristische Registry-Evidenz. Positive
        # Stationsfunde können deshalb als OK gewertet werden; fehlende
        # Namen erzeugen NICHT_PRUEFBAR statt eines möglicherweise
        # falschen NOK.
        # --------------------------------------------------------------
        shell_expected = as_dict(software_expected.get("simatic_shell"))
        configured_stations = [
            text(value).strip()
            for value in as_list(shell_expected.get("expected_proxy_stations"))
            if text(value).strip()
        ]
        current_host_name = text(as_dict(identity).get("ComputerName")).strip()
        required_stations = [
            station
            for station in configured_stations
            if station.lower() != current_host_name.lower()
        ]

        shell_text = " ".join(
            recursive_scalar_text(simatic_shell_evidence)
        ) if isinstance(simatic_shell_evidence, dict) else ""
        station_results = [
            {
                "Station": station,
                "DetectedInSimaticShellEvidence": bool(
                    re.search(re.escape(station), shell_text, re.IGNORECASE)
                ),
            }
            for station in required_stations
        ]

        if not required_stations:
            ipc0254_state = None
        elif not isinstance(simatic_shell_evidence, dict):
            ipc0254_state = None
        elif all(item["DetectedInSimaticShellEvidence"] for item in station_results):
            ipc0254_state = True
        else:
            # Collector selbst kennzeichnet den Speicherort als releaseabhängig/
            # heuristisch; aus einem fehlenden Treffer wird daher kein NOK.
            ipc0254_state = None

        checks["IPC0254"] = make_check(
            "IPC0254",
            "SIMATIC SHELL Proxy ergänzen",
            ipc0254_state,
            {
                "ExpectedProxyStations": required_stations,
            },
            {
                "StationEvaluation": station_results,
                "SimaticShellEvidence": simatic_shell_evidence,
            },
            "Software_PCS7_Components_Valid.SimaticShellEvidence",
            (
                "OK nur bei eindeutig gefundenen Stationsnamen. Fehlende Treffer "
                "bleiben NICHT_PRUEFBAR, weil der Collector die vollständige "
                "Proxy-Stationsliste nicht für jede PCS-7-Version garantieren kann."
            ),
        )

        checks["IPC0185"] = make_ignored(
            "IPC0185",
            "Kontrolle mit WinCC_RT Benutzer",
            "Task wird nicht automatisch geprueft; manuelle Benutzerkontrolle.",
            "0160-Prueflogik",
        )

        checks["IPC0188"] = make_ignored(
            "IPC0188",
            "host/lmhost Dateien verteilen",
            "Task wird nicht automatisch geprueft; anlagenspezifische Dateiinhalte.",
            "0160-Prueflogik",
        )

        checks["IPC0186"] = make_ignored(
            "IPC0186",
            "BGInfo/BGSiVaaS OS-Clients aktualisieren",
            "OS-Client-spezifische Aufgabe; OS Clients werden aktuell ignoriert.",
            "Aktueller ES-only Scope",
        )

        # IPC0143/IPC0144 werden nachfolgend als direkte
        # Zertifikats-INFORMATION ausgegeben. IPC0145/IPC0146 bleiben
        # direkte ORCLA-PKI-Sollwertpruefungen.

        # Weitere direkte read-only Pruefungen und
        # Informationsausgaben werden im naechsten Play ergaenzt.

        return checks, information

    with library_path.open("r", encoding="utf-8-sig") as handle:
        library = json.load(handle)

    if not isinstance(library, dict) or library.get("library_type") != "IPC_Information_Library":
        raise RuntimeError("Die Eingabedatei ist keine gueltige IPC_Information_Library von 0150.")

    library_hosts = as_dict(library.get("hosts"))
    output_hosts = {}
    ok_total = 0
    nok_total = 0
    not_testable_total = 0
    ignored_total = 0
    information_total = 0

    # Wichtig: OS Server und OS Client werden in 0160 bewusst komplett ignoriert.
    for ip in sorted(library_hosts, key=ip_sort_key):
        source_host = as_dict(library_hosts[ip])
        if text(source_host.get("classification")) != "ES":
            continue

        checks, information = evaluate_es(source_host)

        ok_total += sum(
            1 for item in checks.values()
            if as_dict(item).get("status") == "OK"
        )
        nok_total += sum(
            1 for item in checks.values()
            if as_dict(item).get("status") == "NOK"
        )
        not_testable_total += sum(
            1 for item in checks.values()
            if as_dict(item).get("status") == "NICHT_PRUEFBAR"
        )
        ignored_total += sum(
            1 for item in checks.values()
            if as_dict(item).get("status") == "IGNORIERT"
        )
        information_total += sum(
            1 for item in information.values()
            if as_dict(item).get("status") == "INFORMATION"
        )

        access = as_dict(source_host.get("zugriff"))
        installed_software = section(
            source_host,
            "software_und_pcs7",
            "Software_PCS7_Components_Valid",
            "InstalledSoftware",
        )
        siemens_components = software_inventory(installed_software, "SiemensAndPCS7")
        all_installed_software = software_inventory(installed_software, "AllProducts")

        output_hosts[ip] = {
            "ip_address": ip,
            "computer_name": source_host.get("computer_name"),
            "classification": "ES",
            "ansible_access": bool(access.get("ansible_access")),
            "siemens_components": siemens_components,
            "installed_software": all_installed_software,
            "data_quality": source_host.get("datenqualitaet"),
            "pruefungen": {
                task_id: checks[task_id]
                for task_id in TASK_IDS
                if task_id in checks
            },
            "informationen": {
                task_id: information[task_id]
                for task_id in TASK_IDS
                if task_id in information
            },
        }

    output = {
        "schema_version": "2.0",
        "validation_type": "IPC_ES_ID_Validation",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": {
            "included_classifications": ["ES"],
            "ignored_classifications": ["OS_Server", "OS_Client", "Kein_Zugriff"],
            "ids": TASK_IDS,
        },
        "sources": {
            "information_library": str(library_path),
            "source_playbooks_unchanged": [
                "0000IPC_Discovery_Classification",
                "0110IPC_ES_Initial_Installation",
                "0150IPC_Information_Library",
            ],
        },
        "summary": {
            "es_hosts_total": len(output_hosts),
            "checks_ok_total": ok_total,
            "checks_nok_total": nok_total,
            "checks_not_testable_total": not_testable_total,
            "checks_ignored_total": ignored_total,
            "information_total": information_total,
        },
        "hosts": output_hosts,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    json_tmp = output_path.with_name(output_path.name + ".tmp")
    with json_tmp.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(output, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(str(json_tmp), str(output_path))

    csv_tmp = csv_path.with_name(csv_path.name + ".tmp")
    with csv_tmp.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle, delimiter=";", quoting=csv.QUOTE_MINIMAL)
        writer.writerow([
            "IP-Adresse",
            "Rechnername",
            "Computerart",
            "Ansible-Zugriff",
            "Siemens-Komponenten",
            "Installierte-Software-Gesamt",
            *TASK_IDS,
        ])

        for ip in sorted(output_hosts, key=ip_sort_key):
            host = output_hosts[ip]
            row = [
                ip,
                host.get("computer_name") or "",
                "ES",
                "JA" if host.get("ansible_access") else "NEIN",
                software_inventory_csv_value(host.get("siemens_components")),
                software_inventory_csv_value(host.get("installed_software")),
            ]

            checks = as_dict(host.get("pruefungen"))
            information = as_dict(host.get("informationen"))
            for task_id in TASK_IDS:
                if task_id in checks:
                    row.append(as_dict(checks[task_id]).get("status") or "NICHT_PRUEFBAR")
                elif task_id in information:
                    info = as_dict(information[task_id])
                    if info.get("status") != "INFORMATION":
                        row.append("NICHT_PRUEFBAR")
                    else:
                        row.append(compact_info(task_id, info.get("ist")))
                else:
                    row.append("")
            writer.writerow(row)

        handle.flush()
        os.fsync(handle.fileno())
    os.replace(str(csv_tmp), str(csv_path))

    print(json.dumps({
        "json": str(output_path),
        "csv": str(csv_path),
        "summary": output["summary"],
    }, ensure_ascii=False))


def run_merge(args):
    output_path = Path(args.output)
    csv_path = Path(args.csv)
    live_dir = Path(args.live_dir)

    direct_ids = [
        "IPC0046", "IPC0047", "IPC0048", "IPC0055", "IPC0063", "IPC0066",
        "IPC0070", "IPC0073", "IPC0074", "IPC0075", "IPC0076", "IPC0083",
        "IPC0087", "IPC0089", "IPC0145", "IPC0146", "IPC0148", "IPC0160",
        "IPC0161", "IPC0167", "IPC0178", "IPC0182", "IPC0183", "IPC0184",
        "IPC0200", "IPC0234", "IPC0247", "IPC0250", "IPC0251", "IPC0252",
        "IPC0263", "IPC0264", "IPC0265", "IPC0267", "IPC0268", "IPC0269",
        "IPC0270", "IPC0271",
    ]
    direct_information_ids = ["IPC0143", "IPC0144", "IPC0152"]

    with output_path.open("r", encoding="utf-8-sig") as handle:
        output = json.load(handle)

    hosts = output.get("hosts") if isinstance(output, dict) else None
    if not isinstance(hosts, dict):
        raise RuntimeError("0160-Ausgabe enthaelt kein gueltiges hosts-Objekt.")

    def missing_direct_check(task_id):
        names = {
            "IPC0046": "Hot-Keys abschalten (Auswahl: Keine)",
            "IPC0047": "Tastenkombination fuer Eingabesprachen deaktivieren",
            "IPC0048": "Region - Copy Settings fuer Willkommensseite und neue Benutzer",
            "IPC0055": "DNS und WINS-Server eintragen",
            "IPC0063": "Sichtbarkeit im Netzwerk",
            "IPC0066": "VNC-Einstellungen konfigurieren - File Transfer",
            "IPC0070": "UltraVNC Viewer installieren",
            "IPC0073": "Restore Image loeschen",
            "IPC0074": "Taskleiste",
            "IPC0075": "Lupe zur Suche in Taskleiste",
            "IPC0076": "Desktop: Computer Netzwerk Papierkorb",
            "IPC0083": "Bildschirmschoner aktivieren (SE + ES)",
            "IPC0087": "Energieoptionen auf Hoechstleistung setzen",
            "IPC0089": "Starten und Wiederherstellen anpassen",
            "IPC0145": "Zertifikate austauschen - WinCC OPC UA Client / ORCLA OPC UA Server",
            "IPC0146": "Zertifikate austauschen - Online-Modus",
            "IPC0148": "Automatische Systemwiederherstellung / System Restore deaktivieren",
            "IPC0160": "Verwendung von sicheren Cipher Suites - Allowlist",
            "IPC0161": "Verwendung von sicheren Cipher Suites - Sperrliste",
            "IPC0167": "D:\\Projekt erstellen",
            "IPC0178": "Office 2019 - Word und Excel",
            "IPC0182": "BGInfo/BGSiVaaS",
            "IPC0183": "BGInfo/BGSiVaaS - Als Administrator ausfuehren",
            "IPC0184": "Hintergrundbild anpassen",
            "IPC0200": "WSUSClientManager ablegen",
            "IPC0234": "Auslagerungsdatei konfigurieren",
            "IPC0247": "Defender - Manipulationsschutz",
            "IPC0250": "Defender - Downloads blockieren deaktiviert",
            "IPC0251": "Defender Sicherheitsstatus i.O.",
            "IPC0252": "UltraVNC-Viewer nachinstallieren",
            "IPC0263": "USB Boot deaktiviert",
            "IPC0264": "WLAN deaktiviert",
            "IPC0265": "Super IO Configuration",
            "IPC0267": "BIOS Passwortschutz",
            "IPC0268": "Power Failure Recovery - Previous State",
            "IPC0269": "Wake-Up LAN deaktiviert",
            "IPC0270": "Bootup NumLock On",
            "IPC0271": "Festplatte erstes Start-Medium",
        }
        return {
            "id": task_id,
            "aufgabe": names[task_id],
            "pruefart": "SOLLWERT",
            "status": "NICHT_PRUEFBAR",
            "soll": "Fester Sollwert gemaess Aufgabenliste",
            "ist": None,
            "quelle": "Direkt/PowerShell",
            "hinweis": "Direkte WinRM-Pruefung lieferte fuer dieses ES kein verwertbares Ergebnis.",
        }

    def missing_direct_information(task_id):
        names = {
            "IPC0143": "Zertifikate - WinCC OPC UA Client / SIMATIC NET OPC Server",
            "IPC0144": "Zertifikate - WinCC OPC UA Client / OS-Stationen",
            "IPC0152": "Datenschutz-/Privacy-Einstellungen",
        }
        return {
            "id": task_id,
            "aufgabe": names[task_id],
            "pruefart": "INFORMATION",
            "status": "NICHT_PRUEFBAR",
            "ist": None,
            "quelle": "Direkt/PowerShell",
            "hinweis": "Direkte WinRM-Informationsausgabe lieferte kein verwertbares Ergebnis.",
        }

    def compact_information_value(item):
        if not isinstance(item, dict) or item.get("status") != "INFORMATION":
            return "NICHT_PRUEFBAR"
        value = item.get("ist")
        if value is None:
            return "KEINE_INFORMATION"
        if isinstance(value, str):
            return value
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    for ip, host in hosts.items():
        if not isinstance(host, dict):
            continue
        checks = host.setdefault("pruefungen", {})
        information = host.setdefault("informationen", {})
        live_file = live_dir / f"{ip}.json"
        live_checks = {}
        live_information = {}

        if live_file.exists():
            try:
                with live_file.open("r", encoding="utf-8-sig") as handle:
                    live_payload = json.load(handle)

                candidate_checks = (
                    live_payload.get("checks")
                    if isinstance(live_payload, dict)
                    else None
                )
                if isinstance(candidate_checks, dict):
                    live_checks = candidate_checks

                candidate_information = (
                    live_payload.get("information")
                    if isinstance(live_payload, dict)
                    else None
                )
                if isinstance(candidate_information, dict):
                    live_information = candidate_information
            except Exception:
                live_checks = {}
                live_information = {}

        for task_id in direct_ids:
            item = live_checks.get(task_id)
            checks[task_id] = (
                item
                if isinstance(item, dict)
                else missing_direct_check(task_id)
            )

        for task_id in direct_information_ids:
            item = live_information.get(task_id)
            information[task_id] = (
                item
                if isinstance(item, dict)
                else missing_direct_information(task_id)
            )

    ok_total = 0
    nok_total = 0
    not_testable_total = 0
    ignored_total = 0
    information_total = 0
    for host in hosts.values():
        if not isinstance(host, dict):
            continue
        for item in (host.get("pruefungen") or {}).values():
            if not isinstance(item, dict):
                continue
            status = item.get("status")
            if status == "OK":
                ok_total += 1
            elif status == "NOK":
                nok_total += 1
            elif status == "NICHT_PRUEFBAR":
                not_testable_total += 1
            elif status == "IGNORIERT":
                ignored_total += 1
        for item in (host.get("informationen") or {}).values():
            if isinstance(item, dict) and item.get("status") == "INFORMATION":
                information_total += 1

    output["summary"] = {
        "es_hosts_total": len(hosts),
        "checks_ok_total": ok_total,
        "checks_nok_total": nok_total,
        "checks_not_testable_total": not_testable_total,
        "checks_ignored_total": ignored_total,
        "information_total": information_total,
    }
    output.setdefault("scope", {})["live_validation_ids"] = direct_ids
    output.setdefault("scope", {})["live_information_ids"] = direct_information_ids
    output.setdefault("sources", {})["direct_live_checks"] = [
        "IPC0046/IPC0047: HKCU\\Keyboard Layout\\Toggle",
        "IPC0048: Welcome Screen + Default User International Registry",
        "IPC0055: Terminalbus DNS + NetBT WINS NameServerList",
        "IPC0063: aktive Windows-Firewallregeln fuer Netzwerkerkennung und Datei-/Druckerfreigabe",
        "IPC0066: UltraVNC ultravnc.ini",
        "IPC0070: UltraVNC Server/Viewer Dateien und Dienst",
        "IPC0073: D:\\Images",
        "IPC0074/IPC0075: HKCU Explorer Advanced",
        "IPC0076: HKCU DesktopIcons + Common Desktop",
        "IPC0083: HKCU ScreenSaver Policy / Control Panel Desktop",
        "IPC0087: powercfg /query SCHEME_CURRENT",
        "IPC0089: bcdedit + Win32_OSRecoveryConfiguration",
        "IPC0143/IPC0144: INFORMATION - WinCC OPC UA Client PKI certificate files",
        "IPC0145/IPC0146: SIMATIC IPC ORCLA OPC UA PKI certificate files",
        "IPC0148: SystemRestore policy + root/default:SystemRestoreConfig",
        "IPC0152: INFORMATION - Windows Privacy Registry",
        "IPC0160/IPC0161: Get-TlsCipherSuite",
        "IPC0167: Test-Path D:\\Projekt",
        "IPC0178: Office Registry + WINWORD/EXCEL executable evidence",
        "IPC0182/IPC0183: BGSiVaaS path + startup shortcut LinkFlags",
        "IPC0184: BGSiVaaS Win32_Process",
        "IPC0200: WSUSClientManager path + WSUS policy/reachability",
        "IPC0234: Win32_ComputerSystem + Win32_PageFileSetting/Usage",
        "IPC0247: Get-MpComputerStatus.IsTamperProtected",
        "IPC0250/IPC0251: SmartScreenPuaEnabled + Referenzprüfung",
        "IPC0252: UltraVNC Viewer + HKCR .vnc association",
        "IPC0263-IPC0271: CIM BIOS/Firmware Provider Discovery",
    ]

    json_tmp = output_path.with_name(output_path.name + ".tmp")
    with json_tmp.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(output, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(str(json_tmp), str(output_path))

    if csv_path.exists():
        with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle, delimiter=";")
            fieldnames = list(reader.fieldnames or [])
            rows = list(reader)

        for task_id in direct_ids + direct_information_ids:
            if task_id not in fieldnames:
                fieldnames.append(task_id)

        for row in rows:
            ip = row.get("IP-Adresse", "")
            host = hosts.get(ip, {})
            checks = host.get("pruefungen", {}) if isinstance(host, dict) else {}
            information = host.get("informationen", {}) if isinstance(host, dict) else {}

            for task_id in direct_ids:
                item = checks.get(task_id, {}) if isinstance(checks, dict) else {}
                row[task_id] = (
                    item.get("status", "NICHT_PRUEFBAR")
                    if isinstance(item, dict)
                    else "NICHT_PRUEFBAR"
                )

            for task_id in direct_information_ids:
                item = (
                    information.get(task_id, {})
                    if isinstance(information, dict)
                    else {}
                )
                row[task_id] = compact_information_value(item)

        csv_tmp = csv_path.with_name(csv_path.name + ".tmp")
        with csv_tmp.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=fieldnames,
                delimiter=";",
                quoting=csv.QUOTE_MINIMAL,
                extrasaction="ignore",
            )
            writer.writeheader()
            writer.writerows(rows)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(csv_tmp), str(csv_path))

    print(json.dumps({
        "json": str(output_path),
        "csv": str(csv_path),
        "summary": output["summary"],
    }, ensure_ascii=False))


def parse_args():
    parser = argparse.ArgumentParser(description="0160 IPC ES ID Validation")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build", help="Bibliotheksbasierte 0160-Vorpruefung erzeugen")
    build_parser.add_argument("--library", required=True)
    build_parser.add_argument("--output", required=True)
    build_parser.add_argument("--csv", required=True)
    build_parser.add_argument("--expected", required=True)
    build_parser.set_defaults(func=run_build)

    merge_parser = subparsers.add_parser("merge", help="Direkte Read-only-Ergebnisse in 0160-Protokolle uebernehmen")
    merge_parser.add_argument("--output", required=True)
    merge_parser.add_argument("--csv", required=True)
    merge_parser.add_argument("--live-dir", required=True)
    merge_parser.set_defaults(func=run_merge)

    return parser.parse_args()


def main():
    args = parse_args()
    args.func(args)


if __name__ == "__main__":
    main()