import csv
import glob
import ipaddress
import os
import re
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

# ---------------------------------------------------------------------------
# 0050 Task-Status-Matrix
# Ausgabe je Task/IP:
#   OK              = direkte Pruefung mit positivem Ergebnis
#   NOK             = direkte Pruefung mit negativem Ergebnis
#   ISTWERT: ...    = es gibt aus 0010/0020 oder Details nur einen ausgelesenen Wert,
#                    aber keinen belastbaren Soll-Ist-Vergleich
#   NICHT_PRUEFBAR  = weder direkte Pruefung noch verwertbarer Istwert vorhanden
# ---------------------------------------------------------------------------

source_dir = Path(os.environ.get("MATRIX_SOURCE_DIR") or os.environ.get("MATRIX_RESULT_DIR", "."))
output_dir = Path(os.environ.get("MATRIX_OUTPUT_DIR") or source_dir)
output_dir.mkdir(parents=True, exist_ok=True)

template_xlsx = Path(os.environ["MATRIX_TEMPLATE_XLSX"])
template_sheet = os.environ.get("MATRIX_TEMPLATE_SHEET", "VM OS Server V10.0")
output_basename = os.environ["MATRIX_OUTPUT_BASENAME"]

STATUS_OK = os.environ.get("MATRIX_STATUS_OK", "OK")
STATUS_NOK = os.environ.get("MATRIX_STATUS_NOK", "NOK")
STATUS_NP = os.environ.get("MATRIX_STATUS_NP", "NICHT_PRUEFBAR")
STATUS_IST = os.environ.get("MATRIX_STATUS_IST", "ISTWERT")

SHOW_INDIRECT_VALUES = os.environ.get("MATRIX_SHOW_INDIRECT_VALUES", "true").strip().lower() in ("1", "true", "yes", "ja", "y")
SHOW_DETAILS_FOR_NP = os.environ.get("MATRIX_SHOW_DETAILS_FOR_NP", "true").strip().lower() in ("1", "true", "yes", "ja", "y")
MAX_CELL_TEXT_LEN = int(os.environ.get("MATRIX_MAX_CELL_TEXT_LEN", "180"))

source_patterns = {
    "0010": os.environ.get("MATRIX_0010_PATTERN", "network_discovery_*.csv"),
    "0020": os.environ.get("MATRIX_0020_PATTERN", "pcs7_installation_check_*.csv"),
    "0030": os.environ.get("MATRIX_0030_PATTERN", "os_server_v10_validation_*.csv"),
    "0040": os.environ.get("MATRIX_0040_PATTERN", "os_server_systemhardening_v10_validation_*.csv"),
}

# Spalten ohne ID sind normalerweise Istwerte. Nur diese Spalten werden als echte
# OK/NOK-Statusspalten bewertet, weil sie selbst eine klare Pruefaussage enthalten.
# WICHTIG: Domaenenmitglied, DHCP usw. werden bewusst NICHT pauschal als OK/NOK bewertet,
# weil "true" oder "false" je nach Task ein normaler Istwert sein kann.
STATUS_LIKE_COLUMNS = {
    "Ansible_erreichbar",
    "PCS7_Installation_nachgewiesen",
    "Setup_Logpfad_vorhanden",
}

# Manuelle Fallback-Mappings fuer Aufgaben, die nicht ueber ID-Spalten aus 0030/0040
# erkannt werden. Zusaetzlich werden die Zuordnungen aus Q/R der Excel-Vorlage gelesen,
# aber nur verwendet, wenn die genannte CSV-Spalte wirklich existiert.
fallback_task_map = {
    # 0010 / 0020 - Basisinformationen, meist ISTWERT
    11: [("0010", ["Ansible_erreichbar", "WinRM_Listener"]), ("0020", ["WinRM_Port", "WinRM_Schema", "WinRM_Offene_Ports"])],
    13: [("0020", ["System_Locale", "System_Locale_Anzeige", "UI_Culture", "UI_Culture_Anzeige", "Culture", "Culture_Anzeige", "Benutzer_Sprachenliste"])],
    14: [("0010", ["Computername", "FQDN"]), ("0020", ["Computername", "FQDN"])],
    15: [("0020", ["PCS7_Installation_nachgewiesen", "Nachweisqualitaet", "PCS7_Versionen_aus_Setup_Log", "PCS7_Versionen_aus_Registry"])],
    18: [("0010", ["IPv4", "Subnetz", "Gateway", "DNS_Server", "MAC", "DHCP", "Firewallprofile", "WinRM_Listener"]), ("0020", ["Adapterbeschreibung", "DNS_Hostname", "DNS_Domain", "IPv4_Adressen", "IPv6_Adressen", "Subnetzmasken", "Gateway", "DNS_Server", "MAC_Adressen", "DHCP", "WinRM_Port", "WinRM_Schema", "WinRM_Offene_Ports"])],
    20: [("0010", ["Domaene", "Domaenenmitglied", "Workgroup"]), ("0020", ["Domaene_Workgroup", "Domaenenmitglied"])],
    22: [("0010", ["Lokale_Benutzer"])],
    25: [("0010", ["Lokale_Benutzer"])],
    26: [("0010", ["Lokale_Benutzer"])],
    27: [("0010", ["Lokale_Benutzer"])],
    34: [("0020", ["System_Locale", "System_Locale_Anzeige", "UI_Culture", "UI_Culture_Anzeige", "Culture", "Culture_Anzeige", "Benutzer_Sprachenliste"])],
    41: [("0010", ["IPv4", "Subnetz", "Gateway", "MAC"]), ("0020", ["IPv4_Adressen", "Subnetzmasken", "Gateway", "MAC_Adressen"])],
    42: [("0010", ["DNS_Server"]), ("0020", ["DNS_Server"])],
    52: [("0010", ["Domaene", "Domaenenmitglied"]), ("0020", ["Domaene_Workgroup", "Domaenenmitglied"])],
    90: [("0010", ["Firewallprofile"])],

    # 0020 - PCS 7 / Software / Netzwerk
    58: [("0020", ["PCS7_Installation_nachgewiesen", "Nachweisqualitaet", "Anzahl_PCS7_Bezugskomponenten", "PCS7_Komponenten_mit_Version", "PCS7_Versionen_aus_Setup_Log", "PCS7_Versionen_aus_Registry"])],
    59: [("0020", ["PCS7_Installation_nachgewiesen", "Nachweisqualitaet", "Anzahl_PCS7_Bezugskomponenten", "PCS7_Komponenten_mit_Version"])],
    60: [("0020", ["PCS7_Installation_nachgewiesen", "Nachweisqualitaet", "Anzahl_PCS7_Bezugskomponenten", "PCS7_Komponenten_mit_Version"])],
    61: [("0020", ["PCS7_Installation_nachgewiesen", "Nachweisqualitaet", "Anzahl_PCS7_Bezugskomponenten", "PCS7_Komponenten_mit_Version"])],
    62: [("0020", ["PCS7_Installation_nachgewiesen", "Nachweisqualitaet", "Anzahl_PCS7_Bezugskomponenten", "PCS7_Komponenten_mit_Version"])],
    63: [("0020", ["PCS7_Installation_nachgewiesen", "Nachweisqualitaet", "Anzahl_PCS7_Bezugskomponenten", "PCS7_Komponenten_mit_Version"])],
    64: [("0020", ["PCS7_Installation_nachgewiesen", "Nachweisqualitaet", "Anzahl_PCS7_Bezugskomponenten", "PCS7_Komponenten_mit_Version"])],
    66: [("0020", ["Anzahl_Siemens_Komponenten", "Alle_Siemens_Komponenten_mit_Version"])],
    86: [("0020", ["Alle_Siemens_Komponenten_mit_Version", "PCS7_Komponenten_mit_Version"])],
    110: [("0020", ["Gateway", "Adapterbeschreibung", "IPv4_Adressen", "Subnetzmasken"])],
}


def latest_file(pattern):
    matches = [Path(p) for p in glob.glob(str(source_dir / pattern))]
    if not matches:
        return None
    return sorted(matches, key=lambda p: p.stat().st_mtime, reverse=True)[0]


def read_csv(path):
    if path is None or not path.exists():
        return [], []
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh, delimiter=";")
        rows = list(reader)
        headers = reader.fieldnames or []
    return headers, rows


def row_ip(row):
    for key in ("IP", "ip", "IPv4"):
        value = str(row.get(key, "")).strip()
        if value:
            return value
    return ""


def ip_sort_key(ip):
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except Exception:
        return (1, ip)


def clean_text(value):
    if value is None:
        return ""
    return str(value).replace("\r\n", "\n").replace("\r", "\n").strip()


def shorten_text(value, max_len=None):
    text = clean_text(value)
    if max_len is None:
        max_len = MAX_CELL_TEXT_LEN
    text = re.sub(r"\s+", " ", text)
    if max_len > 0 and len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def norm_bool(value):
    v = clean_text(value).lower()
    if v in ("true", "1", "ja", "yes", "y", "wahr", "ok", "erfolgreich", "success"):
        return True
    if v in ("false", "0", "nein", "no", "n", "falsch", "nok", "failed", "fehlgeschlagen"):
        return False
    return None


def column_letters_from_ref(cell_ref):
    return re.sub(r"[^A-Z]", "", cell_ref.upper())


def read_xlsx_rows(path, sheet_name):
    ns_main = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    ns_rel = {"r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships"}

    with zipfile.ZipFile(path) as zf:
        shared_strings = []
        if "xl/sharedStrings.xml" in zf.namelist():
            ss_root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
            for si in ss_root.findall("m:si", ns_main):
                shared_strings.append("".join(t.text or "" for t in si.findall(".//m:t", ns_main)))

        wb_root = ET.fromstring(zf.read("xl/workbook.xml"))
        rel_root = ET.fromstring(zf.read("xl/_rels/workbook.xml.rels"))
        rels = {}
        for rel in rel_root:
            rel_id = rel.attrib.get("Id")
            target = rel.attrib.get("Target")
            if rel_id and target:
                if not target.startswith("xl/"):
                    target = "xl/" + target.lstrip("/")
                rels[rel_id] = target

        selected_sheet_path = None
        first_sheet_path = None
        for sheet in wb_root.findall("m:sheets/m:sheet", ns_main):
            rid = sheet.attrib.get("{%s}id" % ns_rel["r"])
            name = sheet.attrib.get("name", "")
            sheet_path = rels.get(rid)
            if first_sheet_path is None:
                first_sheet_path = sheet_path
            if name == sheet_name:
                selected_sheet_path = sheet_path
                break

        if selected_sheet_path is None:
            selected_sheet_path = first_sheet_path

        if not selected_sheet_path or selected_sheet_path not in zf.namelist():
            raise RuntimeError(f"Worksheet '{sheet_name}' konnte in {path} nicht gelesen werden.")

        sh_root = ET.fromstring(zf.read(selected_sheet_path))
        rows = []
        wanted_cols = {"A", "B", "C", "Q", "R"}

        for row in sh_root.findall("m:sheetData/m:row", ns_main):
            row_idx = int(row.attrib.get("r", "0") or 0)
            values = {"row_index": row_idx, "A": "", "B": "", "C": "", "Q": "", "R": ""}
            for cell in row.findall("m:c", ns_main):
                ref = cell.attrib.get("r", "")
                col = column_letters_from_ref(ref)
                if col not in wanted_cols:
                    continue
                cell_type = cell.attrib.get("t", "")
                value = ""
                if cell_type == "inlineStr":
                    value = "".join(t.text or "" for t in cell.findall(".//m:t", ns_main))
                else:
                    v = cell.find("m:v", ns_main)
                    raw = v.text if v is not None else ""
                    if cell_type == "s" and raw != "":
                        try:
                            value = shared_strings[int(raw)]
                        except Exception:
                            value = raw
                    else:
                        value = raw
                values[col] = clean_text(value)
            if any(values[c] for c in ("A", "B", "C", "Q", "R")):
                rows.append(values)
        return rows


def is_direct_status_column(col):
    return bool(re.match(r"^ID0*\d+_", col or ""))


def is_status_like_column(col):
    return is_direct_status_column(col) or (col in STATUS_LIKE_COLUMNS)


def classify_status_value(value, col):
    """Return OK/NOK/NICHT_PRUEFBAR/ISTWERT_PARTIAL/None for a status-like value."""
    v = clean_text(value)
    vl = v.lower()
    if not v:
        return None

    if vl == "ok":
        return STATUS_OK
    if vl == "nok":
        return STATUS_NOK
    if vl in ("nicht_pruefbar", "nicht prüfbar", "nicht pruefbar", "nicht-pruefbar", "n/a", "na"):
        return STATUS_NP
    if vl in ("teilweise", "partial", "warnung", "warning"):
        return "ISTWERT_PARTIAL"

    b = norm_bool(v)
    if b is not None:
        return STATUS_OK if b else STATUS_NOK

    # Fuer Statusspalten mit Anzahl/Count kann >0 als Nachweis gelten.
    if any(token in (col or "").lower() for token in ("anzahl", "count")):
        try:
            return STATUS_OK if float(v.replace(",", ".")) > 0 else STATUS_NOK
        except Exception:
            pass

    return None


def make_info_text(col, value):
    value = shorten_text(value)
    if not value:
        return ""
    return f"{col}={value}"


def details_for_column(row, col):
    detail_col = f"{col}_Details"
    if detail_col in row:
        return clean_text(row.get(detail_col, ""))
    return ""


def combine_cell(evidence):
    """Combine evidence objects into one matrix cell."""
    direct = [e for e in evidence if e.get("direct") and e.get("status")]
    status_like = [e for e in evidence if (not e.get("direct")) and e.get("status")]
    info_values = [e.get("info") for e in evidence if e.get("info")]
    detail_values = [e.get("details") for e in evidence if e.get("details")]

    # 1. Direkte ID-Pruefspalten aus 0030/0040 haben Vorrang.
    if direct:
        statuses = [e["status"] for e in direct]
        if STATUS_NOK in statuses:
            return STATUS_NOK
        if all(s == STATUS_OK for s in statuses):
            return STATUS_OK
        if "ISTWERT_PARTIAL" in statuses:
            if SHOW_INDIRECT_VALUES and detail_values:
                return f"{STATUS_IST}: {shorten_text(' | '.join(detail_values))}"
            return STATUS_IST
        # Alles andere bei direkten Pruefungen ist nicht pruefbar.
        if SHOW_DETAILS_FOR_NP and detail_values:
            return f"{STATUS_NP}: {shorten_text(' | '.join(detail_values))}"
        return STATUS_NP

    # 2. Nicht-ID-Spalten mit klarer Pruefaussage, z. B. Ansible_erreichbar oder PCS7_Installation_nachgewiesen.
    if status_like:
        statuses = [e["status"] for e in status_like]
        if STATUS_NOK in statuses:
            return STATUS_NOK
        if STATUS_OK in statuses:
            return STATUS_OK
        if "ISTWERT_PARTIAL" in statuses:
            if SHOW_INDIRECT_VALUES and (detail_values or info_values):
                return f"{STATUS_IST}: {shorten_text(' | '.join(detail_values + info_values))}"
            return STATUS_IST
        return STATUS_NP

    # 3. Reine Ausgaben/Istwerte werden explizit als ISTWERT dargestellt.
    if SHOW_INDIRECT_VALUES and info_values:
        return f"{STATUS_IST}: {shorten_text(' | '.join(info_values))}"

    return STATUS_NP


def source_from_segment_name(name):
    m = re.search(r"(0010|0020|0030|0040)", name or "")
    return m.group(1) if m else None


def parse_columns_from_mapping_text(text, available_headers_by_source):
    result = []
    text = clean_text(text)
    if not text or "CSV:" not in text:
        return result

    # Segmente wie: 0030...yml → CSV: Spalte1, Spalte1_Details | 0020...yml → CSV: Spalte2
    seg_re = re.compile(
        r"((?:0010|0020|0030|0040)[^→\n|]*?)\s*→\s*CSV:\s*(.*?)(?=(?:\s*\|\s*(?:0010|0020|0030|0040)[^→\n|]*?\s*→\s*CSV:)|$)",
        re.IGNORECASE | re.DOTALL,
    )
    for match in seg_re.finditer(text):
        src = source_from_segment_name(match.group(1))
        cols_text = match.group(2)
        if not src:
            continue
        available = set(available_headers_by_source.get(src, []))
        candidates = []
        for part in re.split(r",|\n", cols_text):
            c = clean_text(part)
            c = re.sub(r"\(.*?\)", "", c).strip()
            c = c.strip(" .;:")
            if not c:
                continue
            # Details werden automatisch ueber <Spalte>_Details angebunden.
            if c in available and not c.endswith("_Details"):
                candidates.append(c)
        if candidates:
            result.append((src, candidates))
    return result


def id_columns_from_headers(headers):
    by_id = {}
    for h in headers:
        if h.endswith("_Details"):
            continue
        m = re.match(r"^ID0*(\d+)_", h)
        if m:
            by_id.setdefault(int(m.group(1)), []).append(h)
    return by_id


def is_task_id(value):
    try:
        if value is None or clean_text(value) == "":
            return None
        return int(float(clean_text(value).replace(",", ".")))
    except Exception:
        return None


# CSV-Quellen laden
source_files = {}
headers_by_source = {}
rows_by_source_ip = {}

for src, pattern in source_patterns.items():
    path = latest_file(pattern)
    source_files[src] = path
    headers, rows = read_csv(path) if path else ([], [])
    headers_by_source[src] = headers
    indexed = {}
    for r in rows:
        ip = row_ip(r)
        if ip:
            indexed[ip] = r
    rows_by_source_ip[src] = indexed

# IPs aus allen CSV-Quellen sammeln
ips = set()
for indexed in rows_by_source_ip.values():
    ips.update(indexed.keys())
ips = sorted(ips, key=ip_sort_key)

# Excel-Vorlage lesen: A-C fuer Ausgabe, Q/R nur intern fuer Mapping
try:
    template_rows = read_xlsx_rows(template_xlsx, template_sheet)
except Exception as exc:
    raise SystemExit(f"FEHLER: Excel-Vorlage konnte nicht gelesen werden: {exc}")

# Direkte ID-Pruefspalten aus 0030 und 0040 erkennen.
id_based_map = {}
for src in ("0030", "0040"):
    for task_id, cols in id_columns_from_headers(headers_by_source.get(src, [])).items():
        id_based_map.setdefault(task_id, []).append((src, cols))

# Matrix aufbauen
output_rows = []
output_rows.append(["Ansible-ID Protokoll", "Hinweis/System", "Beschreibung"] + ips)

for tr in template_rows:
    task_id = is_task_id(tr.get("A"))
    a = tr.get("A", "")
    b = tr.get("B", "")
    c = tr.get("C", "")

    # Kopfzeilen aus der Vorlage nicht doppelt ausgeben.
    if clean_text(a).lower().startswith("ansible-"):
        continue

    out = [a, b, c]

    if task_id is None:
        out.extend(["" for _ in ips])
        output_rows.append(out)
        continue

    mappings = []
    mappings.extend(id_based_map.get(task_id, []))
    mappings.extend(parse_columns_from_mapping_text(tr.get("Q", ""), headers_by_source))
    mappings.extend(parse_columns_from_mapping_text(tr.get("R", ""), headers_by_source))
    mappings.extend(fallback_task_map.get(task_id, []))

    # Duplikate entfernen und nur vorhandene CSV-Spalten behalten.
    unique_mappings = []
    seen = set()
    for src, cols in mappings:
        available = set(headers_by_source.get(src, []))
        valid_cols = []
        for col in cols:
            if col in available and col not in valid_cols and not col.endswith("_Details"):
                valid_cols.append(col)
        key = (src, tuple(valid_cols))
        if valid_cols and key not in seen:
            seen.add(key)
            unique_mappings.append((src, valid_cols))

    for ip in ips:
        evidence = []
        for src, cols in unique_mappings:
            row = rows_by_source_ip.get(src, {}).get(ip)
            if not row:
                continue
            for col in cols:
                value = row.get(col, "")
                if clean_text(value) == "":
                    continue
                direct = is_direct_status_column(col)
                status_like = is_status_like_column(col)
                status = classify_status_value(value, col) if status_like else None
                evidence.append({
                    "source": src,
                    "column": col,
                    "status": status,
                    "direct": direct,
                    "info": make_info_text(col, value),
                    "details": details_for_column(row, col),
                })
        out.append(combine_cell(evidence))

    output_rows.append(out)

csv_path = output_dir / f"{output_basename}.csv"
meta_path = output_dir / f"{output_basename}_quellen.txt"

with csv_path.open("w", encoding="utf-8-sig", newline="") as fh:
    writer = csv.writer(fh, delimiter=";")
    writer.writerows(output_rows)

with meta_path.open("w", encoding="utf-8") as fh:
    fh.write("0050 Task-Status-Matrix\n")
    fh.write(f"Vorlage: {template_xlsx}\n")
    fh.write(f"Sheet: {template_sheet}\n")
    fh.write(f"CSV-Quellordner: {source_dir}\n")
    fh.write(f"Matrix-Zielordner: {output_dir}\n")
    fh.write("\nVerwendete CSV-Quellen:\n")
    for src in ("0010", "0020", "0030", "0040"):
        fh.write(f"{src}: {source_files.get(src) or 'NICHT GEFUNDEN'}\n")
    fh.write("\nBewertungslogik:\n")
    fh.write("OK = direkte Pruefung oder klare Statusspalte positiv.\n")
    fh.write("NOK = direkte Pruefung oder klare Statusspalte negativ.\n")
    fh.write("ISTWERT = Wert wurde ausgelesen, aber nicht gegen einen Sollwert bewertet.\n")
    fh.write("NICHT_PRUEFBAR = keine direkte Pruefung und kein verwertbarer Istwert vorhanden.\n")
    fh.write("\nHinweise:\n")
    fh.write("Die Spalten A-C stammen aus der Vorlagen-Excel. Spalten D ff. sind die gefundenen IP-Adressen.\n")
    fh.write("D-R aus der Vorlage werden nicht in die Matrix uebernommen. Q/R werden nur intern fuer Mapping genutzt.\n")
    fh.write("ID-basierte Pruefspalten aus 0030/0040 werden aus den echten CSV-Headern erkannt.\n")
    fh.write("Falsche Excel-Pruefzuordnungen werden ignoriert, wenn die angegebene CSV-Spalte nicht existiert.\n")

print(f"CSV={csv_path}")
print(f"META={meta_path}")
print(f"IPS={len(ips)}")
print("SOURCES=" + "; ".join(f"{k}:{v if v else 'NICHT_GEFUNDEN'}" for k, v in source_files.items()))
