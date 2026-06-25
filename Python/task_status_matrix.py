import csv
import glob
import ipaddress
import os
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

source_dir = Path(os.environ.get("MATRIX_SOURCE_DIR") or os.environ.get("MATRIX_RESULT_DIR", "."))
output_dir = Path(os.environ.get("MATRIX_OUTPUT_DIR") or source_dir)
output_dir.mkdir(parents=True, exist_ok=True)
template_xlsx = Path(os.environ["MATRIX_TEMPLATE_XLSX"])
template_sheet = os.environ.get("MATRIX_TEMPLATE_SHEET", "VM OS Server V10.0")
output_basename = os.environ["MATRIX_OUTPUT_BASENAME"]

STATUS_OK = os.environ.get("MATRIX_STATUS_OK", "OK")
STATUS_NOK = os.environ.get("MATRIX_STATUS_NOK", "NOK")
STATUS_NP = os.environ.get("MATRIX_STATUS_NP", "NICHT_PRUEFBAR")

source_patterns = {
    "0010": os.environ.get("MATRIX_0010_PATTERN", "network_discovery_*.csv"),
    "0020": os.environ.get("MATRIX_0020_PATTERN", "pcs7_installation_check_*.csv"),
    "0030": os.environ.get("MATRIX_0030_PATTERN", "os_server_v10_validation_*.csv"),
    "0040": os.environ.get("MATRIX_0040_PATTERN", "os_server_systemhardening_v10_validation_*.csv"),
}

# Manuelle Fallback-Mappings fuer nicht-ID-basierte CSVs 0010/0020.
# Die ID-basierten Spalten aus 0030/0040 werden automatisch ueber die echten CSV-Header erkannt.
fallback_task_map = {
    52: [("0010", ["Domaenenmitglied", "Domaene"]), ("0020", ["Domaenenmitglied", "Domaene_Workgroup"])],
    58: [("0020", ["PCS7_Installation_nachgewiesen", "Nachweisqualitaet", "Anzahl_PCS7_Bezugskomponenten"])],
    59: [("0020", ["PCS7_Installation_nachgewiesen", "Nachweisqualitaet", "Anzahl_PCS7_Bezugskomponenten"])],
    60: [("0020", ["PCS7_Installation_nachgewiesen", "Nachweisqualitaet", "Anzahl_PCS7_Bezugskomponenten"])],
    61: [("0020", ["PCS7_Installation_nachgewiesen", "Nachweisqualitaet", "Anzahl_PCS7_Bezugskomponenten"])],
    62: [("0020", ["PCS7_Installation_nachgewiesen", "Nachweisqualitaet", "Anzahl_PCS7_Bezugskomponenten"])],
    63: [("0020", ["PCS7_Installation_nachgewiesen", "Nachweisqualitaet", "Anzahl_PCS7_Bezugskomponenten"])],
    64: [("0020", ["PCS7_Installation_nachgewiesen", "Nachweisqualitaet", "Anzahl_PCS7_Bezugskomponenten"])],
    66: [("0020", ["Anzahl_Siemens_Komponenten", "Alle_Siemens_Komponenten_mit_Version"])],
    110: [("0020", ["Gateway", "IPv4_Adressen", "Subnetzmasken"])],
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

def norm_bool(value):
    v = str(value).strip().lower()
    if v in ("true", "1", "ja", "yes", "y", "wahr", "ok", "erfolgreich", "success"):
        return True
    if v in ("false", "0", "nein", "no", "n", "falsch", "nok", "failed", "fehlgeschlagen"):
        return False
    return None

def clean_text(value):
    if value is None:
        return ""
    return str(value).replace("\r\n", "\n").replace("\r", "\n").strip()

def column_letters_from_ref(cell_ref):
    return re.sub(r"[^A-Z]", "", cell_ref.upper())

def column_index_to_letters(idx):
    letters = ""
    while idx > 0:
        idx, rem = divmod(idx - 1, 26)
        letters = chr(65 + rem) + letters
    return letters

def read_xlsx_rows(path, sheet_name):
    ns_main = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    ns_rel = {"r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships"}
    with zipfile.ZipFile(path) as zf:
        shared_strings = []
        if "xl/sharedStrings.xml" in zf.namelist():
            ss_root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
            for si in ss_root.findall("m:si", ns_main):
                texts = []
                for t in si.findall(".//m:t", ns_main):
                    texts.append(t.text or "")
                shared_strings.append("".join(texts))

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
                    texts = [t.text or "" for t in cell.findall(".//m:t", ns_main)]
                    value = "".join(texts)
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

def normalize_status_from_value(value, column_name):
    v = clean_text(value)
    vl = v.lower()
    col = column_name or ""
    coll = col.lower()

    if not v:
        return None

    if vl in ("ok", "nok"):
        return STATUS_OK if vl == "ok" else STATUS_NOK
    if vl in ("nicht_pruefbar", "nicht prüfbar", "nicht pruefbar", "nicht-pruefbar", "n/a", "na"):
        return STATUS_NP
    if vl in ("teilweise", "partial", "warnung", "warning"):
        return STATUS_NP

    b = norm_bool(v)
    if b is not None:
        return STATUS_OK if b else STATUS_NOK

    if any(token in coll for token in ("anzahl", "count")):
        try:
            return STATUS_OK if float(v.replace(",", ".")) > 0 else STATUS_NOK
        except Exception:
            pass

    # Details- und Infofelder sind nur Nachweise. Wenn sie Inhalt haben, zaehlen sie als OK-Hinweis.
    return STATUS_OK

def combine_status(evidence):
    # evidence: list of (status, direct_status_column_bool)
    evidence = [(s, d) for s, d in evidence if s]
    if not evidence:
        return STATUS_NP
    statuses = [s for s, _ in evidence]
    direct = [s for s, d in evidence if d]

    if STATUS_NOK in statuses:
        return STATUS_NOK

    # Bei direkten ID-Pruefspalten muessen alle direkten Pruefungen OK sein.
    # Beispiel ID89: VNC5800 und VNC5900 muessen beide OK sein.
    if direct:
        if all(s == STATUS_OK for s in direct):
            return STATUS_OK
        return STATUS_NP

    if STATUS_OK in statuses:
        return STATUS_OK
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
            # Nur echte vorhandene CSV-Spalten verwenden. Dadurch werden falsche Excel-Eintraege ignoriert.
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
            task_id = int(m.group(1))
            by_id.setdefault(task_id, []).append(h)
    return by_id

def is_task_id(value):
    try:
        # Excel kann IDs als '1', '1.0' oder Zahl liefern.
        if value is None or clean_text(value) == "":
            return None
        return int(float(clean_text(value).replace(",", ".")))
    except Exception:
        return None

# CSV-Quellen laden
source_files = {}
headers_by_source = {}
rows_by_source = {}
rows_by_source_ip = {}

for src, pattern in source_patterns.items():
    path = latest_file(pattern)
    source_files[src] = path
    headers, rows = read_csv(path) if path else ([], [])
    headers_by_source[src] = headers
    rows_by_source[src] = rows
    indexed = {}
    for r in rows:
        ip = row_ip(r)
        if ip:
            indexed[ip] = r
    rows_by_source_ip[src] = indexed

# IPs aus allen vier CSV-Dateien sammeln
ips = set()
for indexed in rows_by_source_ip.values():
    ips.update(indexed.keys())
ips = sorted(ips, key=ip_sort_key)

# Excel-Vorlage lesen: A-C bleiben, Q/R werden nur intern fuer Mapping genutzt.
template_rows = read_xlsx_rows(template_xlsx, template_sheet)

# Echte ID-Pruefspalten aus 0030 und 0040 erkennen.
id_based_map = {}
for src in ("0030", "0040"):
    for tid, cols in id_columns_from_headers(headers_by_source.get(src, [])).items():
        id_based_map.setdefault(tid, []).append((src, cols))

# Matrix aufbauen
output_rows = []
output_rows.append(["Ansible-ID Protokoll", "Hinweis/System", "Beschreibung"] + ips)

for tr in template_rows:
    task_id = is_task_id(tr.get("A"))
    a = tr.get("A", "")
    b = tr.get("B", "")
    c = tr.get("C", "")

    # Kopfzeilen aus der Vorlage nicht doppelt als Header ausgeben.
    if clean_text(a).lower().startswith("ansible-"):
        continue

    out = [a, b, c]

    if task_id is None:
        out.extend(["" for _ in ips])
        output_rows.append(out)
        continue

    # Mapping-Reihenfolge:
    # 1. Echte ID-Spalten aus 0030/0040
    # 2. Valide Spalten aus Excel-Pruefzuordnung, aber nur wenn sie in der jeweiligen CSV wirklich existieren
    # 3. Manuelle Fallback-Mappings fuer 0010/0020
    mappings = []
    mappings.extend(id_based_map.get(task_id, []))
    mappings.extend(parse_columns_from_mapping_text(tr.get("Q", ""), headers_by_source))
    mappings.extend(parse_columns_from_mapping_text(tr.get("R", ""), headers_by_source))
    mappings.extend(fallback_task_map.get(task_id, []))

    # Duplikate entfernen
    unique_mappings = []
    seen = set()
    for src, cols in mappings:
        valid_cols = []
        available = set(headers_by_source.get(src, []))
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
                status = normalize_status_from_value(value, col)
                direct = bool(re.match(r"^ID0*\d+_", col))
                evidence.append((status, direct))
        out.append(combine_status(evidence))

    output_rows.append(out)

csv_path = output_dir / f"{output_basename}.csv"
meta_path = output_dir / f"{output_basename}_quellen.txt"

with csv_path.open("w", encoding="utf-8-sig", newline="") as fh:
    writer = csv.writer(fh, delimiter=";")
    writer.writerows(output_rows)

with meta_path.open("w", encoding="utf-8") as fh:
    fh.write("0050 Task-Status-Matrix\n")
    fh.write(f"Vorlage: {template_xlsx}\n")
    fh.write(f"CSV-Quellordner: {source_dir}\n")
    fh.write(f"Matrix-Zielordner: {output_dir}\n")
    fh.write(f"Sheet: {template_sheet}\n")
    fh.write("\nVerwendete CSV-Quellen:\n")
    for src in ("0010", "0020", "0030", "0040"):
        fh.write(f"{src}: {source_files.get(src) or 'NICHT GEFUNDEN'}\n")
    fh.write("\nHinweis:\n")
    fh.write("Die Spalten A-C stammen aus der Vorlagen-Excel. Spalten D ff. sind die gefundenen IP-Adressen.\n")
    fh.write("D-R aus der Vorlage werden nicht in die Matrix uebernommen.\n")
    fh.write("ID-basierte Pruefspalten aus 0030/0040 werden aus den echten CSV-Headern erkannt.\n")
    fh.write("Falsche Excel-Pruefzuordnungen werden ignoriert, wenn die angegebene CSV-Spalte nicht existiert.\n")

print(f"CSV={csv_path}")
print(f"META={meta_path}")
print(f"IPS={len(ips)}")
print("SOURCES=" + "; ".join(f"{k}:{v if v else 'NICHT_GEFUNDEN'}" for k, v in source_files.items()))
