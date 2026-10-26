# =============================================================
# Word Static Feature Extraction — 43 Features (cleaned)
# Extracts the exact 43 features found in Malicious_top43.csv
# Supports: .docx .docm .dotx .dotm .doc .dot
# =============================================================

import os, re, math, zipfile, warnings
from collections import Counter
import pandas as pd

warnings.filterwarnings("ignore")

# Optional deps
try:
    from oletools.olevba import VBA_Parser
    HAVE_OLEVBA = True
except Exception:
    HAVE_OLEVBA = False

try:
    import olefile  # for legacy OLE container traversal (.doc/.dot)
    HAVE_OLEFILE = True
except Exception:
    HAVE_OLEFILE = False

# ---------- Feature schema (keep exact order!) ----------
FEATURE_ORDER = [
    "ole_object_count",
    "ole_object_type_count",
    "macro_present",
    "dde_present",
    "vba_keywords_count",
    "entropy",
    "struct_ContentType",
    "struct_PartName",
    "file_size",
    "struct_pos",
    "struct_val",
    "struct_typeface",
    "struct_script",
    "path_/w-p",
    "path_w-r",
    "path_/w-r",
    "path_a-hlink",
    "path_w-p",
    "path_a-accent3",
    "struct_ang",
    "path_/a-effectLst",
    "path_a-themeElements",
    "struct_dist",
    "path_a-alpha",
    "struct_Extension",
    "path_a-dk1",
    "path_a-ln",
    "path_/a-accent6",
    "struct_w",
    "struct_name",
    "path_a-lt2",
    "path_/a-outerShdw",
    "path_a-accent4",
    "path_/a-dk1",
    "path_a-accent1",
    "path_a-sysClr",
    "path_a-lt1",
    "path_/a-accent4",
    "struct_{http://schemas.openxmlformats.org/wordprocessingml/2006/main}sz",
    "path_a-solidFill",
    "struct_{http://schemas.openxmlformats.org/wordprocessingml/2006/main}themeFill",
    "struct_{http://schemas.openxmlformats.org/wordprocessingml/2006/main}csb1",
    "struct_{http://schemas.openxmlformats.org/wordprocessingml/2006/main}styleId",
]

ALL_COLUMNS = ["file_path"] + FEATURE_ORDER

# ---------- Utilities ----------
def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    probs = [n / len(text) for n in Counter(text).values()]
    return -sum(p * math.log2(p) for p in probs)

def safe_read_zip_entry(z: zipfile.ZipFile, name: str) -> str:
    try:
        with z.open(name) as f:
            return f.read().decode(errors="ignore")
    except Exception:
        return ""

def init_feature_row(filepath: str) -> dict:
    row = {c: 0 for c in ALL_COLUMNS}
    row["file_path"] = filepath
    try:
        row["file_size"] = os.path.getsize(filepath)
    except Exception:
        row["file_size"] = 0
    return row

# ---------- OLE object counting for legacy .doc/.dot ----------
def count_ole_in_olefile(path: str):
    """
    Return (ole_object_count, ole_object_type_count) for legacy OLE files using olefile.
    We consider storages/streams under 'ObjectPool' and names containing 'Ole' or 'Embedded'.
    Type count is number of unique extensions we can infer.
    """
    if not HAVE_OLEFILE:
        return 0, 0
    try:
        if not olefile.isOleFile(path):
            return 0, 0
        with olefile.OleFileIO(path) as ole:
            names = ole.listdir(streams=True, storages=True)
            # Count likely embedded objects
            cand = ["/".join(n) for n in names if any(s.lower() in ("objectpool", "ole", "\x01ole") for s in n)]
            count = len(cand)
            # Infer types from names (best-effort)
            exts = set()
            for n in cand:
                base = os.path.basename(n)
                _, ext = os.path.splitext(base)
                if ext:
                    exts.add(ext.lower())
            return count, len(exts)
    except Exception:
        return 0, 0

# ---------- Main extractor ----------
def extract_word_features(filepath: str) -> dict:
    feats = init_feature_row(filepath)
    text_all = ""

    # Case A: OOXML (.docx/.docm/.dotx/.dotm) — zip container
    if zipfile.is_zipfile(filepath):
        try:
            with zipfile.ZipFile(filepath, "r") as z:
                names = z.namelist()
                # path_* features: count by ZIP member path
                for name in names:
                    low = name.lower()
                    for key in FEATURE_ORDER:
                        if key.startswith("path_"):
                            needle = key[5:].lower()  # after "path_"
                            if needle and needle in low:
                                feats[key] += 1

                # struct_* features and entropy: count within XML text
                xml_files = [n for n in names if n.lower().endswith(".xml")]
                for n in xml_files:
                    xml_text = safe_read_zip_entry(z, n)
                    if not xml_text:
                        continue
                    text_all += xml_text
                    for key in FEATURE_ORDER:
                        if key.startswith("struct_"):
                            needle = key[7:]  # after "struct_"
                            if needle:
                                feats[key] += xml_text.count(needle)

                feats["entropy"] = calculate_entropy(text_all)

                # OLE objects embedded (OOXML): typically under word/embeddings/
                ole_like = [n for n in names if "/embeddings/" in n.lower()]
                feats["ole_object_count"] += len(ole_like)
                type_exts = set(os.path.splitext(n)[1].lower() for n in ole_like if os.path.splitext(n)[1])
                feats["ole_object_type_count"] += len(type_exts)

                # Macros & DDE
                if HAVE_OLEVBA:
                    vb = VBA_Parser(filepath)
                    try:
                        if vb.detect_vba_macros():
                            feats["macro_present"] = 1
                            vba_text = ""
                            for (_, _, _, vba_code) in vb.extract_macros():
                                if vba_code:
                                    vba_text += vba_code + "\n"
                            if vba_text:
                                feats["vba_keywords_count"] = len(re.findall(
                                    r"\b(CreateObject|Shell|AppActivate|Environ|Execute|FileCopy|Dir|Kill|Put|Get|Open)\b",
                                    vba_text, re.IGNORECASE))
                                feats["dde_present"] = int(("DDEAUTO" in vba_text) or ("DDE" in vba_text))
                    finally:
                        vb.close()

        except Exception as e:
            # Keep going; file may be odd ZIP
            # print(f"ZIP parse error: {filepath} — {e}")
            pass

    # Case B: Legacy OLE (.doc/.dot)
    else:
        ext = os.path.splitext(filepath)[1].lower()
        if ext in (".doc", ".dot"):
            # OLE object counts via olefile (if available)
            c, t = count_ole_in_olefile(filepath)
            feats["ole_object_count"] += c
            feats["ole_object_type_count"] += t

            # Macros & DDE via olevba (if available)
            if HAVE_OLEVBA:
                try:
                    vb = VBA_Parser(filepath)
                    try:
                        if vb.detect_vba_macros():
                            feats["macro_present"] = 1
                            vba_text = ""
                            for (_, _, _, vba_code) in vb.extract_macros():
                                if vba_code:
                                    vba_text += vba_code + "\n"
                            if vba_text:
                                feats["vba_keywords_count"] = len(re.findall(
                                    r"\b(CreateObject|Shell|AppActivate|Environ|Execute|FileCopy|Dir|Kill|Put|Get|Open)\b",
                                    vba_text, re.IGNORECASE))
                                feats["dde_present"] = int(("DDEAUTO" in vba_text) or ("DDE" in vba_text))
                                feats["entropy"] = calculate_entropy(vba_text)
                    finally:
                        vb.close()
                except Exception:
                    pass

    # Ensure only the 43 features (plus file_path) go out
    # Fill missing struct/path keys (if any) with 0
    for key in FEATURE_ORDER:
        feats.setdefault(key, 0)

    # Return a row with exact columns
    return {col: feats.get(col, 0 if col != "file_path" else feats["file_path"]) for col in ALL_COLUMNS}

# ---------- Batch ----------
def process_word_folder(input_folder: str, output_csv: str):
    rows = []
    total = failed = 0
    for root, _, files in os.walk(input_folder):
        for fname in files:
            if fname.lower().endswith((".docx", ".docm", ".dotx", ".dotm", ".doc", ".dot")):
                total += 1
                fpath = os.path.join(root, fname)
                try:
                    row = extract_word_features(fpath)
                    rows.append(row)
                except Exception as e:
                    failed += 1
                    # print(f"Failed: {fpath} — {e}")
    if rows:
        df = pd.DataFrame(rows, columns=ALL_COLUMNS)  # enforce order
        os.makedirs(os.path.dirname(output_csv), exist_ok=True)
        df.to_csv(output_csv, index=False)
    print(f"✅ Processed: {total - failed}/{total}  →  {output_csv}")

input_folder = "Put your input path here"
output_csv   = "Put your output path here"

process_word_folder(input_folder, output_csv)

