
import math
import re
import zipfile
from collections import Counter
from pathlib import Path

import openpyxl


def calculate_entropy(text):
    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def extract_excel_model_features(filepath):
    path = Path(filepath)
    extension = path.suffix.lower()

    if extension not in {".xlsx", ".xlsm"}:
        raise ValueError(
            "Excel ML currently supports .xlsx and .xlsm files only."
        )

    all_text = []

    # Match the original spreadsheet reader's cell-text collection.
    workbook = openpyxl.load_workbook(
        path,
        data_only=False,
        keep_links=True,
        read_only=False,
    )

    try:
        numeric_cell_count = 0
        string_cell_count = 0

        for sheet in workbook.worksheets:
            for row in sheet.iter_rows():
                for cell in row:
                    value = cell.value

                    text = (
                        str(value).strip()
                        if value is not None
                        else ""
                    )

                    if text:
                        all_text.append(text)

                        if isinstance(value, str):
                            string_cell_count += 1
                        elif isinstance(value, (int, float)):
                            numeric_cell_count += 1
    finally:
        workbook.close()

    joined = "\n".join(all_text)
    lines = joined.splitlines()
    tokens = re.findall(r"\w+", joined)

    # Preserve the original script's remote-template calculation.
    remote_template_present = 0
    try:
        with zipfile.ZipFile(path, "r") as archive:
            for name in archive.namelist():
                if name.lower().endswith(".xml"):
                    with archive.open(name) as xml_file:
                        xml_text = xml_file.read().decode(
                            "utf-8",
                            errors="ignore",
                        ).lower()

                    if "http://" in xml_text or "https://" in xml_text:
                        remote_template_present = 1
                        break
    except zipfile.BadZipFile as error:
        raise ValueError("Invalid Excel OpenXML archive.") from error

    return {
        "entropy_of_text": calculate_entropy(joined),
        "macro_chr_count": joined.lower().count("chr"),
        "macro_vocab_size": len(set(tokens)),
        "macro_arithmetic_operator_count": sum(
            joined.count(operator)
            for operator in ["+", "-", "*", "/"]
        ),
        "macro_token_count": len(set(tokens)),
        "macro_max_line_length": max(
            (len(line) for line in lines),
            default=0,
        ),
        "remote_template_present": remote_template_present,
        "numeric_cell_count": numeric_cell_count,
        "string_cell_count": string_cell_count,
        "avg_cell_length": (
            sum(len(text) for text in all_text) / len(all_text)
            if all_text
            else 0.0
        ),
    }
