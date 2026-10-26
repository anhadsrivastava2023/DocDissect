
import math
import re
import zipfile
from collections import Counter
from pathlib import Path
from xml.etree import ElementTree

import fitz  # PyMuPDF


# Patterns are investigation indicators, not malware verdicts.
URL_PATTERN = re.compile(
    r"""https?://[^\s"'<>]+""",
    re.IGNORECASE
)

SUSPICIOUS_PATTERNS = {
    "powershell_reference": re.compile(r"\bpowershell(?:\.exe)?\b", re.I),
    "command_shell_reference": re.compile(r"\bcmd\.exe\b", re.I),
    "script_host_reference": re.compile(r"\b(?:wscript|cscript)\.exe\b", re.I),
    "office_auto_macro": re.compile(
        r"\b(?:autoopen|document_open|workbook_open)\b", re.I
    ),
    "object_creation_reference": re.compile(r"\bcreateobject\b", re.I),
    "javascript_reference": re.compile(r"\bjavascript\b", re.I),
    "encoded_content_reference": re.compile(r"\bbase64\b", re.I),
    "process_launch_reference": re.compile(r"\bshell\s*\(", re.I),
}


def calculate_entropy(data):
    """Calculate Shannon entropy in bits per byte (range 0 to 8)."""
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def _extract_xml_text(xml_bytes):
    """Read text nodes from XML without executing embedded content."""
    try:
        root = ElementTree.fromstring(xml_bytes)
        return " ".join(
            text.strip()
            for text in root.itertext()
            if text and text.strip()
        )
    except ElementTree.ParseError:
        return ""


def _extract_office_features(path):
    """Inspect Office ZIP contents and selected XML relationships."""
    features = {
        "embedded_objects": [],
        "external_relationships": [],
        "has_vba_project": False,
        "macro_indicator": False,
        "extracted_text": "",
    }

    text_parts = []

    with zipfile.ZipFile(path, "r") as archive:
        names = archive.namelist()
        name_set = set(names)

        # Record embedded objects without writing them to disk.
        features["embedded_objects"] = [
            name for name in names
            if name.lower().startswith(("word/embeddings/", "xl/embeddings/"))
        ]

        features["has_vba_project"] = any(
            name.lower().endswith("vbaproject.bin")
            for name in names
        )
        features["macro_indicator"] = (
            features["has_vba_project"]
            or path.suffix.lower() in {".docm", ".xlsm"}
        )

        # Extract text from relevant XML files only.
        for name in names:
            lower_name = name.lower()

            if (
                lower_name.startswith("word/")
                or lower_name.startswith("xl/worksheets/")
                or lower_name in {
                    "xl/sharedstrings.xml",
                    "xl/workbook.xml",
                }
            ) and lower_name.endswith(".xml"):
                info = archive.getinfo(name)

                # Avoid parsing unusually large XML entries.
                if info.file_size <= 5 * 1024 * 1024:
                    text_parts.append(
                        _extract_xml_text(archive.read(name))
                    )

        # External relationships can contain linked destinations.
        for name in names:
            if not name.lower().endswith(".rels"):
                continue

            info = archive.getinfo(name)
            if info.file_size > 1024 * 1024:
                continue

            try:
                root = ElementTree.fromstring(archive.read(name))
            except ElementTree.ParseError:
                continue

            for element in root.iter():
                if element.attrib.get("TargetMode", "").lower() == "external":
                    target = element.attrib.get("Target", "")
                    if target:
                        features["external_relationships"].append(target)

    features["external_relationships"] = sorted(
        set(features["external_relationships"])
    )
    features["extracted_text"] = " ".join(text_parts)

    return features


def _extract_pdf_features(path):
    """Extract text and link annotations from a PDF."""
    text_parts = []
    links = []
    indicators = []

    # Open for static inspection only; never execute PDF actions.
    with fitz.open(path) as document:
        for page in document:
            text_parts.append(page.get_text())

            for link in page.get_links():
                uri = link.get("uri")
                if uri:
                    links.append(uri)

    # Inspect raw PDF bytes for structural keywords.
    raw = path.read_bytes()

    for keyword in (
        b"/JavaScript",
        b"/JS",
        b"/EmbeddedFile",
        b"/Launch",
        b"/OpenAction",
        b"/AA",
    ):
        if keyword.lower() in raw.lower():
            indicators.append(keyword.decode("ascii"))

    return {
        "extracted_text": " ".join(text_parts),
        "pdf_links": sorted(set(links)),
        "pdf_structural_indicators": sorted(set(indicators)),
    }


def extract_features(file_path):
    """
    Extract basic static features from a validated supported document.

    Run validate_file() before calling this function.
    """
    path = Path(file_path)

    if not path.is_file():
        raise ValueError("File does not exist or is not a regular file.")

    # Keep the standalone feature extractor bounded too.
    if path.stat().st_size > 25 * 1024 * 1024:
        raise ValueError("File exceeds the 25 MB size limit.")

    extension = path.suffix.lower()

    if extension not in {".pdf", ".docx", ".docm", ".xlsx", ".xlsm"}:
        raise ValueError("Unsupported file format.")

    raw = path.read_bytes()

    result = {
        "file_name": path.name,
        "file_size_bytes": len(raw),
        "entropy": round(calculate_entropy(raw), 4),
        "urls": [],
        "suspicious_patterns": [],
        "embedded_objects": [],
        "external_relationships": [],
        "has_vba_project": False,
        "macro_indicator": False,
        "pdf_links": [],
        "pdf_structural_indicators": [],
        "analysis_notes": [
            "Static indicators do not prove that a file is malicious."
        ],
    }

    if extension == ".pdf":
        extracted = _extract_pdf_features(path)
        text = extracted["extracted_text"]

        result["pdf_links"] = extracted["pdf_links"]
        result["pdf_structural_indicators"] = (
            extracted["pdf_structural_indicators"]
        )

    else:
        extracted = _extract_office_features(path)
        text = extracted["extracted_text"]

        result["embedded_objects"] = extracted["embedded_objects"]
        result["external_relationships"] = (
            extracted["external_relationships"]
        )
        result["has_vba_project"] = extracted["has_vba_project"]
        result["macro_indicator"] = extracted["macro_indicator"]

    # Search extracted text and external relationships for URLs.
    searchable_text = text + " " + " ".join(
        result["external_relationships"]
    )

    urls = URL_PATTERN.findall(searchable_text)
    urls.extend(result["pdf_links"])

    # Remove common punctuation that follows a URL in prose.
    result["urls"] = sorted({
        url.rstrip(".,;:!?)]}")
        for url in urls
    })

    # Flag patterns for later heuristic analysis.
    result["suspicious_patterns"] = [
        name
        for name, pattern in SUSPICIOUS_PATTERNS.items()
        if pattern.search(searchable_text)
    ]

    result["extracted_text_length"] = len(text)

    return result
