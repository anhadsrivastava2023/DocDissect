
import math
import re
from pathlib import Path
from collections import Counter

import fitz
import PyPDF2


def calculate_entropy(text):
    if not text:
        return 0.0

    counts = Counter(ord(char) % 256 for char in text)
    length = len(text)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def extract_pdf_model_features(filepath):
    path = Path(filepath)
    raw_bytes = path.read_bytes()
    raw = raw_bytes.decode("latin-1")

    features = {
        "text_length": 0,
        "total_filters": raw.count("/Filter"),
        "title_chars": 0,
        "file_size": len(raw_bytes),
        "object_count": 0,
        "stream_count": raw.count("stream"),
        "endstream_count": raw.count("endstream"),
        "metadata_size": 0,
        "valid_pdf_header": int(
            raw_bytes[:1024].decode("latin-1").startswith("%PDF")
        ),
        "entropy_of_streams": 0.0,
    }

    # PDF metadata and page text.
    with open(path, "rb") as file:
        reader = PyPDF2.PdfReader(file, strict=False)

        metadata = reader.metadata
        if metadata:
            features["metadata_size"] = len(str(metadata))
            title = metadata.get("/Title") or path.name
        else:
            title = path.name

        features["title_chars"] = len(str(title))

    # Match the original extractor's structural calculations.
    try:
        document = fitz.open(str(path))
        try:
            features["object_count"] = document.xref_length()
            features["text_length"] = sum(
                len(page.get_text()) for page in document
            )
        finally:
            document.close()
    except Exception:
        # A parsing failure should not silently create a prediction.
        raise ValueError(
            "Could not extract PDF structure and text reliably."
        )

    # Calculate mean entropy of raw stream sections.
    matches = re.finditer(
        r"stream(.*?)endstream",
        raw,
        re.DOTALL,
    )
    entropies = [
        calculate_entropy(match.group(1))
        for match in matches
        if match.group(1)
    ]

    features["entropy_of_streams"] = (
        sum(entropies) / len(entropies)
        if entropies
        else 0.0
    )

    return features
