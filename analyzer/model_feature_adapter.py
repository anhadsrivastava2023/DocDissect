
WORD_FEATURES = [
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
]


PDF_FEATURES = [
    "text_length",
    "total_filters",
    "title_chars",
    "file_size",
    "object_count",
    "stream_count",
    "endstream_count",
    "metadata_size",
    "valid_pdf_header",
    "entropy_of_streams",
]

EXCEL_FEATURES = [
    "entropy_of_text",
    "macro_chr_count",
    "macro_vocab_size",
    "macro_arithmetic_operator_count",
    "macro_token_count",
    "macro_max_line_length",
    "remote_template_present",
    "numeric_cell_count",
    "string_cell_count",
    "avg_cell_length",
]


def _validate_numeric_features(features, required, file_type):
    missing = [name for name in required if name not in features]

    if missing:
        raise ValueError(
            f"Missing {file_type} model features: {missing}"
        )

    result = {}

    for name in required:
        value = features[name]

        if isinstance(value, bool):
            value = int(value)

        if not isinstance(value, (int, float)):
            raise ValueError(
                f"{file_type} feature {name} is not numeric."
            )

        result[name] = value

    return result


def adapt_pdf_features(features):
    return _validate_numeric_features(
        features,
        PDF_FEATURES,
        "PDF",
    )


def adapt_excel_features(features):
    return _validate_numeric_features(
        features,
        EXCEL_FEATURES,
        "Excel",
    )

def adapt_word_features(features):
    """Convert original Word extractor output into the model's feature schema."""
    missing = [name for name in WORD_FEATURES if name not in features]

    if missing:
        raise ValueError(
            f"Cannot predict Word document: missing features {missing}"
        )

    result = {name: features[name] for name in WORD_FEATURES}

    # Validate values before passing them to the model.
    for name, value in result.items():
        if isinstance(value, bool):
            result[name] = int(value)
        elif not isinstance(value, (int, float)):
            raise ValueError(
                f"Invalid Word feature {name}: expected a number, "
                f"received {type(value).__name__}"
            )

    return result

