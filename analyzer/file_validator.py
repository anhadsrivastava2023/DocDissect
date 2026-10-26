
from pathlib import Path
import zipfile
from email import policy
from email.parser import BytesParser


# Maximum input file size: 25 MB
MAX_FILE_SIZE = 25 * 1024 * 1024

SUPPORTED_EXTENSIONS = {
    ".pdf",
    ".docx",
    ".docm",
    ".xlsx",
    ".xlsm",
    ".eml",
}


def validate_file(file_path):
    """
    Perform basic file-format validation.

    Supports PDF, DOCX, DOCM, XLSX, XLSM and EML.
    Passing validation does not mean a file is safe.
    """

    path = Path(file_path)

    # 1. Check that the path exists and refers to a regular file.
    if not path.exists():
        raise ValueError("File does not exist.")

    if not path.is_file():
        raise ValueError("The supplied path is not a file.")

    # 2. Validate the extension.
    extension = path.suffix.lower()

    if extension not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            f"Unsupported file extension: {extension or '(none)'}"
        )

    # 3. Check file size.
    size_bytes = path.stat().st_size

    if size_bytes == 0:
        raise ValueError("The file is empty.")

    if size_bytes > MAX_FILE_SIZE:
        raise ValueError("File exceeds the 25 MB size limit.")

    # 4. EML-specific validation.
    if extension == ".eml":
        try:
            with path.open("rb") as file:
                message = BytesParser(
                    policy=policy.default
                ).parse(file)

            # Require at least one recognizable email header.
            if not any(
                message.get(header)
                for header in ("From", "To", "Subject", "Date")
            ):
                raise ValueError(
                    "No recognizable email headers were found."
                )

            return {
                "valid": True,
                "file_name": path.name,
                "extension": extension,
                "detected_type": "EML",
                "size_bytes": size_bytes,
                "message": "Basic email validation passed."
            }

        except (OSError, ValueError) as exc:
            raise ValueError(
                f"Invalid EML file: {exc}"
            ) from exc

    # 5. Read the file signature for PDF and Office documents.
    with path.open("rb") as file:
        header = file.read(8)

    if extension == ".pdf":
        if not header.startswith(b"%PDF-"):
            raise ValueError(
                "File extension is PDF, but the PDF signature is missing."
            )

        return {
            "valid": True,
            "file_name": path.name,
            "extension": extension,
            "detected_type": "PDF",
            "size_bytes": size_bytes,
            "message": "Basic format validation passed."
        }

    # 6. Office documents use ZIP-based containers.
    if not header.startswith(b"PK"):
        raise ValueError(
            "Office document does not have a ZIP signature."
        )

    try:
        with zipfile.ZipFile(path, "r") as archive:
            entries = archive.infolist()
            names = {entry.filename for entry in entries}

            # Limit archive complexity.
            if len(entries) > 10000:
                raise ValueError(
                    "Archive contains too many entries."
                )

            total_uncompressed = sum(
                entry.file_size for entry in entries
            )

            if total_uncompressed > 100 * 1024 * 1024:
                raise ValueError(
                    "Expanded archive size exceeds 100 MB."
                )

            if "[Content_Types].xml" not in names:
                raise ValueError(
                    "Missing Office content type information."
                )

            content_types = archive.read(
                "[Content_Types].xml"
            ).lower()

            # 7. Check Word document structure.
            if extension in {".docx", ".docm"}:
                if "word/document.xml" not in names:
                    raise ValueError(
                        "Missing Word document content."
                    )

                macro_enabled = b"macroenabled" in content_types

                if extension == ".docm" and not macro_enabled:
                    raise ValueError(
                        "DOCM macro-enabled content type was not found."
                    )

                if extension == ".docx" and macro_enabled:
                    raise ValueError(
                        "File appears macro-enabled; "
                        "its extension may be incorrect."
                    )

                detected_type = (
                    "DOCM" if extension == ".docm" else "DOCX"
                )

            # 8. Check Excel workbook structure.
            else:
                if "xl/workbook.xml" not in names:
                    raise ValueError(
                        "Missing Excel workbook content."
                    )

                macro_enabled = b"macroenabled" in content_types

                if extension == ".xlsm" and not macro_enabled:
                    raise ValueError(
                        "XLSM macro-enabled content type was not found."
                    )

                if extension == ".xlsx" and macro_enabled:
                    raise ValueError(
                        "File appears macro-enabled; "
                        "its extension may be incorrect."
                    )

                detected_type = (
                    "XLSM" if extension == ".xlsm" else "XLSX"
                )

    except zipfile.BadZipFile as exc:
        raise ValueError(
            "Office document is not a valid ZIP archive."
        ) from exc

    return {
        "valid": True,
        "file_name": path.name,
        "extension": extension,
        "detected_type": detected_type,
        "size_bytes": size_bytes,
        "message": "Basic format validation passed."
    }
