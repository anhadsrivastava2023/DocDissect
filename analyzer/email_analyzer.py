
import hashlib
import re
from email import policy
from email.parser import BytesParser


URL_PATTERN = re.compile(
    r"""https?://[^\s<>"']+""",
    re.IGNORECASE,
)

SUPPORTED_EXTENSIONS = (
    ".pdf",
    ".docx",
    ".docm",
    ".xlsx",
    ".xlsm",
)

MAX_ATTACHMENTS = 50
MAX_TOTAL_ATTACHMENT_BYTES = 20 * 1024 * 1024


def analyze_eml(file_path):
    """Parse an EML email and inspect its content and attachments."""

    with open(file_path, "rb") as file:
        message = BytesParser(
            policy=policy.default
        ).parse(file)

    body_parts = []
    attachments = []
    total_attachment_bytes = 0

    for part in message.walk():
        if part.is_multipart():
            continue

        filename = part.get_filename()
        content_type = part.get_content_type()
        disposition = part.get_content_disposition()

        if filename or disposition == "attachment":
            if len(attachments) >= MAX_ATTACHMENTS:
                raise ValueError(
                    "Email exceeds the attachment count limit."
                )

            payload = part.get_payload(decode=True) or b""
            total_attachment_bytes += len(payload)

            if total_attachment_bytes > MAX_TOTAL_ATTACHMENT_BYTES:
                raise ValueError(
                    "Total decoded attachment size exceeds 20 MB."
                )

            attachment_name = filename or "unnamed_attachment"
            extension_supported = attachment_name.lower().endswith(
                SUPPORTED_EXTENSIONS
            )

            attachments.append({
                "file_name": attachment_name,
                "content_type": content_type,
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "supported_for_document_analysis": extension_supported,
                # Internal binary data; exclude from the JSON report.
                "_payload": payload,
            })

        elif content_type == "text/plain":
            try:
                body = part.get_content()
                if isinstance(body, str):
                    body_parts.append(body)
            except (LookupError, UnicodeError):
                continue

    body_text = "\n".join(body_parts)

    urls = sorted({
        url.rstrip(".,;:!?)]}")
        for url in URL_PATTERN.findall(body_text)
    })

    report = {
        "subject": str(message.get("Subject", "")),
        "sender": str(message.get("From", "")),
        "recipient": str(message.get("To", "")),
        "date": str(message.get("Date", "")),
        "body_text_length": len(body_text),
        "urls": urls,
        "attachment_count": len(attachments),
        "attachments": [
            {
                key: value
                for key, value in attachment.items()
                if key != "_payload"
            }
            for attachment in attachments
        ],
    }

    return report, body_text, attachments
