import hashlib
import json
import tempfile
from pathlib import Path
from email.utils import parseaddr

import streamlit as st

from analyzer.file_validator import validate_file
from analyzer.hashing import get_file_metadata
from analyzer.feature_extractor import extract_features
from analyzer.heuristic_engine import analyze_features
from analyzer.ml_detector import predict_document

from analyzer.model_feature_adapter import (
    adapt_word_features,
    adapt_pdf_features,
    adapt_excel_features,
)

from analyzer.pdf_model_features import extract_pdf_model_features
from analyzer.excel_model_features import extract_excel_model_features
from analyzer.email_analyzer import analyze_eml


# --------------------------------------------------
# Application configuration
# --------------------------------------------------

st.set_page_config(
    page_title="Document Malware Analyzer",
    page_icon="🛡️",
    layout="wide",
)

SUPPORTED = {
    ".pdf", ".docx", ".docm", ".xlsx", ".xlsm", ".eml"
}

WORD_EXTENSIONS = {".docx", ".docm"}
EXCEL_EXTENSIONS = {".xlsx", ".xlsm"}
DOCUMENT_EXTENSIONS = {
    ".pdf", ".docx", ".docm", ".xlsx", ".xlsm"
}

MAX_SIZE = 25 * 1024 * 1024


# --------------------------------------------------
# Existing document-analysis pipeline
# --------------------------------------------------

def analyze_document_path(file_path, filename, extension):
    """Run the existing validation, heuristic and ML pipeline."""

    validation = validate_file(file_path)

    if not validation.get("valid", False):
        raise ValueError(
            validation.get("message", "File validation failed.")
        )

    metadata = get_file_metadata(file_path)
    features = extract_features(file_path)
    detection = analyze_features(features)

    model_type = None
    model_features = None

    if extension in WORD_EXTENSIONS:
        from word_feature_extractor_original import (
            extract_word_features,
        )

        raw_ml_features = extract_word_features(file_path)
        model_features = adapt_word_features(raw_ml_features)
        model_type = "word"

    elif extension == ".pdf":
        raw_ml_features = extract_pdf_model_features(file_path)
        model_features = adapt_pdf_features(raw_ml_features)
        model_type = "pdf"

    elif extension in EXCEL_EXTENSIONS:
        raw_ml_features = extract_excel_model_features(file_path)
        model_features = adapt_excel_features(raw_ml_features)
        model_type = "excel"

    ml_result = None

    if model_type is not None:
        ml_result = predict_document(
            model_type,
            model_features,
        )

    return {
        "filename": filename,
        "extension": extension,
        "validation": validation,
        "metadata": metadata,
        "features": features,
        "heuristic_detection": detection,
        "ml_prediction": ml_result,
        "ml_features": model_features,
    }


# --------------------------------------------------
# Email-level indicator analysis
# --------------------------------------------------

def analyze_email_indicators(email_report, body_text):
    """
    Produce basic email indicators.

    This is a simple heuristic summary, not a trained phishing
    detector and not a definitive safety classification.
    """

    findings = []
    score = 0

    sender = email_report.get("sender", "")
    reply_to = email_report.get("reply_to", "")
    urls = email_report.get("urls", [])
    attachment_count = email_report.get("attachment_count", 0)

    sender_address = parseaddr(sender)[1].lower()
    reply_address = parseaddr(reply_to)[1].lower()

    if not sender_address:
        findings.append({
            "indicator": "Sender address unavailable",
            "evidence": "No parseable sender email address was found.",
            "points": 5,
        })
        score += 5

    if sender_address and reply_address:
        sender_domain = sender_address.rsplit("@", 1)[-1]
        reply_domain = reply_address.rsplit("@", 1)[-1]

        if sender_domain != reply_domain:
            findings.append({
                "indicator": "Sender and Reply-To domains differ",
                "evidence": (
                    f"From domain: {sender_domain}; "
                    f"Reply-To domain: {reply_domain}"
                ),
                "points": 15,
            })
            score += 15

    if urls:
        findings.append({
            "indicator": "URLs found in email body",
            "evidence": f"Found {len(urls)} unique URL(s).",
            "points": 5,
        })
        score += 5

    if attachment_count:
        findings.append({
            "indicator": "Email contains attachments",
            "evidence": (
                f"Found {attachment_count} attachment(s). "
                "Attachments require individual inspection."
            ),
            "points": 5,
        })
        score += 5

    body_lower = body_text.lower()

    urgency_phrases = (
        "verify your account",
        "account will be suspended",
        "urgent action required",
        "click here immediately",
        "confirm your password",
    )

    matched_phrases = [
        phrase for phrase in urgency_phrases
        if phrase in body_lower
    ]

    if matched_phrases:
        findings.append({
            "indicator": "Potentially suspicious urgency or credential wording",
            "evidence": ", ".join(matched_phrases),
            "points": 10,
        })
        score += 10

    return {
        "indicator_score": min(score, 100),
        "findings": findings,
        "disclaimer": (
            "This score reflects a small set of static indicators only. "
            "It is not a calibrated probability of phishing or malware. "
            "A low score does not establish that an email is safe."
        ),
    }


# --------------------------------------------------
# Display helpers
# --------------------------------------------------

def display_ml_result(ml_result, model_features=None):
    st.subheader("Machine-learning analysis")

    if ml_result is None:
        st.info("No machine-learning prediction was produced.")
        return

    label = str(ml_result["predicted_label"])
    model_name = ml_result["model_type"].upper()

    st.write(f"**Model:** {model_name}")
    st.write(f"**Predicted label:** {label}")

    if label == "1":
        st.warning(
            f"The {model_name} model classified this document "
            "as malicious."
        )
    elif label == "0":
        st.info(
            f"The {model_name} model classified this document "
            "as benign."
        )
    else:
        st.warning(f"The model returned label {label}.")

    probabilities = ml_result.get("class_probabilities", {})

    if probabilities:
        st.write("**Class probabilities**")

        for class_label, probability in probabilities.items():
            if str(class_label) == "0":
                class_name = "Benign (label 0)"
            elif str(class_label) == "1":
                class_name = "Malicious (label 1)"
            else:
                class_name = f"Label {class_label}"

            st.write(f"{class_name}: {probability:.2%}")

    if ml_result.get("disclaimer"):
        st.caption(ml_result["disclaimer"])

    if model_features is not None:
        with st.expander("Model input features"):
            st.json(model_features)


def display_document_result(result):
    detection = result["heuristic_detection"]

    st.subheader(f"Document results: {result['filename']}")

    first, second, third = st.columns(3)

    first.metric(
        "Risk score",
        f"{detection['risk_score']}/100",
    )
    second.metric(
        "Classification",
        detection["classification"],
    )
    third.metric(
        "Findings",
        len(detection["findings"]),
    )

    with st.expander("Validation and file metadata"):
        st.json({
            "validation": result["validation"],
            "metadata": result["metadata"],
        })

    st.write("**Heuristic findings**")

    if detection["findings"]:
        for finding in detection["findings"]:
            with st.expander(finding["rule"]):
                st.write(f"Points: {finding['points']}")
                st.write("Evidence:", finding["evidence"])
    else:
        st.write("No configured heuristic rules were triggered.")

    if detection.get("disclaimer"):
        st.caption(detection["disclaimer"])

    display_ml_result(
        result["ml_prediction"],
        result["ml_features"],
    )

    with st.expander("Extracted static-analysis features"):
        st.json(result["features"])


# --------------------------------------------------
# User interface
# --------------------------------------------------

st.title("🛡️ DocDissect")

st.write(
    "Upload a document or an EML email for static analysis. "
    "Supported document attachments inside EML files are also "
    "analysed using the existing document pipeline."
)

st.info(
    "Files and attachments are not executed. "
    "A low heuristic score or a benign ML prediction does not "
    "guarantee that a file or email is safe."
)

uploaded = st.file_uploader(
    "Choose a document or email",
    type=[
        "pdf", "docx", "docm", "xlsx", "xlsm", "eml"
    ],
)


# --------------------------------------------------
# Upload validation
# --------------------------------------------------

if uploaded is not None:
    filename = Path(uploaded.name).name
    extension = Path(filename).suffix.lower()
    content = uploaded.getvalue()

    st.write(f"**Selected file:** {filename}")
    st.write(f"**Size:** {len(content):,} bytes")

    if extension not in SUPPORTED:
        st.error("Unsupported file format.")
        st.stop()

    if len(content) > MAX_SIZE:
        st.error("File exceeds the 25 MB upload limit.")
        st.stop()

    button_label = (
        "Analyze email and attachments"
        if extension == ".eml"
        else "Analyze document"
    )

    if st.button(button_label, type="primary"):
        temp_paths = []

        try:
            with st.spinner(
                "Analyzing email and supported attachments..."
                if extension == ".eml"
                else "Analyzing document..."
            ):

                # ==========================================
                # EML ANALYSIS PATH
                # ==========================================

                if extension == ".eml":
                    with tempfile.NamedTemporaryFile(
                        suffix=".eml",
                        prefix="email_scan_",
                        delete=False,
                    ) as temp:
                        temp.write(content)
                        eml_path = temp.name
                        temp_paths.append(eml_path)

                    email_report, body_text, attachments = (
                        analyze_eml(eml_path)
                    )

                    email_indicators = analyze_email_indicators(
                        email_report,
                        body_text,
                    )

                    # Add Reply-To and authentication-related
                    # headers to the displayed report.
                    # These headers are evidence, not proof
                    # that a message is authentic.
                    from email import policy
                    from email.parser import BytesParser

                    with open(eml_path, "rb") as email_file:
                        parsed_message = BytesParser(
                            policy=policy.default
                        ).parse(email_file)

                    email_report["reply_to"] = str(
                        parsed_message.get("Reply-To", "")
                    )

                    email_report["authentication_headers"] = {
                        header: [
                            str(value)
                            for value in parsed_message.get_all(
                                header, []
                            )
                        ]
                        for header in (
                            "Authentication-Results",
                            "Received-SPF",
                            "DKIM-Signature",
                        )
                        if parsed_message.get_all(header, [])
                    }

                    # Recalculate indicators after adding Reply-To.
                    email_indicators = analyze_email_indicators(
                        email_report,
                        body_text,
                    )

                    report = {
                        "filename": filename,
                        "file_type": "eml",
                        "email_analysis": email_report,
                        "email_body_text": body_text,
                        "email_indicators": email_indicators,
                        "attachment_analysis": [],
                        "ml_prediction": None,
                        "note": (
                            "No ML model is applied to the EML email "
                            "itself. Supported document attachments "
                            "are analysed individually."
                        ),
                    }

                    st.success("Email parsing completed.")

                    # --------------------------------------
                    # Email summary
                    # --------------------------------------

                    st.header("Email analysis")

                    st.subheader("Email details")
                    st.json({
                        "subject": email_report["subject"],
                        "sender": email_report["sender"],
                        "recipient": email_report["recipient"],
                        "reply_to": email_report["reply_to"],
                        "date": email_report["date"],
                        "body_text_length": (
                            email_report["body_text_length"]
                        ),
                        "attachment_count": (
                            email_report["attachment_count"]
                        ),
                    })

                    st.subheader("Email indicators")

                    first, second = st.columns(2)
                    first.metric(
                        "Indicator score",
                        f"{email_indicators['indicator_score']}/100",
                    )
                    second.metric(
                        "Indicators found",
                        len(email_indicators["findings"]),
                    )

                    for finding in email_indicators["findings"]:
                        with st.expander(finding["indicator"]):
                            st.write(finding["evidence"])
                            st.write(
                                f"Indicator points: {finding['points']}"
                            )

                    st.caption(email_indicators["disclaimer"])

                    st.subheader("URLs found in email body")

                    if email_report["urls"]:
                        for url in email_report["urls"]:
                            # Display only; do not open automatically.
                            st.code(url)
                    else:
                        st.write("No URLs were found in the plain-text body.")

                    with st.expander("Plain-text email body"):
                        st.text(body_text or "No plain-text body found.")

                    with st.expander("Authentication-related headers"):
                        st.json(
                            email_report["authentication_headers"]
                        )

                    # --------------------------------------
                    # Attachment analysis
                    # --------------------------------------

                    st.header("Attachment analysis")

                    if not attachments:
                        st.info("No attachments were found.")

                    for index, attachment in enumerate(
                        attachments, start=1
                    ):
                        attachment_name = attachment["file_name"]
                        attachment_extension = (
                            Path(attachment_name).suffix.lower()
                        )
                        payload = attachment["_payload"]

                        st.subheader(
                            f"Attachment {index}: {attachment_name}"
                        )

                        st.write(
                            f"**Content type:** "
                            f"{attachment['content_type']}"
                        )
                        st.write(
                            f"**Size:** {attachment['size_bytes']:,} bytes"
                        )
                        st.code(
                            f"SHA-256: {attachment['sha256']}"
                        )

                        attachment_result = {
                            key: value
                            for key, value in attachment.items()
                            if key != "_payload"
                        }
                        attachment_result["analysis"] = None
                        attachment_result["analysis_error"] = None

                        if (
                            attachment_extension
                            not in DOCUMENT_EXTENSIONS
                        ):
                            st.info(
                                "This attachment type is not supported "
                                "by the document-analysis pipeline. "
                                "It was not opened or executed."
                            )

                        elif not payload:
                            st.warning(
                                "The attachment is empty; it cannot "
                                "be analysed."
                            )
                            attachment_result["analysis_error"] = (
                                "Attachment is empty."
                            )

                        else:
                            attachment_temp_path = None

                            try:
                                with tempfile.NamedTemporaryFile(
                                    suffix=attachment_extension,
                                    prefix="attachment_scan_",
                                    delete=False,
                                ) as attachment_temp:
                                    attachment_temp.write(payload)
                                    attachment_temp_path = (
                                        attachment_temp.name
                                    )
                                    temp_paths.append(
                                        attachment_temp_path
                                    )

                                result = analyze_document_path(
                                    attachment_temp_path,
                                    attachment_name,
                                    attachment_extension,
                                )

                                attachment_result["analysis"] = result

                                with st.expander(
                                    "View attachment analysis results",
                                    expanded=True,
                                ):
                                    display_document_result(result)

                            except (
                                ValueError,
                                OSError,
                                RuntimeError,
                            ) as error:
                                attachment_result["analysis_error"] = (
                                    str(error)
                                )
                                st.warning(
                                    f"Attachment analysis failed: {error}"
                                )

                            except Exception as error:
                                attachment_result["analysis_error"] = (
                                    f"{type(error).__name__}: {error}"
                                )
                                st.warning(
                                    "Unexpected attachment-analysis error: "
                                    f"{type(error).__name__}: {error}"
                                )

                        report["attachment_analysis"].append(
                            attachment_result
                        )

                    # The EML itself has no ML prediction.
                    st.info(
                        "The email itself was not sent to an ML model. "
                        "Any ML predictions above belong to individual "
                        "supported document attachments."
                    )

                # ==========================================
                # DIRECT DOCUMENT ANALYSIS PATH
                # ==========================================

                else:
                    with tempfile.NamedTemporaryFile(
                        suffix=extension,
                        prefix="document_scan_",
                        delete=False,
                    ) as temp:
                        temp.write(content)
                        document_path = temp.name
                        temp_paths.append(document_path)

                    report = analyze_document_path(
                        document_path,
                        filename,
                        extension,
                    )

                    st.success("Document analysis completed.")
                    display_document_result(report)

                # ==========================================
                # JSON REPORT DOWNLOAD
                # ==========================================

                report_json = json.dumps(
                    report,
                    indent=2,
                    default=str,
                )

                st.divider()
                st.download_button(
                    "Download JSON report",
                    data=report_json,
                    file_name="scan_report.json",
                    mime="application/json",
                )

        except (
            ValueError,
            OSError,
            RuntimeError,
        ) as error:
            st.error(f"Analysis failed: {error}")

        except Exception as error:
            st.error(
                f"Unexpected error: {type(error).__name__}: {error}"
            )

        finally:
            for temp_path in temp_paths:
                try:
                    path = Path(temp_path)
                    if path.exists():
                        path.unlink()
                except OSError:
                    pass
