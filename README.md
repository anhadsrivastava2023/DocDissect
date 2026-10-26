# DocDissect — Document Malware Analyzer

DocDissect is a Python application for static analysis of documents and email files. It combines file validation, metadata and feature extraction, heuristic indicators, and machine-learning predictions for supported Office and PDF documents.


## Features

- **Supported direct uploads:** PDF (`.pdf`), Word (`.docx`, `.docm`), Excel (`.xlsx`, `.xlsm`), and email (`.eml`).
- **Document validation:** Performs basic format validation before analysis.
- **Metadata and static features:** Extracts file metadata and configured document indicators.
- **Heuristic analysis:** Reports rule-based findings and a risk score.
- **Machine-learning predictions:** Uses existing trained models for Word, PDF, and Excel documents.
- **Email analysis:** Parses common email headers, extracts plain-text body content and URLs, and reports attachment metadata and SHA-256 hashes.
- **Attachment routing:** Supported PDF, Word, and Excel attachments inside an EML file are sent through the corresponding document-analysis pipeline.
- **JSON report:** Allows the analysis report to be downloaded for review or record keeping.
- **No file execution:** The application does not intentionally execute uploaded documents or attachments.

## Supported formats and analysis

| File type | Heuristic/static analysis | ML model |
|---|---|---|
| PDF (`.pdf`) | Yes | PDF model |
| Word (`.docx`, `.docm`) | Yes | Word model |
| Excel (`.xlsx`, `.xlsm`) | Yes | Excel model |
| Email (`.eml`) | Email-level indicators and metadata | No EML model |
| Supported document attachment in an EML | Same pipeline as a direct document upload | Corresponding document model |
| Other email attachment types | Metadata and SHA-256 hash only | Not supported |

The email-level checks are basic indicators, not a dedicated phishing classifier. The current email URL extraction reads the plain-text body; HTML-only content may not be covered. Authentication headers, when present, are included as evidence and should not be treated as independently verified by this application.

## Requirements

- Python version compatible with the installed dependencies (Python 3.10 or newer is a reasonable starting point; use the version tested for this project).
- pip
- The dependencies listed in `requirements.txt`
- The trained model files expected by `analyzer/ml_detector.py`


### Analyze a document

1. Upload a PDF, Word, or Excel document.
2. Review validation and metadata.
3. Review heuristic findings and the risk score.
4. Review the corresponding ML prediction, if available.
5. Download the JSON report if required.

### Analyze an email

1. Upload an `.eml` file.
2. Review the subject, sender, recipient, date, body text, URLs, and available authentication-related headers.
3. Review the email-level indicator score and findings.
4. Inspect the attachment list, including file names, content types, sizes, and SHA-256 hashes.
5. Supported PDF, Word, and Excel attachments are analyzed individually through the existing document pipeline.
6. Download the combined JSON report.

The EML file itself is not passed to an ML model. ML results in an email report belong to individual supported document attachments.

## Reports and interpretation

The report can include:

- File validation results
- File metadata and SHA-256 hash
- General static-analysis features
- Heuristic score, classification, and findings
- Model prediction, class probabilities, and model input features
- Email headers, URLs, and attachment metadata
- Individual attachment analysis results

In the dataset convention used by the project, label `0` represents benign and label `1` represents malicious. Confirm this convention against the current training data before interpreting results.
ting Excel model probabilities as reliable.


## Limitations

- This is a static-analysis aid, not a replacement for a professional malware sandbox or antivirus product.
- The current email analyzer is heuristic-based and does not use a dedicated email ML model.
- Email URL extraction currently focuses on plain-text content; HTML-only URLs may be missed.
- Authentication headers are displayed as evidence; the application does not independently verify the sender's identity.
- Only PDF, Word, and Excel attachments are routed through the document-analysis pipeline.
- File validation is a preliminary check and does not guarantee that a file is harmless or structurally safe.
- ML predictions can be affected by dataset bias, feature mismatch, and distribution shifts.
- Keep dependencies updated and use isolated environments when analyzing suspicious files.

## Security and privacy notes

- Uploaded files may contain private information. Only analyze files you are authorized to inspect.
- The application uses temporary files for processing. Temporary files are removed by the application after analysis where possible.
- Do not deploy the application publicly without reviewing upload limits, access controls, storage behavior, dependency security, and error handling.
- Do not use real credentials or sensitive personal information.


## License

Add the license and attribution details appropriate to your project and the datasets or code you use before publishing or distributing this repository.
