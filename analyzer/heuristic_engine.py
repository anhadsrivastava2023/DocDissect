
def analyze_features(features):
    """
    Apply transparent heuristic rules to extracted document features.

    The score is a preliminary heuristic risk score, not a calibrated
    probability that a file is malicious.
    """

    score = 0
    findings = []

    def add_finding(name, points, evidence):
        nonlocal score
        score += points
        findings.append({
            "rule": name,
            "points": points,
            "evidence": evidence,
        })

    urls = features.get("urls", [])
    suspicious_patterns = features.get("suspicious_patterns", [])
    embedded_objects = features.get("embedded_objects", [])
    external_relationships = features.get(
        "external_relationships", []
    )
    pdf_indicators = features.get(
        "pdf_structural_indicators", []
    )

    # Rule 1: Suspicious script or command-related patterns.
    if suspicious_patterns:
        add_finding(
            "SUSPICIOUS_CODE_PATTERNS",
            min(30, 10 + 5 * len(suspicious_patterns)),
            suspicious_patterns,
        )

    # Rule 2: Macro-enabled document with suspicious code indicators.
    if (
        features.get("macro_indicator", False)
        and suspicious_patterns
    ):
        add_finding(
            "MACRO_WITH_SUSPICIOUS_PATTERNS",
            25,
            "Macro-enabled document contains suspicious patterns.",
        )

    # Rule 3: Embedded objects warrant closer inspection.
    if embedded_objects:
        add_finding(
            "EMBEDDED_OBJECTS_PRESENT",
            15,
            embedded_objects[:10],
        )

    # Rule 4: External relationships can point outside the document.
    if external_relationships:
        add_finding(
            "EXTERNAL_RELATIONSHIPS_PRESENT",
            10,
            external_relationships[:10],
        )

    # Rule 5: PDF actions and embedded content indicators.
    concerning_pdf_indicators = {
        "/JavaScript",
        "/JS",
        "/Launch",
        "/OpenAction",
        "/AA",
        "/EmbeddedFile",
    }

    matched_pdf_indicators = [
        indicator
        for indicator in pdf_indicators
        if indicator in concerning_pdf_indicators
    ]

    if matched_pdf_indicators:
        add_finding(
            "PDF_ACTIVE_CONTENT_INDICATORS",
            min(25, 10 + 5 * len(matched_pdf_indicators)),
            matched_pdf_indicators,
        )

    # Rule 6: URLs are useful for investigation, but their presence
    # alone is not evidence that a file is malicious.
    if len(urls) >= 5:
        add_finding(
            "MULTIPLE_URLS_PRESENT",
            5,
            f"{len(urls)} URLs were extracted.",
        )

    # Rule 7: High entropy is weak contextual evidence only.
    entropy = features.get("entropy", 0)

    if isinstance(entropy, (int, float)) and entropy >= 7.5:
        add_finding(
            "HIGH_FILE_ENTROPY",
            5,
            f"Measured entropy: {entropy:.4f} bits per byte.",
        )

    # Cap the score at 100.
    score = min(score, 100)

    # These are initial demonstration thresholds. They must be
    # evaluated and tuned using a labeled validation dataset.
    if score >= 60:
        classification = "Malicious"
    elif score >= 20:
        classification = "Suspicious"
    else:
        classification = "Benign"

    if not findings:
        summary = "No configured heuristic rules were triggered."
    else:
        summary = (
            f"{len(findings)} heuristic finding(s) require review."
        )

    return {
        "risk_score": score,
        "classification": classification,
        "findings": findings,
        "summary": summary,
        "disclaimer": (
            "Heuristic output is preliminary. A low score does not "
            "prove safety, and a high score does not prove malware."
        ),
    }
