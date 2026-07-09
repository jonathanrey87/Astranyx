SAFE_INCLUDE_PATTERNS = [
    "ABSPATH",
    "plugin_dir_path",
    "dirname(__FILE__)",
    "__DIR__",
    "WP_PLUGIN_DIR",
]

SAFE_FILE_READ_PATTERNS = [
    "php://input",
    "$safeFile",
    "$safeFiles",
    "$safeFilePath",
    "$filePath",
    "$manifestPath",
]

SAFE_SQL_PATTERNS = [
    "$wpdb->prepare",
    "esc_like",
    "absint",
]


def reduce_noise(finding, context):
    evidence = finding.evidence
    text = evidence + "\n" + context

    if finding.category == "Dynamic Include":
        if any(p in text for p in SAFE_INCLUDE_PATTERNS):
            finding.confidence = min(finding.confidence, 2)
            finding.reason = "Safe internal include pattern detected."
            return finding

    if finding.category == "SSRF Sink":
        if "php://input" in text:
            finding.confidence = min(finding.confidence, 1)
            finding.reason = "php://input is an input source, not an SSRF sink."
            return finding

        if "file_get_contents" in evidence and any(p in text for p in SAFE_FILE_READ_PATTERNS):
            finding.confidence = min(finding.confidence, 5)
            finding.reason = "Likely local file read pattern detected."
            return finding

    if finding.category == "SQL Query":
        if any(p in text for p in SAFE_SQL_PATTERNS):
            finding.confidence = min(finding.confidence, 1)
            finding.reason = "Prepared or escaped SQL pattern detected."
            return finding

    if finding.category == "Deserialization":
        if "allowed_classes" in text:
            finding.confidence = min(finding.confidence, 1)
            finding.reason = "allowed_classes protection detected."
            return finding

    return finding
