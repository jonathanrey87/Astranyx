def analyze_sql_finding(finding, context):
    evidence = finding.evidence
    ctx = context

    if "$wpdb->prepare" in evidence or "$wpdb->prepare" in ctx:
        finding.confidence = 5
        finding.reason = "Prepared SQL statement detected."
        return finding

    if "$_GET" in ctx or "$_POST" in ctx or "$_REQUEST" in ctx:
        finding.confidence = 95
        finding.reason = "User-controlled input appears near SQL query."
        finding.severity = "High"
        return finding

    if "$wpdb->query($query" in evidence or "$wpdb->get_results($query" in evidence:
        finding.confidence = 60
        finding.reason = "Variable SQL query detected. Trace variable origin."
        return finding

    finding.confidence = 30
    finding.reason = "SQL query detected. Manual review recommended."
    return finding
