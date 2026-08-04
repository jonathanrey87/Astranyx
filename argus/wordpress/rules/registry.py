from argus.wordpress.rules.ajax import RULES as AJAX_RULES
from argus.wordpress.rules.dangerous import RULES as DANGEROUS_RULES
from argus.wordpress.rules.deserialization import RULES as DESERIALIZATION_RULES
from argus.wordpress.rules.include import RULES as INCLUDE_RULES
from argus.wordpress.rules.react import RULES as REACT_RULES
from argus.wordpress.rules.rest import RULES as REST_RULES
from argus.wordpress.rules.sql import RULES as SQL_RULES
from argus.wordpress.rules.ssrf import RULES as SSRF_RULES
from argus.wordpress.rules.upload import RULES as UPLOAD_RULES

PHP_RULES = (
    AJAX_RULES
    + REST_RULES
    + SQL_RULES
    + SSRF_RULES
    + UPLOAD_RULES
    + DESERIALIZATION_RULES
    + DANGEROUS_RULES
    + INCLUDE_RULES
)

JS_RULES = REACT_RULES


def get_rules_for_file(path):
    if path.suffix == ".php":
        return PHP_RULES

    if path.suffix in {".js", ".jsx", ".ts", ".tsx"}:
        return JS_RULES

    return []
