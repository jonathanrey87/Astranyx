import os

from argus.telemetry import trace

try:
    from arize.otel import register
except ImportError:
    register = None


def configure_tracing():
    """Configure Arize tracing when credentials are available."""
    space_id = os.getenv("ARIZE_SPACE_ID")
    api_key = os.getenv("ARIZE_API_KEY")

    if not space_id or not api_key:
        return None

    if register is None:
        return None

    register(
        space_id=space_id,
        api_key=api_key,
        project_name="argus-security",
    )

    return trace.get_tracer("argus-security")
