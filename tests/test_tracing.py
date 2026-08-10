from astranyx.tracing import configure_tracing


def test_tracing_disabled_without_credentials(
    monkeypatch,
):
    monkeypatch.delenv("ARIZE_SPACE_ID", raising=False)
    monkeypatch.delenv("ARIZE_API_KEY", raising=False)

    assert configure_tracing() is None


def test_tracing_registers_with_credentials(
    monkeypatch,
):
    captured = {}

    def fake_register(**kwargs):
        captured.update(kwargs)

    monkeypatch.setenv("ARIZE_SPACE_ID", "test-space")
    monkeypatch.setenv("ARIZE_API_KEY", "test-key")
    monkeypatch.setattr(
        "astranyx.tracing.register",
        fake_register,
    )

    tracer = configure_tracing()

    assert tracer is not None
    assert captured == {
        "space_id": "test-space",
        "api_key": "test-key",
        "project_name": "astranyx",
    }
