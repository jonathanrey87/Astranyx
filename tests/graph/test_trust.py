from astranyx.graph.trust import TrustEngine, TrustLevel


def test_untrusted():
    t = TrustEngine()
    assert t.classify("params[:url]") == TrustLevel.UNTRUSTED


def test_configuration():
    t = TrustEngine()
    assert t.classify("ENV['TOKEN']") == TrustLevel.CONFIGURATION


def test_database():
    t = TrustEngine()
    assert t.classify("database.user") == TrustLevel.DATABASE


def test_external():
    t = TrustEngine()
    assert t.classify("https://example.com") == TrustLevel.EXTERNAL


def test_unknown():
    t = TrustEngine()
    assert t.classify("foo") == TrustLevel.UNKNOWN
