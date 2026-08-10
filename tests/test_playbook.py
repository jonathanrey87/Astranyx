from astranyx.services.playbook import recommend


def test_deeplink_recommendation():
    app = {"CFBundleURLTypes": [{"CFBundleURLSchemes": ["demo"]}]}

    recs = recommend(app)

    assert "deeplink" in recs
