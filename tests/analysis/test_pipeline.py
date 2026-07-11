from argus.analysis.pipeline import AnalysisPipeline, AnalysisStage


class DummyStage(AnalysisStage):

    name = "dummy"

    def run(self, context):
        context["ran"] = True


def test_pipeline():

    pipeline = AnalysisPipeline()

    pipeline.register(DummyStage())

    context = {}

    result = pipeline.execute(context)

    assert result["ran"] is True
