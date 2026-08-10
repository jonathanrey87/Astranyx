from astranyx.graph.callgraph import CallGraph
from astranyx.models.ir import (
    IRCall,
    IRFunction,
    IRModule,
    SourceLocation,
)


def test_callgraph_edges():

    module = IRModule(
        path="demo.rb",
        language="ruby",
    )

    module.functions.append(
        IRFunction(
            name="fetch",
            location=SourceLocation(
                file="demo.rb",
                line=10,
            ),
            calls=[
                IRCall(
                    target="Gitlab::HTTP.get",
                    location=SourceLocation(
                        file="demo.rb",
                        line=12,
                    ),
                )
            ],
        )
    )

    graph = CallGraph()

    graph.add_module(module)

    assert graph.node_count() == 2

    assert graph.edge_count() == 1

    assert graph.callees("demo.rb::fetch") == ["Gitlab::HTTP.get"]

    assert graph.callers("Gitlab::HTTP.get") == ["demo.rb::fetch"]
