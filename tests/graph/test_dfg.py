from argus.graph.dfg import DataFlowGraph
from argus.models.ir import (
    IRCall,
    IRFunction,
    IRModule,
    IRVariable,
    SourceLocation,
)


def test_data_flow():
    module = IRModule(
        path="demo.rb",
        language="ruby",
    )

    module.functions.append(
        IRFunction(
            name="fetch",
            location=SourceLocation(
                file="demo.rb",
                line=1,
            ),
            variables=[
                IRVariable(
                    name="url",
                    location=SourceLocation(
                        file="demo.rb",
                        line=2,
                    ),
                )
            ],
            calls=[
                IRCall(
                    target="Gitlab::HTTP.get",
                    location=SourceLocation(
                        file="demo.rb",
                        line=5,
                    ),
                    arguments=["url"],
                )
            ],
        )
    )

    graph = DataFlowGraph()
    graph.build(module)

    assert graph.successors("url") == ["Gitlab::HTTP.get"]
    assert graph.predecessors("Gitlab::HTTP.get") == ["url"]
