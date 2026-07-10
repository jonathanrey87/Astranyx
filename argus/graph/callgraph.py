from __future__ import annotations

from dataclasses import dataclass, field

from argus.models.ir import IRModule


@dataclass(slots=True)
class GraphNode:
    name: str
    module: str
    metadata: dict = field(default_factory=dict)


class CallGraph:
    """
    Language-neutral call graph built from the Argus IR.
    """

    def __init__(self):
        self.nodes: dict[str, GraphNode] = {}
        self.edges: dict[str, set[str]] = {}

    def add_module(self, module: IRModule):

        for fn in module.functions:

            caller = f"{module.path}::{fn.name}"

            self.nodes.setdefault(
                caller,
                GraphNode(
                    name=fn.name,
                    module=module.path,
                ),
            )

            self.edges.setdefault(caller, set())

            for call in fn.calls:

                callee = call.target

                self.nodes.setdefault(
                    callee,
                    GraphNode(
                        name=callee,
                        module="external",
                    ),
                )

                self.edges[caller].add(callee)

    def callers(self, target: str):

        return sorted(
            node
            for node, callees in self.edges.items()
            if target in callees
        )

    def callees(self, caller: str):

        return sorted(self.edges.get(caller, set()))

    def node_count(self):

        return len(self.nodes)

    def edge_count(self):

        return sum(len(v) for v in self.edges.values())
