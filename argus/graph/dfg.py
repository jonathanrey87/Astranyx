from __future__ import annotations

from dataclasses import dataclass, field

from argus.models.ir import IRModule


@dataclass(slots=True)
class DataNode:
    name: str
    kind: str
    metadata: dict = field(default_factory=dict)


class DataFlowGraph:
    def __init__(self):
        self.nodes: dict[str, DataNode] = {}
        self.edges: dict[str, set[str]] = {}

    def add_edge(self, src: str, dst: str):
        self.nodes.setdefault(src, DataNode(src, "value"))
        self.nodes.setdefault(dst, DataNode(dst, "value"))
        self.edges.setdefault(src, set()).add(dst)

    def successors(self, node: str):
        return sorted(self.edges.get(node, set()))

    def predecessors(self, node: str):
        return sorted(src for src, targets in self.edges.items() if node in targets)

    def build(self, module: IRModule):
        for fn in module.functions:
            for variable in fn.variables:
                self.nodes.setdefault(
                    variable.name,
                    DataNode(variable.name, variable.kind),
                )

            for call in fn.calls:
                for argument in call.arguments:
                    self.add_edge(argument, call.target)
