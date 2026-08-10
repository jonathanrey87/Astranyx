from pathlib import Path

from astranyx.models.ir import IRCall, IRFunction, IRModule, SourceLocation


def test_ir_module_creation():
    module = IRModule.from_path(Path("sample.rb"), "ruby")

    assert module.path == "sample.rb"
    assert module.language == "ruby"


def test_ir_function_can_store_calls():
    call = IRCall(
        target="Gitlab::HTTP.get",
        location=SourceLocation(file="sample.rb", line=10),
        arguments=["url"],
    )

    function = IRFunction(
        name="fetch",
        location=SourceLocation(file="sample.rb", line=5),
        calls=[call],
    )

    assert function.calls[0].target == "Gitlab::HTTP.get"
