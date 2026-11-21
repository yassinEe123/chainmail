# Writing a detector

A detector is a subclass of `chainmail.detectors.Detector`. It declares metadata
as class attributes and reports findings through `self.report(...)`.

```python
from chainmail.core import ast as A
from chainmail.core.analysis import CallKind, render
from chainmail.detectors import Detector, register
from chainmail.findings import Confidence, Severity


@register
class UncheckedApprove(Detector):
    id = "unchecked-approve"                 # kebab-case, unique
    title = "ERC20 approve result ignored"
    severity = Severity.LOW
    confidence = Confidence.MEDIUM
    swc = "SWC-104"
    cwe = "CWE-252"
    description = "Some tokens return false from approve() instead of reverting."
    recommendation = "Use SafeERC20.forceApprove."

    def check_contract(self, info):
        for fn in self.own_functions(info):          # functions declared in this contract
            fa = self.analyze(fn, info)               # cached FunctionAnalysis
            for call in fa.calls:
                if call.kind is CallKind.EXTERNAL and call.name == "approve" and not fa.result_is_used(call.node):
                    self.report(
                        info.file, call.node,
                        f"`{render(call.node)}` ignores the returned bool.",
                        contract=info.name, function=fn,
                    )
```

## Useful building blocks

| API | What it gives you |
|---|---|
| `info.contract` | the `ContractDef` AST node |
| `info.linearization` | C3 order, most-derived first |
| `info.all_state_vars()`, `info.modifier(name)`, `info.functions_named(name)` | inherited lookups |
| `fa.calls` | `CallSite` list: `kind`, `name`, `receiver`, `value`, `gas`, `in_loop`, `resolved`, `confidence` |
| `fa.state_writes` / `fa.state_reads` | ordered state accesses |
| `fa.is_protected`, `fa.access_control` | access-control guard and its description |
| `fa.expr_controlled(expr)` | can the caller choose this value? |
| `fa.type_of(expr)` | best-effort static type |
| `fa.result_is_used(call)` | is a call's return value checked? |
| `fa.is_in_condition(node)` | is the node inside a require/if/loop condition? |
| `node.walk()` | pre-order traversal of any AST node |
| `render(node)` | Solidity-like text for messages |

## Testing

Add positive **and** negative cases to `tests/test_detectors.py`:

```python
def test_unchecked_approve():
    src = P + "interface T { function approve(address,uint) external returns (bool); } contract C { T t; function f() external { t.approve(msg.sender, 1); } }"
    assert [f.location.function for f in scan(src, "unchecked-approve")] == ["f"]
```

Then run the benchmark to make sure you did not introduce noise on audited code:

```bash
python scripts/benchmark.py
```

## Shipping a detector as a plugin

Package it and expose it through the `chainmail.detectors` entry-point group -
see [`examples/plugin`](../examples/plugin):

```toml
[project.entry-points."chainmail.detectors"]
hardcoded-address = "chainmail_example_plugin:HardcodedAddress"
```

After `pip install`, the detector appears in `chainmail detectors` and runs with
every scan.
