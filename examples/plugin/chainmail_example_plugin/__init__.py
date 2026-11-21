"""Example Chainmail plugin: flag hard-coded addresses in function bodies.

Install with ``pip install -e examples/plugin`` and the detector shows up in
``chainmail detectors`` automatically (entry-point group ``chainmail.detectors``).
"""

from __future__ import annotations

import re

from chainmail.core import ast as A
from chainmail.core.project import ContractInfo
from chainmail.detectors import Detector
from chainmail.findings import Confidence, Severity

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


class HardcodedAddress(Detector):
    id = "hardcoded-address"
    title = "Hard-coded address"
    severity = Severity.INFO
    confidence = Confidence.HIGH
    category = "best-practice"
    description = "A literal address is embedded in logic; it cannot be changed per network or rotated."
    recommendation = "Pass the address to the constructor (immutable) or make it configurable."

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            for node in fn.body.walk() if fn.body else []:
                if isinstance(node, A.Literal) and node.kind == "hex" and ADDRESS_RE.match(node.value):
                    self.report(info.file, node, f"Literal address `{node.value}` in `{fn.signature}`.", contract=info.name, function=fn)
