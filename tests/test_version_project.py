import pytest

from chainmail.core.project import Project
from chainmail.core.version import Version, parse_pragma


@pytest.mark.parametrize(
    "pragma,low,high,floating",
    [
        ("^0.8.0", "0.8.0", "0.9.0", True),
        ("0.8.19", "0.8.19", "0.8.20", False),
        ("=0.8.19", "0.8.19", "0.8.20", False),
        (">=0.6.0 <0.9.0", "0.6.0", "0.9.0", True),
        ("~0.5.2", "0.5.2", "0.6.0", True),
        ("^0.4.24", "0.4.24", "0.5.0", True),
        (">=0.8.0", "0.8.0", None, True),
        (">=0.4.22 <0.6.0 || ^0.8.0", "0.4.22", "0.9.0", True),
    ],
)
def test_pragma_ranges(pragma, low, high, floating):
    r = parse_pragma(pragma)
    assert str(r.low) == low
    assert (str(r.high) if r.high else None) == high
    assert r.is_floating is floating


def test_version_ordering():
    assert Version.parse("0.8.19") < Version.parse("0.8.20") < Version.parse("0.10.0")


def test_checked_arithmetic_depends_on_pragma():
    p = Project.from_sources([("a.sol", "pragma solidity ^0.7.0; contract A {}"), ("b.sol", "pragma solidity ^0.8.0; contract B {}")])
    a, b = p.files
    assert not a.checked_arithmetic
    assert b.checked_arithmetic


def test_c3_linearization_matches_solidity():
    src = """
    contract A { uint a; }
    contract B is A { uint b; }
    contract C is A { uint c; }
    contract D is B, C { uint d; }
    """
    p = Project.from_sources([("x.sol", src)])
    d = p.lookup("D")
    assert [i.name for i in d.linearization] == ["D", "C", "B", "A"]
    assert [v.name for v in d.all_state_vars()] == ["a", "b", "c", "d"]


def test_unresolved_bases_are_tracked():
    p = Project.from_sources([("x.sol", "contract X is Ownable, Y {} contract Y {}")])
    x = p.lookup("X")
    assert x.unresolved_bases == ["Ownable"]
    assert [i.name for i in x.linearization] == ["X", "Y"]


def test_cyclic_inheritance_does_not_loop():
    p = Project.from_sources([("x.sol", "contract A is B {} contract B is A {}")])
    assert p.lookup("A").linearization[0].name == "A"
