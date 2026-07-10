"""
tests/test_fuzz_normalize.py  (v1.5.2)

Hypothesis-driven fuzz and property testing of the Normalize boundary — the
first trust boundary in the pipeline. Every request passes through it, so it
deserves abuse: random Unicode (including lone surrogates, controls, bidi and
zero-width characters), malformed structures, deep nesting, null bytes, and
huge strings.

Invariants under test, per ROADMAP v1.5.2:
  * harden() never crashes, never returns None, always returns str,
    is deterministic and idempotent, and its output is clean of the
    character classes it exists to remove.
  * Request.normalize() never crashes, always returns a Request, never
    mutates its input, and produces an inspection view that is itself
    fully hardened.
  * parse_jsonrpc_line() never lets any exception escape and only ever
    returns a dict or None — a hostile peer cannot crash the relay with
    a crafted line. (The deep-nesting RecursionError and non-object
    top-level JSON crash were FOUND by this suite; the parser is the fix.)

Every payload here is synthetic and benign, consistent with the rest of the
test suite: the structure of an attack with no destructive function.
"""

import copy
import json
import unicodedata

from hypothesis import given, settings, strategies as st

from proxy.core.textnorm import harden, _INVISIBLES, _HOMOGLYPHS
from proxy.core.request import Request
from proxy.transport.mcp import parse_jsonrpc_line


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Full-hostility text: every Unicode category INCLUDING lone surrogates (Cs),
# controls (Cc), formats (Cf) — plus the specific characters textnorm targets,
# mixed in at elevated frequency so every run exercises them.
_nasty_chars = st.sampled_from(
    sorted(_INVISIBLES)
    + [chr(c) for c in _HOMOGLYPHS.keys()]
    + ["\x00", "\u202e", "\ufeff", "\uff29", "ﬁ", "\u0130", "\u00df"]
)
_any_char = st.characters()  # default: excludes surrogates
_surrogate = st.sampled_from(["\ud800", "\udfff", "\udc00"])
hostile_text = st.text(
    alphabet=st.one_of(_any_char, _nasty_chars, _surrogate),
    max_size=400,
)

# JSON-ish values for args dicts: scalars, then nested lists/dicts.
_scalars = st.one_of(
    st.none(), st.booleans(), st.integers(),
    st.floats(allow_nan=True, allow_infinity=True),
    st.text(max_size=60),
)
json_values = st.recursive(
    _scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(max_size=12), children, max_size=4),
    ),
    max_leaves=12,
)
args_dicts = st.dictionaries(st.text(max_size=20), json_values, max_size=6)


# ---------------------------------------------------------------------------
# harden() — the Unicode-hardening core
# ---------------------------------------------------------------------------

class TestHardenProperties:
    @settings(max_examples=300, deadline=None)
    @given(hostile_text)
    def test_total_function_returns_str(self, s):
        out = harden(s)
        assert out is not None
        assert isinstance(out, str)

    @settings(max_examples=300, deadline=None)
    @given(hostile_text)
    def test_deterministic(self, s):
        assert harden(s) == harden(s)

    @settings(max_examples=300, deadline=None)
    @given(hostile_text)
    def test_idempotent(self, s):
        once = harden(s)
        assert harden(once) == once

    @settings(max_examples=300, deadline=None)
    @given(hostile_text)
    def test_output_contains_no_invisibles(self, s):
        out = harden(s)
        assert not (_INVISIBLES & set(out))

    @settings(max_examples=300, deadline=None)
    @given(hostile_text)
    def test_output_contains_no_null_bytes_or_hidden_controls(self, s):
        out = harden(s)
        assert "\x00" not in out
        for ch in out:
            if ch in "\n\t\r":
                continue
            assert unicodedata.category(ch) not in ("Cf", "Cc")

    @settings(max_examples=300, deadline=None)
    @given(hostile_text)
    def test_output_contains_no_mapped_homoglyphs(self, s):
        out = harden(s)
        assert not any(ord(ch) in _HOMOGLYPHS for ch in out)

    @settings(max_examples=20, deadline=None)
    @given(st.text(min_size=1, max_size=200), st.integers(min_value=50, max_value=200))
    def test_huge_strings_survive(self, chunk, reps):
        s = chunk * reps  # up to ~40k chars, built from a small base example
        out = harden(s)
        assert isinstance(out, str)
        assert harden(out) == out


# ---------------------------------------------------------------------------
# Request.normalize() — the single entry point
# ---------------------------------------------------------------------------

class TestNormalizeProperties:
    @settings(max_examples=200, deadline=None)
    @given(hostile_text, args_dicts)
    def test_total_function_returns_request(self, tool, args):
        r = Request.normalize(tool, args)
        assert isinstance(r, Request)
        assert isinstance(r.tool, str)
        assert r.request_id and r.received_at

    @settings(max_examples=200, deadline=None)
    @given(hostile_text, args_dicts)
    def test_tool_name_is_fully_hardened(self, tool, args):
        r = Request.normalize(tool, args)
        assert harden(r.tool) == r.tool

    @settings(max_examples=200, deadline=None)
    @given(hostile_text, args_dicts)
    def test_input_args_never_mutated(self, tool, args):
        snapshot = copy.deepcopy(args)
        r = Request.normalize(tool, args)
        r.inspection_text()
        assert _eq(args, snapshot)

    @settings(max_examples=200, deadline=None)
    @given(hostile_text, args_dicts)
    def test_inspection_text_is_hardened_str(self, tool, args):
        r = Request.normalize(tool, args)
        view = r.inspection_text()
        assert isinstance(view, str)
        assert harden(view) == view
        assert not (_INVISIBLES & set(view))

    @settings(max_examples=100, deadline=None)
    @given(hostile_text, args_dicts)
    def test_same_input_same_shape_distinct_ids(self, tool, args):
        a = Request.normalize(tool, args)
        b = Request.normalize(tool, args)
        assert a.tool == b.tool and _eq(a.args, b.args) and a.user == b.user
        assert a.request_id != b.request_id


def _eq(a, b):
    """Equality that treats NaN as equal to itself (fuzzed floats)."""
    if isinstance(a, float) and isinstance(b, float):
        return (a != a and b != b) or a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_eq(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_eq(x, y) for x, y in zip(a, b))
    return a == b


# ---------------------------------------------------------------------------
# parse_jsonrpc_line() — the relay's parse boundary
# ---------------------------------------------------------------------------

class TestJsonRpcParseProperties:
    @settings(max_examples=300, deadline=None)
    @given(st.text(max_size=400))
    def test_arbitrary_text_never_raises(self, line):
        out = parse_jsonrpc_line(line)
        assert out is None or isinstance(out, dict)

    @settings(max_examples=200, deadline=None)
    @given(st.binary(max_size=400))
    def test_arbitrary_bytes_never_raise(self, line):
        out = parse_jsonrpc_line(line)
        assert out is None or isinstance(out, dict)

    @settings(max_examples=200, deadline=None)
    @given(json_values)
    def test_valid_json_only_objects_pass(self, value):
        try:
            line = json.dumps(value)
        except ValueError:
            return  # NaN/Infinity permutations json can't emit; irrelevant
        out = parse_jsonrpc_line(line)
        if isinstance(value, dict):
            assert isinstance(out, dict)
        else:
            assert out is None  # lists, scalars: no JSON-RPC meaning — dropped

    def test_deep_nesting_bomb_is_dropped_not_crashed(self):
        # The exact payload class that previously escaped the old guard as
        # RecursionError and could kill the relay pump.
        assert parse_jsonrpc_line("[" * 100_000) is None
        assert parse_jsonrpc_line('{"a":' * 50_000) is None

    def test_top_level_array_is_dropped(self):
        # Valid JSON, wrong shape: previously crashed the server pump on .get().
        assert parse_jsonrpc_line('[1, 2, 3]') is None
        assert parse_jsonrpc_line('"just a string"') is None
        assert parse_jsonrpc_line("42") is None

    def test_null_bytes_and_garbage_are_dropped(self):
        assert parse_jsonrpc_line("\x00\x00\x00") is None
        assert parse_jsonrpc_line(b"\xff\xfe garbage") is None

    def test_real_jsonrpc_object_passes(self):
        msg = parse_jsonrpc_line('{"jsonrpc":"2.0","id":1,"method":"tools/call"}')
        assert msg == {"jsonrpc": "2.0", "id": 1, "method": "tools/call"}
