"""Cross-language fuzz + boundary check for _ecmascript_number_bytes.

Generates boundary doubles plus random bit-pattern doubles, computes the
Python ECMAScript-style serialization for each, and asks a real Node process
for JSON.stringify of the same parsed values. Any disagreement is a contract
failure. Provenance: LOCAL_EXECUTION / FIXTURE.
"""

from __future__ import annotations

import json
import math
import random
import struct
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from basebreak.causal.public_receipt import _ecmascript_number_bytes  # noqa: E402

NODE_SCRIPT = r"""
import fs from "node:fs";
const values = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const out = [];
for (const v of values) {
  out.push(JSON.stringify(JSON.parse(v)));
}
process.stdout.write(JSON.stringify(out));
"""


def _random_finite_double(rng: random.Random) -> float:
    while True:
        bits = rng.getrandbits(64)
        value = struct.unpack("<d", struct.pack("<Q", bits))[0]
        if math.isfinite(value):
            return value


def main() -> None:
    rng = random.Random(20261022)
    boundaries = [
        0.1,
        0.5,
        1.5,
        2.5,
        -2.5,
        100.0,
        30.0,
        0.0,
        -0.0,
        1.0,
        -1.0,
        1e-4,
        1e-5,
        1e-6,
        1e-7,
        1e-8,
        5e-324,
        2.2250738585072014e-308,
        1.7976931348623157e308,
        1e15,
        1e16,
        1e17,
        1e20,
        1e21,
        1e22,
        1.5e16,
        1.5e21,
        123.456,
        0.30000000000000004,
        1 / 3,
        2 / 3,
        100 / 3,
        0.0000125,
        0.0000425,
        4.853,
        44.4047,
        1.665,
        2.25,
        -1e-5,
        -1e21,
        -1.5e16,
        2**53 - 1,
        -(2**53 - 1),
        2**53,
        -(2**53),
        1e-323,
        9007199254740992.0,
        123456789012345.67,
    ]
    # Boundary floats that are integral are exercised through the float path
    # directly (the receipt payload normalizes them to ints, but the serializer
    # must still format them correctly if reached as floats).
    randoms = [_random_finite_double(rng) for _ in range(4000)]
    values = boundaries + randoms
    # 2**53 and -(2**53) as floats are integral and within... 2**53 > 2**53-1!
    # The serializer rejects ints beyond the safe range, but these are FLOATS;
    # _ecmascript_number_bytes itself has no safe-int bound (the bound applies
    # to the int path). Verify JS agrees on their bytes too.
    literals = []
    for v in values:
        if isinstance(v, float) and math.isfinite(v):
            literals.append(repr(v))
    tmp = Path(__file__).with_name("fuzz_values.json")
    tmp.write_text(json.dumps(literals), encoding="utf-8")
    script = Path(__file__).with_name("fuzz_node_check.mjs")
    script.write_text(NODE_SCRIPT, encoding="utf-8")
    result = subprocess.run(
        ["node", str(script), str(tmp)],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(REPO),
    )
    if result.returncode != 0:
        print("NODE FAILED:", result.stderr[:500])
        sys.exit(1)
    js_bytes = json.loads(result.stdout)
    assert len(js_bytes) == len(literals), (len(js_bytes), len(literals))
    mismatches = []
    for literal, js in zip(literals, js_bytes):
        py = _ecmascript_number_bytes(float(literal))
        if py != js:
            mismatches.append((literal, py, js))
    print(f"checked {len(literals)} finite doubles (boundaries + 4000 random)")
    if mismatches:
        print(f"MISMATCHES: {len(mismatches)}")
        for literal, py, js in mismatches[:20]:
            print(f"  value={literal} python={py!r} js={js!r}")
        sys.exit(1)
    print("ALL MATCH — Python ECMAScript formatter agrees with Node on every value")
    # Fail-closed checks.
    for bad in (float("nan"), float("inf"), float("-inf")):
        try:
            _ecmascript_number_bytes(bad)
            print("FAIL: non-finite accepted:", bad)
            sys.exit(1)
        except Exception as exc:
            print(f"non-finite {bad!r} rejected: {type(exc).__name__}")
    from basebreak.causal.public_receipt import _canonical_receipt_json_bytes

    for bad_int in (2**53, -(2**53), 10**30):
        try:
            _canonical_receipt_json_bytes(bad_int)
            print("FAIL: unsafe int accepted:", bad_int)
            sys.exit(1)
        except Exception as exc:
            print(f"unsafe int {bad_int} rejected: {type(exc).__name__}")
    for bad_key in ({"ç": 1}, {42: 1}):
        try:
            _canonical_receipt_json_bytes(bad_key)
            print("FAIL: bad key accepted:", bad_key)
            sys.exit(1)
        except Exception as exc:
            print(f"bad key {bad_key!r} rejected: {type(exc).__name__}")
    print("fail-closed contract verified")


if __name__ == "__main__":
    main()
