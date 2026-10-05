"""Phase 8.4: CWE-338 Insecure Pseudo-Random Number Generators (Zero-FP Policy).

Covers:
  1. All stdlib random.* method calls (random.random, randint, choice, etc.)
  2. random.Random() constructor
  3. CSPRNG exclusions (secrets.*, os.urandom, random.SystemRandom)

Each test asserts vulnerable shapes FIRE and safe/CSPRNG shapes stay SILENT.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ast_scanner import TaintTracker


def _cwes_at(code: str, line: int) -> set[str]:
    """Run TaintTracker on a snippet and return CWEs at the given line."""
    tracker = TaintTracker(files={"snippet.py": code})
    sources, sinks, edges = tracker.analyze()
    by_id = {s.id: s for s in sinks}
    cwes: set[str] = set()
    for edge in edges:
        sink = by_id.get(edge.target_id)
        if sink is None:
            continue
        loc = sink.location
        if loc.line_start == line:
            cwe = (sink.metadata or {}).get("cwe")
            if cwe:
                cwes.add(cwe)
    return cwes


def _fires(code: str, line: int, expected_cwe: str) -> None:
    cwes = _cwes_at(code, line)
    assert expected_cwe in cwes, f"Expected {expected_cwe} at line {line}, got {cwes}"


def _silent(code: str, line: int, expected_cwe: str) -> None:
    cwes = _cwes_at(code, line)
    assert expected_cwe not in cwes, f"Unexpected {expected_cwe} at line {line}, got {cwes}"


# ─── 1. Positive cases: insecure random.* calls ──────────────────────────────

class TestInsecureRandomCalls:
    def test_random_randint(self):
        _fires('import random\nx = random.randint(1, 10)\n', 2, "CWE-338")

    def test_random_choice(self):
        _fires('import random\nitems = [1, 2, 3]\nx = random.choice(items)\n', 3, "CWE-338")

    def test_random_random(self):
        _fires('import random\nx = random.random()\n', 2, "CWE-338")

    def test_random_randrange(self):
        _fires('import random\nx = random.randrange(100)\n', 2, "CWE-338")

    def test_random_sample(self):
        _fires('import random\nitems = [1, 2, 3, 4, 5]\nx = random.sample(items, 3)\n', 3, "CWE-338")

    def test_random_choices(self):
        _fires('import random\nx = random.choices([1, 2, 3], k=2)\n', 2, "CWE-338")

    def test_random_shuffle(self):
        _fires('import random\nitems = [1, 2, 3]\nrandom.shuffle(items)\n', 3, "CWE-338")

    def test_random_uniform(self):
        _fires('import random\nx = random.uniform(0.0, 1.0)\n', 2, "CWE-338")

    def test_random_constructor(self):
        _fires('import random\nrng = random.Random()\n', 2, "CWE-338")

    def test_random_getrandbits(self):
        _fires('import random\nx = random.getrandbits(16)\n', 2, "CWE-338")

    def test_from_import_randint(self):
        _fires('from random import randint\nx = randint(1, 10)\n', 2, "CWE-338")

    def test_from_import_choice(self):
        _fires('from random import choice\nx = choice([1, 2, 3])\n', 2, "CWE-338")


# ─── 2. Negative guards: CSPRNGs must stay silent ────────────────────────────

class TestCSPRNGExclusions:
    def test_secrets_token_hex(self):
        _silent('import secrets\nx = secrets.token_hex(16)\n', 2, "CWE-338")

    def test_secrets_token_bytes(self):
        _silent('import secrets\nx = secrets.token_bytes(16)\n', 2, "CWE-338")

    def test_secrets_choice(self):
        _silent('import secrets\nx = secrets.choice([1, 2, 3])\n', 2, "CWE-338")

    def test_os_urandom(self):
        _silent('import os\nx = os.urandom(32)\n', 2, "CWE-338")

    def test_systemrandom_constructor(self):
        _silent('import random\nrng = random.SystemRandom()\n', 2, "CWE-338")

    def test_systemrandom_method(self):
        # Methods called on SystemRandom instances are safe
        _silent('import random\nrng = random.SystemRandom()\nx = rng.randint(1, 10)\n', 3, "CWE-338")

    def test_secrets_randbelow(self):
        _silent('import secrets\nx = secrets.randbelow(100)\n', 2, "CWE-338")

    def test_secrets_token_urlsafe(self):
        _silent('import secrets\nx = secrets.token_urlsafe(16)\n', 2, "CWE-338")


# ─── 3. Real-world corpus patterns ───────────────────────────────────────────

class TestCorpusPatterns:
    def test_django_random_choice_in_generator(self):
        # From hashids-with-django-secret.py line 49
        _fires(
            'import random\nimport string\ndef get_random_string(length):\n'
            '    letters = string.ascii_lowercase + string.digits\n'
            '    return "".join(random.choice(letters) for i in range(length))\n',
            5, "CWE-338"
        )

    def test_bandit_random_module(self):
        # From bandit_corpus/examples/random_module.py
        _fires('import random\nbad = random.Random()\n', 2, "CWE-338")
        _fires('import random\nbad = random.random()\n', 2, "CWE-338")
        _fires('import random\nbad = random.randrange()\n', 2, "CWE-338")
        _fires('import random\nbad = random.randint()\n', 2, "CWE-338")
        _fires('import random\nbad = random.choice()\n', 2, "CWE-338")
        _fires('import random\nbad = random.choices()\n', 2, "CWE-338")
        _fires('import random\nbad = random.uniform()\n', 2, "CWE-338")
        _fires('import random\nbad = random.triangular()\n', 2, "CWE-338")
        _fires('import random\nbad = random.randbytes()\n', 2, "CWE-338")
        _fires('import random\nbad = random.sample()\n', 2, "CWE-338")
        _fires('import random\nbad = random.getrandbits()\n', 2, "CWE-338")


# ─── 4. Crash resilience: receivers whose canonical name cannot be folded ────

class TestUnresolvableReceiver:
    def test_call_receiver_does_not_raise(self):
        _fires(
            'import random\n\n\ndef handler():\n    return get_random().randint(1, 10)\n',
            5, "CWE-338"
        )

    def test_inline_systemrandom_chain_stays_silent(self):
        _silent('import random\nx = random.SystemRandom().randint(1, 10)\n', 2, "CWE-338")

    def test_subscript_receiver_does_not_raise(self):
        _fires('import random\nrngs = load_rngs()\nx = rngs[0].randint(1, 10)\n', 3, "CWE-338")
