"""Big-8 real-world gate: 136 findings on eight real Transformers files, none lost, none invented.

The corpus is eight large Hugging Face Transformers files (~2.1 MB) and the frozen baseline in
`big8_before.keys` is what the pinned engine (`gate_meta.json` > `big8` > `pinned_engine_rev`)
found on them. A missing key is a regression against that pinned engine -- a false negative on real
code, the class of bug the hand-written fixtures cannot show; a new key is an unsupported claim.
The only intentional shrink so far is the CWE-338 library-identity re-bless (154 -> 136), and the
header of the keys file lists every retired line and where its adversarial proof lives.

The baseline is not recomputed by re-running the pinned engine, because that would need a second
1.4 MB engine copy in the tree. Instead the corpus is hash-checked against `corpus_sha256` first:
frozen keys are only an authority for the exact bytes they were blessed on, so a wrong input is an
error, never a verdict.

Usage: python benchmark/gates/big8_ab.py [corpus_dir]
       The corpus is looked up in `benchmark/gates/corpus_big8/`, then the legacy `scratch/_p3_big/`;
       pass a directory to override.
"""
from __future__ import annotations

import os
import sys

from gate_common import (META, GATES_DIR, GatePathError, corpus_dir, diff, load_keys, report,
                         scan_rows, verify_corpus)


def main() -> int:
    meta = META['big8']
    before = load_keys(os.path.join(GATES_DIR, meta['keys_file']), 'big8')
    corpus = corpus_dir('big8', sys.argv[1] if len(sys.argv) > 1 else None)
    verify_corpus('big8', corpus)
    print(f'corpus={corpus} sha256 verified ({len(before)} pinned keys, '
          f"engine {meta['pinned_engine_rev']})")
    after = scan_rows('big8', corpus)
    missing, new = diff(before, after)
    return report('big8', len(before), len(after), missing, new, meta['expected_keys'])


if __name__ == '__main__':
    try:
        sys.exit(main())
    except GatePathError as error:
        print(f'GATE ERROR: {error}')
        sys.exit(2)
