#!/usr/bin/env python3
"""Generate the deterministic, licensing-clean 1024-word key-name list (spec §3.9.1).

CVCV pronounceable syllable-words (proquint-adjacent, explicitly allowed by §3.9.1) over a
confusable-reduced consonant set. Spread evenly across the CVCV space so initial letters vary.
Run from the crate root:  python3 tools/gen_wordlist.py > wordlist.txt
"""
cons = list("bdfgklmnprstvz")  # dropped c/h/j/w/x/q/y to reduce visual/aural confusables
vows = list("aeiou")
combos = [c1+v1+c2+v2 for c1 in cons for v1 in vows for c2 in cons for v2 in vows]  # 4900
need, step, picked, seen, i = 1024, len(combos)/1024, [], set(), 0.0
while len(picked) < need:
    w = combos[int(i) % len(combos)]
    if w not in seen:
        seen.add(w); picked.append(w)
    i += step
    if i >= len(combos):
        i = (i - len(combos)) + 1.0
assert len(picked) == len(set(picked)) == 1024
import sys
sys.stdout.write("\n".join(picked) + "\n")
