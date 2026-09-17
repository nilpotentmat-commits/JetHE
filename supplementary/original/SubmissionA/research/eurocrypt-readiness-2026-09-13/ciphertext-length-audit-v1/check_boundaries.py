"""Exact counterexamples guarding the length lemma's hypotheses; no HE or PKE claim."""
from collections import Counter
from fractions import Fraction
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def check():
    rows = []
    assignments = 0
    for bits in range(2, 9):
        size = 1 << bits
        # Full-domain correctness without privacy allows a special short message.
        codes = ['' if m == 0 else '1' + format(m, f'0{bits}b') for m in range(size)]
        for m, c in enumerate(codes):
            assert (0 if not c else int(c[1:], 2)) == m
        uniform_short = Fraction(sum(len(c) == 0 for c in codes), size)
        gap = 1 - uniform_short
        assert uniform_short == Fraction(1, size) and gap == Fraction(size - 1, size)
        # A private one-time encoding can compress a promised subspace.
        kept = bits // 2
        mask = (1 << kept) - 1
        histograms = []
        full_correct = promised_correct = 0
        for m in range(size):
            hist = Counter()
            for key in range(size):
                c = (m ^ key) & mask
                decoded = c ^ (key & mask)
                hist[c] += 1
                full_correct += decoded == m
                if m < (1 << kept):
                    promised_correct += decoded == m
                assignments += 1
            histograms.append(hist)
        assert all(hist == histograms[0] for hist in histograms)
        assert set(histograms[0].values()) == {1 << (bits - kept)}
        assert promised_correct == size * (1 << kept)
        success = Fraction(full_correct, size * size)
        assert success == Fraction(1 << kept, size)
        # The exact short-and-correct counting bound includes all strings up to kept bits.
        exact_count = Fraction((1 << (kept + 1)) - 1, size)
        assert success <= exact_count
        rows.append({'message_bits': bits, 'full_domain_codec_correct': True,
                     'zero_message_length': 0, 'uniform_short_probability': str(uniform_short),
                     'length_distinguishing_gap': str(gap), 'projected_pad_bits': kept,
                     'projected_one_time_view_identical_for_all_messages': True,
                     'promised_subspace_correctness': '1',
                     'uniform_full_domain_correctness': str(success),
                     'uniform_full_domain_error': str(1 - success)})
    return {'status': 'CIPHERTEXT_LENGTH_HYPOTHESIS_COUNTEREXAMPLES_PASS',
            'cases': rows, 'pad_message_key_assignments': assignments,
            'new_he_execution': False, 'new_security_assumption': False,
            'toy_is_reusable_pke': False, 'new_timing_benchmark': False,
            'scope': 'Exact finite counterexamples to omitted privacy or full-domain correctness; not a proof of the asymptotic theorem.'}


if __name__ == '__main__':
    out = check()
    (HERE / 'boundary-check.json').write_text(json.dumps(out, indent=2), encoding='utf-8')
    print(json.dumps({'cases': len(out['cases']), 'pad_message_key_assignments': out['pad_message_key_assignments']}))
