from __future__ import annotations

from backend_bryan.regression.synthetic_pcap_corpus import CORPUS, verify_corpus


def test_raw_pcap_corpus_integrity_and_generated_reproducibility() -> None:
    assert len(CORPUS) == 7
    assert verify_corpus(check_rebuilds=True, verbose=False) == []
