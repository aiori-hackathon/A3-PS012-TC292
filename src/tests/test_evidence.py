"""Polling behaviour of EvidenceStore.wait_for_nonces."""
from __future__ import annotations

import json

from dnsassess.evidence import EvidenceStore


def test_wait_for_nonces_returns_immediately_when_log_has_all(tmp_path):
    log = tmp_path / "queries.jsonl"
    log.write_text(
        json.dumps({"nonce": "abc123", "qname": "abc123.probe.lab.test."}) + "\n",
        encoding="utf-8",
    )
    store = EvidenceStore(tmp_path / "evidence.jsonl")
    index = store.wait_for_nonces(log, {"abc123"}, timeout_seconds=5.0)
    assert "abc123" in index


def test_wait_for_nonces_exits_after_timeout(tmp_path):
    log = tmp_path / "queries.jsonl"
    log.write_text("", encoding="utf-8")
    store = EvidenceStore(tmp_path / "evidence.jsonl")
    state = {"now": 0.0}
    sleeps = []

    def clock():
        return state["now"]

    def sleep(duration):
        sleeps.append(duration)
        state["now"] += duration

    index = store.wait_for_nonces(
        log,
        {"missing-nonce"},
        timeout_seconds=2.0,
        interval=0.5,
        clock=clock,
        sleep=sleep,
    )
    assert index == {}
    assert sleeps, "must poll at least once before giving up"
    # 2s timeout / 0.5s interval -> a bounded number of polls.
    assert len(sleeps) <= 4 + 1


def test_wait_for_nonces_returns_early_once_all_seen(tmp_path):
    log = tmp_path / "queries.jsonl"
    store = EvidenceStore(tmp_path / "evidence.jsonl")
    state = {"now": 0.0}

    def clock():
        return state["now"]

    def sleep(duration):
        state["now"] += duration
        # The nonce arrives after the first poll.
        log.write_text(
            json.dumps({"nonce": "late-nonce", "qname": "x.probe.lab.test."}) + "\n",
            encoding="utf-8",
        )

    index = store.wait_for_nonces(
        log,
        {"late-nonce"},
        timeout_seconds=30.0,
        interval=1.0,
        clock=clock,
        sleep=sleep,
    )
    assert "late-nonce" in index
