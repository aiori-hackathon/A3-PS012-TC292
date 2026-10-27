from dnsassess.classifier import classify
from dnsassess.prober import ProbeResult


def _probe_a(**overrides):
    """Probe A (recursion probe) result with sensible defaults."""
    defaults = dict(
        target_id="t01",
        probe_type="A",
        qname="nonce.probe.lab.test",
        qtype="A",
        flags={"QR": True, "AA": False, "TC": False, "RD": True, "RA": False},
        rcode="NOERROR",
        answer=["nonce.probe.lab.test. 0 IN A 192.0.2.1"],
        response_time_ms=50.0,
        transport="udp",
        error=None,
        nonce="nonce",
        via_forwarder=False,
    )
    defaults.update(overrides)
    return ProbeResult(**defaults)


def _probe_b(**overrides):
    """Probe B (zone probe) result with sensible defaults."""
    defaults = dict(
        target_id="t01",
        probe_type="B",
        qname="owned.t01.lab.test",
        qtype="SOA",
        flags={"QR": True, "AA": False, "TC": False, "RD": False, "RA": False},
        rcode="NOERROR",
        answer=[],
        response_time_ms=30.0,
        transport="udp",
        error=None,
        nonce=None,
        via_forwarder=False,
    )
    defaults.update(overrides)
    return ProbeResult(**defaults)


# ------------------------------------------------------------------
# Rule 1: No response after retries -> Inconclusive (timeout)
# ------------------------------------------------------------------
def test_rule1_no_response_timeout():
    a = _probe_a(rcode="timeout", answer=[], transport="udp", error="timeout")
    b = _probe_b(rcode="skipped", answer=[], transport="none", error="no serves_zone configured")
    result = classify(a, b, [], "172.28.0.101")
    assert result.label == "Inconclusive"
    assert result.reason == "timeout"


# ------------------------------------------------------------------
# Rule 2: SERVFAIL / bad reply -> Inconclusive (servfail / bad_reply)
# ------------------------------------------------------------------
def test_rule2_servfail():
    a = _probe_a(rcode="SERVFAIL", answer=[])
    b = _probe_b(rcode="NOERROR")
    result = classify(a, b, [], "172.28.0.101")
    assert result.label == "Inconclusive"
    assert result.reason == "servfail"


def test_rule2_bad_reply():
    a = _probe_a(rcode="FORMERR", answer=[])
    b = _probe_b(rcode="NOERROR")
    result = classify(a, b, [], "172.28.0.101")
    assert result.label == "Inconclusive"
    assert result.reason == "bad_reply"


# ------------------------------------------------------------------
# Rule 3: NOERROR + expected A + nonce in auth log -> Recursive
# ------------------------------------------------------------------
def test_rule3_recursive_nonce_seen():
    a = _probe_a(rcode="NOERROR", answer=["nonce.probe.lab.test. 0 IN A 192.0.2.1"], nonce="nonce")
    b = _probe_b(rcode="NOERROR")
    entries = [{"nonce": "nonce", "src_ip": "172.28.0.101", "qname": "nonce.probe.lab.test.", "qtype": "A"}]
    result = classify(a, b, entries, "172.28.0.101")
    assert result.label == "Recursive"
    assert result.reason == "nonce_seen_in_auth_log"
    assert result.nonce_seen is True
    assert result.via_forwarder is False


# ------------------------------------------------------------------
# Rule 3b: Recursive via forwarder (src_ip differs from target IP)
# ------------------------------------------------------------------
def test_rule3_recursive_via_forwarder():
    a = _probe_a(rcode="NOERROR", answer=["nonce.probe.lab.test. 0 IN A 192.0.2.1"], nonce="nonce")
    b = _probe_b(rcode="NOERROR")
    entries = [{"nonce": "nonce", "src_ip": "10.0.0.5", "qname": "nonce.probe.lab.test.", "qtype": "A"}]
    result = classify(a, b, entries, "172.28.0.101")
    assert result.label == "Recursive"
    assert result.via_forwarder is True


# ------------------------------------------------------------------
# Rule 4: Answer but no nonce in log -> Inconclusive
# (answer_without_upstream_evidence)
# ------------------------------------------------------------------
def test_rule4_answer_without_nonce():
    a = _probe_a(rcode="NOERROR", answer=["nonce.probe.lab.test. 0 IN A 192.0.2.1"], nonce="nonce")
    b = _probe_b(rcode="NOERROR")
    result = classify(a, b, [], "172.28.0.101")
    assert result.label == "Inconclusive"
    assert result.reason == "answer_without_upstream_evidence"
    assert result.nonce_seen is False


# ------------------------------------------------------------------
# Rule 5: Both probes REFUSED -> Refused
# ------------------------------------------------------------------
def test_rule5_both_refused():
    a = _probe_a(rcode="REFUSED", answer=[], flags={"QR": True, "AA": False, "TC": False, "RD": True, "RA": False})
    b = _probe_b(rcode="REFUSED", answer=[], flags={"QR": True, "AA": False, "TC": False, "RD": False, "RA": False})
    result = classify(a, b, [], "172.28.0.101")
    assert result.label == "Refused"
    assert result.reason == "both_probes_refused"


# ------------------------------------------------------------------
# Rule 5b: Probe A REFUSED + Probe B skipped (no serves_zone) -> Refused
# ------------------------------------------------------------------
def test_rule5_refused_plus_skipped():
    a = _probe_a(rcode="REFUSED", answer=[], flags={"QR": True, "AA": False, "TC": False, "RD": True, "RA": False})
    b = _probe_b(rcode="skipped", answer=[], transport="none", error="no serves_zone configured")
    result = classify(a, b, [], "172.28.0.101")
    assert result.label == "Refused"
    assert result.reason == "both_probes_refused"


# ------------------------------------------------------------------
# Rule 6: Probe B AA=1 + Probe A REFUSED -> Authoritative-only
# ------------------------------------------------------------------
def test_rule6_auth_only_probe_a_refused():
    a = _probe_a(rcode="REFUSED", answer=[], flags={"QR": True, "AA": False, "TC": False, "RD": True, "RA": False})
    b = _probe_b(
        rcode="NOERROR",
        answer=["owned.t01.lab.test. 0 IN SOA ns.owned.t01.lab.test. ... 3600 ..."],
        flags={"QR": True, "AA": True, "TC": False, "RD": False, "RA": False},
    )
    result = classify(a, b, [], "172.28.0.101")
    assert result.label == "Authoritative-only"
    assert result.reason == "zone_answer_without_recursion"


# ------------------------------------------------------------------
# Rule 6b: Probe B AA=1 + Probe A NXDOMAIN without nonce -> Authoritative-only
# ------------------------------------------------------------------
def test_rule6_auth_only_nxdomain_no_nonce():
    a = _probe_a(rcode="NXDOMAIN", answer=[], nonce="nonce")
    b = _probe_b(
        rcode="NOERROR",
        answer=["owned.t01.lab.test. 0 IN SOA ..."],
        flags={"QR": True, "AA": True, "TC": False, "RD": False, "RA": False},
    )
    result = classify(a, b, [], "172.28.0.101")
    assert result.label == "Authoritative-only"
    assert result.reason == "zone_answer_without_recursion"


# ------------------------------------------------------------------
# Rule 6c: Probe B AA=1 + Probe A REFUSED/no answer/NXDOMAIN without nonce
# -> Authoritative-only
# ------------------------------------------------------------------
def test_rule6_auth_only_probe_a_refused():
    a = _probe_a(rcode="REFUSED", answer=[], flags={"QR": True, "AA": False, "TC": False, "RD": True, "RA": False})
    b = _probe_b(
        rcode="NOERROR",
        answer=["owned.t01.lab.test. 0 IN SOA ns.owned.t01.lab.test. ... 3600 ..."],
        flags={"QR": True, "AA": True, "TC": False, "RD": False, "RA": False},
    )
    result = classify(a, b, [], "172.28.0.101")
    assert result.label == "Authoritative-only"
    assert result.reason == "zone_answer_without_recursion"


def test_rule6_auth_only_nxdomain_no_nonce():
    a = _probe_a(rcode="NXDOMAIN", answer=[], nonce="nonce")
    b = _probe_b(
        rcode="NOERROR",
        answer=["owned.t01.lab.test. 0 IN SOA ..."],
        flags={"QR": True, "AA": True, "TC": False, "RD": False, "RA": False},
    )
    result = classify(a, b, [], "172.28.0.101")
    assert result.label == "Authoritative-only"
    assert result.reason == "zone_answer_without_recursion"


# ------------------------------------------------------------------
# Rule 7: Else -> Inconclusive (conflicting_evidence)
# ------------------------------------------------------------------
def test_rule7_conflicting_evidence():
    # Probe A NOERROR with empty answer (no A record), Probe B answers
    # without AA, nonce not seen. Rules 1-6 don't match, falls to 7.
    a = _probe_a(rcode="NOERROR", answer=[], nonce="nonce")
    b = _probe_b(rcode="NOERROR", answer=["some.answer"], flags={"QR": True, "AA": False, "TC": False, "RD": False, "RA": False})
    result = classify(a, b, [], "172.28.0.101")
    assert result.label == "Inconclusive"
    assert result.reason == "conflicting_evidence"


# ------------------------------------------------------------------
# Evidence IDs
# ------------------------------------------------------------------
def test_evidence_ids_recorded():
    a = _probe_a(rcode="NOERROR", answer=["nonce.probe.lab.test. 0 IN A 192.0.2.1"], nonce="nonce")
    b = _probe_b(rcode="NOERROR")
    entries = [{"nonce": "nonce", "src_ip": "172.28.0.101"}]
    result = classify(a, b, entries, "172.28.0.101")
    assert "t01:nonce:A" in result.evidence_ids
