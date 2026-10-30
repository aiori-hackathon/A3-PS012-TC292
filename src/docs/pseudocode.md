# Scan pseudocode

```text
load scope and rate configuration
validate authorization, target count, and every target's scope
start the global and per-target rate scheduler
enforce max_total_queries, max_queries_per_target, and the kill switch before every query

for each authorized target:
    generate a nonce reproducibly from seed and target ID
    send an A query for nonce.test-zone with recursion desired
    on UDP timeout: re-wait on the rate limiter and retry the same qname up to udp_retries
    if the UDP reply is truncated:
        rate-limit and retry over TCP
    if target has a configured zone:
        send an SOA query with recursion disabled (or record a skipped probe with the reason)
    append probe evidence

wait for the test-zone log by polling until every answered probe's nonce appears
for each target:
    correlate its nonce with the test-zone log
    classify from response codes, authoritative answer, and nonce evidence
    store label, reason, attempt count, and evidence references

load seeded ground truth
compare predictions and ground truth
report confusion matrix, accuracy, precision, recall, and mismatch causes
write results.json, results.csv, and report.html with run metadata
```
