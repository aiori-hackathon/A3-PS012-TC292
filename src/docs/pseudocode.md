# Scan pseudocode

```text
load scope and rate configuration
validate authorization, target count, and every target's scope
start the global and per-target rate scheduler

for each authorized target:
    check kill switch
    generate a nonce reproducibly from seed and target ID
    send an A query for nonce.test-zone with recursion desired
    if the UDP reply is truncated:
        rate-limit and retry over TCP
    if target has a configured zone:
        send an SOA query with recursion disabled
    append probe evidence

wait for the test-zone log
for each target:
    correlate its nonce with the test-zone log
    classify from response codes, authoritative answer, and nonce evidence
    store label, reason, and evidence references

load seeded ground truth
compare predictions and ground truth
report confusion matrix, accuracy, precision, recall, and mismatch causes
write results.json, results.csv, and report.html with run metadata
```
