with open('/var/log/authzone/queries.jsonl') as f:
    lines = f.readlines()
entries = [l for l in lines if 'nonce' in l and 'test' not in l.split('"nonce": "')[1].split('"')[0]]
print(f'Real probe entries: {len(entries)}')
for e in entries:
    print(e.strip())