
import hashlib, time

def load_dump(path):
    out = {}
    with open(path) as f:
        for line in f:
            u, d = line.strip().split(":")
            out[u] = d
    return out

accounts = load_dump("crack/leaked_users.txt")
wordlist = [w.strip() for w in open("crack/wordlist.txt") if w.strip()]

start = time.time()
cracked = {}

for candidate in wordlist:
    cd = hashlib.md5(candidate.encode()).hexdigest()
    for u, d in accounts.items():
        if u not in cracked and d == cd:
            cracked[u] = candidate

elapsed = time.time() - start

print(f"cracked {len(cracked)} / {len(accounts)} in {elapsed*1000:.1f} ms")
for u, p in cracked.items():
    print(f"  {u} : {p}")
