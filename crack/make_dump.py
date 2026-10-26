import hashlib

accounts = {
    "liwei": "123456",
    "sofia": "iloveyou",
    "tomk": "qwerty123",
    "aisha": "password1",
    "marie": "mariepw",
    "raj": "Gv7#pLm2!xQ",
}

with open("crack/leaked_users.txt", "w") as f:
    for username, password in accounts.items():
        digest = hashlib.md5(password.encode()).hexdigest()
        f.write(f"{username}:{digest}\n")

print("wrote crack/leaked_users.txt")