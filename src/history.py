import os
from datetime import datetime

_DIR = os.path.dirname(os.path.abspath(__file__))
_HISTORY_FILE = os.path.join(_DIR, "history.txt")
_LIMIT = 200


def log_attack(username, command):
    try:
        with open(_HISTORY_FILE, "a") as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}|{username}|{command}\n")
    except:
        pass


def get_history(username=None, is_admin=False, limit=50):
    try:
        with open(_HISTORY_FILE) as f:
            lines = f.readlines()
    except:
        return []
    result = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        parts = line.split("|", 2)
        if len(parts) < 3:
            continue
        ts, user, cmd = parts[0], parts[1], parts[2]
        if is_admin or user == username:
            result.append({"time": ts, "user": user, "command": cmd})
            if len(result) >= limit:
                break
    return result


def is_admin_user(username):
    try:
        logins = os.path.join(_DIR, "logins.txt")
        with open(logins) as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 3 and parts[0].lower() == "admin" and parts[1].lower() == username.lower():
                    return True
    except:
        pass
    return False


def parse_login_line(line):
    parts = line.strip().split(":")
    if len(parts) >= 2 and parts[0].lower() == "admin":
        uname = parts[1]
        pwd = parts[2]
        exp = parts[3] if len(parts) >= 4 else None
        return uname, pwd, exp, True
    if len(parts) >= 2:
        return parts[0], parts[1], parts[2] if len(parts) >= 3 else None, False
    return None, None, None, False
