def detect_ssh_bruteforce(node):
    brute_users=[]
    for (username,tries) in node.targets.items():
        if tries >= 10:
            brute_users.append(username)
    return brute_users

def detect_ssh_enumeration(node):
    enum_users = []
    for (username,tries) in node.targets.items():
        if tries < 3:
            enum_users.append(username)
    
    if len(enum_users) != 0 and len(set(enum_users) & set(node.invalid_targets)) / len(enum_users) > 0.5:
        return enum_users
    return []

def detect_fuzzing(node):
    if node.errortype.get("unicode")>=10:
        return True
    return False

def detect_ftp_bruteforce(node):
    brute_users=[]
    for (username,tries) in node.targets.items():
        if username == 'UNSPECIFIED':
            continue
        if tries >= 10:
            brute_users.append(username)
    return brute_users