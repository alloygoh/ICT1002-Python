from signature import *
class AttackNode:
    def __init__(self,ip:str,country:str,geo:list,targets:dict,invalid_targets:list,errortype=None):
        self.ip = ip
        self.country = country
        self.geo = geo
        # dictionary containing {username:tries}
        self.targets = targets
        # list of invalid usernames
        self.invalid_targets = invalid_targets

        # additional info for ftp sigs
        self.errortype = errortype

        # init to None 1st
        self.attacks = None

    def get_usernames(self) -> list:
        return self.targets.keys()

    def get_validusernames(self) -> list:
        return [t for t in self.targets if t not in self.invalid_targets]

    # calculate total number of requests made by IP
    def get_totaltries(self) -> int:
        return sum(self.targets.values())

    def run_sigs(self,ftp=False):
        if ftp:
            enum_users = []
            is_fuzzing = detect_fuzzing(self)
            bf_users = detect_ftp_bruteforce(self)
        else:
            bf_users = detect_ssh_bruteforce(self)
            enum_users = detect_ssh_enumeration(self)
            is_fuzzing = False
        tmp_dict = {}

        if len(enum_users) > 0:
            tmp_dict['ssh_enum_user'] = enum_users
        if len(bf_users) > 0:
            tmp_dict['user_bruteforce'] = bf_users
        if is_fuzzing:
            tmp_dict['fuzzing'] = True
        self.attacks = tmp_dict
    def sigs_descriptions(self):
        descriptions = []
        for s in self.attacks.keys():
            if s == 'ssh_enum_user':
                descriptions.append('Potential SSH Enumeration Detected (CVE-2018-15473)!')
            elif s == 'user_bruteforce':
                descriptions.append('User Bruteforce Detected!')
            elif s == 'fuzzing':
                descriptions.append('Suspicious Non-Ascii Traffic, Potential Fuzzing Detected!')
        return descriptions
