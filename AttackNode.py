from signature import *
class AttackNode:
    def __init__(self,ip:str,country:str,geo:list,targets:dict,invalid_targets:list):
        self.ip = ip
        # self.geoinfo = dict{country, etc, etc}
        self.country = country
        self.geo = geo
        # dictionary containing {username:tries}
        self.targets = targets
        self.invalid_targets = invalid_targets

    def get_usernames(self) -> list:
        return self.targets.keys()

    def get_validusernames(self) -> list:
        return [t for t in self.targets if t not in self.invalid_targets]

    def get_totaltries(self) -> int:
        return sum(self.targets.values())

    def run_sigs(self):
        enum_users = detect_ssh_enumeration(self)
        bf_users = detect_bruteforce(self)
        tmp_dict = {}
        if len(enum_users) > 0:
            tmp_dict['ssh_enum_user'] = enum_users
        if len(bf_users) > 0:
            tmp_dict['ssh_bruteforce'] = bf_users
        self.attacks = tmp_dict
