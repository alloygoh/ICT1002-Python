class AttackNode:
    def __init__(self,ip,country,targets,invalid_targets):
        self.ip = ip
        # self.geoinfo = dict{country, etc, etc}
        self.country = country
        # dictionary containing {username:tries}
        self.targets = targets
        self.invalid_targets = invalid_targets

    def get_usernames(self):
        return self.targets.keys()

    def get_validusernames(self):
        return [t for t in self.targets if t not in self.invalid_targets]
