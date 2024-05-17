class LabelUtil:
    def __init__(self):
        self.category_label = [
            'BENIGN', 'PORTSCAN', 'RECONNAISSANCE', 'WEB_ATTACK_BRUTE_FORCE', 'WEB_ATTACK_XSS',
            'WEB_ATTACK_SQL_INJECTION',
            'HEARTBLEED', 'EXPLOITS', 'FUZZERS', 'FTP_PATATOR', 'SSH_PATATOR', 'BACKDOOR', 'BOT', 'SHELLCODE', 'WORMS',
            'INFILTRATION', 'DOS_SLOWHTTPTEST', 'DDOS', 'DOS', 'DOS_GOLDENEYE', 'DOS_HULK', 'DOS_SLOWLORIS', 'GENERIC',
            'ANALYSIS'
        ]

        self.user_label = [
            'WEB_ATTACK_BRUTE_FORCE', 'FTP_PATATOR', 'SSH_PATATOR'
        ]

        self.script_label = [
            'WEB_ATTACK_XSS', 'WEB_ATTACK_SQL_INJECTION', 'BACKDOOR', 'INFILTRATION', 'SHELLCODE', 'EXPLOITS', 'GENERIC'
        ]

        self.restricted_script_label = [
            'EXPLOITS', 'GENERIC'
        ]

    @staticmethod
    def get_category_label() -> list:
        label_util = LabelUtil()
        return label_util.category_label

    @staticmethod
    def get_user_label() -> list:
        label_util = LabelUtil()
        return label_util.user_label

    @staticmethod
    def get_script_label() -> list:
        label_util = LabelUtil()
        return label_util.script_label

    @staticmethod
    def get_restricted_script_label() -> list:
        label_util = LabelUtil()
        return label_util.restricted_script_label