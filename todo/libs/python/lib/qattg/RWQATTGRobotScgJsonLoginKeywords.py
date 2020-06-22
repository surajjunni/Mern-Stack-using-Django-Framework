from qattg.coreapi.common.ScgJsonLogin import ScgJsonLogin

class RWQATTGRobotScgJsonLoginKeywords():

    def __init__(self):
        self.sjl = None
        self.jsessionid = None
        pass

    def login_to_scg(self, **kwargs):

        self.sjl = ScgJsonLogin()
        res, jsessionid = self.sjl.login(**kwargs)

        if not res:
            raise Exception("Failed to Login to SCG")

        self.jsessionid = jsessionid
        return jsessionid

    def get_jsessionid(self):
        return self.jsessionid

