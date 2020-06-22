import json
import traceback
import qa.ttgcommon.coreapi.common.json_interface as ji

class ScgJsonLogin():

    def __init__(self):
        self.jsessionid = None
        pass

    def login(self, scg_mgmt_ip='127.0.0.2', scg_port='8443',
            username='admin', password='ruckus', **kwargs):
        """
        Login to SCG-C GUI with given username and password
        """

        req_api_login = "/wsg/api/public/v5_0/session"
        req_api_login_validation = '/wsg/api/scg/session/validation?'

        data = { "username":"", "password":"",}

        data['username'] = username
        data['password'] = password
        url = ji.get_url(req_api_login, scg_mgmt_ip, scg_port)
        data_json = json.dumps(data)
        jsessionid = ''

        try:
            jsessionid = ji.get_jsessionid(dict(req_uri=req_api_login_validation,
                                                      scg_mgmt_ip=scg_mgmt_ip,
                                                      scg_port=scg_port,
                                                      proto='https'))

            result, jsessionid = ji.login_json_data(url, jsessionid, data_json)
        except Exception:
            print traceback.format_exc()
            return False, None

        self.jsessionid = jsessionid
        return result, jsessionid

    def get_jsessionid(self):
        return self.jsessionid 


