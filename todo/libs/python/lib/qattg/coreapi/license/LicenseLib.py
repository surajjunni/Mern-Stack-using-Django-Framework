import qa.ttgcommon.coreapi.common.json_interface as ji
from qattg.coreapi.common.ScgJsonLogin import ScgJsonLogin

class LicenseLib():

    def __init__(self, scg_mgmt_ip='127.0.0.1', scg_port='8443'):
        self.scg_mgmt_ip = scg_mgmt_ip 
        self.scg_port = scg_port
        self.req_api_license = "/wsg/api/scg/globalSettings/license?"
        self.jsessionid = '' 

    def _login(self, username='admin', password='ruckus', **kwargs):

        l = ScgJsonLogin()
        result, self.jsessionid = l.login(scg_mgmt_ip=self.scg_mgmt_ip, scg_port=self.scg_port,
                username=username, password=password)

        return result

    def set_jsessionid(self, jsessionid=''):
        self.jsessionid = jsessionid

    def get_license_stats(self):
        lic_url = ji.get_url(self.req_api_license, self.scg_mgmt_ip, self.scg_port)
        lic_data = ji.get_json_data(lic_url, self.jsessionid)
        ue_lic_data = {}
        for i in range(0, len(lic_data["data"]["licenseUsageList"])):
            if lic_data["data"]["licenseUsageList"][i]["type"] == "UE":
                ue_lic_data.update(lic_data["data"]["licenseUsageList"][i])

        return ue_lic_data["usedCount"], ue_lic_data["availableCount"], ue_lic_data["usageCountPerc"], ue_lic_data["availablCountPerc"]


    def count_license_increment(self, init_status=0, incrmt_status=0):

        if int(init_status[0] + 1) == int(incrmt_status[0]):
            return True
        else:
            print "count_license_increment(): Lic count is not incremented after connect client, expected is: %d and found: %d" %(init_status[0] + 1,incrmt_status[0])
            return False

    def count_license_decrement(self, init_status=0, dcrmt_status=0):
        
        if int(init_status[0] - 1) == int(dcrmt_status[0]):
            return True
        else:
            print "count_license_decrement(): Lic count is not decremented after disconnect client, expected is: %d and found: %d" %(init_status[0] - 1,dcrmt_status[0])
            return False
    





