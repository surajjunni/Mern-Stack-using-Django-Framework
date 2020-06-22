class PMIP_Template():
    def __init__(self):
        pass


    def get_login_template_data(self):
        login_data = { "userName":"","password":""}
        return login_data
    
    def get_global_lma_mag_template_data(self):
        """template contains the dictionary of PMIP put data
        """
        lma_timer = {
                "key":"pmipv6GlobalSetting",
                "lmaKeepAliveInterval":30,
                "lmaKeepAliveRetry":5,
                "bindingRefreshTime":300
                }
        return lma_timer


    def get_lma_template_data(self):
        """template contains the dictionary of PMIP post data
        """
        lma_data = {
                "key":"",
                "tenantId":"",
                "profileType":"PMIPv6",
                "name":"LMA Profile",
                "description":"testing",
                "lmaPrimaryIp":"1.1.1.1",
                "lmaSecondaryIp":"2.2.2.2",
                "mnIdType":"NAI_From_Authentication",
                "apn":"",
                }
        return lma_data