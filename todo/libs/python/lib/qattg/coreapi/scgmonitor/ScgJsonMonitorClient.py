import traceback
import qa.ttgcommon.coreapi.common.json_interface as ji
from qattg.coreapi.common.ScgJsonLogin import ScgJsonLogin
from qattg.coreapi.common.ScgJsonConfigApZone import ScgJsonConfigApZone
import json

class ScgJsonMonitorClient():

    def __init__(self, scg_mgmt_ip = "127.0.0.2" ,scg_port ="8443"):
        self.scg_mgmt_ip = scg_mgmt_ip
        self.scg_port = scg_port
        self.http_proto = "https"
        self.jsessionid = "" 
        self.req_api_monitor_client = '/wsg/api/scg/clients/byZone/%s?'
        self.apzone_api = ScgJsonConfigApZone(scg_mgmt_ip=scg_mgmt_ip)
        self.req_api_client_ttg_info = '/wsg/api/scg/clients/ttgsessions/latest/%s/summary?'
        self.req_api_client_pdp_info = '/wsg/api/scg/clients/ttgsessions/latest/%s/pdp?'
        self.req_api_client_gtpu_info = '/wsg/api/scg/clients/ttgsessions/latest/%s/gtpu?'
        self.req_api_client_info = '/wsg/api/scg/clients/%s'
        self.req_api_ttg_client_stats = '/wsg/api/scg/clients/ttgsessions/summary/byZone/%s?isThirdPartyZone=false'
        self.req_api_overall_client = '/wsg/api/scg/domains/%s/domainTree?treeZoneType=All&showStagingZone=false&'
        self.req_api_delete_client = '/wsg/api/scg/clients/%s/disconnect'
        self.req_api_deauth_client = '/wsg/api/scg/clients/%s/deauth'

        self.req_api_of_ap = '/wsg/api/scg/aps/%s?'


    def get_jsessionid(self):
        return self.jsessionid

    def set_jsessionid(self, jsessionid):
        self.jsessionid = jsessionid

    def _login(self, username = 'admin', password = 'ruckus'):
        l = ScgJsonLogin()

        result, self.jsessionid = l.login(scg_mgmt_ip=self.scg_mgmt_ip, scg_port=self.scg_port,
                username=username, password=password)
        return result

    def print_err_validate(self,client,given_data):
        print "Error - In %s the given %s is not found " %(client,given_data)


    def search_client(self, client_mac=None, client_ip=None, 
            domain_label='Administration Domain', apzone_name=None):
        """
        API is used to Search Client

        URI GET: /wsg/api/scg/clients/byZone/<Zone_uuid>?'

        :param str client_mac: Client MAC Address
        :param str client_ip: Client IP Address
        :param str domain_label: AP Zone Domain Name
        :param str apzone_name: Name of AP Zone
        :return: True if Client Found else False
        :rtype: boolean

        """
        _err = (False, {})
        try:

            self.apzone_api.set_jsessionid(self.get_jsessionid())

            domain_uuid = self.apzone_api.get_domain_uuid(domain_label=domain_label)
            
            if not domain_uuid:
                print "search_client(): domain_uuid not found for domain_label: %s" % domain_label
                return _err

            zone_uuid = self.apzone_api.get_apzone_uuid(domain_label=domain_label, apzone_name=apzone_name)
            
            if not zone_uuid:
                print "search_client(): zone_uuid not found for apzone_name: %s" % apzone_name
                return _err

            url = ji.get_url(self.req_api_monitor_client%zone_uuid, self.scg_mgmt_ip, self.scg_port)

            expd_result = (True if client_mac else False, True if client_ip  else False)

            data = ji.get_json_data(url, self.jsessionid)
            
            is_client_found = False
            client_wlan_info = None

            for i in range(0, len(data['data']['list'])):
                is_client_mac_found = False
                is_client_ip_found = False
                if client_mac and (data['data']['list'][i]['key']) == client_mac:
                    is_client_mac_found = True
                if client_ip and data['data']['list'][i]['ipAddress'] == client_ip:
                    is_client_ip_found = True
                actual_result = (is_client_mac_found, is_client_ip_found)
                if expd_result == actual_result:
                    is_client_found = True
                    client_wlan_info = data['data']['list'][i]
                    break

            return is_client_found, client_wlan_info 

        except Exception:
            print traceback.format_exc()
            return _err


    def get_client_info(self, client_mac=None, client_ip=None, 
            domain_label='Administration Domain', apzone_name='Auto-1-APzone'):

        """
        API is used to get Client Info

        :param str client_mac: Client MAC Address
        :param str client_ip: Client IP Address
        :param str domain_label: AP Zone Domain Name
        :param str apzone_name: Name of AP Zone
        :return: Client Information if Client Found else False
        :rtype: Dictionary

        """
        clientinfo = {}
        _client_mac = client_mac.upper()

        try:
            is_client_found, client_wlan_info = self.search_client(client_mac=_client_mac, client_ip=client_ip,
                    domain_label=domain_label, apzone_name=apzone_name)

            if not is_client_found:
                print "get_client_info:: client_mac: %s ip: %s not found" % (_client_mac, client_ip)
                return {}
            else:
                clientinfo.update({'wlan_info': client_wlan_info})

            '''
                getting TTG client info in detail
            '''

            client_common_info = self.get_common_client_info(client_mac=_client_mac)
            if not client_common_info:
                print "get_common_client_info() failed. client_mac: %s" % _client_mac
                return {}
            else:
                clientinfo.update({'common_info': client_common_info})
           
            is_ttg_client = False
            ttg_clients_stats_info_by_apzone = self.get_ttg_client_statics(domain_label = domain_label,apzone_name = apzone_name)
            if ttg_clients_stats_info_by_apzone:
                clientinfo.update({'ttg_stats_info': {}})
                for ttg_client in ttg_clients_stats_info_by_apzone:
                    if 'uePerSessStats' in ttg_client:
                        if ttg_client['uePerSessStats']['ueMac'] == _client_mac:
                            clientinfo['ttg_stats_info'].update({'uePerSessStats' : ttg_client['uePerSessStats'],
                                                                 'ttgInfoSessStats' : ttg_client['ttgInfoSessStats'],})
                            is_ttg_client = True
                            break
            else:
                return clientinfo

            if is_ttg_client:
                client_ttg_info = self.get_client_ttg_info(client_mac=_client_mac)
                if client_ttg_info:
                    clientinfo.update({'ttg_info':client_ttg_info})
                
                client_pdp_info = self.get_client_pdp_info(client_mac=_client_mac)
                if client_pdp_info:
                    clientinfo.update({'pdp_info':client_pdp_info})

                client_gtpu_info = self.get_client_gtpu_info(client_mac=_client_mac)
                if client_gtpu_info:
                    clientinfo.update({'gtpu_info': client_gtpu_info})
                
            return clientinfo
            
        except Exception:
            print traceback.format_exc()
            return {}

    def get_common_client_info(self, client_mac=None):

        """
        API is used to Common Client PDP Info

        URI GET: /wsg/api/scg/clients/<client_mac>

        :param str client_mac: Client MAC Address
        :rtype: Dictionary

        """

        try:
            url = ji.get_url(self.req_api_client_info%client_mac.upper(), self.scg_mgmt_ip, self.scg_port)
            data = ji.get_json_data(url, self.jsessionid)
            return data['data']
        except Exception:
            print traceback.format_exc()
            return False

    def get_client_ttg_info(self, client_mac=None):

        """
        API is used to get Client TTG Info

        URI GET: /wsg/api/scg/clients/ttgsessions/latest/<client_mac>/summary?

        :param str client_mac: Client MAC Address
        :rtype: Dictionary

        """

        try:
            data = None
            url = ji.get_url(self.req_api_client_ttg_info%client_mac.upper(), self.scg_mgmt_ip, self.scg_port)
            data = ji.get_json_data(url, self.jsessionid)
            return data['data']
        except Exception:
            print traceback.format_exc()
            return False

    def get_client_pdp_info(self, client_mac=None):
        

        """
        API is used to get Client PDP Info

        URI GET: /wsg/api/scg/clients/ttgsessions/latest/<client_mac>/pdp?

        :param str client_mac: Client MAC Address
        :rtype: Dictionary

        """
        try: 
            url = ji.get_url (self.req_api_client_pdp_info%client_mac.upper(), self.scg_mgmt_ip, self.scg_port)
            data = ji.get_json_data(url, self.jsessionid)
            return data['data']['list']
        except Exception:
            print traceback.format_exc()
            return False

    def get_client_gtpu_info(self, client_mac=None):
       
        """
        API is used to get Client GTPU Info

        URI GET: /wsg/api/scg/clients/ttgsessions/latest/<client_mac>/gtpu?

        :param str client_mac: Client MAC Address
        :rtype: Dictionary

        """

        try:
            url = ji.get_url(self.req_api_client_gtpu_info %client_mac.upper(), self.scg_mgmt_ip, self.scg_port)
            data = ji.get_json_data(url, self.jsessionid)
            return data['data']['list']
        except Exception,e:
            print traceback.format_exc()
            return False

    def get_ttg_client_statics(self, apzone_name='Auto-1-apzone',domain_label = 'Administration Domain'):

        """
        API is used to get Client Statics  Info

        URI GET: /wsg/api/scg/clients/ttgsessions/summary/byZone/<zone_uuid>isThirdPartyZone=false

        :param str client_mac: Client MAC Address
        :param str domain_label: Ap Zone Domain Name
        :rtype: Dictionary

        """

        try:
            self.apzone_api.set_jsessionid(self.get_jsessionid())
            zone_uuid = self.apzone_api.get_apzone_uuid(domain_label=domain_label, apzone_name=apzone_name)
            url = ji.get_url(self.req_api_ttg_client_stats%zone_uuid ,self.scg_mgmt_ip, self.scg_port)
            data = ji.get_json_data(url, self.jsessionid)
            return data['data']['list']
        except Exception:
            print traceback.format_exc()
            return False


    def get_overall_client_details(self, domain_label = 'Administration Domain',apzone_name ="Auto-1-apzone"):

        """
        API is used to get Over All Client Details

        URI GET: /wsg/api/scg/domains/<domain_uuid>/domainTree?treeZoneType=All&showStagingZone=false& 

        :param str client_mac: Client MAC Address
        :param str domain_label: AP Zone Domain Name
        :param str apzone_name: Name of AP Zone
        :rtype: Dictionary

        """

        try:
            self.apzone_api.set_jsessionid(self.get_jsessionid())
            domain_uuid = self.apzone_api.get_domain_uuid(domain_label=domain_label)
            url = ji.get_url(self.req_api_overall_client%domain_uuid, self.scg_mgmt_ip, self.scg_port)
            data = ji.get_json_data(url, self.jsessionid)
            ap = []

            for i in range(0,len(data["data"]["children"])):
                ap.append(data["data"]["children"][i]["text"])
        except Exception:
            print traceback.format_exc()
            return False

    def delete_client(self, client_mac=None, client_ip=None,
            domain_label='Administration Domain', apzone_name='Auto-1-apzone'):
        
        """
        API is used to Delete Client

        URI PUT: /wsg/api/scg/clients/<client_mac>/disconnect

        :param str client_mac: Client MAC Address
        :param str domain_label:AP Zone  Domain Name
        :param str apzone_name: Name of AP Zone
        :return: True if Client Deleted else False
        :rtype: Dictionary

        """


        _client_mac = client_mac.upper()
        try: 
            is_client_found, client_wlan_info = self.search_client(client_mac=_client_mac, client_ip=client_ip,
                    domain_label=domain_label, apzone_name=apzone_name)

            if not is_client_found:
                print "delete_client:: client_mac: %s ip: %s not found" % (_client_mac, client_ip)
                return False

            data1 = {"ssid": client_wlan_info['ssid'],
                     "apName": "RuckusAP","apMac":client_wlan_info['apMac'],
                     "wlanId": client_wlan_info['wlanId']}

            url = ji.get_url(self.req_api_delete_client%client_mac, self.scg_mgmt_ip, self.scg_port)
            data = ji.put_json_data(url, self.jsessionid, data=json.dumps(data1), last_action=False,
                            ssid=client_wlan_info['ssid'],apName="RuckusAP",
                            apMac=client_wlan_info['apMac'],wlanid=client_wlan_info['wlanId'])

            return True

        except Exception:
            print traceback.format_exc()
            return False
        
    def deauth_client(self, client_mac=None, client_ip=None,
            domain_label='Administration Domain', apzone_name='Auto-1-apzone'):
        
        """
        API is used to Deauthenticate Client

        URI PUT: /wsg/api/scg/clients/<client_mac>/deauth

        :param str client_mac: Client MAC Address
        :param str domain_label:AP Zone  Domain Name
        :param str apzone_name: Name of AP Zone
        :param str client_ip: Client ip Address
        :return: True if Client Deauthenticated else False
        :rtype: Dictionary

        """


        _client_mac = client_mac.upper()
        try: 
            is_client_found, client_wlan_info = self.search_client(client_mac=_client_mac, client_ip=client_ip,
                    domain_label=domain_label, apzone_name=apzone_name)

            if not is_client_found:
                print "deauth_client:: client_mac: %s ip: %s not found" % (_client_mac, client_ip)
                return False
            data1 = {"ssid": client_wlan_info['ssid'],
                     "apName": "RuckusAP","apMac":client_wlan_info['apMac'],
                     "wlanId": client_wlan_info['wlanId'],"clientAuditInfo" : _client_mac}
            
            url = ji.get_url(self.req_api_deauth_client%client_mac, self.scg_mgmt_ip, self.scg_port)
            data = ji.put_json_data(url, self.jsessionid, data=data1, last_action=False,
                            ssid=client_wlan_info['ssid'],apName="RuckusAP",
                            apMac=client_wlan_info['apMac'],wlanid=client_wlan_info['wlanId'],deauth=True)

            return True

        except Exception:
            print traceback.format_exc()
            return False
        
    def is_client_authorized(self, client_mac=None, client_ip=None,
            domain_label='Administration Domain', apzone_name='Auto-1-apzone'):
        
        """
        API is used to Deauthenticate Client

        URI PUT: /wsg/api/scg/clients/<client_mac>/deauth

        :param str client_mac: Client MAC Address
        :param str domain_label:AP Zone  Domain Name
        :param str apzone_name: Name of AP Zone
        :param str client_ip: Client ip Address
        :return: True if Client Deauthenticated else False
        :rtype: Dictionary

        """


        _client_mac = client_mac.upper()
        try: 
            is_client_found, client_wlan_info = self.search_client(client_mac=_client_mac, client_ip=client_ip,
                    domain_label=domain_label, apzone_name=apzone_name)

            if not is_client_found:
                print "is_client_authorized:: client_mac: %s ip: %s not found" % (_client_mac, client_ip)
                return False
            if client_wlan_info['status'] == "AUTHORIZED":
                print "is_client_authorized:: client_mac: %s ip: %s is authorized" % (_client_mac, client_ip)
                return True
            else:
                print "is_client_authorized:: client_mac: %s ip: %s is not authorized client status is: %s" % (_client_mac, client_ip, client_wlan_info['status'] )


            return True

        except Exception:
            print traceback.format_exc()
            return False    
    def get_ap_info(self,ap_mac = ""):

        """
        API is used to get Client AP Info

        URI GET: /wsg/api/scg/aps/<ap_mac>

        :param str client_mac: Client MAC Address
        :rtype: Dictionary

        """


        try:
            url = ji.get_url(self.req_api_of_ap%ap_mac, self.scg_mgmt_ip, self.scg_port)
            data = ji.get_json_data(url, self.jsessionid)
            return data["data"]
        except Exception:
            print traceback.format_exc()
            return False

    def verify_ap_info(self,ap_mac="",apzone_name ="Auto-1-apzone"):

        """
        API is used to get Client PDP Info

        URI GET:

        :param str apzone_name: Name of AP Zone
        :return: True if Ap Info is Verifed else False
        :rtype: boolean

        """
    
        ap_data = {}
        ap_data = self.get_ap_info(ap_mac = ap_mac)
        for i in range(0,len(ap_data)):
            if ap_data["clientCount"] == 0:
                print "Invalid client count",ap_data["clientCount"]
                break
            else:
                print "valid client count",ap_data["clientCount"]
                break
    

"""

if __name__ == '__main__':
    client_mac = "60:36:DD:C5:E5:72"

    domain_label="Administration Domain"
    #apzone_name='Auto-1-SPY'
    username='admin'
    password='ruckus1!'
    
    apzone_name='Auto-8-SPY'

    sjc = ScgJsonMonitorClient(scg_mgmt_ip='172.19.16.150', scg_port='8443')
    if not sjc._login(username=username, password=password):
        print "login failed"
        sys.exit(1)
    print "login: success"

    clientinfo = sjc.get_client_info(client_mac = client_mac, domain_label=domain_label, apzone_name=apzone_name,)
    if not clientinfo:
        print "Error - client: %s not found" % client_mac
        sys.exit(1)
    else:
        print "client: %s found. clientinfo: %s" % (client_mac, clientinfo)
                
    print 'Deleting the client mac: %s' % client_mac
    if not sjc.delete_client(client_mac = client_mac, domain_label= domain_label, apzone_name=apzone_name,):
        print 'delete_client(): client_mac: %s failed' % client_mac
    else:
        print 'delete_client(): client_mac: %s success' % client_mac
"""
