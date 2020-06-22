import json
#import sys
import traceback
import copy
from ScgJsonTemplate import ScgJsonTemplate
from qattg.coreapi.common.ScgJsonLogin import ScgJsonLogin
import qa.ttgcommon.coreapi.common.json_interface as ji

class ScgJsonConfig():
    def __init__(self, scg_mgmt_ip="127.0.0.2", scg_port="8443"):
        self.scg_mgmt_ip = scg_mgmt_ip
        self.scg_port = scg_port
        self.req_api_radius = '/wsg/api/scg/aaaServers/proxy/'
        self.req_api_radius_updt_del='/wsg/api/scg/aaaServers/proxy/%s'
        self.req_api_ggsn = '/wsg/api/scg/ggsn/'
        self.req_api_dhcp = '/wsg/api/scg/dhcpserver/'
        self.req_api_dhcp_updt_del = '/wsg/api/scg/dhcpserver/%s'
        self.req_api_cgf = '/wsg/api/scg/cgfs?'
        self.req_api_cgf_updt_del = '/wsg/api/scg/cgfs/%s?'
        self.req_api_ttgpdg = '/wsg/api/scg/serviceProfiles/forwarding/'
        self.req_api_ttgpdg_updt = '/wsg/api/scg/serviceProfiles/forwarding/%s'
        self.req_api_ttgpdg_data = '/wsg/api/scg/serviceProfiles/forwarding?type=TTGPDG'
        self.req_api_eapaka = '/wsg/api/scg/globalSettings/eapaka?'
        self.req_api_eapsim = '/wsg/api/scg/globalSettings/eapsim?'
        self.req_api_wispr = '/wsg/api/scg/hotspots/'
        self.req_api_wispr_data = '/wsg/api/scg/hotspots/byZone/' 
        self.req_api_wispr_updt_del = '/wsg/api/scg/hotspots/%s'
        self.req_api_aaa = '/wsg/api/scg/aaaServers/zone/'
        self.req_api_aaa_updt_del = '/wsg/api/scg/aaaServers/zone/%s' 
        self.req_api_domains = '/wsg/api/scg/session/currentUser/domainList?includeSelf=true'
        self.req_ap_zone_api = '/wsg/api/scg/domains/'
        self.req_api_apzones = '/wsg/api/scg/zones/byDomain/%s'
        self.req_api_ftp = '/wsg/api/scg/globalSettings/mvno/ftps?'
        self.req_api_aaa_data = '/wsg/api/scg/aaaServers/zone/byZone/'
        self.req_api_acctid = '/wsg/api/scg/aaaServers/zone/byZone/'
        self.req_api_aaa_wlan = '/wsg/api/scg/aaaServers/zone/byZone/%s'
        self.req_api_cgf = '/wsg/api/scg/cgfs/'
        self.req_api_guest_pass = '/wsg/api/scg/identity/guestpass/generate/generate'
        self.req_api_guestpass_del = '/wsg/api/scg/identity/guestpass/%s'
        self.req_api_guest_access = '/wsg/api/scg/guestAccess'
        self.req_api_get_wlan_key = '/wsg/api/scg/identity/guestpass/ssids/%s'
        self.req_api_wlan_multiple = '/wsg/api/scg/identity/guestpass/generate/multiple/'
        self.req_api_guestpass_getlatest = '/wsg/api/scg/identity/guestpass/getlatest?'
        self.req_api_mncndc = '/wsg/api/scg/hlrs/mncndc?'
        self.req_api_hotspot = '/wsg/api/scg/hotspotsProfile?'
        self.req_api_hotspot_updt_del = '/wsg/api/scg/hotspotsProfile/%s' 
        self.req_api_radius_id = '/wsg/api/scg/aaaServers/tenant/byTenant?aaaType=%s'
        self.req_api_thirdparty_apzone = '/wsg/api/scg/zones/thirdparty?'
        self.req_api_thirdparty_apzone_updt_del = '/wsg/api/scg/zones/thirdparty/%s'
        self.req_api_auth_profile = '/wsg/api/scg/serviceProfiles/authentication?'
        self.req_api_forwarding_service = '/wsg/api/scg/serviceProfiles/forwarding/service?'
        self.req_api_networktraffic = '/wsg/api/scg/serviceProfiles/networkTraffic/default?'
        self.req_api_thirdparty_apzone_updt_del1 = '/wsg/api/scg/zones/thirdparty/byDomain/%s?'
        self.req_api_ftp_service = '/wsg/api/scg/ftpservice?'
        self.req_api_ftp_service_updt_del = '/wsg/api/scg/ftpservice/%s'
        self.req_api_authprofile = '/wsg/api/scg/serviceProfiles/authentication/'
        self.req_api_acctprofile = '/wsg/api/scg/serviceProfiles/accounting/'
        self.req_api_forwardingprofile = '/wsg/api/scg/serviceProfiles/forwarding?type=%s'
        self.req_api_wispr_wlan = '/wsg/api/scg/hotspots/byZone/%s'
        self.req_api_hotspot_wlan = '/wsg/api/scg/hotspot20/op/byzone/%s'
        self.req_api_radius_for_wispr = '/wsg/api/scg/aaaServers/proxy?aaaType=RADIUS'
        self.req_api_radius_acct_for_wispr = '/wsg/api/scg/aaaServers/proxy?aaaType=RADIUSAcct'
        self.req_api_configwlan = '/wsg/api/scg/wlans/'
        self.req_api_update_authprofile = '/wsg/api/scg/serviceProfiles/authentication/%s'
        self.req_api_auth_service = '/wsg/api/scg/serviceProfiles/authentication/service?type=ALL'
        self.req_api_radius_api = '/wsg/api/scg/aaaServers/proxy?'
        self.req_api_hlr = '/wsg/api/scg/hlrs/'
        self.control_plane_id = '/wsg/api/scg/planes/control/ids?'
        self.map_gateway_settings = '/wsg/api/scg/hlrs/globalsettings?'
        self.req_api_hlr_update ='/wsg/api/scg/hlrs/%s'
        self.req_api_acct_profile = '/wsg/api/scg/serviceProfiles/accounting?'
        self.req_api_acct_service = '/wsg/api/scg/serviceProfiles/accounting/service?'
        self.req_api_update_acctprofile = '/wsg/api/scg/serviceProfiles/accounting/%s'
        self.req_api_accounting = '/wsg/api/scg/serviceProfiles/accounting?'
        self.req_zone_api = '/wsg/api/scg/zones/byDomain/%s'
        self.req_update_ap_zone_api = '/wsg/api/scg/domains/%s/domainTree?treeZoneType=MobilityZone'
        self.req_api_zoneprofile = '/wsg/api/scg/zones?'
        self.req_api_update_zoneprofile = '/wsg/api/scg/zones/%s/config'
        self.req_api_del_zoneprofile = '/wsg/api/scg/zones/%s'
        self.req_api_firmware = '/wsg/api/scg/session/firmwares?'
        self.req_api_deletewlan = '/wsg/api/scg/wlans/byZone/%s'
        self.req_api_configwlan_delete = '/wsg/api/scg/wlans/%s'
        self.req_api_get_tenatuuid = '/wsg/api/scg/session/currentUser?'
        self.req_api_mvno = "/wsg/api/scg/tenants?"
        self.req_api_update_mvno = '/wsg/api/scg/tenants/%s?'
        self.req_api_package = '/wsg/api/scg/packages?'
        self.req_api_package_del = '/wsg/api/scg/packages/%s'
        self.req_api_profile = '/wsg/api/scg/identity/profiles/create?'
        self.req_api_profile_data = '/wsg/api/scg/identity/profiles?'
        self.req_api_del_profile = '/wsg/api/scg/identity/profiles/%s/%s?'

        self.req_api_country_id = '/wsg/api/scg/identity/profiles/countries?'
        self.req_api_get_package = '/wsg/api/scg/identity/profiles/packages?'
        self.jsessionid = ''
        self.http_proto = "https"
        self.req_api_logout = '/wsg/api/scg/session/currentUser/logout?'
        self.req_user_traffic = '/wsg/api/scg/serviceProfiles/userTraffic/?'
        self.SJT = ScgJsonTemplate()

    def _login(self, username='admin', password='ruckus', **kwargs):
        l = ScgJsonLogin()
        result, self.jsessionid = l.login(scg_mgmt_ip=self.scg_mgmt_ip, scg_port=self.scg_port,
                username=username, password=password)

        print "SCG Login: jsessionid: %s" % self.jsessionid
        return result

    def set_jsessionid(self, jsessionid):
        self.jsessionid = jsessionid

    def get_jsessionid(self):
        return self.jsessionid

    def create_ggsn(self, domain_name="Auto_Domain_Name.com", ggsn_ip="1.3.5.7", is_mvno_account=False):  
        """ 
        API used to create GGSN service

        URI: PUT /wsg/api/scg/ggsn/

        :param str domain_name: APN Resolution Domain Name
        :param str ggsn_ip: IP Address to Domain Name
        :param bool is_mvno_account: make True if API used to create GGSN in MVNO Account else False
        :return: True if create GGSN else False
        :rtype: boolean
        """
        result = False
        ggsn_profile = data_ggsn = {}

        try:
            url = ji.get_url(self.req_api_ggsn, self.scg_mgmt_ip, self.scg_port)
            rcv_data_ggsn = ji.get_json_data(url, self.jsessionid)
            data_ggsn = rcv_data_ggsn["data"] 
            if is_mvno_account == False:

                ggsn_profile.update(self.SJT.get_ggsn_template_data())
                ggsn_profile["gtpSettings"]["t3ResponseTimer"] =  ggsn_profile["gtpSettings"]["t3ResponseTimer"] \
                    if not data_ggsn["gtpSettings"]["t3ResponseTimer"] else data_ggsn["gtpSettings"]["t3ResponseTimer"]
                ggsn_profile["gtpSettings"]["echoRequestTimer"] = ggsn_profile["data"]["gtpSettings"]["echoRequestTimer"] \
                    if not data_ggsn["gtpSettings"]["echoRequestTimer"] else data_ggsn["gtpSettings"]["echoRequestTimer"]
                ggsn_profile["gtpSettings"]["responseTimeout"] = ggsn_profile["data"]["gtpSettings"]["responseTimeout"]\
                        if not data_ggsn["gtpSettings"]["responseTimeout"] else data_ggsn["gtpSettings"]["responseTimeout"]
                ggsn_profile["gtpSettings"]["dnsNumberOfRetries"] = ggsn_profile["data"]["gtpSettings"]["dnsNumberOfRetries"] \
                            if not data_ggsn["gtpSettings"]["dnsNumberOfRetries"] else data_ggsn["gtpSettings"]["dnsNumberOfRetries"]

            elif is_mvno_account == True:
                ggsn_profile.update(self.SJT.get_ggsn_template_data_mvno()) 

            else:
                print "invalid data entered in is_mvno_account"
                return False

            for i in range (0, len(rcv_data_ggsn["data"]["ggsns"])):
                ggsn_profile["ggsns"].append({"domainName":rcv_data_ggsn["data"]["ggsns"][i]["domainName"],
                                              "ggsnIPAddress":rcv_data_ggsn["data"]["ggsns"][i]["ggsnIPAddress"]})

            if domain_name:
                for i in range (0, len(rcv_data_ggsn["data"]["ggsns"])):
                    if domain_name == rcv_data_ggsn["data"]["ggsns"][i]["domainName"]:
                        print "create_ggsn(): duplicate entry of domain name : %s" %(domain_name)
                        return False

            if domain_name and ggsn_ip:
                ggsn_profile["ggsns"].append({"domainName":domain_name, "ggsnIPAddress":ggsn_ip})
            else:
                print "domain name and ggsn ip parameters are invalid"
                return False

            for i in range(len(rcv_data_ggsn['data']['dnsServers'])):
                ggsn_profile["dnsServers"].append({"ip":rcv_data_ggsn['data']['dnsServers'][i]['ip'],
                                               "priority":rcv_data_ggsn['data']['dnsServers'][i]["priority"],
                                               "key":rcv_data_ggsn['data']['dnsServers'][i]["key"],
                                               "tenantId":rcv_data_ggsn['data']['dnsServers'][i]["tenantId"]})  
            data_json = json.dumps(ggsn_profile)
            result = ji.put_json_data(url, self.jsessionid, data_json)
        
        except Exception, e:
            print traceback.format_exc()
            return False

        return result
   

    def update_ggsn(self, t3response_timer=None, number_of_retries=None,
                          echo_request_timer=None, response_timeout=None,
                          dnsnumber_of_retries=None, current_domain_name=None,
                          domain_name=None, ggsn_ip=None, is_mvno_account=False):
        """
        API used to  create GGSN Service

        URI: PUT /wsg/api/scg/ggsn/

        :param str t3response_timer: 2 to 5
        :param str number_of_retries: 3 to 6
        :param str echo_request_timer: 60 to 300
        :param str response_timeout: 1 to 10
        :param str dnsnumber_of_retries: 1 to 10
        :param str domain_name: Domain Name
        :param str ggsn_ip: IP Address of GGSN
        :param boolean is_mvno_account: True if MVNO Account else False
        :return: True if GGSN created else False
        :rtype: boolean

        """
        
        result = False
        is_entry_found = False
        fwd_ggsn = {}

        try:

            url = ji.get_url(self.req_api_ggsn, self.scg_mgmt_ip, self.scg_port)

            data_ggsn = ji.get_json_data(url, self.jsessionid)

            if is_mvno_account == False:
                fwd_ggsn.update(self.SJT.get_ggsn_update_template())
                fwd_ggsn["gtpSettings"]["t3ResponseTimer"] = \
                        data_ggsn["data"]["gtpSettings"]["t3ResponseTimer"] if t3response_timer is None else int(t3response_timer)
                fwd_ggsn["gtpSettings"]["numberOfRetries"] = \
                        data_ggsn["data"]["gtpSettings"]["numberOfRetries"] if number_of_retries is None else int(number_of_retries)
                fwd_ggsn["gtpSettings"]["echoRequestTimer"] = \
                        str(data_ggsn["data"]["gtpSettings"]["echoRequestTimer"]) if echo_request_timer is None else echo_request_timer
                fwd_ggsn["gtpSettings"]["responseTimeout"] = \
                        data_ggsn["data"]["gtpSettings"]["responseTimeout"] if response_timeout is None else int(response_timeout)
                fwd_ggsn["gtpSettings"]["dnsNumberOfRetries"] = \
                        data_ggsn["data"]["gtpSettings"]["dnsNumberOfRetries"] if dnsnumber_of_retries is None else int(dnsnumber_of_retries)

            elif is_mvno_account == True:
                fwd_ggsn.update(self.SJT.get_ggsn_update_template_mvno())

            for i in range(0, len(data_ggsn["data"]["ggsns"])):
                fwd_ggsn["ggsns"].append({"domainName":data_ggsn["data"]["ggsns"][i]["domainName"],
                                          "ggsnIPAddress":data_ggsn["data"]["ggsns"][i]["ggsnIPAddress"]})

            if domain_name:
                for i in range(0, len(data_ggsn["data"]["ggsns"])):
                    if data_ggsn["data"]["ggsns"][i]["domainName"] == domain_name:
                        print "update_ggsn(): Duplicate entry of domian name %s" % (domain_name)
                        return False

            if current_domain_name:
                for i in range(0, len(data_ggsn["data"]["ggsns"])):
                    if data_ggsn["data"]["ggsns"][i]["domainName"] == current_domain_name:
                        fwd_ggsn["ggsns"][i].update({"domainName":data_ggsn["data"]["ggsns"][i]["domainName"] \
                                                                   if not  domain_name else domain_name, 
                                                     "ggsnIPAddress":data_ggsn["data"]["ggsns"][i]["ggsnIPAddress"] \
                                                                   if not ggsn_ip else ggsn_ip})
                        is_entry_found = True
                        break

                if not is_entry_found:
                    print "update_ggsn(): domain_name: %s does not exist" % current_domain_name
                    return False

            for i in range(len(data_ggsn['data']['dnsServers'])):
                fwd_ggsn["dnsServers"].append({"ip":data_ggsn['data']['dnsServers'][i]['ip'],
                                               "priority":data_ggsn['data']['dnsServers'][i]["priority"],
                                               "key":data_ggsn['data']['dnsServers'][i]["key"],
                                               "tenantId":data_ggsn['data']['dnsServers'][i]["tenantId"]})
                
            data_json = json.dumps(fwd_ggsn)
            result = ji.put_json_data(url, self.jsessionid, data_json)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

  
    def delete_ggsn(self, domain_name="Auto_Domain_Name.com"):
        """
        API is used to validate GGSN Profile

        URI: GET /wsg/api/scg/ggsn/ 

        :param str t3response_timer: 2 to 5
        :param str number_of_retries: 3 to 6
        :param str echo_request_timer: 60 to 300
        :param str response_timeout: 1 to 10
        :param str dnsnumber_of_retries: 1 to 10
        :param str domain_name: Domain Name
        :param str ggsn_ip: IP Address of GGSN
        :param boolean is_mvno_account: True if MVNO Account else False
        :return: True if GGSN Profile is validated else False
        :rtype: boolean

        """
 
        result = False
        is_entry_found = False
        ggsn_profile = {}

        try:
            url = ji.get_url(self.req_api_ggsn, self.scg_mgmt_ip, self.scg_port)
            ggsn_data = ji.get_json_data(url,self.jsessionid)

            ggsn_profile.update(self.SJT.get_ggsn_update_template())
            ggsn_profile.update(gtpSettings=ggsn_data['data']['gtpSettings'])

            for i in range(0,len(ggsn_data["data"]["ggsns"])):
                if ggsn_data["data"]["ggsns"][i]["domainName"] != domain_name:
                    ggsn_profile["ggsns"].append({'domainName':ggsn_data["data"]["ggsns"][i]["domainName"],
                                                    'ggsnIPAddress':ggsn_data["data"]["ggsns"][i]["ggsnIPAddress"]})
                else:
                    is_entry_found = True

            if not is_entry_found:
                print "delete_ggsn(): domain_name: %s does not exist" % domain_name
                return False

            for i in range(len(ggsn_data['data']['dnsServers'])):
                ggsn_profile["dnsServers"].append({"ip":ggsn_data['data']['dnsServers'][i]['ip'],
                                               "priority":ggsn_data['data']['dnsServers'][i]["priority"],
                                               "key":ggsn_data['data']['dnsServers'][i]["key"],
                                               "tenantId":ggsn_data['data']['dnsServers'][i]["tenantId"]})

            json_data = json.dumps(ggsn_profile)
            result = ji.put_json_data(url, self.jsessionid, json_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result
 
    def validate_ggsn(self, t3response_timer=None, number_of_retries=None,
                          echo_request_timer=None, response_timeout=None,
                          dnsnumber_of_retries=None, domain_name="Auto_Domain_Name.com", ggsn_ip=None):  
        """
        API is used to validate GGSN Profile

        URI: GET /wsg/api/scg/ggsn/ 

        :param str t3response_timer: 2 to 5
        :param str number_of_retries: 3 to 6
        :param str echo_request_timer: 60 to 300
        :param str response_timeout: 1 to 10
        :param str dnsnumber_of_retries: 1 to 10
        :param str domain_name: Domain Name
        :param str ggsn_ip: IP Address of GGSN
        :param boolean is_mvno_account: True if MVNO Account else False
        :return: True if GGSN Profile is validated else False
        :rtype: boolean

        """
 
        rcvd_data = {}
        rcvd_ggsn_data = {'data':{}}
        is_entry_found = False
        is_entry_ip_found = False
        is_entry_domain_found = False
        try:
            url = ji.get_url(self.req_api_ggsn, self.scg_mgmt_ip, self.scg_port)
            rcvd_ggsn_data = ji.get_json_data(url, self.jsessionid)
            rcvd_data = copy.deepcopy(rcvd_ggsn_data["data"])
            
            if t3response_timer:
                if rcvd_data["gtpSettings"]["t3ResponseTimer"] != int(t3response_timer):
                    self._print_err_validate('validate_ggsn', 't3response_timer', 't3ResponseTimer', 
                            t3response_timer, rcvd_data["gtpSettings"]["t3ResponseTimer"])
                    return False
            if number_of_retries:
                if rcvd_data["gtpSettings"]["numberOfRetries"] != int(number_of_retries):
                    self._print_err_validate('validate_ggsn', 'number_of_retries', 'numberOfRetries', 
                            number_of_retries, rcvd_data["gtpSettings"]["numberOfRetries"])
                    return False
            if echo_request_timer:
                if str(rcvd_data["gtpSettings"]["echoRequestTimer"]) != echo_request_timer:
                    self._print_err_validate('validate_ggsn', 'echo_request_timer', 'echoRequestTimer', 
                            echo_request_timer, str(rcvd_data["gtpSettings"]["echoRequestTimer"]))
                    return False
            if response_timeout:
                if rcvd_data["gtpSettings"]["responseTimeout"] != int(response_timeout):
                    self._print_err_validate('validate_ggsn', 'response_timeout', 'responseTimeout', 
                            response_timeout, rcvd_data["gtpSettings"]["responseTimeout"])
                    return False
            if dnsnumber_of_retries:
                if rcvd_data["gtpSettings"]["dnsNumberOfRetries"] != int(dnsnumber_of_retries):
                    self._print_err_validate('validate_ggsn', 'dnsnumber_of_retries', 'dnsNumberOfRetries', \
                        dnsnumber_of_retries, rcvd_data["gtpSettings"]["dnsNumberOfRetries"])
                    return False

            if domain_name and ggsn_ip:
                for i in range (0, len(rcvd_data["ggsns"])):
                    if (rcvd_data["ggsns"][i]["domainName"] == domain_name) and \
                            rcvd_data["ggsns"][i]["ggsnIPAddress"] == ggsn_ip:
                        is_entry_found =  True
                        break
                if not is_entry_found: 
                    print "validate_ggsn(): domain_name [%s] and ggsn_ip [%s] not found" % (
                            domain_name, ggsn_ip)
                    return False
            if domain_name:
                for i in range (0, len(rcvd_data["ggsns"])):
                    if rcvd_data["ggsns"][i]["domainName"] == domain_name:
                        is_entry_domain_found =  True
                        break
                if not is_entry_domain_found: 
                    print "validate_ggsn(): domain_name [%s] not found" % (
                            domain_name)
                    return False
            if ggsn_ip:
                for i in range (0, len(rcvd_data["ggsns"])):
                    if rcvd_data["ggsns"][i]["ggsnIPAddress"] == ggsn_ip:
                        is_entry_ip_found =  True
                        break
                if not is_entry_ip_found:
                    print "validate_ggsn(): ggsn_ip [%s] not found" % (
                            ggsn_ip)
                    return False
            
            return True

        except Exception, e:
            print traceback.format_exc()
            return False

    def _print_err_validate(self, fname, xvar, yvar, x, y):

        """
        API used to print the validate error

        :param str fname: Name of the API
        :param str xvar: user variable name
        :param str yvar: JSON variable name
        :param x: user variable
        :param y: JSON variable
        """
        
        print "%s:: userdata: %s --> [ %s ] != serverdata: %s --> [ %s ]" % (fname, xvar, x, yvar, y)

    def add_dns_server_to_ggsn(self, dns_ip="1.2.3.4"):

        """
        Add DNS Server ip to GGSN 

        URI: PUT  /wsg/api/scg/ggsn/
        
        :param str dns_ip: DNS ip address can be added to GGSN service
        :return: True if add DNS ip success else False
        :rtype: boolean

        """

        result = False
        fwd_data = {}
        try:
            url = ji.get_url(self.req_api_ggsn, self.scg_mgmt_ip, self.scg_port)
            rcv_data_ggsn = ji.get_json_data(url, self.jsessionid)
            data_ggsn = rcv_data_ggsn["data"]
            fwd_data.update(self.SJT.get_ggsn_update_template())
            fwd_data.update(gtpSettings = data_ggsn["gtpSettings"])

            for i in range(0, len(data_ggsn["ggsns"])):
                fwd_data["ggsns"].append({"domainName":data_ggsn["ggsns"][i]["domainName"],
                                          "ggsnIPAddress":data_ggsn["ggsns"][i]["ggsnIPAddress"]}) 
            for i in range(0, len(data_ggsn["dnsServers"])):
                fwd_data["dnsServers"].append({"ip":data_ggsn['dnsServers'][i]['ip'],
                                               "priority":data_ggsn['dnsServers'][i]["priority"],
                                               "key":data_ggsn['dnsServers'][i]["key"],
                                               "tenantId":data_ggsn['dnsServers'][i]["tenantId"]})
            for i in range(0,len(data_ggsn["dnsServers"])):
                if data_ggsn["dnsServers"][i]["ip"] == dns_ip:
                    print "add_dns_server_to_ggsn(): dns_ip %s already exists" % (dns_ip)
                    return False

            if len(data_ggsn["dnsServers"]) < 2:        
                no_of_dnsservers = len(data_ggsn["dnsServers"])
                fwd_data["dnsServers"].append({ "ip":dns_ip, "priority": no_of_dnsservers+1}) 
            else:
                print "list full"
                return False

            data_json = json.dumps(fwd_data)
            result = ji.put_json_data(url, self.jsessionid, data_json)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def validate_dnsip_in_ggsn(self, dns_ip="1.2.3.4"):
        """
        API is used to validate DNS IP in GGSN Profile
        
        URI: GET /wsg/api/scg/ggsn/

        :param str dns_ip: IP Address of DNS IP
        :return: True if DNS IP Address is validated else False
        :rtype: boolean

        """

        rcvd_data = {}
        is_entry_found = False
        try:
            url = ji.get_url(self.req_api_ggsn, self.scg_mgmt_ip, self.scg_port)
            rcvd_ggsn_data = ji.get_json_data(url, self.jsessionid)
            rcvd_data = copy.deepcopy(rcvd_ggsn_data["data"])
            if dns_ip:
                for i in range(0, len(rcvd_data["dnsServers"])):
                    if rcvd_data["dnsServers"][i]["ip"] == dns_ip:
                        is_entry_found = True
                        break
                if is_entry_found == False:
                    print "validate_dnsip_in_ggsn(): dns_ip %s not found" % (dns_ip)
                    return False

            return True

        except Exception, e:
            print traceback.format_exc()
            return False

    def update_dns_server_in_ggsn(self, current_dns_ip="1.2.3.4", new_dns_ip=None, new_priority=None):
        """
        API used to update DNS Server in GGSN

        URI: PUT /wsg/api/scg/ggsn/
        
        :param str current_dns_ip: DNS IP address
        :param str new_dns_ip: New IP address of DNS Server
        :param str new_priority: New Priority of DNS IP
        :return: True if DNS Server in GGSN is updated else False
        :rtype: boolean

        """
        
        result = False
        current_priority = None
        _priority = None
        _index = 0
        _updt_index = 0
        is_entry_found = False
           
        #if not new_priority and not new_dns_ip:
        #    print "update_dns_servers_in_ggsn(): Nothing to update"
        #    return False

        try:
            url = ji.get_url(self.req_api_ggsn, self.scg_mgmt_ip, self.scg_port)
            rcv_data_ggsn = ji.get_json_data(url, self.jsessionid)
            data_ggsn = rcv_data_ggsn["data"]
            fwd_data = {} 
            fwd_data.update(self.SJT.get_ggsn_update_template())
            fwd_data.update(gtpSettings = data_ggsn["gtpSettings"])
            
            for i in range(0, len(data_ggsn["ggsns"])):
                fwd_data["ggsns"].append({"domainName":data_ggsn["ggsns"][i]["domainName"],
                                          "ggsnIPAddress":data_ggsn["ggsns"][i]["ggsnIPAddress"]})
            
            for i in range(0, len(data_ggsn["dnsServers"])):
                fwd_data["dnsServers"].append({"ip":data_ggsn['dnsServers'][i]['ip'],
                                               "priority":data_ggsn['dnsServers'][i]["priority"],
                                               "key":data_ggsn['dnsServers'][i]["key"],
                                               "tenantId":data_ggsn['dnsServers'][i]["tenantId"]}) 
            
            #find dns entry (if any) having this new priority and steal its priority
            if new_priority:
                if int(new_priority) > len(fwd_data["dnsServers"]):
                    print "update_dns_servers_in_ggsn(): new_priority: %d out of range" % int(new_priority)
                    return False
                for dns_entry in fwd_data["dnsServers"]:
                    if dns_entry['priority'] == int(new_priority):
                        _priority = dns_entry['priority']
                        break
                    _index = _index + 1

            for dns_entry in fwd_data["dnsServers"]:
                if dns_entry['ip'] == current_dns_ip:
                    is_entry_found = True
                    current_priority = dns_entry['priority']
                    break
                _updt_index = _updt_index + 1


            if not is_entry_found:
                print "update_dns_servers_in_ggsn(): current_dns_ip: %s not found" % current_dns_ip
                return False

            if _priority is not None:
                #swap priorities
                fwd_data['dnsServers'][_index]['priority'], fwd_data['dnsServers'][_updt_index]['priority'] = current_priority, new_priority
            else:
                #This is new priority
                if new_priority:
                    fwd_data['dnsServers'][_updt_index]['priority'] = new_priority

            if new_dns_ip:
                #update dns IP
                fwd_data['dnsServers'][_updt_index]['ip'] = new_dns_ip

            #swap the elements in dnsServers list 
            fwd_data['dnsServers'][_index], fwd_data['dnsServers'][_updt_index] = \
                    fwd_data['dnsServers'][_updt_index], fwd_data['dnsServers'][_index]

            data_json = json.dumps(fwd_data)
            result = ji.put_json_data(url, self.jsessionid, data_json)
        
        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def delete_dns_server_in_ggsn(self, dns_ip="1.2.3.4", is_mvno_account=False):
        """
        API is used to delete dns servers in GGSN

        URI: PUT /wsg/api/scg/ggsn/

        :param str dns_ip: dns server IP Address of GGSN
        :param boolean is_mvno_account: True | False
        :return: if dns servers in GGSN is deleted else False
        :rtype: boolean

        """

        result = False
        is_entry_found = False
        ggsn_profile = {}

        try:
            url = ji.get_url(self.req_api_ggsn, self.scg_mgmt_ip, self.scg_port)
            ggsn_data = ji.get_json_data(url, self.jsessionid)
            if is_mvno_account == False:
                ggsn_profile.update(self.SJT.get_ggsn_update_template())
                ggsn_profile["gtpSettings"]["t3ResponseTimer"] = ggsn_data["data"]["gtpSettings"]["t3ResponseTimer"] 
                ggsn_profile["gtpSettings"]["numberOfRetries"] = ggsn_data["data"]["gtpSettings"]["numberOfRetries"] 
                ggsn_profile["gtpSettings"]["echoRequestTimer"] = ggsn_data["data"]["gtpSettings"]["echoRequestTimer"] 
                ggsn_profile["gtpSettings"]["responseTimeout"] = ggsn_data["data"]["gtpSettings"]["responseTimeout"]
                ggsn_profile["gtpSettings"]["dnsNumberOfRetries"] = ggsn_data["data"]["gtpSettings"]["dnsNumberOfRetries"]
            else:
                ggsn_profile.update(self.SJT.get_ggsn_update_template_mvno())

            for i in range(0, len(ggsn_data["data"]["ggsns"])):
                ggsn_profile["ggsns"].append({"domainName":ggsn_data["data"]["ggsns"][i]["domainName"],
                                              "ggsnIPAddress":ggsn_data["data"]["ggsns"][i]["ggsnIPAddress"]})

            for i in range(0,len(ggsn_data[u"data"][u"dnsServers"])):
                if ggsn_data[u"data"][u"dnsServers"][i][u"ip"] != dns_ip:
                    ggsn_profile["dnsServers"].append({'priority':ggsn_data[u"data"][u"dnsServers"][i][u"priority"],
                                                       'ip':ggsn_data[u"data"][u"dnsServers"][i][u"ip"],
                                                       "key":ggsn_data['data']['dnsServers'][i]['key'],
                                                       "tenantId":ggsn_data['data']['dnsServers'][i]['tenantId']})
                else:
                    is_entry_found = True

            if not is_entry_found:
                print "delete_dns(): IP: %s does not exist" 
                return False

            json_data = json.dumps(ggsn_profile)
            result = ji.put_json_data(url, self.jsessionid, json_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result
 

    def create_radius_service(self, service_name="Auto_Radius_Service",
                              description=None,
                              service_type="RADIUS",                                       # RADIUS or RADIUSAcct
                              radius_accounting_support_backup='0',                        # 0 or 1
                              radius_support_backup='0',                                   # 0 or 1
                              response_window='20', zombie_period='40',
                              revive_interval='120', noresponse_fail="false",
                              max_outstanding_req='0', threshold='0', sanity_timer='10',
                              primary_ip="1.2.1.1", primary_port="1812", primary_share_secret="testing123",
                              secondary_ip=None, secondary_port=None, secondary_share_secret=None):
        """ 
        API used to create RADIUS Service

        URI: POST /wsg/api/scg/aaaServers/proxy/

        :param str service_name: Name of Radius Service
        :param str description: Description
        :param str service_type: RADIUS | RADIUSAcct
        :param str radius_accounting_support_backup: 0 | 1
        :param str radius_support_backup: 0 | 1
        :param str response_window: Response Window
        :param str zombie_period: ZombiePeriod
        :param str revive_interval: Revive Interval
        :param str noresponse_fail: No Response Fail
        :param str primary_ip: Primary Server IP
        :param str primary_port: Primary Server Port
        :param str primary_share_secret: Primary Server Secret
        :param str secondary_ip: Secondary Server IP
        :param str secondary_port: Secondary Server Port
        :param str secondary_share_secret: Secondary Server Secret
        :return: True if RADIUS service created else False
        :rtype: boolean
        
        """

        result = False
        radius_service={}
        
        try:
            url = ji.get_url(self.req_api_radius, self.scg_mgmt_ip, self.scg_port)
            radius_service.update(self.SJT.get_radius_template_data())
            radius_service.update({"type":service_type, 
                                    "name":service_name,
                                    "description":description,
                                    "primaryIP":primary_ip,
                                    "primaryPort":int(primary_port),
                                    "respWindow":int(response_window),
                                    "zombiePeriod":int(zombie_period),
                                    "reviveInterval":int(revive_interval),
                                    "maxOutstandingRequestsPerServer":int(max_outstanding_req),
                                    "threshold":int(threshold),
                                    "sanityTimer":int(sanity_timer),
                                    "primarySecret":primary_share_secret})
            if service_type == "RADIUS":
                radius_service.update({"responseFail":noresponse_fail})
            elif service_type == "RADIUSAcct":
                radius_service.update({"responseFail":"false"})

            if service_type == "RADIUSAcct" and radius_accounting_support_backup:                                
                radius_service.update({"accountingSupportBackup":int(radius_accounting_support_backup)})

                if int(radius_accounting_support_backup) == 1:
                    radius_service.update({"secondaryIP":secondary_ip,
                                           "secondaryPort":int(secondary_port), 
                                           "secondarySecret":secondary_share_secret})
            elif service_type == "RADIUS" and radius_support_backup:
                radius_service.update({"backup":int(radius_support_backup)})
            
                if int(radius_support_backup) == 1:
                    radius_service.update({"secondaryIP":secondary_ip,
                                           "secondaryPort":int(secondary_port), 
                                           "secondarySecret":secondary_share_secret})

            radius_profile = json.dumps(radius_service)
            result = ji.post_json_data(url, self.jsessionid, radius_profile)

        
        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def validate_radius_service(self, service_name="Auto_Radius_Service",
                              description=None,
                              service_type=None,                                # RADIUS or RADIUSAcct
                              radius_accounting_support_backup=None,            # 0 or 1
                              radius_support_backup=None,                       # 0 or 1
                              response_window=None, zombie_period=None,
                              revive_interval=None, 
                              noresponse_fail=None,                             # true or false
                              max_outstanding_req=None, threshold=None, sanity_timer=None,
                              primary_ip=None, primary_port=None, primary_share_secret=None,
                              secondary_ip=None, secondary_port=None, secondary_share_secret=None):
        """
        
        API is used to Validate Radius Service
           
        URI: GET /wsg/api/scg/aaaServers/proxy/ 

        :param str service_name: Name of Radius Service
        :param str description: Description
        :param str service_type: RADIUS | RADIUSAcct
        :param str radius_accounting_support_backup: 0 | 1
        :param str radius_support_backup: 0 | 1
        :param str response_window: Response Window
        :param str zombie_period: ZombiePeriod
        :param str revive_interval: Revive Interval
        :param str noresponse_fail: No Response Fail
        :param str primary_ip: Primary Server IP
        :param str primary_port: Primary Server Port
        :param str primary_share_secret: Primary Server Secret
        :param str secondary_ip: Secondary Server IP
        :param str secondary_port: Secondary Server Port
        :param str secondary_share_secret: Secondary Server Secret
        :return: True if RADIUS service is validated else False
        :rtype: boolean 
        """

        
        try:
            url = ji.get_url(self.req_api_radius, self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_radius_service(url=url, name=service_name)
            if service_name:
                if rcvd_data["name"] != service_name:
                    self._print_err_validate('validate_radius_service', 'profile_name',
                            'name', service_name, rcvd_data["name"])
                    return False
            if description:
                if rcvd_data["description"] != description:
                    self._print_err_validate('validate_radius_service','description', 'description', description, rcvd_data["description"])
                    return False
            if service_type:
                if rcvd_data["type"] != service_type:
                    self._print_err_validate('validate_radius_service', 'profile_type',
                            'type', service_type, rcvd_data["type"])
                    return False
            if radius_accounting_support_backup:
                if rcvd_data["accountingSupportBackup"] != int(radius_accounting_support_backup):
                    self._print_err_validate('validate_radius_service','radius_accounting_support_backup','accountingSupportBackup',
                            int(radius_accounting_support_backup), rcvd_data["accountingSupportBackup"])
                    return False
            if radius_support_backup: 
                if rcvd_data["backup"] != int(radius_support_backup):
                    self._print_err_validate('validate_radius_service','radius_support_backup', 'backup', int(radius_support_backup), 
                            int(rcvd_data["backup"]))
                    return False
            if response_window:
                if rcvd_data["respWindow"] != int(response_window):
                    self._print_err_validate('validate_radius_service', 'response_window', 'respWindow', int(response_window), 
                            rcvd_data["respWindow"])
                    return False
            if zombie_period:
                if rcvd_data["zombiePeriod"] != int(zombie_period):
                    self._print_err_validate('validate_radius_service', 'zombie_period', 'zombiePeriod', int(zombie_period), 
                            rcvd_data["zombiePeriod"])
                    return False
            if revive_interval:
                if rcvd_data["reviveInterval"] != int(revive_interval):
                    self._print_err_validate('validate_radius_service', 'revive_interval', 'reviveInterval', 
                            int(revive_interval), rcvd_data["reviveInterval"])
                    return False
            if noresponse_fail:
                if not service_type:
                    print "invalid input: service_type"
                    return False
                if service_type == "RADIUSAcct":
                    noresponse_fail = "false"

                _var = str(noresponse_fail)
                _bool_var = json.loads(_var)
                if rcvd_data["responseFail"] != _bool_var:
                    self._print_err_validate('validate_radius_service', 'noresponse_fail','responseFail', noresponse_fail, rcvd_data["responseFail"])
                    return False

            if max_outstanding_req:
                if rcvd_data["maxOutstandingRequestsPerServer"] != int(max_outstanding_req):
                    self._print_err_validate('validate_radius_service', 'max_outstanding_req', 'maxOutstandingRequestsPerServer',
                            int(max_outstanding_req), rcvd_data["maxOutstandingRequestsPerServer"])
                    return False
            if threshold:
                if rcvd_data["threshold"] != int(threshold):
                    self._print_err_validate('validate_radius_service', 'threshold', 'threshold', int(threshold), rcvd_data["threshold"])
                    return False
            if sanity_timer:
                if rcvd_data["sanityTimer"] != int(sanity_timer):
                    self._print_err_validate('validate_radius_service', 'sanity_timer', 'sanityTimer', int(sanity_timer),
                            rcvd_data["sanityTimer"])
                    return False

            if primary_ip:
                if rcvd_data["primaryIP"] != primary_ip:
                    self._print_err_validate('validate_radius_service', 'primary_ip', 'primaryIP', primary_ip, rcvd_data["primaryIP"])
                    return False
            if primary_port:
                if rcvd_data["primaryPort"] != int(primary_port):
                    self._print_err_validate('validate_radius_service', 'primary_port', 'primaryPort', int(primary_port), rcvd_data["primaryPort"])
                    return False
            if primary_share_secret:
                if rcvd_data["primarySecret"] != primary_share_secret:
                    self._print_err_validate('validate_radius_service', 'primary_share_secret', 'primarySecret', primary_share_secret,
                            rcvd_data["primarySecret"])
                    return False
            
            if secondary_ip:
                if rcvd_data["secondaryIP"] != secondary_ip:
                    self._print_err_validate('validate_radius_service', 'secondary_ip', 'secondaryIP', secondary_ip, rcvd_data["secondaryIP"])
                    return False

            if secondary_port:
                if rcvd_data["secondaryPort"] != int(secondary_port):
                    self._print_err_validate('validate_radius_service', 'secondary_port', 'secondaryPort', int(secondary_port),
                        rcvd_data["secondaryPort"])
                    return False

            if secondary_share_secret:
                if rcvd_data["secondarySecret"] != secondary_share_secret:
                    self._print_err_validate('validate_radius_service', 'secondary_share_secret', 'secondarySecret', secondary_share_secret,
                        rcvd_data["secondarySecret"])
                    return False

            return True

        except Exception, e:
            print traceback.format_exc()
            return False
                
    def _get_key_for_radius_service(self, url=None, name="Auto_Radius_Service"):
        
        """
        API used to get the key and data of Radius Service

        :param unicode url: URL 
        :param str name: Name of Radius Service
        :return: key and data
        :rtype: unicode, dictionary
        
        """

        key, data = None, None
        rcv_data = ji.get_json_data(url, self.jsessionid)
        for i in range(0, len(rcv_data["data"]["list"])):
            if rcv_data["data"]["list"][i]["name"] == name:
                key, data = rcv_data["data"]["list"][i]["key"], rcv_data["data"]["list"][i]
                break

        if not key:
            raise Exception("_get_key_for_radius_service():Key not found for the name: %s" % (name))

        return key, data

    def update_radius_service(self, current_service_name="Auto_Radius_Service", new_service_name=None, description=None, 
                              radius_accounting_support_backup=None,                            
                              radius_support_backup=None,                                       
                              response_window=None, zombie_period=None, revive_interval=None,
                              max_outstanding_req=None, threshold=None, sanity_timer=None,
                              noresponse_fail=None,                                             
                              primary_ip=None, primary_port=None, primary_shared_secret=None,
                              secondary_ip=None, secondary_port=None, secondary_shared_secret=None):
        """ 
        API used to update the RADIUS Service
        
        URI: PUT /wsg/api/scg/aaaServers/proxy/<radius_service_key>

        :param str current_service_name: Name of Radius Service
        :param str new_service_name: New Radius service name
        :param str description: Description
        :param str service_type: RADIUS | RADIUSAcct
        :param str radius_accounting_support_backup: 0 | 1
        :param str radius_support_backup: 0 | 1
        :param str response_window: Response Window
        :param str zombie_period: ZombiePeriod
        :param str revive_interval: Revive Interval
        :param str noresponse_fail: No Response Fail
        :param str primary_ip: Primary Server IP
        :param str primary_port: Primary Server Port
        :param str primary_share_secret: Primary Server Secret
        :param str secondary_ip: Secondary Server IP
        :param str secondary_port: Secondary Server Port
        :param str secondary_share_secret: Secondary Server Secret
        :return: True if RADIUS service updated else False
        :rtype: boolean

        """
        result = False
        json_data = None 
        fwd_radius_data = {}
        try:
            url = ji.get_url(self.req_api_radius, self.scg_mgmt_ip, self.scg_port)
            key, rcv_radius_data = self._get_key_for_radius_service(url=url, name=current_service_name)
            profile_type = rcv_radius_data["type"]
            fwd_radius_data["type"] = rcv_radius_data["type"]
            fwd_radius_data["name"] = rcv_radius_data["name"]if new_service_name is None else new_service_name
            fwd_radius_data["key"] = rcv_radius_data["key"]
            fwd_radius_data["tenantId"] = rcv_radius_data["tenantId"]
            fwd_radius_data["description"] = rcv_radius_data["description"]if description is None else description
            fwd_radius_data["primaryIP"] = rcv_radius_data["primaryIP"]if primary_ip is None else primary_ip 
            fwd_radius_data["primarySecret"] = rcv_radius_data["primarySecret"]if primary_shared_secret is None else primary_shared_secret 
            fwd_radius_data["primaryPort"] = rcv_radius_data["primaryPort"]if primary_port is None else int(primary_port)
            fwd_radius_data["responseFail"] = rcv_radius_data["responseFail"]if noresponse_fail is None else noresponse_fail
            fwd_radius_data["respWindow"] = rcv_radius_data["respWindow"]if response_window is None else int(response_window)
            fwd_radius_data["zombiePeriod"] = rcv_radius_data["zombiePeriod"] if zombie_period is None else int(zombie_period)
            fwd_radius_data["reviveInterval"] = rcv_radius_data["reviveInterval"] if revive_interval is None else int(revive_interval)
            fwd_radius_data["maxOutstandingRequestsPerServer"] = rcv_radius_data["maxOutstandingRequestsPerServer"] \
                if  max_outstanding_req is None else int(max_outstanding_req)
            fwd_radius_data["threshold"] = rcv_radius_data["threshold"] if threshold is None else int(threshold)
            fwd_radius_data["sanityTimer"] = rcv_radius_data["sanityTimer"] if sanity_timer is None else int(sanity_timer)

            if profile_type == "RADIUSAcct":
                fwd_radius_data["accountingSupportBackup"] = rcv_radius_data["accountingSupportBackup"] \
                    if radius_accounting_support_backup is None else int(radius_accounting_support_backup) 
                if (secondary_ip or secondary_port or secondary_shared_secret):
                    if fwd_radius_data["accountingSupportBackup"] != 1:
                        print "invalid input: radius accounting support backup"
                        return False
                fwd_radius_data["secondaryIP"] = rcv_radius_data["secondaryIP"] if secondary_ip is None else secondary_ip
                fwd_radius_data["secondaryPort"] = rcv_radius_data["secondaryPort"] if secondary_port is None else int(secondary_port)
                fwd_radius_data["secondarySecret"] = \
                    rcv_radius_data["secondarySecret"] if secondary_shared_secret is None else secondary_shared_secret

            elif profile_type == "RADIUS":
                fwd_radius_data["backup"] = rcv_radius_data["backup"] if radius_support_backup is None else int(radius_support_backup)
                if (secondary_ip or secondary_port or secondary_shared_secret):
                    if fwd_radius_data["backup"] != 1:
                        print "invalid input: radius support backup"
                        return False

                fwd_radius_data["secondaryIP"]= \
                        rcv_radius_data["secondaryIP"] if secondary_ip is None else secondary_ip
                fwd_radius_data["secondaryPort"] = \
                        rcv_radius_data["secondaryPort"] if secondary_port is None else int(secondary_port)
                fwd_radius_data["secondarySecret"] = \
                        rcv_radius_data["secondarySecret"] if secondary_shared_secret is None else secondary_shared_secret
                 
            json_data = json.dumps(fwd_radius_data)
            url_radius_update = ji.get_url(self.req_api_radius_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(url_radius_update, self.jsessionid, json_data)
        
        except Exception, e:
            print traceback.format_exc()
            return False

        return result
        
    def delete_radius_service(self, radius_service_name="Auto_Radius_Service"):
        """ 
        API used to delete the Radius Service

        URI: DELETE /wsg/api/scg/aaaServers/proxy/<radius_service_key>

        :param str radius_service_name: Name of Radius Service
        :return: True if Radius Service deleted else False
        :rtype: boolean

        """
 
        result = False
        try:
            url = ji.get_url(self.req_api_radius, self.scg_mgmt_ip, self.scg_port)
            key, rcv_radius_data = self._get_key_for_radius_service(url=url, name=radius_service_name)
            del_radius_url = ji.get_url( self.req_api_radius_updt_del%key , self.scg_mgmt_ip, self.scg_port)
            result = ji.delete_scg_data(del_radius_url, self.jsessionid, None)

        except Exception, e:
           print traceback.format_exc()
           return False

        return result
 
    def create_dhcp_service(self, dhcp_service_name="Auto_Dhcp_Service", description=None, 
                                  primary_server_ip="1.2.4.5", secondary_server_ip=None):
        
        """ 
        API used to Create the DHCP service

        URI: POST /wsg/api/scg/dhcpserver/ 

        :param str dhcp_service_name: Name of the DHCP service
        :param str description: Description about the Service
        :param str primary_server_ip: IP Address of First server
        :param str secondary_server_ip: IP Address of Second Server
        :return: True if DHCP Service created else False
        :rtype: boolean

        """
        result = False
        dhcp_profile =  {}
        
        try:
            url = ji.get_url(self.req_api_dhcp, self.scg_mgmt_ip, self.scg_port)
        
            dhcp_profile.update(self.SJT.get_dhcp_template_data())
            dhcp_profile.update({"name":dhcp_service_name, 
                                 "description":description,
                                 "firstServer":primary_server_ip, 
                                 "secondServer":secondary_server_ip})
            dhcp_profile = json.dumps(dhcp_profile)
            result = ji.post_json_data(url, self.jsessionid, dhcp_profile)
        
        except Exception, e:
            print traceback.format_exc()
            return False

        return result
    
    def validate_dhcp_service(self, dhcp_service_name="Auto_Dhcp_Service", description=None,
                                    primary_server_ip=None, secondary_server_ip=None):
        """
        API used to Validate the DHCP service

        URI: GET /wsg/api/scg/dhcpserver/ 

        :param str 
        
        dhcp_service_name: Name of the DHCP service
        :param str description: Description about the Service
        :param str primary_server_ip: IP Address of First server
        :param str secondary_server_ip: IP Address of Second Server
        :return: True if DHCP Service validated else False
        :rtype: boolean

        """

        try:
            url = ji.get_url(self.req_api_dhcp, self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_dhcp_service(url=url, name=dhcp_service_name)
            if dhcp_service_name:
                if rcvd_data["name"] != dhcp_service_name:
                    self._print_err_validate('validate_dhcp_service', 'profile_name', 'name',
                            dhcp_service_name, rcvd_data["name"])
                    return False
            if description:
                if rcvd_data['description'] != description:
                    self._print_err_validate('validate_dhcp_service', 'description', 'description',
                            description, rcvd_data['description'])
                    return False
            if primary_server_ip:
                if rcvd_data["firstServer"] != primary_server_ip:
                    self._print_err_validate('validate_dhcp_service', 'primary_server_ip', 'firstServer', primary_server_ip, 
                            rcvd_data["firstServer"])
                    return False
            if secondary_server_ip:
                if rcvd_data["secondServer"] != secondary_server_ip:
                    self._print_err_validate('validate_dhcp_service', 'secondary_server_ip', 'secondServer', secondary_server_ip,
                            rcvd_data["secondServer"])
                    return False

            return True

        except Exception, e:
            print traceback.format_exc()
            return False

    def _get_key_for_dhcp_service(self, url=None, name="Auto_Dhcp_Service"):

        """
        API used to get the key of DHCP service

        :param str url: URL to fetch data
        :param str name: Name of the DHCP service
        :return: key and data of given DHCP service
        :rtype: unicode, dictionary

        """

        key, data = None, None
        rcv_data = ji.get_json_data(url,self.jsessionid)
        for i in range(0, len(rcv_data["data"]["list"])):
            if rcv_data["data"]["list"][i]["name"] == name:
                key, data = rcv_data["data"]["list"][i]["key"], rcv_data["data"]["list"][i]
                break

        if not key:
            raise Exception("_get_key_for_dhcp_service():Key not found for the name: %s" % (name))

        return key, data

    def update_dhcp_service(self, current_dhcp_name="Auto_Dhcp_service", new_dhcp_name=None, 
                                  description=None, primary_server_ip=None, 
                                  secondary_server_ip=None):
        
        """
        API used to Update the DHCP Service

        URI: PUT /wsg/api/scg/dhcpserver/<dhcp_service_key>

        :param str current_dhcp_name: Name of the DHCP Service to be modified
        :param str new_dhcp_name: New name of DHCP Service
        :param str description: Description about the DHCP Service
        :param str primary_server_ip: IP Address of the Primary Server
        :param str secondary_server_ip: IP Address of the Secondary Server
        :return: True if DHCP Service updated else False
        :rtype: boolean
        """
        result = False
        fwd_dhcp_data = {} 
        try:
            url = ji.get_url(self.req_api_dhcp, self.scg_mgmt_ip, self.scg_port)
            key, rcv_dhcp_data = self._get_key_for_dhcp_service(url=url, name=current_dhcp_name)
            fwd_dhcp_data["key"] = key        
            fwd_dhcp_data["tenantId"] = rcv_dhcp_data["tenantId"]
            fwd_dhcp_data["name"] = rcv_dhcp_data["name"] if new_dhcp_name is None else new_dhcp_name
            fwd_dhcp_data["firstServer"] = rcv_dhcp_data["firstServer"] if primary_server_ip is None else primary_server_ip
            fwd_dhcp_data["description"] = rcv_dhcp_data["description"] if description is None else description
            fwd_dhcp_data["secondServer"] = rcv_dhcp_data["secondServer"] if secondary_server_ip is None else secondary_server_ip
                    
            data_json = json.dumps(fwd_dhcp_data)
            url_put_data = ji.get_url(self.req_api_dhcp_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            
            result = ji.put_json_data(url_put_data, self.jsessionid, data_json)
        
        except Exception, e:
            print traceback.format_exc()
            return False

        return result 
    
    def delete_dhcp_service(self, dhcp_service_name="Auto_Dhcp_Service"):
        """
        API used to delete the DHCP Service

        URI: DELETE /wsg/api/scg/dhcpserver/<dhcp_service_key>

        :param str dhcp_service_name: Name of the DHCP Service to be deleted
        :return: True if DHCP Service deleted else False
        :rtype: boolean

        """

        result = False
        try:
            url = ji.get_url(self.req_api_dhcp, self.scg_mgmt_ip, self.scg_port)
            key, rcv_data = self._get_key_for_dhcp_service(url=url, name=dhcp_service_name)
        
            del_dhcp_url = ji.get_url(self.req_api_dhcp_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.delete_scg_data(del_dhcp_url, self.jsessionid, None)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    
    def create_ttgpdg_profile(self, ttgpdg_profile_name="Auto_TTGPDG_profile", description=None,
                                apn_format_to_ggsn="DNS",
                                use_apn_io_for_dns_resolution=False,
                                no_of_acct_retry='5', acct_retry_timeout='5', session_idle_timeout='300',
                                apn="www.ttgpdg.com", 
                                apn_type="NI", 
                                route_type="GTPv1",
                                realm=None):

        """
        API used to create the TTGPDG forwarding profile

        URI: POST /wsg/api/scg/serviceProfiles/forwarding/

        :param str ttgpdg_profile_name: Name of TTGPDG forwarding profile
        :param str description: Descrption on TTGPDG profile
        :param str apn_format_to_ggsn: APN Format to GGSN
        :param str use_apn_io_for_dns_resolution: True | False
        :param str no_of_acct_retry: No.of Accounting retries 1 to 10
        :param str acct_retry_timeout: Accounting retry timeout 1 to 30
        :param str session_idle_timeout: PDG UE session Idle timeout
        :param str apn: Forwarding Policy per Realm APN
        :param str apn_type: NI | NIOI
        :param str route_type: GTPv1 | GTPv2 | PDG
        :param str realm: Realm
        :return: True if create TTGPDG success else False
        :rtype: boolean

        """
        result = False
        ttgpdg_profile = {}

        try:
            url = ji.get_url(self.req_api_ttgpdg, self.scg_mgmt_ip, self.scg_port)

            ttgpdg_profile.update(self.SJT.get_ttgpdg_template_data())
            ttgpdg_profile.update({ "name":ttgpdg_profile_name,
                                    "description":description,
                                    "defaultNoMatchingAPN":apn,
                                    "defaultNoRealmAPN":apn})

            ttgpdg_profile["apnForwardingRealms"].append({"apn":apn, "apnType":apn_type, "routeType":route_type})

            if realm:
                ttgpdg_profile["apnRealms"].append({"realm":realm, "defaultAPN":apn})

            ttgpdg_profile["ttgCommonSetting"].update({"apnFormat2GGSN": apn_format_to_ggsn,
                                                       "apnOIInUse":use_apn_io_for_dns_resolution,
                                                       "acctRetry":int(no_of_acct_retry),
                                                       "acctRetryTimeout":int(acct_retry_timeout),
                                                       "pdgUeIdleTimeout":int(session_idle_timeout)})

            ttgpdg_profile = json.dumps(ttgpdg_profile)
            result = ji.post_json_data(url, self.jsessionid, ttgpdg_profile)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def validate_ttgpdg_profile(self, ttgpdg_profile_name="Auto_TTGPDG_profile", description=None,
                                apn_format_to_ggsn=None,
                                use_apn_oi_for_dns_resolution=False,
                                no_of_acct_retry=None, acct_retry_timeout=None, session_idle_timeout=None,
                                default_nomatching_apn=None, default_norealm_apn=None,
                                apn=None, apn_type=None, route_type=None,
                                realm=None, default_apn=None):
        """
        API is used to Validate TTGPDG Profile

        URI: GET /wsg/api/scg/serviceProfiles/forwarding?type=TTGPDG 

        :param str ttgpdg_profile_name: Name of TTGPDG forwarding profile
        :param str description: Descrption on TTGPDG profile
        :param str apn_format_to_ggsn: APN Format to GGSN
        :param str use_apn_io_for_dns_resolution: True | False
        :param str no_of_acct_retry: No.of Accounting retries 1 to 10
        :param str acct_retry_timeout: Accounting retry timeout 1 to 30
        :param str session_idle_timeout: PDG UE session Idle timeout
        :param str apn: Forwarding Policy per Realm APN
        :param str apn_type: NI | NIOI
        :param str route_type: GTPv1 | GTPv2 | PDG
        :param str realm: Realm
        :return: True if TTGPDG profile is validated else False
        :rtype: boolean

        """

        try:
            url = ji.get_url(self.req_api_ttgpdg_data, self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_ttgpdg_profile(url, ttgpdg_profile_name)
            if ttgpdg_profile_name:
                if rcvd_data["name"] != ttgpdg_profile_name:
                    self._print_err_validate('validate_ttgpdg_profile', 'ttgpdg_profile_name', 'name', ttgpdg_profile_name,
                            rcvd_data["name"])
                    return False
            if description:
                if rcvd_data["description"] != description:
                    self._print_err_validate('validate_ttgpdg_profile', 'description', 'description', description, rcvd_data["description"])
                    return False
            if apn_format_to_ggsn:
                if rcvd_data["ttgCommonSetting"]["apnFormat2GGSN"] != apn_format_to_ggsn:
                    self._print_err_validate('validate_ttgpdg_profile', 'apn_foramt_to_ggsn', 'apnFormat2GGSN', apn_format_to_ggsn,
                            rcvd_data["ttgCommonSetting"]["apnFormat2GGSN"])
                    return False
            if use_apn_oi_for_dns_resolution != rcvd_data["ttgCommonSetting"]["apnOIInUse"]:
                self._print_err_validate('validate_ttgpdg_profile', 'use_apn_io_for_dns_resolution', 'apnOIInUse', use_apn_oi_for_dns_resolution,
                        rcvd_data["ttgCommonSetting"]["apnOIInUse"])
                return False
            if no_of_acct_retry:
                if no_of_acct_retry != str(rcvd_data["ttgCommonSetting"]["acctRetry"]):
                    self._print_err_validate('validate_ttgpdg_profile', 'no_of_acct_retry', 'acctRetry', no_of_acct_retry,
                            rcvd_data["ttgCommonSetting"]["acctRetry"])
                    return False
            if acct_retry_timeout:
                if acct_retry_timeout != str(rcvd_data["ttgCommonSetting"]["acctRetryTimeout"]):
                    self._print_err_validate('validate_ttgpdg_profile', 'acct_retry_timeout', 'acctRetryTimeout', acct_retry_timeout,
                            rcvd_data["ttgCommonSetting"]["acctRetryTimeout"])
                    return False
            if session_idle_timeout:
                if session_idle_timeout != str(rcvd_data["ttgCommonSetting"]["pdgUeIdleTimeout"]):
                    self._print_err_validate('validate_ttgpdg_profile', 'sessoin_idle_timeout', 'pdgUeIdleTimeout', session_idle_timeout,
                            rcvd_data["ttgCommonSetting"]["pdgUeIdleTimeout"])
                    return False
            is_apn_found_for_nomatch_apn = False
            if default_nomatching_apn:
                for i in range(0, len(rcvd_data["apnForwardingRealms"])):
                    if rcvd_data["apnForwardingRealms"][i]["apn"] == default_nomatching_apn:
                        is_apn_found_for_nomatch_apn = True
                        break
                if is_apn_found_for_nomatch_apn is False:
                    print "validate_ttgpdg_profile(): %s apn not found" % (default_nomatching_apn)
                    return False

                if default_nomatching_apn != rcvd_data["defaultNoMatchingAPN"]:
                    self._print_err_validate('validate_ttgpdg_profile','default_nomatching_apn', 'defaultNoMatchingAPN', default_nomatching_apn,
                            rcvd_data["defaultNoMatchingAPN"])
                    return False
            is_apn_found_for_norealm_apn = False
            if default_norealm_apn:
                for i in range(0, len(rcvd_data["apnForwardingRealms"])):
                    if rcvd_data["apnForwardingRealms"][i]["apn"] == default_norealm_apn:
                        is_apn_found_for_norealm_apn = True
                        break
                if is_apn_found_for_norealm_apn is False:
                    print "validate_ttgpdg_profile(): %s apn not found" % (default_nomatching_apn)
                    return False

                if default_norealm_apn != rcvd_data["defaultNoRealmAPN"]:
                    self._print_err_validate('validate_ttgpdg_profile', 'default_norealm_apn', 'defaultNoRealmAPN', default_norealm_apn,
                            rcvd_data["defaultNoRealmAPN"])
                    return False

            _apn_exist = False
            exp_result_for_apn = (True if apn else False, True if apn_type else False, True if route_type else False)
            actual_result_for_apn_list = None
            if rcvd_data["apnForwardingRealms"]:
                for i in range(0, len(rcvd_data["apnForwardingRealms"])):
                    is_apn_entry_found = False
                    is_apn_type_found = False
                    is_route_type_found = False

                    if apn == rcvd_data["apnForwardingRealms"][i]["apn"]:
                        is_apn_entry_found = True
                    if apn_type == str(rcvd_data["apnForwardingRealms"][i]["apnType"]):
                        is_apn_type_found = True
                    if route_type == rcvd_data["apnForwardingRealms"][i]["routeType"]:
                        is_route_type_found = True

                    actual_result_for_apn_list = (is_apn_entry_found, is_apn_type_found, is_route_type_found)
                    if actual_result_for_apn_list == exp_result_for_apn:
                        _apn_exist = True
                        break

                if _apn_exist is False:
                    self._print_err_validate('validate_ttgpdg_profile', 'exp_result_for_apn', 'actual_result_for_apn_list',
                        exp_result_for_apn, actual_result_for_apn_list)
                    return False

            _realm_exist = False
            actual_result_for_realm_list = None
            exp_result_for_realm = (True if realm else False, True if default_apn else False)
            if rcvd_data["apnRealms"]:
                for i in range(0, len(rcvd_data["apnRealms"])):
                    is_default_apn_realm = False
                    is_apn_found = False

                    if rcvd_data["apnRealms"][i]["realm"] == realm:
                        is_default_apn_realm = True
                    if rcvd_data["apnRealms"][i]["defaultAPN"] == default_apn:
                        is_apn_found = True
                    actual_result_for_realm_list = (is_default_apn_realm, is_apn_found)
                    if actual_result_for_realm_list == exp_result_for_realm:
                        _realm_exist = True
                        break

                if _realm_exist is False:
                    self._print_err_validate('validate_ttgpdg_profile', 'exp_result_for_realm', 'actual_result_for_realm_list',
                        exp_result_for_realm, actual_result_for_realm_list)
                    return False

            return True

        except Exception, e:
            print traceback.format_exc()
            return False

    def _get_key_for_ttgpdg_profile(self, url=None, name='Auto_TTGPDG_profile'):
        """
        API used to get the key and data of TTGPDG forwarding profile

        :param str url: URL
        :param str name: Name of TTGPDG forwarding profile
        :return: key and data else raise Exception
        :rtype: unicode, dictionary
        """             

        key, data = None, None
        rcv_data = ji.get_json_data(url, self.jsessionid)
        for i in range(0, len(rcv_data["data"]["list"])):
            if rcv_data["data"]["list"][i]["name"] == name:
                key, data = rcv_data["data"]["list"][i]["key"], rcv_data["data"]["list"][i]
                break

        if not key:
            raise Exception("_get_key_for_ttgpdg_profile():Key not found for the name: %s" % (name))
        
        return key, data
    
    def update_ttgpdg_profile(self, current_ttgpdg_profile_name="Auto_TTGPDG_profile", new_ttgpdg_profile_name=None, description=None,
                                    apn_format_to_ggsn=None,
                                    use_apn_io_for_dns_resolution=False,
                                    no_of_acct_retry=None, acct_retry_timeout=None, session_idle_timeout=None,
                                    default_apn_nomatching_realm=None, default_apn_norealm=None):
        """
        API used to update TTGPDG forwarding profile

        URI: PUT /wsg/api/scg/serviceProfiles/forwarding/<fwd_profile_key>

        :param str current_ttgpdg_profile_name: Name of TTGPDG forwarding profile
        :param str new_profile_name: New name of TTGPDG forwarding profile
        :param str description: Descrption on TTGPDG profile
        :param str apn_format_to_ggsn: APN Format to GGSN
        :param str apn_io_inuse: True | False
        :param str no_of_acct_retry: No.of Accounting retries 1 to 10
        :param str acct_retry_timeout: Accounting retry timeout 1 to 30
        :param str session_idle_timeout: PDG UE session Idle timeout
        :param str default_apn_nomatching_realm: Default APN no mathing Realm
        :param str default_apn_norealm: Default APN no Realm specified
        :return: True if update TTGPDG success else False
        :rtype: boolean

        """

        result = False
        fwd_ttgpdg_data = {}
        try:
            url = ji.get_url(self.req_api_ttgpdg_data, self.scg_mgmt_ip, self.scg_port)
            key, rcv_ttgpdg_data = self._get_key_for_ttgpdg_profile(url, current_ttgpdg_profile_name)
            fwd_ttgpdg_data.update(self.SJT.get_ttgpdg_template_update())
            fwd_ttgpdg_data["name"] = rcv_ttgpdg_data["name"] if new_ttgpdg_profile_name is None else new_ttgpdg_profile_name
            fwd_ttgpdg_data["description"] = rcv_ttgpdg_data["description"] if description is None else description
            fwd_ttgpdg_data["key"] = rcv_ttgpdg_data["key"]
            fwd_ttgpdg_data["tenantId"] = rcv_ttgpdg_data["tenantId"]
            fwd_ttgpdg_data["pdgUeIdleTimeout"] = \
                rcv_ttgpdg_data["ttgCommonSetting"]["pdgUeIdleTimeout"] if session_idle_timeout is None else int(session_idle_timeout)
            fwd_ttgpdg_data["ttgCommonSetting"]["pdgUeIdleTimeout"] = \
                rcv_ttgpdg_data["ttgCommonSetting"]["pdgUeIdleTimeout"] if session_idle_timeout is None else int(session_idle_timeout)
            fwd_ttgpdg_data["ttgCommonSetting"]["apnFormat2GGSN"] = \
                rcv_ttgpdg_data["ttgCommonSetting"]["apnFormat2GGSN"] if  apn_format_to_ggsn is None else  apn_format_to_ggsn
            fwd_ttgpdg_data["ttgCommonSetting"]["apnOIInUse"] = \
                rcv_ttgpdg_data["ttgCommonSetting"]["apnOIInUse"] 
            if use_apn_io_for_dns_resolution and use_apn_io_for_dns_resolution == True: 
                fwd_ttgpdg_data["ttgCommonSetting"]["apnOIInUse"] = True
            elif use_apn_io_for_dns_resolution and use_apn_io_for_dns_resolution == False:
                fwd_ttgpdg_data["ttgCommonSetting"]["apnOIInUse"] = False
            fwd_ttgpdg_data["ttgCommonSetting"]["acctRetry"] = \
                rcv_ttgpdg_data["ttgCommonSetting"]["acctRetry"] if no_of_acct_retry is None else int(no_of_acct_retry)
            fwd_ttgpdg_data["ttgCommonSetting"]["acctRetryTimeout"] = \
                rcv_ttgpdg_data["ttgCommonSetting"]["acctRetryTimeout"] if acct_retry_timeout is None else int(acct_retry_timeout)
            
            for i in range(len(rcv_ttgpdg_data["apnForwardingRealms"])):
                fwd_ttgpdg_data["apnForwardingRealms"].append({"apn":rcv_ttgpdg_data["apnForwardingRealms"][i]["apn"],
                                                               "apnType":rcv_ttgpdg_data["apnForwardingRealms"][i]["apnType"],
                                                               "routeType":rcv_ttgpdg_data["apnForwardingRealms"][i]["routeType"]})
            for i in range(len(rcv_ttgpdg_data["apnRealms"])):
                fwd_ttgpdg_data["apnRealms"].append({"realm":rcv_ttgpdg_data["apnRealms"][i]["realm"],
                                                     "defaultAPN":rcv_ttgpdg_data["apnRealms"][i]["defaultAPN"]})
            is_default_nomatching_apn_found = False
            fwd_ttgpdg_data["defaultNoMatchingAPN"] = rcv_ttgpdg_data["defaultNoMatchingAPN"]

            if default_apn_nomatching_realm:
                for j in range(0, len(rcv_ttgpdg_data["apnForwardingRealms"])):
                    if rcv_ttgpdg_data["apnForwardingRealms"][j]["apn"] == default_apn_nomatching_realm:
                        is_default_nomatching_apn_found = True
                        fwd_ttgpdg_data["defaultNoMatchingAPN"] = default_apn_nomatching_realm
                        break

                if is_default_nomatching_apn_found is False:
                    print "update_ttgdg_profile(): %s apn not found" % (default_apn_nomatching_realm)
                    return False

            is_default_norealm_apn_found  = False
            fwd_ttgpdg_data["defaultNoRealmAPN"] = rcv_ttgpdg_data["defaultNoRealmAPN"]
            if default_apn_norealm:
                for k in range(0, len(rcv_ttgpdg_data["apnForwardingRealms"])):
                    if rcv_ttgpdg_data["apnForwardingRealms"][k]["apn"] ==  default_apn_norealm:
                        is_default_norealm_apn_found = True
                        fwd_ttgpdg_data["defaultNoRealmAPN"] = \
                            rcv_ttgpdg_data["defaultNoRealmAPN"] if default_apn_norealm is None else default_apn_norealm
                        break

                if is_default_norealm_apn_found is False:
                    print "update_ttgdg_profile(): %s apn not found" % (default_apn_norealm)
                    return False

            data_json = json.dumps(fwd_ttgpdg_data)
            put_url = ji.get_url(self.req_api_ttgpdg_updt%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(put_url, self.jsessionid, data_json)
        
        except Exception, e:
            print traceback.format_exc()
            return False

        return result
 
    
    def delete_ttgpdg_profile(self, ttgpdg_profile_name="Auto_TTGPDG_profile"):

        """ 
        API used to delete the TTGPDG profile 

        URI: DELETE /wsg/api/scg/serviceProfiles/forwarding/<ttgpdg_profile_key>

        :param str ttgpdg_profile_name: Name of TTGPDG forwarding profile
        :return: True if TTGPDG profile deleted else False
        :rtype: boolean

        """

        result = False
        try:
            url = ji.get_url(self.req_api_ttgpdg_data, self.scg_mgmt_ip, self.scg_port)
            key, rcv_data = self._get_key_for_ttgpdg_profile(url, ttgpdg_profile_name)

            del_ttgpdg_url = ji.get_url(self.req_api_ttgpdg_updt%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.delete_scg_data(del_ttgpdg_url, self.jsessionid, None)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

 
    def add_forwarding_policy_per_realm_to_ttgpdg_profile(self, ttgpdg_profile_name="Auto_TTGPDG_profile", 
                                                                apn="www.ttgpdg2.com",
                                                                apn_type="NI", route_type= "GTPv1"):

        """ 
        Adds APN to Forwarding Policy per Realm in TTGPDG profile

        URI: PUT /wsg/api/scg/serviceProfiles/forwarding/<fwd_profile_key>
        
        :param str ttgpdg_profile_name: TTGPDG forwading profile name 
        :param str apn: APN to be added
        :param str apn_type: NI | NIOI
        :param str route_type: GTPv1 | GTPv2 | PDG
        :return: True if APN added  to the Forwarding Policy per Realm else False
        :rtype: boolean

        """

        result = False
        fwd_ttgpdg_data = {}
        try:
            url = ji.get_url(self.req_api_ttgpdg_data, self.scg_mgmt_ip, self.scg_port)
            key, rcv_ttgpdg_data = self._get_key_for_ttgpdg_profile(url, ttgpdg_profile_name)
            _found = False
            for i in range(0, len(rcv_ttgpdg_data["apnForwardingRealms"])): #range (len(rcv_ttgpdg_data["apnForwardingRealms"])):
                if apn == rcv_ttgpdg_data["apnForwardingRealms"][i]["apn"]:
                    _found = True
                    break
                
            if _found == True:
                print "add_forwarding_policy_per_realm_to_ttgpdg_profile(): Duplicate apn %s found" % (apn)
                return False

            fwd_ttgpdg_data.update(self.SJT.get_ttgpdg_template_update())
            fwd_ttgpdg_data["name"] = rcv_ttgpdg_data["name"] 
            fwd_ttgpdg_data["description"] = rcv_ttgpdg_data["description"] 
            fwd_ttgpdg_data["key"] = rcv_ttgpdg_data["key"]
            fwd_ttgpdg_data["tenantId"] = rcv_ttgpdg_data["tenantId"]
            fwd_ttgpdg_data["pdgUeIdleTimeout"] = rcv_ttgpdg_data["ttgCommonSetting"]["pdgUeIdleTimeout"] 
            fwd_ttgpdg_data["ttgCommonSetting"]["pdgUeIdleTimeout"] = rcv_ttgpdg_data["ttgCommonSetting"]["pdgUeIdleTimeout"] 
            fwd_ttgpdg_data["ttgCommonSetting"]["apnFormat2GGSN"] = rcv_ttgpdg_data["ttgCommonSetting"]["apnFormat2GGSN"]
            fwd_ttgpdg_data["ttgCommonSetting"]["apnOIInUse"] = rcv_ttgpdg_data["ttgCommonSetting"]["apnOIInUse"]
            fwd_ttgpdg_data["ttgCommonSetting"]["acctRetry"] = rcv_ttgpdg_data["ttgCommonSetting"]["acctRetry"]
            fwd_ttgpdg_data["ttgCommonSetting"]["acctRetryTimeout"] = rcv_ttgpdg_data["ttgCommonSetting"]["acctRetryTimeout"]
            fwd_ttgpdg_data["defaultNoMatchingAPN"] = rcv_ttgpdg_data["defaultNoMatchingAPN"] 
            fwd_ttgpdg_data["defaultNoRealmAPN"] = rcv_ttgpdg_data["defaultNoRealmAPN"] 

            for i in range(0, len(rcv_ttgpdg_data["apnForwardingRealms"])):
                fwd_ttgpdg_data["apnForwardingRealms"].append({"apn":rcv_ttgpdg_data["apnForwardingRealms"][i]["apn"],
                                                               "apnType":rcv_ttgpdg_data["apnForwardingRealms"][i]["apnType"],
                                                               "routeType":rcv_ttgpdg_data["apnForwardingRealms"][i]["routeType"]})

            for i in range(0, len(rcv_ttgpdg_data["apnRealms"])):
                fwd_ttgpdg_data["apnRealms"].append({"realm":rcv_ttgpdg_data["apnRealms"][i]["realm"],
                                                     "defaultAPN":rcv_ttgpdg_data["apnRealms"][i]["defaultAPN"]})

            fwd_ttgpdg_data["apnForwardingRealms"].append({"apn":apn, 
                                                           "apnType":apn_type, 
                                                           "routeType":route_type})
            data= json.dumps(fwd_ttgpdg_data)
            append_url = ji.get_url(self.req_api_ttgpdg_updt%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(append_url, self.jsessionid, data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def validate_forwarding_policy_per_realm_in_ttgpdg_profile(self, ttgpdg_profile_name="Auto_TTGPDG_profile",
                                                               apn=None, apn_type=None, route_type=None):
        """
        API is used to validate Forwarding Policy Per Realm in TTGPDG Profile

        URI: GET /wsg/api/scg/serviceProfiles/forwarding?type=TTGPDG

        :param str ttgpdg_profile_name: TTGPDG forwading profile name 
        :param str apn: APN to be added
        :param str apn_type: NI | NIOI
        :param str route_type: GTPv1 | GTPv2 | PDG
        :return: True if Forwarding Policy Per Realm in TTGPDG Profile is validated else False
        :rtype: boolean
 
        """

        try:
            url = ji.get_url(self.req_api_ttgpdg_data, self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_ttgpdg_profile(url, ttgpdg_profile_name)
            is_apn_found = False
            exp_result_for_apn = (True if apn else False, True if apn_type else False, True if route_type else False)
            actual_result_for_apn = None

            if rcvd_data["apnForwardingRealms"]:
                for i in range(0, len(rcvd_data["apnForwardingRealms"])):
                    is_apn_entry_found = False
                    is_apn_type_found = False
                    is_route_type_found = False

                    if apn == rcvd_data["apnForwardingRealms"][i]["apn"]:
                        is_apn_entry_found = True
                    if apn_type == rcvd_data["apnForwardingRealms"][i]["apnType"]:
                        is_apn_type_found = True
                    if route_type == rcvd_data["apnForwardingRealms"][i]["routeType"]:
                        is_route_type_found = True

                    actual_result_for_apn = (is_apn_entry_found, is_apn_type_found, is_route_type_found)
                    if actual_result_for_apn == exp_result_for_apn:
                        is_apn_found = True
                        break

                if is_apn_found is False:
                    self._print_err_validate('validate_ttgpdg_profile', 'exp_result_for_apn', 'actual_result_for_apn_list',
                        exp_result_for_apn, actual_result_for_apn)
                    return False
            else:
                print "APN List is empty"
                return False

            return True

        except Exception, e:
            print traceback.format_exc()
            return False

    def update_forwarding_policy_per_realm_in_ttgpdg_profile(self, ttgpdg_profile_name="Auto_TTGPDG_profile",
                                                             current_apn="www.ttgpdg.com", new_apn=None, apn_type=None, route_type=None,
                                                             default_nomatch_apn=None, default_norealm_apn=None):
        """
        API is used to create Forwarding Policy Per Realm in TTGPDG Profile

        URI: /wsg/api/scg/serviceProfiles/forwarding/<ttgpdg_service_keys>
        
        :param str ttgpdg_profile_name: TTGPDG forwading profile name 
        :param str current_apn: Origial APN 
        :param new_apn: New APN
        :param str apn_type: NI | NIOI
        :param str route_type: GTPv1 | GTPv2 | PDG
        :param str default_nomatch_apn: default APN
        :param str default_norealm_apn: default APN
        :return: True if Forwarding Policy per Realm is updated in TTGPDG Profile else False
        :rtype: boolean      

        """

        result = False
        is_entry_found = False
        fwd_ttgpdg_data = {}
        try:
            url = ji.get_url(self.req_api_ttgpdg_data, self.scg_mgmt_ip, self.scg_port)
            key, rcv_ttgpdg_data = self._get_key_for_ttgpdg_profile(url, ttgpdg_profile_name)

            _found = False
            for i in range(0, len(rcv_ttgpdg_data["apnForwardingRealms"])):
                if rcv_ttgpdg_data["apnForwardingRealms"][i]["apn"] == new_apn:
                    _found = True
                    break
            if _found == True:
                print "update_forwarding_policy_per_realm_to_ttgpdg_profile(): Duplicate apn %s found" % (new_apn)
                return False

            fwd_ttgpdg_data.update(self.SJT.get_ttgpdg_template_update())
            fwd_ttgpdg_data["name"] = rcv_ttgpdg_data["name"]
            fwd_ttgpdg_data["description"] = rcv_ttgpdg_data["description"]
            fwd_ttgpdg_data["key"] = rcv_ttgpdg_data["key"]
            fwd_ttgpdg_data["tenantId"] = rcv_ttgpdg_data["tenantId"]
            fwd_ttgpdg_data["pdgUeIdleTimeout"] = rcv_ttgpdg_data["ttgCommonSetting"]["pdgUeIdleTimeout"]
            fwd_ttgpdg_data["ttgCommonSetting"]["pdgUeIdleTimeout"] = rcv_ttgpdg_data["ttgCommonSetting"]["pdgUeIdleTimeout"]
            fwd_ttgpdg_data["ttgCommonSetting"]["apnFormat2GGSN"] = rcv_ttgpdg_data["ttgCommonSetting"]["apnFormat2GGSN"]
            fwd_ttgpdg_data["ttgCommonSetting"]["apnOIInUse"] = rcv_ttgpdg_data["ttgCommonSetting"]["apnOIInUse"]
            fwd_ttgpdg_data["ttgCommonSetting"]["acctRetry"] = rcv_ttgpdg_data["ttgCommonSetting"]["acctRetry"]
            fwd_ttgpdg_data["ttgCommonSetting"]["acctRetryTimeout"] = rcv_ttgpdg_data["ttgCommonSetting"]["acctRetryTimeout"]
            fwd_ttgpdg_data["defaultNoMatchingAPN"] = rcv_ttgpdg_data["defaultNoMatchingAPN"]
            fwd_ttgpdg_data["defaultNoRealmAPN"] = rcv_ttgpdg_data["defaultNoRealmAPN"]
             
            for i in range(0, len(rcv_ttgpdg_data["apnForwardingRealms"])):
                fwd_ttgpdg_data["apnForwardingRealms"].append({"apn":rcv_ttgpdg_data["apnForwardingRealms"][i]["apn"],
                                                               "apnType":rcv_ttgpdg_data["apnForwardingRealms"][i]["apnType"],
                                                               "routeType":rcv_ttgpdg_data["apnForwardingRealms"][i]["routeType"]})
            for i in range(0, len(rcv_ttgpdg_data["apnRealms"])):
                fwd_ttgpdg_data["apnRealms"].append({"realm":rcv_ttgpdg_data["apnRealms"][i]["realm"],
                                                     "defaultAPN":rcv_ttgpdg_data["apnRealms"][i]["defaultAPN"]})
            
             
            for j in range(0, len(rcv_ttgpdg_data["apnForwardingRealms"])):
                if rcv_ttgpdg_data["apnForwardingRealms"][j]["apn"]  == current_apn:
                    is_entry_found = True
                    fwd_ttgpdg_data["apnForwardingRealms"][j]["apn"]= \
                            rcv_ttgpdg_data["apnForwardingRealms"][j]["apn"] if new_apn is None else new_apn

                    fwd_ttgpdg_data["apnForwardingRealms"][j]["apnType"]= \
                              rcv_ttgpdg_data["apnForwardingRealms"][j]["apnType"] if apn_type is None else apn_type

                    fwd_ttgpdg_data["apnForwardingRealms"][j]["routeType"] = \
                              rcv_ttgpdg_data["apnForwardingRealms"][j]["routeType"] if route_type is None else route_type
                    break

            if is_entry_found == False:
                print "update_forwarding_policy_per_realm_to_ttgpdg_profile: %s not found" % current_apn
                return False

            
            if new_apn and is_entry_found == True:
                    if rcv_ttgpdg_data["defaultNoMatchingAPN"] == current_apn:
                        is_entry1 = False
                        for i in range(0 , len(rcv_ttgpdg_data["apnForwardingRealms"])):
                            if fwd_ttgpdg_data["apnForwardingRealms"][i]["apn"] == default_nomatch_apn:
                                is_entry1 = True
                                fwd_ttgpdg_data["defaultNoMatchingAPN"] = default_nomatch_apn
                                break
                        if is_entry1 == False:
                            print "referenced: enter valid default_nomatch_apn"
                            return False

                    if rcv_ttgpdg_data["defaultNoRealmAPN"] == current_apn:
                        is_entry2 = False
                        for i in range(0 , len(rcv_ttgpdg_data["apnForwardingRealms"])):
                            if fwd_ttgpdg_data["apnForwardingRealms"][i]["apn"] == default_norealm_apn:
                                is_entry2 = True
                                fwd_ttgpdg_data["defaultNoRealmAPN"] = default_norealm_apn
                                break
                        if is_entry2 == False:
                            print "referenced: enter valid default_norealm_apn"
                            return False

            for k in range(0, len(rcv_ttgpdg_data["apnRealms"])):
                if rcv_ttgpdg_data["apnRealms"][k]["defaultAPN"] ==current_apn:
                    fwd_ttgpdg_data["apnRealms"][k]["defaultAPN"] = \
                            rcv_ttgpdg_data["apnRealms"][k]["defaultAPN"] if  new_apn is None else new_apn
        

            data = json.dumps(fwd_ttgpdg_data)
            put_url = ji.get_url(self.req_api_ttgpdg_updt%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(put_url, self.jsessionid, data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result


    def delete_forwarding_policy_per_realm_from_ttgpdg_profile(self, ttgpdg_profile_name="Auto_TTGPDG_profile", del_apn="www.ttgpdg.com"):
        """
        API is used delete Forwarding policy per realm in TTGPDG Profile

        URI: PUT /wsg/api/scg/serviceProfiles/forwarding/<ttgpdg_service_keys> 
        
        :param str ttgpdg_profile_name: Name of TTGPDG Profile
        :param str default_apn: Default apn 
        :return: if Forwarding policy per realm in TTGPDG Profile is deleted else False
        :rtype: boolean

        """
        
        result = False
        is_referenced_by_apn_settings = False
        is_entry_found = False
        is_referenced_by_realms = False
        fwd_ttgpdg_data = {}
        try:

            url = ji.get_url(self.req_api_ttgpdg_data, self.scg_mgmt_ip, self.scg_port)
            key, rcv_ttgpdg_data = self._get_key_for_ttgpdg_profile(url, ttgpdg_profile_name)
            fwd_ttgpdg_data.update(self.SJT.get_ttgpdg_template_update())
            fwd_ttgpdg_data["name"] = rcv_ttgpdg_data["name"]
            fwd_ttgpdg_data["description"] = rcv_ttgpdg_data["description"]
            fwd_ttgpdg_data["key"] = rcv_ttgpdg_data["key"]
            fwd_ttgpdg_data["tenantId"] = rcv_ttgpdg_data["tenantId"]
            fwd_ttgpdg_data["pdgUeIdleTimeout"] = rcv_ttgpdg_data["ttgCommonSetting"]["pdgUeIdleTimeout"]
            fwd_ttgpdg_data["ttgCommonSetting"]["pdgUeIdleTimeout"] = rcv_ttgpdg_data["ttgCommonSetting"]["pdgUeIdleTimeout"]
            fwd_ttgpdg_data["ttgCommonSetting"]["apnFormat2GGSN"] = rcv_ttgpdg_data["ttgCommonSetting"]["apnFormat2GGSN"]
            fwd_ttgpdg_data["ttgCommonSetting"]["apnOIInUse"] = rcv_ttgpdg_data["ttgCommonSetting"]["apnOIInUse"]
            fwd_ttgpdg_data["ttgCommonSetting"]["acctRetry"] = rcv_ttgpdg_data["ttgCommonSetting"]["acctRetry"]
            fwd_ttgpdg_data["ttgCommonSetting"]["acctRetryTimeout"] = rcv_ttgpdg_data["ttgCommonSetting"]["acctRetryTimeout"]
            fwd_ttgpdg_data["defaultNoMatchingAPN"] = rcv_ttgpdg_data["defaultNoMatchingAPN"]
            fwd_ttgpdg_data["defaultNoRealmAPN"] = rcv_ttgpdg_data["defaultNoRealmAPN"]
            for i in range(len(rcv_ttgpdg_data["apnForwardingRealms"])):
                fwd_ttgpdg_data["apnForwardingRealms"].append({"apn":rcv_ttgpdg_data["apnForwardingRealms"][i]["apn"],
                                                               "apnType":rcv_ttgpdg_data["apnForwardingRealms"][i]["apnType"],
                                                               "routeType":rcv_ttgpdg_data["apnForwardingRealms"][i]["routeType"]})

            for i in range(len(rcv_ttgpdg_data["apnRealms"])):
                fwd_ttgpdg_data["apnRealms"].append({"realm":rcv_ttgpdg_data["apnRealms"][i]["realm"],
                                                     "defaultAPN":rcv_ttgpdg_data["apnRealms"][i]["defaultAPN"]})

            if rcv_ttgpdg_data["defaultNoMatchingAPN"] == del_apn or rcv_ttgpdg_data["defaultNoRealmAPN"] == del_apn:
                is_referenced_by_apn_settings = True

            if is_referenced_by_apn_settings == True:
                print " %s is referenced by apn_settings" % del_apn
                return False

            for i in range(0, len(rcv_ttgpdg_data["apnRealms"])):
                if rcv_ttgpdg_data["apnRealms"][i]["defaultAPN"] == del_apn:
                    is_referenced_by_realms = True
                    break

            if is_referenced_by_realms == True:
                print " %s referenced by realms" % del_apn
                return False

            for j in range(0, len(rcv_ttgpdg_data["apnForwardingRealms"])):
                if rcv_ttgpdg_data["apnForwardingRealms"][j]["apn"] == del_apn:
                    del fwd_ttgpdg_data["apnForwardingRealms"][j]
                    is_entry_found = True
                    break

            if is_entry_found == False:
                print "apn %s not found " % del_apn
                return False
                    
            data= json.dumps(fwd_ttgpdg_data)
            url_del = ji.get_url(self.req_api_ttgpdg_updt%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(url_del, self.jsessionid, data)
 
        except Exception, e:
            print traceback.format_exc()
            return False

        return result
    
    
    def add_defaultapn_per_realm_entry_to_ttgpdg_profile(self, ttgpdg_profile_name="Auto_TTGPDG_profile",
                                                         realm ="www.realm.com",
                                                         default_apn="www.ttgpdg.com"):
        """ 
        Adds defaultAPN and realm to TTGPDG profile.

        URI: PUT /wsg/api/scg/serviceProfiles/forwarding/<fwd_profile_key>

        :param str ttgpdg_profile_name: TTGPDG forwarding profile name
        :param str realm: realm to be added to profile
        :param str default_apn: default APN per realm

        :return: True if add defaultAPN is success, else False
        :rtype: boolean
        """

        result = False
        fwd_ttgpdg_data = {}
        apn_found = False
        try:
            url = ji.get_url(self.req_api_ttgpdg_data, self.scg_mgmt_ip, self.scg_port)
            key, rcv_ttgpdg_data = self._get_key_for_ttgpdg_profile(url, ttgpdg_profile_name)

            _entry = False
            for i in range(0, len(rcv_ttgpdg_data["apnRealms"])):
                if realm == rcv_ttgpdg_data["apnRealms"][i]["realm"]:
                    _entry = True
                    break
            if _entry == True:
                print "add_defaultapn_per_realm_entry_to_ttgpdg_profile(): duplicate entry of realm %s" % (realm)
                return False

            fwd_ttgpdg_data.update(self.SJT.get_ttgpdg_template_update())
            fwd_ttgpdg_data["name"] = rcv_ttgpdg_data["name"]
            fwd_ttgpdg_data["description"] = rcv_ttgpdg_data["description"]
            fwd_ttgpdg_data["key"] = rcv_ttgpdg_data["key"]
            fwd_ttgpdg_data["tenantId"] = rcv_ttgpdg_data["tenantId"]
            fwd_ttgpdg_data["pdgUeIdleTimeout"] = rcv_ttgpdg_data["ttgCommonSetting"]["pdgUeIdleTimeout"]
            fwd_ttgpdg_data["ttgCommonSetting"]["pdgUeIdleTimeout"] = rcv_ttgpdg_data["ttgCommonSetting"]["pdgUeIdleTimeout"]
            fwd_ttgpdg_data["ttgCommonSetting"]["apnFormat2GGSN"] = rcv_ttgpdg_data["ttgCommonSetting"]["apnFormat2GGSN"]
            fwd_ttgpdg_data["ttgCommonSetting"]["apnOIInUse"] = rcv_ttgpdg_data["ttgCommonSetting"]["apnOIInUse"]
            fwd_ttgpdg_data["ttgCommonSetting"]["acctRetry"] = rcv_ttgpdg_data["ttgCommonSetting"]["acctRetry"]
            fwd_ttgpdg_data["ttgCommonSetting"]["acctRetryTimeout"] = rcv_ttgpdg_data["ttgCommonSetting"]["acctRetryTimeout"]
            fwd_ttgpdg_data["defaultNoMatchingAPN"] = rcv_ttgpdg_data["defaultNoMatchingAPN"]
            fwd_ttgpdg_data["defaultNoRealmAPN"] = rcv_ttgpdg_data["defaultNoRealmAPN"]
            
            for i in range(len(rcv_ttgpdg_data["apnForwardingRealms"])):
                fwd_ttgpdg_data["apnForwardingRealms"].append({"apn":rcv_ttgpdg_data["apnForwardingRealms"][i]["apn"],
                                                               "apnType":rcv_ttgpdg_data["apnForwardingRealms"][i]["apnType"],
                                                               "routeType":rcv_ttgpdg_data["apnForwardingRealms"][i]["routeType"]})

            for j in range(len(rcv_ttgpdg_data["apnRealms"])):
                fwd_ttgpdg_data["apnRealms"].append({"realm":rcv_ttgpdg_data["apnRealms"][j]["realm"],
                                                        "defaultAPN":rcv_ttgpdg_data["apnRealms"][j]["defaultAPN"]})

            for k in range(len(rcv_ttgpdg_data["apnForwardingRealms"])):
                if rcv_ttgpdg_data["apnForwardingRealms"][k]["apn"] ==  default_apn:
                    apn_found = True
                    break

            if apn_found == False:
                print " default apn %s not found" % default_apn
                return False

            fwd_ttgpdg_data["apnRealms"].append({"realm":realm,
                                                 "defaultAPN":default_apn})
            data = json.dumps(fwd_ttgpdg_data)
            url_add = ji.get_url(self.req_api_ttgpdg_updt%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(url_add, self.jsessionid, data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    
    def validate_defaultapn_per_realm_entry_in_ttgpdg_profile(self, ttgpdg_profile_name="Auto_TTGPDG_profile",
                                                                    realm=None, default_apn=None):
        """
        API is used to validate Apn per Realm entry in TTGPDG Profile

        URI: GET /wsg/api/scg/serviceProfiles/forwarding?type=TTGPDG
        
        :param str ttgpdg_profile_name: Name of TTGPDG forwarding profile
        :param str description: Descrption on TTGPDG profile
        :param str default_apn: Default Apn 
        :param str realm: Realm
        :return: True if Apn per Realm entry in TTGPDG Profile is validated else False
        :rtype: boolean
         
        """

        try:
            url = ji.get_url(self.req_api_ttgpdg_data, self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_ttgpdg_profile(url, ttgpdg_profile_name)
            is_realm_found = False
            exp_result_for_realm = (True if realm else False, True if default_apn else False)
            actual_result_for_realm = None
            
            if realm and rcvd_data["apnRealms"]:
                for i in range(0, len(rcvd_data["apnRealms"])):
                    is_default_apn_realm = False
                    is_apn_found = False

                    if rcvd_data["apnRealms"][i]["realm"] == realm:
                        is_default_apn_realm = True
                    if rcvd_data["apnRealms"][i]["defaultAPN"] == default_apn:
                        is_apn_found = True

                    actual_result_for_realm = (is_default_apn_realm, is_apn_found)
                    if actual_result_for_realm == exp_result_for_realm:
                        is_realm_found = True
                        break

                if is_realm_found is False:
                    self._print_err_validate('validate_defaultapn_per_realm_entry_in_ttgpdg_profile', 'exp_result_for_realm',
                        'actual_result_for_realm_list', exp_result_for_realm, actual_result_for_realm)
                    return False

            return True

        except Exception, e:
            print traceback.format_exc()
            return False

    def update_defaultapn_per_realm_entry_in_ttgpdg_profile(self, ttgpdg_profile_name="Auto_TTGPDG_profile",
                                                                  current_realm='www.realm.com',
                                                                  new_realm=None, 
                                                                  default_apn=None):
        """
        API used to update Default APN per realm in TTGPDG profile.

        URI: PUT /wsg/api/scg/serviceProfiles/forwarding/<fwd_profile_key>

        :param str ttgpdg_profile_name: TTGPDG forwarding profile name
        :param str current_realm: realm to be added to profile
        :param str new_realm: New Realm name
        :param str default_apn: default APN per realm
        :return: True if add defaultAPN is success, else False
        :rtype: boolean

        """

        result = False
        is_entry_found_apn = False
        is_entry_found_realm = False
        fwd_ttgpdg_data = {}
        try:
            url = ji.get_url(self.req_api_ttgpdg_data, self.scg_mgmt_ip, self.scg_port)
            key, rcv_ttgpdg_data = self._get_key_for_ttgpdg_profile(url, ttgpdg_profile_name)

            _entry = False
            for i in range(0, len(rcv_ttgpdg_data["apnRealms"])):
                if new_realm == rcv_ttgpdg_data["apnRealms"][i]["realm"]:
                    _entry = True
                    break
            if _entry == True:
                print "update_defaultapn_per_realm_entry_to_ttgpdg_profile(): duplicate entry of realm %s" % (new_realm)
                return False

            fwd_ttgpdg_data.update(self.SJT.get_ttgpdg_template_update())
            fwd_ttgpdg_data["name"] = rcv_ttgpdg_data["name"]
            fwd_ttgpdg_data["description"] = rcv_ttgpdg_data["description"]
            fwd_ttgpdg_data["key"] = rcv_ttgpdg_data["key"]
            fwd_ttgpdg_data["tenantId"] = rcv_ttgpdg_data["tenantId"]
            fwd_ttgpdg_data["pdgUeIdleTimeout"] = rcv_ttgpdg_data["ttgCommonSetting"]["pdgUeIdleTimeout"]
            fwd_ttgpdg_data["ttgCommonSetting"]["pdgUeIdleTimeout"] = rcv_ttgpdg_data["ttgCommonSetting"]["pdgUeIdleTimeout"]
            fwd_ttgpdg_data["ttgCommonSetting"]["apnFormat2GGSN"] = rcv_ttgpdg_data["ttgCommonSetting"]["apnFormat2GGSN"]
            fwd_ttgpdg_data["ttgCommonSetting"]["apnOIInUse"] = rcv_ttgpdg_data["ttgCommonSetting"]["apnOIInUse"]
            fwd_ttgpdg_data["ttgCommonSetting"]["acctRetry"] = rcv_ttgpdg_data["ttgCommonSetting"]["acctRetry"]
            fwd_ttgpdg_data["ttgCommonSetting"]["acctRetryTimeout"] = rcv_ttgpdg_data["ttgCommonSetting"]["acctRetryTimeout"]
            fwd_ttgpdg_data["defaultNoMatchingAPN"] = rcv_ttgpdg_data["defaultNoMatchingAPN"]
            fwd_ttgpdg_data["defaultNoRealmAPN"] = rcv_ttgpdg_data["defaultNoRealmAPN"]
 
            for i in range(len(rcv_ttgpdg_data["apnForwardingRealms"])):
                fwd_ttgpdg_data["apnForwardingRealms"].append({"apn":rcv_ttgpdg_data["apnForwardingRealms"][i]["apn"],
                                                               "apnType":rcv_ttgpdg_data["apnForwardingRealms"][i]["apnType"],
                                                               "routeType":rcv_ttgpdg_data["apnForwardingRealms"][i]["routeType"]})

            for i in range(len(rcv_ttgpdg_data["apnRealms"])):
                fwd_ttgpdg_data["apnRealms"].append({"realm":rcv_ttgpdg_data["apnRealms"][i]["realm"],
                                                     "defaultAPN":rcv_ttgpdg_data["apnRealms"][i]["defaultAPN"]})
            
            for j in range(0, len(rcv_ttgpdg_data["apnRealms"])):
                if current_realm and current_realm == rcv_ttgpdg_data["apnRealms"][j]["realm"]:
                    fwd_ttgpdg_data["apnRealms"][j]["realm"] = rcv_ttgpdg_data["apnRealms"][j]["realm"] \
                        if new_realm is None else new_realm
                    is_entry_found_realm = True
                    break

            if is_entry_found_realm == False:
                print "update_defaultapn_per_realm_entry_to_ttgpdg_profile: %s realm not found" % (current_realm)
                return False
             
            if default_apn:
                for k in range(0, len(rcv_ttgpdg_data["apnForwardingRealms"])):
                    if default_apn and rcv_ttgpdg_data["apnForwardingRealms"][k]["apn"] == default_apn:
                        fwd_ttgpdg_data["apnRealms"][j]["defaultAPN"] = default_apn
                        is_entry_found_apn = True
                        break

                if is_entry_found_apn == False:
                    print " update_defaultapn_per_realm_entry_to_ttgpdg_profile: apn %s not found" % default_apn
                    return False
            else:
                fwd_ttgpdg_data["apnRealms"][j]["defaultAPN"] = rcv_ttgpdg_data["apnRealms"][j]["defaultAPN"]

            data= json.dumps(fwd_ttgpdg_data)
            url_update = ji.get_url(self.req_api_ttgpdg_updt%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(url_update, self.jsessionid, data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result


    def delete_defaultapn_per_realm_entry_from_ttgpdg_profile(self, ttgpdg_profile_name="Auto_TTGPDG_profile", del_realm="www.ttgpdg.com"):
        """
        API used to delete the Default APN per Realm entry in TTGPDG profile

        URI: PUT /wsg/api/scg/serviceProfiles/forwarding/<ttgpdg_profile_key>

        :param str ttgpdg_profile_name: Name of TTGPDG profile
        :param str del_realm: Realm name
        :return: True if Default APN per Realm entry deleted else False
        :rtype: boolean

        """
    
        result = False
        is_entry_found = False
        fwd_ttgpdg_data = {}
        try:

            url = ji.get_url(self.req_api_ttgpdg_data, self.scg_mgmt_ip, self.scg_port)
            key, rcv_ttgpdg_data = self._get_key_for_ttgpdg_profile(url, ttgpdg_profile_name)
            fwd_ttgpdg_data.update(self.SJT.get_ttgpdg_template_update())
            fwd_ttgpdg_data["name"] = rcv_ttgpdg_data["name"]
            fwd_ttgpdg_data["description"] = rcv_ttgpdg_data["description"]
            fwd_ttgpdg_data["key"] = rcv_ttgpdg_data["key"]
            fwd_ttgpdg_data["tenantId"] = rcv_ttgpdg_data["tenantId"]
            fwd_ttgpdg_data["pdgUeIdleTimeout"] = rcv_ttgpdg_data["ttgCommonSetting"]["pdgUeIdleTimeout"]
            fwd_ttgpdg_data["ttgCommonSetting"]["pdgUeIdleTimeout"] = rcv_ttgpdg_data["ttgCommonSetting"]["pdgUeIdleTimeout"]
            fwd_ttgpdg_data["ttgCommonSetting"]["apnFormat2GGSN"] = rcv_ttgpdg_data["ttgCommonSetting"]["apnFormat2GGSN"]
            fwd_ttgpdg_data["ttgCommonSetting"]["apnOIInUse"] = rcv_ttgpdg_data["ttgCommonSetting"]["apnOIInUse"]
            fwd_ttgpdg_data["ttgCommonSetting"]["acctRetry"] = rcv_ttgpdg_data["ttgCommonSetting"]["acctRetry"]
            fwd_ttgpdg_data["ttgCommonSetting"]["acctRetryTimeout"] = rcv_ttgpdg_data["ttgCommonSetting"]["acctRetryTimeout"]
            fwd_ttgpdg_data["defaultNoMatchingAPN"] = rcv_ttgpdg_data["defaultNoMatchingAPN"]
            fwd_ttgpdg_data["defaultNoRealmAPN"] = rcv_ttgpdg_data["defaultNoRealmAPN"]
            for i in range(len(rcv_ttgpdg_data["apnForwardingRealms"])):
                fwd_ttgpdg_data["apnForwardingRealms"].append({"apn":rcv_ttgpdg_data["apnForwardingRealms"][i]["apn"],
                                                               "apnType":rcv_ttgpdg_data["apnForwardingRealms"][i]["apnType"],
                                                               "routeType":rcv_ttgpdg_data["apnForwardingRealms"][i]["routeType"]})

            for i in range(len(rcv_ttgpdg_data["apnRealms"])):
                fwd_ttgpdg_data["apnRealms"].append({"realm":rcv_ttgpdg_data["apnRealms"][i]["realm"],
                                                     "defaultAPN":rcv_ttgpdg_data["apnRealms"][i]["defaultAPN"]}) 

            for j in range(0, len(rcv_ttgpdg_data["apnRealms"])):
                    if rcv_ttgpdg_data["apnRealms"][j]["realm"] == del_realm:
                        del fwd_ttgpdg_data["apnRealms"] [j]
                        is_entry_found = True
                        break

            if is_entry_found == False:
                print "delete_defaultapn_per_realm_entry_to_ttgpdg_profile(): %s realm not found " % del_realm
                return False

            data= json.dumps(fwd_ttgpdg_data)
            url_delete = ji.get_url(self.req_api_ttgpdg_updt%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(url_delete, self.jsessionid, data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result
        
    def enable_eapaka_service(self):

        """ 
        API used to Enable the EAP-AKA configuration
        
        URI: PUT /wsg/api/scg/globalSettings/eapaka? 

        :return: True if EAP-AKA Service enabled else False
        :rtype: boolean
        """

        result = False
        fwd_data = {}
        try:
            url = ji.get_url(self.req_api_eapaka, self.scg_mgmt_ip, self.scg_port)
            data = {"enabled":"true", 
                    "cleanUp":"false", 
                    "privacySupport":False, 
                    "fastReAuth":False, 
                    "secretKeyList":[]}

            fwd_data = json.dumps(data)
            result = ji.put_json_data(url, self.jsessionid, fwd_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def disable_eapaka_service(self):

        """ 
        API used to Disable the EAP-AKA configuration

        URI: PUT /wsg/api/scg/globalSettings/eapaka?

        :return: True if EAP-AKA Service disabled else False
        :rtype: boolean
        """

        result = False
        data = {}
        try:
            url = ji.get_url(self.req_api_eapaka, self.scg_mgmt_ip, self.scg_port)
            data = {"enabled":"false"}
            eapaka = json.dumps(data)
            result = ji.put_json_data(url, self.jsessionid, eapaka)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def enable_eapsim_service(self):
        """ 
        API used to Enable the EAP-SIM configuration
        
        URI: PUT /wsg/api/scg/globalSettings/eapsim? 

        :return: True if EAP-SIM Service enabled else False
        :rtype: boolean
        """

        result = False
        data = {}
        try:
            url = ji.get_url(self.req_api_eapsim, self.scg_mgmt_ip, self.scg_port)
            data = {"enabled":"true",
                    "cleanUp":"false",
                    "privacySupport":False,
                    "fastReAuth":False,
                    "secretKeyList":[]}

            eapsim = json.dumps(data)
            result = ji.put_json_data(url, self.jsessionid,eapsim)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def disable_eapsim_service(self):
        """ 
        API used to Disable the EAP-SIM configuration
        
        URI: PUT /wsg/api/scg/globalSettings/eapsim? 
            
        :return: True if EAP-SIM Service disabled else False
        :rtype: boolean
        """

        result = False
        data = {}
        try:
            url = ji.get_url(self.req_api_eapsim, self.scg_mgmt_ip, self.scg_port)
            data = {"enabled":"false"}
            eapsim = json.dumps(data)
            result = ji.put_json_data(url, self.jsessionid, eapsim)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def update_eapaka_service(self, eapaka_config_enable=None, privacy_support=None,
                               fast_reauth=None, secret_key_for_active_key=None,
                               fast_reauth_realm=None,
                               max_sucreauth=None, cleanup=None, cleanup_time_hrs=None,
                               cleanup_time_mins=None, cache_history_len=None):
        """ 
        API update the EAP-AKA Service with given parameters

        URI: PUT /wsg/api/scg/globalSettings/eapaka?

        :param str eapaka_config_enable: true | false
        :param boolean privacy_support: True | False
        :param boolean fast_reauth: True | False
        :param str secret_key_for_active_key: Active secret key in number
        :param str fast_reauth_realm: Reauthentication Realm
        :param str max_sucreahth: Max successive Reauthentication 1 to 65535
        :param str cleanup: true | false
        :param str cleanup_time_hrs: Cache cleanup time in hours 0 to 23
        :param str cleanup_time_mins: Cache cleanup time in minutes 0 to 59
        :param str cache_history_len: Cache history length 1 to 744
        :return: True if  EAP-AKA configuration success else False
        :rtype: boolean
        """

        result = False
        is_found = False
        fwd_eapaka_data = {}
        try:
            url = ji.get_url(self.req_api_eapaka, self.scg_mgmt_ip, self.scg_port)
            rcv_eapaka_data = ji.get_json_data(url, self.jsessionid)
            fwd_eapaka_data.update(self.SJT.get_eapaka_template_update())
            fwd_eapaka_data["enabled"] = rcv_eapaka_data["data"]["enabled"] if eapaka_config_enable is None else eapaka_config_enable

            if fwd_eapaka_data["enabled"] == "true" or fwd_eapaka_data["enabled"] == True:
                fwd_eapaka_data["privacySupport"] = rcv_eapaka_data["data"]["privacySupport"] if privacy_support is None else privacy_support
                fwd_eapaka_data["fastReAuth"] = rcv_eapaka_data["data"]["fastReAuth"] if fast_reauth  is None else fast_reauth
                fwd_eapaka_data["cleanUp"] = rcv_eapaka_data["data"]["cleanUp"] if cleanup is None else cleanup

                if fwd_eapaka_data["fastReAuth"] == True:
                    fwd_eapaka_data.update({"maxSucReAhth": fwd_eapaka_data["maxSucReAhth"] if not rcv_eapaka_data["data"]["maxSucReAhth"] \
                            else rcv_eapaka_data["data"]["maxSucReAhth"]})
                    fwd_eapaka_data.update({"maxSucReAhth": fwd_eapaka_data["maxSucReAhth"] if max_sucreauth is None else int(max_sucreauth),
                                    "fastReAuthRealm":rcv_eapaka_data["data"]["fastReAuthRealm"] if fast_reauth_realm  is None else fast_reauth_realm})

                for i in range(len(rcv_eapaka_data["data"]["secretKeyList"])):
                    fwd_eapaka_data["secretKeyList"].append({"secretKey":rcv_eapaka_data["data"]["secretKeyList"][i]["secretKey"],
                                                              "keyNum":rcv_eapaka_data["data"]["secretKeyList"][i]["keyNum"],               
                                           "createDatetime":rcv_eapaka_data["data"]["secretKeyList"][i]["createDatetime"]})

                if fwd_eapaka_data["privacySupport"] or fwd_eapaka_data["fastReAuth"] == True:
                    if secret_key_for_active_key:
                        for i in range(0, len(fwd_eapaka_data["secretKeyList"])):
                            if fwd_eapaka_data["secretKeyList"][i]["secretKey"] == secret_key_for_active_key:
                                active_key = fwd_eapaka_data["secretKeyList"][i]["keyNum"]
                                is_found = True
                                break

                        if is_found == False:
                            print "secret key not exists"
                            return False


                if fwd_eapaka_data["fastReAuth"] == True or fwd_eapaka_data["privacySupport"] == True:
                    fwd_eapaka_data.update({"activeKey":rcv_eapaka_data["data"]["activeKey"] if secret_key_for_active_key is None else active_key})

                if fwd_eapaka_data["fastReAuth"] == True:
                    if fast_reauth == True and (not fwd_eapaka_data["maxSucReAhth"]) or (not fwd_eapaka_data["fastReAuthRealm"]):
                        print "Required parameter Reauthentication Realm is missing"
                        return False
                    fwd_eapaka_data.update({"fastReAuthRealm":fast_reauth_realm})

                    if max_sucreauth is None:
                        fwd_eapaka_data.update({"maxSucReAhth":rcv_eapaka_data["data"]["maxSucReAhth"]})
                    else:
                        fwd_eapaka_data.update({"maxSucReAhth":int(max_sucreauth)})

                #if fwd_eapaka_data["fastReAuth"] == True and max_sucreauth is None:
                #    fwd_eapaka_data.update({"maxSucReAhth":rcv_eapaka_data["data"]["maxSucReAhth"]}) if max_sucreauth is None else int(max_sucreauth)

                if fwd_eapaka_data["cleanUp"] == "true" or fwd_eapaka_data["cleanUp"] == True:

                    fwd_eapaka_data.update({"cleanUpTimeMins": rcv_eapaka_data["data"]["cleanUpTimeMins"] \
                            if cleanup_time_mins is None else int(cleanup_time_mins)})

                    fwd_eapaka_data.update({"cacheHisLen":rcv_eapaka_data["data"]["cacheHisLen"] if cache_history_len is None else int(cache_history_len)})
                    fwd_eapaka_data.update({"cleanUpTimeHrs": rcv_eapaka_data["data"]["cleanUpTimeHrs"] if cleanup_time_hrs is None \
                            else int(cleanup_time_hrs)})

                eap_profile = json.dumps(fwd_eapaka_data)
                result = ji.put_json_data(url, self.jsessionid, eap_profile)

            else:
                fwd_disable = {"enabled":"false"}
                eap_profile = json.dumps(fwd_disable)
                result = ji.put_json_data(url, self.jsessionid, eap_profile)
        
        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def validate_eapaka_service(self, eapaka_config_enable=None, privacy_support=None,
                               fast_reauth=None, secret_key_for_active_key=None,
                               secret_key_entry=None, fast_reauth_realm=None,
                               max_sucreahth=None, cleanup=None, cleanup_time_hrs=None,
                               cleanup_time_mins=None, cache_history_len=None):
        """ 
        API update the EAP-AKA Service with given parameters

        URI: PUT /wsg/api/scg/globalSettings/eapaka?

        :param str eapaka_config_enable: true | false
        :param boolean privacy_support: True | False
        :param boolean fast_reauth: True | False
        :param str secret_key_for_active_key: Active secret key in number
        :param str secret_key_entry: secret key for EAP-AKA Secret Key Configurarion
        :param str fast_reauth_realm: Reauthentication Realm
        :param str max_sucreahth: Max successive Reauthentication 1 to 65535
        :param str cleanup: true | false
        :param str cleanup_time_hrs: Cache cleanup time in hours 0 to 23
        :param str cleanup_time_mins: Cache cleanup time in minutes 0 to 59
        :param str cache_history_len: Cache history length 1 to 744
        :return: True if  EAP-AKA configuration success else False
        :rtype: boolean
        """

        try:
            url = ji.get_url(self.req_api_eapaka, self.scg_mgmt_ip, self.scg_port)
            rcvd_data = ji.get_json_data(url, self.jsessionid)
            if eapaka_config_enable:
                if eapaka_config_enable != rcvd_data["data"]["enabled"]:
                    self._print_err_validate('validate_eapaka_service', 'eapaka_config_enable', 'enabled', eapaka_config_enable, 
                        rcvd_data["data"]["enabled"])
                    return False
            if privacy_support:
                if privacy_support != rcvd_data["data"]["privacySupport"]:
                    self._print_err_validate('validate_eapaka_service', 'privacy_support', 'privacySupport', privacy_support,
                        rcvd_data["data"]["privacySupport"])
                    return False
            if secret_key_for_active_key:
                _active_key = None
                for i in range(0, len(rcvd_data["data"]["secretKeyList"])):
                    if rcvd_data["data"]["secretKeyList"][i]["secretKey"] == secret_key_for_active_key:
                        _active_key = rcvd_data["data"]["secretKeyList"][i]["keyNum"]
                        break
                if int(rcvd_data["data"]["activeKey"]) != _active_key:
                    self._print_err_validate('validate_eapaka_service', '_active_key', 'activeKey', _active_key,
                        int(rcvd_data["data"]["activeKey"]))
                    return False
            if fast_reauth_realm:
                if rcvd_data["data"]["fastReAuthRealm"] != fast_reauth_realm:
                    self._print_err_validate('validate_eapaka_service', 'fast_reauth_realm', 'fastReAuthRealm', 
                            fast_reauth_realm, rcvd_data["data"]["fastReAuthRealm"])
                    return False
            if max_sucreahth:
                if str(rcvd_data["data"]["maxSucReAhth"]) != str(max_sucreahth):
                    self._print_err_validate('validate_eapaka_service', 'max_sucreahth', 'maxSucReAhth', max_sucreahth,
                        rcvd_data["data"]["maxSucReAhth"])
                    return False
            
            if cleanup is not None:
                if cleanup != rcvd_data["data"]["cleanUp"]:
                    self._print_err_validate('validate_eapaka_service', 'cleanup', 'cleanUp', cleanup, rcvd_data["data"]["cleanUp"])
                    return False
            if cleanup_time_hrs:
                if str(rcvd_data["data"]["cleanUpTimeHrs"]) != cleanup_time_hrs:
                    self._print_err_validate('validate_eapaka_service', 'cleanup_time_hrs', 'cleanUpTimeHrs', cleanup_time_hrs,
                            rcvd_data["data"]["cleanUpTimeHrs"])
                    return False
            if cleanup_time_mins:
                if str(rcvd_data["data"]["cleanUpTimeMins"]) != cleanup_time_mins:
                    self._print_err_validate('validate_eapaka_service', 'cleanup_time_mins', 'cleanUpTimeMins', cleanup_time_mins,
                            rcvd_data["data"]["cleanUpTimeMins"])
                    return False
            if cache_history_len:
                if str(rcvd_data["data"]["cacheHisLen"]) != cache_history_len:
                    self._print_err_validate('validate_eapaka_service', 'cache_history_len', 'cacheHisLen', cache_history_len,
                            rcvd_data["data"]["cacheHisLen"])
                    return False
                    
            return True

        except Exception, e:
            print traceback.format_exc()
            return False


    def add_secretkey_to_eapaka_configuration(self, secret_key="test.com"):

        """
        Adds Secret Key Configuration to EAP-AKA 

        URI: PUT /wsg/api/scg/globalSettings/eapaka?

        :param str secret_key: Secret Key to be added
        :return: True if Secret Key is added else False
        :rtype: boolean

        """

        result = False
        max_num=None
        fwd_eapaka_data = {}
        try:
            url = ji.get_url(self.req_api_eapaka, self.scg_mgmt_ip, self.scg_port)
            rcv_eapaka_data= ji.get_json_data(url, self.jsessionid)
            fwd_eapaka_data.update(self.SJT.get_eapaka_template_update())
            fwd_eapaka_data["enabled"] = rcv_eapaka_data["data"]["enabled"] 

            if fwd_eapaka_data["enabled"] == True:
                fwd_eapaka_data["privacySupport"] = rcv_eapaka_data["data"]["privacySupport"] 
                fwd_eapaka_data["fastReAuth"] = rcv_eapaka_data["data"]["fastReAuth"] 
                fwd_eapaka_data["cleanUp"] = rcv_eapaka_data["data"]["cleanUp"] 

                if fwd_eapaka_data["fastReAuth"] == True:
                    fwd_eapaka_data.update({"maxSucReAhth":rcv_eapaka_data["data"]["maxSucReAhth"],
                                    "fastReAuthRealm":rcv_eapaka_data["data"]["fastReAuthRealm"]}) 

                for i in range(len(rcv_eapaka_data["data"]["secretKeyList"])):
                    fwd_eapaka_data["secretKeyList"].append({"secretKey":rcv_eapaka_data["data"]["secretKeyList"][i]["secretKey"],
                                                              "keyNum":rcv_eapaka_data["data"]["secretKeyList"][i]["keyNum"],
                                                              "createDatetime":rcv_eapaka_data["data"]["secretKeyList"][i]["createDatetime"]})   

                if fwd_eapaka_data["fastReAuth"] or fwd_eapaka_data["privacySupport"] == True:
                    fwd_eapaka_data.update({"activeKey":rcv_eapaka_data["data"]["activeKey"]})

                if fwd_eapaka_data["cleanUp"] == "true":
                    fwd_eapaka_data.update({"cleanUpTimeMins": rcv_eapaka_data["data"]["cleanUpTimeMins"]})
                    fwd_eapaka_data.update({"cacheHisLen":rcv_eapaka_data["data"]["cacheHisLen"]})
                    fwd_eapaka_data.update({"cleanUpTimeHrs": rcv_eapaka_data["data"]["cleanUpTimeHrs"]})

                for i in range(0,len(rcv_eapaka_data["data"]["secretKeyList"])):
                    max_num =  rcv_eapaka_data["data"]["secretKeyList"][i]["keyNum"]

                if max_num == None:
                    key_num = 0 
                else:
                    key_num = max_num + 1
                fwd_eapaka_data["secretKeyList"].append({"keyNum":key_num,
                                                     "secretKey":secret_key,
                                                     "createDatetime":""})

            else:
                raise Exception("eapaka is not enabled")

            eap_profile = json.dumps(fwd_eapaka_data)
            result = ji.put_json_data(url, self.jsessionid, eap_profile)
                
        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def validate_secretkey_in_eapaka_configuration(self, secret_key=None):

        """
        Adds Secret Key Configuration to EAP-AKA 

        URI: PUT /wsg/api/scg/globalSettings/eapaka?

        :param str secret_key: Secret Key to be added
        :return: True if Secret Key is added else False
        :rtype: boolean

        """
        is_key_found = False 
        _list_len = None
        try:
            url = ji.get_url(self.req_api_eapaka, self.scg_mgmt_ip, self.scg_port)
            rcvd_data= ji.get_json_data(url, self.jsessionid)

            if secret_key:
                _list_len = len(rcvd_data["data"]["secretKeyList"])

                if _list_len <= 0:
                    print "Secret Key list is empty in EAP-AKA Service"
                    return False

                else:
                    for i in range(0, len(rcvd_data["data"]["secretKeyList"])):
                        if rcvd_data["data"]["secretKeyList"][i]["secretKey"] == secret_key:
                            is_key_found = True
                            break

                    if is_key_found == False:
                        print "validate_secretkey_to_eapaka_config(): secret key %s not found" % (secret_key)
                        return False

            return True

        except Exception, e:
            print traceback.format_exc()
            return False
 
    def update_secretkey_in_eapaka_configuration(self, current_secret_key="test.com", new_secret_key="ruckus.com"):
        
        """
        API used to update the Secret Key in EAP-AKA Service
        
        URI: PUT /wsg/api/scg/globalSettings/eapaka?

        :param str current_secret_key: Name of the existing secret key 
        :param str new_secret_key: Name of new secret key 
        :return: True if update secret key success else False
        :rtype: boolean
        """

        result = False
        fwd_eapaka_data = {}
        try:
            url = ji.get_url(self.req_api_eapaka, self.scg_mgmt_ip, self.scg_port)
            rcv_eapaka_data= ji.get_json_data(url, self.jsessionid)
            fwd_eapaka_data.update(self.SJT.get_eapaka_template_update())
            fwd_eapaka_data["enabled"] = rcv_eapaka_data["data"]["enabled"]

            if fwd_eapaka_data["enabled"] == True:
                fwd_eapaka_data["privacySupport"] = rcv_eapaka_data["data"]["privacySupport"]
                fwd_eapaka_data["fastReAuth"] = rcv_eapaka_data["data"]["fastReAuth"]
                fwd_eapaka_data["cleanUp"] = rcv_eapaka_data["data"]["cleanUp"]
                if fwd_eapaka_data["fastReAuth"] == True:
                    fwd_eapaka_data.update({"maxSucReAhth":rcv_eapaka_data["data"]["maxSucReAhth"],
                                    "fastReAuthRealm":rcv_eapaka_data["data"]["fastReAuthRealm"]})
                for i in range(len(rcv_eapaka_data["data"]["secretKeyList"])):
                    fwd_eapaka_data["secretKeyList"].append({"secretKey":rcv_eapaka_data["data"]["secretKeyList"][i]["secretKey"],
                                                              "keyNum":rcv_eapaka_data["data"]["secretKeyList"][i]["keyNum"],
                                                              "createDatetime":rcv_eapaka_data["data"]["secretKeyList"][i]["createDatetime"]})

                if fwd_eapaka_data["fastReAuth"] or fwd_eapaka_data["privacySupport"] == True:
                    fwd_eapaka_data.update({"activeKey":rcv_eapaka_data["data"]["activeKey"]})

                if fwd_eapaka_data["cleanUp"] == "true":
                    fwd_eapaka_data.update({"cleanUpTimeMins": rcv_eapaka_data["data"]["cleanUpTimeMins"]})
                    fwd_eapaka_data.update({"cacheHisLen":rcv_eapaka_data["data"]["cacheHisLen"]})
                    fwd_eapaka_data.update({"cleanUpTimeHrs": rcv_eapaka_data["data"]["cleanUpTimeHrs"]}) 
                for i in range(0,len(rcv_eapaka_data["data"]["secretKeyList"])):
                    if rcv_eapaka_data["data"]["secretKeyList"][i]["secretKey"] == current_secret_key:
                        fwd_eapaka_data["secretKeyList"][i].update({"secretKey":new_secret_key})
            else:
                raise Exception("EAP-AKA is not enabled")
                return False 

            eap_profile = json.dumps(fwd_eapaka_data)
            result = ji.put_json_data(url, self.jsessionid, eap_profile)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def delete_secretkey_from_eapaka_configuration(self, secret_key="test.com"):
        """
        API used to delete the Secret key in EAPAKA Configuration
        
        URI: PUT /wsg/api/scg/globalSettings/eapaka?

        :param str secret_key: Name of the Secret Key to be deleted
        :return: True if Secret Key deleted else False
        :rtype: boolean
        """
        result = False
        is_entry_found = False
        fwd_eapaka_data = {}
        try:
            url = ji.get_url(self.req_api_eapaka, self.scg_mgmt_ip, self.scg_port)
            rcv_eapaka_data= ji.get_json_data(url, self.jsessionid)
            fwd_eapaka_data.update(self.SJT.get_eapaka_template_update())

            fwd_eapaka_data["enabled"] = rcv_eapaka_data["data"]["enabled"]

            if fwd_eapaka_data["enabled"] == True:
                fwd_eapaka_data["privacySupport"] = rcv_eapaka_data["data"]["privacySupport"]
                fwd_eapaka_data["fastReAuth"] = rcv_eapaka_data["data"]["fastReAuth"]
                fwd_eapaka_data["cleanUp"] = rcv_eapaka_data["data"]["cleanUp"]

                if fwd_eapaka_data["fastReAuth"] == True:
                    fwd_eapaka_data.update({"maxSucReAhth":rcv_eapaka_data["data"]["maxSucReAhth"],
                                            "fastReAuthRealm":rcv_eapaka_data["data"]["fastReAuthRealm"]})

                ref_key = None
                for k in range(0, len(rcv_eapaka_data["data"]["secretKeyList"])):
                    if rcv_eapaka_data["data"]["secretKeyList"][k]["secretKey"] == secret_key:
                        ref_key = rcv_eapaka_data["data"]["secretKeyList"][k]["keyNum"]
                        is_entry_found = True
                        break
                if is_entry_found == False:
                    print "secret key %s not found" % secret_key
                    return False
                if rcv_eapaka_data["data"]["activeKey"] and int(rcv_eapaka_data["data"]["activeKey"]) == ref_key:
                    print "Sercret Key is Referenced: not possible to delete"
                    return False

                for i in range(len(rcv_eapaka_data["data"]["secretKeyList"])):
                    if rcv_eapaka_data["data"]["secretKeyList"][i]["secretKey"] != secret_key:
                        fwd_eapaka_data["secretKeyList"].append({"secretKey":rcv_eapaka_data["data"]["secretKeyList"][i]["secretKey"],
                                                                 "keyNum":rcv_eapaka_data["data"]["secretKeyList"][i]["keyNum"],
                                                                 "createDatetime":rcv_eapaka_data["data"]["secretKeyList"][i]["createDatetime"]})
                    else:
                        is_entry_found = True

                if fwd_eapaka_data["fastReAuth"] or fwd_eapaka_data["privacySupport"] == True:
                    fwd_eapaka_data.update({"activeKey":rcv_eapaka_data["data"]["activeKey"]})

                if fwd_eapaka_data["cleanUp"] == True:
                    fwd_eapaka_data.update({"cleanUpTimeMins": rcv_eapaka_data["data"]["cleanUpTimeMins"]})
                    fwd_eapaka_data.update({"cacheHisLen":rcv_eapaka_data["data"]["cacheHisLen"]})
                    fwd_eapaka_data.update({"cleanUpTimeHrs": rcv_eapaka_data["data"]["cleanUpTimeHrs"]})

                if is_entry_found == False:
                    print "secret key %s not found" % secret_key
                    return False

            else:
                raise Exception("eapaka is not enabled")
                return False
            eap_profile = json.dumps(fwd_eapaka_data)
            result = ji.put_json_data(url, self.jsessionid, eap_profile)

        except Exception, e:
            print traceback.format_exc()
            return False
        return result


    def update_eapsim_service(self, eapsim_config_enable=None, privacy_support=None,
                               fast_reauth=None, secret_key_for_active_key=None, fast_reauth_realm=None, max_sucreahth=None, 
                               cleanup=None, cleanup_time_hrs=None, cleanup_time_mins=None, cache_history_len=None):
        """ 
        API update the EAP-SIM Service with given parameters

        URI: PUT /wsg/api/scg/globalSettings/eapsim?

        :param str eapsim_config_enable: true | false
        :param boolean privacy_support: True | False
        :param boolean fast_reauth: True | False
        :param str secret_key_for_active_key: Active secret key in number
        :param str fast_reauth_realm: Reauthentication Realm
        :param str max_sucreahth: Max successive Reauthentication 1 to 65535
        :param str cleanup: true | false
        :param str cleanup_time_hrs: Cache cleanup time in hours 0 to 23
        :param str cleanup_time_mins: Cache cleanup time in minutes 0 to 59
        :param str cache_history_len: Cache history length 1 to 744
        :return: True if  EAP-SIM configuration success else False
        :rtype: boolean
        """

        is_found = False
        result = False
        fwd_eapsim_data = {}
        try:
            url = ji.get_url(self.req_api_eapsim, self.scg_mgmt_ip,self.scg_port) 
            rcv_eapsim_data= ji.get_json_data(url, self.jsessionid)
            fwd_eapsim_data.update(self.SJT.get_eapaka_template_update())

            fwd_eapsim_data["enabled"] = rcv_eapsim_data["data"]["enabled"] if eapsim_config_enable is None else eapsim_config_enable

            if fwd_eapsim_data["enabled"] == "true" or fwd_eapsim_data["enabled"] == True:
                fwd_eapsim_data["privacySupport"] = rcv_eapsim_data["data"]["privacySupport"] if privacy_support is None else privacy_support
                fwd_eapsim_data["fastReAuth"] = rcv_eapsim_data["data"]["fastReAuth"] if fast_reauth  is None else fast_reauth
                fwd_eapsim_data["cleanUp"] = rcv_eapsim_data["data"]["cleanUp"] if cleanup is None else cleanup

                if fwd_eapsim_data["fastReAuth"] == True:
                    fwd_eapsim_data.update({"maxSucReAhth":fwd_eapsim_data["maxSucReAhth"] if not rcv_eapsim_data["data"]["maxSucReAhth"] else \
                        rcv_eapsim_data["data"]["maxSucReAhth"] })
                    fwd_eapsim_data.update({"maxSucReAhth": fwd_eapsim_data["maxSucReAhth"] if not max_sucreahth else max_sucreahth,
                                    "fastReAuthRealm":rcv_eapsim_data["data"]["fastReAuthRealm"] if fast_reauth_realm  is None else fast_reauth_realm})

                for i in range(len(rcv_eapsim_data["data"]["secretKeyList"])):
                    fwd_eapsim_data["secretKeyList"].append({"secretKey":rcv_eapsim_data["data"]["secretKeyList"][i]["secretKey"],
                                                              "keyNum":rcv_eapsim_data["data"]["secretKeyList"][i]["keyNum"],
                                           "createDatetime":rcv_eapsim_data["data"]["secretKeyList"][i]["createDatetime"]})

                if fwd_eapsim_data["privacySupport"] or fwd_eapsim_data["fastReAuth"] == True:
                    if secret_key_for_active_key:
                        for i in range(0, len(fwd_eapsim_data["secretKeyList"])):
                            if fwd_eapsim_data["secretKeyList"][i]["secretKey"] == secret_key_for_active_key:
                                active_key = fwd_eapsim_data["secretKeyList"][i]["keyNum"]
                                is_found = True
                                break

                        if is_found == False:
                            print "secret key not exists"
                            return False


                if fwd_eapsim_data["fastReAuth"] == True or fwd_eapsim_data["privacySupport"] == True:
                    fwd_eapsim_data.update({"activeKey":rcv_eapsim_data["data"]["activeKey"] if secret_key_for_active_key is None else active_key})

                if fwd_eapsim_data["fastReAuth"] == True:
                    if fast_reauth == True and (not fwd_eapsim_data["maxSucReAhth"]) or (not fwd_eapsim_data["fastReAuthRealm"]):
                        print "Required parameter Reauthentication Realm is missing"
                        return False
                fwd_eapsim_data.update({"fastReAuthRealm":fast_reauth_realm})
                if max_sucreahth is None:
                     fwd_eapsim_data.update({"maxSucReAhth":rcv_eapsim_data["data"]["maxSucReAhth"]})
                else:
                    fwd_eapsim_data.update({"maxSucReAhth":int(max_sucreahth)})

                if cleanup == "true" or cleanup == True:
                    fwd_eapsim_data.update({"cleanUpTimeMins": rcv_eapsim_data["data"]["cleanUpTimeMins"] \
                            if cleanup_time_mins is None else int(cleanup_time_mins)})
                    fwd_eapsim_data.update({"cacheHisLen":rcv_eapsim_data["data"]["cacheHisLen"] if cache_history_len is None else int(cache_history_len)})
                    fwd_eapsim_data.update({"cleanUpTimeHrs": rcv_eapsim_data["data"]["cleanUpTimeHrs"] if cleanup_time_hrs is None \
                            else int(cleanup_time_hrs)})
                eap_profile = json.dumps(fwd_eapsim_data)
                result = ji.put_json_data(url, self.jsessionid, eap_profile)

            else:
                fwd_disable = {"enabled":"false"}
                eap_profile = json.dumps(fwd_disable)
                result = ji.put_json_data(url, self.jsessionid, eap_profile)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def validate_eapsim_service(self, eapsim_config_enable=None, privacy_support=None,
                               fast_reauth=None, secret_key_for_active_key=None, fast_reauth_realm=None, max_sucreahth=None,
                               cleanup=None, cleanup_time_hrs=None, cleanup_time_mins=None, cache_history_len=None):
        """ 
        API Validates the EAP-SIM Service with given parameters

        URI: PUT /wsg/api/scg/globalSettings/eapsim?

        :param str eapsim_config_enable: true | false
        :param boolean privacy_support: True | False
        :param boolean fast_reauth: True | False
        :param str secret_key_for_active_key: Active secret key in number
        :param str fast_reauth_realm: Reauthentication Realm
        :param str max_sucreahth: Max successive Reauthentication 1 to 65535
        :param str cleanup: true | false
        :param str cleanup_time_hrs: Cache cleanup time in hours 0 to 23
        :param str cleanup_time_mins: Cache cleanup time in minutes 0 to 59
        :param str cache_history_len: Cache history length 1 to 744
        :return: True if  EAP-SIM configuration success else False
        :rtype: boolean
        """


        try:
            url = ji.get_url(self.req_api_eapsim, self.scg_mgmt_ip, self.scg_port)
            rcvd_data = ji.get_json_data(url, self.jsessionid)
            #eapsim_config_enable = json.loads(eapsim_config_enable)
            if eapsim_config_enable:
                if eapsim_config_enable != rcvd_data["data"]["enabled"]:
                    self._print_err_validate('validate_eapsim_service', 'eapaka_config_enable', 'enabled', eapsim_config_enable,
                                rcvd_data["data"]["enabled"])
                    return False
            if privacy_support:
                if privacy_support != rcvd_data["data"]["privacySupport"]:
                    self._print_err_validate('validate_eapsim_service', 'privacy_support', 'privacySupport', privacy_support,
                        rcvd_data["data"]["privacySupport"])
                    return False
            if secret_key_for_active_key:
                _active_key = None
                for i in range(0, len(rcvd_data["data"]["secretKeyList"])):
                    if rcvd_data["data"]["secretKeyList"][i]["secretKey"] == secret_key_for_active_key:
                        _active_key = rcvd_data["data"]["secretKeyList"][i]["keyNum"]
                        break
                if int(rcvd_data["data"]["activeKey"]) != _active_key:
                    self._print_err_validate('validate_eapsim_service', '_active_key', 'activeKey', _active_key,
                        int(rcvd_data["data"]["activeKey"]))
                    return False
            if fast_reauth_realm:
                if rcvd_data["data"]["fastReAuthRealm"] != fast_reauth_realm:
                    self._print_err_validate('validate_eapsim_service', 'fast_reauth_realm', 'fastReAuthRealm',
                            fast_reauth_realm, rcvd_data["data"]["fastReAuthRealm"])
                    return False
            if max_sucreahth:
                if str(rcvd_data["data"]["maxSucReAhth"]) != str(max_sucreahth):
                    self._print_err_validate('validate_eapaka_service', 'max_sucreahth', 'maxSucReAhth', max_sucreahth,
                        rcvd_data["data"]["maxSucReAhth"])
                    return False
            if cleanup is not None: 
                if cleanup != rcvd_data["data"]["cleanUp"]:
                    self._print_err_validate('validate_eapsim_service', 'cleanup', 'cleanUp', cleanup, rcvd_data["data"]["cleanUp"])
                    return False
            if cleanup_time_hrs:
                if str(rcvd_data["data"]["cleanUpTimeHrs"]) != cleanup_time_hrs:
                    self._print_err_validate('validate_eapsim_service', 'cleanup_time_hrs', 'cleanUpTimeHrs', cleanup_time_hrs,
                            rcvd_data["data"]["cleanUpTimeHrs"])
                    return False
            if cleanup_time_mins:
                if str(rcvd_data["data"]["cleanUpTimeMins"]) != cleanup_time_mins:
                    self._print_err_validate('validate_eapaka_service', 'cleanup_time_mins', 'cleanUpTimeMins', cleanup_time_mins,
                            rcvd_data["data"]["cleanUpTimeMins"])
                    return False
            if cache_history_len:
                if str(rcvd_data["data"]["cacheHisLen"]) != cache_history_len:
                    self._print_err_validate('validate_eapaka_service', 'cache_history_len', 'cacheHisLen', cache_history_len,
                            rcvd_data["data"]["cacheHisLen"])
                    return False

            return True

        except Exception, e:
            print traceback.format_exc()
            return False


    def add_secretkey_to_eapsim_configuration(self, secret_key="test.com"):

        """
        Adds Secret Key Configuration to EAP-SIM 

        URI: PUT /wsg/api/scg/globalSettings/eapsim?

        :param str secret_key: Secret Key to be added
        :return: True if Secret Key is added else False
        :rtype: boolean

        """

        result = False
        _max_num = None
        fwd_eapsim_data = {}
        try:
            url = ji.get_url(self.req_api_eapsim, self.scg_mgmt_ip, self.scg_port)
            rcv_eapsim_data = ji.get_json_data(url, self.jsessionid)
            fwd_eapsim_data.update(self.SJT.get_eapaka_template_update())
            fwd_eapsim_data["enabled"] = rcv_eapsim_data["data"]["enabled"] 

            if fwd_eapsim_data["enabled"] == True:
                fwd_eapsim_data["privacySupport"] = rcv_eapsim_data["data"]["privacySupport"]
                fwd_eapsim_data["fastReAuth"] = rcv_eapsim_data["data"]["fastReAuth"] 
                fwd_eapsim_data["cleanUp"] = rcv_eapsim_data["data"]["cleanUp"]

                if fwd_eapsim_data["fastReAuth"] == True:
                    fwd_eapsim_data.update({"maxSucReAhth":rcv_eapsim_data["data"]["maxSucReAhth"],
                                            "fastReAuthRealm":rcv_eapsim_data["data"]["fastReAuthRealm"]})

                for i in range(0, len(rcv_eapsim_data["data"]["secretKeyList"])):
                    fwd_eapsim_data["secretKeyList"].append({"secretKey":rcv_eapsim_data["data"]["secretKeyList"][i]["secretKey"],
                                                              "keyNum":rcv_eapsim_data["data"]["secretKeyList"][i]["keyNum"],
                                                              "createDatetime":rcv_eapsim_data["data"]["secretKeyList"][i]["createDatetime"]})

                if fwd_eapsim_data["fastReAuth"] or fwd_eapsim_data["privacySupport"] == True:
                    fwd_eapsim_data.update({"activeKey":rcv_eapsim_data["data"]["activeKey"]})

                if fwd_eapsim_data["cleanUp"] == True:
                    fwd_eapsim_data.update({"cleanUpTimeMins": rcv_eapsim_data["data"]["cleanUpTimeMins"]})
                    fwd_eapsim_data.update({"cacheHisLen":rcv_eapsim_data["data"]["cacheHisLen"]})
                    fwd_eapsim_data.update({"cleanUpTimeHrs": rcv_eapsim_data["data"]["cleanUpTimeHrs"]}) 
 
                for i in range(0,len(rcv_eapsim_data["data"]["secretKeyList"])):
                    _max_num =  rcv_eapsim_data["data"]["secretKeyList"][i]["keyNum"]
                if  _max_num == None:
                    _key_num = 0
                else:
                    _key_num = _max_num + 1
                fwd_eapsim_data["secretKeyList"].append({"keyNum":_key_num,
                                                         "secretKey":secret_key,
                                                         "createDatetime":""})
            else:
                raise Exception("eapsim is not enabled")

            eap_profile = json.dumps(fwd_eapsim_data)
            result = ji.put_json_data(url, self.jsessionid, eap_profile)


        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def validate_secretkey_in_eapsim_configuration(self, secret_key=None):
        """
        Validate Secret Key in EAP-SIM Service

        URI: PUT /wsg/api/scg/globalSettings/eapsim?

        :param str secret_key: Secret Key to be validated
        :return: True if Secret Key is validates else False
        :rtype: boolean

        """

        _list_len = None
        is_key_found = False
        try:
            url = ji.get_url(self.req_api_eapsim, self.scg_mgmt_ip, self.scg_port)
            rcvd_data= ji.get_json_data(url, self.jsessionid)
            if secret_key:
                _list_len = len(rcvd_data["data"]["secretKeyList"])

                if _list_len <= 0:
                    print "Secret Key list in EAP-SIM Service is empty"
                    return False

                else:
                    for i in range(0, len(rcvd_data["data"]["secretKeyList"])):
                        if rcvd_data["data"]["secretKeyList"][i]["secretKey"] == secret_key:
                            is_key_found = True
                            break

                    if is_key_found == False:
                        print "validate_secretkey_to_eapsim_config(): secret key %s not found" % (secret_key)
                        return False
            
            return True

        except Exception, e:
            print traceback.format_exc()
            return False

    def update_secretkey_in_eapsim_configuration(self, current_secret_key="test.com", new_secret_key="ruckus.com"):
        """
        API used to update the Secret Key in EAP-SIM Service
        
        URI: PUT /wsg/api/scg/globalSettings/eapsim?

        :param str current_secret_key: Name of the existing secret key 
        :param str new_secret_key: Name of new secret key 
        :return: True if update secret key success else False
        :rtype: boolean
        """

        result = False
        is_entry_found = False
        fwd_eapsim_data = {}
        try:
            url = ji.get_url(self.req_api_eapsim, self.scg_mgmt_ip, self.scg_port)
            rcv_eapsim_data= ji.get_json_data(url, self.jsessionid)
            fwd_eapsim_data.update(self.SJT.get_eapaka_template_update())
            fwd_eapsim_data["enabled"] = rcv_eapsim_data["data"]["enabled"]

            if fwd_eapsim_data["enabled"] == True:
                fwd_eapsim_data["privacySupport"] = rcv_eapsim_data["data"]["privacySupport"]
                fwd_eapsim_data["fastReAuth"] = rcv_eapsim_data["data"]["fastReAuth"]
                fwd_eapsim_data["cleanUp"] = rcv_eapsim_data["data"]["cleanUp"]

                if fwd_eapsim_data["fastReAuth"] == True:
                    fwd_eapsim_data.update({"maxSucReAhth":rcv_eapsim_data["data"]["maxSucReAhth"],
                                    "fastReAuthRealm":rcv_eapsim_data["data"]["fastReAuthRealm"]})

                for i in range(len(rcv_eapsim_data["data"]["secretKeyList"])):
                    fwd_eapsim_data["secretKeyList"].append({"secretKey":rcv_eapsim_data["data"]["secretKeyList"][i]["secretKey"],
                                                              "keyNum":rcv_eapsim_data["data"]["secretKeyList"][i]["keyNum"],
                                                              "createDatetime":rcv_eapsim_data["data"]["secretKeyList"][i]["createDatetime"]})

                if fwd_eapsim_data["fastReAuth"] or fwd_eapsim_data["privacySupport"] == True:
                    fwd_eapsim_data.update({"activeKey":rcv_eapsim_data["data"]["activeKey"]})

                if fwd_eapsim_data["cleanUp"] == True:
                    fwd_eapsim_data.update({"cleanUpTimeMins": rcv_eapsim_data["data"]["cleanUpTimeMins"]})
                    fwd_eapsim_data.update({"cacheHisLen":rcv_eapsim_data["data"]["cacheHisLen"]})
                    fwd_eapsim_data.update({"cleanUpTimeHrs": rcv_eapsim_data["data"]["cleanUpTimeHrs"]})

                for i in range(0,len(rcv_eapsim_data["data"]["secretKeyList"])):
                    if rcv_eapsim_data["data"]["secretKeyList"][i]["secretKey"] == current_secret_key:
                        fwd_eapsim_data["secretKeyList"][i].update({"secretKey":new_secret_key})
                        is_entry_found = True
                        break

                if is_entry_found == False:
                    print "secret key %s not found" %current_secret_key
                    return False

            else:
                raise Exception("eapsim is not enabled")

            eap_profile = json.dumps(fwd_eapsim_data)
            result = ji.put_json_data(url, self.jsessionid, eap_profile)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result
    
    def delete_secretkey_from_eapsim_configuration(self, secret_key="ruckus.com"):
        """
        API used to delete the Secret key in EAP-SIM Service
        
        URI: PUT /wsg/api/scg/globalSettings/eapsim?

        :param str secret_key: Name of the Secret Key to be deleted
        :return: True if Secret Key deleted else False
        :rtype: boolean
        """

        result = False
        is_key_found = False
        fwd_eapsim_data = {}
        try:
            url = ji.get_url(self.req_api_eapsim, self.scg_mgmt_ip, self.scg_port)
            rcv_eapsim_data = ji.get_json_data(url, self.jsessionid)
            fwd_eapsim_data.update(self.SJT.get_eapaka_template_update())
            fwd_eapsim_data["enabled"] = rcv_eapsim_data["data"]["enabled"]

            if fwd_eapsim_data["enabled"] == True:
                fwd_eapsim_data["privacySupport"] = rcv_eapsim_data["data"]["privacySupport"]
                fwd_eapsim_data["fastReAuth"] = rcv_eapsim_data["data"]["fastReAuth"]
                fwd_eapsim_data["cleanUp"] = rcv_eapsim_data["data"]["cleanUp"]

                if fwd_eapsim_data["fastReAuth"] == True:
                    fwd_eapsim_data.update({"maxSucReAhth":rcv_eapsim_data["data"]["maxSucReAhth"],
                                    "fastReAuthRealm":rcv_eapsim_data["data"]["fastReAuthRealm"]})

                for i in range(0, len(rcv_eapsim_data["data"]["secretKeyList"])):
                    fwd_eapsim_data["secretKeyList"].append({"secretKey":rcv_eapsim_data["data"]["secretKeyList"][i]["secretKey"],
                                                              "keyNum":rcv_eapsim_data["data"]["secretKeyList"][i]["keyNum"],
                                                              "createDatetime":rcv_eapsim_data["data"]["secretKeyList"][i]["createDatetime"]})
                ref_key = None
                for k in range(0, len(rcv_eapsim_data["data"]["secretKeyList"])):
                    if rcv_eapsim_data["data"]["secretKeyList"][k]["secretKey"] == secret_key:
                        is_key_found = True
                        ref_key = rcv_eapsim_data["data"]["secretKeyList"][k]["keyNum"]
                        break
                if is_key_found == False:
                    print "Secret Key %s not found" % (secret_key)
                    return False

                if rcv_eapsim_data["data"]["activeKey"] and int(rcv_eapsim_data["data"]["activeKey"]) == ref_key:
                    print "Sercret Key is Referenced: not possible to delete"
                    return False

                if fwd_eapsim_data["fastReAuth"] or fwd_eapsim_data["privacySupport"] == True:
                    fwd_eapsim_data.update({"activeKey":rcv_eapsim_data["data"]["activeKey"]})

                if fwd_eapsim_data["cleanUp"] == True:
                    fwd_eapsim_data.update({"cleanUpTimeMins": rcv_eapsim_data["data"]["cleanUpTimeMins"]})
                    fwd_eapsim_data.update({"cacheHisLen":rcv_eapsim_data["data"]["cacheHisLen"]})
                    fwd_eapsim_data.update({"cleanUpTimeHrs": rcv_eapsim_data["data"]["cleanUpTimeHrs"]}) 


                for i in range(0,len(rcv_eapsim_data["data"]["secretKeyList"])):
                    if rcv_eapsim_data["data"]["secretKeyList"][i]["secretKey"] == secret_key:
                        del fwd_eapsim_data["secretKeyList"][i]    
                        is_key_found = True
                        break

                if is_key_found == False:
                    print "Secret Key %s not found" % (secret_key)
                    return False

            else:
                raise Exception("eapsim is not enabled")

            eap_profile = json.dumps(fwd_eapsim_data)
            result = ji.put_json_data(url, self.jsessionid, eap_profile)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def get_domain_uuid(self, domain_label='Administration Domain'):
        """
        API used to find the domainUUID of given Domain Name
        
        URI: GET /wsg/api/scg/session/currentUser/domainList?includeSelf=true 

        :param str domain_label: Name of the Domain 
        :return: domainUUID
        :rtype: unicode

        """

        is_entry_found = False
        domain_uuid = None

        url = ji.get_url(self.req_api_domains, self.scg_mgmt_ip, self.scg_port)
        rcvd_data = ji.get_json_data(url, self.jsessionid)

        if len(rcvd_data['data']['list']) >= 1:
            for data in rcvd_data['data']['list']:
                if data['label'] == domain_label:
                    domain_uuid = data['key']
                    is_entry_found = True
                    break
        else:
            raise Exception("get_domain_uuid(): No data.list recvd")

        if not is_entry_found:
            raise Exception("get_domain_uuid(): domain_label: %s not found" % domain_label)

        return domain_uuid

    def get_apzone_uuid(self, apzone_name='APZone-1', domain_label='Administration Domain'):
        """
        API used to find the zoneUUID of given Zone and Domain name
        
        URI: GET /wsg/api/scg/zones/byDomain/<domainUUID>

        :param str apzone_name: Name of the APZone
        :param str domain_label: Name of the Domain
        :return: zoneUUID
        :rtype: unicode

        """

        is_entry_found = False
        domain_uuid = None
        zone_uuid = None

        domain_uuid = self.get_domain_uuid(domain_label=domain_label)
        if not domain_uuid:
            print "get_domain_uuid(): domain_label: %s failed" % domain_label
            return domain_uuid

        url = ji.get_url(self.req_api_apzones % domain_uuid, self.scg_mgmt_ip, self.scg_port)
        rcvd_data = ji.get_json_data(url, self.jsessionid)


        if len(rcvd_data['data']['list']) >= 1:
            for data in rcvd_data['data']['list']:
                if data['mobilityZoneName'] == apzone_name:
                    zone_uuid = data['key']
                    is_entry_found = True
                    break
        else:
            raise Exception("get_apzone_uuid(): No data.list recvd")

        if not is_entry_found:
            raise Exception("get_apzone_uuid(): apzone: %s not found" % apzone_name)
        
        return zone_uuid



    def _get_acctid(self, aaa_name="AAAServerName", zone_name="zone", domain_label='Administration Domain'):
        """
        API used to get the account id of AAA Server

        URI: GET /wsg/api/scg/aaaServers/zone/byZone/
        
        :param str aaa_name: Name of AAA Server
        :param str zone_name: Name of APZone
        :param str domain_label: Name of the Domain
        :return: account id
        :rtype: unicode
 
        """

        acctid = None
        api = self.req_api_acctid + self.get_apzone_uuid(apzone_name=zone_name, domain_label=domain_label)
        url = ji.get_url(api, self.scg_mgmt_ip, self.scg_port)
        data = ji.get_json_data(url, self.jsessionid)
        for i in range(0,len(data[u"data"][u"list"])):
            if data[u"data"][u"list"][i][u"name"] == aaa_name:
                acctid = data[u"data"][u"list"][i][u"key"]
                break
        if not acctid:
            raise Exception("_get_acctid(): Account ID not found for name: %s" % (aaa_name))
        return acctid


    def create_aaa_profile(self, aaa_name="Auto_AAA_Server", zone_name="Auto_APZone", domain_label='Administration Domain', 
                           radius_type="RADIUS", 
                           enable_secondary_radius='0',
                           primary_radius_ip="1.2.3.4", primary_radius_port="1812", primary_radius_share_secret="testing123",
                           response_window='20', zombie_period='40', revive_interval='120', noresponse_fail="false",
                           secondary_radius_ip=None, secondary_radius_port=None, secondary_radius_share_secret=None):

        """
        Create the AAA with respective AP zone

        URI: POST /wsg/api/scg/aaaServers/zone/

        :param str aaa_name: Name of AAA to be created
        :param str zone_name: Name of the AP zone 
        :param str radius_type: RADIUS | RADIUSAcct
        :param str enable_secondary_radius: 0 | 1
        :param str primary_radius_ip: primary server ip address 
        :param str primary_radius_port: primary server port number
        :param str primary_radius_share_secret: primary server shared secret
        :param str response_window: Health check policy Response Window
        :param str zombie_period: Health check policy Zombie Period
        :param str revive_interval: Health check policy Revive Interval
        :param str noresponse_fail: true | false
        :param str secondary_radius_ip: secondary server ip address
        :param str secondary_radius_port: secondary server port number
        :param str secondary_radius_share_secret: secondary server shared secret
        :return: True if AAA created else False
        :rtype: boolean

        """

        result = False
        aaa_profile = {}
        
        try:
	    url = ji.get_url(self.req_api_aaa, self.scg_mgmt_ip, self.scg_port)
            aaa_profile.update(self.SJT.get_aaa_template_data())
            aaa_profile.update({"name":aaa_name, 
                                "zoneName":zone_name,
                                "zoneUUID":self.get_apzone_uuid(apzone_name=zone_name, domain_label=domain_label),
                                "type":radius_type,
                                "respWindow":int(response_window),
                                "zombiePeriod":int(zombie_period),
                                "reviveInterval":int(revive_interval)})

            if radius_type == "RADIUS":
                aaa_profile.update({"responseFail":noresponse_fail})
            elif radius_type == "RADIUSAcct":
                aaa_profile.update({"responseFail":"false"})

            aaa_profile.update({"radiusIP":primary_radius_ip,
                                "radiusShareSecret":primary_radius_share_secret,
                                "radiusPort":int(primary_radius_port),
                                "enableSecondaryRadius":int(enable_secondary_radius)})

            if int(enable_secondary_radius) == 1:
                aaa_profile.update({"secondaryRadiusIP":secondary_radius_ip,
                                    "secondaryRadiusPort":int(secondary_radius_port),
                                    "secondaryRadiusShareSecret":secondary_radius_share_secret})

            aaa_profile_json = json.dumps(aaa_profile)
            result = ji.post_json_data(url, self.jsessionid, aaa_profile_json)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result
    
    def validate_aaa_profile(self, aaa_name="Auto_AAA_Server", zone_name="Auto_APZone", domain_label='Administration Domain',
                           radius_type=None, enable_secondary_radius=None,
                           primary_radius_ip=None, primary_radius_port=None, primary_radius_share_secret=None,
                           response_window=None, zombie_period=None, revive_interval=None, noresponse_fail=None,
                           secondary_radius_ip=None, secondary_radius_port=None, secondary_radius_share_secret=None): 
        """
        
        API is used to validate AAA Profile

        URI: GET /wsg/api/scg/aaaServers/zone/byZone/  

        :param str aaa_name: Name of the AAA Profile
        :param str domain_label: Name of the Domain
        :param str zone_name: Name of the AP zone 
        :param str radius_type: RADIUS | RADIUSAcct
        :param str enable_secondary_radius: 0 | 1
        :param str primary_radius_ip: primary server ip address 
        :param str primary_radius_port: primary server port number
        :param str primary_radius_share_secret: primary server shared secret
        :param str response_window: Health check policy Response Window
        :param str zombie_period: Health check policy Zombie Period
        :param str revive_interval: Health check policy Revive Interval
        :param str noresponse_fail: True | False
        :param str secondary_radius_ip: secondary server ip address
        :param str secondary_radius_port: secondary server port number
        :param str secondary_radius_share_secret: secondary server shared secret
        :return: True if AAA profile is validated  else False
        :rtype: boolean
        
        """

        try:
            api = self.req_api_aaa_data + self.get_apzone_uuid(apzone_name=zone_name, domain_label=domain_label) + "?"
            url = ji.get_url(api, self.scg_mgmt_ip, self.scg_port)
            key, rcv_aaa_data = self._get_key_for_aaa_profile(url, aaa_name)
            if aaa_name:
                if rcv_aaa_data["name"] != aaa_name:
                    self._print_err_validate('validate_aaa_profile', 'aaa_name', 'name', aaa_name, rcv_aaa_data["name"])
                    return False
            if zone_name:
                if rcv_aaa_data["zoneName"] != zone_name:
                    self._print_err_validate('validate_aaa_profile', 'zone_name', 'zoneName', zone_name, rcv_aaa_data["zoneName"])
                    return False
            if radius_type:
                if rcv_aaa_data["type"] != radius_type:
                    self._print_err_validate('validate_aaa_profile', 'radius_type', 'type', radius_type, rcv_aaa_data["type"])
                    return False
            if enable_secondary_radius:
                if rcv_aaa_data["enableSecondaryRadius"] != int(enable_secondary_radius):
                    self._print_err_validate('validate_aaa_profile', 'enable_secondary_radius', 'enableSecondaryRadius', enable_secondary_radius,
                            rcv_aaa_data["enableSecondaryRadius"])
                    return False
            if primary_radius_ip:
                if rcv_aaa_data['radiusIP'] != primary_radius_ip:
                    self._print_err_validate('validate_aaa_profile', 'primary_radius_ip', 'radiusIP', primary_radius_ip, rcv_aaa_data['radiusIP'])
                    return False
            if primary_radius_port:
                if rcv_aaa_data["radiusPort"] != int(primary_radius_port):
                    self._print_err_validate('validate_aaa_profile', 'primary_radius_port', 'radiusPort', primary_radius_port, rcv_aaa_data["radiusPort"])
                    return False
            if primary_radius_share_secret:
                if str(rcv_aaa_data["radiusShareSecret"]) != primary_radius_share_secret:
                    self._print_err_validate('validate_aaa_profile', 'primary_radius_share_secret', 'radiusShareSecret', primary_radius_share_secret,
                            rcv_aaa_data["radiusShareSecret"])
                    return False
            if response_window:
                if str(rcv_aaa_data["respWindow"]) != response_window:
                    self._print_err_validate('validate_aaa_profile', 'response_window', 'respWindow', response_window, rcv_aaa_data["respWindow"])
                    return False
            if zombie_period:
                if str(rcv_aaa_data["zombiePeriod"]) != zombie_period:
                    self._print_err_validate('validate_aaa_profile', 'zombie_period', 'zombiePeriod', zombie_period, rcv_aaa_data["zombiePeriod"])
                    return False
            if revive_interval:
                if str(rcv_aaa_data["reviveInterval"]) != revive_interval:
                    self._print_err_validate('validate_aaa_profile', 'revive_interval', 'reviveInterval', revive_interval, 
                            rcv_aaa_data["reviveInterval"])
                    return False

            if noresponse_fail:
                if not radius_type:
                    print "Invalid input: radius type is required"
                    return False
                if radius_type == "RADIUSAcct":
                    noresponse_fail = "false"
                _var = str(noresponse_fail)
                _bool_var = json.loads(_var)
                if rcv_aaa_data["responseFail"] != _bool_var:
                    self._print_err_validate('validate_aaa_profile', 'noresponse_fail', 'responseFail', _bool_var, rcv_aaa_data["responseFail"])
                    return False
            if secondary_radius_ip:
                if rcv_aaa_data["secondaryRadiusIP"] != secondary_radius_ip:
                    self._print_err_validate('validate_aaa_profile', 'secondary_radius_ip','secondaryRadiusIP', secondary_radius_ip,
                            rcv_aaa_data["secondaryRadiusIP"])
                    return False
            if secondary_radius_port:
                if str(rcv_aaa_data["secondaryRadiusPort"]) != secondary_radius_port:
                    self._print_err_validate('validate_aaa_profile', 'secondary_radius_port', 'secondaryRadiusPort', secondary_radius_port,
                            rcv_aaa_data["secondaryRadiusPort"])
                    return False
            if secondary_radius_share_secret:
                if rcv_aaa_data["secondaryRadiusShareSecret"] != secondary_radius_share_secret:
                    self._print_err_validate('validate_aaa_profile', 'secondary_radius_share_secret', 'secondaryRadiusShareSecret',
                            secondary_radius_share_secret, rcv_aaa_data["secondaryRadiusShareSecret"])
                    return False

            return True

        except Exception, e:
            print traceback.format_exc()
            return False

    def _get_key_for_aaa_profile(self, url=None, name='Auto_AAA_Server'):
        """
        API used to get the key and data of AAA profile
        
        :param str url: URL
        :param str name: Name of AAA profile
        :return: key and data of AAA profile
        :rtype: unicode, dictionary

        """

        key, data = None, None
        rcv_data = ji.get_json_data(url,self.jsessionid)
        for i in range(0, len(rcv_data["data"]["list"])):
            if rcv_data["data"]["list"][i]["name"] == name:
                key, data = rcv_data["data"]["list"][i]["key"], rcv_data["data"]["list"][i]
                break

        if not key:
            raise Exception("_get_key_for_aaa_profile():Key not found for the name:%s" % (name))

        return key, data
    
    def update_aaa_profile(self, current_aaa_name="Auto_AAA_Server", zone_name="Auto_APZone", domain_label='Administration Domain', 
                           enable_secondary_radius=None, new_aaa_name=None, 
                           primary_radius_ip=None, primary_radius_port=None, primary_share_secret=None,
                           response_window=None, zombie_period=None, revive_interval=None, noresponse_fail=None,
                           secondary_radius_ip=None, secondary_radius_port=None, secondary_radius_share_secret=None):
        
        """
        API used to update AAA profile

        URI: PUT '/wsg/api/scg/aaaServers/zone/<aaa_profile_key>
        
        :param str current_aaa_name: Name of AAA profile
        :param str zone_name: Name of the AP zone 
        :param str domain_label: Name of the Domain
        :param str radius_type: RADIUS | RADIUSAcct
        :param str enable_secondary_radius: 0 | 1
        :param str primary_radius_ip: primary server ip address 
        :param str primary_radius_port: primary server port number
        :param str primary_radius_share_secret: primary server shared secret
        :param str response_window: Health check policy Response Window
        :param str zombie_period: Health check policy Zombie Period
        :param str revive_interval: Health check policy Revive Interval
        :param str noresponse_fail: true | false
        :param str secondary_radius_ip: secondary server ip address
        :param str secondary_radius_port: secondary server port number
        :param str secondary_radius_share_secret: secondary server shared secret
        :return: True if AAA created else False
        :rtype: boolean
        
        """

        result = False
        fwd_aaa_data = {}
        try:
            api = self.req_api_aaa_data + self.get_apzone_uuid(apzone_name=zone_name, domain_label=domain_label) + "?"
            url = ji.get_url(api, self.scg_mgmt_ip, self.scg_port)
            key, rcv_aaa_data = self._get_key_for_aaa_profile(url, current_aaa_name)
            fwd_aaa_data.update(self.SJT.get_aaa_template_update())

            fwd_aaa_data["name"] = rcv_aaa_data["name"] if new_aaa_name is None else new_aaa_name
            fwd_aaa_data["type"] = rcv_aaa_data["type"]
            fwd_aaa_data["key"] = rcv_aaa_data["key"]
            fwd_aaa_data["zoneName"] = rcv_aaa_data["zoneName"]
            fwd_aaa_data["zoneUUID"] = rcv_aaa_data["zoneUUID"]

            if fwd_aaa_data["type"] == "RADIUS":
                fwd_aaa_data["responseFail"] = rcv_aaa_data["responseFail"] if not noresponse_fail else noresponse_fail
            elif fwd_aaa_data["type"] == "RADIUSAcct":
                fwd_aaa_data["responseFail"] = "false"

            fwd_aaa_data["respWindow"] = rcv_aaa_data["respWindow"] if response_window is None else int(response_window)
            fwd_aaa_data["zombiePeriod"] = rcv_aaa_data["zombiePeriod"] if zombie_period is None else int(zombie_period)
            fwd_aaa_data["reviveInterval"] = rcv_aaa_data["reviveInterval"] if revive_interval is None else int(revive_interval)
                    
            fwd_aaa_data["radiusIP"] = rcv_aaa_data["radiusIP"] if primary_radius_ip is None else primary_radius_ip
            fwd_aaa_data["radiusPort"] = rcv_aaa_data["radiusPort"] if primary_radius_port is None else int(primary_radius_port) 
            fwd_aaa_data["radiusShareSecret"] = \
                rcv_aaa_data["radiusShareSecret"] if primary_share_secret is None else primary_share_secret
            fwd_aaa_data["enableSecondaryRadius"] = \
                rcv_aaa_data["enableSecondaryRadius"] if enable_secondary_radius is None else int(enable_secondary_radius) 
                    
            if fwd_aaa_data["enableSecondaryRadius"] == 1:
                fwd_aaa_data["backup"] = 1
                fwd_aaa_data["secondaryRadiusIP"] = \
                    rcv_aaa_data["secondaryRadiusIP"] if secondary_radius_ip is None else secondary_radius_ip

                fwd_aaa_data["secondaryRadiusPort"] = \
                    rcv_aaa_data["secondaryRadiusPort"] if secondary_radius_port is None else int(secondary_radius_port)

                fwd_aaa_data["secondaryRadiusShareSecret"] = \
                    rcv_aaa_data["secondaryRadiusShareSecret"] if secondary_radius_share_secret is None else secondary_radius_share_secret
                

            json_data = json.dumps(fwd_aaa_data)           
            url_put = ji.get_url(self.req_api_aaa_updt_del%key,self.scg_mgmt_ip, self.scg_port) 
            result = ji.put_json_data(url_put,self.jsessionid,json_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def delete_aaa_profile(self, aaa_name="Auto_AAA_Server", zone_name="Auto_APZone", domain_label='Administration Domain'):
        """ 
        API used to delete AAA profile

        URI: DELETE /wsg/api/scg/aaaServers/zone/<aaa_profile_key>

        :param str aaa_name: Name of AAA profile
        :param str zone_name: Name of APZone
        :param str domain_label: Name of Domain
        :return: True if AAA profile deleted else False
        :rtype: boolean

        """

        result = False

        try:
            api = self.req_api_aaa_data + self.get_apzone_uuid(apzone_name=zone_name, domain_label=domain_label) + "?"
            url = ji.get_url(api, self.scg_mgmt_ip, self.scg_port)
            key, rcv_aaa_data = self._get_key_for_aaa_profile(url, aaa_name)
            del_aaa_url = ji.get_url(self.req_api_aaa_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.delete_scg_data(del_aaa_url, self.jsessionid, None)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def create_wispr_profile(self, wispr_profile_name="Auto_wispr_profile", zone_name="Auto_APZone", domain_label="Administration Domain",
                                   description=None,
                                   #guest_user="0",                                  # "0" or "1"
                                   smart_client_mode="none",                        # enable or none or only
                                   access_type="EXTERNAL",                          # INTERNAL or EXTERNAL
                                   second_redirect_type="user",
                                   session_time='1440', 
                                   grace_period='60',
                                   smart_client_info=None,
                                   authentication_url=None,
                                   redirect_url=None,
                                   location_id=None,
                                   location_name=None,):
                                   #walled_garden=None):
        """ 
        API used to create the WISPr profile

        URI: POST /wsg/api/scg/hotspots/

        :param str wispr_profile_name: Name of WISPr Profile
        :param str zone_name: Name of the APZone
        :param str domain_label: Name of the Domain
        :param str description: Descrption
        :param str guest_user: 0 | 1
        :param str smart_client_mode: enable | none | only
        :param str access_type: INTERNAL | EXTERNAL
        :param str second_redirect_type: start | user
        :param str session_time: Session Timeout
        :param str grace_period: Grace Period
        :param str smart_client_info: Information about the smart client
        :param str authentication_url: Logon URL
        :param str redirect_url: Start Page URL
        :param str location_id: Location ID
        :param str location_name: Location Name
        :param str walled_garden: Walled Garden entry
        :return: True if WISPr profile created else False
        :rtype: boolean
  
        """
        result = False
        wispr_profile = {}
        
        try:
            url = ji.get_url(self.req_api_wispr+"?", self.scg_mgmt_ip, self.scg_port)
            wispr_profile.update(self.SJT.get_wispr_template_data())
            
            wispr_profile.update({"name":wispr_profile_name, 
                                  "descrption":description,
                                  "zoneName":zone_name,
                                  "zoneUUID":self.get_apzone_uuid(apzone_name=zone_name, domain_label=domain_label)})

            wispr_profile.update({"sessionTime":int(session_time),
                                  #"guestUser":guest_user,

                                  "gracePeriod":int(grace_period)})
                                  #"walledGarden":walled_garden})
            if location_id:
                wispr_profile.update({"wisperLocationId":location_id})
            if location_name:
                wispr_profile.update({"wisperLocationName":location_name})

            #if guest_user == "0":
            wispr_profile.update({"smartClientMode":smart_client_mode})

            if smart_client_mode == "only":
                wispr_profile.update({"smartClientInfo":smart_client_info})

            else:
                wispr_profile.update({"spMode":access_type,
                                           "secondRedirect":second_redirect_type})
            if access_type == "EXTERNAL":
                wispr_profile.update({"redirectUrl":authentication_url})
            else:
                wispr_profile.update({"redirectUrl":""})
             
            if second_redirect_type == "start":
                wispr_profile.update({"startUrl":redirect_url})
            else:
                wispr_profile.update({"startUrl":""})
            #else: 
            #    wispr_profile.update({"spMode":access_type,
            #                                  "secondRedirect":second_redirect_type})
            #    if second_redirect_type == "start":
            #        wispr_profile.update({"startUrl":redirect_url})
            #    else:
            #        wispr_profile.update({"startUrl":""})
             
            wispr_profile = json.dumps(wispr_profile)
            result = ji.post_json_data(url, self.jsessionid, wispr_profile)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def validate_wispr_profile(self, wispr_profile_name="Auto_wispr_profile", zone_name="Auto_APZone", domain_label='Administration Domain',
                                   description=None,
                                   guest_user=None,
                                   smart_client_mode=None,
                                   access_type=None,
                                   second_redirect_type=None,
                                   session_time=None, 
                                   grace_period=None,
                                   smart_client_info=None,
                                   authentication_url=None,
                                   redirect_url=None,
                                   location_name=None,
                                   location_id=None):
        """
        API is used to validate WISPr Profile

        URI: GET /wsg/api/scg/hotspots/byZone/

        :param str wispr_profile_name: Name of WISPr Profile
        :param str zone_name: Name of the APZone
        :param str domain_label: Name of the Domain
        :param str description: Descrption
        :param str guest_user: 0 | 1
        :param str smart_client_mode: enable | none | only
        :param str access_type: INTERNAL | EXTERNAL
        :param str second_redirect_type: start | user
        :param str session_time: Session Timeout
        :param str grace_period: Grace Period
        :param str location_id: Location ID
        :param str location_name: Location Name
        :param str smart_client_info: Information about the smart client
        :param str authentication_url: Logon URL
        :param str redirect_url: Start Page URL
        :param str walled_garden: Walled Garden entry
        :return: True if WISPr profile is validated else False
        :rtype: boolean
  
        """

        try:
            api_get = self.req_api_wispr_data + self.get_apzone_uuid(apzone_name=zone_name, domain_label=domain_label) + "?"
            url = ji.get_url(api_get, self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_wispr(url, wispr_profile_name)
            
            if wispr_profile_name:
                if rcvd_data["name"] != wispr_profile_name:
                    self._print_err_validate('validate_wispr_profile', 'wispr_profile_name', 'name', wispr_profile_name,
                            rcvd_data["name"])
                    return False

            if zone_name:
                if rcvd_data["zoneName"] != zone_name:
                    self._print_err_validate('validate_wispr_profile', 'zone_name', 'zoneName', zone_name,
                            rcvd_data["zoneName"])
                    return False
            if description:
                if rcvd_data['description'] != description:
                    self._print_err_validate('validate_wispr_profile', 'description', 'description', description,
                            rcvd_data['description'])
                    return False
            if guest_user:
                if rcvd_data["guestUser"] != int(guest_user):
                    self._print_err_validate('validate_wispr_profile', 'guest_user', 'guestUser', int(guest_user), rcvd_data["guestUser"])
                    return False
            if smart_client_mode:
                if rcvd_data["smartClientMode"] != smart_client_mode:
                    self._print_err_validate('validate_wispr_profile', 'smart_client_mode', 'smartClientMode',smart_client_mode,
                            rcvd_data["smartClientMode"])
                    return False

            if access_type:
                if rcvd_data["spMode"] != access_type:
                    self._print_err_validate('validate_wispr_profile', 'access_type', 'spMode', access_type, rcvd_data["spMode"])
                    return False
            if smart_client_info:
                if rcvd_data["smartClientInfo"] != smart_client_info:
                    self._print_err_validate('validate_wispr_profile', 'smart_client_info', 'smartClientInfo', smart_client_info, 
                            rcvd_data["smartClientInfo"])
                    return False
            if second_redirect_type:
                if rcvd_data["secondRedirect"] != second_redirect_type:
                    self._print_err_validate('validate_wispr_profile', 'second_redirect_type', 'secondRedirect', second_redirect_type,
                            rcvd_data["secondRedirect"])
                    return False
            if authentication_url:
                if rcvd_data["redirectUrl"] != authentication_url:
                    self._print_err_validate('validate_wispr_profile', 'authentication_url', 'redirectUrl', authentication_url,
                            rcvd_data["redirectUrl"])
                    return False
            if redirect_url:
                if rcvd_data["startUrl"] != redirect_url:
                    self._print_err_validate('validate_wispr_profile', 'redirect_url', 'startUrl', redirect_url,
                            rcvd_data["startUrl"])
                    return False
            if session_time:
                if str(rcvd_data["sessionTime"]) != session_time:
                    self._print_err_validate('validate_wispr_profile', 'session_time', 'sessionTime', session_time, rcvd_data["sessionTime"])
                    return False
            if grace_period:
                if str(rcvd_data["gracePeriod"]) != grace_period:
                    self._print_err_validate('validate_wispr_profile', 'grace_period', 'gracePeriod', grace_period, rcvd_data["gracePeriod"])
                    return False
            if location_name:
                if rcvd_data["wisperLocationName"] != location_name:
                    self._print_err_validate('validate_wispr_profile', 'location_name', 'wisperLocationName', location_name,
                            rcvd_data["wisperLocationName"])
                    return False
            if location_id:
                if rcvd_data["wisperLocationId"] != location_id:
                    self._print_err_validate('validate_wispr_profile', 'location_id', 'wisperLocationId',
                            location_id, rcvd_data["wisperLocationId"])
                    return False

            return True

        except Exception, e:
            print traceback.format_exc()
            return False

    def _get_key_for_wispr(self, url=None, name="Auto_wispr_profile"):
        """
        API used to get the key and data of WISPr profile
        
        :param str url: URL
        :param str name: Name of the WISPr profile 
        :return: key and data of WISPr profile
        :rtype: unicode, dictionary
        """
 
        key, data = None, None
        rcv_data = ji.get_json_data(url, self.jsessionid)
        for i in range(0, len(rcv_data["data"]["list"])):
            if rcv_data["data"]["list"][i]["name"] == name:
                key, data = rcv_data["data"]["list"][i]["key"], rcv_data["data"]["list"][i]
                break
        if not key:
            raise Exception("_get_key_for_wispr():Key not found for the name:%s" % (name))

        return key, data

    def update_wispr_profile(self, current_wispr_profile_name="Auto_wispr_profile", zone_name="Auto_APZone", domain_label='Administration Domain',
                                   new_wispr_profile_name=None, description=None,
                                   guest_user=None,                                  
                                   smart_client_mode=None,
                                   access_type=None, smart_client_info=None,
                                   second_redirect_type=None, authentication_url=None,
                                   redirect_url=None, session_time=None, grace_period=None,
                                   location_name=None, location_id=None):
        """ 
        API used to update the WISPr profile

        URI: PUT /wsg/api/scg/hotspots/<wispr_profile_key> 

        :param str current_wispr_profile_name: Name of WISPr Profile
        :param str zone_name: Name of the APZone
        :param str new_wispr_profile_name: New WISPr profile name
        :param str domain_label: Name of the Domain
        :param str description: Descrption
        :param str guest_user: 0 | 1
        :param str smart_client_mode: enable | none | only
        :param str access_type: INTERNAL | EXTERNAL
        :param str second_redirect_type: start | user
        :param str session_time: Session Timeout
        :param str grace_period: Grace Period
        :param str smart_client_info: Information about the smart client
        :param str authentication_url: Logon URL
        :param str redirect_url: Start Page URL
        :param str location_id: Location ID
        :param str location_name: Location Name
        :return: True if WISPr profile updated else False
        :rtype: boolean
  
        """

        result = False
        fwd_wispr_data={}
        try:
            api_get = self.req_api_wispr_data + self.get_apzone_uuid(apzone_name=zone_name, domain_label=domain_label) + "?"
            url = ji.get_url(api_get, self.scg_mgmt_ip, self.scg_port)
            key, rcv_wispr_data = self._get_key_for_wispr(url, current_wispr_profile_name)

            fwd_wispr_data.update(self.SJT.get_wispr_template_data()) 
            fwd_wispr_data["key"] = key
            fwd_wispr_data["zoneName"] = rcv_wispr_data["zoneName"]
            fwd_wispr_data["zoneUUID"] = rcv_wispr_data["zoneUUID"]
            fwd_wispr_data["name"] = rcv_wispr_data["name"] if new_wispr_profile_name is None else new_wispr_profile_name
            fwd_wispr_data["description"] = rcv_wispr_data["description"] if not description else description 
            fwd_wispr_data["guestUser"] = str(rcv_wispr_data["guestUser"]) if guest_user is None else guest_user
            fwd_wispr_data["sessionTime"] = rcv_wispr_data["sessionTime"] if session_time is None else int(session_time)
            fwd_wispr_data["gracePeriod"] = rcv_wispr_data["gracePeriod"] if grace_period is None else int(grace_period)
            fwd_wispr_data["walledGarden"] = rcv_wispr_data["walledGarden"]
            fwd_wispr_data['wisperLocationName'] = rcv_wispr_data['wisperLocationName'] if not location_name else location_name
            fwd_wispr_data['wisperLocationId'] = rcv_wispr_data['wisperLocationId'] if not location_id else location_id

            if location_name:
                if location_name == 'Delete':
                    fwd_wispr_data['wisperLocationName'] = ""
            if location_id:
                if location_id == 'Delete':
                    fwd_wispr_data['wisperLocationId'] = ""
                
            if fwd_wispr_data["guestUser"] == "0":
                fwd_wispr_data["smartClientMode"] = rcv_wispr_data["smartClientMode"] if smart_client_mode is None else smart_client_mode
  
                if fwd_wispr_data["smartClientMode"] == "only":
                        fwd_wispr_data["smartClientInfo"] = rcv_wispr_data["smartClientInfo"] if smart_client_info is None else smart_client_info    
                else:
                    fwd_wispr_data["spMode"] = rcv_wispr_data["spMode"] if access_type is None else access_type   
                    fwd_wispr_data["secondRedirect"] = \
                            rcv_wispr_data["secondRedirect"] if second_redirect_type is None else second_redirect_type

                    if fwd_wispr_data["spMode"] == "EXTERNAL":
                            fwd_wispr_data["redirectUrl"] = rcv_wispr_data["redirectUrl"] if authentication_url is None else authentication_url        
                    else:
                            fwd_wispr_data["redirectUrl"] = ""

                    if fwd_wispr_data["secondRedirect"] == "start":
                            fwd_wispr_data["startUrl"] = rcv_wispr_data["startUrl"] if redirect_url is None else redirect_url
                    else:
                            fwd_wispr_data["startUrl"] = ""

            elif fwd_wispr_data["guestUser"] == "1":

                fwd_wispr_data["smartClientMode"] = "none"
                fwd_wispr_data["spMode"] = "INTERNAL"
                fwd_wispr_data["secondRedirect"] = rcv_wispr_data["secondRedirect"] if second_redirect_type is None else second_redirect_type
                      
                if fwd_wispr_data["secondRedirect"] == "start":
                    fwd_wispr_data["startUrl"] = rcv_wispr_data["startUrl"] if redirect_url is None else redirect_url

                elif fwd_wispr_data["secondRedirect"] == "user":
                    fwd_wispr_data["startUrl"] = ""
                
            json_data = json.dumps(fwd_wispr_data)
            url_put = ji.get_url(self.req_api_wispr_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(url_put, self.jsessionid, json_data)
        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def add_walledgarden_to_wispr_profile(self, wispr_profile_name="Auto_Hotspot_Profile", 
                                                  zone_name='Auto_APZone', 
                                                  domain_label="Administration Domain",
                                                  walledgarden="1.2.3.4"):
        """
        API used to add the WalledGarden to Wispr Profile

        URI: PUT /wsg/api/scg/hotspotsProfile/<hotspot_profile_key>

        :param str wispr_profile_name: Name of the Wispr Profile
        :param str zone_name: Apzone Name
        :param str domain_label: Domain Name
        :param str walledgarden: walledgarden value
        :return: True if WalledGarden added to Wispr Profile successfully else False
        :rtype: boolean
        """

        result = False
        fwd_wispr_data = {}
        try:
            api_get = self.req_api_wispr_data + self.get_apzone_uuid(apzone_name=zone_name, domain_label=domain_label) + "?"
            url = ji.get_url(api_get, self.scg_mgmt_ip, self.scg_port)
            key, rcv_wispr_data = self._get_key_for_wispr(url=url, name=wispr_profile_name)
            fwd_wispr_data.update(self.SJT.get_wispr_template_data())
            fwd_wispr_data["name"] = rcv_wispr_data["name"] 
            fwd_wispr_data["key"] = rcv_wispr_data["key"]
            fwd_wispr_data["description"] = rcv_wispr_data["description"]
            fwd_wispr_data["zoneName"] = rcv_wispr_data["zoneName"]
            fwd_wispr_data["zoneUUID"] = rcv_wispr_data["zoneUUID"]
            fwd_wispr_data["bridgeMode"] = rcv_wispr_data["bridgeMode"]
            #fwd_wispr_data["guestUser"] = str(rcv_wispr_data["guestUser"])            
            fwd_wispr_data["sessionTime"] = rcv_wispr_data["sessionTime"] 
            fwd_wispr_data["gracePeriod"] = rcv_wispr_data["gracePeriod"] 

            rcvd_walledgarden = rcv_wispr_data["walledGarden"]
            concat = None
            if rcvd_walledgarden == ",":
                concat = str(walledgarden)
            else:
                wall = str(rcvd_walledgarden)
                concat = str(wall) + "," + str(walledgarden)

            fwd_wispr_data["walledGarden"] = concat
            fwd_wispr_data["smartClientMode"] = rcv_wispr_data["smartClientMode"]

            fwd_wispr_data['wisperLocationName'] = rcv_wispr_data['wisperLocationName'] 
            fwd_wispr_data['wisperLocationId'] = rcv_wispr_data['wisperLocationId']

            fwd_wispr_data["smartClientInfo"] = rcv_wispr_data["smartClientInfo"]
            fwd_wispr_data["spMode"] = rcv_wispr_data["spMode"] 
            fwd_wispr_data["secondRedirect"] = rcv_wispr_data["secondRedirect"]
                     
            fwd_wispr_data["redirectUrl"] = rcv_wispr_data["redirectUrl"]
        
            fwd_wispr_data["startUrl"] = rcv_wispr_data["startUrl"]
    
            json_data = json.dumps(fwd_wispr_data)
            url_put = ji.get_url(self.req_api_wispr_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(url_put, self.jsessionid, json_data)


        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def validate_walledgarden_in_wispr(self, wispr_profile_name="Auto_Hotspot_Profile",
                                            zone_name='Auto_APZone', 
                                            domain_label='Administration Domain',
                                            walledgarden=None):
        """
        API used to validate the WalledGarden in Wispr Profile

        URI: GET /wsg/api/scg/hotspots/byZone/<apzone_key>?

        :param str wispr_profile_name: Name of the Wispr Profile
        :param str zone_name: Name of APZone
        :param str domain_label: Name of the Domain
        :param str walledgarden: ip or iprange
        :return: True if validation success else False
        :rtype: boolean
        """

        try:
            api_get = self.req_api_wispr_data + self.get_apzone_uuid(apzone_name=zone_name, domain_label=domain_label) + "?"
            url = ji.get_url(api_get, self.scg_mgmt_ip, self.scg_port)
            key, rcv_wispr_data = self._get_key_for_wispr(url=url, name=wispr_profile_name)

            rcvd_walledgarden = rcv_wispr_data["walledGarden"]
            
            if walledgarden:
                if rcvd_walledgarden == ",":
                    print "No items in walled garden list"
                    return False
            
                elif rcvd_walledgarden:
                    ret_result = walledgarden in rcvd_walledgarden
                    if not ret_result:
                        print "WalledGarden %s not found" % (walledgarden)
                        return False
            
            return True

        except Exception, e:
            print traceback.format_exc()
            return False



    def update_walledgarden_in_wispr_profile(self, wispr_profile_name="Auto_Hotspot_Profile", 
                                                  zone_name='Auto_APZone', 
                                                  domain_label="Administration Domain",
                                                  current_walledgarden="1.2.3.4",
                                                  new_walledgarden=None):
        """
        API used to update the WalledGarden to Wispr Profile

        URI: PUT /wsg/api/scg/hotspotsProfile/<hotspot_profile_key>?

        :param str wispr_profile_name: Name of the Wispr Profile
        :param str zone_name: Apzone Name
        :param str domain_label: Domain Name
        :param str curent_walledgarden: ip or iprange
        :param str new_walledgarden: ip or iprange
        :return: True if WalledGarden updated successfully else False
        :rtype: boolean
        """

        result = False
        fwd_wispr_data = {}
        try:
            api_get = self.req_api_wispr_data + self.get_apzone_uuid(apzone_name=zone_name, domain_label=domain_label) + "?"
            url = ji.get_url(api_get, self.scg_mgmt_ip, self.scg_port)
            key, rcv_wispr_data = self._get_key_for_wispr(url=url, name=wispr_profile_name)
            fwd_wispr_data.update(self.SJT.get_wispr_template_data())
            fwd_wispr_data["name"] = rcv_wispr_data["name"] 
            fwd_wispr_data["key"] = rcv_wispr_data["key"]
            fwd_wispr_data["description"] = rcv_wispr_data["description"]
            fwd_wispr_data["zoneName"] = rcv_wispr_data["zoneName"]
            fwd_wispr_data["zoneUUID"] = rcv_wispr_data["zoneUUID"]
            fwd_wispr_data["guestUser"] = str(rcv_wispr_data["guestUser"])            
            fwd_wispr_data["sessionTime"] = rcv_wispr_data["sessionTime"] 
            fwd_wispr_data["gracePeriod"] = rcv_wispr_data["gracePeriod"] 

            rcvd_walledgarden = rcv_wispr_data["walledGarden"]
            updt_wg = None

            if rcvd_walledgarden == ",":
                print "No items in walled garden"
                return False

            elif rcvd_walledgarden:
                ret_result = False
                ret_result = current_walledgarden in rcvd_walledgarden
                if not ret_result:
                    print "Entry %s not found" % (current_walledgarden)
                    return False

                updt_wg = rcvd_walledgarden.replace(current_walledgarden, new_walledgarden)

            fwd_wispr_data["walledGarden"] = updt_wg

            fwd_wispr_data["smartClientMode"] = rcv_wispr_data["smartClientMode"]

            fwd_wispr_data['wisperLocationName'] = rcv_wispr_data['wisperLocationName'] 
            fwd_wispr_data['wisperLocationId'] = rcv_wispr_data['wisperLocationId']

            fwd_wispr_data["smartClientInfo"] = rcv_wispr_data["smartClientInfo"]
            fwd_wispr_data["spMode"] = rcv_wispr_data["spMode"] 
            fwd_wispr_data["secondRedirect"] = rcv_wispr_data["secondRedirect"]
                     
            fwd_wispr_data["redirectUrl"] = rcv_wispr_data["redirectUrl"]
        
            fwd_wispr_data["startUrl"] = rcv_wispr_data["startUrl"]
    
            json_data = json.dumps(fwd_wispr_data)
            url_put = ji.get_url(self.req_api_wispr_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(url_put, self.jsessionid, json_data)


        except Exception, e:
            print traceback.format_exc()
            return False

        return result


    def delete_walledgarden_from_wispr_profile(self, wispr_profile_name="Auto_wispr_profile", 
                                                  zone_name='Auto_APZone', 
                                                  domain_label="Administration Domain",
                                                  walledgarden="1.2.3.4"):
        """
        API used to update the WalledGarden to Wispr Profile

        URI: PUT /wsg/api/scg/hotspotsProfile/<hotspot_profile_key>?

        :param str wispr_profile_name: Name of the Wispr Profile
        :param str zone_name: Apzone Name
        :param str domain_label: Domain Name
        :param str walledgarden: walledgarden value
        :return: True if WalledGarden updated successfully else False
        :rtype: boolean
        """

        result = False
        fwd_wispr_data = {}
        try:
            api_get = self.req_api_wispr_data + self.get_apzone_uuid(apzone_name=zone_name, domain_label=domain_label) + "?"
            url = ji.get_url(api_get, self.scg_mgmt_ip, self.scg_port)
            key, rcv_wispr_data = self._get_key_for_wispr(url=url, name=wispr_profile_name)
            fwd_wispr_data.update(self.SJT.get_wispr_template_data())
            fwd_wispr_data["name"] = rcv_wispr_data["name"] 
            fwd_wispr_data["key"] = rcv_wispr_data["key"]
            fwd_wispr_data["description"] = rcv_wispr_data["description"]
            fwd_wispr_data["zoneName"] = rcv_wispr_data["zoneName"]
            fwd_wispr_data["zoneUUID"] = rcv_wispr_data["zoneUUID"]
            fwd_wispr_data["guestUser"] = str(rcv_wispr_data["guestUser"])            
            fwd_wispr_data["sessionTime"] = rcv_wispr_data["sessionTime"] 
            fwd_wispr_data["gracePeriod"] = rcv_wispr_data["gracePeriod"] 
            
            rcvd_walledgarden = rcv_wispr_data["walledGarden"]
            del_wg = None

            if rcvd_walledgarden == ",":
                print "No items in walled garden"
                return False

            elif rcvd_walledgarden:
                ret_result = False
                _walledgarden = None
                ret_result = walledgarden in rcvd_walledgarden
                if not ret_result:
                    print "entry %s not found"%(walledgarden)
                    return False
                _split_str= rcvd_walledgarden.split(',')
                if len(_split_str) == 1:
                    del_wg = ","
                elif walledgarden == _split_str[0]:
                    _walledgarden = walledgarden+','
                    del_wg = rcvd_walledgarden.replace(_walledgarden,'')
                else:
                    _walledgarden = ','+walledgarden
                    del_wg = rcvd_walledgarden.replace(_walledgarden,'')


            fwd_wispr_data["walledGarden"] = del_wg

            fwd_wispr_data["smartClientMode"] = rcv_wispr_data["smartClientMode"]

            fwd_wispr_data['wisperLocationName'] = rcv_wispr_data['wisperLocationName'] 
            fwd_wispr_data['wisperLocationId'] = rcv_wispr_data['wisperLocationId']

            fwd_wispr_data["smartClientInfo"] = rcv_wispr_data["smartClientInfo"]
            fwd_wispr_data["spMode"] = rcv_wispr_data["spMode"] 
            fwd_wispr_data["secondRedirect"] = rcv_wispr_data["secondRedirect"]
                     
            fwd_wispr_data["redirectUrl"] = rcv_wispr_data["redirectUrl"]
        
            fwd_wispr_data["startUrl"] = rcv_wispr_data["startUrl"]
    
            json_data = json.dumps(fwd_wispr_data)
            url_put = ji.get_url(self.req_api_wispr_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(url_put, self.jsessionid, json_data)


        except Exception, e:
            print traceback.format_exc()
            return False

        return result




    def delete_wispr_profile(self, wispr_profile_name="Auto_wispr_profile", zone_name="Auto_APZone", domain_label='Administration Domain'):
        """
        API used to delete WISPr profile

        URI: DELETE /wsg/api/scg/hotspots/byZone/<apzone_uuid_keys>?

        :param str wispr_profile_name: Name of WISPr profile
        :param str zone_name: Name of APZone
        :param str domain_label: Name of Domain
        :return: True if WISPr profile deleted else False
        :rtype: boolean

        """
 
        result = False
        try:
            self.req_api_get_wispr = self.req_api_wispr_data + self.get_apzone_uuid(apzone_name=zone_name, domain_label=domain_label) + "?"
            url = ji.get_url(self.req_api_get_wispr, self.scg_mgmt_ip, self.scg_port)
            key, wispr_data = self._get_key_for_wispr(url,wispr_profile_name)
            del_wispr_url = ji.get_url(self.req_api_wispr_updt_del%key,self.scg_mgmt_ip, self.scg_port)
            result = ji.delete_scg_data(del_wispr_url,self.jsessionid,None)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result
    

    def _get_key_for_guest_pass(self, name=None):

        key, data = None, None
        url = ji.get_url(self.req_api_guestpass_getlatest, self.scg_mgmt_ip, self.scg_port)
        rcvd_data = ji.get_json_data(url, self.jsessionid)
        for i in range(0, len(rcvd_data['data']['list'])):
            if rcvd_data['data']['list'][i]['loginName'] == name:
                key, data = rcvd_data['data']['list'][i]['key'], rcvd_data['data']['list'][i]
                break
        if not key:
            raise Exception("_get_key_for_guest_pass(): Key not found for the name %s " % name)

        return key, data

    def delete_guest_pass(self, login_name='auto_guest'):
        """
        API used to delete Guestpass

        URI: DELETE /wsg/api/scg/identity/guestpass/<guest_pass key>

        :param login_name: Login name
        :return: True if Guestpass deleted else False
        :rtype: boolean

        """
        result = False
        try:
            key, rcvd_data = self._get_key_for_guest_pass(name=login_name)
            url = ji.get_url(self.req_api_guestpass_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.delete_scg_data(url, self.jsessionid, None)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def create_cgf_service(self, cgf_service_name="CGF", description=None,
                                 charging_service_type="SERVER", gtp_echo_timeout="60",
                                 no_of_gtpecho_response="5", max_no_of_cdr_per_request="1",
                                 cdr_response_timeout="5", cdr_no_of_retries="3",
                                 server_ip="1.2.3.4", server_port="1813",
                                 
                                 record_limit=None, file_time_limit=None, file_lifetime=None,
                                 auto_export_ftp=None, ftp_host_ip=None, ftp_port=None,
                                 ftp_username=None, ftp_password=None, remote_directory=None,
                                 interval=None, hour=None, minute=None,
                                 enable_cdr_for_ttg=True, enable_cdr_for_direct_ip_access=False,
                                 cdr_type="Default_CDR", send_sgsn_address=False,
                                 send_apn_network_identifier=False, send_pdp_type=False,
                                 send_served_pdp_address=False, send_diagnostic=False,
                                 send_cdr_node_id=False, send_cdr_local_record_sequence_number=False,
                                 send_apn_selection_mode=False, send_apn_operator_identifier=False,
                                 send_msisdn=False, send_charging_character_selection_mode=False,
                                 send_dynamic_mode_address_flag=False, send_rat_type=False,
                                 list_of_traffic_volumes=False, cdr_node_id=None, send_sgsn_plmn_id=False,
                                 send_wlan_node_id=False, send_wlan_local_record_sequence_number=False, lbo_node_id=None):
        """
        API used to create CGF Service

        URI: POST /wsg/api/scg/cgfs?

        :param str cgf_service_name: Name of CGF Service
        :param str description: Descrption
        :param str charging_service_type: SEVER | LOCAL_BINARY_FILE | BOTH
        :param str gtp_echo_timeout: 60 to 300
        :param str no_of_gtpecho_response: 3 to 6
        :param str max_no_of_cdr_per_request: 1 to 10
        :param str cdr_response_timeout: 5 to 300
        :param str cdr_no_of_retries: 1 to 10
        :param str record_limit: 1 to 65535
        :param str file_time_limit: 1 to 65535
        :param str file_lifetime: 1 to 80
        :param str server_ip: IP Address of Server
        :param str server_port: Port number
        :param str auto_export_ftp: True | False 
        :param str ftp_host_ip: FTP Host
        :param str ftp_port: FTP Port
        :param str ftp_username: Username 
        :param str ftp_password: Password
        :param str remote_directory: Remote Directory
        :param str interval: Daily | Hourly
        :param str hour: Hours
        :param str minute: Minutes
        :param boolean enable_cdr_for_ttg: True | False
        :param boolean enable_cdr_for_direct_ip_access: True | False
        :param str cdr_type: Default_CDR | S_CDR
        :param boolean send_sgsn_address: True | False
        :param boolean send_apn_network_identifier: True | False
        :param boolean send_pdp_type: True | False
        :param boolean send_served_pdp_address: True | False 
        :param boolean send_diagnostic: True | False
        :param boolean send_cdr_node_id: True | False 
        :param boolean send_cdr_local_record_sequence_number: True | False
        :param boolean send_apn_selection_mode: True | False 
        :param boolean send_apn_operator_identifier: True | False
        :param boolean send_msisdn: True | False 
        :param boolean send_charging_character_selection_mode: True | False
        :param boolean send_dynamic_mode_address_flag: True | False 
        :param boolean send_rat_type: True | False
        :param boolean list_of_traffic_volumes: True | False 
        :param str cdr_node_id: CDR Node ID 
        :param boolean send_sgsn_plmn_id: True | False
        :param boolean send_wlan_node_id: True | False 
        :param boolean send_wlan_local_record_sequence_number: True | False 
        :param str lbo_node_id: LBO Node ID 
        :return: True if CGF Service created else False
        :rtype: boolean

        """

    
        cgf_profile = {}
        
        try:
            url = ji.get_url(self.req_api_cgf, self.scg_mgmt_ip, self.scg_port)
            cgf_profile.update({"name":cgf_service_name,
                                "ttgpdgEnabled":enable_cdr_for_ttg,
                                "description":description,
                                "lboEnabled":enable_cdr_for_direct_ip_access,
                                "chargingServiceType":charging_service_type})

            if charging_service_type == "SERVER" or charging_service_type == "BOTH": 
                cgf_profile["serverOptions"]={}
                cgf_profile["serverOptions"].update({"gtpEchoTimeout":int(gtp_echo_timeout),
                                      "numOfRetriesForGtpEchoResponse":int(no_of_gtpecho_response),
                                      "cdrResponseTimeout":int(cdr_response_timeout),
                                      "cdrNumOfRetries":int(cdr_no_of_retries),
                                      "maxNumOfCDRsPerRequest":int(max_no_of_cdr_per_request),
                                      "serverConfigurationList":[{"priority":"1",
                                                                  "serverIp":server_ip,
                                                                  "serverPort":int(server_port)}]}) 
            
            if charging_service_type == "LOCAL_BINARY_FILE" or charging_service_type == "BOTH":
                cgf_profile["ftpSettings"]={}
                cgf_profile["localBinaryFileOptions"]={}
                if not remote_directory:
                    remote_directory = ""
                cgf_profile["ftpSettings"].update({"ftpHost":ftp_host_ip,
                                                    "ftpPort":int(ftp_port),
                                                    "ftpUserName":ftp_username,
                                                    "ftpPassword":ftp_password,
                                                    "key":self._get_ftp_key(ftp_host_ip),
                                                    "ftpRemoteDirectory":remote_directory})

                cgf_profile["localBinaryFileOptions"].update({"autoExportViaFtp":auto_export_ftp,
                                                              "recordLimit":int(record_limit),
                                                              "fileTimeLimit":int(file_time_limit),
                                                              "fileLifetime":int(file_lifetime),
                                                              "exportScheduleList":[{"interval":interval,
                                                                                     "hour":hour,
                                                                                     "minute":minute}],
                                                              "ftpServerSettingsKey":self._get_ftp_key(ftp_host_ip)})

            if enable_cdr_for_ttg == True:

                    cgf_profile.update({"sendAPNNetworkIdentifier":send_apn_network_identifier,
                                    "sendDiagnostic":send_diagnostic,
                                    "sendNodeID":send_cdr_node_id,
                                    "sendLocalRecordSequenceNumber":send_cdr_local_record_sequence_number,
                                    "sendMSISDN":send_msisdn,
                                    "sendChargingCharacteristicsSelectionMode":send_charging_character_selection_mode,
                                    "sgsnPlmnId":send_sgsn_plmn_id,
                                    "cdrType":cdr_type})      
                    if send_cdr_node_id == True:
                        if cdr_node_id:
                            cgf_profile.update({"nodeID":cdr_node_id})
                        else:
                            print "create_cgf_service(): cdr_node_id is required"
                            return False
                    else:
                        cgf_profile.update({"nodeID":cdr_node_id})
                    if cdr_type == "S_CDR":
                        cgf_profile.update({"sendSGSNAddress":send_sgsn_address,
                                        "sendPDPType":send_pdp_type,
                                        "sendServedPDPAddress":send_served_pdp_address,
                                        "sendAPNSelectionMode":send_apn_selection_mode,
                                        "sendAPNOperatorIdentifier":send_apn_operator_identifier,
                                        "sendDynamicModeAddressFlag":send_dynamic_mode_address_flag,
                                        "sendRATType":send_rat_type,
                                        "listOfTrafficVolumes":list_of_traffic_volumes})
                
            if enable_cdr_for_direct_ip_access == True:
                cgf_profile.update({"lboSendLocalRecordSequenceNumber":send_wlan_local_record_sequence_number,
                                    "lboSendNodeID":send_wlan_node_id})
                if send_wlan_node_id == True:
                    if lbo_node_id:
                        cgf_profile.update({"lboNodeID":lbo_node_id})
                    else:
                        print "create_cgf_service(): lbo_node_id is required"
                        return False
                else:
                    cgf_profile.update({"lboNodeID":lbo_node_id})

            cgf_data = json.dumps(cgf_profile)
            self.result = ji.post_json_data(url, self.jsessionid, cgf_data)
        except Exception, e:
            print traceback.format_exc()
            return False

        return self.result

    def _string_to_bool(self, string_var):
        _bool_var = json.loads(str(string_var))
        if not _bool_var:
            raise Exception("_string_to_bool(): Not possible to convert string to boolean")
        return _bool_var

    def validate_cgf_service(self,cgf_service_name="CGF", description=None,
                                 charging_service_type=None, gtp_echo_timeout=None,
                                 no_of_gtpecho_response=None, max_no_of_cdr_per_request=None,
                                 cdr_response_timeout=None, cdr_no_of_retries=None,
                                 record_limit=None, file_time_limit=None, file_lifetime=None,
                                 server_ip=None, server_port=None,
                                 auto_export_ftp=False, ftp_host_ip=None, ftp_port=None,
                                 ftp_username=None, ftp_password=None,
                                 interval=None, hour=None, minute=None,
                                 enable_cdr_for_ttg=None, enable_cdr_for_direct_ip_access=None,
                                 cdr_type=None, send_sgsn_address=None,
                                 send_apn_network_identifier=None, send_pdp_type=None,
                                 send_served_pdp_address=None, send_diagnostic=None,
                                 send_cdr_node_id=None, send_cdr_local_record_sequence_number=None,
                                 send_apn_selection_mode=None, send_apn_operator_identifier=None,
                                 send_msisdn=None, send_charging_character_selection_mode=None,
                                 send_dynamic_mode_address_flag=None, send_rat_type=None,
                                 list_of_traffic_volumes=None, cdr_node_id=None, send_sgsn_plmn_id=None,
                                 send_wlan_node_id=None, send_wlan_local_record_sequence_number=None, lbo_node_id=None):
        """
        API used to validate CGF Service

        URI: GET /wsg/api/scg/cgfs?

        :param str cgf_service_name: Name of CGF Service
        :param str description: Descrption
        :param str charging_service_type: SEVER | LOCAL_BINARY_FILE | BOTH
        :param str gtp_echo_timeout: 60 to 300
        :param str no_of_gtpecho_response: 3 to 6
        :param str max_no_of_cdr_per_request: 1 to 10
        :param str cdr_response_timeout: 5 to 300
        :param str cdr_no_of_retries: 1 to 10
        :param str record_limit: 1 to 65535
        :param str file_time_limit: 1 to 65535
        :param str file_lifetime: 1 to 80
        :param str server_ip: IP Address of Server
        :param str server_port: Port number
        :param str auto_export_ftp: True | False 
        :param str ftp_host_ip: FTP Host
        :param str ftp_port: FTP Port
        :param str ftp_username: Username 
        :param str ftp_password: Password
        :param str remote_directory: Remote Directory
        :param str interval: Daily | Hourly
        :param str hour: Hours
        :param str minute: Minutes
        :param boolean enable_cdr_for_ttg: True | False
        :param boolean enable_cdr_for_direct_ip_access: True | False
        :param str cdr_type: Default_CDR | S_CDR
        :param boolean send_sgsn_address: True | False
        :param boolean send_apn_network_identifier: True | False
        :param boolean send_pdp_type: True | False
        :param boolean send_served_pdp_address: True | False 
        :param boolean send_diagnostic: True | False
        :param boolean send_cdr_node_id: True | False 
        :param boolean send_cdr_local_record_sequence_number: True | False
        :param boolean send_apn_selection_mode: True | False 
        :param boolean send_apn_operator_identifier: True | False
        :param boolean send_msisdn: True | False 
        :param boolean send_charging_character_selection_mode: True | False
        :param boolean send_dynamic_mode_address_flag: True | False 
        :param boolean send_rat_type: True | False
        :param boolean list_of_traffic_volumes: True | False 
        :param str cdr_node_id: CDR Node ID 
        :param boolean send_sgsn_plmn_id: True | False
        :param boolean send_wlan_node_id: True | False 
        :param boolean send_wlan_local_record_sequence_number: True | False 
        :param str lbo_node_id: LBO Node ID 
        :return: True if CGF Service validated else False
        :rtype: boolean

        """

                                 
        try:
            url = ji.get_url(self.req_api_cgf, self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_cgf_service(url=url, name=cgf_service_name)
            if cgf_service_name:
                if rcvd_data["name"] != cgf_service_name:
                    self._print_err_validate('validate_cgf_service', 'cgf_service_name', 'name', cgf_service_name, rcvd_data["name"])
                    return False
            if description:
                if rcvd_data["description"] != description:
                    self._print_err_validate('validate_cgf_service', 'description', 'description', description, rcvd_data["description"])
                    return False
            if charging_service_type:
                if rcvd_data["chargingServiceType"] != charging_service_type:
                    self._print_err_validate('validate_cgf_service', 'charging_service_type', 'chargingServiceType', charging_service_type,
                            rcvd_data["chargingServiceType"])
                    return False 
                if charging_service_type == "SERVER":
                    if self._validate_server_option(rcvd_data["serverOptions"], gtp_echo_timeout, no_of_gtpecho_response, max_no_of_cdr_per_request, 
                                            cdr_response_timeout,cdr_no_of_retries,server_ip,server_port) != True:
                        return False
                elif charging_service_type == "LOCAL_BINARY_FILE":
                    if self._validate_local_binary_file(rcvd_data, auto_export_ftp, ftp_host_ip, ftp_port,
                                            ftp_username, ftp_password, interval, hour, minute, 
                                            record_limit, file_time_limit, file_lifetime) != True:
                        return False
                elif charging_service_type == "BOTH":
                    if self._validate_server_option(rcvd_data["serverOptions"], gtp_echo_timeout, no_of_gtpecho_response, max_no_of_cdr_per_request, 
                            cdr_response_timeout,cdr_no_of_retries,server_ip,server_port) != True:
                        return False
                    elif self._validate_local_binary_file(rcvd_data, auto_export_ftp, ftp_host_ip, ftp_port,
                            ftp_username, ftp_password, interval, hour, minute,
                            record_limit, file_time_limit, file_lifetime) != True:
                        return False
            
            if enable_cdr_for_ttg is not None and rcvd_data["ttgpdgEnabled"] != enable_cdr_for_ttg:
                self._print_err_validate('validate_cgf_service', 'enable_cdr_for_ttg', 'ttgpdgEnabled', enable_cdr_for_ttg,
                            rcvd_data["ttgpdgEnabled"])
                return False
            if enable_cdr_for_ttg == True:
                if cdr_type == "Default CDR" or "S_CDR":

                    if send_apn_network_identifier is not None and rcvd_data["sendAPNNetworkIdentifier"] != send_apn_network_identifier:
                        self._print_err_validate('validate_cgf_service', 'send_apn_network_identifier', 'sendAPNNetworkIdentifier',
                                send_apn_network_identifier, rcvd_data["sendAPNNetworkIdentifier"])
                        return False 
                    if send_diagnostic is not None and rcvd_data["sendDiagnostic"] != send_diagnostic:
                        self._print_err_validate('validate_cgf_service', 'send_diagnostic', 'sendDiagnostic', send_diagnostic,
                                rcvd_data["sendDiagnostic"])
                        return False
                    if send_cdr_node_id is not None and rcvd_data["sendNodeID"] != send_cdr_node_id:
                        self._print_err_validate('validate_cgf_service', 'send_cdr_node_id', 'sendNodeID', send_cdr_node_id,
                                rcvd_data["sendNodeID"])
                        return False
                    if send_cdr_local_record_sequence_number is not None and \
                            rcvd_data["sendLocalRecordSequenceNumber"] != send_cdr_local_record_sequence_number:
                        self._print_err_validate('validate_cgf_service', 'send_cdr_local_record_sequence_number', 'sendLocalRecordSequenceNumber',
                               send_cdr_local_record_sequence_number , rcvd_data["sendLocalRecordSequenceNumber"])
                        return False
                    if send_msisdn is not None and rcvd_data["sendMSISDN"] != send_msisdn:
                        self._print_err_validate('validate_cgf_service', 'send_msisdn', 'sendMSISDN', send_msisdn,
                                rcvd_data["sendMSISDN"])
                        return False
                    if send_charging_character_selection_mode is not None and \
                            rcvd_data["sendChargingCharacteristicsSelectionMode"] != send_charging_character_selection_mode:
                        self._print_err_validate('validate_cgf_service', 'send_charging_character_selection_mode',
                                'sendChargingCharacteristicsSelectionMode', send_charging_character_selection_mode,
                                rcvd_data["sendChargingCharacteristicsSelectionMode"])
                        return False
                    if cdr_node_id:
                        if rcvd_data["nodeID"] != cdr_node_id:
                            self._print_err_validate('validate_cgf_service', 'cdr_node_id', 'nodeID', cdr_node_id, rcvd_data["nodeID"])
                            return False
                    if send_sgsn_plmn_id is not None and rcvd_data["sgsnPlmnId"] != send_sgsn_plmn_id:
                        self._print_err_validate('validate_cgf_service', 'send_sgsn_plmn_id', 'sgsnPlmnId', send_sgsn_plmn_id,
                                rcvd_data["sgsnPlmnId"])
                        return False
            
                elif cdr_type and cdr_type == "S_CDR":

                    if enable_cdr_for_direct_ip_access is not None and rcvd_data["lboEnabled"] != enable_cdr_for_direct_ip_access:
                        self._print_err_validate('validate_cgf_service', 'enable_cdr_for_direct_ip_access', 'lboEnabled',
                            enable_cdr_for_direct_ip_access, rcvd_data["lboEnabled"])
                        return False
                    if cdr_type:
                        if rcvd_data["cdrType"] != cdr_type:
                            self._print_err_validate('validate_cgf_service', 'cdr_type', 'cdrType', cdr_type, rcvd_data["cdrType"])
                            return False
                    if send_sgsn_address is not None and rcvd_data["sendSGSNAddress"] != send_sgsn_address:
                        self._print_err_validate('validate_cgf_service', 'send_sgsn_address', 'sendSGSNAddress', send_sgsn_address,
                            rcvd_data["sendSGSNAddress"])
                        return False
                    if send_pdp_type is not None and rcvd_data["sendPDPType"] != send_pdp_type:
                        self._print_err_validate('validate_cgf_service', 'send_pdp_type', 'sendPDPType', send_pdp_type,
                            rcvd_data["sendPDPType"])
                        return False
                    if send_served_pdp_address is not None and rcvd_data["sendServedPDPAddress"] != send_served_pdp_address:
                        self._print_err_validate('validate_cgf_service', 'send_served_pdp_address', 'sendServedPDPAddress', send_served_pdp_address,
                            rcvd_data["sendServedPDPAddress"])
                        return False
                    if send_apn_selection_mode is not None and rcvd_data["sendAPNSelectionMode"] != send_apn_selection_mode:
                        self._print_err_validate('validate_cgf_service', 'send_apn_selection_mode', 'sendAPNSelectionMode',
                            send_apn_selection_mode, rcvd_data["sendAPNSelectionMode"])
                        return False
                    if send_apn_operator_identifier is not None and rcvd_data["sendAPNOperatorIdentifier"] != send_apn_operator_identifier:
                        self._print_err_validate('validate_cgf_service', 'send_apn_operator_identifier', 'sendAPNOperatorIdentifier',
                            send_apn_operator_identifier, rcvd_data["sendAPNOperatorIdentifier"])
                        return False
                    if send_dynamic_mode_address_flag is not None and rcvd_data["sendDynamicModeAddressFlag"] != send_dynamic_mode_address_flag:
                        self._print_err_validate('validate_cgf_service', 'send_dynamic_mode_address_flag', 'sendDynamicModeAddressFlag',
                            send_dynamic_mode_address_flag, rcvd_data["sendDynamicModeAddressFlag"])
                        return False
                    if send_rat_type is not None and rcvd_data["sendRATType"] != send_rat_type:
                        self._print_err_validate('validate_cgf_service', 'send_rat_type', 'sendRATType',
                            send_rat_type, rcvd_data["sendRATType"])
                        return False
                    if list_of_traffic_volumes is not None and rcvd_data["listOfTrafficVolumes"] != list_of_traffic_volumes:
                        self._print_err_validate('validate_cgf_service', 'list_of_traffic_volumes', 'listOfTrafficVolumes',
                            list_of_traffic_volumes, rcvd_data["listOfTrafficVolumes"])
                        return False

            if enable_cdr_for_direct_ip_access == True:

                if send_wlan_node_id is not None and rcvd_data["lboSendNodeID"] != send_wlan_node_id:
                    self._print_err_validate('validate_cgf_service', 'send_wlan_node_id', 'lboSendNodeID', send_wlan_node_id,
                        rcvd_data["lboSendNodeID"])
                    return False
                if send_wlan_local_record_sequence_number is not None and \
                        rcvd_data["lboSendLocalRecordSequenceNumber"] != send_wlan_local_record_sequence_number:
                    self._print_err_validate('validate_cgf_service', 'send_wlan_local_record_sequence_number', 'lboSendLocalRecordSequenceNumber',
                        send_wlan_local_record_sequence_number, rcvd_data["lboSendLocalRecordSequenceNumber"])
                    return False
                if lbo_node_id:
                    if rcvd_data["lboNodeID"] != lbo_node_id:
                        self._print_err_validate('validate_cgf_service', 'lbo_node_id', 'lboNodeID', lbo_node_id,
                                rcvd_data["lboNodeID"])
                        return False

            return True

        except Exception, e:
            print traceback.format_exc()
            return False

    def _validate_local_binary_file(self, rcvd_data, auto_export_ftp, ftp_host_ip, ftp_port,
                                ftp_username, ftp_password, interval, hour, minute, record_limit, file_time_limit, file_lifetime):
        try:
            rcv_data = rcvd_data["localBinaryFileOptions"]
            if auto_export_ftp:
                _var = str(auto_export_ftp)
                _bool_var = json.loads(_var)
                if rcv_data["autoExportViaFtp"] != _bool_var:
                    self._print_err_validate('_validate_local_binary', 'auto_export_ftp', 'autoExportViaFtp', _bool_var,
                            rcv_data["autoExportViaFtp"])
                    return False
            if record_limit:
                if int(rcv_data["recordLimit"]) != record_limit:
                    self._print_err_validate('_validate_local_binary', 'record_limit', 'recordLimit', record_limit,
                            rcv_data["recordLimit"])
                    return False
            if file_time_limit:
                if int(rcv_data["fileTimeLimit"]) != file_time_limit:
                    self._print_err_validate('_validate_local_binary', 'file_time_limit', 'fileTimeLimit', file_time_limit,
                            rcv_data["fileTimeLimit"])
                    return False
            if file_lifetime:
                if int(rcv_data["fileLifetime"]) != file_lifetime:
                    self._print_err_validate('_validate_local_binary', 'file_lifetime', 'fileLifetime', file_lifetime,
                            rcv_data["fileLifetime"])
                    return False
            if interval:
                if rcv_data["exportScheduleList"][0]["interval"] != interval:
                    self._print_err_validate('_validate_local_binary', 'interval', 'interval', interval,
                            rcv_data["exportScheduleList"][0]["interval"])
                    return False
            if hour:
                if str(rcv_data["exportScheduleList"][0]["hour"]) != hour:
                    self._print_err_validate('_validate_local_binary', 'hour', 'hour', hour, 
                            str(rcv_data["exportScheduleList"][0]["hour"]))
                    return False
            if minute:
                if str(rcv_data["exportScheduleList"][0]["minute"]) != minute:
                    self._print_err_validate('_validate_local_binary', 'minute', 'minute', minute,
                            str(rcv_data["exportScheduleList"][0]["minute"]))
            
            url_ftp = ji.get_url(self.req_api_ftp, self.scg_mgmt_ip, self.scg_port)
            data = ji.get_json_data(url_ftp, self.jsessionid)
            rcv_ftp = {}
            if ftp_host_ip:
                for i in range(0, len(data["data"]["list"])):
                    if data["data"]["list"][i]["ftpHost"] == ftp_host_ip:
                        rcv_ftp = data["data"]["list"][i]
                if not rcv_ftp:
                    raise Exception("_validate_local_binary_file: %s Not found" %(ftp_host_ip))
                if rcv_ftp["ftpHost"] != ftp_host_ip:
                    self._print_err_validate('_validate_local_binary', 'ftp_host_ip', 'ftpHost', ftp_host_ip,
                            rcv_ftp["ftpHost"])
                if str(rcv_ftp["ftpPort"]) != ftp_port:
                    self._print_err_validate('_validate_local_binary', 'ftp_port', 'ftpPort', ftp_port, str(rcv_ftp["ftpPort"]))
                    return False
                if rcv_ftp["ftpUserName"] != ftp_username:
                    self._print_err_validate('_validate_local_binary', 'ftp_username', 'ftpUserName', ftp_username,
                            rcv_ftp["ftpUserName"])
                    return False
                if  rcv_ftp["ftpPassword"] != ftp_password:
                    self._print_err_validate('_validate_local_binary', 'ftp_password', 'ftpPassword', ftp_password,
                            rcv_ftp["ftpPassword"])
                    return False
        
            return True
        except Exception, e:
            print traceback.format_exc()
            return False

    def _validate_server_option(self, rcvd_data, gtp_echo_timeout, no_of_gtpecho_response, max_no_of_cdr_per_request,
            cdr_response_timeout, cdr_no_of_retries,server_ip, server_port):
        try:
            if gtp_echo_timeout:
                if rcvd_data["gtpEchoTimeout"] != int(gtp_echo_timeout):
                    self._print_err_validate('_validate_server_option', 'gtp_echo_timeout', 'gtpEchoTimeout', gtp_echo_timeout,
                            rcvd_data["gtpEchoTimeout"])
                    return False
            if no_of_gtpecho_response:
                if rcvd_data["numOfRetriesForGtpEchoResponse"] != int(no_of_gtpecho_response):
                    self._print_err_validate('_validate_server_option', 'no_of_gtpecho_response', 'numOfRetriesForGtpEchoResponse',
                            no_of_gtpecho_response, rcvd_data["numOfRetriesForGtpEchoResponse"])
                    return False
            if max_no_of_cdr_per_request:
                if rcvd_data["maxNumOfCDRsPerRequest"] != int(max_no_of_cdr_per_request):
                    self._print_err_validate('_validate_server_option', 'max_no_of_cdr_per_request', 'maxNumOfCDRsPerRequest',
                            max_no_of_cdr_per_request, rcvd_data["maxNumOfCDRsPerRequest"])
                    return False
            if cdr_response_timeout:
                if rcvd_data["cdrResponseTimeout"] != int(cdr_response_timeout):
                    self._print_err_validate('_validate_server_option', 'cdr_response_timeout', 'cdrResponseTimeout', cdr_response_timeout,
                            rcvd_data["cdrResponseTimeout"])
                    return False
            if cdr_no_of_retries:
                if rcvd_data["cdrNumOfRetries"] != int(cdr_no_of_retries):
                    self._print_err_validate('_validate_server_option', 'cdr_no_of_retries', 'cdrNumOfRetries', cdr_no_of_retries,
                            rcvd_data["cdrNumOfRetries"])
                    return False
            rcvd_data["serverConfigurationList"]
            if server_ip:
                if rcvd_data["serverConfigurationList"][0]["serverIp"] != server_ip:
                    self._print_err_validate('_validate_server_option', 'server_ip', 'serverIp', server_ip,
                            rcvd_data["serverConfigurationList"][0]["serverIp"])
                    return False
                if rcvd_data["serverConfigurationList"][0]["serverPort"] != int(server_port):
                    self._print_err_validate('_validate_server_option', 'server_port', 'serverPort', server_port,
                            rcvd_data["serverConfigurationList"][0]["serverPort"])
                    return False
            return True

        except Exception, e:
            print traceback.format_exc()
            return False

    def _get_key_for_cgf_service(self, url=None, name="Auto_CGF_Service"):
        """
        API used to get the key and data of CGF Service

        :param str url: URL
        :param str name: Name of CGF Service
        :return: key and data of CGF Service
        :rtype: unicode, dictionary

        """

        key, data = None, None
        rcv_data = ji.get_json_data(url,self.jsessionid)
        for i in range(0, len(rcv_data["data"]["list"])):
            if rcv_data["data"]["list"][i]["name"] == name:
                key, data = rcv_data["data"]["list"][i]["key"], rcv_data["data"]["list"][i]
                break

        if not key:
            raise Exception("_get_key_for_cgf_service(): Key not found for name: %s" % (name))

        return key, data

    def update_cgf_service(self, current_cgf_service_name="CGF", new_cgf_service_name=None,description=None,
                                 charging_service_type=None, gtp_echo_timeout=None,
                                 no_of_gtpecho_response=None, max_no_of_cdr_per_request=None,
                                 cdr_response_timeout=None, cdr_no_of_retries=None,
                                 record_limit=None, file_time_limit=None, file_lifetime=None,
                                 server_ip=None, server_port=None,
                                 auto_export_ftp=None, ftp_host_ip=None, ftp_port=None,
                                 ftp_username=None, ftp_password=None,
                                 interval=None, hour=None, minute=None,
                                 enable_cdr_for_ttg=None, enable_cdr_for_direct_ip_access=False,
                                 cdr_type=None, send_sgsn_address=None,
                                 send_apn_network_identifier=None, send_pdp_type=None,
                                 send_served_pdp_address=None, send_diagnostic=None,
                                 send_cdr_node_id=None, send_cdr_local_record_sequence_number=None,
                                 send_apn_selection_mode=None, send_apn_operator_identifier=None,
                                 send_msisdn=None, send_charging_character_selection_mode=None,
                                 send_dynamic_mode_address_flag=None, send_rat_type=None,
                                 list_of_traffic_volumes=None, cdr_node_id=None, send_sgsn_plmn_id=None,
                                 send_wlan_node_id=None, send_wlan_local_record_sequence_number=None, lbo_node_id=None):
        """
        API used to update CGF Service

        URI: PUT /wsg/api/scg/cgfs?

        :param str current_cgf_service_name: Name of CGF Service
        :param str new_cgf_service_name: New CGF Service Name
        :param str description: Descrption
        :param str charging_service_type: SEVER | LOCAL_BINARY_FILE | BOTH
        :param str gtp_echo_timeout: 60 to 300
        :param str no_of_gtpecho_response: 3 to 6
        :param str max_no_of_cdr_per_request: 1 to 10
        :param str cdr_response_timeout: 5 to 300
        :param str cdr_no_of_retries: 1 to 10
        :param str record_limit: 1 to 65535
        :param str file_time_limit: 1 to 65535
        :param str file_lifetime: 1 to 80
        :param str server_ip: IP Address of Server
        :param str server_port: Port number
        :param str auto_export_ftp: True | False 
        :param str ftp_host_ip: FTP Host
        :param str ftp_port: FTP Port
        :param str ftp_username: Username 
        :param str ftp_password: Password
        :param str remote_directory: Remote Directory
        :param str interval: Daily | Hourly
        :param str hour: Hours
        :param str minute: Minutes
        :param boolean enable_cdr_for_ttg: True | False
        :param boolean enable_cdr_for_direct_ip_access: True | False
        :param str cdr_type: Default_CDR | S_CDR
        :param boolean send_sgsn_address: True | False
        :param boolean send_apn_network_identifier: True | False
        :param boolean send_pdp_type: True | False
        :param boolean send_served_pdp_address: True | False 
        :param boolean send_diagnostic: True | False
        :param boolean send_cdr_node_id: True | False 
        :param boolean send_cdr_local_record_sequence_number: True | False
        :param boolean send_apn_selection_mode: True | False 
        :param boolean send_apn_operator_identifier: True | False
        :param boolean send_msisdn: True | False 
        :param boolean send_charging_character_selection_mode: True | False
        :param boolean send_dynamic_mode_address_flag: True | False 
        :param boolean send_rat_type: True | False
        :param boolean list_of_traffic_volumes: True | False 
        :param str cdr_node_id: CDR Node ID 
        :param boolean send_sgsn_plmn_id: True | False
        :param boolean send_wlan_node_id: True | False 
        :param boolean send_wlan_local_record_sequence_number: True | False 
        :param str lbo_node_id: LBO Node ID 
        :return: True if CGF Service is updated else False
        :rtype: boolean

        """

        result = False
        temp_fwd_data = {}
        try:
            url = ji.get_url(self.req_api_cgf, self.scg_mgmt_ip,self.scg_port)
            key, rcv_cgf_data = self._get_key_for_cgf_service(url=url, name=current_cgf_service_name)  
            temp_fwd_data.update(self.SJT.get_cgf_template_data_basic())
            temp_fwd_data["key"] = key
            temp_fwd_data["name"] = rcv_cgf_data["name"] if new_cgf_service_name is None else new_cgf_service_name 
            temp_fwd_data["description"] =  rcv_cgf_data["description"]  if description is None else description
            temp_fwd_data["ttgpdgEnabled"] = \
                    rcv_cgf_data["ttgpdgEnabled"] if enable_cdr_for_ttg is None else enable_cdr_for_ttg 
            temp_fwd_data["chargingServiceType"] = \
                    rcv_cgf_data["chargingServiceType"] if charging_service_type is None else charging_service_type
            temp_fwd_data["lboEnabled"] = \
                    rcv_cgf_data["lboEnabled"] if enable_cdr_for_direct_ip_access is None else enable_cdr_for_direct_ip_access
            prev_charging_type = rcv_cgf_data["chargingServiceType"] 
            
            if temp_fwd_data["chargingServiceType"] == "SERVER":
                self._update_cgf_server_type(prev_charging_type=prev_charging_type,temp_fwd_data=temp_fwd_data, 
                                            rcv_cgf_data=rcv_cgf_data, gtp_echo_timeout=gtp_echo_timeout,
                                            no_of_gtpecho_response=no_of_gtpecho_response, cdr_response_timeout=cdr_response_timeout, 
                                            cdr_no_of_retries=cdr_no_of_retries, 
                                            max_no_of_cdr_per_request=max_no_of_cdr_per_request)
            
            if temp_fwd_data["chargingServiceType"] == "LOCAL_BINARY_FILE":
                self._update_cgf_local_binary_file(prev_charging_type=prev_charging_type, temp_fwd_data=temp_fwd_data, 
                                                rcv_cgf_data=rcv_cgf_data, auto_export_ftp=auto_export_ftp,
                                                ftp_host_ip=ftp_host_ip, ftp_port=ftp_port, ftp_username=ftp_username,
                                                ftp_password=ftp_password,
                                                record_limit=record_limit, file_time_limit=file_time_limit,
                                                file_lifetime=file_lifetime,
                                                interval=interval, hour=hour, minute=minute) 
            
            if temp_fwd_data["chargingServiceType"] == "BOTH":
                self._update_cgf_both(prev_charging_type=prev_charging_type, temp_fwd_data=temp_fwd_data, rcv_cgf_data=rcv_cgf_data,
                                  gtp_echo_timeout=gtp_echo_timeout,
                                  no_of_gtpecho_response=no_of_gtpecho_response, cdr_response_timeout=cdr_response_timeout,
                                  cdr_no_of_retries=cdr_no_of_retries,
                                  max_no_of_cdr_per_request=max_no_of_cdr_per_request, 
                                  auto_export_ftp=auto_export_ftp, ftp_host_ip=ftp_host_ip, ftp_port=ftp_port,
                                  ftp_username=ftp_username, ftp_password=ftp_password,
                                  record_limit=record_limit, file_time_limit=file_time_limit, file_lifetime=file_lifetime,
                                  interval=interval, hour=hour, minute=minute) 
            
            if temp_fwd_data["ttgpdgEnabled"] == True:
                temp_fwd_data.update(self.SJT.get_cgf_template_data_default_cdr())
                temp_fwd_data.update({"cdrType":cdr_type,
                                    "sendAPNNetworkIdentifier":rcv_cgf_data['sendAPNNetworkIdentifier'] if send_apn_network_identifier is None \
                                            else send_apn_network_identifier,
                                    "sendDiagnostic":rcv_cgf_data['sendDiagnostic'] if send_diagnostic is None else send_diagnostic,
                                    "sendNodeID":rcv_cgf_data['sendNodeID'] if send_cdr_node_id is None else send_cdr_node_id,
                                    "sendLocalRecordSequenceNumber":rcv_cgf_data['sendLocalRecordSequenceNumber'] if \
                                            send_cdr_local_record_sequence_number is None else send_cdr_local_record_sequence_number,
                                    "sendMSISDN":rcv_cgf_data['sendMSISDN'] if send_msisdn is None else send_msisdn,
                                    "sendChargingCharacteristicsSelectionMode":rcv_cgf_data['sendChargingCharacteristicsSelectionMode'] if \
                                            send_charging_character_selection_mode is None else send_charging_character_selection_mode,
                                    "sgsnPlmnId":rcv_cgf_data['sgsnPlmnId'] if send_sgsn_plmn_id is None else send_sgsn_plmn_id})

                _cdr_node_id = rcv_cgf_data["nodeID"] if cdr_node_id is None else cdr_node_id
                if temp_fwd_data["sendNodeID"] == True and (not _cdr_node_id):
                    print "CDR Node ID required"
                    return False
                temp_fwd_data.update({"nodeID":cdr_node_id})

                if temp_fwd_data["cdrType"] == "S_CDR":
                    temp_fwd_data.update(self.SJT.get_cgf_template_data_s_cdr())
                    temp_fwd_data.update({"sendSGSNAddress":rcv_cgf_data['sendSGSNAddress'] if send_sgsn_address is None else send_sgsn_address,
                                          "sendPDPType":rcv_cgf_data['sendPDPType'] if send_pdp_type is None else send_pdp_type,
                                          "sendServedPDPAddress":rcv_cgf_data['sendServedPDPAddress'] if send_served_pdp_address is \
                                                  None else send_served_pdp_address,
                                          "sendAPNSelectionMode":rcv_cgf_data['sendAPNSelectionMode'] if send_apn_selection_mode is \
                                                  None else send_apn_selection_mode,
                                          "sendAPNOperatorIdentifier":rcv_cgf_data['sendAPNOperatorIdentifier'] if send_apn_operator_identifier \
                                                  is None else send_apn_operator_identifier,
                                          "sendDynamicModeAddressFlag":rcv_cgf_data['sendDynamicModeAddressFlag'] if send_dynamic_mode_address_flag \
                                                  is None else send_dynamic_mode_address_flag,
                                          "sendRATType":rcv_cgf_data['sendRATType'] if send_rat_type is None else send_rat_type,
                                          "listOfTrafficVolumes":rcv_cgf_data['listOfTrafficVolumes'] if list_of_traffic_volumes is None \
                                                  else list_of_traffic_volumes})
                     
            if temp_fwd_data["lboEnabled"] == True:
                temp_fwd_data["lboSendLocalRecordSequenceNumber"]= rcv_cgf_data["lboSendLocalRecordSequenceNumber"] \
                    if send_wlan_local_record_sequence_number is None else send_wlan_local_record_sequence_number
                temp_fwd_data["lboSendNodeID"] = rcv_cgf_data["lboSendNodeID"] if send_wlan_node_id is None else send_wlan_node_id
                _lbo_node_id = rcv_cgf_data["lboNodeID"] if lbo_node_id is None else lbo_node_id

                if temp_fwd_data["lboSendNodeID"] == True and (not _lbo_node_id ): 
                    print "LBO Node ID required"
                    return False

                temp_fwd_data["lboNodeID"]= rcv_cgf_data['lboNodeID']if  lbo_node_id is None else lbo_node_id
                temp_fwd_data.update({"lboSendServiceContextID": False})
            
            cgf_data= json.dumps(temp_fwd_data)
            put_url = ji.get_url(self.req_api_cgf_updt_del%key, self.scg_mgmt_ip, self.scg_port) 
            result = ji.put_json_data(put_url, self.jsessionid, cgf_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result
    
    def _update_cgf_both(self, prev_charging_type, temp_fwd_data, rcv_cgf_data,
                              gtp_echo_timeout, no_of_gtpecho_response,
                              cdr_response_timeout, cdr_no_of_retries,
                              max_no_of_cdr_per_request, auto_export_ftp,
                              ftp_host_ip, ftp_port, ftp_username, ftp_password,
                              record_limit, file_time_limit, file_lifetime,
                              interval, hour, minute):


        if prev_charging_type == "SERVER" or "BOTH":
            temp_fwd_data.update(self.SJT.get_cgf_template_data_binary_server())
            temp_fwd_data["localBinaryFileOptions"]["autoExportViaFtp"]=temp_fwd_data["localBinaryFileOptions"]["autoExportViaFtp"] \
                        if auto_export_ftp is None else auto_export_ftp
            temp_fwd_data["localBinaryFileOptions"]["recordLimit"] = temp_fwd_data["localBinaryFileOptions"]["recordLimit"] \
                      if record_limit is None else record_limit
            temp_fwd_data["localBinaryFileOptions"]["fileTimeLimit"]= temp_fwd_data["localBinaryFileOptions"]["fileTimeLimit"] \
                      if file_time_limit is None else file_time_limit
            temp_fwd_data["localBinaryFileOptions"]["fileLifetime"]=temp_fwd_data["localBinaryFileOptions"]["fileLifetime"] \
                      if file_lifetime is None else file_lifetime
            temp_fwd_data["ftpSettings"]["ftpHost"]=temp_fwd_data["ftpSettings"]["ftpHost"] if ftp_host_ip is None else ftp_host_ip
            temp_fwd_data["ftpSettings"]["ftpPort"]=temp_fwd_data["ftpSettings"]["ftpPort"] if ftp_port is None else ftp_port
            temp_fwd_data["ftpSettings"]["ftpUserName"]= temp_fwd_data["ftpSettings"]["ftpUserName"] if ftp_username is None else ftp_username
            temp_fwd_data["ftpSettings"]["ftpPassword"]=temp_fwd_data["ftpSettings"]["ftpPassword"] if ftp_password is None else ftp_password
            temp_fwd_data["ftpSettings"]["key"] = self._get_ftp_key(ftp_host_ip)
            temp_fwd_data["localBinaryFileOptions"]["exportScheduleList"][0]["interval"] = temp_fwd_data["localBinaryFileOptions"]\
                  ["exportScheduleList"][0]["interval"] if interval is None else interval
            temp_fwd_data["localBinaryFileOptions"]["exportScheduleList"][0]["hour"]= temp_fwd_data["localBinaryFileOptions"]\
                  ["exportScheduleList"][0]["hour"] if hour is None else hour
            temp_fwd_data["localBinaryFileOptions"]["exportScheduleList"][0]["minute"]= temp_fwd_data["localBinaryFileOptions"]\
                  ["exportScheduleList"][0]["minute"] if minute is None else minute
            temp_fwd_data.update(self.SJT.get_cgf_template_data_server()) 
            temp_fwd_data["serverOptions"]["gtpEchoTimeout"]= temp_fwd_data["serverOptions"]["gtpEchoTimeout"] if  \
                  rcv_cgf_data["serverOptions"]["gtpEchoTimeout"] is None else rcv_cgf_data["serverOptions"]["gtpEchoTimeout"]
            temp_fwd_data["serverOptions"]["gtpEchoTimeout"] = temp_fwd_data["serverOptions"]["gtpEchoTimeout"] if gtp_echo_timeout is None \
                  else gtp_echo_timeout
            temp_fwd_data["serverOptions"]["numOfRetriesForGtpEchoResponse"]= temp_fwd_data["serverOptions"]["numOfRetriesForGtpEchoResponse"]\
                  if rcv_cgf_data["serverOptions"]["numOfRetriesForGtpEchoResponse"] is None \
                  else rcv_cgf_data["serverOptions"]["numOfRetriesForGtpEchoResponse"]
            temp_fwd_data["serverOptions"]["numOfRetriesForGtpEchoResponse"] = temp_fwd_data["serverOptions"]["numOfRetriesForGtpEchoResponse"] \
                  if no_of_gtpecho_response is None else no_of_gtpecho_response
            temp_fwd_data["serverOptions"]["cdrResponseTimeout"]=temp_fwd_data["serverOptions"]["cdrResponseTimeout"] if \
                  rcv_cgf_data["serverOptions"]["cdrResponseTimeout"] is None else rcv_cgf_data["serverOptions"]["cdrResponseTimeout"]
            temp_fwd_data["serverOptions"]["cdrResponseTimeout"]=temp_fwd_data["serverOptions"]["cdrResponseTimeout"] if cdr_response_timeout \
                  is None else cdr_response_timeout
            temp_fwd_data["serverOptions"]["cdrNumOfRetries"]=temp_fwd_data["serverOptions"]["cdrNumOfRetries"] if \
                      rcv_cgf_data["serverOptions"]["cdrNumOfRetries"] is None else rcv_cgf_data["serverOptions"]["cdrNumOfRetries"]
            temp_fwd_data["serverOptions"]["cdrNumOfRetries"]=temp_fwd_data["serverOptions"]["cdrNumOfRetries"] if cdr_no_of_retries \
                       is None else cdr_no_of_retries
            temp_fwd_data["serverOptions"]["maxNumOfCDRsPerRequest"]=temp_fwd_data["serverOptions"]["maxNumOfCDRsPerRequest"] if \
                      rcv_cgf_data["serverOptions"]["maxNumOfCDRsPerRequest"] is None else rcv_cgf_data["serverOptions"]["maxNumOfCDRsPerRequest"]
            temp_fwd_data["serverOptions"]["maxNumOfCDRsPerRequest"]=temp_fwd_data["serverOptions"]["maxNumOfCDRsPerRequest"] if \
                      max_no_of_cdr_per_request is None else max_no_of_cdr_per_request

        elif prev_charging_type == "LOCAL_BINARY_FILE" or "BOTH":

            temp_fwd_data.update(self.SJT.get_cgf_template_data_server())
            temp_fwd_data["serverOptions"]["gtpEchoTimeout"]= temp_fwd_data["serverOptions"]["gtpEchoTimeout"] \
                  if gtp_echo_timeout is None else gtp_echo_timeout
            temp_fwd_data["serverOptions"]["numOfRetriesForGtpEchoResponse"] = temp_fwd_data["serverOptions"]["numOfRetriesForGtpEchoResponse"] \
                  if no_of_gtpecho_response is None else no_of_gtpecho_response
            temp_fwd_data["serverOptions"]["cdrResponseTimeout"]=temp_fwd_data["serverOptions"]["cdrResponseTimeout"] if cdr_response_timeout \
                  is None else cdr_response_timeout
            temp_fwd_data["serverOptions"]["cdrNumOfRetries"]=temp_fwd_data["serverOptions"]["cdrNumOfRetries"] if cdr_no_of_retries \
                   is None else cdr_no_of_retries
            temp_fwd_data["serverOptions"]["maxNumOfCDRsPerRequest"]=temp_fwd_data["serverOptions"]["maxNumOfCDRsPerRequest"] if \
                  max_no_of_cdr_per_request is None else max_no_of_cdr_per_request

            temp_fwd_data.update(self.SJT.get_cgf_template_data_binary_server())
            temp_fwd_data["localBinaryFileOptions"]["autoExportViaFtp"]=temp_fwd_data["localBinaryFileOptions"]["autoExportViaFtp"] if \
                  rcv_cgf_data["localBinaryFileOptions"]["autoExportViaFtp"] is None else \
                  rcv_cgf_data["localBinaryFileOptions"]["autoExportViaFtp"]
            temp_fwd_data["localBinaryFileOptions"]["autoExportViaFtp"]=temp_fwd_data["localBinaryFileOptions"]["autoExportViaFtp"] \
                  if auto_export_ftp is None else auto_export_ftp
            temp_fwd_data["localBinaryFileOptions"]["recordLimit"]=temp_fwd_data["localBinaryFileOptions"]["recordLimit"] \
                  if rcv_cgf_data["localBinaryFileOptions"]["recordLimit"] is None else rcv_cgf_data["localBinaryFileOptions"]["recordLimit"]
            temp_fwd_data["localBinaryFileOptions"]["recordLimit"] = temp_fwd_data["localBinaryFileOptions"]["recordLimit"] \
                  if record_limit is None else record_limit
            temp_fwd_data["localBinaryFileOptions"]["fileTimeLimit"]=temp_fwd_data["localBinaryFileOptions"]["fileTimeLimit"] if \
                  rcv_cgf_data["localBinaryFileOptions"]["fileTimeLimit"] is None else rcv_cgf_data["localBinaryFileOptions"]["fileTimeLimit"]
            temp_fwd_data["localBinaryFileOptions"]["fileTimeLimit"]= temp_fwd_data["localBinaryFileOptions"]["fileTimeLimit"] \
                  if file_time_limit is None else file_time_limit
            temp_fwd_data["localBinaryFileOptions"]["fileLifetime"]= temp_fwd_data["localBinaryFileOptions"]["fileLifetime"] if \
                  rcv_cgf_data["localBinaryFileOptions"]["fileLifetime"] is None else rcv_cgf_data["localBinaryFileOptions"]["fileLifetime"]
            temp_fwd_data["localBinaryFileOptions"]["fileLifetime"]=temp_fwd_data["localBinaryFileOptions"]["fileLifetime"] \
                  if file_lifetime is None else file_lifetime
            temp_fwd_data["ftpSettings"]["ftpHost"]=temp_fwd_data["ftpSettings"]["ftpHost"] if ftp_host_ip is None else ftp_host_ip
            temp_fwd_data["ftpSettings"]["ftpPort"]=temp_fwd_data["ftpSettings"]["ftpPort"] if ftp_port is None else ftp_port
            temp_fwd_data["ftpSettings"]["ftpUserName"]= temp_fwd_data["ftpSettings"]["ftpUserName"] if ftp_username is None else ftp_username
            temp_fwd_data["ftpSettings"]["ftpPassword"]=temp_fwd_data["ftpSettings"]["ftpPassword"] if ftp_password is None else ftp_password
            temp_fwd_data["ftpSettings"]["key"] = self._get_ftp_key(ftp_host_ip)
            temp_fwd_data["localBinaryFileOptions"]["exportScheduleList"][0]["interval"]= temp_fwd_data["localBinaryFileOptions"]\
                          ["exportScheduleList"][0]["interval"] if rcv_cgf_data["localBinaryFileOptions"]["exportScheduleList"][0]["interval"] is \
                          None else rcv_cgf_data["localBinaryFileOptions"]["exportScheduleList"][0]["interval"]
            temp_fwd_data["localBinaryFileOptions"]["exportScheduleList"][0]["interval"] = temp_fwd_data["localBinaryFileOptions"]\
                          ["exportScheduleList"][0]["interval"] if interval is None else interval
            temp_fwd_data["localBinaryFileOptions"]["exportScheduleList"][0]["hour"]= temp_fwd_data["localBinaryFileOptions"] \
                          ["exportScheduleList"][0]["hour"] if rcv_cgf_data["localBinaryFileOptions"]["exportScheduleList"][0]["hour"] is \
                          None else rcv_cgf_data["localBinaryFileOptions"]["exportScheduleList"][0]["hour"]
            temp_fwd_data["localBinaryFileOptions"]["exportScheduleList"][0]["hour"]= temp_fwd_data["localBinaryFileOptions"]\
                          ["exportScheduleList"][0]["hour"] if hour is None else hour
            temp_fwd_data["localBinaryFileOptions"]["exportScheduleList"][0]["minute"]= temp_fwd_data["localBinaryFileOptions"] \
                          ["exportScheduleList"][0]["minute"] if rcv_cgf_data["localBinaryFileOptions"]["exportScheduleList"][0]["minute"] is \
                          None else rcv_cgf_data["localBinaryFileOptions"]["exportScheduleList"][0]["minute"]
            temp_fwd_data["localBinaryFileOptions"]["exportScheduleList"][0]["minute"]= temp_fwd_data["localBinaryFileOptions"]\
                          ["exportScheduleList"][0]["minute"] if minute is None else minute


    def _update_cgf_local_binary_file(self,prev_charging_type, temp_fwd_data, 
                                          rcv_cgf_data,auto_export_ftp,ftp_host_ip,
                                          ftp_port,ftp_username,
                                          ftp_password,record_limit,
                                          file_time_limit,file_lifetime,
                                          interval,hour,minute):
        if prev_charging_type == "LOCAL_BINARY_FILE" or "BOTH":
                
            temp_fwd_data.update(self.SJT.get_cgf_template_data_binary_server())
            temp_fwd_data["localBinaryFileOptions"]["autoExportViaFtp"]=temp_fwd_data["localBinaryFileOptions"]["autoExportViaFtp"] \
                    if rcv_cgf_data["localBinaryFileOptions"]["autoExportViaFtp"] is None \
                    else rcv_cgf_data["localBinaryFileOptions"]["autoExportViaFtp"]
            temp_fwd_data["localBinaryFileOptions"]["autoExportViaFtp"] = temp_fwd_data["localBinaryFileOptions"]["autoExportViaFtp"] if \
                    auto_export_ftp is None else auto_export_ftp
            temp_fwd_data["localBinaryFileOptions"]["recordLimit"]=temp_fwd_data["localBinaryFileOptions"]["recordLimit"] if \
                    rcv_cgf_data["localBinaryFileOptions"]["recordLimit"] is None else rcv_cgf_data["localBinaryFileOptions"]["recordLimit"]
            temp_fwd_data["localBinaryFileOptions"]["recordLimit"]=temp_fwd_data["localBinaryFileOptions"]["recordLimit"] if \
                    record_limit is None else record_limit
            temp_fwd_data["localBinaryFileOptions"]["fileTimeLimit"]=temp_fwd_data["localBinaryFileOptions"]["fileTimeLimit"] \
                    if rcv_cgf_data["localBinaryFileOptions"]["fileTimeLimit"] is None else rcv_cgf_data["localBinaryFileOptions"]["fileTimeLimit"]
            temp_fwd_data["localBinaryFileOptions"]["fileTimeLimit"]=temp_fwd_data["localBinaryFileOptions"]["fileTimeLimit"] if \
                    file_time_limit is None else file_time_limit
            temp_fwd_data["localBinaryFileOptions"]["fileLifetime"]=temp_fwd_data["localBinaryFileOptions"]["fileLifetime"] \
                    if rcv_cgf_data["localBinaryFileOptions"]["fileLifetime"] is None else rcv_cgf_data["localBinaryFileOptions"]["fileLifetime"]
            temp_fwd_data["localBinaryFileOptions"]["fileLifetime"]=temp_fwd_data["localBinaryFileOptions"]["fileLifetime"] \
                    if file_lifetime is None else file_lifetime
            temp_fwd_data["localBinaryFileOptions"]["exportScheduleList"][0]["interval"]= \
                    rcv_cgf_data["localBinaryFileOptions"]["exportScheduleList"][0]["interval"]
            temp_fwd_data["localBinaryFileOptions"]["exportScheduleList"][0]["interval"]= temp_fwd_data["localBinaryFileOptions"] \
                    ["exportScheduleList"][0]["interval"]  if interval is None else interval
            temp_fwd_data["localBinaryFileOptions"]["exportScheduleList"][0]["hour"]= temp_fwd_data["localBinaryFileOptions"]\
                    ["exportScheduleList"][0]["hour"] if rcv_cgf_data["localBinaryFileOptions"]["exportScheduleList"][0]["hour"] is None else \
                    rcv_cgf_data["localBinaryFileOptions"]["exportScheduleList"][0]["hour"]
            temp_fwd_data["localBinaryFileOptions"]["exportScheduleList"][0]["hour"]=temp_fwd_data["localBinaryFileOptions"]\
                    ["exportScheduleList"][0]["hour"] if hour is None else hour
            temp_fwd_data["localBinaryFileOptions"]["exportScheduleList"][0]["minute"]= temp_fwd_data["localBinaryFileOptions"] \
                    ["exportScheduleList"][0]["minute"] if rcv_cgf_data["localBinaryFileOptions"]["exportScheduleList"][0]["minute"] is None \
                    else rcv_cgf_data["localBinaryFileOptions"]["exportScheduleList"][0]["minute"]
            temp_fwd_data["localBinaryFileOptions"]["exportScheduleList"][0]["minute"]= temp_fwd_data["localBinaryFileOptions"] \
                    ["exportScheduleList"][0]["minute"] if minute is None else minute
            temp_fwd_data["ftpSettings"]["ftpHost"]=temp_fwd_data["ftpSettings"]["ftpHost"] if rcv_cgf_data["ftpSettings"]["ftpHost"] is None \
                    else rcv_cgf_data["ftpSettings"]["ftpHost"]
            temp_fwd_data["ftpSettings"]["ftpHost"]=temp_fwd_data["ftpSettings"]["ftpHost"] if ftp_host_ip is None else ftp_host_ip
            temp_fwd_data["ftpSettings"]["ftpPort"]=temp_fwd_data["ftpSettings"]["ftpPort"] if rcv_cgf_data["ftpSettings"]["ftpPort"] is None \
                    else rcv_cgf_data["ftpSettings"]["ftpPort"]
            temp_fwd_data["ftpSettings"]["ftpPort"]=temp_fwd_data["ftpSettings"]["ftpPort"] if ftp_port is None else ftp_port
            temp_fwd_data["ftpSettings"]["ftpUserName"]= temp_fwd_data["ftpSettings"]["ftpUserName"] if rcv_cgf_data["ftpSettings"]["ftpUserName"]\
                    is None else rcv_cgf_data["ftpSettings"]["ftpUserName"]
            temp_fwd_data["ftpSettings"]["ftpUserName"]= temp_fwd_data["ftpSettings"]["ftpUserName"] if ftp_username is None else ftp_username
            temp_fwd_data["ftpSettings"]["ftpPassword"]=temp_fwd_data["ftpSettings"]["ftpPassword"] if rcv_cgf_data["ftpSettings"]["ftpPassword"] \
                     is None else rcv_cgf_data["ftpSettings"]["ftpPassword"]
            temp_fwd_data["ftpSettings"]["ftpPassword"]=temp_fwd_data["ftpSettings"]["ftpPassword"] if ftp_password is None else ftp_password
            temp_fwd_data["ftpSettings"]["key"] = self._get_ftp_key(ftp_host_ip)

        if prev_charging_type == "SERVER":

            temp_fwd_data.update(self.SJT.get_cgf_template_data_binary_server())
            temp_fwd_data["localBinaryFileOptions"]["autoExportViaFtp"] = temp_fwd_data["localBinaryFileOptions"]["autoExportViaFtp"] if \
                    auto_export_ftp is None else auto_export_ftp
            temp_fwd_data["localBinaryFileOptions"]["recordLimit"] = temp_fwd_data["localBinaryFileOptions"]["recordLimit"] if \
                    record_limit is None else record_limit
            temp_fwd_data["localBinaryFileOptions"]["fileTimeLimit"]=temp_fwd_data["localBinaryFileOptions"]["fileTimeLimit"] \
                    if file_time_limit is None else file_time_limit
            temp_fwd_data["localBinaryFileOptions"]["fileLifetime"] = temp_fwd_data["localBinaryFileOptions"]["fileLifetime"] if \
                    file_lifetime is None else file_lifetime
            temp_fwd_data["ftpSettings"]["ftpHost"]=temp_fwd_data["ftpSettings"]["ftpHost"] if ftp_host_ip is None else ftp_host_ip
            temp_fwd_data["ftpSettings"]["ftpPort"]=temp_fwd_data["ftpSettings"]["ftpPort"] if ftp_port is None else ftp_port
            temp_fwd_data["ftpSettings"]["ftpUserName"]= temp_fwd_data["ftpSettings"]["ftpUserName"] if ftp_username is None else ftp_username
            temp_fwd_data["ftpSettings"]["ftpPassword"]=temp_fwd_data["ftpSettings"]["ftpPassword"] if ftp_password is None else ftp_password
            temp_fwd_data["localBinaryFileOptions"]["exportScheduleList"][0]["interval"] = \
                    temp_fwd_data["localBinaryFileOptions"]["exportScheduleList"][0]["interval"] if interval is None else interval
            temp_fwd_data["localBinaryFileOptions"]["exportScheduleList"][0]["hour"]=\
                    temp_fwd_data["localBinaryFileOptions"]["exportScheduleList"][0]["hour"] if hour is None else hour
            temp_fwd_data["localBinaryFileOptions"]["exportScheduleList"][0]["minute"] = \
                    temp_fwd_data["localBinaryFileOptions"]["exportScheduleList"][0]["minute"] if minute is None else minute

    
    def _update_cgf_server_type(self,prev_charging_type,
                                    temp_fwd_data, 
                                    rcv_cgf_data,
                                    gtp_echo_timeout,
                                    no_of_gtpecho_response,
                                    cdr_response_timeout, 
                                    cdr_no_of_retries, 
                                    max_no_of_cdr_per_request):

        if prev_charging_type == "SERVER" or "BOTH":
                
            temp_fwd_data.update(self.SJT.get_cgf_template_data_server())
            temp_fwd_data["serverOptions"]["gtpEchoTimeout"] = temp_fwd_data["serverOptions"]["gtpEchoTimeout"] \
                    if rcv_cgf_data["serverOptions"]["gtpEchoTimeout"] is  None else rcv_cgf_data["serverOptions"]["gtpEchoTimeout"]
            temp_fwd_data["serverOptions"]["gtpEchoTimeout"] = temp_fwd_data["serverOptions"]["gtpEchoTimeout"] if gtp_echo_timeout is None \
                    else gtp_echo_timeout
            temp_fwd_data["serverOptions"]["numOfRetriesForGtpEchoResponse"] = temp_fwd_data["serverOptions"]["numOfRetriesForGtpEchoResponse"] if \
                    rcv_cgf_data["serverOptions"]["numOfRetriesForGtpEchoResponse"] is None else \
                    rcv_cgf_data["serverOptions"]["numOfRetriesForGtpEchoResponse"]
            temp_fwd_data["serverOptions"]["numOfRetriesForGtpEchoResponse"] = temp_fwd_data["serverOptions"]["numOfRetriesForGtpEchoResponse"] if \
                    no_of_gtpecho_response is None else no_of_gtpecho_response
            temp_fwd_data["serverOptions"]["cdrResponseTimeout"]= temp_fwd_data["serverOptions"]["cdrResponseTimeout"] \
                    if rcv_cgf_data["serverOptions"]["cdrResponseTimeout"] is None else rcv_cgf_data["serverOptions"]["cdrResponseTimeout"]
            temp_fwd_data["serverOptions"]["cdrResponseTimeout"]= temp_fwd_data["serverOptions"]["cdrResponseTimeout"] if cdr_response_timeout \
                    is None else cdr_response_timeout
            temp_fwd_data["serverOptions"]["cdrNumOfRetries"]= temp_fwd_data["serverOptions"]["cdrNumOfRetries"] if \
                    rcv_cgf_data["serverOptions"]["cdrNumOfRetries"] is None else rcv_cgf_data["serverOptions"]["cdrNumOfRetries"]
            temp_fwd_data["serverOptions"]["cdrNumOfRetries"]= temp_fwd_data["serverOptions"]["cdrNumOfRetries"] \
                    if cdr_no_of_retries is None else cdr_no_of_retries
            temp_fwd_data["serverOptions"]["maxNumOfCDRsPerRequest"]=temp_fwd_data["serverOptions"]["maxNumOfCDRsPerRequest"] if \
                    rcv_cgf_data["serverOptions"]["maxNumOfCDRsPerRequest"] is None else rcv_cgf_data["serverOptions"]["maxNumOfCDRsPerRequest"]
            temp_fwd_data["serverOptions"]["maxNumOfCDRsPerRequest"]=temp_fwd_data["serverOptions"]["maxNumOfCDRsPerRequest"] \
                    if max_no_of_cdr_per_request is None else max_no_of_cdr_per_request
            temp_fwd_data["serverOptions"]["serverConfigurationList"] = copy.deepcopy(rcv_cgf_data["serverOptions"]["serverConfigurationList"])

        if prev_charging_type == "LOCAL_BINARY_FILE":

            temp_fwd_data.update(self.SJT.get_cgf_template_data_server())
            temp_fwd_data["serverOptions"]["gtpEchoTimeout"] = temp_fwd_data["serverOptions"]["gtpEchoTimeout"] if gtp_echo_timeout is None \
                else gtp_echo_timeout
            temp_fwd_data["serverOptions"]["numOfRetriesForGtpEchoResponse"] = temp_fwd_data["serverOptions"]["numOfRetriesForGtpEchoResponse"] \
                if no_of_gtpecho_response is None else no_of_gtpecho_response
            temp_fwd_data["serverOptions"]["cdrResponseTimeout"]= temp_fwd_data["serverOptions"]["cdrResponseTimeout"] \
                  if cdr_response_timeout is None else cdr_response_timeout
            temp_fwd_data["serverOptions"]["cdrNumOfRetries"]= temp_fwd_data["serverOptions"]["cdrNumOfRetries"] \
                  if cdr_no_of_retries is None else cdr_no_of_retries
            temp_fwd_data["serverOptions"]["maxNumOfCDRsPerRequest"]=temp_fwd_data["serverOptions"]["maxNumOfCDRsPerRequest"] \
                  if max_no_of_cdr_per_request is None else max_no_of_cdr_per_request
    

    def delete_cgf_service(self, cgf_service_name="TEST"):
        """
        API used to delete CGF Services

        URI: DELETE /wsg/api/scg/cgfs/<cgf_service_keys> 

        :param str cgf_service_name: Name of the CGF service Profile
        :return: True if CGF service is deleted successfully else False
        :rtype: boolean

        """

        result = False
        try:
            url = ji.get_url(self.req_api_cgf, self.scg_mgmt_ip, self.scg_port)
            key, rcv_cgf_data=self._get_key_for_cgf_service(url=url, name=cgf_service_name) 
            url_delete_cgf = ji.get_url(self.req_api_cgf_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.delete_scg_data(url_delete_cgf, self.jsessionid, None)
        except Exception, e:
            print traceback.format_exc()
            return False

        return result

        
    def _get_ftp_key(self, ftp_host_ip='1.2.3.4'):    
        """
        API used to get the key of FTP Server
        
        URI: GET 
        
        :param str ftp_host_ip: IP Address of FTP Host
        :return: key of FTP Server
        :rtype: unicode

        """
        ftp_key = None

        ftp_key_url = ji.get_url(self.req_api_ftp,self.scg_mgmt_ip,self.scg_port)
        ftp_data = ji.get_json_data(ftp_key_url, self.jsessionid)
        for i in range (0, len(ftp_data["data"]["list"])):
            if ftp_data["data"]["list"][i]["ftpHost"] == ftp_host_ip:
                ftp_key = ftp_data["data"]["list"][i]["key"]
                break

        return ftp_key

    def add_server_ip_to_cgf_service(self,cgf_service_name="CGF", 
                                          server_ip="2.3.4.5", 
                                          server_port="1812"):
        """
        Adds Server IP to CGF Service if  charging service is SERVER

        URI: PUT /wsg/api/scg/cgfs/<cgf_service_key>

        :param str cgf_service_name: Name of CGF Service
        :param str server_ip: IP of the server
        :param str server_port: Port number
        :return: True if Service IP is added to the CGF service else False
        :rtype: boolean

        """
        
        result = False
        try:
            url = ji.get_url(self.req_api_cgf, self.scg_mgmt_ip, self.scg_port)
            key, rcv_cgf_data = self._get_key_for_cgf_service(url=url, name=cgf_service_name)

            if rcv_cgf_data["serverOptions"]["serverConfigurationJSONArray"]:
                del rcv_cgf_data["serverOptions"]["serverConfigurationJSONArray"]
            if rcv_cgf_data["columns"]:
                del rcv_cgf_data["columns"]
            if rcv_cgf_data["localBinaryFileOptions"]:
                del rcv_cgf_data["localBinaryFileOptions"]  

            fwd_server_data = copy.deepcopy(rcv_cgf_data)
            len_list = len(fwd_server_data["serverOptions"]["serverConfigurationList"])
            priority = len_list+1
            fwd_server_data["serverOptions"]["serverConfigurationList"].append({"priority":priority,
                                                                               "serverIp":server_ip,
                                                                                "serverPort":int(server_port)})
            data = json.dumps(fwd_server_data)
            url_put = ji.get_url(self.req_api_cgf_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(url_put, self.jsessionid, data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def validate_server_ip_to_cgf_service(self, cgf_service_name="CGF", server_ip=None, server_port=None):
        """
        API used to validate the Server IP in CGF Service
        
        URI: GET /wsg/api/scg/cgfs?

        :param str cgf_service_name: Name of CGF Service
        :param str server_ip: IP of the server
        :param str server_port: Port number
        :return: True if Server IP is validated in CGF service else False
        :rtype: boolean

        """

        try:
            url = ji.get_url(self.req_api_cgf, self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_cgf_service(url=url, name=cgf_service_name)
            is_entry_found = False

            if server_port and not server_ip:
                print "invalid input parameter combination"
                return False

            exp_result = (True if server_ip else False, True if server_port else False)

            if server_ip:
                is_server_ip_found = False
                is_server_port_found = False
                for i in range(0, len(rcvd_data["serverOptions"]["serverConfigurationList"])):
                    if server_ip == rcvd_data["serverOptions"]["serverConfigurationList"][i]["serverIp"]:
                        is_server_ip_found = True
                    if server_port and int(server_port) == rcvd_data["serverOptions"]["serverConfigurationList"][i]["serverPort"]:
                        is_server_port_found = True
                    actual_result = (is_server_ip_found, is_server_port_found)
                    if exp_result == actual_result:
                        is_entry_found = True
                        break

                if is_entry_found == False:
                    print "validate_add_server_ip_to_cgf_service(): server ip %s not found" % server_ip
                    return False

            return True

        except Exception, e:
            print traceback.format_exc()
            return False

    def update_server_ip_in_cgf_service(self, cgf_service_name="CGF", 
                                              current_server_ip=None, 
                                              new_server_ip=None, 
                                              new_server_port=None, 
                                              new_priority=None):
        """
        API used to update Server IP in CGF Service 
        
        URI: PUT /wsg/api/scg/cgfs/<cgf_service_key>
        
        :param str cgf_service_name: Name of CGF Service
        :param str current_server_ip: IP of Sever to be changed
        :param str new_server_ip: IP of the server
        :param str new_server_port: Port number
        :param str new_priority: Priority of IP
        :return: True if Server IP is updated to the CGF service else False
        :rtype: boolean

        """

        result = False

        current_priority = None
        _priority = None
        _index = 0
        _updt_index = 0
        is_entry_found = False

        try:
            url = ji.get_url(self.req_api_cgf, self.scg_mgmt_ip, self.scg_port)
            key, rcv_cgf_data = self._get_key_for_cgf_service(url=url, name=cgf_service_name)
            if rcv_cgf_data["serverOptions"]["serverConfigurationJSONArray"]:
                del rcv_cgf_data["serverOptions"]["serverConfigurationJSONArray"]
            if rcv_cgf_data["columns"]:
                del rcv_cgf_data["columns"]
            if rcv_cgf_data["localBinaryFileOptions"]:
                del rcv_cgf_data["localBinaryFileOptions"]

            fwd_cgf_data = copy.deepcopy(rcv_cgf_data)

            #find server entry (if any) having this new priority and steal its priority
            if new_priority:
                if int(new_priority) > len(fwd_cgf_data["serverOptions"]["serverConfigurationList"]):
                    print "update_servers_in_cgf(): new_priority: %d out of range" % int(new_priority)
                    return False
                for server_entry in fwd_cgf_data["serverOptions"]["serverConfigurationList"]:
                    if server_entry['priority'] == int(new_priority):
                        _priority = server_entry['priority']
                        break
                    _index = _index + 1

            for server_entry in fwd_cgf_data["serverOptions"]["serverConfigurationList"]:
                if server_entry['serverIp'] == current_server_ip:
                    is_entry_found = True
                    current_priority = server_entry['priority']
                    break
                _updt_index = _updt_index + 1


            if not is_entry_found:
                print "update_dns_servers_in_ggsn(): current_dns_ip: %s not found" % current_server_ip
                return False

            if _priority is not None:
                #swap priorities
                fwd_cgf_data['serverOptions']['serverConfigurationList'][_index]['priority'], \
                     fwd_cgf_data['serverOptions']['serverConfigurationList'][_updt_index]['priority'] = current_priority, int(new_priority)
            else:
                #This is new priority
                if new_priority:
                    fwd_cgf_data['serverOptions']['serverConfigurationList'][_updt_index]['priority'] = int(new_priority)

            if new_server_ip:
                #update server IP
                fwd_cgf_data['serverOptions']['serverConfigurationList'][_updt_index]['serverIp'] = new_server_ip


            if new_server_port:
                fwd_cgf_data['serverOptions']['serverConfigurationList'][_updt_index]['serverPort'] = int(new_server_port)

            #swap the elements in Servers list 
            fwd_cgf_data['serverOptions']['serverConfigurationList'][_index], fwd_cgf_data['serverOptions']['serverConfigurationList'][_updt_index] = \
                    fwd_cgf_data['serverOptions']['serverConfigurationList'][_updt_index], fwd_cgf_data['serverOptions']['serverConfigurationList'][_index]

            data_json = json.dumps(fwd_cgf_data)
            put_url = ji.get_url(self.req_api_cgf_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(put_url, self.jsessionid, data_json)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def delete_server_from_cgf_service(self, cgf_service_name="TEST", server_ip="1.2.3.4"):
        """
        API used to delete Server IP from CGF service

        URI: PUT /wsg/api/scg/cgfs/<cgf_service_key>

        :param str cgf_service_name: Name of CGF Service
        :param str server_ip: IP Address
        :return: True if Server IP from CGF service deleted else False
        :rtype: boolean

        """

        result = False
        is_entry_found = False
        fwd_cgf_data = {}
        _priority = None
        try:
            url= ji.get_url(self.req_api_cgf, self.scg_mgmt_ip, self.scg_port)
            key, rcv_cgf_data =self._get_key_for_cgf_service(url=url, name=cgf_service_name)
            if rcv_cgf_data["serverOptions"]["serverConfigurationJSONArray"]:
                del rcv_cgf_data["serverOptions"]["serverConfigurationJSONArray"]
            if rcv_cgf_data["columns"]:
                del rcv_cgf_data["columns"]
            if rcv_cgf_data["localBinaryFileOptions"]:
                del rcv_cgf_data["localBinaryFileOptions"]

            fwd_cgf_data = copy.deepcopy(rcv_cgf_data)
            if len(fwd_cgf_data["serverOptions"]["serverConfigurationList"]) > 1:
                for entry in range(0,len(fwd_cgf_data["serverOptions"]["serverConfigurationList"])):
                    if rcv_cgf_data["serverOptions"]["serverConfigurationList"][entry]["serverIp"] == server_ip:
                        del fwd_cgf_data["serverOptions"]["serverConfigurationList"][entry]
                        is_entry_found = True
                        _priority = rcv_cgf_data["serverOptions"]["serverConfigurationList"][entry]["priority"]
                        break
                if is_entry_found == False: 
                    print "server ip %s not found" % server_ip
                    return False
            else:
                print "Not possible to delete %s, CGF service server cant be empty" % server_ip
                return False
            for i in range(_priority-1, len(fwd_cgf_data["serverOptions"]["serverConfigurationList"])):
                fwd_cgf_data["serverOptions"]["serverConfigurationList"][i].update({"priority":i+1})

            data_json = json.dumps(fwd_cgf_data)
            put_url = ji.get_url(self.req_api_cgf_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(put_url, self.jsessionid, data_json)
        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def create_user_def_intf(self, dblade_mac, cluster_name, user_def_intf_ip, user_def_intf_gw, cntrl_plane_vlan):
        """
        API used to create User Defined Interface

        URI: PUT /wsg/api/scg/planes/data?

        :param str dblade_mac: Dblade MAC address
        :param str cluster_name: Cluster Name
        :param str user_def_intf_ip: User Defined Interface IP
        :param str user_def_intf_gw: User Defined Interface gateway IP
        :param str cntrl_plane_vlan: Control plane VLAN
        :return: True if User Defined Interface created else False
        :rtype: boolean

        """

        plane_data_api = "/wsg/api/scg/planes/data?"
        url = ji.get_url(plane_data_api, self.scg_mgmt_ip, self.scg_port)
        plane_data = ji.get_json_data(url,self.jsessionid)
        blade_id = ''
        for value in plane_data["data"]["list"]:
            if value["key"] == dblade_mac:
                blade_id = value["bladeId"]
        api = "/wsg/api/scg/planes/northbound/" + blade_id + "?"
        data = {"key":blade_id,
                "hostName":cluster_name,
                "userNetworkInterfaces":[{"name":"wispr",
                    "ip":user_def_intf_ip,
                    "subnetMask":"255.255.255.0",
                    "gateway":user_def_intf_gw,
                    "vlan":cntrl_plane_vlan,
                    "interfaceType":"br0",
                    "attachedServices":["CP","SP"]}]}
        js_data = json.dumps(data)
        req_url = ji.get_url(api, self.scg_mgmt_ip, self.scg_port)
        result = ji.put_json_data(req_url, self.jsessionid, js_data)

        return result
    
    def create_hotspot_profile(self, hotspot_profile_name="Auto_Hotspot_Profile",
                                   access_type="EXTERNAL",                      # INTERNAL or EXTERNAL
                                   smart_client_mode="enable",                  # enable or none or only
                                   smart_client_info=None,
                                   second_redirect_type="user",
                                   authentication_url=None,
                                   redirect_url=None,
                                   session_time='1440', 
                                   grace_period='60', 
                                   location_name=None,
                                   location_id=None,):
        """
        API used to create Hotspot profile

        URI: POST /wsg/api/scg/hotspotsProfile?

        :param str hotspot_profile_name: Name of Hotspot Profile
        :param str zone_name: Name of the Zone
        :param str access_type: INTERNAL | EXTERNAL
        :param str smart_client_mode: enable | none | only
        :param str smart_client_info: Information about the smart client
        :param str second_redirect_type: start | user
        :param str authentication_url: Logon URL
        :param str redirect_url: Start Page URL
        :param str session_time: Session Timeout [default = 1440]
        :param str grace_period: Grace Period   [default = 60]
        :param str location_name: Name of the location
        :param str location_id: Location ID
        :return: True if Hotspot created else False
        :rtype: boolean
        """       

        result = False
        hotspot_profile = {} 
        try:
            url = ji.get_url(self.req_api_hotspot, self.scg_mgmt_ip, self.scg_port)
            hotspot_profile.update(self.SJT.get_hotspot_template_data())
            hotspot_profile.update({"name": hotspot_profile_name})

            hotspot_profile.update({"sessionTime":int(session_time),
                                    "gracePeriod":int(grace_period)})
            
            hotspot_profile.update({"smartClientMode":smart_client_mode})

            if smart_client_mode == "only":
                hotspot_profile.update({"smartClientInfo":smart_client_info})

            else:
                hotspot_profile.update({"spMode":access_type,
                                        "secondRedirect":second_redirect_type})

                if access_type == "EXTERNAL":
                    hotspot_profile.update({"redirectUrl":authentication_url})
                elif access_type == "INTERNAL":
                    hotspot_profile.update({"redirectUrl":""})

                if second_redirect_type == "start":
                    hotspot_profile.update({"startUrl":redirect_url})
                elif second_redirect_type == "user":
                    hotspot_profile.update({"startUrl":""})
    
            json_data = json.dumps(hotspot_profile)
            result = ji.post_json_data(url, self.jsessionid, json_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def validate_hotspot_profile(self, hotspot_profile_name="Auto_Hotspot_Profile",
                                   access_type=None,
                                   smart_client_mode=None,
                                   smart_client_info=None,
                                   second_redirect_type=None,
                                   authentication_url=None,
                                   redirect_url=None,
                                   session_time=None, grace_period=None, 
                                   location_id=None,
                                   location_name=None,):
        """
        API is used to validate Hotspot Profile
        
        URI: GET /wsg/api/scg/hotspotsProfile? 

        :param str hotspot_profile_name: Name of Hotspot Profile
        :param str account_server_name: Name of Accounting profile
        :param str acct_update_interval: 0 to 1440
        :param str access_type: INTERNAL | EXTERNAL
        :param str smart_client_mode: enable | none | only
        :param str smart_client_info: Information about the smart client
        :param str second_redirect_type: start | user
        :param str authentication_url: Logon URL
        :param str redirect_url: Start Page URL
        :param str session_time: Session Timeout
        :param str grace_period: Grace Period
        :param str location_name: Name of the location
        :param str location_id: Location ID
        :return: True if Hotspot Profile is validated else False
        :rtype: boolean
  
        """

        try:
            url = ji.get_url(self.req_api_hotspot, self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_hotspot(url=url, name=hotspot_profile_name)
            if hotspot_profile_name:
                if rcvd_data["name"] != hotspot_profile_name:
                    self._print_err_validate('validate_hotspot_profile', 'hotspot_profile_name', 'name', hotspot_profile_name,
                            rcvd_data["name"])
                    return False
            if smart_client_mode:
                if rcvd_data["smartClientMode"] != smart_client_mode:
                    self._print_err_validate('validate_hotspot_profile', 'smart_client_mode', 'smartClientMode',smart_client_mode,
                            rcvd_data["smartClientMode"])
                    return False
            if access_type:
                if rcvd_data["spMode"] != access_type:
                    self._print_err_validate('validate_hotspot_profile', 'access_type', 'spMode', access_type, rcvd_data["spMode"])
                    return False
            if smart_client_info:
                if rcvd_data["smartClientInfo"] != smart_client_info:
                    self._print_err_validate('validate_hotspot_profile', 'smart_client_info', 'smartClientInfo', smart_client_info,
                            rcvd_data["smartClientInfo"])
                    return False
            if second_redirect_type:
                if rcvd_data["secondRedirect"] != second_redirect_type:
                    self._print_err_validate('validate_hotspot_profile', 'second_redirect_type', 'secondRedirect', second_redirect_type,
                            rcvd_data["secondRedirect"])
                    return False
            if authentication_url:
                if rcvd_data["redirectUrl"] != authentication_url:
                    self._print_err_validate('validate_hotspot_profile', 'authentication_url', 'redirectUrl', authentication_url,
                            rcvd_data["redirectUrl"])
                    return False
            if redirect_url:
                if rcvd_data["startUrl"] != redirect_url:
                    self._print_err_validate('validate_hotspot_profile', 'redirect_url', 'startUrl', redirect_url,
                            rcvd_data["startUrl"])
                    return False
            if session_time:
                if str(rcvd_data["sessionTime"]) != session_time:
                    self._print_err_validate('validate_hotspot_profile', 'session_time', 'sessionTime', session_time, rcvd_data["sessionTime"])
                    return False
            if grace_period:
                if str(rcvd_data["gracePeriod"]) != grace_period:
                    self._print_err_validate('validate_hotspot_profile', 'grace_period', 'gracePeriod', grace_period, rcvd_data["gracePeriod"])
                    return False
            if location_name:
                if rcvd_data["wisperLocationName"] != location_name:
                    self._print_err_validate('validate_wispr_profile', 'location_name', 'wisperLocationName', location_name,
                            rcvd_data["wisperLocationName"])
                    return False
            if location_id:
                if rcvd_data["wisperLocationId"] != location_id:
                    self._print_err_validate('validate_wispr_profile', 'location_id', 'wisperLocationId',
                            location_id, rcvd_data["wisperLocationId"])
                    return False

            return True
        except Exception, e:
            print traceback.format_exc()
            return False
 
    def _get_key_for_hotspot(self, url=None, name="Auto_Hotspot_Profile"):
        """
        API used to get the key and data of Hotspot

        :param str url: URL
        :param str name: Name of Hotspot profile
        :return: key and data of  Hotspot profile
        :rtype: unicode, dictionary
        
        """
        key, data = None, None
        rcv_data = ji.get_json_data(url, self.jsessionid)
        for i in range(0, len(rcv_data["data"]["list"])):
            if rcv_data["data"]["list"][i]["name"] == name:
                key, data = rcv_data["data"]["list"][i]["key"], rcv_data["data"]["list"][i]
                break

        if not key:
            raise Exception("_get_key_for_hotspot(): Key not found for name: %s" % (name))

        return key, data

            
    def update_hotspot_profile(self, current_profile_name="Auto_Hotspot_Profile",
                                   new_profile_name=None,
                                   new_descripton=None,
                                   smart_client_mode=None,
                                   access_type=None, smart_client_info=None,
                                   second_redirect_type=None, authentication_url=None,
                                   redirect_url=None, session_time=None, grace_period=None,
                                   location_id=None, location_name=None,):
        
        """
        API is used to update Hotspot Profile

        URI: /wsg/api/scg/hotspotsProfile/<hotspot_recvd_keys>

        :param str current_profile_name: Original Name of Hotspot Profile
        :param str new_profile_name: New Name of Hotspot Profile
        :param str new_descripton: New Description of Hotspot Profile
        :param str access_type: INTERNAL | EXTERNAL
        :param str smart_client_mode: enable | none | only
        :param str smart_client_info: Information about the smart client
        :param str second_redirect_type: start | user
        :param str authentication_url: Logon URL
        :param str redirect_url: Start Page URL
        :param str session_time: Session Timeout
        :param str grace_period: Grace Period
        :param str location_name: Name of the Location
        :param str Location id: Location ID
        :return: True if Hotspot created else False
        :rtype: boolean
        """

        result = False
        fwd_hotspot_data = {}
        try:
            url = ji.get_url(self.req_api_hotspot, self.scg_mgmt_ip, self.scg_port)
            key, rcv_hotspot_data = self._get_key_for_hotspot(url=url, name=current_profile_name)
            fwd_hotspot_data.update(self.SJT.get_hotspot_template_data())
            fwd_hotspot_data["name"] = rcv_hotspot_data["name"] if new_profile_name is None else new_profile_name
            fwd_hotspot_data["key"] = rcv_hotspot_data["key"]

            fwd_hotspot_data["sessionTime"] = rcv_hotspot_data["sessionTime"] if session_time is None else int(session_time)
            fwd_hotspot_data["gracePeriod"] = rcv_hotspot_data["gracePeriod"] if grace_period is None else int(grace_period) 
            fwd_hotspot_data["walledGarden"]= rcv_hotspot_data["walledGarden"]
            fwd_hotspot_data["smartClientMode"] = rcv_hotspot_data["smartClientMode"] if smart_client_mode is None else smart_client_mode 

            fwd_hotspot_data['wisperLocationName'] = rcv_hotspot_data['wisperLocationName'] if not location_name else location_name
            fwd_hotspot_data['wisperLocationId'] = rcv_hotspot_data['wisperLocationId'] if not location_id else location_id

            if location_name:
                if location_name == 'Delete':
                    fwd_hotspot_data['wisperLocationName'] = ""
            if location_id:
                if location_id == 'Delete':
                    fwd_hotspot_data['wisperLocationId'] = ""


            if fwd_hotspot_data["smartClientMode"] == "only":
                fwd_hotspot_data["smartClientInfo"] = rcv_hotspot_data["smartClientInfo"] if smart_client_info is None else smart_client_info
            else:
                fwd_hotspot_data["spMode"] = rcv_hotspot_data["spMode"] if access_type is None else access_type
                fwd_hotspot_data["secondRedirect"] = rcv_hotspot_data["secondRedirect"] if second_redirect_type is None else second_redirect_type
                     
                if fwd_hotspot_data["spMode"] == "EXTERNAL":
                    fwd_hotspot_data["redirectUrl"] = rcv_hotspot_data["redirectUrl"] if authentication_url is None else authentication_url
                else:
                    fwd_hotspot_data["redirectUrl"] = ""

                if fwd_hotspot_data["secondRedirect"] == "start":
                    fwd_hotspot_data["startUrl"] = rcv_hotspot_data["startUrl"] if redirect_url is None else redirect_url
                else:
                    fwd_hotspot_data["startUrl"] = "" 

            json_data = json.dumps(fwd_hotspot_data)
            put_url = ji.get_url(self.req_api_hotspot_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(put_url, self.jsessionid, json_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def add_walledgarden_to_hotspot_profile(self, hotspot_profile_name="Auto_Hotspot_Profile", walledgarden="1.2.3.4"):
        """
        API used to add the WalledGarden to Hotspot Profile

        URI: PUT /wsg/api/scg/hotspotsProfile/<hotspot_profile_key>

        :param str hotspot_profile_name: Name of the Hotspot Profile
        :param str walledgarden: ip or iprange 
        :return: True if WalledGarden addedd successfully else False
        :rtype: boolean
        """

        result = False
        fwd_hotspot_data = {}
        try:
            url = ji.get_url(self.req_api_hotspot, self.scg_mgmt_ip, self.scg_port)
            key, rcv_hotspot_data = self._get_key_for_hotspot(url=url, name=hotspot_profile_name)
            fwd_hotspot_data.update(self.SJT.get_hotspot_template_data())
            fwd_hotspot_data["name"] = rcv_hotspot_data["name"] 
            fwd_hotspot_data["key"] = rcv_hotspot_data["key"]

            fwd_hotspot_data["sessionTime"] = rcv_hotspot_data["sessionTime"] 
            fwd_hotspot_data["gracePeriod"] = rcv_hotspot_data["gracePeriod"] 

            rcvd_walledgarden = rcv_hotspot_data["walledGarden"]
            concat = None
            if rcvd_walledgarden == ",":
                concat = str(walledgarden)
            else:
                wall = str(rcvd_walledgarden)
                concat = str(wall) + "," + str(walledgarden)
            fwd_hotspot_data["walledGarden"] = concat
            fwd_hotspot_data["smartClientMode"] = rcv_hotspot_data["smartClientMode"]

            fwd_hotspot_data['wisperLocationName'] = rcv_hotspot_data['wisperLocationName'] 
            fwd_hotspot_data['wisperLocationId'] = rcv_hotspot_data['wisperLocationId']

            fwd_hotspot_data["smartClientInfo"] = rcv_hotspot_data["smartClientInfo"]
            fwd_hotspot_data["spMode"] = rcv_hotspot_data["spMode"] 
            fwd_hotspot_data["secondRedirect"] = rcv_hotspot_data["secondRedirect"]
                     
            fwd_hotspot_data["redirectUrl"] = rcv_hotspot_data["redirectUrl"]
        
            fwd_hotspot_data["startUrl"] = rcv_hotspot_data["startUrl"]
    
            json_data = json.dumps(fwd_hotspot_data)
            put_url = ji.get_url(self.req_api_hotspot_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(put_url, self.jsessionid, json_data)


        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def validate_walledgarden_in_hotspot(self, hotspot_profile_name="Auto_Hotspot_Profile",
                                               walledgarden='1.2.3.4'):
        """
        API used to validate the WalledGarden in Hotspot Profile

        URI: GET /wsg/api/scg/hotspotsProfile?

        :param str hotspot_profile_name: Name of the Hotspot Profile
        :param str walledgarden: ip or iprange
        :return: True if validation success else False
        :rtype: boolean
        """

        try:
            url = ji.get_url(self.req_api_hotspot, self.scg_mgmt_ip, self.scg_port)
            key, rcv_hotspot_data = self._get_key_for_hotspot(url=url, name=hotspot_profile_name)
            
            rcvd_walledgarden = rcv_hotspot_data["walledGarden"]

            if walledgarden:
                if rcvd_walledgarden == ",":
                    print "No items in walled garden list"
                    return False

                elif rcvd_walledgarden:
                    ret_result = walledgarden in rcvd_walledgarden
                    if not ret_result:
                        print "WalledGarden %s not found" % (walledgarden)
                        return False

            return True

        except Exception, e:
            print traceback.format_exc()
            return False


    def update_walledgarden_in_hotspot(self, hotspot_profile_name="Auto_Hotspot_Profile", 
                                             current_walledgarden='1.2.3.4',
                                             new_walledgarden=None):
        """
        API used to update the WalledGarden to Hotspot Profile

        URI: PUT /wsg/api/scg/hotspotsProfile/<hotspot_profile_key>

        :param str hotspot_profile_name: Name of the Hotspot Profile
        :param str current_walledgarden: ip or iprange 
        :param str new_walledgarden: ip or iprange
        :return: True if WalledGarden updated successfully else False
        :rtype: boolean
        """    

        result = False
        fwd_hotspot_data = {}
        try:
            url = ji.get_url(self.req_api_hotspot, self.scg_mgmt_ip, self.scg_port)
            key, rcv_hotspot_data = self._get_key_for_hotspot(url=url, name=hotspot_profile_name)
            fwd_hotspot_data.update(self.SJT.get_hotspot_template_data())
            fwd_hotspot_data["name"] = rcv_hotspot_data["name"]
            fwd_hotspot_data["key"] = rcv_hotspot_data["key"]

            fwd_hotspot_data["sessionTime"] = rcv_hotspot_data["sessionTime"]
            fwd_hotspot_data["gracePeriod"] = rcv_hotspot_data["gracePeriod"]

            rcvd_walledgarden = rcv_hotspot_data["walledGarden"]
            updt_wg = None

            if rcvd_walledgarden == ",":
                print "No items in walled garden"
                return False

            elif rcvd_walledgarden:
                ret_result = False
                ret_result = current_walledgarden in rcvd_walledgarden
                if not ret_result:
                    print "Entry %s not found" % (current_walledgarden)
                    return False

                updt_wg = rcvd_walledgarden.replace(current_walledgarden, new_walledgarden)

            fwd_hotspot_data["walledGarden"] = updt_wg
            fwd_hotspot_data["smartClientMode"] = rcv_hotspot_data["smartClientMode"]
            
            fwd_hotspot_data['wisperLocationName'] = rcv_hotspot_data['wisperLocationName'] 
            fwd_hotspot_data['wisperLocationId'] = rcv_hotspot_data['wisperLocationId']
            
            fwd_hotspot_data["smartClientInfo"] = rcv_hotspot_data["smartClientInfo"]
            fwd_hotspot_data["spMode"] = rcv_hotspot_data["spMode"] 
            fwd_hotspot_data["secondRedirect"] = rcv_hotspot_data["secondRedirect"]
                     
            fwd_hotspot_data["redirectUrl"] = rcv_hotspot_data["redirectUrl"]
            
            fwd_hotspot_data["startUrl"] = rcv_hotspot_data["startUrl"]
            
            json_data = json.dumps(fwd_hotspot_data)
            put_url = ji.get_url(self.req_api_hotspot_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(put_url, self.jsessionid, json_data)


        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def delete_walledgarden_entry_from_hospot_profile(self, hotspot_profile_name='Auto_Hotspot',
                                                            walledgarden='1.2.3.4'):
        """
        API used to delete the WalledGarden in Hotspot Profile

        URI: PUT /wsg/api/scg/hotspotsProfile/<hotspot_profile_key>

        :param str hotspot_profile_name: Name of the Hotspot Profile
        :param str walledgarden: ip or iprange 
        :return: True if WalledGarden deleted successfully else False
        :rtype: boolean
        """    

        result = False
        fwd_hotspot_data = {}
        try:
            url = ji.get_url(self.req_api_hotspot, self.scg_mgmt_ip, self.scg_port)
            key, rcv_hotspot_data = self._get_key_for_hotspot(url=url, name=hotspot_profile_name)
            fwd_hotspot_data.update(self.SJT.get_hotspot_template_data())
            fwd_hotspot_data["name"] = rcv_hotspot_data["name"]
            fwd_hotspot_data["key"] = rcv_hotspot_data["key"]

            fwd_hotspot_data["sessionTime"] = rcv_hotspot_data["sessionTime"]
            fwd_hotspot_data["gracePeriod"] = rcv_hotspot_data["gracePeriod"]

            rcvd_walledgarden = rcv_hotspot_data["walledGarden"]
            del_wg = None
            
            if rcvd_walledgarden == ",":
                print "No items in walled garden"
                return False

            elif rcvd_walledgarden:
                ret_result = False
                _walledgarden = None
                ret_result = walledgarden in rcvd_walledgarden
                if not ret_result:
                    print "entry %s not found"%(walledgarden)
                    return False

                _split_str= rcvd_walledgarden.split(',')

                if len(_split_str) == 1:
                    del_wg = ","
                elif walledgarden == _split_str[0]:
                    _walledgarden = walledgarden+','
                    del_wg = rcvd_walledgarden.replace(_walledgarden,'')
                else:
                    _walledgarden = ','+walledgarden
                    del_wg = rcvd_walledgarden.replace(_walledgarden,'')


            fwd_hotspot_data["walledGarden"] = del_wg
            fwd_hotspot_data["smartClientMode"] = rcv_hotspot_data["smartClientMode"]
            
            fwd_hotspot_data['wisperLocationName'] = rcv_hotspot_data['wisperLocationName'] 
            fwd_hotspot_data['wisperLocationId'] = rcv_hotspot_data['wisperLocationId']
            
            fwd_hotspot_data["smartClientInfo"] = rcv_hotspot_data["smartClientInfo"]
            fwd_hotspot_data["spMode"] = rcv_hotspot_data["spMode"] 
            fwd_hotspot_data["secondRedirect"] = rcv_hotspot_data["secondRedirect"]
                     
            fwd_hotspot_data["redirectUrl"] = rcv_hotspot_data["redirectUrl"]
            
            fwd_hotspot_data["startUrl"] = rcv_hotspot_data["startUrl"]
            
            json_data = json.dumps(fwd_hotspot_data)
            put_url = ji.get_url(self.req_api_hotspot_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(put_url, self.jsessionid, json_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result
         
 
    def delete_hotspot_profile(self, hotspot_name="Auto_Hotspot_Profile"):
        """
        API used to delete Hotspot profile

        URI: DELETE /wsg/api/scg/hotspotsProfile/<hotspot_profile_key>

        :param str hotspot_name: Name of Hotspot profile
        :return: True if Hotspot Profile deleted else False
        :rtype: boolean
        """

        result = False
        try:
            url = ji.get_url(self.req_api_hotspot, self.scg_mgmt_ip, self.scg_port)
            key, data = self._get_key_for_hotspot(url=url, name=hotspot_name)
            url_del = ji.get_url(self.req_api_hotspot_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.delete_scg_data(url_del, self.jsessionid, None)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def _traffic_network(self, name="Traffic_Network"):
        """
        API used to get the Traffic Network

        URI: GET /wsg/api/scg/serviceProfiles/forwarding/service?

        :param str name: Name of the Traffic Network
        :return: key of the Traffic Network
        :rtype: unicode

        """                        

        key = None
        url = ji.get_url(self.req_api_networktraffic, self.scg_mgmt_ip, self.scg_port)
        rcv_data = ji.get_json_data(url, self.jsessionid)
        for i in range(0, len(rcv_data["data"]["list"])):
            if rcv_data["data"]["list"][i]["name"] == name:
                key = rcv_data["data"]["list"][i]["key"]
                break
        if not key:
            raise Exception("_traffic_network():  Key not found for the name %s" %(name))
        return key


    def _get_acct_profile_id(self, name, url):
        """
        API used to Account Profile id
        
        :param str url: URL
        :param str name: Name of the accounting profile
        :return: key of accounting profile
        :rtype: unicode

        """
        key = None
        rcv_data = ji.get_json_data(url, self.jsessionid)
        for i in range(0, len(rcv_data["data"]["list"])):
            if rcv_data["data"]["list"][i]["name"] == name:
                key = rcv_data["data"]["list"][i]["key"]
                break
        if not key:
            raise Exception("_get_acct_profile_id(): Key not found for the name %s" %(name))
        return key
 
    def _get_forwarding_profile_id(self, name, url):
        """
        API used to Forwarding Profile id
        
        :param str url: URL
        :param str name: Name of the Forwarding Profile
        :return: key of Forwarding Profile
        :rtype: unicode

        """

        key = None
        rcv_data = ji.get_json_data(url, self.jsessionid)
        for i in range(0, len(rcv_data["data"]["list"])):
            if rcv_data["data"]["list"][i]["serviceName"] == name:
                key = rcv_data["data"]["list"][i]["id"]
                break
        if not key:
            raise Exception("_get_forwarding_profile_id(): Key not found for the name %s" %(name))
        return key

    def _get_hotspot_profile(self, name):
        """
        API used to get the Hotspot key
        
        URI: GET /wsg/api/scg/hotspotsProfile? 
        
        :param str name: Name of Hotspot profile
        :return: key of Hotspot profile
        :rtype: unicode

        """
        key = None
        
        url = ji.get_url(self.req_api_hotspot, self.scg_mgmt_ip, self.scg_port)
        rcv_data = ji.get_json_data(url, self.jsessionid)
        for i in range(0, len(rcv_data["data"]["list"])):
            if rcv_data["data"]["list"][i]["name"] == name:
                key = rcv_data["data"]["list"][i]["key"]
                break
        if not key:
            raise Exception("get_hotspot_profile(): Key not found for name: %s" % (name))
        return key


    def create_thirdparty_apzone(self, zone_name="Auto_ThrdPrty_Zone", 
                                       domain_label="Administration Domain", 
                                       access_network="QinQL2", 
                                       core_network="Bridge",
                                       auth_service_type="x8021", 
                                       network_traffic_name="SCG Factory Default",
                                       acct_name="Auto_acct_profile", 
                                       auth_name=None, 
                                       forwarding_profile_name=None,
                                       hotspot_name=None, 
                                       acct_update_interval=None,
                                       vlan_map_type="StripSPreserveC", 
                                       default_shared_secret=None,
                                       shared_secret=None, 
                                       ip_type=None, 
                                       ap_ip_type=None, 
                                       ip_address=None, 
                                       ap_ip_address=None,
                                       core_add_fixed_vlan=None,    #core_add_fixed_valn="" 
                                       start_ip=None, 
                                       end_ip=None, 
                                       subnet=None, 
                                       network=None,    #network=""
                                       ap_start_ip=None, 
                                       ap_end_ip=None, 
                                       ap_subnet=None, 
                                       ap_network=None,
                                       acct_ttgsession_enable=False,
                                       core_qinq_enable=False,
                                       start_cvlan="10", end_cvlan="11", 
                                       start_svaln="20", end_svlan="21"):
        """
        API used to create Third Party APZone

        URI: POST /wsg/api/scg/zones/thirdparty?

        :param str zone_name: Name of Third Party APZone
        :param str domain_label: Name of Domain
        :param str access_network: QinQL2 | L2oGRE
        :param str core_network: TTGPDG | Bridge
        :param str auth_service_type: Open | x8021 | WISPr
        :param str network_traffic_name: Network Traffic Profile
        :param str acct_name: Accounting profile name
        :param str auth_name: Authentication Profile name
        :param str forwarding_profile_name: Name of Forwarding profile
        :param str hotspot_name: Name of Hotspot profile
        :param str acct_update_interval: time to send account interim update 
        :param str vlan_map_type: MapSPreserveC | StripAll | StripSPreserveC | StripAllAddFixedSingle
        :param str default_shared_secret: Radius Client option Default Share Secret
        :param str shared_secret: Shared Secret
        :param str ip_type: SingleIP | IPRange | Subnet
        :param str ip_address: IP Address
        :param str core_add_fixed_valn: Core add fixed VLAN
        :param str start_ip: start IP
        :param str end_ip: end IP
        :param str subnet: subnet
        :param str network: network
        :param str ap_ip_type: SingleIP | IPRange | Subnet
        :param str ap_ip: IP Address
        :param str ap_start_ip: start IP
        :param str ap_end_ip: end IP
        :param str ap_subnet: subnet
        :param str ap_network: network
        :param boolean acct_ttgsession_enable: True | False
        :param boolean core_qinq_enable: True | False
        :param str start_cvlan: Start CVLAN
        :param str end_cvlan: End CVLAN
        :param str start_svaln: Start SVLAN
        :param str end_svlan: End SVLAN
        :return: True if Third Party APZone created else False
        :rtype: boolean
        """

        result = False
        thirdparty_data={}
        try:
            url = ji.get_url(self.req_api_thirdparty_apzone, self.scg_mgmt_ip, self.scg_port)
            acct_url = ji.get_url(self.req_api_acct_profile, self.scg_mgmt_ip, self.scg_port)
            auth_url = ji.get_url(self.req_api_auth_profile, self.scg_mgmt_ip, self.scg_port)
            radius_url = ji.get_url(self.req_api_radius_id%'RADIUS', self.scg_mgmt_ip, self.scg_port)
            radius_acct_url = ji.get_url(self.req_api_radius_id%'RADIUSAcct', self.scg_mgmt_ip, self.scg_port)

            forwarding_profile_url = ji.get_url(self.req_api_forwarding_service, self.scg_mgmt_ip, self.scg_port)

            thirdparty_data.update(self.SJT.get_thirdparty_apzone())
            thirdparty_data.update({"zoneName":zone_name})
            thirdparty_data.update({"accessNetworkType":access_network,
                                    "domainUUID":self.get_domain_uuid(domain_label=domain_label),
                                    "networkTrafficPackageId":self._traffic_network(name=network_traffic_name)})
            

            if access_network == "QinQL2":
                thirdparty_data.update({"coreNetworkType":core_network})
                thirdparty_data.update({"coreQinQEnabled":core_qinq_enable,
                                        "vlanMappingType": vlan_map_type})
                if core_network == "Bridge":
                    acct_url = ji.get_url(self.req_api_acct_profile, self.scg_mgmt_ip, self.scg_port)
                    thirdparty_data.update({"authType":auth_service_type})

                    if auth_service_type == "Open":
                        thirdparty_data.update({"vlanMappingType":vlan_map_type})                        
                        if acct_name == "Disable":
                            thirdparty_data.update({"acctServiceProfileId":""})
                        else:
                            thirdparty_data.update({"acctServiceProfileId":self._get_acct_profile_id(acct_name, acct_url)})

                    elif auth_service_type == "WISPr":
                        thirdparty_data.update({"hotspotServiceProfileId":self._get_hotspot_profile(hotspot_name)})
                        thirdparty_data.update({"vlanMappingType": vlan_map_type})
                        thirdparty_data.update({"aaaId":self._get_acct_profile_id(auth_name, radius_url)})
                        thirdparty_data.update({"acctId":self._get_acct_profile_id(acct_name, radius_acct_url)})
                        if acct_name != 'Disable':
                            thirdparty_data.update({"acctUpdateInterval":int(acct_update_interval)})

                elif core_network == "TTGPDG":
                    thirdparty_data.update({"authType":"x8021",
                                            "forwardingServiceProfileId":self._get_forwarding_profile_id(forwarding_profile_name,forwarding_profile_url),
                                            "authServiceProfileId":self._get_acct_profile_id(auth_name, auth_url)})
                    if acct_name == "Disable":
                        thirdparty_data.update({"acctServiceProfileId":""})
                    else:
                        thirdparty_data.update({"acctServiceProfileId":self._get_acct_profile_id(acct_name,acct_url)})

                    thirdparty_data.update({"vlanMappingType": vlan_map_type})

                if (core_network == "Bridge" and acct_name != "Disable" and auth_service_type == "Open" or auth_service_type == "WISPr") \
                        or core_network == "TTGPDG":
                    
                    thirdparty_data.update({"defaultShareSecret":default_shared_secret,
                                            "ipType":ip_type,
                                            "ip":ip_address,
                                            "startIP":start_ip,
                                            "endIP":end_ip,
                                            "subnet":subnet,
                                            "network":network,
                                            "secret":shared_secret,
                                            "acctTTGSessionEnabled":acct_ttgsession_enable})

                    thirdparty_data["clientAddressList"] = []
                    thirdparty_data["clientAddressList"].append({"ipType":ip_type,
                                                                    "startIP":start_ip,
                                                                    "endIP":end_ip,
                                                                    "network":network,
                                                                    "subnet":subnet,
                                                                    "ip":ip_address,
                                                                    "secret":shared_secret})
                if core_qinq_enable == True:
                    thirdparty_data.update({"vlanMappingType":vlan_map_type})
                    thirdparty_data["vlanMappingList"] = []
                    thirdparty_data["vlanMappingList"].append({"accessStart":start_svaln,
                                                               "accessEnd":end_svlan,
                                                               "coreStart":start_svaln,
                                                               "coreEnd":end_svlan})
                thirdparty_data.update({"qinqVLANTagList":[]})
                thirdparty_data["qinqVLANTagList"].append({"startCVlan":start_cvlan,
                                                              "endCVlan":end_cvlan,
                                                              "startSVlan":start_svaln,
                                                              "endSVlan":end_svlan})


            elif access_network == "L2oGRE":
                thirdparty_data.update({"coreNetworkType":core_network})
                thirdparty_data.update({"coreQinQEnabled":core_qinq_enable,
                                        "vlanMappingType": vlan_map_type})
                acct_url = ji.get_url(self.req_api_acct_profile, self.scg_mgmt_ip, self.scg_port)
                thirdparty_data.update({"authType":auth_service_type})

                if vlan_map_type == "StripAllAddFixedSingle":
                    thirdparty_data.update({"coreAddFixedVlan":int(core_add_fixed_vlan)})

                if auth_service_type == "Open":
                    if acct_name == "Disable":
                        thirdparty_data.update({"acctServiceProfileId":""})
                    else:
                        thirdparty_data.update({"acctServiceProfileId":self._get_acct_profile_id(acct_name, acct_url)})

                elif auth_service_type == "WISPr":
                    radius_uri = ji.get_url(self.req_api_radius_id%'RADIUSAcct', self.scg_mgmt_ip, self.scg_port)
                    if acct_name == "Disable":
                        thirdparty_data.update({"acctId":""})
                    else:
                        thirdparty_data.update({"acctId":self._get_acct_profile_id(acct_name, radius_uri)})
                        thirdparty_data.update({"acctUpdateInterval":int(acct_update_interval)})
                    if auth_name == "Always Accept":
                        thirdparty_data.update({"aaaId":"22222222-2222-2222-2222-222222222222"})

                    thirdparty_data.update({"hotspotServiceProfileId":self._get_hotspot_profile(hotspot_name)})

                elif auth_service_type == "x8021":
                    if acct_name == "Disable":
                        thirdparty_data.update({"acctServiceProfileId":""})
                    else:
                        thirdparty_data.update({"acctServiceProfileId":self._get_acct_profile_id(acct_name, acct_url)})

                    thirdparty_data.update({"authServiceProfileId":self._get_acct_profile_id(auth_name, auth_url)})

                if auth_service_type == "x8021" or (auth_service_type == "Open" and acct_name != "Disable") or \
                        (auth_service_type == "WISPr" and acct_name != "Disable") :
                    thirdparty_data.update({"clientAddressList":[]})
                    thirdparty_data["clientAddressList"].append({"ipType":ip_type,
                                                                    "startIP":start_ip,
                                                                    "endIP":end_ip,
                                                                    "network":network,
                                                                    "subnet":subnet,
                                                                    "ip":ip_address,
                                                                    "secret":shared_secret})

                thirdparty_data.update({"accessNetworkSourceIPList":[]})
                thirdparty_data.update({"defaultShareSecret":default_shared_secret,
                                            "ipType":ap_ip_type,
                                            "ip":ap_ip_address,
                                            "startIP":ap_start_ip,
                                            "endIP":ap_end_ip,
                                            "subnet":ap_subnet,
                                            "network":ap_network,
                                            "secret":shared_secret if not ap_ip_type else "",
                                            "acctTTGSessionEnabled":acct_ttgsession_enable})

                thirdparty_data["accessNetworkSourceIPList"].append({"ipType":ap_ip_type,
                                                                    "startIP":ap_start_ip,
                                                                    "endIP":ap_end_ip,
                                                                    "network":ap_network,
                                                                    "subnet":ap_subnet,
                                                                    "ip":ap_ip_address,
                                                                    "secret":""})
            
                
            json_data = json.dumps(thirdparty_data)
            result = ji.post_json_data(url, self.jsessionid, json_data)
            
        except Exception, e:
            print traceback.format_exc()
            return False

        return result 

    def validate_third_party_apzone(self, zone_name="Auto_ThrdPrty_Zone", domain_label='Administration Domain',
                                       access_network=None, core_network=None,
                                       auth_service_type=None, network_traffic_name=None,
                                       acct_name=None, auth_name=None, forwarding_profile_name=None,
                                       hotspot_name=None, acct_update_interval=None, 
                                       vlan_map_type=None, default_shared_secret=None,
                                       shared_secret=None, ip_type=None, ip_address=None,
                                       ap_ip_type=None, ap_ip_address=None, ap_start_ip=None, ap_end_ip=None,
                                       ap_subnet=None, ap_network=None,
                                       start_ip=None, end_ip=None, subnet=None, network=None,
                                       core_add_fixed_vlan=None,
                                       acct_ttgsession_enable=False, core_qinq_enable=False,
                                       start_cvlan=None, end_cvlan=None, start_svaln=None, end_svlan=None):
        """
        API is used to validate Third Party AP Zone

        URI: GET /wsg/api/scg/zones/thirdparty/byDomain/<domain_uuid>
        
        :param str zone_name: Name of Third Party APZone
        :param str domain_label: Name of Domain
        :param str access_network: QinQL2 | L2oGRE
        :param str core_network: TTGPDG | Bridge
        :param str auth_service_type: Open | x8021 | WISPr
        :param str network_traffic_name: Network Traffic Profile
        :param str acct_name: Accounting profile name
        :param str auth_name: Authentication Profile name
        :param str forwarding_profile_name: Name of Forwarding profile
        :param str hotspot_name: Name of Hotspot profile
        :param str acct_update_interval: interval of time to send accounting interim 
        :param str vlan_map_type: MapSPreserveC | StripAll | StripSPreserveC | StripAllAddFixedSingle
        :param str default_shared_secret: Radius Client option Default Share Secret
        :param str shared_secret: Shared Secret
        :param str ip_type: SingleIP | IPRange | Subnet
        :param str ip_address: IP Address
        :param str core_add_fixed_valn: Core add fixed VLAN
        :param str start_ip: start IP
        :param str end_ip: end IP
        :param str subnet: subnet
        :param str network: network
        :param boolean acct_ttgsession_enable: True | False
        :param boolean core_qinq_enable: True | False
        :param str start_cvlan: Start CVLAN
        :param str end_cvlan: End CVLAN
        :param str start_svaln: Start SVLAN
        :param str end_svlan: End SVLAN
        :return: True if Third Party APZone is validated else False
        :rtype: boolean

        """

        try:
            url = ji.get_url(self.req_api_thirdparty_apzone_updt_del1%self.get_domain_uuid(domain_label=domain_label), self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_thirdparty_apzone(url, zone_name)
            acct_url = ji.get_url(self.req_api_acct_profile, self.scg_mgmt_ip, self.scg_port)
            auth_url = ji.get_url(self.req_api_auth_profile, self.scg_mgmt_ip, self.scg_port)
            radius_url = ji.get_url(self.req_api_radius_id%'RADIUS', self.scg_mgmt_ip, self.scg_port)
            radius_acct_url = ji.get_url(self.req_api_radius_id%'RADIUSAcct', self.scg_mgmt_ip, self.scg_port)

            forwarding_profile_url = ji.get_url(self.req_api_forwarding_service, self.scg_mgmt_ip, self.scg_port)

            if zone_name:
                if zone_name != rcvd_data["zoneName"]:
                    self._print_err_validate('validate_third_party_zone', 'zone_name', 'name', zone_name, rcvd_data["name"])
                    return False
            if access_network:
                if access_network != rcvd_data["accessNetworkType"]:
                    self._print_err_validate('validate_third_party_zone', 'access_network', 'accessNetworkType', 
                            access_network, rcvd_data["accessNetworkType"])
                    return False
            if core_network:
                if core_network != rcvd_data["coreNetworkType"]:
                    self._print_err_validate('validate_third_party_zone', 'core_network', 'coreNetworkType',
                            core_network, rcvd_data["coreNetworkType"])
                    return False
            if auth_service_type:
                if auth_service_type != rcvd_data["authType"]:
                    self._print_err_validate('validate_third_party_zone', 'auth_service_type', 'authType', auth_service_type,
                            rcvd_data["authType"])
                    return False
            if network_traffic_name:
                network_traffic_id = None
                network_traffic_id = self._traffic_network(name=network_traffic_name)
                if network_traffic_id != rcvd_data["networkTrafficPackageId"]:
                    self._print_err_validate('validate_third_party_zone', 'network_traffic_id', 'networkTrafficPackageId', 
                            network_traffic_id, rcvd_data["networkTrafficPackageId"])
                    return False
            if acct_name:
                acct_id = None
                if acct_name == "Disable":
                    acct_id = ""
                else:
                    acct_id = self._get_acct_profile_id(acct_name, acct_url) 

                if acct_id != rcvd_data["acctServiceProfileId"]:
                    self._print_err_validate('validate_third_party_zone', 'acct_id', 'acctServiceProfileId',  acct_id,
                            rcvd_data["acctServiceProfileId"])
                    return False

            if acct_update_interval:
                if int(acct_update_interval) != rcvd_data['acctUpdateInterval']:
                    self._print_err_validate('validate_third_party_zone', 'acct_update_interval', 'acctUpdateInterval',
                            acct_update_interval, rcvd_data['acctUpdateInterval'])
                    return False

            if access_network and access_network == "QinQL2" and core_network and core_network == "TTGPDG":
                if auth_name:
                    auth_id = None
                    auth_id = self._get_acct_profile_id(auth_name,auth_url)
                    if auth_id != rcvd_data["authServiceProfileId"]:
                        self._print_err_validate('validate_third_party_zone', 'auth_id', 'authServiceProfileId', auth_id,
                                rcvd_data["authServiceProfileId"])
                        return False
                if forwarding_profile_name:
                    forwarding_profile_id = None
                    forwarding_profile_id = self._get_forwarding_profile_id(forwarding_profile_name,forwarding_profile_url)
                    if forwarding_profile_id != rcvd_data["forwardingServiceProfileId"]:
                        self._print_err_validate('validate_third_party_zone', 'forwarding_profile_id', 'forwardingServiceProfileId',
                                forwarding_profile_id, rcvd_data["forwardingServiceProfileId"])
                        return False
            if vlan_map_type:
                if vlan_map_type != rcvd_data["vlanMappingType"]:
                    self._print_err_validate('validate_third_party_zone', 'vlan_map_type', 'vlanMappingType',
                            vlan_map_type, rcvd_data["vlanMappingType"])
                    return False
            if default_shared_secret:
                if default_shared_secret != rcvd_data["defaultShareSecret"]:
                    self._print_err_validate('validate_third_party_zone', 'default_shared_secret', 'defaultShareSecret',
                            default_shared_secret, rcvd_data["defaultShareSecret"])
                    return False

            is_entry_found = False

            exp_result = (True if ip_type else False, True if ip_address else False, True if start_ip else False,
                    True if end_ip else False, True if network else False, True if subnet else False, True if shared_secret else False)
            actual_result = None
            if rcvd_data["clientAddressList"]:
                for i in range(0, len(rcvd_data["clientAddressList"])):
                    is_ip_type = False
                    is_ip_address = False
                    is_start_ip = False
                    is_end_ip = False
                    is_network = False
                    is_subnet = False
                    is_shared_secret = False

                    if ip_type == str(rcvd_data["clientAddressList"][i]["ipType"]):
                        is_ip_type = True
                    if ip_address == str(rcvd_data["clientAddressList"][i]["ip"]):
                        is_ip_address = True
                    if start_ip == str(rcvd_data["clientAddressList"][i]["startIP"]):
                        is_start_ip = True
                    if end_ip == str(rcvd_data["clientAddressList"][i]["endIP"]):
                        is_end_ip = True
                    if network == str(rcvd_data["clientAddressList"][i]["network"]):
                        is_network = True
                    if subnet == str(rcvd_data["clientAddressList"][i]["subnet"]):
                        is_subnet = True
                    if shared_secret == str(rcvd_data["clientAddressList"][i]["secret"]):
                        is_shared_secret = True
                    actual_result = (is_ip_type, is_ip_address, is_start_ip, is_end_ip, is_network, is_subnet, is_shared_secret)
                    if exp_result == actual_result:
                        is_entry_found = True
                        break

                if is_entry_found == False:
                    self._print_err_validate('validate_third_party_zone', 'Client Address List : actual_result', 'exp_result', actual_result, 
                            exp_result)
                    return False

            is_aplist_found = False
            expected_result = (True if ap_ip_type else False, True if ap_ip_address else False, True if ap_start_ip else False,
                                True if ap_end_ip else False, True if ap_network else False, True if ap_subnet else False)
            act_result = ()
            if rcvd_data["accessNetworkSourceIPList"]:
                for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                    is_ip_type = False
                    is_ip_address = False
                    is_start_ip = False
                    is_end_ip = False
                    is_network = False
                    is_subnet = False

                    if ap_ip_type == str(rcvd_data["accessNetworkSourceIPList"][i]["ipType"]):
                        is_ip_type = True
                    if ap_ip_address == str(rcvd_data["accessNetworkSourceIPList"][i]["ip"]):
                        is_ip_address = True
                    if ap_start_ip == str(rcvd_data["accessNetworkSourceIPList"][i]["startIP"]):
                        is_start_ip = True
                    if ap_end_ip == str(rcvd_data["accessNetworkSourceIPList"][i]["endIP"]):
                        is_end_ip = True
                    if ap_network == str(rcvd_data["accessNetworkSourceIPList"][i]["network"]):
                        is_network = True
                    if ap_subnet == str(rcvd_data["accessNetworkSourceIPList"][i]["subnet"]):
                        is_subnet = True

                    act_result = (is_ip_type, is_ip_address, is_start_ip, is_end_ip, is_network, is_subnet)


                    if expected_result == act_result:
                        is_aplist_found = True
                        break

                if is_aplist_found == False:
                    self._print_err_validate('validate_third_party_zone', 'AP list : actual_result', 'exp_result', act_result, expected_result)
                    return False

            if core_add_fixed_vlan:
                if core_add_fixed_vlan != str(rcvd_data["coreAddFixedVlan"]):
                    self._print_err_validate('validate_third_party_zone', 'core_add_fixed_valn', 'coreAddFixedVlan',
                            core_add_fixed_vlan, rcvd_data["coreAddFixedVlan"])
                    return False
            if acct_ttgsession_enable != rcvd_data["acctTTGSessionEnabled"]:
                self._print_err_validate('validate_third_party_zone', 'acct_ttgsession_enable', 'acctTTGSessionEnabled',
                        acct_ttgsession_enable, rcvd_data["acctTTGSessionEnabled"])
                return False
            if core_qinq_enable != rcvd_data["coreQinQEnabled"]:
                self._print_err_validate('validate_third_party_zone', 'core_qinq_enable', 'coreQinQEnabled',
                        core_qinq_enable, rcvd_data["coreQinQEnabled"])
                return False

            is_valn_entry_found = False
            expect_result = (True if start_cvlan else False, True if end_cvlan else False, True if start_svaln else False, True if end_svlan else False)
            actual_res = None
            if not rcvd_data["qinqVLANTagList"] and (start_cvlan or end_cvlan or start_svaln or end_svlan):
                print "validate_third_party_zone: QinQVLANTagList- No items recieved"
                return False

            elif rcvd_data["qinqVLANTagList"]:
                for i in range(0, len(rcvd_data["qinqVLANTagList"])):
                    is_start_cvlan = False
                    is_end_cvlan = False
                    is_start_svaln = False
                    is_end_svlan = False

                    if start_cvlan == str(rcvd_data["qinqVLANTagList"][i]["startCVlan"]):
                        is_start_cvlan = True
                    if end_cvlan == str(rcvd_data["qinqVLANTagList"][i]["endCVlan"]):
                        is_end_cvlan = True
                    if start_svaln == str(rcvd_data["qinqVLANTagList"][i]["startSVlan"]):
                        is_start_svaln = True
                    if end_svlan == str(rcvd_data["qinqVLANTagList"][i]["endSVlan"]):
                        is_end_svlan = True

                    actual_res = (is_start_cvlan, is_end_cvlan, is_start_svaln, is_end_svlan)
                    if expect_result == actual_res:
                        is_valn_entry_found = True
                        break

                if is_valn_entry_found == False:
                    self._print_err_validate('validate_third_party_zone', 'actual_res', 'expect_result', actual_res, expect_result)
                    return False
            
            return True
        except Exception, e:
            print traceback.format_exc()
            return False

    def add_radius_client_ip_to_third_party_apzone(self, zone_name="Auto_ThrdPrty_Zone", domain_label='Administration Domain',
                                        ip_type="SingleIP", 
                                        ip_addr="1.2.3.4", 
                                        start_ip="", 
                                        end_ip="", 
                                        network="", 
                                        subnet="", 
                                        secret="ruckus1!"):
        """       
        Adds Radius Client ip address to third party apzone

        URI: PUT /wsg/api/scg/zones/thirdparty/<thirdparty_apzonbe_key>

        :param str zone_name: Name of the third party ap zone
        :param str ip_type: SingleIP | IPRange | Subnet
        :param str ip_addr: ip address to be added
        :param str start_ip: if ip_type is IPRange then pass the starting ip address 
        :param str end_ip: if ip_type is IPRange then pass the ending ip address
        :param str network: if ip_type is Subnet then pass ip address of the network
        :param str subnet: if ip_type is Subnet then pass ip address of subnet
        :param str secret: secret key 
        :return: True if Radius Client ip added to third party apzone else False
        :rtype: boolean
        """

        result = False
        thirdparty_data = {}
        try:
            url = ji.get_url(self.req_api_thirdparty_apzone_updt_del1%self.get_domain_uuid(domain_label=domain_label), self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_thirdparty_apzone(url, zone_name)
            vlan_mapping_type = None
            vlan_mapping_type = rcvd_data["vlanMappingType"]
            thirdparty_data["key"] = rcvd_data["key"]
            thirdparty_data["zoneIntId"] = str(rcvd_data["zoneIntId"])
            thirdparty_data["zoneName"] = rcvd_data["zoneName"]
            thirdparty_data["accessNetworkType"] = rcvd_data["accessNetworkType"]
            thirdparty_data["networkTrafficPackageId"] = rcvd_data["networkTrafficPackageId"]
            thirdparty_data["description"] = rcvd_data["description"]
            thirdparty_data["coreNetworkType"] = rcvd_data["coreNetworkType"]
            thirdparty_data["authType"] = rcvd_data["authType"]

            if rcvd_data["authServiceProfileId"]:
                thirdparty_data["authServiceProfileId"] = rcvd_data["authServiceProfileId"]

            thirdparty_data["acctServiceProfileId"] = rcvd_data["acctServiceProfileId"]
            thirdparty_data["subscriberPackageId"] = rcvd_data["subscriberPackageId"]

            if rcvd_data["forwardingServiceProfileId"]:
                thirdparty_data["forwardingServiceProfileId"] = rcvd_data["forwardingServiceProfileId"]

            thirdparty_data["acctUpdateInterval"] = rcvd_data["acctUpdateInterval"]
            thirdparty_data["coreQinQEnabled"] = rcvd_data["coreQinQEnabled"]
            thirdparty_data["vlanMappingType"] = rcvd_data["vlanMappingType"]
            thirdparty_data["coreAddFixedVlan"] = rcvd_data["coreAddFixedVlan"]
            thirdparty_data["coreAddFixedSVlan"] = rcvd_data["coreAddFixedSVlan"]
            thirdparty_data["defaultShareSecret"] = rcvd_data["defaultShareSecret"]
            thirdparty_data["clientAddressList"] = []
            if rcvd_data["clientAddressList"]:
                for i in range(0, len(rcvd_data["clientAddressList"])):
                    thirdparty_data["clientAddressList"].append({"ip":rcvd_data["clientAddressList"][i]["ip"],
                                                                "startIP":rcvd_data["clientAddressList"][i]["startIP"],
                                                                "endIP":rcvd_data["clientAddressList"][i]["endIP"],
                                                                "subnet":rcvd_data["clientAddressList"][i]["subnet"],
                                                                "network":rcvd_data["clientAddressList"][i]["network"],
                                                                "ipType":rcvd_data["clientAddressList"][i]["ipType"],
                                                                "secret":rcvd_data["clientAddressList"][i]["secret"]})
            thirdparty_data["accessNetworkSourceIPList"] = []
            if rcvd_data["accessNetworkSourceIPList"]:
                for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                    thirdparty_data["accessNetworkSourceIPList"].append({"ip":rcvd_data["accessNetworkSourceIPList"][i]["ip"],
                                                                     "startIP":rcvd_data["accessNetworkSourceIPList"][i]["startIP"],
                                                                     "endIP":rcvd_data["accessNetworkSourceIPList"][i]["endIP"],
                                                                     "subnet":rcvd_data["accessNetworkSourceIPList"][i]["subnet"],
                                                                     "network":rcvd_data["accessNetworkSourceIPList"][i]["network"],
                                                                     "ipType":rcvd_data["accessNetworkSourceIPList"][i]["ipType"],
                                                                     "secret":""})


            thirdparty_data.update({"ipType":ip_type})
            _ip_addr_updated = []
            _start_ip_updated = []
            _end_ip_updated = []
            _subnet_updated = []
            _network_updated = []

            if ip_type == "SingleIP":
                thirdparty_data.update({"ip":ip_addr,
                                       "ipType":ip_type,
                                       "secret":secret})

                for i in range(0, len(rcvd_data["clientAddressList"])):
                    _start_ip_updated.append(rcvd_data["clientAddressList"][i]["startIP"])
                    _end_ip_updated.append(rcvd_data["clientAddressList"][i]["endIP"])
                    _subnet_updated.append(rcvd_data["clientAddressList"][i]["subnet"])
                    _network_updated.append(rcvd_data["clientAddressList"][i]["network"])

                thirdparty_data.update({"startIP":_start_ip_updated,
                                        "endIP":_end_ip_updated,
                                        "subnet":_subnet_updated,
                                        "network":_network_updated})
            elif ip_type == "IPrange":
                thirdparty_data.update({"ipType":ip_type,
                                        "startIP":start_ip,
                                        "endIP":end_ip,
                                        "secret":secret})
                for i in range(0, len(rcvd_data["clientAddressList"])):
                    _ip_addr_updated.append(rcvd_data["clientAddressList"][i]["ip"])
                    _subnet_updated.append(rcvd_data["clientAddressList"][i]["subnet"])
                    _network_updated.append(rcvd_data["clientAddressList"][i]["network"])
                thirdparty_data.update({"ip":_ip_addr_updated,
                                        "subnet":_subnet_updated,
                                        "network":_network_updated})

            elif ip_type == "Subnet":
                thirdparty_data.update({"ipType":ip_type,
                                        "subnet":subnet,
                                        "network":network,
                                        "secret":secret})

                for i in range(0, len(rcvd_data["clientAddressList"])):
                    _ip_addr_updated.append(rcvd_data["clientAddressList"][i]["ip"])
                    _start_ip_updated.append(rcvd_data["clientAddressList"][i]["startIP"])
                    _end_ip_updated.append(rcvd_data["clientAddressList"][i]["endIP"])
                thirdparty_data.update({"ip":_ip_addr_updated,
                                        "startIP":_start_ip_updated,
                                        "endIP":_end_ip_updated})
            thirdparty_data["clientAddressList"].append({"ipType":ip_type,
                                                        "ip":ip_addr,
                                                        "startIP":start_ip,
                                                        "endIP":end_ip,
                                                        "subnet":subnet,
                                                        "network":network,
                                                        "secret":secret})

            if vlan_mapping_type == "MapSPreserveC":
                thirdparty_data["vlanMappingList"] = []
                if rcvd_data["vlanMappingList"]:
                    for i in range(0, len(rcvd_data["vlanMappingList"])):
                        thirdparty_data["vlanMappingList"].append({"accessStart":rcvd_data["vlanMappingList"][i]["accessStart"],
                                                               "accessEnd":rcvd_data["vlanMappingList"][i]["accessEnd"],
                                                               "coreStart":rcvd_data["vlanMappingList"][i]["coreStart"],
                                                               "coreEnd":rcvd_data["vlanMappingList"][i]["coreEnd"]})


            thirdparty_data["qinqVLANTagList"] = []
            if rcvd_data["qinqVLANTagList"]:
                for i in range(0, len(rcvd_data["qinqVLANTagList"])):

                    thirdparty_data["qinqVLANTagList"].append({"startCVlan":rcvd_data["qinqVLANTagList"][i]["startCVlan"],
                                                           "endCVlan":rcvd_data["qinqVLANTagList"][i]["endCVlan"],
                                                           "startSVlan":rcvd_data["qinqVLANTagList"][i]["startSVlan"],
                                                           "endSVlan":rcvd_data["qinqVLANTagList"][i]["endSVlan"]})

            json_data = json.dumps(thirdparty_data)
            update_url = ji.get_url(self.req_api_thirdparty_apzone_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(update_url, self.jsessionid, json_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def validate_radius_client_ip_in_third_party_apzone(self, zone_name="Auto_ThrdPrty_Zone", 
                                                      domain_label='Administration Domain', 
                                                      ip_type=None,
                                                      ip_addr=None, 
                                                      start_ip=None, end_ip=None, 
                                                      network=None, subnet=None, 
                                                      secret=None):
        """
        API is used to validate Radius Client Address in Third Party AP

        URI: GET /wsg/api/scg/zones/thirdparty/byDomain/<domain_uuid> 
        
        :param str zone_name: Name of the third party ap zone
        :param str domain_label: Name of the Domain
        :param str ip_type: SingleIP | IPRange | Subnet
        :param str ip_addr: ip address to be added
        :param str start_ip: if ip_type is IPRange then pass the starting ip address 
        :param str end_ip: if ip_type is IPRange then pass the ending ip address
        :param str network: if ip_type is Subnet then pass ip address of the network
        :param str subnet: if ip_type is Subnet then pass ip address of subnet
        :param str secret: secret key 
        :return: True if Radius Client ip to third party apzone is validated else False
        :rtype: boolean

        """
        
        try:
            url = ji.get_url(self.req_api_thirdparty_apzone_updt_del1%self.get_domain_uuid(domain_label=domain_label), self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_thirdparty_apzone(url, zone_name)
            is_entry_found = False

            exp_result = (True if ip_type else False, True if ip_addr else False, True if start_ip else False,
                    True if end_ip else False, True if network else False, True if subnet else False, True if secret else False)

            actual_result = None
            for i in range(0, len(rcvd_data["clientAddressList"])):
                is_ip_type = False
                is_ip_addr = False
                is_start_ip = False
                is_end_ip = False
                is_network = False
                is_subnet = False
                is_secret = False
                
                if ip_type:
                    if ip_type == str(rcvd_data["clientAddressList"][i]["ipType"]):
                        is_ip_type = True
                if ip_addr:
                    if ip_addr == str(rcvd_data["clientAddressList"][i]["ip"]):
                        is_ip_addr = True
                if start_ip:
                    if start_ip == str(rcvd_data["clientAddressList"][i]["startIP"]):
                        is_start_ip = True
                if end_ip:
                    if end_ip == str(rcvd_data["clientAddressList"][i]["endIP"]):
                        is_end_ip = True
                if network:
                    if network == str(rcvd_data["clientAddressList"][i]["network"]):
                        is_network = True
                if subnet:
                    if subnet == str(rcvd_data["clientAddressList"][i]["subnet"]):
                        is_subnet = True
                if secret:
                    if secret == str(rcvd_data["clientAddressList"][i]["secret"]):
                        is_secret = True
                actual_result = (is_ip_type, is_ip_addr, is_start_ip, is_end_ip, is_network, is_subnet, is_secret)
                if actual_result == exp_result:
                    is_entry_found = True
                    break
            if is_entry_found == False:
                self._print_err_validate('validate_radius_client_addr_to_third_party_ap', 'actual_result', 'exp_result', actual_result,
                        exp_result)
                return False

            return True

        except Exception, e:
            print traceback.format_exc()
            return False

    def update_radius_client_ip_in_third_party_apzone(self, zone_name="Auto_ThrdPrty_Zone", domain_label='Administration Domain', 
                                                             curr_ip_type=None, curr_ip_addr=None,
                                                             curr_start_ip=None, curr_end_ip=None, curr_subnet=None, curr_network=None,
                                                             ip_type=None, ip_addr=None, start_ip=None, end_ip=None,
                                                             subnet=None, network=None, secret=None):
        """
        API is used to update Radius Client IP Address in Third Party AP

        URI: PUT /wsg/api/scg/zones/thirdparty/<thirdparty_apzonbe_key>

        :param str zone_name: Name of the third party ap zone
        :param str domain_label: Name of the Domain 
        :param str curr_ip_type: Original ip_type SingleIP | IPRange | Subnet
        :param str curr_ip_addr: Original IP address
        :param str curr_start_ip: Original ip_type if ip_type is IPRange then pass the starting ip address
        :param str curr_end_ip: Original ip_type if ip_type is IPRange then pass the ending ip address
        :param str curr_subnet: Original ip_type if ip_type is Subnet then pass ip address of subnet
        :param str curr_network: Original ip_type if ip_type is Subnet then pass ip address of the network
        :param str ip_type: SingleIP | IPRange | Subnet
        :param str ip_addr: ip address to be added 
        :param str start_ip: if ip_type is IPRange then pass the starting ip address 
        :param str end_ip: if ip_type is IPRange then pass the ending ip address
        :param str network: if ip_type is Subnet then pass ip address of the network
        :param str subnet: if ip_type is Subnet then pass ip address of subnet
        :param str secret: secret key 
        :return: True if Radius Client ip address is updated to third party apzone else False
        :rtype: boolean

        """

        result = False
        thirdparty_data = {}
        try:
            url = ji.get_url(self.req_api_thirdparty_apzone_updt_del1%self.get_domain_uuid(domain_label=domain_label), self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_thirdparty_apzone(url, zone_name)
            vlan_mapping_type = None
            vlan_mapping_type = rcvd_data["vlanMappingType"]
            thirdparty_data["key"] = rcvd_data["key"]
            thirdparty_data["zoneIntId"] = str(rcvd_data["zoneIntId"])
            thirdparty_data["zoneName"] = rcvd_data["zoneName"]
            thirdparty_data["accessNetworkType"] = rcvd_data["accessNetworkType"]
            thirdparty_data["networkTrafficPackageId"] = rcvd_data["networkTrafficPackageId"]
            thirdparty_data["description"] = rcvd_data["description"]
            thirdparty_data["coreNetworkType"] = rcvd_data["coreNetworkType"]
            thirdparty_data["authType"] = rcvd_data["authType"]

            if rcvd_data["authServiceProfileId"]:
                thirdparty_data["authServiceProfileId"] = rcvd_data["authServiceProfileId"]

            thirdparty_data["acctServiceProfileId"] = rcvd_data["acctServiceProfileId"]
            thirdparty_data["subscriberPackageId"] = rcvd_data["subscriberPackageId"]

            if rcvd_data["forwardingServiceProfileId"]:
                thirdparty_data["forwardingServiceProfileId"] = rcvd_data["forwardingServiceProfileId"]

            thirdparty_data["acctUpdateInterval"] = rcvd_data["acctUpdateInterval"]
            thirdparty_data["coreQinQEnabled"] = rcvd_data["coreQinQEnabled"]
            thirdparty_data["vlanMappingType"] = rcvd_data["vlanMappingType"]
            thirdparty_data["coreAddFixedVlan"] = rcvd_data["coreAddFixedVlan"]
            thirdparty_data["coreAddFixedSVlan"] = rcvd_data["coreAddFixedSVlan"]
            thirdparty_data["defaultShareSecret"] = rcvd_data["defaultShareSecret"]
            len_client_addr_list = len(rcvd_data["clientAddressList"])
            thirdparty_data["clientAddressList"] = []
            thirdparty_data["accessNetworkSourceIPList"] = []
            if rcvd_data["clientAddressList"]:
                for i in range(0, len(rcvd_data["clientAddressList"])):
                    thirdparty_data["clientAddressList"].append({"ip":rcvd_data["clientAddressList"][i]["ip"],
                                                                "startIP":rcvd_data["clientAddressList"][i]["startIP"],
                                                                "endIP":rcvd_data["clientAddressList"][i]["endIP"],
                                                                "subnet":rcvd_data["clientAddressList"][i]["subnet"],
                                                                "network":rcvd_data["clientAddressList"][i]["network"],
                                                                "ipType":rcvd_data["clientAddressList"][i]["ipType"],
                                                                "secret":rcvd_data["clientAddressList"][i]["secret"]})
            if rcvd_data["accessNetworkSourceIPList"]:
                for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                    thirdparty_data["accessNetworkSourceIPList"].append({"ip":rcvd_data["accessNetworkSourceIPList"][i]["ip"],
                                                                     "startIP":rcvd_data["accessNetworkSourceIPList"][i]["startIP"],
                                                                     "endIP":rcvd_data["accessNetworkSourceIPList"][i]["endIP"],
                                                                     "subnet":rcvd_data["accessNetworkSourceIPList"][i]["subnet"],
                                                                     "network":rcvd_data["accessNetworkSourceIPList"][i]["network"],
                                                                     "ipType":rcvd_data["accessNetworkSourceIPList"][i]["ipType"],
                                                                     "secret":""})

            _pos_update = None
            

            if _pos_update == len_client_addr_list-1:
                _ip_addr_updated = []
                _start_ip_updated = []
                _end_ip_updated = []
                _subnet_updated = []
                _network_updated = []

                if ip_type == "SingleIP":
                    for i in range(0, len(rcvd_data["clientAddressList"])):
                        if ip_type == rcvd_data["clientAddressList"][i]["ipType"] and ip_addr == rcvd_data["clientAddressList"][i]["ip"]:
                            
                            thirdparty_data.update({"ip":rcvd_data["clientAddressList"][i]["ip"] if not ip_addr else ip_addr,
                                                    "ipType":rcvd_data["clientAddressList"][i]["ipType"] if not ip_type else ip_type,
                                                    "secret":rcvd_data["clientAddressList"][i]["secret"] if not secret else secret})

                    for i in range(0, len(rcvd_data["clientAddressList"])):
                        _start_ip_updated.append(rcvd_data["clientAddressList"][i]["startIP"])
                        _end_ip_updated.append(rcvd_data["clientAddressList"][i]["endIP"])
                        _subnet_updated.append(rcvd_data["clientAddressList"][i]["subnet"])
                        _network_updated.append(rcvd_data["clientAddressList"][i]["network"])

                    thirdparty_data.update({"startIP":_start_ip_updated,
                                            "endIP":_end_ip_updated,
                                            "subnet":_subnet_updated,
                                            "network":_network_updated})
                elif ip_type == "IPRange":
                    thirdparty_data.update({"ipType":ip_type,
                                            "startIP":start_ip,
                                            "endIP":end_ip,
                                            "secret":secret})
                    for i in range(0, len(rcvd_data["clientAddressList"])):
                        _ip_addr_updated.append(rcvd_data["clientAddressList"][i]["ip"])
                        _subnet_updated.append(rcvd_data["clientAddressList"][i]["subnet"])
                        _network_updated.append(rcvd_data["clientAddressList"][i]["network"])
                    thirdparty_data.update({"ip":_ip_addr_updated,
                                            "subnet":_subnet_updated,
                                            "network":_network_updated})
                elif ip_type == "Subnet":
                    thirdparty_data.update({"ipType":ip_type,
                                            "subnet":subnet,
                                            "network":network,
                                            "secret":secret})

                    for i in range(0, len(rcvd_data["clientAddressList"])):
                        _ip_addr_updated.append(rcvd_data["clientAddressList"][i]["ip"])
                        _start_ip_updated.append(rcvd_data["clientAddressList"][i]["startIP"])
                        _end_ip_updated.append(rcvd_data["clientAddressList"][i]["endIP"])

                    thirdparty_data.update({"ip":_ip_addr_updated,
                                            "startIP":_start_ip_updated,
                                            "endIP":_end_ip_updated})



            else:
                thirdparty_data.update({"ipType":rcvd_data["clientAddressList"][len_client_addr_list-1]["ipType"],
                                    "ip":rcvd_data["clientAddressList"][len_client_addr_list-1]["ipType"],
                                    "startIP":rcvd_data["clientAddressList"][len_client_addr_list-1]["startIP"],
                                    "endIP":rcvd_data["clientAddressList"][len_client_addr_list-1]["endIP"],
                                    "subnet":rcvd_data["clientAddressList"][len_client_addr_list-1]["subnet"],
                                    "network":rcvd_data["clientAddressList"][len_client_addr_list-1]["network"],
                                    "secret":rcvd_data["clientAddressList"][len_client_addr_list-1]["secret"]})


            #update to Single IP 
            if ip_type == "SingleIP":
                res_single_ip = self._update_radius_client_ip_single_ip(rcvd_data=rcvd_data, thirdparty_data=thirdparty_data, 
                                                    curr_ip_type=curr_ip_type, curr_ip_addr=curr_ip_addr, curr_subnet=curr_subnet,
                                                    curr_network=curr_network, curr_start_ip=curr_start_ip, curr_end_ip=curr_end_ip, 
                                                    ip_type=ip_type, ip_addr=ip_addr, secret=secret)

                thirdparty_data.update(res_single_ip[0])
                _pos_update = res_single_ip[1]

                if res_single_ip[2] == False:
                    print "_update_radius_client_ip_single_ip() failed"
                    return False
            
            #update to  IPRange
            if ip_type == "IPRange":
                res_ip_range = self._update_radius_client_ip_range(rcvd_data=rcvd_data, thirdparty_data=thirdparty_data, curr_ip_type=curr_ip_type, 
                                                    curr_ip_addr=curr_ip_addr, curr_subnet=curr_subnet,
                                                    curr_network=curr_network, curr_start_ip=curr_start_ip, curr_end_ip=curr_end_ip,
                                                    ip_type=ip_type, start_ip=start_ip, end_ip=end_ip, secret=secret)
                thirdparty_data.update(res_ip_range[0])
                _pos_update = res_ip_range[1]
                if res_ip_range[2] == False:
                    print "_update_radius_client_ip_range(): failed"
                    return False

            #update to Subnet
            if ip_type == "Subnet":
                res_subnet = self._update_radius_client_ip_subnet(rcvd_data=rcvd_data, thirdparty_data=thirdparty_data, curr_ip_type=curr_ip_type, 
                                                curr_ip_addr=curr_ip_addr, curr_subnet=curr_subnet,
                                                curr_network=curr_network, curr_start_ip=curr_start_ip, curr_end_ip=curr_end_ip,
                                                ip_type=ip_type, subnet=subnet, network=network, secret=secret)
                thirdparty_data.update(res_subnet[0])
                _pos_update = res_subnet[1]
                if res_subnet[2] == False:
                    print "_update_radius_client_ip_subnet() failed"
                    return False
            #update_ the keys which are outside the list
            ################
            
            if vlan_mapping_type == "MapSPreserveC":
                thirdparty_data["vlanMappingList"] = []
                if rcvd_data["vlanMappingList"]:
                    for i in range(0, len(rcvd_data["vlanMappingList"])):
                        thirdparty_data["vlanMappingList"].append({"accessStart":rcvd_data["vlanMappingList"][i]["accessStart"],
                                                               "accessEnd":rcvd_data["vlanMappingList"][i]["accessEnd"],
                                                               "coreStart":rcvd_data["vlanMappingList"][i]["coreStart"],
                                                               "coreEnd":rcvd_data["vlanMappingList"][i]["coreEnd"]})


            thirdparty_data["qinqVLANTagList"] = []
            if rcvd_data["qinqVLANTagList"]:
                for i in range(0, len(rcvd_data["qinqVLANTagList"])):

                    thirdparty_data["qinqVLANTagList"].append({"startCVlan":rcvd_data["qinqVLANTagList"][i]["startCVlan"],
                                                           "endCVlan":rcvd_data["qinqVLANTagList"][i]["endCVlan"],
                                                           "startSVlan":rcvd_data["qinqVLANTagList"][i]["startSVlan"],
                                                           "endSVlan":rcvd_data["qinqVLANTagList"][i]["endSVlan"]})

            json_data = json.dumps(thirdparty_data)
            update_url = ji.get_url(self.req_api_thirdparty_apzone_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(update_url, self.jsessionid, json_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def _update_radius_client_ip_subnet(self, rcvd_data=None, thirdparty_data=None, curr_ip_type=None, curr_ip_addr=None, curr_subnet=None,
                                            curr_network=None, curr_start_ip=None, curr_end_ip=None,
                                            ip_type=None, subnet=None, network=None, secret=None):
        try:
            is_single_ip = False
            is_iprange_found = False
            is_subnet_found = False
            _pos_update = None

            if curr_ip_type == "SingleIP":
                for i in range(0, len(rcvd_data["clientAddressList"])):
                    if curr_ip_type == rcvd_data["clientAddressList"][i]["ipType"] and curr_ip_addr == rcvd_data["clientAddressList"][i]["ip"]:
                        is_single_ip = True
                        _pos_update = i
                        thirdparty_data["clientAddressList"][i].update({"ipType":rcvd_data["clientAddressList"][i]["ipType"] if not ip_type else ip_type,
                                                    "ip":"",
                                                    "startIP":"",
                                                    "endIP":"",
                                                    "subnet":rcvd_data["clientAddressList"][i]["subnet"] if not subnet else subnet,
                                                    "network":rcvd_data["clientAddressList"][i]["network"] if not network else network,
                                                    "secret":rcvd_data["clientAddressList"][i]["secret"] if not secret else secret})
                        break
                if is_single_ip == False:
                    print "_update_radius_client_ip_subnet(): singleIP of ipaddress not found"
                    return False

            elif curr_ip_type == "IPRange":
                for i in range(0, len(rcvd_data["clientAddressList"])):
                    if curr_ip_type == rcvd_data["clientAddressList"][i]["ipType"] and \
                        curr_start_ip == rcvd_data["clientAddressList"][i]["startIP"] and \
                        curr_end_ip == rcvd_data["clientAddressList"][i]["endIP"]:
                            is_iprange_found = True
                            _pos_update = i
                            thirdparty_data["clientAddressList"][i].update({"ipType":rcvd_data["clientAddressList"][i]["ipType"] \
                                                                                    if not ip_type else ip_type,
                                                                "ip":"",
                                                                "startIP":"",
                                                                "endIP":"",
                                                                "subnet":rcvd_data["clientAddressList"][i]["subnet"] if not subnet else subnet,
                                                                "network":rcvd_data["clientAddressList"][i]["network"] if not network else network,
                                                                "secret":rcvd_data["clientAddressList"][i]["secret"] if not secret else secret})
                            break
                if is_iprange_found == False:
                    print "_update_radius_client_ip_subnet(): IPrange not found"
                    return False

            elif curr_ip_type == "Subnet":
                for i in range(0, len(rcvd_data["clientAddressList"])):
                    if curr_ip_type == rcvd_data["clientAddressList"][i]["ipType"] and \
                        curr_subnet == rcvd_data["clientAddressList"][i]["subnet"] and \
                        curr_network == rcvd_data["clientAddressList"][i]["network"]:
                            is_subnet_found = True
                            _pos_update = i
                            thirdparty_data["clientAddressList"][i].update({"ipType":rcvd_data["clientAddressList"][i]["ipType"] \
                                                                                    if not ip_type else ip_type,
                                                                "ip":"",
                                                                "startIP":"",
                                                                "endIP":"",
                                                                "subnet":rcvd_data["clientAddressList"][i]["subnet"] if not subnet else subnet,
                                                                "network":rcvd_data["clientAddressList"][i]["network"] if not network else network,
                                                                "secret":rcvd_data["clientAddressList"][i]["secret"] if not secret else secret})
                            break
                if is_subnet_found == False:
                    print "_update_radius_client_ip_subnet(): subnet not found"
                    return False

            return thirdparty_data, _pos_update, True

        except Exception, e:
            print traceback.format_exc()
            return False

    def _update_radius_client_ip_range(self, rcvd_data=None, thirdparty_data=None, curr_ip_type=None, curr_ip_addr=None, curr_subnet=None,
                                        curr_network=None, curr_start_ip=None, curr_end_ip=None, 
                                        ip_type=None, start_ip=None, end_ip=None, secret=None):
        try:
            is_single_ip = False
            is_iprange_found = False
            is_subnet_found = False
            _pos_update = None
            if curr_ip_type == "SingleIP":
                for i in range(0, len(rcvd_data["clientAddressList"])):
                    if curr_ip_type == rcvd_data["clientAddressList"][i]["ipType"] and curr_ip_addr == rcvd_data["clientAddressList"][i]["ip"]:
                        is_single_ip = True
                        _pos_update = i
                        thirdparty_data["clientAddressList"][i].update({"ipType":rcvd_data["clientAddressList"][i]["ipType"] if not ip_type else ip_type,
                                                    "ip":"",
                                                    "startIP":rcvd_data["clientAddressList"][i]["startIP"] if not start_ip else start_ip,
                                                    "endIP":rcvd_data["clientAddressList"][i]["endIP"] if not end_ip else end_ip,
                                                    "subnet":"",
                                                    "network":"",
                                                    "secret":rcvd_data["clientAddressList"][i]["secret"] if not secret else secret})

                        break
                if is_single_ip == False:
                    print "_update_radius_client_ip_range(): singleIP of ipaddress not found"
                    return False

            elif curr_ip_type == "IPRange":
                for i in range(0, len(rcvd_data["clientAddressList"])):
                    if curr_ip_type == rcvd_data["clientAddressList"][i]["ipType"] and \
                        curr_start_ip == rcvd_data["clientAddressList"][i]["startIP"] and \
                        curr_end_ip == rcvd_data["clientAddressList"][i]["endIP"]:
                            is_iprange_found = True
                            _pos_update = i
                            thirdparty_data["clientAddressList"][i].update({"ipType":rcvd_data["clientAddressList"][i]["ipType"] \
                                                                                    if not ip_type else ip_type,
                                                                    "ip":"",
                                                                    "startIP":rcvd_data["clientAddressList"][i]["startIP"] if not start_ip else start_ip,
                                                                    "endIP":rcvd_data["clientAddressList"][i]["endIP"] if not end_ip else end_ip,
                                                                    "subnet":"",
                                                                    "network":"",
                                                                    "secret":rcvd_data["clientAddressList"][i]["secret"] if not secret else secret})
                            break
                if is_iprange_found == False:
                    print "_update_radius_client_ip_range(): IPrange not found"
                    return False

            elif curr_ip_type == "Subnet":
                for i in range(0, len(rcvd_data["clientAddressList"])):
                    if curr_ip_type == rcvd_data["clientAddressList"][i]["ipType"] and \
                        curr_subnet == rcvd_data["clientAddressList"][i]["subnet"] and \
                        curr_network == rcvd_data["clientAddressList"][i]["network"]:
                            is_subnet_found = True
                            _pos_update = i
                            thirdparty_data["clientAddressList"][i].update({"ipType":rcvd_data["clientAddressList"][i]["ipType"] \
                                                                                    if not ip_type else ip_type,
                                                                    "ip":"",
                                                                    "startIP":rcvd_data["clientAddressList"][i]["startIP"] if not start_ip else start_ip,
                                                                    "endIP":rcvd_data["clientAddressList"][i]["endIP"] if not end_ip else end_ip,
                                                                    "subnet":"",
                                                                    "network":"",
                                                                    "secret":rcvd_data["clientAddressList"][i]["secret"] if not secret else secret})
                            break
                if is_subnet_found == False:
                    print "_update_radius_client_ip_range(): subnet not found"
                    return False

            return thirdparty_data, _pos_update, True

        except Exception, e:
            print traceback.format_exc()
            return False
     
    def _update_radius_client_ip_single_ip(self, rcvd_data=None, thirdparty_data=None, curr_ip_type=None, curr_ip_addr=None, curr_subnet=None, 
                          curr_network=None, curr_start_ip=None, curr_end_ip=None, ip_type=None, ip_addr=None, secret=None):
        try:
            is_single_ip = False
            is_iprange_found = False
            is_subnet_found = False
            _pos_update = None 
            if curr_ip_type == "SingleIP":
                for i in range(0, len(rcvd_data["clientAddressList"])):
                    if curr_ip_type == rcvd_data["clientAddressList"][i]["ipType"] and curr_ip_addr == rcvd_data["clientAddressList"][i]["ip"]:
                        is_single_ip = True
                        _pos_update = i
                        thirdparty_data["clientAddressList"][i].update({"ipType":rcvd_data["clientAddressList"][i]["ipType"] if not ip_type else ip_type,
                                                    "ip":rcvd_data["clientAddressList"][i]["ip"] if not ip_addr else ip_addr,
                                                    "startIP":"",
                                                    "endIP":"",
                                                    "subnet":"",
                                                    "network":"",
                                                    "secret":rcvd_data["clientAddressList"][i]["secret"] if not secret else secret})
                        break
                if is_single_ip == False:
                    print "_update_radius_client_ip_single_ip(): singleIP of ipaddress not found"
                    return False

            elif curr_ip_type == "IPRange":
                for i in range(0, len(rcvd_data["clientAddressList"])):
                    if curr_ip_type == rcvd_data["clientAddressList"][i]["ipType"] and \
                        curr_start_ip == rcvd_data["clientAddressList"][i]["startIP"] and \
                        curr_end_ip == rcvd_data["clientAddressList"][i]["endIP"]:
                            _pos_update = i
                            is_iprange_found = True
                            thirdparty_data["clientAddressList"][i].update({"ipType":rcvd_data["clientAddressList"][i]["ipType"] \
                                                                                            if not ip_type else ip_type,
                                                    "ip":rcvd_data["clientAddressList"][i]["ip"] if not ip_addr else ip_addr,
                                                    "startIP":"",
                                                    "endIP":"",
                                                    "subnet":"",
                                                    "network":"",
                                                    "secret":rcvd_data["clientAddressList"][i]["secret"] if not secret else secret})

                            break
                if is_iprange_found == False:
                    print "_update_radius_client_ip_single_ip(): IPrange not found"
                    return False

            elif curr_ip_type == "Subnet":
                for i in range(0, len(rcvd_data["clientAddressList"])):
                    if curr_ip_type == rcvd_data["clientAddressList"][i]["ipType"] and \
                        curr_subnet == rcvd_data["clientAddressList"][i]["subnet"] and \
                        curr_network == rcvd_data["clientAddressList"][i]["network"]:
                            is_subnet_found = True
                            _pos_update = i
                            thirdparty_data["clientAddressList"][i].update({"ipType":rcvd_data["clientAddressList"][i]["ipType"] \
                                                                    if not ip_type else ip_type,
                                                    "ip":rcvd_data["clientAddressList"][i]["ip"] if not ip_addr else ip_addr,
                                                    "startIP":"",
                                                    "endIP":"",
                                                    "subnet":"",
                                                    "network":"",
                                                    "secret":rcvd_data["clientAddressList"][i]["secret"] if not secret else secret})
                            break

                if is_subnet_found == False:
                    print "_update_radius_client_ip_single_ip(): subnet not found"
                    return False

            return thirdparty_data, _pos_update, True

        except Exception, e:
            print traceback.format_exc()
            return False



    def add_ap_ipaddr_to_third_party_apzone(self, zone_name="Auto_ThrdPrty_Zone", domain_label='Administration Domain',
                                        ip_type="SingleIP", 
                                        ip_addr="1.2.3.4", 
                                        start_ip="", 
                                        end_ip="", 
                                        network="", 
                                        subnet="", 
                                        secret="ruckus1!"):
        """       
        Adds AP ip address to third party apzone

        URI: PUT /wsg/api/scg/zones/thirdparty/<thirdparty_apzonbe_key>

        :param str zone_name: Name of the third party ap zone
        :param str ip_type: SingleIP | IPRange | Subnet
        :param str ip_addr: ip address to be added
        :param str start_ip: if ip_type is IPRange then pass the starting ip address 
        :param str end_ip: if ip_type is IPRange then pass the ending ip address
        :param str network: if ip_type is Subnet then pass ip address of the network
        :param str subnet: if ip_type is Subnet then pass ip address of subnet
        :param str secret: secret key 
        :return: True if AP ip address added to third party apzone else False
        :rtype: boolean
        """

        result = False
        thirdparty_data = {}
        try:
            url = ji.get_url(self.req_api_thirdparty_apzone_updt_del1%self.get_domain_uuid(domain_label=domain_label), self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_thirdparty_apzone(url, zone_name)
            vlan_mapping_type = None
            vlan_mapping_type = rcvd_data["vlanMappingType"]
            thirdparty_data["key"] = rcvd_data["key"]
            thirdparty_data["zoneIntId"] = str(rcvd_data["zoneIntId"])
            thirdparty_data["zoneName"] = rcvd_data["zoneName"]
            thirdparty_data["accessNetworkType"] = rcvd_data["accessNetworkType"]
            thirdparty_data["networkTrafficPackageId"] = rcvd_data["networkTrafficPackageId"]
            thirdparty_data["description"] = rcvd_data["description"]
            thirdparty_data["coreNetworkType"] = rcvd_data["coreNetworkType"]
            thirdparty_data["authType"] = rcvd_data["authType"]

            if rcvd_data["authServiceProfileId"]:
                thirdparty_data["authServiceProfileId"] = rcvd_data["authServiceProfileId"]

            thirdparty_data["acctServiceProfileId"] = rcvd_data["acctServiceProfileId"]
            thirdparty_data["subscriberPackageId"] = rcvd_data["subscriberPackageId"]

            if rcvd_data["forwardingServiceProfileId"]:
                thirdparty_data["forwardingServiceProfileId"] = rcvd_data["forwardingServiceProfileId"]

            thirdparty_data["acctUpdateInterval"] = rcvd_data["acctUpdateInterval"]
            thirdparty_data["coreQinQEnabled"] = rcvd_data["coreQinQEnabled"]
            thirdparty_data["vlanMappingType"] = rcvd_data["vlanMappingType"]
            thirdparty_data["coreAddFixedVlan"] = rcvd_data["coreAddFixedVlan"]
            thirdparty_data["coreAddFixedSVlan"] = rcvd_data["coreAddFixedSVlan"]
            thirdparty_data["defaultShareSecret"] = rcvd_data["defaultShareSecret"]
            thirdparty_data.update({"clientAddressList":[]})
            if rcvd_data["clientAddressList"]:
                for i in range(0, len(rcvd_data["clientAddressList"])):
                    thirdparty_data["clientAddressList"].append({"ip":rcvd_data["clientAddressList"][i]["ip"],
                                                                "startIP":rcvd_data["clientAddressList"][i]["startIP"],
                                                                "endIP":rcvd_data["clientAddressList"][i]["endIP"],
                                                                "subnet":rcvd_data["clientAddressList"][i]["subnet"],
                                                                "network":rcvd_data["clientAddressList"][i]["network"],
                                                                "ipType":rcvd_data["clientAddressList"][i]["ipType"],
                                                                "secret":rcvd_data["clientAddressList"][i]["secret"]})
            thirdparty_data.update({"accessNetworkSourceIPList":[]})
            if rcvd_data["accessNetworkSourceIPList"]:
                for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                    thirdparty_data["accessNetworkSourceIPList"].append({"ip":rcvd_data["accessNetworkSourceIPList"][i]["ip"],
                                                                         "startIP":rcvd_data["accessNetworkSourceIPList"][i]["startIP"],
                                                                         "endIP":rcvd_data["accessNetworkSourceIPList"][i]["endIP"],
                                                                         "subnet":rcvd_data["accessNetworkSourceIPList"][i]["subnet"],
                                                                         "network":rcvd_data["accessNetworkSourceIPList"][i]["network"],
                                                                         "ipType":rcvd_data["accessNetworkSourceIPList"][i]["ipType"],
                                                                         "secret":""})


            thirdparty_data.update({"ipType":ip_type})
            _ip_addr_updated = []
            _start_ip_updated = []
            _end_ip_updated = []
            _subnet_updated = []
            _network_updated = []

            if ip_type == "SingleIP":
                thirdparty_data.update({"ip":ip_addr,
                                       "ipType":ip_type,
                                       "secret":secret})

                for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                    _start_ip_updated.append(rcvd_data["accessNetworkSourceIPList"][i]["startIP"])
                    _end_ip_updated.append(rcvd_data["accessNetworkSourceIPList"][i]["endIP"])
                    _subnet_updated.append(rcvd_data["accessNetworkSourceIPList"][i]["subnet"])
                    _network_updated.append(rcvd_data["accessNetworkSourceIPList"][i]["network"])

                thirdparty_data.update({"startIP":_start_ip_updated,
                                        "endIP":_end_ip_updated,
                                        "subnet":_subnet_updated,
                                        "network":_network_updated})
            elif ip_type == "IPRange":
                thirdparty_data.update({"ipType":ip_type,
                                        "startIP":start_ip,
                                        "endIP":end_ip,
                                        "secret":secret})

                for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                    _ip_addr_updated.append(rcvd_data["accessNetworkSourceIPList"][i]["ip"])
                    _subnet_updated.append(rcvd_data["accessNetworkSourceIPList"][i]["subnet"])
                    _network_updated.append(rcvd_data["accessNetworkSourceIPList"][i]["network"])
                thirdparty_data.update({"ip":_ip_addr_updated,
                                        "subnet":_subnet_updated,
                                        "network":_network_updated})

            elif ip_type == "Subnet":
                thirdparty_data.update({"ipType":ip_type,
                                        "subnet":subnet,
                                        "network":network,
                                        "secret":secret})

                for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                    _ip_addr_updated.append(rcvd_data["accessNetworkSourceIPList"][i]["ip"])
                    _start_ip_updated.append(rcvd_data["accessNetworkSourceIPList"][i]["startIP"])
                    _end_ip_updated.append(rcvd_data["accessNetworkSourceIPList"][i]["endIP"])
                thirdparty_data.update({"ip":_ip_addr_updated,
                                        "startIP":_start_ip_updated,
                                        "endIP":_end_ip_updated})

            thirdparty_data["accessNetworkSourceIPList"].append({"ipType":ip_type,
                                                        "ip":ip_addr,
                                                        "startIP":start_ip,
                                                        "endIP":end_ip,
                                                        "subnet":subnet,
                                                        "network":network,
                                                        "secret":secret})

            if vlan_mapping_type == "MapSPreserveC":
                thirdparty_data.update({"vlanMappingList":[]})
                if rcvd_data["vlanMappingList"]:
                    for i in range(0, len(rcvd_data["vlanMappingList"])):
                        thirdparty_data["vlanMappingList"].append({"accessStart":rcvd_data["vlanMappingList"][i]["accessStart"],
                                                               "accessEnd":rcvd_data["vlanMappingList"][i]["accessEnd"],
                                                               "coreStart":rcvd_data["vlanMappingList"][i]["coreStart"],
                                                               "coreEnd":rcvd_data["vlanMappingList"][i]["coreEnd"]})


                        thirdparty_data.update({"qinqVLANTagList":[]})

            if rcvd_data["qinqVLANTagList"]:
                for i in range(0, len(rcvd_data["qinqVLANTagList"])):

                    thirdparty_data["qinqVLANTagList"].append({"startCVlan":rcvd_data["qinqVLANTagList"][i]["startCVlan"],
                                                           "endCVlan":rcvd_data["qinqVLANTagList"][i]["endCVlan"],
                                                           "startSVlan":rcvd_data["qinqVLANTagList"][i]["startSVlan"],
                                                           "endSVlan":rcvd_data["qinqVLANTagList"][i]["endSVlan"]})

            json_data = json.dumps(thirdparty_data)
            update_url = ji.get_url(self.req_api_thirdparty_apzone_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(update_url, self.jsessionid, json_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def validate_ap_ipaddr_in_third_party_apzone(self, zone_name="Auto_ThrdPrty_Zone", 
                                                      domain_label='Administration Domain', 
                                                      ip_type=None,
                                                      ip_addr=None, 
                                                      start_ip=None, end_ip=None, 
                                                      network=None, subnet=None):
        """
        API is used to validate AP IP Address in Third Party AP

        URI: GET /wsg/api/scg/zones/thirdparty/byDomain/<domain_uuid> 
        
        :param str zone_name: Name of the third party ap zone
        :param str domain_label: Name of the Domain
        :param str ip_type: SingleIP | IPRange | Subnet
        :param str ip_addr: ip address to be added
        :param str start_ip: if ip_type is IPRange then pass the starting ip address 
        :param str end_ip: if ip_type is IPRange then pass the ending ip address
        :param str network: if ip_type is Subnet then pass ip address of the network
        :param str subnet: if ip_type is Subnet then pass ip address of subnet
        :return: True if AP IP validated in third party apzone else False
        :rtype: boolean

        """
        
        try:
            url = ji.get_url(self.req_api_thirdparty_apzone_updt_del1%self.get_domain_uuid(domain_label=domain_label), self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_thirdparty_apzone(url, zone_name)
            is_entry_found = False

            exp_result = (True if ip_type else False, True if ip_addr else False, True if start_ip else False,
                    True if end_ip else False, True if network else False, True if subnet else False)

            actual_result = None
            for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                is_ip_type = False
                is_ip_addr = False
                is_start_ip = False
                is_end_ip = False
                is_network = False
                is_subnet = False
                
                if ip_type == str(rcvd_data["accessNetworkSourceIPList"][i]["ipType"]):
                    is_ip_type = True
                if ip_addr == str(rcvd_data["accessNetworkSourceIPList"][i]["ip"]):
                    is_ip_addr = True
                if start_ip == str(rcvd_data["accessNetworkSourceIPList"][i]["startIP"]):
                    is_start_ip = True
                if end_ip == str(rcvd_data["accessNetworkSourceIPList"][i]["endIP"]):
                    is_end_ip = True
                if network == str(rcvd_data["accessNetworkSourceIPList"][i]["network"]):
                    is_network = True
                if subnet == str(rcvd_data["accessNetworkSourceIPList"][i]["subnet"]):
                    is_subnet = True

                actual_result = (is_ip_type, is_ip_addr, is_start_ip, is_end_ip, is_network, is_subnet)
                if actual_result == exp_result:
                    is_entry_found = True
                    break

            if is_entry_found == False:
                self._print_err_validate('validate_ap_ipaddr_to_third_party_ap', 'actual_result', 'exp_result', actual_result,
                        exp_result)
                return False

            return True

        except Exception, e:
            print traceback.format_exc()
            return False

 

    def update_ap_ipaddr_in_third_party_apzone(self, zone_name="Auto_ThrdPrty_Zone", domain_label='Administration Domain', 
                                                             curr_ip_type=None, curr_ip_addr=None,
                                                             curr_start_ip=None, curr_end_ip=None, curr_subnet=None, curr_network=None,
                                                             ip_type=None, ip_addr=None, start_ip=None, end_ip=None,
                                                             subnet=None, network=None, secret=None):
        """
        API is used to update AP IP Address in Third Party AP

        URI: PUT /wsg/api/scg/zones/thirdparty/<thirdparty_apzonbe_key>

        :param str zone_name: Name of the third party ap zone
        :param str domain_label: Name of the Domain 
        :param str curr_ip_type: Original ip_type SingleIP | IPRange | Subnet
        :param str curr_ip_addr: Original IP address
        :param str curr_start_ip: Original ip_type if ip_type is IPRange then pass the starting ip address
        :param str curr_end_ip: Original ip_type if ip_type is IPRange then pass the ending ip address
        :param str curr_subnet: Original ip_type if ip_type is Subnet then pass ip address of subnet
        :param str curr_network: Original ip_type if ip_type is Subnet then pass ip address of the network
        :param str ip_type: SingleIP | IPRange | Subnet
        :param str ip_addr: ip address to be added 
        :param str start_ip: if ip_type is IPRange then pass the starting ip address 
        :param str end_ip: if ip_type is IPRange then pass the ending ip address
        :param str network: if ip_type is Subnet then pass ip address of the network
        :param str subnet: if ip_type is Subnet then pass ip address of subnet
        :param str secret: secret key 
        :return: True if AP ip address is updated to third party apzone else False
        :rtype: boolean

        """

        result = False
        thirdparty_data = {}
        try:
            url = ji.get_url(self.req_api_thirdparty_apzone_updt_del1%self.get_domain_uuid(domain_label=domain_label), self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_thirdparty_apzone(url, zone_name)
            vlan_mapping_type = None
            vlan_mapping_type = rcvd_data["vlanMappingType"]
            thirdparty_data["key"] = rcvd_data["key"]
            thirdparty_data["zoneIntId"] = str(rcvd_data["zoneIntId"])
            thirdparty_data["zoneName"] = rcvd_data["zoneName"]
            thirdparty_data["accessNetworkType"] = rcvd_data["accessNetworkType"]
            thirdparty_data["networkTrafficPackageId"] = rcvd_data["networkTrafficPackageId"]
            thirdparty_data["description"] = rcvd_data["description"]
            thirdparty_data["coreNetworkType"] = rcvd_data["coreNetworkType"]
            thirdparty_data["authType"] = rcvd_data["authType"]

            if rcvd_data["authServiceProfileId"]:
                thirdparty_data["authServiceProfileId"] = rcvd_data["authServiceProfileId"]
            if rcvd_data["acctServiceProfileId"]:
                thirdparty_data["acctServiceProfileId"] = rcvd_data["acctServiceProfileId"]
            thirdparty_data["subscriberPackageId"] = rcvd_data["subscriberPackageId"]

            if rcvd_data["forwardingServiceProfileId"]:
                thirdparty_data["forwardingServiceProfileId"] = rcvd_data["forwardingServiceProfileId"]
            
            thirdparty_data["acctUpdateInterval"] = rcvd_data["acctUpdateInterval"]
            thirdparty_data["coreQinQEnabled"] = rcvd_data["coreQinQEnabled"]
            thirdparty_data["vlanMappingType"] = rcvd_data["vlanMappingType"]
            thirdparty_data["coreAddFixedVlan"] = rcvd_data["coreAddFixedVlan"]
            thirdparty_data["coreAddFixedSVlan"] = rcvd_data["coreAddFixedSVlan"]
            thirdparty_data["defaultShareSecret"] = rcvd_data["defaultShareSecret"]

            #len_client_addr_list = len(rcvd_data["clientAddressList"])
            thirdparty_data.update({"clientAddressList":[]})
            thirdparty_data.update({"accessNetworkSourceIPList":[]})
            if rcvd_data["clientAddressList"]:
                for i in range(0, len(rcvd_data["clientAddressList"])):
                    thirdparty_data["clientAddressList"].append({"ip":rcvd_data["clientAddressList"][i]["ip"],
                                                                "startIP":rcvd_data["clientAddressList"][i]["startIP"],
                                                                "endIP":rcvd_data["clientAddressList"][i]["endIP"],
                                                                "subnet":rcvd_data["clientAddressList"][i]["subnet"],
                                                                "network":rcvd_data["clientAddressList"][i]["network"],
                                                                "ipType":rcvd_data["clientAddressList"][i]["ipType"],
                                                                "secret":rcvd_data["clientAddressList"][i]["secret"]})

            for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                thirdparty_data["accessNetworkSourceIPList"].append({"ip":rcvd_data["accessNetworkSourceIPList"][i]["ip"],
                                                                     "startIP":rcvd_data["accessNetworkSourceIPList"][i]["startIP"],
                                                                     "endIP":rcvd_data["accessNetworkSourceIPList"][i]["endIP"],
                                                                     "subnet":rcvd_data["accessNetworkSourceIPList"][i]["subnet"],
                                                                     "network":rcvd_data["accessNetworkSourceIPList"][i]["network"],
                                                                     "ipType":rcvd_data["accessNetworkSourceIPList"][i]["ipType"],
                                                                     "secret":""})
            _pos_update = None
            len_client_addr_list = len(rcvd_data["accessNetworkSourceIPList"]) 

            if _pos_update == len_client_addr_list-1:
                _ip_addr_updated = []
                _start_ip_updated = []
                _end_ip_updated = []
                _subnet_updated = []
                _network_updated = []

                if ip_type == "SingleIP":
                    for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                        if ip_type == rcvd_data["accessNetworkSourceIPList"][i]["ipType"] and ip_addr == rcvd_data["accessNetworkSourceIPList"][i]["ip"]:
                            
                            thirdparty_data.update({"ip":rcvd_data["accessNetworkSourceIPList"][i]["ip"] if not ip_addr else ip_addr,
                                                    "ipType":rcvd_data["accessNetworkSourceIPList"][i]["ipType"] if not ip_type else ip_type,
                                                    "secret":""}) #rcvd_data["accessNetworkSourceIPList"][i]["secret"] if not secret else secret})

                    for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                        _start_ip_updated.append(rcvd_data["accessNetworkSourceIPList"][i]["startIP"])
                        _end_ip_updated.append(rcvd_data["accessNetworkSourceIPList"][i]["endIP"])
                        _subnet_updated.append(rcvd_data["accessNetworkSourceIPList"][i]["subnet"])
                        _network_updated.append(rcvd_data["accessNetworkSourceIPList"][i]["network"])

                    thirdparty_data.update({"startIP":_start_ip_updated,
                                            "endIP":_end_ip_updated,
                                            "subnet":_subnet_updated,
                                            "network":_network_updated})
                elif ip_type == "IPRange":
                    thirdparty_data.update({"ipType":ip_type,
                                            "startIP":start_ip,
                                            "endIP":end_ip,
                                            "secret":""}) #secret})
                    for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                        _ip_addr_updated.append(rcvd_data["accessNetworkSourceIPList"][i]["ip"])
                        _subnet_updated.append(rcvd_data["accessNetworkSourceIPList"][i]["subnet"])
                        _network_updated.append(rcvd_data["accessNetworkSourceIPList"][i]["network"])
                    thirdparty_data.update({"ip":_ip_addr_updated,
                                            "subnet":_subnet_updated,
                                            "network":_network_updated})
                elif ip_type == "Subnet":
                    thirdparty_data.update({"ipType":ip_type,
                                            "subnet":subnet,
                                            "network":network,
                                            "secret":""})

                    for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                        _ip_addr_updated.append(rcvd_data["accessNetworkSourceIPList"][i]["ip"])
                        _start_ip_updated.append(rcvd_data["accessNetworkSourceIPList"][i]["startIP"])
                        _end_ip_updated.append(rcvd_data["accessNetworkSourceIPList"][i]["endIP"])

                    thirdparty_data.update({"ip":_ip_addr_updated,
                                            "startIP":_start_ip_updated,
                                            "endIP":_end_ip_updated})



            else:
                thirdparty_data.update({"ipType":rcvd_data["accessNetworkSourceIPList"][len_client_addr_list-1]["ipType"],
                                    "ip":rcvd_data["accessNetworkSourceIPList"][len_client_addr_list-1]["ipType"],
                                    "startIP":rcvd_data["accessNetworkSourceIPList"][len_client_addr_list-1]["startIP"],
                                    "endIP":rcvd_data["accessNetworkSourceIPList"][len_client_addr_list-1]["endIP"],
                                    "subnet":rcvd_data["accessNetworkSourceIPList"][len_client_addr_list-1]["subnet"],
                                    "network":rcvd_data["accessNetworkSourceIPList"][len_client_addr_list-1]["network"],
                                    "secret":""})


            #update to Single IP 
            if ip_type == "SingleIP":
                res_single_ip = self._update_ap_ip_single_ip(rcvd_data=rcvd_data, thirdparty_data=thirdparty_data, 
                                                    curr_ip_type=curr_ip_type, curr_ip_addr=curr_ip_addr, curr_subnet=curr_subnet,
                                                    curr_network=curr_network, curr_start_ip=curr_start_ip, curr_end_ip=curr_end_ip, 
                                                    ip_type=ip_type, ip_addr=ip_addr, secret=secret)

                if res_single_ip == False:
                    print "_update_ap_ip_single_ip() failed"
                    return False
                thirdparty_data.update(res_single_ip[0])
                _pos_update = res_single_ip[1]
            
            #update to  IPRange
            if ip_type == "IPRange":
                res_ip_range = self._update_ap_ip_range(rcvd_data=rcvd_data, thirdparty_data=thirdparty_data, curr_ip_type=curr_ip_type, 
                                                    curr_ip_addr=curr_ip_addr, curr_subnet=curr_subnet,
                                                    curr_network=curr_network, curr_start_ip=curr_start_ip, curr_end_ip=curr_end_ip,
                                                    ip_type=ip_type, start_ip=start_ip, end_ip=end_ip, secret=secret)

                if res_ip_range == False:
                    print "_update_ap_ip_range(): failed"
                    return False
                thirdparty_data.update(res_ip_range[0])
                _pos_update = res_ip_range[1]

            #update to Subnet
            if ip_type == "Subnet":
                res_subnet = self._update_ap_ip_subnet(rcvd_data=rcvd_data, thirdparty_data=thirdparty_data, curr_ip_type=curr_ip_type, 
                                                curr_ip_addr=curr_ip_addr, curr_subnet=curr_subnet,
                                                curr_network=curr_network, curr_start_ip=curr_start_ip, curr_end_ip=curr_end_ip,
                                                ip_type=ip_type, subnet=subnet, network=network, secret=secret)

                if res_subnet == False:
                    print "_update_ap_ip_subnet() failed"
                    return False
                thirdparty_data.update(res_subnet[0])
                _pos_update = res_subnet[1]

            #update_ the keys which are outside the list
            if vlan_mapping_type == "MapSPreserveC":
                thirdparty_data["vlanMappingList"] = []
                if rcvd_data["vlanMappingList"]:
                    for i in range(0, len(rcvd_data["vlanMappingList"])):
                        thirdparty_data["vlanMappingList"].append({"accessStart":rcvd_data["vlanMappingList"][i]["accessStart"],
                                                               "accessEnd":rcvd_data["vlanMappingList"][i]["accessEnd"],
                                                               "coreStart":rcvd_data["vlanMappingList"][i]["coreStart"],
                                                               "coreEnd":rcvd_data["vlanMappingList"][i]["coreEnd"]})


            thirdparty_data["qinqVLANTagList"] = []
            if rcvd_data["qinqVLANTagList"]:
                for i in range(0, len(rcvd_data["qinqVLANTagList"])):

                    thirdparty_data["qinqVLANTagList"].append({"startCVlan":rcvd_data["qinqVLANTagList"][i]["startCVlan"],
                                                           "endCVlan":rcvd_data["qinqVLANTagList"][i]["endCVlan"],
                                                           "startSVlan":rcvd_data["qinqVLANTagList"][i]["startSVlan"],
                                                           "endSVlan":rcvd_data["qinqVLANTagList"][i]["endSVlan"]})
            json_data = json.dumps(thirdparty_data)
            update_url = ji.get_url(self.req_api_thirdparty_apzone_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(update_url, self.jsessionid, json_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def _update_ap_ip_subnet(self, rcvd_data=None, thirdparty_data=None, curr_ip_type=None, curr_ip_addr=None, curr_subnet=None,
                                            curr_network=None, curr_start_ip=None, curr_end_ip=None,
                                            ip_type=None, subnet=None, network=None, secret=None):
        try:
            is_single_ip = False
            is_iprange_found = False
            is_subnet_found = False
            _pos_update = None

            if curr_ip_type == "SingleIP":
                for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                    if curr_ip_type == rcvd_data["accessNetworkSourceIPList"][i]["ipType"] and \
                    curr_ip_addr == rcvd_data["accessNetworkSourceIPList"][i]["ip"]:
                        is_single_ip = True
                        _pos_update = i
                        thirdparty_data["accessNetworkSourceIPList"][i].update({"ipType":rcvd_data["accessNetworkSourceIPList"][i]["ipType"] \
                                if not ip_type else ip_type,
                                                    "ip":"",
                                                    "startIP":"",
                                                    "endIP":"",
                                                    "subnet":rcvd_data["accessNetworkSourceIPList"][i]["subnet"] if not subnet else subnet,
                                                    "network":rcvd_data["accessNetworkSourceIPList"][i]["network"] if not network else network,
                                                    "secret":""}) #rcvd_data["accessNetworkSourceIPList"][i]["secret"] if not secret else secret})
                        break
                if is_single_ip == False:
                    print "_update_ap_ip_subnet(): singleIP of ipaddress not found"
                    return False

            elif curr_ip_type == "IPRange":
                for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                    if curr_ip_type == rcvd_data["accessNetworkSourceIPList"][i]["ipType"] and \
                        curr_start_ip == rcvd_data["accessNetworkSourceIPList"][i]["startIP"] and \
                        curr_end_ip == rcvd_data["accessNetworkSourceIPList"][i]["endIP"]:
                            is_iprange_found = True
                            _pos_update = i
                            thirdparty_data["accessNetworkSourceIPList"][i].update({"ipType":rcvd_data["accessNetworkSourceIPList"][i]["ipType"] \
                                                                                    if not ip_type else ip_type,
                                                                "ip":"",
                                                                "startIP":"",
                                                                "endIP":"",
                                                                "subnet":rcvd_data["accessNetworkSourceIPList"][i]["subnet"] if not subnet else subnet,
                                                                "network":rcvd_data["accessNetworkSourceIPList"][i]["network"] if not network else network,
                                                                "secret":""}) 
                                                                #rcvd_data["accessNetworkSourceIPList"][i]["secret"] if not secret else secret})
                            break
                if is_iprange_found == False:
                    print "_update_ap_ip_subnet(): IPrange not found"
                    return False

            elif curr_ip_type == "Subnet":
                for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                    if curr_ip_type == rcvd_data["accessNetworkSourceIPList"][i]["ipType"] and \
                        curr_subnet == rcvd_data["accessNetworkSourceIPList"][i]["subnet"] and \
                        curr_network == rcvd_data["accessNetworkSourceIPList"][i]["network"]:
                            is_subnet_found = True
                            _pos_update = i
                            thirdparty_data["accessNetworkSourceIPList"][i].update({"ipType":rcvd_data["accessNetworkSourceIPList"][i]["ipType"] \
                                                                                    if not ip_type else ip_type,
                                                                "ip":"",
                                                                "startIP":"",
                                                                "endIP":"",
                                                                "subnet":rcvd_data["accessNetworkSourceIPList"][i]["subnet"] if not subnet else subnet,
                                                                "network":rcvd_data["accessNetworkSourceIPList"][i]["network"] if not network else network,
                                                                "secret":""})
                                                                #rcvd_data["accessNetworkSourceIPList"][i]["secret"] if not secret else secret})
                            break
                if is_subnet_found == False:
                    print "_update_ap_ip_subnet(): subnet not found"
                    return False

            return thirdparty_data, _pos_update, True

        except Exception, e:
            print traceback.format_exc()
            return False

    def _update_ap_ip_range(self, rcvd_data=None, thirdparty_data=None, curr_ip_type=None, curr_ip_addr=None, curr_subnet=None,
                                        curr_network=None, curr_start_ip=None, curr_end_ip=None, 
                                        ip_type=None, start_ip=None, end_ip=None, secret=None):
        try:
            is_single_ip = False
            is_iprange_found = False
            is_subnet_found = False
            _pos_update = None
            if curr_ip_type == "SingleIP":
                for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                    if curr_ip_type == rcvd_data["accessNetworkSourceIPList"][i]["ipType"] and curr_ip_addr == \
                    rcvd_data["accessNetworkSourceIPList"][i]["ip"]:
                        is_single_ip = True
                        _pos_update = i
                        thirdparty_data["accessNetworkSourceIPList"][i].update({"ipType":rcvd_data["accessNetworkSourceIPList"][i]["ipType"] \
                                if not ip_type else ip_type,
                                                    "ip":"",
                                                    "startIP":rcvd_data["accessNetworkSourceIPList"][i]["startIP"] if not start_ip else start_ip,
                                                    "endIP":rcvd_data["accessNetworkSourceIPList"][i]["endIP"] if not end_ip else end_ip,
                                                    "subnet":"",
                                                    "network":"",
                                                    "secret":""}) #rcvd_data["clientAddressList"][i]["secret"] if not secret else secret})

                        break
                if is_single_ip == False:
                    print "_update_ap_ip_range(): singleIP of ipaddress not found"
                    return False

            elif curr_ip_type == "IPRange":
                for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                    if curr_ip_type == rcvd_data["accessNetworkSourceIPList"][i]["ipType"] and \
                        curr_start_ip == rcvd_data["accessNetworkSourceIPList"][i]["startIP"] and \
                        curr_end_ip == rcvd_data["accessNetworkSourceIPList"][i]["endIP"]:
                            is_iprange_found = True
                            _pos_update = i
                            thirdparty_data["accessNetworkSourceIPList"][i].update({"ipType":rcvd_data["accessNetworkSourceIPList"][i]["ipType"] \
                                                                                    if not ip_type else ip_type,
                                                                    "ip":"",
                                                                    "startIP":rcvd_data["accessNetworkSourceIPList"][i]["startIP"] \
                                                                            if not start_ip else start_ip,
                                                                    "endIP":rcvd_data["accessNetworkSourceIPList"][i]["endIP"] if not end_ip else end_ip,
                                                                    "subnet":"",
                                                                    "network":"",
                                                                    "secret":""}) #rcvd_data["clientAddressList"][i]["secret"] if not secret else secret})
                            break
                if is_iprange_found == False:
                    print "_update_ap_ip_range(): IPrange not found"
                    return False

            elif curr_ip_type == "Subnet":
                for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                    if curr_ip_type == rcvd_data["accessNetworkSourceIPList"][i]["ipType"] and \
                        curr_subnet == rcvd_data["accessNetworkSourceIPList"][i]["subnet"] and \
                        curr_network == rcvd_data["accessNetworkSourceIPList"][i]["network"]:
                            is_subnet_found = True
                            _pos_update = i
                            thirdparty_data["accessNetworkSourceIPList"][i].update({"ipType":rcvd_data["accessNetworkSourceIPList"][i]["ipType"] \
                                                                                    if not ip_type else ip_type,
                                                                    "ip":"",
                                                                    "startIP":rcvd_data["accessNetworkSourceIPList"][i]["startIP"] \
                                                                            if not start_ip else start_ip,
                                                                    "endIP":rcvd_data["accessNetworkSourceIPList"][i]["endIP"] if not end_ip else end_ip,
                                                                    "subnet":"",
                                                                    "network":"",
                                                                    "secret":rcvd_data["accessNetworkSourceIPList"][i]["secret"] if not secret else secret})
                            break
                if is_subnet_found == False:
                    print "_update_ap_ip_range(): subnet not found"
                    return False

            return thirdparty_data, _pos_update, True

        except Exception, e:
            print traceback.format_exc()
            return False
     
    def _update_ap_ip_single_ip(self, rcvd_data=None, thirdparty_data=None, curr_ip_type=None, curr_ip_addr=None, curr_subnet=None, 
                          curr_network=None, curr_start_ip=None, curr_end_ip=None, ip_type=None, ip_addr=None, secret=None):
        try:
            is_single_ip = False
            is_iprange_found = False
            is_subnet_found = False
            _pos_update = None 
            if curr_ip_type == "SingleIP":
                for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                    if curr_ip_type == rcvd_data["accessNetworkSourceIPList"][i]["ipType"] and \
                            curr_ip_addr == rcvd_data["accessNetworkSourceIPList"][i]["ip"]:
                        is_single_ip = True
                        _pos_update = i
                        thirdparty_data["accessNetworkSourceIPList"][i].update({"ipType":rcvd_data["accessNetworkSourceIPList"][i]["ipType"] \
                                if not ip_type else ip_type,
                                                    "ip":rcvd_data["accessNetworkSourceIPList"][i]["ip"] if not ip_addr else ip_addr,
                                                    "startIP":"",
                                                    "endIP":"",
                                                    "subnet":"",
                                                    "network":"",
                                                    "secret":""}) #rcvd_data["clientAddressList"][i]["secret"] if not secret else secret})
                        break
                if is_single_ip == False:
                    print "_update_ap_ip_single_ip(): singleIP of ipaddress not found"
                    return False

            elif curr_ip_type == "IPRange":
                for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                    if curr_ip_type == rcvd_data["accessNetworkSourceIPList"][i]["ipType"] and \
                        curr_start_ip == rcvd_data["accessNetworkSourceIPList"][i]["startIP"] and \
                        curr_end_ip == rcvd_data["accessNetworkSourceIPList"][i]["endIP"]:
                            _pos_update = i
                            is_iprange_found = True
                            thirdparty_data["accessNetworkSourceIPList"][i].update({"ipType":rcvd_data["accessNetworkSourceIPList"][i]["ipType"] \
                                                                                            if not ip_type else ip_type,
                                                    "ip":rcvd_data["clientAddressList"][i]["ip"] if not ip_addr else ip_addr,
                                                    "startIP":"",
                                                    "endIP":"",
                                                    "subnet":"",
                                                    "network":"",
                                                    "secret":""}) #rcvd_data["clientAddressList"][i]["secret"] if not secret else secret})

                            break
                if is_iprange_found == False:
                    print "_update_ap_ip_single_ip(): IPrange not found"
                    return False

            elif curr_ip_type == "Subnet":
                for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                    if curr_ip_type == rcvd_data["accessNetworkSourceIPList"][i]["ipType"] and \
                        curr_subnet == rcvd_data["accessNetworkSourceIPList"][i]["subnet"] and \
                        curr_network == rcvd_data["accessNetworkSourceIPList"][i]["network"]:
                            is_subnet_found = True
                            _pos_update = i
                            thirdparty_data["accessNetworkSourceIPList"][i].update({"ipType":rcvd_data["accessNetworkSourceIPList"][i]["ipType"] \
                                                                    if not ip_type else ip_type,
                                                    "ip":rcvd_data["accessNetworkSourceIPList"][i]["ip"] if not ip_addr else ip_addr,
                                                    "startIP":"",
                                                    "endIP":"",
                                                    "subnet":"",
                                                    "network":"",
                                                    "secret":""}) #rcvd_data["clientAddressList"][i]["secret"] if not secret else secret})
                            break

                if is_subnet_found == False:
                    print "_update_ap_ip_single_ip(): subnet not found"
                    return False

            return thirdparty_data, _pos_update, True

        except Exception, e:
            print traceback.format_exc()
            return False


    def delete_ap_ipaddr_from_third_party_apzone(self, zone_name="Auto_ThrdPrty_Zone", domain_label='Administration Domain',
                                ip_type="IPRange", ip_addr="1.2.3.4",
                                start_ip=None, end_ip=None,
                                subnet=None, network=None, 
                                secret=None):
        """
        API used to delete the AP enrty form thirdparty APZone

        URI: PUT /wsg/api/scg/zones/thirdparty/<third_party_apzone_key>

        :param str zone_name: Thirdparty APZone name
        :param str domain_label: Name of Domain
        :param str ip_type: SingleIP | IPRange | Subnet
        :param str ip_addr: IP Address
        :param str start_ip: Start IP Address
        :param str end_ip: End IP Address
        :param str subnet: Subnet
        :param str network: network
        :param str secret: Secret
        :return: True if AP IP enrty deleted from thirdparty APZone else False
        :rtype: boolean

        """

        result = False
        thirdparty_data = {}
        try:
            url = ji.get_url(self.req_api_thirdparty_apzone_updt_del1%self.get_domain_uuid(domain_label=domain_label), self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_thirdparty_apzone(url, zone_name)
            vlan_mapping_type = None
            vlan_mapping_type = rcvd_data["vlanMappingType"]
            thirdparty_data["key"] = rcvd_data["key"]
            thirdparty_data["zoneIntId"] = str(rcvd_data["zoneIntId"])
            thirdparty_data["zoneName"] = rcvd_data["zoneName"]
            thirdparty_data["accessNetworkType"] = rcvd_data["accessNetworkType"]
            thirdparty_data["networkTrafficPackageId"] = rcvd_data["networkTrafficPackageId"]
            thirdparty_data["description"] = rcvd_data["description"]
            thirdparty_data["coreNetworkType"] = rcvd_data["coreNetworkType"]
            thirdparty_data["authType"] = rcvd_data["authType"]

            if rcvd_data["authServiceProfileId"]:
                thirdparty_data["authServiceProfileId"] = rcvd_data["authServiceProfileId"]

            thirdparty_data["acctServiceProfileId"] = rcvd_data["acctServiceProfileId"]
            thirdparty_data["subscriberPackageId"] = rcvd_data["subscriberPackageId"]

            if rcvd_data["forwardingServiceProfileId"]:
                thirdparty_data["forwardingServiceProfileId"] = rcvd_data["forwardingServiceProfileId"]

            thirdparty_data["acctUpdateInterval"] = rcvd_data["acctUpdateInterval"]
            thirdparty_data["coreQinQEnabled"] = rcvd_data["coreQinQEnabled"]
            thirdparty_data["vlanMappingType"] = rcvd_data["vlanMappingType"]
            thirdparty_data["coreAddFixedVlan"] = rcvd_data["coreAddFixedVlan"]
            thirdparty_data["coreAddFixedSVlan"] = rcvd_data["coreAddFixedSVlan"]
            thirdparty_data["defaultShareSecret"] = rcvd_data["defaultShareSecret"]
            thirdparty_data["clientAddressList"] = []
            thirdparty_data["accessNetworkSourceIPList"] = []

            if rcvd_data["clientAddressList"]:
                for i in range(0, len(rcvd_data["clientAddressList"])):
                    thirdparty_data["clientAddressList"].append({"ip":rcvd_data["clientAddressList"][i]["ip"],
                                                                "startIP":rcvd_data["clientAddressList"][i]["startIP"],
                                                                "endIP":rcvd_data["clientAddressList"][i]["endIP"],
                                                                "subnet":rcvd_data["clientAddressList"][i]["subnet"],
                                                                "network":rcvd_data["clientAddressList"][i]["network"],
                                                                "ipType":rcvd_data["clientAddressList"][i]["ipType"],
                                                                "secret":rcvd_data["clientAddressList"][i]["secret"]})

            if rcvd_data["accessNetworkSourceIPList"]:
                for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                    thirdparty_data["accessNetworkSourceIPList"].append({"ip":rcvd_data["accessNetworkSourceIPList"][i]["ip"],
                                                                     "startIP":rcvd_data["accessNetworkSourceIPList"][i]["startIP"],
                                                                     "endIP":rcvd_data["accessNetworkSourceIPList"][i]["endIP"],
                                                                     "subnet":rcvd_data["accessNetworkSourceIPList"][i]["subnet"],
                                                                     "network":rcvd_data["accessNetworkSourceIPList"][i]["network"],
                                                                     "ipType":rcvd_data["accessNetworkSourceIPList"][i]["ipType"],
                                                                     "secret":""})
 

            if ip_type == "SingleIP":
                is_single_ip_found = False
                for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                    if ip_type == rcvd_data["accessNetworkSourceIPList"][i]["ipType"] and ip_addr == rcvd_data["accessNetworkSourceIPList"][i]["ip"]:
                        is_single_ip_found = True
                        del thirdparty_data["accessNetworkSourceIPList"][i]
                        break
                if is_single_ip_found == False:
                    print "delete_ap_ip_client(): single ip %s not found" %(ip_addr)
                    return False

            elif ip_type == "IPRange":
                is_iprange_found = False
                for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                    if ip_type == rcvd_data["accessNetworkSourceIPList"][i]["ipType"] and \
                        start_ip == rcvd_data["accessNetworkSourceIPList"][i]["startIP"] and \
                        end_ip == rcvd_data["accessNetworkSourceIPList"][i]["endIP"]:
                            is_iprange_found = True
                            del thirdparty_data["accessNetworkSourceIPList"][i]
                            break
                if is_iprange_found == False:
                    print "delete_ap_ip_client(): IPRange start_ip %s  and  end_ip %s not found" % (start_ip, end_ip)
                    return False
            elif ip_type == "Subnet":
                is_subnet_found = False
                for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                    if ip_type == rcvd_data["accessNetworkSourceIPList"][i]["ipType"] and \
                        subnet == rcvd_data["accessNetworkSourceIPList"][i]["subnet"] and \
                        network == rcvd_data["accessNetworkSourceIPList"][i]["network"]:
                            is_subnet_found = True
                            del thirdparty_data["accessNetworkSourceIPList"][i]
                            break
                if is_subnet_found == False:
                    print "delete_ap_ip_client():subnet %s and network %s not found" % (subnet, network)
                    return False

            _ip_addr_updated = []
            _start_ip_updated = []
            _end_ip_updated = []
            _subnet_updated = []
            _network_updated = []
            _ip_type_updated = []
            _secret_updated = []

            for i in range(0, len(thirdparty_data["clientAddressList"])):
                    _start_ip_updated.append(thirdparty_data["clientAddressList"][i]["startIP"])
                    _end_ip_updated.append(thirdparty_data["clientAddressList"][i]["endIP"])
                    _subnet_updated.append(thirdparty_data["clientAddressList"][i]["subnet"])
                    _network_updated.append(thirdparty_data["clientAddressList"][i]["network"])
                    _ip_type_updated.append(thirdparty_data["clientAddressList"][i]["ipType"])
                    _secret_updated.append(thirdparty_data["clientAddressList"][i]["secret"])

            thirdparty_data.update({"ip":_ip_addr_updated,
                                    "ipType":_ip_type_updated,
                                    "startIP":_start_ip_updated,
                                    "endIP":_end_ip_updated,
                                    "subnet":_subnet_updated,
                                    "network":_network_updated,
                                    "secret":_secret_updated})
            
            if vlan_mapping_type == "MapSPreserveC":
                thirdparty_data["vlanMappingList"] = []
                if rcvd_data["vlanMappingList"]:
                    for i in range(0, len(rcvd_data["vlanMappingList"])):
                        thirdparty_data["vlanMappingList"].append({"accessStart":rcvd_data["vlanMappingList"][i]["accessStart"],
                                                               "accessEnd":rcvd_data["vlanMappingList"][i]["accessEnd"],
                                                               "coreStart":rcvd_data["vlanMappingList"][i]["coreStart"],
                                                               "coreEnd":rcvd_data["vlanMappingList"][i]["coreEnd"]})


            thirdparty_data["qinqVLANTagList"] = []
            if rcvd_data["qinqVLANTagList"]:
                for i in range(0, len(rcvd_data["qinqVLANTagList"])):
                    thirdparty_data["qinqVLANTagList"].append({"startCVlan":rcvd_data["qinqVLANTagList"][i]["startCVlan"],
                                                           "endCVlan":rcvd_data["qinqVLANTagList"][i]["endCVlan"],
                                                           "startSVlan":rcvd_data["qinqVLANTagList"][i]["startSVlan"],
                                                           "endSVlan":rcvd_data["qinqVLANTagList"][i]["endSVlan"]})

            json_data = json.dumps(thirdparty_data)
            update_url = ji.get_url(self.req_api_thirdparty_apzone_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(update_url, self.jsessionid, json_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result




    def delete_radius_ip_from_third_party_apzone(self, zone_name="Auto_ThrdPrty_Zone", domain_label='Administration Domain',
                                ip_type="IPRange", ip_addr="1.2.3.4", 
                                start_ip=None, end_ip=None,
                                subnet=None, network=None,):
                                #secret=None):
        """
        API used to delete the Radius Client enrty form thirdparty APZone

        URI: PUT /wsg/api/scg/zones/thirdparty/<third_party_apzone_key>

        :param str zone_name: Thirdparty APZone name
        :param str domain_label: Name of Domain
        :param str ip_type: SingleIP | IPRange | Subnet
        :param str ip_addr: IP Address
        :param str start_ip: Start IP Address
        :param str end_ip: End IP Address
        :param str subnet: Subnet
        :param str network: network
        :param str secret: Secret
        :return: True if Radius Client enrty deleted from thirdparty APZone else False
        :rtype: boolean

        """

        result = False
        thirdparty_data = {}
        try:
            url = ji.get_url(self.req_api_thirdparty_apzone_updt_del1%self.get_domain_uuid(domain_label=domain_label), self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_thirdparty_apzone(url, zone_name)
            vlan_mapping_type = None
            vlan_mapping_type = rcvd_data["vlanMappingType"]
            thirdparty_data["key"] = rcvd_data["key"]
            thirdparty_data["zoneIntId"] = str(rcvd_data["zoneIntId"])
            thirdparty_data["zoneName"] = rcvd_data["zoneName"]
            thirdparty_data["accessNetworkType"] = rcvd_data["accessNetworkType"]
            thirdparty_data["networkTrafficPackageId"] = rcvd_data["networkTrafficPackageId"]
            thirdparty_data["description"] = rcvd_data["description"]
            thirdparty_data["coreNetworkType"] = rcvd_data["coreNetworkType"]
            thirdparty_data["authType"] = rcvd_data["authType"]

            if rcvd_data["authServiceProfileId"]:
                thirdparty_data["authServiceProfileId"] = rcvd_data["authServiceProfileId"]

            thirdparty_data["acctServiceProfileId"] = rcvd_data["acctServiceProfileId"]
            thirdparty_data["subscriberPackageId"] = rcvd_data["subscriberPackageId"]

            if rcvd_data["forwardingServiceProfileId"]:
                thirdparty_data["forwardingServiceProfileId"] = rcvd_data["forwardingServiceProfileId"]

            thirdparty_data["acctUpdateInterval"] = rcvd_data["acctUpdateInterval"]
            thirdparty_data["coreQinQEnabled"] = rcvd_data["coreQinQEnabled"]
            thirdparty_data["vlanMappingType"] = rcvd_data["vlanMappingType"]
            thirdparty_data["coreAddFixedVlan"] = rcvd_data["coreAddFixedVlan"]
            thirdparty_data["coreAddFixedSVlan"] = rcvd_data["coreAddFixedSVlan"]
            thirdparty_data["defaultShareSecret"] = rcvd_data["defaultShareSecret"]
            thirdparty_data["clientAddressList"] = []
            if rcvd_data["clientAddressList"]:
                for i in range(0, len(rcvd_data["clientAddressList"])):
                    thirdparty_data["clientAddressList"].append({"ip":rcvd_data["clientAddressList"][i]["ip"],
                                                                "startIP":rcvd_data["clientAddressList"][i]["startIP"],
                                                                "endIP":rcvd_data["clientAddressList"][i]["endIP"],
                                                                "subnet":rcvd_data["clientAddressList"][i]["subnet"],
                                                                "network":rcvd_data["clientAddressList"][i]["network"],
                                                                "ipType":rcvd_data["clientAddressList"][i]["ipType"],
                                                                "secret":rcvd_data["clientAddressList"][i]["secret"]})

            thirdparty_data.update({"accessNetworkSourceIPList":[]})
            if rcvd_data["accessNetworkSourceIPList"]:
                for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                    thirdparty_data["accessNetworkSourceIPList"].append({"ip":rcvd_data["accessNetworkSourceIPList"][i]["ip"],
                                                                         "startIP":rcvd_data["accessNetworkSourceIPList"][i]["startIP"],
                                                                         "endIP":rcvd_data["accessNetworkSourceIPList"][i]["endIP"],
                                                                         "subnet":rcvd_data["accessNetworkSourceIPList"][i]["subnet"],
                                                                         "network":rcvd_data["accessNetworkSourceIPList"][i]["network"],
                                                                         "ipType":rcvd_data["accessNetworkSourceIPList"][i]["ipType"],
                                                                         "secret":""})


            
            if ip_type == "SingleIP":
                is_single_ip_found = False
                for i in range(0, len(rcvd_data["clientAddressList"])):
                    if ip_type == rcvd_data["clientAddressList"][i]["ipType"] and ip_addr == rcvd_data["clientAddressList"][i]["ip"]:
                        is_single_ip_found = True
                        del thirdparty_data["clientAddressList"][i]
                        break
                if is_single_ip_found == False:
                    print "delete_radius_ip_client(): single ip %s not found" %(ip_addr)
                    return False

            elif ip_type == "IPRange":
                is_iprange_found = False
                for i in range(0, len(rcvd_data["clientAddressList"])):
                    if ip_type == rcvd_data["clientAddressList"][i]["ipType"] and \
                        start_ip == rcvd_data["clientAddressList"][i]["startIP"] and \
                        end_ip == rcvd_data["clientAddressList"][i]["endIP"]:
                            is_iprange_found = True
                            del thirdparty_data["clientAddressList"][i]
                            break
                if is_iprange_found == False:
                    print "delete_radius_ip_client(): IPRange start_ip %s  and  end_ip %s not found" % (start_ip, end_ip)
                    return False
            elif ip_type == "Subnet":
                is_subnet_found = False
                for i in range(0, len(rcvd_data["clientAddressList"])):
                    if ip_type == rcvd_data["clientAddressList"][i]["ipType"] and \
                        subnet == rcvd_data["clientAddressList"][i]["subnet"] and \
                        network == rcvd_data["clientAddressList"][i]["network"]:
                            is_subnet_found = True
                            del thirdparty_data["clientAddressList"][i]
                            break
                if is_subnet_found == False:
                    print "delete_radius_ip_client():subnet %s and network %s not found" % (subnet, network)
                    return False

            _ip_addr_updated = []
            _start_ip_updated = []
            _end_ip_updated = []
            _subnet_updated = []
            _network_updated = []
            _ip_type_updated = []
            _secret_updated = []

            for i in range(0, len(thirdparty_data["clientAddressList"])):
                    _start_ip_updated.append(thirdparty_data["clientAddressList"][i]["startIP"])
                    _end_ip_updated.append(thirdparty_data["clientAddressList"][i]["endIP"])
                    _subnet_updated.append(thirdparty_data["clientAddressList"][i]["subnet"])
                    _network_updated.append(thirdparty_data["clientAddressList"][i]["network"])
                    _ip_type_updated.append(thirdparty_data["clientAddressList"][i]["ipType"])
                    _secret_updated.append(thirdparty_data["clientAddressList"][i]["secret"])

            thirdparty_data.update({"ip":_ip_addr_updated,
                                    "ipType":_ip_type_updated,
                                    "startIP":_start_ip_updated,
                                    "endIP":_end_ip_updated,
                                    "subnet":_subnet_updated,
                                    "network":_network_updated,
                                    "secret":_secret_updated})
            
            if vlan_mapping_type == "MapSPreserveC":
                thirdparty_data["vlanMappingList"] = []
                if rcvd_data["vlanMappingList"]:
                    for i in range(0, len(rcvd_data["vlanMappingList"])):
                        thirdparty_data["vlanMappingList"].append({"accessStart":rcvd_data["vlanMappingList"][i]["accessStart"],
                                                               "accessEnd":rcvd_data["vlanMappingList"][i]["accessEnd"],
                                                               "coreStart":rcvd_data["vlanMappingList"][i]["coreStart"],
                                                               "coreEnd":rcvd_data["vlanMappingList"][i]["coreEnd"]})


            thirdparty_data["qinqVLANTagList"] = []
            if rcvd_data["qinqVLANTagList"]:
                for i in range(0, len(rcvd_data["qinqVLANTagList"])):

                    thirdparty_data["qinqVLANTagList"].append({"startCVlan":rcvd_data["qinqVLANTagList"][i]["startCVlan"],
                                                           "endCVlan":rcvd_data["qinqVLANTagList"][i]["endCVlan"],
                                                           "startSVlan":rcvd_data["qinqVLANTagList"][i]["startSVlan"],
                                                           "endSVlan":rcvd_data["qinqVLANTagList"][i]["endSVlan"]})

            json_data = json.dumps(thirdparty_data)
            update_url = ji.get_url(self.req_api_thirdparty_apzone_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(update_url, self.jsessionid, json_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result


    def add_svlan_cvlan_to_third_party_apzone(self, zone_name="Auto_ThrdPrty_Zone", 
                                                    domain_label='Administration Domain', 
                                                    start_cvlan='20', 
                                                    end_cvlan='21', 
                                                    start_svlan='22', 
                                                    end_svlan='23'):

        """
        Adds Access SVALN range and CVLAN range to third party apzone

        URI: PUT /wsg/api/scg/zones/thirdparty/<third_party_apzone_key>

        :param str zone_name: Name of Thirdparty APzone
        :param str start_cvaln: Access CVALN range start value
        :param str end_cvlan: Access CVALN range end value
        :param str start_svaln: Access SVLAN range start value
        :param str end_svlan: Access SVLAN range end value
        :return: True if SVLAN and CVLAN addedd to Thirdparty apzone
        :rtype: boolean

        """

        result = False
        thirdparty_data = {}
        try:
            url = ji.get_url(self.req_api_thirdparty_apzone_updt_del1%self.get_domain_uuid(domain_label=domain_label), self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_thirdparty_apzone(url, zone_name)
            vlan_mapping_type = None
            vlan_mapping_type = rcvd_data["vlanMappingType"]
            thirdparty_data["key"] = rcvd_data["key"]
            thirdparty_data["zoneIntId"] = str(rcvd_data["zoneIntId"])
            thirdparty_data["zoneName"] = rcvd_data["zoneName"]
            thirdparty_data["accessNetworkType"] = rcvd_data["accessNetworkType"]
            thirdparty_data["networkTrafficPackageId"] = rcvd_data["networkTrafficPackageId"]
            thirdparty_data["description"] = rcvd_data["description"]
            thirdparty_data["coreNetworkType"] = rcvd_data["coreNetworkType"]
            thirdparty_data["authType"] = rcvd_data["authType"]

            if rcvd_data["authServiceProfileId"]:
                thirdparty_data["authServiceProfileId"] = rcvd_data["authServiceProfileId"]

            thirdparty_data["acctServiceProfileId"] = rcvd_data["acctServiceProfileId"]
            thirdparty_data["subscriberPackageId"] = rcvd_data["subscriberPackageId"]

            if rcvd_data["forwardingServiceProfileId"]:
                thirdparty_data["forwardingServiceProfileId"] = rcvd_data["forwardingServiceProfileId"]

            thirdparty_data["acctUpdateInterval"] = rcvd_data["acctUpdateInterval"]
            thirdparty_data["coreQinQEnabled"] = rcvd_data["coreQinQEnabled"]
            thirdparty_data["vlanMappingType"] = rcvd_data["vlanMappingType"]
            thirdparty_data["coreAddFixedVlan"] = rcvd_data["coreAddFixedVlan"]
            thirdparty_data["coreAddFixedSVlan"] = rcvd_data["coreAddFixedSVlan"]
            thirdparty_data["defaultShareSecret"] = rcvd_data["defaultShareSecret"]
            len_list_client_address = len(rcvd_data["clientAddressList"])

            thirdparty_data["ipType"] = rcvd_data["clientAddressList"][len_list_client_address-1]["ipType"]
            
            thirdparty_data["subnet"] = rcvd_data["clientAddressList"][len_list_client_address-1]["subnet"]
            thirdparty_data["startIP"] = rcvd_data["clientAddressList"][len_list_client_address-1]["startIP"]
            thirdparty_data["endIP"] = rcvd_data["clientAddressList"][len_list_client_address-1]["endIP"]
            thirdparty_data["ip"] = rcvd_data["clientAddressList"][len_list_client_address-1]["ip"]
            thirdparty_data["subnet"] = rcvd_data["clientAddressList"][len_list_client_address-1]["subnet"]
            thirdparty_data["secret"] = rcvd_data["clientAddressList"][len_list_client_address-1]["secret"]
            thirdparty_data["network"] = rcvd_data["clientAddressList"][len_list_client_address-1]["network"]

            thirdparty_data["clientAddressList"] = copy.deepcopy(rcvd_data["clientAddressList"])


            if vlan_mapping_type == "MapSPreserveC":
                thirdparty_data["vlanMappingList"] = []
                if rcvd_data["vlanMappingList"]:
                    for i in range(0, len(rcvd_data["vlanMappingList"])):
                        thirdparty_data["vlanMappingList"].append({"accessStart":rcvd_data["vlanMappingList"][i]["accessStart"],
                                                               "accessEnd":rcvd_data["vlanMappingList"][i]["accessEnd"],
                                                               "coreStart":rcvd_data["vlanMappingList"][i]["coreStart"],
                                                               "coreEnd":rcvd_data["vlanMappingList"][i]["coreEnd"]})

                    for i in range(0, len(rcvd_data["vlanMappingList"])):
                        if start_svlan == rcvd_data["vlanMappingList"][i]["accessStart"] or \
                        end_svlan == rcvd_data["vlanMappingList"][i]["accessEnd"]:
                            print "add_svlan_cvlan_to_third_party_apzone():SVlan range have been covered"
                            return False
                       
                thirdparty_data["vlanMappingList"].append({"accessStart":start_svlan,
                                                               "accessEnd":end_svlan,
                                                               "coreStart":start_svlan,
                                                               "coreEnd":end_svlan})
            thirdparty_data["qinqVLANTagList"] = []
            for i in range(0, len(rcvd_data["qinqVLANTagList"])):
                thirdparty_data["qinqVLANTagList"].append({"startCVlan":rcvd_data["qinqVLANTagList"][i]["startCVlan"],
                                                           "endCVlan":rcvd_data["qinqVLANTagList"][i]["endCVlan"],
                                                           "startSVlan":rcvd_data["qinqVLANTagList"][i]["startSVlan"],
                                                           "endSVlan":rcvd_data["qinqVLANTagList"][i]["endSVlan"]})

            for i in range(0, len(rcvd_data["qinqVLANTagList"])):
                if start_cvlan == rcvd_data["qinqVLANTagList"][i]["startCVlan"] or \
                    end_cvlan == rcvd_data["qinqVLANTagList"][i]["endCVlan"] or \
                    start_svlan == rcvd_data["qinqVLANTagList"][i]["startSVlan"] or \
                    end_svlan == rcvd_data["qinqVLANTagList"][i]["endSVlan"]:
                    print "Svlan or Cvlan entered have been covered"
                    return False
            thirdparty_data["qinqVLANTagList"].append({"startCVlan":start_cvlan,
                                                              "endCVlan":end_cvlan,
                                                              "startSVlan":start_svlan,
                                                              "endSVlan":end_svlan})


            json_data = json.dumps(thirdparty_data)
            update_url = ji.get_url(self.req_api_thirdparty_apzone_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(update_url, self.jsessionid, json_data)


        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def validate_svlan_cvlan_to_third_party_apzone(self, zone_name="Auto_ThrdPrty_Zone", domain_label='Administration Domain',
                                                    start_cvlan='10', 
                                                    end_cvlan='20', 
                                                    start_svlan=None, 
                                                    end_svlan=None):
        """                                       
        API used to validate Access SVALN range and CVLAN range in third party apzone
                                                  
        URI: PUT /wsg/api/scg/zones/thirdparty/byDomain/<domain_uuid>
                                                  
        :param str zone_name: Name of Thirdparty APzone
        :param str domain_label: Name of the Domain
        :param str start_cvaln: Access CVALN range start value
        :param str end_cvlan: Access CVALN range end value
        :param str start_svaln: Access SVLAN range start value
        :param str end_svlan: Access SVLAN range end value
        :return: True if SVLAN and CVLAN validated in Thirdparty apzone else False
        :rtype: boolean

        """

        try:
            url = ji.get_url(self.req_api_thirdparty_apzone_updt_del1%self.get_domain_uuid(domain_label=domain_label), self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_thirdparty_apzone(url, zone_name)
            
            is_valn_entry_found = False
            expect_result = (True if start_cvlan else False, True if end_cvlan else False, True if start_svlan else False, True if end_svlan else False)
            actual_res = None
            for i in range(0, len(rcvd_data["qinqVLANTagList"])):
                is_start_cvlan = False
                is_end_cvlan = False
                is_start_svaln = False
                is_end_svlan = False

                if start_cvlan:
                    if start_cvlan == str(rcvd_data["qinqVLANTagList"][i]["startCVlan"]):
                        is_start_cvlan = True
                if end_cvlan:
                    if end_cvlan == str(rcvd_data["qinqVLANTagList"][i]["endCVlan"]):
                        is_end_cvlan = True
                if start_svlan:
                    if start_svlan == str(rcvd_data["qinqVLANTagList"][i]["startSVlan"]):
                        is_start_svaln = True
                if end_svlan:
                    if end_svlan == str(rcvd_data["qinqVLANTagList"][i]["endSVlan"]):
                        is_end_svlan = True
                actual_res = (is_start_cvlan, is_end_cvlan, is_start_svaln, is_end_svlan)
                if expect_result == actual_res:
                    is_valn_entry_found = True
                    break

            if is_valn_entry_found == False:
                self._print_err_validate('validate_svlan_cvlan_to_third_party_apzone', 'actual_res', 'expect_result', actual_res, expect_result)
                return False

            return True
        except Exception, e:
            print traceback.format_exc()
            return False

    

    def update_svlan_cvlan_to_third_party_apzone(self, zone_name="Auto_ThrdPrty_Zone", domain_label='Administration Domain',
                                access_svlan_start=None, access_svlan_end=None,
                                start_cvlan=None, end_cvlan=None, 
                                start_svaln=None, end_svlan=None):
        """
        updates Access SVALN range and CVLAN range to Third party APZone
                                                  
        URI: PUT /wsg/api/scg/zones/thirdparty/<third_party_apzone_key>
                                                  
        :param str zone_name: Name of Thirdparty APzone
        :param str domain_label: Name of the Domain
        :param str access_svlan_start: Access SVLAN start value
        :param str access_svlan_end: Access SVLAN end value
        :param str start_cvaln: Access CVALN range start value
        :param str end_cvlan: Access CVALN range end value
        :param str start_svaln: Access SVLAN range start value
        :param str end_svlan: Access SVLAN range end value
        :return: True if SVLAN and CVLAN updated to Thirdparty apzone else False
        :rtype: boolean

        """

        result = False
        is_found = False
        is_entry_found = False
        thirdparty_data = {}
        try:
            url = ji.get_url(self.req_api_thirdparty_apzone_updt_del1%self.get_domain_uuid(domain_label=domain_label), self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_thirdparty_apzone(url, zone_name)
            vlan_mapping_type = None
            vlan_mapping_type = rcvd_data["vlanMappingType"]
            thirdparty_data["key"] = rcvd_data["key"]
            thirdparty_data["zoneIntId"] = str(rcvd_data["zoneIntId"])
            thirdparty_data["zoneName"] = rcvd_data["zoneName"] 
            thirdparty_data["accessNetworkType"] = rcvd_data["accessNetworkType"] 
            thirdparty_data["networkTrafficPackageId"] = rcvd_data["networkTrafficPackageId"] 
            thirdparty_data["description"] = rcvd_data["description"]
            thirdparty_data["coreNetworkType"] = rcvd_data["coreNetworkType"]
            thirdparty_data["authType"] = rcvd_data["authType"]

            if rcvd_data["authServiceProfileId"]:
                thirdparty_data["authServiceProfileId"] = rcvd_data["authServiceProfileId"]

            thirdparty_data["acctServiceProfileId"] = rcvd_data["acctServiceProfileId"]
            thirdparty_data["subscriberPackageId"] = rcvd_data["subscriberPackageId"]

            if rcvd_data["forwardingServiceProfileId"]:
                thirdparty_data["forwardingServiceProfileId"] = rcvd_data["forwardingServiceProfileId"]

            thirdparty_data["acctUpdateInterval"] = rcvd_data["acctUpdateInterval"]
            thirdparty_data["coreQinQEnabled"] = rcvd_data["coreQinQEnabled"]
            thirdparty_data["vlanMappingType"] = rcvd_data["vlanMappingType"]
            thirdparty_data["coreAddFixedVlan"] = rcvd_data["coreAddFixedVlan"]
            thirdparty_data["coreAddFixedSVlan"] = rcvd_data["coreAddFixedSVlan"]
            thirdparty_data["defaultShareSecret"] = rcvd_data["defaultShareSecret"] 
            len_list_client_address = len(rcvd_data["clientAddressList"])

            thirdparty_data["ipType"] = rcvd_data["clientAddressList"][len_list_client_address-1]["ipType"]
            thirdparty_data["subnet"] = rcvd_data["clientAddressList"][len_list_client_address-1]["subnet"]
            thirdparty_data["startIP"] = rcvd_data["clientAddressList"][len_list_client_address-1]["startIP"]
            thirdparty_data["endIP"] = rcvd_data["clientAddressList"][len_list_client_address-1]["endIP"]
            thirdparty_data["ip"] = rcvd_data["clientAddressList"][len_list_client_address-1]["ip"]
            thirdparty_data["subnet"] = rcvd_data["clientAddressList"][len_list_client_address-1]["subnet"]
            thirdparty_data["secret"] = rcvd_data["clientAddressList"][len_list_client_address-1]["secret"]
            thirdparty_data["network"] = rcvd_data["clientAddressList"][len_list_client_address-1]["network"]

            thirdparty_data["clientAddressList"] = copy.deepcopy(rcvd_data["clientAddressList"])


            if vlan_mapping_type == "MapSPreserveC":
                for i in range(0, len(rcvd_data["vlanMappingList"])):
                    thirdparty_data["vlanMappingList"].append({"accessStart":rcvd_data["vlanMappingList"][i]["accessStart"],
                                                               "accessEnd":rcvd_data["vlanMappingList"][i]["accessEnd"],
                                                               "coreStart":rcvd_data["vlanMappingList"][i]["coreStart"],
                                                               "coreEnd":rcvd_data["vlanMappingList"][i]["coreEnd"]})
                for i in range(0, len(rcvd_data["vlanMappingList"])):
                    if start_svaln == rcvd_data["vlanMappingList"][i]["accessStart"] or \
                       end_svlan == rcvd_data["vlanMappingList"][i]["accessEnd"]:
                        print "update_svlan_cvlan_to_third_party_apzone():SVlan is already covered"
                        return False

                for i in range(0, len(rcvd_data["vlanMappingList"])):
                    if access_svlan_start == rcvd_data["vlanMappingList"][i]["accessStart"] and \
                        access_svlan_end == rcvd_data["vlanMappingList"][i]["accessEnd"]:
                        is_entry_found = True
                        thirdparty_data["vlanMappingList"][i].update({"accessStart":start_svaln,
                                                               "accessEnd":end_svlan,
                                                               "coreStart":start_svaln,
                                                               "coreEnd":end_svlan})
                        break
                if is_entry_found == False:
                    print "update_svlan_cvlan_to_third_party_apzone():access SVlan range not found "
                    return False

            thirdparty_data["qinqVLANTagList"] = []
            for i in range(0, len(rcvd_data["qinqVLANTagList"])):
                thirdparty_data["qinqVLANTagList"].append({"startCVlan":rcvd_data["qinqVLANTagList"][i]["startCVlan"],
                                                           "endCVlan":rcvd_data["qinqVLANTagList"][i]["endCVlan"],
                                                           "startSVlan":rcvd_data["qinqVLANTagList"][i]["startSVlan"],
                                                           "endSVlan":rcvd_data["qinqVLANTagList"][i]["endSVlan"]})
            for i in range(0, len(rcvd_data["qinqVLANTagList"])):
                if start_cvlan == rcvd_data["qinqVLANTagList"][i]["startCVlan"] or \
                   end_cvlan == rcvd_data["qinqVLANTagList"][i]["endCVlan"] or \
                   start_svaln == rcvd_data["qinqVLANTagList"][i]["startSVlan"] or \
                   end_svlan == rcvd_data["qinqVLANTagList"][i]["endSVlan"]:
                    print "update_svlan_cvlan_to_third_party_apzone():SVlan or CVlan is already covered"
                    return False

            for i in range(0, len(rcvd_data["qinqVLANTagList"])):
                if access_svlan_start == str(rcvd_data["qinqVLANTagList"][i]["startSVlan"]) and \
                        access_svlan_end == str(rcvd_data["qinqVLANTagList"][i]["endSVlan"]):
                        is_found = True
                        thirdparty_data["qinqVLANTagList"][i].update({"startCVlan":start_cvlan,
                                                              "endCVlan":end_cvlan,
                                                              "startSVlan":start_svaln,
                                                              "endSVlan":end_svlan})
                        break

            if is_found == False:
                print "update_svlan_cvlan_to_third_party_apzone():access SVlan range not found"
                return False

            json_data = json.dumps(thirdparty_data)
            update_url = ji.get_url(self.req_api_thirdparty_apzone_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(update_url, self.jsessionid, json_data)

        
        except Exception, e:
            print traceback.format_exc()
            return False 

        return result

    def delete_svlan_cvlan_in_third_party_apzone(self, zone_name="Auto_ThrdPrty_Zone", domain_label='Administration Domain',
                                                       svlan_start='22', svlan_end='23'):
        """
        API used to delete SVLAN and CVLAN entry from Thirdparty APZone

        URI: PUT /wsg/api/scg/zones/thirdparty/<third_party_apzone_key>

        :param str zone_name: Thirdparty APZone name
        :param str domain_label: name of the Domain
        :param str svlan_start: SVLAN start value
        :param str svlan_end: SVLAN end value
        :return: True if SVLAN and CVLAN entry deleted from Thirdparty APZone else False
        :rtype: boolean

        """

        result = False
        is_found = False
        is_entry_found = False
        thirdparty_data = {}
        try:
            url = ji.get_url(self.req_api_thirdparty_apzone_updt_del1%self.get_domain_uuid(domain_label=domain_label), self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_thirdparty_apzone(url, zone_name)
            vlan_mapping_type = None
            vlan_mapping_type = rcvd_data["vlanMappingType"]
            thirdparty_data["key"] = rcvd_data["key"]
            thirdparty_data["zoneIntId"] = str(rcvd_data["zoneIntId"])
            thirdparty_data["zoneName"] = rcvd_data["zoneName"]
            thirdparty_data["accessNetworkType"] = rcvd_data["accessNetworkType"]
            thirdparty_data["networkTrafficPackageId"] = rcvd_data["networkTrafficPackageId"]
            thirdparty_data["description"] = rcvd_data["description"]
            thirdparty_data["coreNetworkType"] = rcvd_data["coreNetworkType"]
            thirdparty_data["authType"] = rcvd_data["authType"]

            if rcvd_data["authServiceProfileId"]:
                thirdparty_data["authServiceProfileId"] = rcvd_data["authServiceProfileId"]

            thirdparty_data["acctServiceProfileId"] = rcvd_data["acctServiceProfileId"]
            thirdparty_data["subscriberPackageId"] = rcvd_data["subscriberPackageId"]

            if rcvd_data["forwardingServiceProfileId"]:
                thirdparty_data["forwardingServiceProfileId"] = rcvd_data["forwardingServiceProfileId"]

            thirdparty_data["acctUpdateInterval"] = rcvd_data["acctUpdateInterval"]
            thirdparty_data["coreQinQEnabled"] = rcvd_data["coreQinQEnabled"]
            thirdparty_data["vlanMappingType"] = rcvd_data["vlanMappingType"]
            thirdparty_data["coreAddFixedVlan"] = rcvd_data["coreAddFixedVlan"]
            thirdparty_data["coreAddFixedSVlan"] = rcvd_data["coreAddFixedSVlan"]
            thirdparty_data["defaultShareSecret"] = rcvd_data["defaultShareSecret"]
            len_list_client_address = len(rcvd_data["clientAddressList"])
            
            thirdparty_data["ipType"] = rcvd_data["clientAddressList"][len_list_client_address-1]["ipType"]
            thirdparty_data["subnet"] = rcvd_data["clientAddressList"][len_list_client_address-1]["subnet"]
            thirdparty_data["startIP"] = rcvd_data["clientAddressList"][len_list_client_address-1]["startIP"]
            thirdparty_data["endIP"] = rcvd_data["clientAddressList"][len_list_client_address-1]["endIP"]
            thirdparty_data["ip"] = rcvd_data["clientAddressList"][len_list_client_address-1]["ip"]
            thirdparty_data["subnet"] = rcvd_data["clientAddressList"][len_list_client_address-1]["subnet"]
            thirdparty_data["secret"] = rcvd_data["clientAddressList"][len_list_client_address-1]["secret"]
            thirdparty_data["network"] = rcvd_data["clientAddressList"][len_list_client_address-1]["network"]

            thirdparty_data["clientAddressList"] = copy.deepcopy(rcvd_data["clientAddressList"])


            if vlan_mapping_type == "MapSPreserveC":
                for i in range(0, len(rcvd_data["vlanMappingList"])):
                    thirdparty_data["vlanMappingList"].append({"accessStart":rcvd_data["vlanMappingList"][i]["accessStart"],
                                                               "accessEnd":rcvd_data["vlanMappingList"][i]["accessEnd"],
                                                               "coreStart":rcvd_data["vlanMappingList"][i]["coreStart"],
                                                               "coreEnd":rcvd_data["vlanMappingList"][i]["coreEnd"]})
                if len(rcvd_data["vlanMappingList"]) <= 0:
                    print "delete_svlan_cvlan_in_third_party_apzone():not possible to delete"
                    return False

                for i in range(0, len(rcvd_data["vlanMappingList"])):
                    if svlan_start == rcvd_data["vlanMappingList"][i]["accessStart"] and \
                        svlan_end == rcvd_data["vlanMappingList"][i]["accessEnd"]:
                        is_entry_found = True
                        del thirdparty_data["vlanMappingList"][i]
                        break

                if is_entry_found == False:
                    print "delete_svlan_cvlan_in_third_party_apzone():access SVlan range not found "
                    return False

            thirdparty_data["qinqVLANTagList"] = []
            for i in range(0, len(rcvd_data["qinqVLANTagList"])):
                thirdparty_data["qinqVLANTagList"].append({"startCVlan":rcvd_data["qinqVLANTagList"][i]["startCVlan"],
                                                           "endCVlan":rcvd_data["qinqVLANTagList"][i]["endCVlan"],
                                                           "startSVlan":rcvd_data["qinqVLANTagList"][i]["startSVlan"],
                                                           "endSVlan":rcvd_data["qinqVLANTagList"][i]["endSVlan"]})
            if len(rcvd_data["qinqVLANTagList"]) <= 0:
                print "delete_svlan_cvlan_in_third_party_apzone():not possible to delete"
                return False

            for i in range(0, len(rcvd_data["qinqVLANTagList"])):
                if svlan_start == str(rcvd_data["qinqVLANTagList"][i]["startSVlan"]) and \
                        svlan_end == str(rcvd_data["qinqVLANTagList"][i]["endSVlan"]):
                        is_found = True
                        del thirdparty_data["qinqVLANTagList"][i]
                        break

            if is_found == False:
                print "delete_svlan_cvlan_in_third_party_apzone():access SVlan range not found"
                return False

            json_data = json.dumps(thirdparty_data)
            update_url = ji.get_url(self.req_api_thirdparty_apzone_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(update_url, self.jsessionid, json_data)


        except Exception, e:
            print traceback.format_exc()
            return False

        return result
    
    def update_third_party_apzone(self, zone_name="Auto_ThrdPrty_Zone", domain_label='Administration Domain',
                                       new_zone_name=None, access_network=None, core_network=None,
                                       auth_service_type=None, network_traffic_name=None,
                                       acct_name=None, auth_name=None, forwarding_profile_name=None,
                                       hotspot_name=None, vlan_map_type=None, default_shared_secret=None,
                                       core_add_fixed_vlan=None,
                                       acct_ttgsession_enable=False,
                                       core_qinq_enable=False,):
        """
        API used to update Third Party APZone

        URI: PUT /wsg/api/scg/zones/thirdparty/<third_party_apzone_key>

        :param str zone_name: Name of Third Party APZone
        :param str domain_label: Name of Domain
        :param str new_zone_name: New name of Third Party APZone
        :param str access_network: QinQL2 | L2oGRE
        :param str core_network: TTGPDG | Bridge
        :param str auth_service_type: Open | x8021 | WISPr
        :param str network_traffic_name: Name of Network Traffic Profile
        :param str acct_name: Accounting profile name
        :param str auth_name: Authentication Profile name
        :param str forwarding_profile_name: Name of Forwarding profile
        :param str hotspot_name: Name of Hotspot profile
        :param str vlan_map_type: MapSPreserveC | StripAll | StripSPreserveC | StripAllAddFixedSingle
        :param str default_shared_secret: Radius Client option Default Share Secret
        :param str core_add_fixed_valn: Core add fixed VLAN
        :param boolean acct_ttgsession_enable: True | False
        :param boolean core_qinq_enable: True | False
        :return: True if Third Party APZone updated else False
        :rtype: boolean
 
        """

        result = False
        thirdparty_data = {}
        try:
            url = ji.get_url(self.req_api_thirdparty_apzone_updt_del1%self.get_domain_uuid(domain_label=domain_label), self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_thirdparty_apzone(url, zone_name)
            acct_url = ji.get_url(self.req_api_acct_profile, self.scg_mgmt_ip, self.scg_port)
            auth_url = ji.get_url(self.req_api_auth_profile, self.scg_mgmt_ip, self.scg_port)
            forwarding_profile_url = ji.get_url(self.req_api_forwarding_service, self.scg_mgmt_ip, self.scg_port)
            thirdparty_data.update(self.SJT.get_third_party_apzone_update())
            thirdparty_data["key"] = rcvd_data["key"]
            thirdparty_data["zoneIntId"] = str(rcvd_data["zoneIntId"]) 
            thirdparty_data["zoneName"] = rcvd_data["zoneName"] if not new_zone_name else new_zone_name
            thirdparty_data["accessNetworkType"] = rcvd_data["accessNetworkType"] if not access_network else access_network
            thirdparty_data["subscriberPackageId"] = rcvd_data["subscriberPackageId"]
            thirdparty_data["networkTrafficPackageId"] = rcvd_data["networkTrafficPackageId"] if not network_traffic_name \
                    else self._traffic_network(name=network_traffic_name)
            _access_nw = access_network if access_network else rcvd_data["accessNetworkType"]
            _core_nw = core_network if core_network else rcvd_data["coreNetworkType"]
            if rcvd_data["accessNetworkType"] != _access_nw:
                print "Because of data complexity, not possible to update"
                return False

            
            if _access_nw == "QinQL2":
                thirdparty_data["coreNetworkType"] =  rcvd_data["coreNetworkType"] if not core_network else core_network 
                thirdparty_data["coreQinQEnabled"] = rcvd_data["coreQinQEnabled"] if core_qinq_enable is None else core_qinq_enable
                thirdparty_data["vlanMappingType"] = rcvd_data["vlanMappingType"] if vlan_map_type is None else vlan_map_type

                if _core_nw == "Bridge":
                    acct_url = ji.get_url(self.req_api_acct_profile, self.scg_mgmt_ip, self.scg_port)
                    thirdparty_data.update({"authType":rcvd_data["authType"] if not auth_service_type else auth_service_type})

                    if thirdparty_data["authType"] == "Open":
                        thirdparty_data.update({"vlanMappingType":rcvd_data["vlanMappingType"] if not vlan_map_type else vlan_map_type})
                        thirdparty_data.update({"acctServiceProfileId":rcvd_data["acctServiceProfileId"]})
                        if acct_name and acct_name == "Disable":
                            thirdparty_data.update({"acctServiceProfileId":""})
                        elif acct_name:
                            thirdparty_data.update({"acctServiceProfileId":self._get_acct_profile_id(acct_name, acct_url)})

                    elif thirdparty_data["authType"] == "WISPr":
                        thirdparty_data.update({"hotspotServiceProfileId": rcvd_data["hotspotServiceProfileId"] if not hotspot_name \
                                else self._get_hotspot_profile(hotspot_name)})
                        thirdparty_data.update({"vlanMappingType": rcvd_data["vlanMappingType"] if not vlan_map_type else vlan_map_type})
                    else:
                        print "update_third_party_apzone(): auth_service_type is invalid or enpty"
                        return False

                elif _core_nw == "TTGPDG":
                    thirdparty_data.update({"authType":"x8021",
                                            "forwardingServiceProfileId":rcvd_data["forwardingServiceProfileId"] if not forwarding_profile_name \
                                                    else self._get_forwarding_profile_id(forwarding_profile_name,forwarding_profile_url),
                                            "authServiceProfileId":rcvd_data["authServiceProfileId"] if not auth_name else \
                                                    self._get_acct_profile_id(auth_name,auth_url),
                                            "acctServiceProfileId":rcvd_data["acctServiceProfileId"] if not acct_name else \
                                                    self._get_acct_profile_id(acct_name,acct_url)})

                    thirdparty_data.update({"vlanMappingType": rcvd_data["vlanMappingType"] if not vlan_map_type else vlan_map_type,
                                            "defaultShareSecret":rcvd_data["defaultShareSecret"] if not default_shared_secret else default_shared_secret})

                #if (_core_nw == "Bridge" and  acct_name != "Disable" and thirdparty_data["authType"] == "Open" or "WISPr") or _core_nw == "TTGPDG":
                if (_core_nw == "Bridge" and  thirdparty_data["acctServiceProfileId"] != None \
                        and (thirdparty_data["authType"] == "Open" or thirdparty_data["authType"] == "WISPr")) or _core_nw == "TTGPDG":

                    len_client_addr = len(rcvd_data["clientAddressList"])
                    thirdparty_data.update({"coreAddFixedVlan":rcvd_data["coreAddFixedVlan"] if not core_add_fixed_vlan else int(core_add_fixed_vlan),
                                            "defaultShareSecret":rcvd_data["defaultShareSecret"] if not default_shared_secret else default_shared_secret,
                                            "ipType":rcvd_data["clientAddressList"][len_client_addr-1]["ipType"],
                                            "ip":rcvd_data["clientAddressList"][len_client_addr-1]["ip"],
                                            "startIP":rcvd_data["clientAddressList"][len_client_addr-1]["startIP"],
                                            "endIP":rcvd_data["clientAddressList"][len_client_addr-1]["endIP"],
                                            "subnet":rcvd_data["clientAddressList"][len_client_addr-1]["subnet"],
                                            "network":rcvd_data["clientAddressList"][len_client_addr-1]["network"],
                                            "secret":rcvd_data["clientAddressList"][len_client_addr-1]["secret"],
                                            "acctTTGSessionEnabled":rcvd_data["acctTTGSessionEnabled"] if acct_ttgsession_enable is None else \
                                                    acct_ttgsession_enable})

                    thirdparty_data["clientAddressList"] = []
                    for i in range(0, len(rcvd_data["clientAddressList"])):
                        thirdparty_data["clientAddressList"].append({"ipType":rcvd_data["clientAddressList"][i]["ipType"],
                                                                    "startIP":rcvd_data["clientAddressList"][i]["startIP"],
                                                                    "endIP":rcvd_data["clientAddressList"][i]["endIP"],
                                                                    "network":rcvd_data["clientAddressList"][i]["network"],
                                                                    "subnet":rcvd_data["clientAddressList"][i]["subnet"],
                                                                    "ip":rcvd_data["clientAddressList"][i]["ip"],
                                                                    "secret":rcvd_data["clientAddressList"][i]["secret"]})

                if rcvd_data["coreQinQEnabled"] == True and thirdparty_data["coreQinQEnabled"] == True:
                    thirdparty_data.update({"vlanMappingType":rcvd_data["vlanMappingType"] if not vlan_map_type else vlan_map_type})
                    if not rcvd_data["vlanMappingList"]:
                        print "S-VLAN mapping Error"
                        return False

                    thirdparty_data["vlanMappingList"] = []
                    for i in range(0, len(rcvd_data["vlanMappingList"])):
                        thirdparty_data["vlanMappingList"].append({"accessStart":rcvd_data["vlanMappingList"][i]["accessStart"],
                                                               "accessEnd":rcvd_data["vlanMappingList"][i]["accessEnd"],
                                                               "coreStart":rcvd_data["vlanMappingList"][i]["coreStart"],
                                                               "coreEnd":rcvd_data["vlanMappingList"][i]["coreEnd"]})
                        
                elif rcvd_data["coreQinQEnabled"] == False and core_qinq_enable and core_qinq_enable == True:
                    print "Vlan mapping Error: Create a new ThrdPrtyZone"
                    return False

                thirdparty_data["qinqVLANTagList"] = []
                for i in range(0, len(rcvd_data["qinqVLANTagList"])):
                    thirdparty_data["qinqVLANTagList"].append({"startCVlan":str(rcvd_data["qinqVLANTagList"][i]["startCVlan"]),
                                                              "endCVlan":str(rcvd_data["qinqVLANTagList"][i]["endCVlan"]),
                                                              "startSVlan":str(rcvd_data["qinqVLANTagList"][i]["startSVlan"]),
                                                              "endSVlan":str(rcvd_data["qinqVLANTagList"][i]["endSVlan"])})

            elif _access_nw == "L2oGRE":
                thirdparty_data["coreQinQEnabled"] = rcvd_data["coreQinQEnabled"] if core_qinq_enable is None else core_qinq_enable
                thirdparty_data["vlanMappingType"] = rcvd_data["vlanMappingType"] if vlan_map_type is None else vlan_map_type

                acct_url = ji.get_url(self.req_api_acct_profile, self.scg_mgmt_ip, self.scg_port)
                thirdparty_data.update({"authType": rcvd_data["authType"] if not auth_service_type else auth_service_type})

                if thirdparty_data["vlanMappingType"] == "StripAllAddFixedSingle":

                    thirdparty_data.update({"coreAddFixedVlan": rcvd_data["coreAddFixedVlan"] if not core_add_fixed_vlan else int(core_add_fixed_vlan)})

                if thirdparty_data["authType"] == "Open":
                    if acct_name and acct_name == "Disable":
                        thirdparty_data.update({"acctServiceProfileId":""})
                    else:
                        thirdparty_data.update({"acctServiceProfileId":rcvd_data["acctServiceProfileId"] if not acct_name else \
                                self._get_acct_profile_id(acct_name, acct_url)})

                elif thirdparty_data["authType"] == "WISPr":
                    radius_uri = ji.get_url(self.req_api_radius_id%'RADIUSAcct', self.scg_mgmt_ip, self.scg_port)
                    if acct_name and acct_name == "Disable":
                        thirdparty_data.update({"acctId":""})
                    elif auth_name and auth_name == "Always Accept":
                        thirdparty_data.update({"aaaId":"22222222-2222-2222-2222-222222222222"})
                    else:
                        thirdparty_data.update({"acctId":rcvd_data["acctId"] if not acct_name else self._get_acct_profile_id(acct_name, radius_uri)})

                    thirdparty_data.update({"hotspotServiceProfileId":rcvd_data["hotspotServiceProfileId"] if not \
                            hotspot_name else self._get_hotspot_profile(hotspot_name)})

                elif thirdparty_data["authType"] == "x8021":
                    if acct_name and acct_name == "Disable":
                        thirdparty_data.update({"acctServiceProfileId":""})
                    else:
                        thirdparty_data.update({"acctServiceProfileId":rcvd_data["acctServiceProfileId"] if not \
                                acct_name else self._get_acct_profile_id(acct_name, acct_url)})

                    thirdparty_data.update({"authServiceProfileId":rcvd_data["authServiceProfileId"] if not auth_name else \
                            self._get_acct_profile_id(auth_name, auth_url)})
                _acct_exist = thirdparty_data['acctServiceProfileId']

                if thirdparty_data["authType"] == "x8021" or (thirdparty_data["authType"] == "Open" and _acct_exist != None) or \
                        (thirdparty_data["authType"] == "WISPr" and _acct_exist != None) :

                    thirdparty_data.update({"clientAddressList":[]})
                    for i in range(0, len(rcvd_data["clientAddressList"])):
                        thirdparty_data["clientAddressList"].append({"ipType":rcvd_data["clientAddressList"][i]["ipType"],
                                                                    "startIP":rcvd_data["clientAddressList"][i]["startIP"],
                                                                    "endIP":rcvd_data["clientAddressList"][i]["endIP"],
                                                                    "network":rcvd_data["clientAddressList"][i]["network"],
                                                                    "subnet":rcvd_data["clientAddressList"][i]["subnet"],
                                                                    "ip":rcvd_data["clientAddressList"][i]["ip"],
                                                                    "secret":rcvd_data["clientAddressList"][i]["secret"]})

                    len_client_addr = len(rcvd_data["clientAddressList"])
                    thirdparty_data.update({"coreAddFixedVlan":rcvd_data["coreAddFixedVlan"] if not core_add_fixed_vlan else int(core_add_fixed_vlan),
                                            "defaultShareSecret":rcvd_data["defaultShareSecret"] if not default_shared_secret else default_shared_secret,
                                            "ipType":rcvd_data["clientAddressList"][len_client_addr-1]["ipType"],
                                            "ip":rcvd_data["clientAddressList"][len_client_addr-1]["ip"],
                                            "startIP":rcvd_data["clientAddressList"][len_client_addr-1]["startIP"],
                                            "endIP":rcvd_data["clientAddressList"][len_client_addr-1]["endIP"],
                                            "subnet":rcvd_data["clientAddressList"][len_client_addr-1]["subnet"],
                                            "network":rcvd_data["clientAddressList"][len_client_addr-1]["network"],
                                            "secret":rcvd_data["clientAddressList"][len_client_addr-1]["secret"],
                                            "acctTTGSessionEnabled":rcvd_data["acctTTGSessionEnabled"] if acct_ttgsession_enable is None else \
                                                    acct_ttgsession_enable})


                thirdparty_data.update({"accessNetworkSourceIPList":[]})
                for i in range(0, len(rcvd_data["accessNetworkSourceIPList"])):
                    thirdparty_data["accessNetworkSourceIPList"].append({"ipType":rcvd_data["accessNetworkSourceIPList"][i]["ipType"],
                                                                    "startIP":rcvd_data["accessNetworkSourceIPList"][i]["startIP"],
                                                                    "endIP":rcvd_data["accessNetworkSourceIPList"][i]["endIP"],
                                                                    "network":rcvd_data["accessNetworkSourceIPList"][i]["network"],
                                                                    "subnet":rcvd_data["accessNetworkSourceIPList"][i]["subnet"],
                                                                    "ip":rcvd_data["accessNetworkSourceIPList"][i]["ip"],
                                                                    "secret":""})
 
            data_json = json.dumps(thirdparty_data)
            update_url = ji.get_url(self.req_api_thirdparty_apzone_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(update_url, self.jsessionid, data_json)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def _get_key_for_thirdparty_apzone(self, url=None, name="Auto_ThrdPrty_Zone"):
        """
        API used to get the key of Thirdparty APZone

        :param str url: URL
        :param str name: Name of Thirdparty APZone
        :return: key and data of Thirdparty APZone
        :rtype: unicode, dictionary

        """

        key, data = None, None
        rcv_data = ji.get_json_data(url, self.jsessionid)
        for i in range(0, len(rcv_data["data"]["list"])):
            if rcv_data["data"]["list"][i]["zoneName"] == name:
                key, data = rcv_data["data"]["list"][i]["key"], rcv_data["data"]["list"][i]
                break
        if not key:
            raise Exception("get_key_for_thirdparty_apzone(): Key not found for name: %s" %(name))
        return key, data
    
    def delete_thirdparty_apzone(self, thirdparty_apzone_name="Auto_ThrdPrty_Zone", domain_label='Administration Domain'):
        """
        API used to delete Thirdparty APzone

        URI: DELETE /wsg/api/scg/zones/thirdparty/<thirdparty_apzonbe_key>

        :param str thirdparty_apzone_name: Name of Thirdparty APzone
        :param str domain_label: Name of Doamin
        :return: True if Thirdparty APzone deleted else False
        :rtype: boolean

        """

        result = False
        try:
            url = ji.get_url(self.req_api_thirdparty_apzone_updt_del1%self.get_domain_uuid(domain_label=domain_label), self.scg_mgmt_ip, self.scg_port)
            key, rcv_data = self._get_key_for_thirdparty_apzone(url, thirdparty_apzone_name)
            url_del = ji.get_url(self.req_api_thirdparty_apzone_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.delete_scg_data(url_del, self.jsessionid, None)
        except Exception, e:
            print traceback.format_exc()
            return False
        return result
    
    def create_ftp_service(self, ftp_name="BORA", ftp_host="1.2.3.4",
                                 ftp_port="22", ftp_username="ruckus", ftp_password="ruckus1!", remote_dir=""):
        """
        API used to create FTP service

        URI: POST /wsg/api/scg/ftpservice?

        :param str ftp_name: Name of FTP service
        :param str ftp_host: IP Address of FTP Service
        :param str ftp_port: Port number
        :param str ftp_username: Username of FTP
        :param str ftp_password: Password
        :param remote_dir: Remote Directory
        :return: True if FTP Service created else False
        :rtype: boolean
        """

        result = False
        fwd_ftp_data = {}
        try:
            fwd_ftp_data.update(self.SJT.get_ftp_template_data())
            fwd_ftp_data.update({"ftpName":ftp_name,
                                 "ftpHost":ftp_host,
                                 "ftpPort":ftp_port,
                                 "ftpUserName":ftp_username,
                                 "ftpPassword":ftp_password,
                                 "ftpRemoteDirectory":remote_dir})
            url = ji.get_url(self.req_api_ftp_service, self.scg_mgmt_ip, self.scg_port)
            json_data = json.dumps(fwd_ftp_data)
            result = ji.post_json_data(url, self.jsessionid, json_data)
        except Exception, e:
            print traceback.format_exc()
            return False
        return result

    def _get_key_for_ftp_service(self, name):
        """
        API used to get the key and data of FTP Service

        URI: GET /wsg/api/scg/ftpservice? 

        :param str name: Name of FTP Service
        :return: key and data of FTP Service
        :rtype: unicode, dictionary

        """

        key, data = None, None
        url = ji.get_url(self.req_api_ftp_service, self.scg_mgmt_ip, self.scg_port)
        rcv_data = ji.get_json_data(url, self.jsessionid)
        for i in range(0, len(rcv_data["data"]["list"])):
            if rcv_data["data"]["list"][i]["ftpName"] == name:
                key, data = rcv_data["data"]["list"][i]["key"], rcv_data["data"]["list"][i]
                break
        if not key:
            raise Exception("get_key_for_ftp_service(): Key not found for name: %s" % (name))
        return key, data
 

    def validate_ftp_service(self,ftp_name="BORA", ftp_host=None, ftp_port=None, ftp_username=None, ftp_password=None, remote_dir=None):

        """
        API used to get the key and data of FTP Service

        URI: GET /wsg/api/scg/ftpservice? 

        :param str name: Name of FTP Service
        :return: key and data of FTP Service
        :rtype: unicode, dictionary

        """
 
        try:
            key, rcv_ftp_data = self._get_key_for_ftp_service(ftp_name)
            if ftp_name:
                if rcv_ftp_data["ftpName"] != ftp_name:
                    self._print_err_validate('validate_ftp_service', 'ftp_name', 'ftpName', ftp_name, rcv_ftp_data["ftpName"])
                    return False
            if ftp_host:
                if rcv_ftp_data["ftpHost"] != ftp_host:
                    self._print_err_validate('validate_ftp_service', 'ftp_host', 'ftpHost', ftp_host, rcv_ftp_data["ftpHost"])
                    return False
            if ftp_port:
                if rcv_ftp_data["ftpPort"] != int(ftp_port):
                    self._print_err_validate('validate_ftp_service', 'ftp_port', 'ftpPort', ftp_port, rcv_ftp_data["ftpPort"])
                    return False
            if ftp_username:
                if rcv_ftp_data["ftpUserName"] != ftp_username:
                    self._print_err_validate('validate_ftp_service', 'ftp_username', 'ftpUserName', ftp_username, rcv_ftp_data["ftpUserName"])
                    return False
            if ftp_password:
                if rcv_ftp_data["ftpPassword"] != ftp_password:
                    self._print_err_validate('validate_ftp_service', 'ftp_password', 'ftpPassword', ftp_password, rcv_ftp_data["ftpPassword"])
                    return False
            if remote_dir:
                if rcv_ftp_data["ftpRemoteDirectory"] != remote_dir:
                    self._print_err_validate('validate_ftp_service', 'remote_dir', 'ftpRemoteDirectory', remote_dir,
                            rcv_ftp_data["ftpRemoteDirectory"])
                    return False
            return True
        except Exception, e:
            print traceback.format_exc()
            return False



    def update_ftp_service(self, current_ftp_name="BORA", new_ftp_name=None, ftp_host=None,
                                 ftp_port=None, ftp_username=None, ftp_password=None, remote_dir=None):
        """
        API is used to update FTP services

        URI: PUT /wsg/api/scg/ftpservice/<ftp_service_key>

        :param str current_ftp_name: Original Name of FTP service
        :param str new_ftp_name: New Name of FTP service
        :param str ftp_host: IP Address of FTP Service
        :param str ftp_port: Port number
        :param str ftp_username: Username of FTP
        :param str ftp_password: Password
        :param remote_dir: Remote Directory
        :return: True if FTP Service is updated else False
        :rtype: boolean 

        """

        result = False
        fwd_ftp_data = {}
        try:
            fwd_ftp_data.update(self.SJT.get_ftp_template_data())
            key, rcv_ftp_data = self._get_key_for_ftp_service(current_ftp_name)
            fwd_ftp_data["key"] = rcv_ftp_data["key"]
            fwd_ftp_data["ftpName"] = rcv_ftp_data["ftpName"] if not new_ftp_name else new_ftp_name
            fwd_ftp_data["ftpHost"] = rcv_ftp_data["ftpHost"] if not ftp_host else ftp_host
            fwd_ftp_data["ftpPort"] = rcv_ftp_data["ftpPort"] if not ftp_port else ftp_port
            fwd_ftp_data["ftpUserName"] = rcv_ftp_data["ftpUserName"] if not ftp_username else ftp_username
            fwd_ftp_data["ftpPassword"] = rcv_ftp_data["ftpPassword"] if not ftp_password else ftp_password
            fwd_ftp_data["ftpRemoteDirectory"] = rcv_ftp_data["ftpRemoteDirectory"] if not remote_dir else remote_dir
            json_data = json.dumps(fwd_ftp_data)
            put_url = ji.get_url(self.req_api_ftp_service_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(put_url, self.jsessionid, json_data)
        except Exception, e:
            print traceback.format_exc()
            return False
        return result

    def delete_ftp_service(self, ftp_name="TEST"):
        """
        API is used to delete FTP Service

        URI: DELETE /wsg/api/scg/ftpservice/<ftp_service_keys> 

        :param str ftp_name: Name of the FTP Service Profile
        :return: True if FTP Service Profile is deleted else False
        :rtype: boolean

        """

        result = False
        try:
            key, rcv_ftp_data = self._get_key_for_ftp_service(ftp_name)
            url = ji.get_url(self.req_api_ftp_service_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.delete_scg_data(url, self.jsessionid, None)
        except Exception, e:
            print traceback.format_exc()
            return False
        return result

    def _get_auth_service_id_and_type(self, service_name='HLR_Service-1'):
        """
        API used to get the authentication id and type

        URI: GET /wsg/api/scg/serviceProfiles/authentication/service?type=ALL'

        :param str service_name: Name of the Service
        :return: service type
        :rtype: dictionary

        """
        key, service_type = None, None
        url = ji.get_url(self.req_api_auth_service, self.scg_mgmt_ip, self.scg_port)
        rcv_data = ji.get_json_data(url, self.jsessionid)
        for i in range(0, len(rcv_data["data"]["list"])):
            if rcv_data["data"]["list"][i]["serviceName"] == service_name:
                key, service_type = rcv_data["data"]["list"][i]["serviceId"], rcv_data["data"]["list"][i]['serviceType']
                break
        if not key:
            raise Exception("_get_auth_service_type(): Key not found for name: %s" % (service_name))

        return key, service_type


    def create_authentication_profile(self, auth_profile_name="Auto_auth_profile", description=None,
                enable_hosted_aaa_support=False, 
                enable_3gpp_support=False,
                mobile_country_code=None, 
                mobile_network_code=None, 
                interim_acct_interval=None, 
                session_timeout=None, 
                session_idle_timeout=None,
                default_auth_service_nomatch_realm='Auto_Radius_Service',
                nomatch_realm_auth_method=None,                  #NonGPPCallFlow or GPPCallFlow
                dynamic_vlanid_nomatch_realm="", 
                default_auth_service_no_realm='Auto_Radius_Service',
                norealm_auth_method=None, 
                dynamic_vlanid_no_realm="",
                realm_authservice_name=None, 
                realm=None,
                realm_dynamic_vlanid="", 
                realm_auth_method=None):
        
        """
        API used to create Authentication profile 

        URI: POST /wsg/api/scg/serviceProfiles/authentication/

        :param str auth_profile_name: Name of the Authentication Profile
        :param str description: Description about the profile
        :param str enable_3gpp_support: True | False
        :param str enable_hosted_aaa_support: True | False
        :param str mobile_country_code: Mobile Country Code
        :param str mobile_network_code: Mobile Network Code
        :param str interim_acct_interval: Interim Accounting interval 
        :param str session_timeout: Session timeout in hosted AAA Radius settings
        :param str session_idle_timeout: Session Idle time out int hosted AAA Radius settings
        :param str default_auth_service_nomatch_realm: Name of default Authentication service
        :param str nomatch_realm_auth_method: NonGPPCallFlow | GPPCallFlow
        :param str dynamic_vlanid_nomatch_realm: Dynamic VLAN id 
        :param str default_auth_service_no_realm: Name of default Authentication service
        :param str norealm_auth_method: NonGPPCallFlow | GPPCallFlow
        :param str dynamic_vlanid_no_realm: Dynamic VLAN id
        :param str realm_authservice_name: Authentication Service name
        :param str realm: Realm name
        :param str realm_dynamic_vlanid: Dynamic VLAN id of Realm
        :param str realm_auth_method: NonGPPCallFlow | GPPCallFlow
        :return: True if Athentication profile created else False
        :rtype: boolean
        """
        result = False
        auth_service_profile = {}
        try:
            auth_url = ji.get_url(self.req_api_authprofile, self.scg_mgmt_ip, self.scg_port)
            auth_service_profile.update(self.SJT.authentication_data())
            auth_service_profile["ttgCommonSetting"] = {}

            auth_service_profile["name"] = auth_profile_name
            auth_service_profile["description"] = description
            auth_service_profile["gppSuppportEnabled"] = enable_3gpp_support
            auth_service_profile["aaaSuppportEnabled"] = enable_hosted_aaa_support

            if enable_3gpp_support == True:
                auth_service_profile["ttgCommonSetting"].update(
                    {"mobileCountryCode":mobile_country_code,
                    "mobileNetworkCode":mobile_network_code})

            if enable_3gpp_support == False and enable_hosted_aaa_support == True:
                if realm_auth_method == "GPPCallFlow"or nomatch_realm_auth_method == "GPPCallFlow":
                    print "auth_method should be NonGPPCallFlow"
                    return False

            if enable_hosted_aaa_support == True:
                auth_service_profile["ttgCommonSetting"].update(
                 {"interimAcctInterval":int(interim_acct_interval),
                  "sessionTimeout":int(session_timeout),
                  "sessionIdleTimeout":int(session_idle_timeout),
                  "mobileCountryCode":mobile_country_code,
                  "mobileNetworkCode":mobile_network_code
                  })

            if enable_3gpp_support == True or enable_hosted_aaa_support == True:
                if not norealm_auth_method:
                    print "NoRealm Auth Method is required"
                    return False

                if not nomatch_realm_auth_method:
                    print "NoMatch Realm Auth Method is required"
                    return False

                if realm:
                    if not realm_auth_method:
                        print "Auth Method for Realm is required"
                        return False


            if default_auth_service_no_realm == "NA-Request Rejected":
                authservice_id_norealm = None
                authservice_type_norealm = "NA"
            else:
                authservice_id_norealm, authservice_type_norealm = self._get_auth_service_id_and_type(service_name=default_auth_service_no_realm)

            if dynamic_vlanid_no_realm:
                dynamic_vlanid_no_realm = int(dynamic_vlanid_no_realm)
            else:
                dynamic_vlanid_no_realm = ""

            auth_service_profile["noRealmDefaultMapping"].update(
                 {"authServiceId":authservice_id_norealm, 
                  "authServiceType":authservice_type_norealm,
                  "authorizationMethod":norealm_auth_method, 
                  "dynamicVlanId":dynamic_vlanid_no_realm})

            if default_auth_service_nomatch_realm == "NA-Request Rejected":
                authservice_id_nomatch = None
                authservice_type_nomatch = "NA"
            else:
                authservice_id_nomatch, authservice_type_nomatch = self._get_auth_service_id_and_type(service_name=default_auth_service_nomatch_realm)
            if dynamic_vlanid_nomatch_realm:
                dynamic_vlanid_nomatch_realm = int(dynamic_vlanid_nomatch_realm)
            else:
                dynamic_vlanid_nomatch_realm = ""

            auth_service_profile["noMatchingDefaultMapping"].update(
                 {"authServiceId": authservice_id_nomatch,
                  "authServiceType":authservice_type_nomatch,
                  "authorizationMethod":nomatch_realm_auth_method,
                  "dynamicVlanId":dynamic_vlanid_nomatch_realm})

            authservice_id_realm, authservice_type_realm = None, None

            if not (realm and realm_authservice_name):
                auth_service_profile["nonDefaultRealmMappings"] = []

            elif realm and realm_authservice_name == "NA-Request Rejected":
                authservice_id_realm = None
                authservice_type_realm = "NA"
                realm_auth_method = "NonGPPCallFlow"

            elif realm and realm_authservice_name:
                authservice_id_realm, authservice_type_realm = self._get_auth_service_id_and_type(service_name=realm_authservice_name)
                print authservice_id_realm
            if realm_dynamic_vlanid:
                realm_dynamic_vlanid = int(realm_dynamic_vlanid)
            else: 
                realm_dynamic_vlanid = ""
            if realm and realm_authservice_name:
                auth_service_profile["nonDefaultRealmMappings"].append(
                     {"authServiceId":authservice_id_realm,
                      "authServiceType":authservice_type_realm,
                      "noRealmDefault":False,
                      "noMatchingDefault":False,
                      "realm":realm,
                      "authorizationMethod":realm_auth_method,
                      "dynamicVlanId":realm_dynamic_vlanid})

            data_json = json.dumps(auth_service_profile)
            result = ji.post_json_data(auth_url, self.jsessionid, data_json)

        except Exception, e:
            print "Exception", traceback.format_exc()
            return False

        return result

    def validate_authentication_profile(self, auth_profile_name="Auto_auth_profile", description=None,
                enable_hosted_aaa_support=None, enable_3gpp_support=None, mobile_country_code=None,
                mobile_network_code=None, interim_acct_interval=None,
                session_timeout=None, session_idle_timeout=None,
                default_auth_service_nomatch_realm=None,
                nomatch_realm_auth_method=None,
                dynamic_vlanid_nomatch_realm=None, default_auth_service_no_realm=None,
                norealm_auth_method=None, dynamic_vlanid_no_realm=None,
                realm_authservice_name=None, realm=None,
                realm_dynamic_vlanid=None, realm_auth_method=None):
        """
        API used to validate Authentication profile 
                  
        URI: GET /wsg/api/scg/serviceProfiles/authentication/
                  
        :param str auth_profile_name: Name of the Authentication Profile
        :param str description: Description about the profile
        :param str enable_3gpp_support: True | False
        :param str enable_hosted_aaa_support: True | False
        :param str mobile_country_code: Mobile Country Code
        :param str mobile_network_code: Mobile Network Code
        :param str interim_acct_interval: Interim Accounting interval 
        :param str session_timeout: Session timeout in hosted AAA Radius settings
        :param str session_idle_timeout: Session Idle time out int hosted AAA Radius settings
        :param str default_auth_service_nomatch_realm: Name of default Authentication service
        :param str nomatch_realm_auth_method: Authorization method
        :param str dynamic_vlanid_nomatch_realm: Dynamic VLAN id 
        :param str default_auth_service_no_realm: Name of default Authentication service
        :param str norealm_auth_method: Authorization method
        :param str dynamic_vlanid_no_realm: Dynamic VLAN id
        :param str realm_authservice_name: Authentication Service name
        :param str realm: Realm name 
        :param str realm_dynamic_vlanid: Dynamic VLAN id of Realm
        :param str realm_auth_method: Authorization Method
        :return: True if Athentication profile validated else False
        :rtype: boolean
        """

        try:
            key, rcvd_data = self._get_key_for_auth(name=auth_profile_name)
            if auth_profile_name:
                if rcvd_data["name"] != auth_profile_name:
                    self._print_err_validate('validate_auth_profile','auth_profile_name','name', auth_profile_name,
                            rcvd_data["name"])
                    return False

            if description:
                if rcvd_data["description"] != description:
                    self._print_err_validate('validate_auth_profile', 'description', 'description', description,
                            rcvd_data["description"])
                    return False

            if enable_3gpp_support and rcvd_data["gppSuppportEnabled"] != enable_3gpp_support:
                self._print_err_validate('validate_auth_profile', 'enable_3gpp_support', 'gppSuppportEnabled', enable_3gpp_support,
                        rcvd_data["gppSuppportEnabled"])
                return False

            if enable_hosted_aaa_support and rcvd_data["aaaSuppportEnabled"] != enable_hosted_aaa_support:
                self._print_err_validate('validate_auth_profile', 'enable_hosted_aaa_support', 'aaaSuppportEnabled', enable_hosted_aaa_support,
                        rcvd_data["aaaSuppportEnabled"])
                return False
            if ((enable_hosted_aaa_support and enable_hosted_aaa_support == True) or (enable_3gpp_support and enable_3gpp_support == True)):
                if mobile_country_code:
                    if rcvd_data["ttgCommonSetting"]["mobileCountryCode"] != mobile_country_code:
                        self._print_err_validate('validate_auth_profile', 'mobile_country_code', 'mobileCountryCode', mobile_country_code,
                            rcvd_data["ttgCommonSetting"]["mobileCountryCode"])
                        return False
                if mobile_network_code:
                    if rcvd_data["ttgCommonSetting"]["mobileNetworkCode"] != mobile_network_code:
                        self._print_err_validate('validate_auth_profile', 'mobile_network_code', 'mobileNetworkCode', mobile_network_code,
                            rcvd_data["ttgCommonSetting"]["mobileNetworkCode"])
                        return False 

            if enable_hosted_aaa_support and enable_hosted_aaa_support == True:

                if interim_acct_interval:
                    if str(rcvd_data["ttgCommonSetting"]["interimAcctInterval"]) != interim_acct_interval:
                        self._print_err_validate('validate_auth_profile', 'interim_acct_interval', 'interimAcctInterval', interim_acct_interval,
                            rcvd_data["ttgCommonSetting"]["interimAcctInterval"])
                        return False
                if session_timeout:
                    if str(rcvd_data["ttgCommonSetting"]["sessionTimeout"]) != session_timeout:
                        self._print_err_validate('validate_auth_profile', 'session_timeout', 'sessionTimeout', session_timeout, 
                                rcvd_data["ttgCommonSetting"]["sessionTimeout"])
                        return False
                if session_idle_timeout:
                    if str(rcvd_data["ttgCommonSetting"]["sessionIdleTimeout"]) != session_idle_timeout:
                        self._print_err_validate('validate_auth_profile', 'session_idle_timeout', 'sessionIdleTimeout',
                            session_idle_timeout, rcvd_data["ttgCommonSetting"]["sessionIdleTimeout"])
                        return False

            if default_auth_service_nomatch_realm:
                _auth_id = None
                _auth_id, service_type = self._get_auth_service_id_and_type(service_name=default_auth_service_nomatch_realm)

                if rcvd_data["noMatchingDefaultMapping"]["authServiceId"] != _auth_id:
                    self._print_err_validate('validate_auth_profile', '_auth_id', 'authServiceId', _auth_id, rcvd_data["authServiceId"])
                    return False

            if nomatch_realm_auth_method:
                if rcvd_data ["noMatchingDefaultMapping"]["authorizationMethod"] != nomatch_realm_auth_method:
                    self._print_err_validate('validate_auth_profile', 'nomatch_realm_auth_method', 'authorizationMethod',
                            nomatch_realm_auth_method, rcvd_data["noMatchingDefaultMapping"]["authorizationMethod"])
                    return False

            if dynamic_vlanid_nomatch_realm:
                if str(rcvd_data["noMatchingDefaultMapping"]["dynamicVlanId"]) != dynamic_vlanid_nomatch_realm:
                    self._print_err_validate('validate_auth_profile', 'dynamic_vlanid_nomatch_realm', 'dynamicVlanId', 
                            dynamic_vlanid_nomatch_realm, str(rcvd_data["noMatchingDefaultMapping"]["dynamicVlanId"]))
                    return False
            if default_auth_service_no_realm:
                _auth_id = None
                _auth_id, service_type = self._get_auth_service_id_and_type(service_name=default_auth_service_no_realm)

                if rcvd_data["noRealmDefaultMapping"]["authServiceId"] != _auth_id:
                    self._print_err_validate('validate_auth_profile', '_auth_id', 'authServiceId', _auth_id, 
                            rcvd_data["noRealmDefaultMapping"]["authServiceId"])
                    return False
            if norealm_auth_method:
                if rcvd_data["noRealmDefaultMapping"]["authorizationMethod"] != norealm_auth_method:
                    self._print_err_validate('validate_auth_profile', 'norealm_auth_method', 'authorizationMethod', norealm_auth_method,
                            rcvd_data["noRealmDefaultMapping"]["authorizationMethod"])
                    return False
            if dynamic_vlanid_no_realm:
                if str(rcvd_data["noRealmDefaultMapping"]["dynamicVlanId"]) != dynamic_vlanid_no_realm:
                    self._print_err_validate('validate_auth_profile', 'dynamic_vlanid_no_realm', 'dynamicVlanId', dynamic_vlanid_no_realm,
                            str(rcvd_data["noRealmDefaultMapping"]["dynamicVlanId"]))
                    return False

            if realm:
                _auth_id = None
                if len(rcvd_data["nonDefaultRealmMappings"]) < 1:
                    print "validate_authentication_profile(): Empty List recieved"
                    return False

                exp_result_realm = (True if realm_authservice_name else False, True if realm else False, True if realm_auth_method else False,
                                        True if realm_dynamic_vlanid else False)
                is_found = False
                for i in range(0, len(rcvd_data["nonDefaultRealmMappings"])):
                    is_realm_found = False
                    is_auth_id_found = False
                    is_realm_auth_methd_found = False
                    is_realm_dynamic_valnid_found = False

                    if not realm_authservice_name:
                        _auth_id = '0'
                    elif realm_authservice_name and realm_authservice_name == "NA-Request Rejected":
                        _auth_id = None
                    elif realm_authservice_name:
                        _auth_id, service_type = self._get_auth_service_id_and_type(service_name=realm_authservice_name)

                    if rcvd_data["nonDefaultRealmMappings"][i]["authServiceId"] == _auth_id:
                        is_auth_id_found = True
                    if rcvd_data["nonDefaultRealmMappings"][i]["realm"] == realm:
                        is_realm_found = True
                    if ((enable_hosted_aaa_support and enable_hosted_aaa_support == True) or (enable_3gpp_support and enable_3gpp_support == True)):
                        if rcvd_data["nonDefaultRealmMappings"][i]["authorizationMethod"] == realm_auth_method:
                            is_realm_auth_methd_found = True
                    if str(rcvd_data["nonDefaultRealmMappings"][i]["dynamicVlanId"]) == realm_dynamic_vlanid:
                        is_realm_dynamic_valnid_found  = True
 
                    actual_res_realm = (is_auth_id_found, is_realm_found, is_realm_auth_methd_found, is_realm_dynamic_valnid_found)
                    if exp_result_realm == actual_res_realm:
                        is_found = True
                        break

                if is_found == False:
                    print "Validate_auth_profile(): failed"
                    return False

            return True

        except Exception, e:
            print "Exception", traceback.format_exc()
            return False

    def _get_key_for_auth(self, name='Auto_auth_profile'):
        """
        API used to key and data of Authentication profile

        URI: GET /wsg/api/scg/serviceProfiles/authentication?

        :param str name: Name of the Authentication profile
        :return: key and data
        :rtype: unicode
        """
 
        key, key_info = None, None
        url = ji.get_url(self.req_api_auth_profile, self.scg_mgmt_ip, self.scg_port)
        data = ji.get_json_data(url, self.jsessionid)

        for i in range(0, len(data["data"]["list"])):          
            if data["data"]["list"][i]["name"] == name:
                key, key_info = data["data"]["list"][i]["key"], data["data"]["list"][i]
                break

        if not key:
            raise Exception("_get_key_for_auth():Key not found for name: %s " % (name))

        return key, key_info

    def update_authentication_profile(self, current_auth_name="Auto_auth_profile",
            new_auth_name=None,
            enable_hosted_aaa_support=None,
            enable_3gpp_support=None,
            mobile_country_code= None, mobile_network_code=None,
            interim_acct_interval=None,
            session_timeout=None,
            session_idle_timeout=None,
            default_auth_service_nomatch_realm=None, nomatch_auth_method=None,
            dynamic_vlanid_nomatch_realm=None,
            dynamic_vlanid_no_realm=None,
            default_auth_service_no_realm=None, norealm_auth_method=None):
        """
        API used to update the Authentication profile

        URI: PUT /wsg/api/scg/serviceProfiles/authentication/<auth_profile_key>
        
        :param str current_auth_name: Name of the Authentication Profile to be updated
        :param str new_auth_name: Name of New Authentication Profile
        :param str description: Description about the profile
        :param str enable_3gpp_support: True | False
        :param str enable_hosted_aaa_support: True | False
        :param str mobile_country_code: Mobile Country Code
        :param str mobile_network_code: Mobile Network Code
        :param str interim_acct_interval: Interim Accounting interval 
        :param str session_timeout: Session timeout in hosted AAA Radius settings
        :param str session_idle_timeout: Session Idle time out int hosted AAA Radius settings
        :param str default_auth_service_nomatch_realm: Name of default Authentication service
        :param str nomatch_realm_auth_method: Authorization method
        :param str dynamic_vlanid_nomatch_realm: Dynamic VLAN id 
        :param str default_auth_service_no_realm: Name of default Authentication service
        :param str norealm_auth_method: Authorization method
        :param str dynamic_vlanid_no_realm: Dynamic VLAN id
        :return: True if Athentication profile updated else False
        :rtype: boolean
        
        """

        result = False
        try:

            key, auth_profile_data = self._get_key_for_auth(name=current_auth_name)

            if auth_profile_data["gppSuppportEnabled"] == False and norealm_auth_method == "GPPCallFlow" and enable_3gpp_support is None:
                print "Authorization method is NonGPP call flow"
                return False
            if auth_profile_data["gppSuppportEnabled"] == False and nomatch_auth_method == "GPPCallFlow" and enable_3gpp_support is None:
                print "Authorization method is NonGPP call flow"
                return False
            if auth_profile_data["realmMappings"]:
                del auth_profile_data["realmMappings"]

            fwd_auth_data = copy.deepcopy(auth_profile_data)
            fwd_auth_data["aaaSuppportEnabled"] = auth_profile_data["aaaSuppportEnabled"] if not enable_hosted_aaa_support else enable_hosted_aaa_support
            fwd_auth_data["name"] = auth_profile_data["name"] if new_auth_name is None else new_auth_name
            fwd_auth_data["gppSuppportEnabled"] = \
                    auth_profile_data["gppSuppportEnabled"] if  enable_3gpp_support is None else  enable_3gpp_support

            authservice_id_norealm, authservice_type_norealm = None, None
            if default_auth_service_no_realm:
                if default_auth_service_no_realm == "NA-Request Rejected":
                    authservice_id_norealm = None
                    authservice_type_norealm = "NA"
                else:
                    authservice_id_norealm, authservice_type_norealm = self._get_auth_service_id_and_type(service_name=default_auth_service_no_realm)

            if authservice_type_norealm == "HLR":
                if auth_profile_data["aaaSuppportEnabled"] == True and enable_hosted_aaa_support == False:
                    print "update_authentication_profile(): Give the proper Default Authentication Service NoRealm"
                    return False

            fwd_auth_data["noRealmDefaultMapping"]["authServiceId"] = auth_profile_data["noRealmDefaultMapping"]["authServiceId"] \
                    if not default_auth_service_no_realm else authservice_id_norealm
            fwd_auth_data["noRealmDefaultMapping"]["authServiceType"] = auth_profile_data["noRealmDefaultMapping"]["authServiceType"] if not \
                    default_auth_service_no_realm else authservice_type_norealm
            fwd_auth_data["noRealmDefaultMapping"]["authorizationMethod"] = \
                    auth_profile_data["noRealmDefaultMapping"]["authorizationMethod"] if norealm_auth_method is None else norealm_auth_method
            fwd_auth_data["noRealmDefaultMapping"]["dynamicVlanId"] = \
                    auth_profile_data["noRealmDefaultMapping"]["dynamicVlanId"] if dynamic_vlanid_no_realm is None else int(dynamic_vlanid_no_realm)

            authservice_id_nomatch, authservice_type_nomatch = None, None
            if default_auth_service_nomatch_realm:
                if default_auth_service_nomatch_realm == "NA-Request Rejected":
                    authservice_type_nomatch = "NA"
                else:
                    authservice_id_nomatch, authservice_type_nomatch = self._get_auth_service_id_and_type(service_name=default_auth_service_nomatch_realm)

            if authservice_type_nomatch == "HLR":

                if auth_profile_data["aaaSuppportEnabled"] == True and enable_hosted_aaa_support == False:
                    print "update_authentication_profile(): Give the proper Default Authentication Service NoMatch Realm"
                    return False

            fwd_auth_data["noMatchingDefaultMapping"]["authServiceId"] = auth_profile_data["noMatchingDefaultMapping"]["authServiceId"] \
                    if not default_auth_service_nomatch_realm  else authservice_id_nomatch
            fwd_auth_data["noMatchingDefaultMapping"]["authServiceType"] = auth_profile_data["noMatchingDefaultMapping"]["authServiceType"] \
                    if not default_auth_service_nomatch_realm else authservice_type_nomatch
            fwd_auth_data["noMatchingDefaultMapping"]["authorizationMethod"] = \
                    auth_profile_data["noMatchingDefaultMapping"]["authorizationMethod"] if nomatch_auth_method is None else nomatch_auth_method
            fwd_auth_data["noMatchingDefaultMapping"]["dynamicVlanId"] = auth_profile_data["noMatchingDefaultMapping"]["dynamicVlanId"] \
                    if dynamic_vlanid_nomatch_realm is None else int(dynamic_vlanid_nomatch_realm)

            if fwd_auth_data["aaaSuppportEnabled"] == True:
                fwd_auth_data["ttgCommonSetting"]["interimAcctInterval"] =\
                    auth_profile_data["ttgCommonSetting"]["interimAcctInterval"] if interim_acct_interval is None else int(interim_acct_interval)
                fwd_auth_data["ttgCommonSetting"]["sessionTimeout"] =\
                    auth_profile_data["ttgCommonSetting"]["sessionTimeout"] if session_timeout is None else int(session_timeout)
                fwd_auth_data["ttgCommonSetting"]["sessionIdleTimeout"] =\
                    auth_profile_data["ttgCommonSetting"]["sessionIdleTimeout"] if session_idle_timeout is None else int(session_idle_timeout)
                fwd_auth_data["ttgCommonSetting"]["mobileCountryCode"] =\
                   auth_profile_data["ttgCommonSetting"]["mobileCountryCode"] if mobile_country_code is None else mobile_country_code
                fwd_auth_data["ttgCommonSetting"]["mobileNetworkCode"] =\
                   auth_profile_data["ttgCommonSetting"]["mobileNetworkCode"] if mobile_network_code is None else mobile_network_code
            
            if fwd_auth_data["gppSuppportEnabled"] == True:
                fwd_auth_data["ttgCommonSetting"]["mobileCountryCode"] =\
                   auth_profile_data["ttgCommonSetting"]["mobileCountryCode"] if mobile_country_code is None else mobile_country_code
                fwd_auth_data["ttgCommonSetting"]["mobileNetworkCode"] =\
                   auth_profile_data["ttgCommonSetting"]["mobileNetworkCode"] if mobile_network_code is None else mobile_network_code

            if fwd_auth_data["gppSuppportEnabled"] == False and fwd_auth_data["aaaSuppportEnabled"] == True:
                if ((norealm_auth_method and norealm_auth_method == "GPPCallFlow") or \
                    (nomatch_auth_method and nomatch_auth_method == "GPPCallFlow")):
                    print "auth_method should be NonGPPCallFlow"
                    return False


            json_data = json.dumps(fwd_auth_data)
            api_auth_update = self.req_api_update_authprofile % key
            url_auth_update = ji.get_url(api_auth_update, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(url_auth_update, self.jsessionid, json_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def delete_authentication_profile(self, auth_profile_name="Auto_auth_profile"):
        """
        API used to Delete the Authentication Profile

        URI: DELTE /wsg/api/scg/serviceProfiles/authentication/<auth_profile_key>

        :param str auth_profile_name: Name of Authentication profile to be Deleted
        :return: True if Authentication Profile deleted else False
        :rtype: boolean

        """

        result = False

        try:
            key, rcvd_data = self._get_key_for_auth(name=auth_profile_name)
            api_delete_auth = self.req_api_update_authprofile % key
            url_delete_auth = ji.get_url(api_delete_auth, self.scg_mgmt_ip, self.scg_port)
            result = ji.delete_scg_data(url_delete_auth,self.jsessionid,None)
        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def add_nondefaultrealm_to_authentication_profile(self, realm="Realm",
                                                            auth_profile_name="Auto_auth_profile",
                                                            auth_service_name="Auto_Radius_Service",
                                                            auth_method=None,
                                                            dynamic_vlan_id=None):
        """
        Adds Realm to Authentication Service per Realm in Authentication profile

        URI: PUT /wsg/api/scg/serviceProfiles/authentication/<auth_profile_key>

        :param str realm: Realm to be added
        :param str auth_profile_name: Authentication profile name 
        :param str auth_service_name: Authentication Service name to be added
        :param str auth_method: Authentication Method
        :param str dynamic_vlan_id: Dynamic VLAN ID of adding Realm
        :return: True if Realm added to Authentication Service per Realm else False
        :rtype: boolean
        """
        result = False
        try:
            key, rcv_realm_list = self._get_key_for_auth(name=auth_profile_name)
            
            if rcv_realm_list["realmMappings"]:
                del rcv_realm_list["realmMappings"]

            default_realm_list = copy.deepcopy(rcv_realm_list)
            
            if auth_service_name == "NA-Request Rejected":
                authservice_id = None
                authservice_type = "NA"
            elif auth_service_name:
                authservice_id, authservice_type = self._get_auth_service_id_and_type(service_name=auth_service_name)

            if dynamic_vlan_id:
                dynamic_vlan_id = int(dynamic_vlan_id)
            else:
                dynamic_vlan_id = ""

            if rcv_realm_list["aaaSuppportEnabled"] == False and authservice_type == "HLR":
                print "add_nondefaultrealm_to_authentication_profile(): Hosted AAA disabled"
                return False


            default_realm_list["nonDefaultRealmMappings"].append({"authServiceType":authservice_type,
                                                                      "realm":realm,
                                                                      "authServiceId":authservice_id,
                                                                      "noMatchingDefault":False,
                                                                      "noRealmDefault":False,
                                                                      "authorizationMethod":auth_method,
                                                                      "dynamicVlanId":dynamic_vlan_id})
             
            appended_data = json.dumps(default_realm_list)
            api_add_realm = self.req_api_update_authprofile % key
            url_add_realm = ji.get_url(api_add_realm, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(url_add_realm, self.jsessionid, appended_data)
        
        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def validate_nondefaultrealm_in_authentication_profile(self, realm="Realm",
                    auth_profile_name="Auto_auth_profile",
                    auth_service_name=None,
                    auth_method=None,
                    dynamic_vlan_id=None):
        """
        API used to Validate the NonDefaultRealm in Authentication Profile

        URI: GET /wsg/api/scg/serviceProfiles/authentication/

        :param str auth_profile_name: Name of the Authentication Profile
        :param str auth_service_realm: Realm name
        :param str auth_method: NonGPPCallFlow | GPPCallFlow | RestoreData | NoAutz | UpdateGPRSLocation
        :param str realm_auth_service_name: Name of Authentication Service of Realm
        :param str dynamic_vlan_id: Dynamic VLAN id
        :return: True if Validate NonDefaultRealm is success else False
        :rtype: boolean

        """

        try:
            key, rcvd_data = self._get_key_for_auth(name=auth_profile_name)

            if auth_profile_name:
                if auth_profile_name != rcvd_data["name"]:
                    self._print_err_validate('validate_nondefaultrealm_in_authentication_profile', 'auth_profile_name', 'name',
                        auth_profile_name, rcvd_data["name"])
                    return False

            _realm_exist = False
            exp_res = (True if realm else False, True if auth_service_name else False, True if auth_method else False, True if dynamic_vlan_id else False)
            
            if auth_service_name == "NA-Request Rejected":
                authservice_id_realm = None
            elif auth_service_name:
                authservice_id_realm, authservie_type = self._get_auth_service_id_and_type(service_name=auth_service_name)
            actual_result = None
            if realm:
                is_realm_found = False
                is_auth_service_name_found = False
                is_auth_method_found = False
                is_dynamic_valn_id = False

                for i in range(0, len(rcvd_data["nonDefaultRealmMappings"])):

                    if realm == rcvd_data["nonDefaultRealmMappings"][i]["realm"]:
                        is_realm_found = True
                    if authservice_id_realm == rcvd_data["nonDefaultRealmMappings"][i]["authServiceId"]:
                        is_auth_service_name_found = True
                    if auth_method:
                        if auth_method == rcvd_data["nonDefaultRealmMappings"][i]["authorizationMethod"]:
                            is_auth_method_found = True
                    if is_dynamic_valn_id:
                        if is_dynamic_valn_id == rcvd_data["nonDefaultRealmMappings"][i]["dynamicVlanId"]:
                            is_dynamic_valn_id = True

                    actual_result = (is_realm_found, is_auth_service_name_found, is_auth_method_found, is_dynamic_valn_id)

                    if actual_result == exp_res:
                        _realm_exist = True
                        break

                if _realm_exist == False:
                    self._print_err_validate('validate_nondefaultrealm_to_authentication_profile', 'actual_result', 'exp_res',
                            actual_result, exp_res)
                    return False

            return True

        except Exception, e:
            print traceback.format_exc()
            return False



    def update_nondefaultrealm_in_authentication_profile(self, current_realm="Realm",
                                                               new_realm=None, 
                                                               auth_profile_name="Auto_auth_profile",
                                                               realm_auth_service_name=None, 
                                                               auth_method=None, 
                                                               dynamic_vlan_id=None):
        """
        API used to Update the NonDefaultRealm in Authentication Profile

        URI: PUT /wsg/api/scg/serviceProfiles/authentication/<auth_profile_key>

        :param str current_realm: Name of Realm to be updated
        :param str new_realm: Name of Realm 
        :param str auth_profile_name: Name of the Authentication Profile
        :param str auth_method: NonGPPCallFlow | GPPCallFlow | RestoreData | NoAutz | UpdateGPRSLocation
        :param str realm_auth_service_name: Name of Authentication Service of Realm
        :param str dynamic_vlan_id: Dynamic VLAN id
        :return: True if Validate NonDefaultRealm is success else False
        :rtype: boolean

        """


        is_entry_found = False
        data_realm = {}

        try:
            key, data_realm = self._get_key_for_auth(name=auth_profile_name)
            if data_realm["realmMappings"]:
                del data_realm["realmMappings"]
            default_realm_list = copy.deepcopy(data_realm)

            if data_realm["nonDefaultRealmMappings"]:

                for i in range(0, len(data_realm["nonDefaultRealmMappings"])):
                    if data_realm["nonDefaultRealmMappings"][i]["realm"] == current_realm:

                        default_realm_list["nonDefaultRealmMappings"][i]["realm"] = \
                            data_realm["nonDefaultRealmMappings"][i]["realm"] if new_realm is None else new_realm

                        authservice_id_realm, authservice_type_realm = None, None
                        if realm_auth_service_name:
                            if realm_auth_service_name == "NA-Request Rejected":
                                authservice_id_realm = None
                                authservice_type_realm = "NA"
                            else:
                                authservice_id_realm, authservice_type_realm = self._get_auth_service_id_and_type(service_name=realm_auth_service_name)

                        if data_realm["aaaSuppportEnabled"] == False and authservice_type_realm == "HLR":
                            print "update_nondefaultrealm_to_authentication_profile(): Hosted AAA Disabled"
                            return False

                        if data_realm["gppSuppportEnabled"] == False and auth_method == "GPPCallFlow":
                            print "Authorization method is Non GPP Call flow"
                            return False
     
                        default_realm_list["nonDefaultRealmMappings"][i]["authServiceId"] = \
                            data_realm["nonDefaultRealmMappings"][i]["authServiceId"] if not realm_auth_service_name else authservice_id_realm

                        default_realm_list["nonDefaultRealmMappings"][i]["authServiceType"] = data_realm["nonDefaultRealmMappings"][i]["authServiceType"] \
                                if not realm_auth_service_name else authservice_type_realm

                        default_realm_list["nonDefaultRealmMappings"][i]["authorizationMethod"] = \
                            data_realm["nonDefaultRealmMappings"][i]["authorizationMethod"] if auth_method is None else auth_method

                        default_realm_list["nonDefaultRealmMappings"][i]["dynamicVlanId"] = \
                            data_realm["nonDefaultRealmMappings"][i]["dynamicVlanId"] if dynamic_vlan_id is None else dynamic_vlan_id

                        is_entry_found = True
                        break

                if not is_entry_found:
                    print "update_realm Failed since realm_name: %s does not exist" % current_realm
                    return False

            json_data = json.dumps(default_realm_list)
            api_update_realm = self.req_api_update_authprofile % key
            url_update_realm = ji.get_url(api_update_realm, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(url_update_realm, self.jsessionid, json_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def delete_nondefaultrealm_from_authentication_profile(self, auth_profile_name="Auto_auth_profile", realm="Realm"):
        """
        API used to delete the NonDefaultRealm entry in Authentication Profile

        URI: PUT /wsg/api/scg/serviceProfiles/authentication/<auth_profile_key>

        :param str auth_profile_name: Name of the Authentication Profile
        :param str realm: Name of Realm to be deleted
        :return: True if Realm deleted else False
        :rtype: boolean

        """


        is_key_found = False
        try:
            key, rcv_realm_list = self._get_key_for_auth(name=auth_profile_name)
            if rcv_realm_list["realmMappings"]:
                del rcv_realm_list["realmMappings"]

            data_realm_list = copy.deepcopy(rcv_realm_list)
            
            for i in range(0,len(data_realm_list["nonDefaultRealmMappings"])):
                if data_realm_list["nonDefaultRealmMappings"][i]["realm"] == realm:
                    del data_realm_list["nonDefaultRealmMappings"][i]
                    is_key_found = True
                    break

            if not is_key_found:
                print "delete_realm Failed since realm_name: %s does not exist" % realm
                return False

            appended_data = json.dumps(data_realm_list)
            api_del_realm = self.req_api_update_authprofile % key
            url_add_realm = ji.get_url(api_del_realm, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(url_add_realm, self.jsessionid, appended_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def create_hlr_service(self, hlr_name="Auto_HLR_Service", 
                         description=None, 
                         sgsn_isdn_address="1234",
                         routing_context='124', 
                         local_point_code='3', 
                         local_network_indicator="international", 
                         default_point_code_format='integer',
                         eap_sim_map_version="version3", 
                         auth_map_version="version3",
                         source_gt_indicator="global_title_includes_translation_type_only", 
                         has_src_point_code="true",
                         source_translation_type='40', 
                         source_nature_address_indicator="subscriber_number",
                         source_numbering_plan='isdn_telephony_numbering_plan',
                         destination_gt_indicator="global_title_includes_translation_type_only", 
                         destination_translation_type="40",
                         dest_nature_address_indicator="international_number", 
			 dest_numbering_plan="isdn_mobile_numbering_plan",
                         dest_gt_point_code='5',
                         sctp_destination_ip="1.2.3.4", 
                         sctp_destination_port="1234", 
                         sctp_source_port="1235",
                         sctp_max_inbound_streams='1', 
                         sctp_max_outbound_streams='1', 
                         sctp_adj_point_code="1",
                         sccp_gt_digits="1234", 
                         sccp_gt_indicator="global_title_includes_translation_type_only", 
                         sccp_address_indicator="route_on_gt",
                         sccp_has_point_code=False, 
                         sccp_point_code='1', 
                         sccp_has_ssn=True, 
                         sccp_trans_type='1',
                         sccp_numbering_plan="isdn_mobile_numbering_plan", 
                         sccp_nature_of_address_indicator="subscriber_number",
                         enable_av_caching=False, 
                         enable_auth_caching=False,
                         cleanup_time_hour='0', 
                         cleanup_time_minute='0', 
                         cache_history_time='0', 
                         max_time_reuse='0'):
        """
        API used to create HLR service

        URI: POST /wsg/api/scg/hlrs/

        :param str hlr_name: Name of the HLR service 
        :param str description: Description 
        :param str sgsn_isdn_address: SGSN ISDN Adress
        :param str routing_context: Routing context
        :param str local_point_code: Local point code 1 to 16383
        :param str local_network_indicator: international | international_spare | national | national_spare
        :param str default_point_code_format: integer | dotted 
        :param str eap_sim_map_version: version2 | version3
        :param str auth_map_version: version2 | version3
        :param str source_gt_indicator: global_title_includes_translation_type_only | 
                                        global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator
        :param boolean has_src_point_code: True | False
        :param str source_translation_type: Source Translation Type
        :param str source_numbering_plan: isdn_mobile_numbering_plan
        :param str source_nature_address_indicator: international_number | subscriber_number | reserved_for_national_use | national_significant_number |
                                                    unknown
        :param str destination_gt_indicator: global_title_includes_translation_type_only |
                                             global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator
        :param str destination_translation_type: Destination Translation Type
        :param str dest_numbering_plan: isdn_mobile_numbering_plan
        :param str dest_nature_address_indicator: international_number | subscriber_number | reserved_for_national_use |
                                                  national_significant_number | unknown
        :param str dest_gt_point_code: Destination gt point code 
        :param str sctp_destination_ip: Destination IP Address of SCTP Association to core Network
        :param str sctp_destination_port: Destination Port Number 1 to 65535
        :param str sctp_source_port: Source Port Address 1 to 65535
        :param str sctp_max_inbound_streams: Maxium Inbound Streams 1 to 255
        :param str sctp_max_outbound_streams:  Maxium outbound Streams 1 to 255
        :param str sctp_adj_point_code: adjacent point code 
        :param str sccp_gt_digits: gt digits of SCCP GTT
        :param str sccp_gt_indicator: global_title_includes_translation_type_only |
                                      global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator
        :param str sccp_address_indicator: route_on_gt | route_on_ssn
        :param str sccp_point_code: Point Code 1 to 16383
        :param boolean sccp_has_ssn: True | False
        :param str sccp_trans_type: Translation Type 1 to 254
        :param str sccp_numbering_plan: isdn_mobile_numbering_plan
        :param str sccp_nature_of_address_indicator: international_number | subscriber_number | reserved_for_national_use | national_significant_number |
                                                     unknown
        :param boolean enable_av_caching: True | False
        :param boolean enable_auth_caching: True | False
        :param str cleanup_time_hour: from 0 to 23
        :param str cleanup_time_minute: from 0 t0 59
        :param str cache_history_time: from 1 to 4294967296
        :param str max_time_reuse:from  0 to 5
        :return: True if HLR Service is created  else False
        :rtype: boolean

        """

        result = False
        hlr_profile = {}
        try:
            url = ji.get_url(self.req_api_hlr, self.scg_mgmt_ip, self.scg_port)
            hlr_data = ji.get_json_data(url, self.jsessionid)

            for i in range(0,len(hlr_data["data"]["list"])):
                if hlr_data["data"]["list"][i]["routingContext"] == routing_context:
                    print "duplicate routing context found in %s profile"  % hlr_data["data"]["list"][i]["name"]
                    return False
                break

            hlr_url = ji.get_url(self.req_api_hlr, self.scg_mgmt_ip, self.scg_port)
            hlr_profile.update(self.SJT.get_hlr_template_data())

            hlr_profile.update({"name":hlr_name, "description":description,
                "sgsnIsdnAddress":sgsn_isdn_address, "routingContext":routing_context,
                "localPointCode":int(local_point_code), "localNetworkIndicator":local_network_indicator,
                "defaultPointCodeFormat":default_point_code_format,
                "eapSimMapVer":eap_sim_map_version, "authMapVer":auth_map_version,
                "srcGtIndicator":source_gt_indicator, "hasSrcPointCode":has_src_point_code,
                "srcNumberingPlan":source_numbering_plan, "destNumberingPlan":dest_numbering_plan,
                "srcTransType":int(source_translation_type), "srcNatureOfAddressIndicator":source_nature_address_indicator,
                "destGtIndicator":destination_gt_indicator, "destTransType":destination_translation_type,
                "destNatureOfAddressIndicator":dest_nature_address_indicator, "avCachingEnabled":enable_av_caching,
                "authorizationCachingEnabled":enable_auth_caching})

            if enable_auth_caching == True or enable_av_caching == True:
                hlr_profile.update({"cleanUpTimeMinute":int(cleanup_time_minute),
                        "historyTime":int(cache_history_time),"cleanUpTimeHour":int(cleanup_time_hour)})
                if enable_av_caching == True:
                    hlr_profile.update({"maxReuseTimes":max_time_reuse})

            if (dest_gt_point_code != local_point_code):
                hlr_profile.update({"gtPointCode":int(dest_gt_point_code)})
            else:
                print "local point code and gt point code should not be same"
            hlr_profile["sctpAssociationsList"][0].update({"destinationIp":sctp_destination_ip,
                "destinationPort":sctp_destination_port, "sourcePort":sctp_source_port,
                "maxInboundsStreams":int(sctp_max_inbound_streams), "maxOutboundsStreams":int(sctp_max_outbound_streams),
                "adjPointCode":sctp_adj_point_code})

            if (sctp_adj_point_code != local_point_code):
                hlr_profile["sctpAssociationsList"][0].update({"adjPointCode":sctp_adj_point_code})
            else:
                print "local point code and SCTP adj point code should not be same"

            hlr_profile["sccpGttList"][0].update({"gtDigits":sccp_gt_digits,
                                                  "gtIndicator":sccp_gt_indicator, 
                                                  "addressIndicator":sccp_address_indicator,
                                                  "hasPointCode":sccp_has_point_code, 
                                                  "hasSSN":sccp_has_ssn,
                                                  "transType":int(sccp_trans_type), 
                                                  "numberingPlan":sccp_numbering_plan,
                                                  "natureOfAddressIndicator":sccp_nature_of_address_indicator})

            if (sccp_point_code != local_point_code):
                hlr_profile["sccpGttList"][0].update({"pointCode":int(sccp_point_code)})
            else:
                print "local point code and SCCP point code should not be same"

            data_json = json.dumps(hlr_profile)
            result = ji.post_json_data(hlr_url, self.jsessionid, data_json)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def validate_hlr_service(self, hlr_name="Auto_HLR_Service", description=None, sgsn_isdn_address=None,
            routing_context=None, local_point_code=None, local_network_indicator=None,
            default_point_code_format=None,
            eap_sim_map_version=None, auth_map_version=None,
            source_gt_indicator=None, has_src_point_code=None,
            source_translation_type=None, source_numbering_plan=None, source_nature_address_indicator=None,
            destination_gt_indicator=None, destination_translation_type=None, dest_numbering_plan=None,
            dest_nature_address_indicator=None, dest_gt_point_code=None,
            sctp_destination_ip=None, sctp_destination_port=None, sctp_source_port=None,
            sctp_max_inbound_streams=None, sctp_max_outbound_streams=None, sctp_adj_point_code=None,
            sccp_gt_digits=None, sccp_gt_indicator=None, sccp_address_indicator=None,
            sccp_has_point_code=False, sccp_point_code=None, sccp_has_ssn=True, sccp_trans_type=None,
            sccp_numbering_plan=None, sccp_nature_of_address_indicator=None,
            enable_av_caching=False, enable_auth_caching=False,
            cleanup_time_hour=None, cleanup_time_minute=None, cache_history_time=None, max_time_reuse=None):
        """
        API used to validate HLR services

        URI: GET /wsg/api/scg/hlrs/

        :param str hlr_name: Name of the HLR services 
        :param str description: Description 
        :param str sgsn_isdn_address: SGSN ISDN Adress
        :param str routing_context: Routing context
        :param str local_point_code: Local point code 1 to 16383
        :param str local_network_indicator: international | international_spare | national | national_spare
        :param str default_point_code_format: integer | dotted 
        :param str eap_sim_map_version: version2 | version3
        :param str auth_map_version: version2 | version3
        :param str source_gt_indicator: global_title_includes_translation_type_only | 
                                        global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator
        :param boolean has_src_point_code: True | False
        :param str source_translation_type: Source Translation Type
        :param str source_numbering_plan: isdn_mobile_numbering_plan
        :param str source_nature_address_indicator: international_number | subscriber_number | reserved_for_national_use | national_significant_number |
                                                    unknown
        :param str destination_gt_indicator: global_title_includes_translation_type_only |
                                             global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator
        :param str destination_translation_type: Destination Translation Type
        :param str dest_numbering_plan: isdn_mobile_numbering_plan
        :param str dest_nature_address_indicator: international_number | subscriber_number | reserved_for_national_use |
                                                  national_significant_number | unknown
        :param str dest_gt_point_code: Destination gt point code
        :param str sctp_destination_ip: Destination IP Address 
        :param str sctp_destination_port: Destination Port Address 1 to 65535
        :param str sctp_source_port: Source Port Address 1 to 65535
        :param str sctp_max_inbound_streams: Maxium Inbound Streams 1 to 255
        :param str sctp_max_outbound_streams: Maxium outbound Streams 1 to 255
        :param str sctp_adj_point_code: Adjacent point code 
        :param str sccp_gt_digits: gt digits of SCCP GTT
        :param str sccp_gt_indicator: global_title_includes_translation_type_only |
                                      global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator
        :param str sccp_address_indicator: route_on_gt | route_on_ssn
        :param boolean sccp_has_point_code: True | False
        :param str sccp_point_code: Point Code of SCCP GTT
        :param boolean sccp_has_ssn: True | False
        :param str sccp_trans_type: Translation Type of SCCP GTT 
        :param str sccp_numbering_plan: isdn_mobile_numbering_plan
        :param str sccp_nature_of_address_indicator: international_number | subscriber_number | reserved_for_national_use | national_significant_number |
                                                     unknown
        :param boolean enable_av_caching: True | False
        :param boolean enable_auth_caching: True | False
        :param str cleanup_time_hour: from 0 to 23
        :param str cleanup_time_minute: from 0 t0 59
        :param str cache_history_time: from 1 to 4294967296
        :param str max_time_reuse: from 0 to 5
        :return: True if HLR Service is validated else False
        :rtype: boolean

        """

        try:
            hlr_url = ji.get_url(self.req_api_hlr, self.scg_mgmt_ip, self.scg_port)
            rcvd_data = self._get_key_for_hlr(name=hlr_name, url=hlr_url)['data_ret']
            if hlr_name:
                if rcvd_data["name"] != hlr_name:
                    self._print_err_validate('validate_hlr_service', 'hlr_name', 'name', hlr_name, rcvd_data["name"])
                    return False
            if description:
                if rcvd_data["description"] != description:
                    self._print_err_validate('validate_hlr_service', 'description', 'description', description,
                            rcvd_data["description"])
                    return False
            if sgsn_isdn_address:
                if rcvd_data["sgsnIsdnAddress"] != sgsn_isdn_address:
                    self._print_err_validate('validate_hlr_service', 'sgsn_isdn_address', 'sgsnIsdnAddress', sgsn_isdn_address,
                            rcvd_data["sgsnIsdnAddress"])
                    return False
            if routing_context:
                if rcvd_data["routingContext"] != routing_context:
                    self._print_err_validate('validate_hlr_service', 'routing_context', 'routingContext', routing_context,
                            rcvd_data["routingContext"])
                    return False
            if local_point_code:
                if str(rcvd_data["localPointCode"]) != local_point_code:
                    self._print_err_validate('validate_hlr_service', 'local_point_code', 'localPointCode', local_point_code,
                        rcvd_data["localPointCode"])
                    return False
            if local_network_indicator:
                if rcvd_data["localNetworkIndicator"] != local_network_indicator:
                    self._print_err_validate('validate_hlr_service', 'local_network_indicator', 'localNetworkIndicator',
                            local_network_indicator, rcvd_data["localNetworkIndicator"])
                    return False
            if default_point_code_format:
                if default_point_code_format != rcvd_data["defaultPointCodeFormat"]:
                    self._print_err_validate('validate_hlr_service', 'default_point_code_format', 'defaultPointCodeFormat',
                            default_point_code_format, rcvd_data["defaultPointCodeFormat"])
                    return False
            if eap_sim_map_version:
                if rcvd_data["eapSimMapVer"] != eap_sim_map_version:
                    self._print_err_validate('validate_hlr_service', 'eap_sim_map_version', 'eapSimMapVer', eap_sim_map_version,
                            rcvd_data["eapSimMapVer"])
                    return False
            if auth_map_version:
                if rcvd_data["authMapVer"] != auth_map_version:
                    self._print_err_validate('validate_hlr_service', 'auth_map_version', 'authMapVer', auth_map_version,
                            rcvd_data["authMapVer"])
                    return False
            if source_gt_indicator:
                if rcvd_data["srcGtIndicator"] != source_gt_indicator:
                    self._print_err_validate('validate_hlr_service', 'source_gt_indicator', 'srcGtIndicator', source_gt_indicator,
                            rcvd_data["srcGtIndicator"])
                    return False
            if has_src_point_code:
                if rcvd_data["hasSrcPointCode"] != json.loads(has_src_point_code):
                    self._print_err_validate('validate_hlr_service', 'has_src_point_code', 'hasSrcPointCode', json.loads(has_src_point_code),
                            rcvd_data["hasSrcPointCode"])
                    return False
            if source_translation_type:
                if rcvd_data["srcTransType"] != source_translation_type:
                    self._print_err_validate('validate_hlr_service', 'source_translation_type', 'srcTransType', source_translation_type,
                            rcvd_data["srcTransType"])
                    return False
            if source_numbering_plan:
                if source_numbering_plan != rcvd_data["srcNumberingPlan"]:
                    self._print_err_validate('validate_hlr_service', 'source_numbering_plan', 'srcNumberingPlan', source_numbering_plan,
                            rcvd_data["srcNumberingPlan"])
                    return False
            if source_nature_address_indicator:
                if rcvd_data["srcNatureOfAddressIndicator"] != source_nature_address_indicator:
                    self._print_err_validate('validate_hlr_service', 'source_nature_address_indicator', 'srcNatureOfAddressIndicator',
                            source_nature_address_indicator, rcvd_data["srcNatureOfAddressIndicator"])
                    return False
            if destination_gt_indicator:
                if rcvd_data["destGtIndicator"] != destination_gt_indicator:
                    self._print_err_validate('validate_hlr_service', 'destination_gt_indicator', 'destGtIndicator',
                            destination_gt_indicator, rcvd_data["destGtIndicator"])
                    return False
            if destination_translation_type:
                if rcvd_data["destTransType"] != destination_translation_type:
                    self._print_err_validate('validate_hlr_service', 'destination_translation_type', 'destTransType',
                            destination_translation_type, rcvd_data["destTransType"])
                    return False
            if dest_numbering_plan:
                if rcvd_data["destNumberingPlan"] != dest_numbering_plan:
                    self._print_err_validate('validate_hlr_service', 'dest_numbering_plan', 'destNumberingPlan', dest_numbering_plan,
                            rcvd_data["destNumberingPlan"])
                    return False
            if dest_nature_address_indicator:
                if rcvd_data["destNatureOfAddressIndicator"] != dest_nature_address_indicator:
                    self._print_err_validate('validate_hlr_service', 'dest_nature_address_indicator', 'destNatureOfAddressIndicator',
                        dest_nature_address_indicator, rcvd_data["destNatureOfAddressIndicator"])
                    return False
            if dest_gt_point_code:
                if rcvd_data["gtPointCode"] != dest_gt_point_code:
                    self._print_err_validate('validate_hlr_service', 'dest_gt_point_code', 'gtPointCode',
                            dest_gt_point_code, rcvd_data["gtPointCode"])
                    return False
            if rcvd_data["avCachingEnabled"] != enable_av_caching:
                self._print_err_validate('validate_hlr_service', 'enable_av_caching', 'avCachingEnabled',
                         enable_av_caching, rcvd_data["avCachingEnabled"])
                return False
            if rcvd_data["authorizationCachingEnabled"] != enable_auth_caching:
                self._print_err_validate('validate_hlr_service', 'enable_auth_caching', 'authorizationCachingEnabled',
                        enable_auth_caching, rcvd_data["authorizationCachingEnabled"])
                return False

            sctp_data = rcvd_data["sctpAssociationsList"]
            if self._validate_sctp_list(sctp_passed_data=sctp_data, sctp_destination_ip=sctp_destination_ip, 
                                    sctp_destination_port=sctp_destination_port, 
                                    sctp_source_port=sctp_source_port, sctp_max_inbound_streams=sctp_max_inbound_streams,
                                    sctp_max_outbound_streams=sctp_max_outbound_streams, 
                                    sctp_adj_point_code=sctp_adj_point_code) == False:
                print "validate_hlr_service(): _validate_sctp_list() Failed"
                return False
            
            sccp_data = rcvd_data["sccpGttList"]
            if self._validate_sccp_list(sccp_passed_data=sccp_data, 
                                       sccp_gt_digits=sccp_gt_digits, sccp_gt_indicator=sccp_gt_indicator, sccp_address_indicator=sccp_address_indicator,
                                       sccp_has_point_code=sccp_has_point_code, sccp_point_code=sccp_point_code, 
                                       sccp_has_ssn=sccp_has_ssn, sccp_trans_type=sccp_trans_type,
                                       sccp_numbering_plan=sccp_numbering_plan, 
                                       sccp_nature_of_address_indicator=sccp_nature_of_address_indicator) == False:
                print "validate_hlr_service():_validate_sccp_list() Failed"
                return False

            if enable_av_caching == True or enable_auth_caching == True:
                if cleanup_time_hour:
                    if int(rcvd_data["cleanUpTimeHour"]) != cleanup_time_hour:
                        self._print_err_validate('validate_hlr_service', 'cleanup_time_hour', 'cleanUpTimeHour', cleanup_time_hour,
                            int(rcvd_data["cleanUpTimeHour"]))
                        return False
                if cleanup_time_minute:
                    if int(rcvd_data["cleanUpTimeMinute"]) != cleanup_time_minute:
                        self._print_err_validate('validate_hlr_service', 'cleanup_time_minute', 'cleanUpTimeMinute', cleanup_time_minute,
                            int(rcvd_data["cleanUpTimeMinute"]))
                        return False
                if cache_history_time:
                    if rcvd_data["historyTime"] != cache_history_time:
                        self._print_err_validate('validate_hlr_service', 'cache_history_time', 'historyTime', cache_history_time,
                            rcvd_data["historyTime"])
                        return False
            elif enable_av_caching == True:
                if max_time_reuse:
                    if rcvd_data["maxReuseTimes"] != max_time_reuse:
                        self._print_err_validate('validate_hlr_service', 'max_time_reuse', 'maxReuseTimes', max_time_reuse,
                            rcvd_data["maxReuseTimes"])
                        return False

            return True
        except Exception, e:
            print traceback.format_exc()
            return False
    
    def _validate_sctp_list(self, sctp_passed_data=None, hlr_name=None, sctp_destination_ip=None, sctp_destination_port=None, 
                                sctp_source_port=None, sctp_max_inbound_streams=None,
                                sctp_max_outbound_streams=None, sctp_adj_point_code=None):
        """
        API used to validate SCTP Association to Core Network list in HLR Services

        URL: GET  /wsg/api/scg/hlrs/

        :param str hlr_name: Name of the HLR Profile
        :param str sctp_passed_data: 
        :param str sctp_destination_ip: Destination IP Address of SCTP Association to Core Network
        :param str sctp_destination_port: Destination Port Address of SCTP Association to Core Network
        :param str sctp_source_port: Source Port Address of SCTP Association to Core Network
        :param str sctp_max_inbound_streams: Maximum Inbound streams of SCTP Association to Core Network
        :param str sctp_max_outbound_streams: Maximum Outbound streams of SCTP Association to Core Network
        :param str sctp_adj_point_code: Adjacent point code of SCTP Association to Core Network
        :return: True if SCTP Association to Core Network list is validated else False
        :rtype: boolean
        
        """

        try:
            hlr_url = ji.get_url(self.req_api_hlr, self.scg_mgmt_ip, self.scg_port)

            is_entry_found = False
            sctp_data = None
            if not sctp_passed_data:
                rcvd_data = self._get_key_for_hlr(name=hlr_name, url=hlr_url)['data_ret'] 
                sctp_data = copy.deepcopy(rcvd_data["sctpAssociationsList"])
            else:
                sctp_data = sctp_passed_data

            exp_result = (True if sctp_destination_ip else False, True if sctp_destination_port else False,
                    True if sctp_source_port else False, True if sctp_max_inbound_streams else False,
                    True if sctp_max_outbound_streams else False, True if sctp_adj_point_code else False)

            if sctp_destination_ip:
                is_sctp_destination_ip = False
                is_sctp_destination_port = False
                is_sctp_source_port = False
                is_sctp_max_inbound_streams = False
                is_sctp_max_outbound_streams = False
                is_sctp_adj_point_code = False

                for i in range(0, len(sctp_data)):
                    if sctp_destination_ip == str(sctp_data[i]["destinationIp"]):
                        is_sctp_destination_ip = True
                    if sctp_destination_port == str(sctp_data[i]["destinationPort"]):
                        is_sctp_destination_port = True
                    if sctp_source_port == str(sctp_data[i]["sourcePort"]):
                        is_sctp_source_port = True
                    if sctp_max_inbound_streams == str(sctp_data[i]["maxInboundsStreams"]):
                        is_sctp_max_inbound_streams = True
                    if sctp_max_outbound_streams == str(sctp_data[i]["maxOutboundsStreams"]):
                        is_sctp_max_outbound_streams = True
                    if sctp_adj_point_code == str(sctp_data[i]["adjPointCode"]):
                        is_sctp_adj_point_code = True
                    actual_result = (is_sctp_destination_ip, is_sctp_destination_port, is_sctp_source_port, is_sctp_max_inbound_streams,
                            is_sctp_max_outbound_streams, is_sctp_adj_point_code)
                    if actual_result == exp_result:
                        is_entry_found = True
                        break

                if is_entry_found == False:
                    self._print_err_validate('_validate_sctp_list', 'actual_result', 'exp_result', actual_result,
                            exp_result)
                    return False

            return True
        except Exception, e:
            print traceback.format_exc()
            return False

    def _validate_sccp_list(self, sccp_passed_data=None, hlr_name=None, sccp_gt_digits=None, 
                    sccp_gt_indicator=None, sccp_address_indicator=None,
                    sccp_has_point_code=None, sccp_point_code=None, sccp_has_ssn=None, sccp_trans_type=None,
                    sccp_numbering_plan=None, sccp_nature_of_address_indicator=None):
        """

        API is used to validate SCCP GTT list in HLR Services

        URI: GET /wsg/api/scg/hlrs/

        :param str hlr_name: Name of the HLR profile
        :param str sccp_passed_data: 
        :param str sccp_gt_digits: gt digits of SCCP GTTP Table
        :param str sccp_gt_indicator:global_title_includes_translation_type_only |
                                     global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator
        :param str sccp_address_indicator:route_on_gt | route_on_ssn
        :param str sccp_has_point_code: True | False
        :param str sccp_point_code: Point Code of SCCP GTT
        :param str sccp_has_ssn: True | False
        :param str sccp_trans_type: Translation Type of SCCP GTT
        :param str sccp_numbering_plan: isdn_mobile_numbering_plan
        :param str sccp_nature_of_address_indicator: international_number | subscriber_number | reserved_for_national_use | national_significant_number |
                                                     unknown
        :return: True if SCCP GTT list is validated else False
        :rtype: boolean
        """

        try:
            is_entry_found = False
            hlr_url = ji.get_url(self.req_api_hlr, self.scg_mgmt_ip, self.scg_port)
            if not sccp_passed_data:
                rcvd_data = self._get_key_for_hlr(name=hlr_name, url=hlr_url)['data_ret']
                sccp_data = copy.deepcopy(rcvd_data["sccpGttList"])
            else:
                sccp_data = sccp_passed_data

             
            exp_result = (True if sccp_gt_digits else False, True if sccp_gt_indicator else False, True if sccp_address_indicator else False,
                    True if str(sccp_has_point_code) else False, True if sccp_point_code else False, True if sccp_has_ssn else False,
                    True if sccp_trans_type else False, True if  sccp_numbering_plan else False, True if sccp_nature_of_address_indicator else False)
            if sccp_gt_digits:
                for i in range(0, len(sccp_data)):
                    is_sccp_gt_digits = False
                    is_sccp_gt_indicator = False
                    is_sccp_address_indicator = False
                    is_sccp_has_point_code = False
                    is_sccp_point_code = False
                    is_sccp_has_ssn = False
                    is_sccp_trans_type = False
                    is_sccp_numbering_plan = False
                    is_sccp_nature_of_address_indicator = False

                    if sccp_gt_digits == str(sccp_data[i]["gtDigits"]):
                        is_sccp_gt_digits = True
                    if sccp_gt_indicator == str(sccp_data[i]["gtIndicator"]):
                        is_sccp_gt_indicator = True
                    if sccp_address_indicator == sccp_data[i]["addressIndicator"]:
                        is_sccp_address_indicator = True
                    if sccp_has_point_code == sccp_data[i]["hasPointCode"]:
                        is_sccp_has_point_code = True
                    if sccp_point_code == str(sccp_data[i]["pointCode"]):
                        is_sccp_point_code = True
                    if sccp_has_ssn == sccp_data[i]["hasSSN"]:
                        is_sccp_has_ssn = True
                    if sccp_trans_type == str(sccp_data[i]["transType"]):
                        is_sccp_trans_type = True
                    if sccp_numbering_plan == sccp_data[i]["numberingPlan"]:
                        is_sccp_numbering_plan = True
                    if sccp_nature_of_address_indicator == sccp_data[i]["natureOfAddressIndicator"]:
                        is_sccp_nature_of_address_indicator = True
                    actual_result = (is_sccp_gt_digits, is_sccp_gt_indicator, is_sccp_address_indicator, is_sccp_has_point_code,
                            is_sccp_point_code, is_sccp_has_ssn, is_sccp_trans_type, is_sccp_numbering_plan,
                            is_sccp_nature_of_address_indicator)
                    if actual_result == exp_result:
                        is_entry_found = True
                        break
                if is_entry_found == False:
                    self._print_err_validate('_validate_sccp_list', 'actual_result', 'exp_result', actual_result, exp_result)
                    return False

            return True

        except Exception, e:
            print traceback.format_exc()
            return False


    def _get_key_for_hlr(self, name="Auto_HLR_Service", url=None):
        """
        API is used to get key for HLR service

        :param str name: key value
        :param str url: URL required to get data
        :return: key of HLR Service
        :rtype: unicode

        """

        key, key_info = None, None
        result = False
        data = ji.get_json_data(url,self.jsessionid)
        for i in range(0,len(data[u"data"][u"list"])):
            if data[u"data"][u"list"][i][u"name"] == name:
                key, key_info = data[u"data"][u"list"][i][u"key"], data[u"data"][u"list"][i]
                result = True
                break

        if not key:
            raise Exception("_get_key_for_hlr(): Key not found for name: %s" % (name))

        return {'key':key, 'data_ret':key_info,'result':result}

    def add_sctp_association_to_hlr(self, hlr_name="Auto_HLR_Service", sctp_destination_ip="1.2.3.4",
                                    sctp_destination_port="1234", sctp_source_port="1235",
                                    sctp_max_inbound_streams='1', sctp_max_outbound_streams='1', sctp_adj_point_code="1"):
        """
        Adds SCTP Association entry to HLR service

        URI: PUT /wsg/api/scg/hlrs/<HLR_service_key>

        :param str hlr_name: Name of the HLR service 
        :param str sctp_destination_ip: Destination IP address
        :param str sctp_destination_port: Destination Port number 1 to 16383
        :param str sctp_source_port: Source Port Number 1 to 16383
        :param str sctp_max_inbound_streams: Maximum Inbound Streams 1 to 255
        :param str sctp_max_outbound_streams: Maximum Outbound Streams 1 to 255
        :param str sctp_adj_point_code: Adj. Point Code
        :return: True if SCTP Association to Core Network entry is added to HLR service else False
        :rtype: boolean

        """

        result = False
        try:
            hlr_url = ji.get_url(self.req_api_hlr, self.scg_mgmt_ip, self.scg_port)
            rcv_sctp_data = self._get_key_for_hlr(name=hlr_name, url=hlr_url)['data_ret']
            if rcv_sctp_data["columns"]:
                del rcv_sctp_data["columns"]
            sctp_data = copy.deepcopy(rcv_sctp_data)
            if sctp_data["localPointCode"] != sctp_adj_point_code:
                sctp_data["sctpAssociationsList"].append({"destinationIp":sctp_destination_ip,
                                                              "destinationPort":sctp_destination_port, 
                                                              "sourcePort":sctp_source_port,
                                                              "maxInboundsStreams":int(sctp_max_inbound_streams), 
                                                              "maxOutboundsStreams":int(sctp_max_outbound_streams),
                                                              "adjPointCode":sctp_adj_point_code})
            else:
                print "local point code and adj point code should not be same"
                return False
            appended_data = json.dumps(sctp_data)
            api = self.req_api_hlr_update%self._get_key_for_hlr(name=hlr_name, url=hlr_url)['key']
            add_url = ji.get_url(api, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(add_url, self.jsessionid, appended_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def validate_sctp_association_in_hlr(self, hlr_name="Auto_HLR_Service", sctp_destination_ip=None,
                                            sctp_destination_port=None, sctp_source_port=None,
                                            sctp_max_inbound_streams=None, sctp_max_outbound_streams=None, sctp_adj_point_code=None):
        """
        API is used to validate SCTP Association List in HLR

        URI: GET /wsg/api/scg/hlrs/
        
        :param str hlr_name: Name of the HLR service 
        :param str sctp_destination_ip: Destination IP address
        :param str sctp_destination_port: Destination Port number 1 to 16383
        :param str sctp_source_port: Source Port Number 1 to 16383
        :param str sctp_max_inbound_streams: Maximum Inbound Streams 1 to 255
        :param str sctp_max_outbound_streams: Maximum Outbound Streams 1 to 255
        :param str sctp_adj_point_code: Adj. Point Code
        :return: True if SCTP Association to Core Network entry is validated in HLR service else False
        :rtype: boolean

        """

        
        try:
            url = ji.get_url(self.req_api_hlr, self.scg_mgmt_ip, self.scg_port)
            rcvd_data = self._get_key_for_hlr(name=hlr_name, url=url)['data_ret']
            sctp_data = rcvd_data["sctpAssociationsList"]
            if hlr_name:
                if rcvd_data["name"] != hlr_name:
                    self._print_err_validate('validate_add_sctp_association_to_hlr', 'hlr_name', 'name', hlr_name,
                            rcvd_data["name"])
                    return False

            if self._validate_sctp_list(sctp_passed_data=sctp_data, sctp_destination_ip=sctp_destination_ip,
                                sctp_destination_port=sctp_destination_port,
                                sctp_source_port=sctp_source_port, sctp_max_inbound_streams=sctp_max_inbound_streams,
                                sctp_max_outbound_streams=sctp_max_outbound_streams, sctp_adj_point_code=sctp_adj_point_code) == False:
                return False

            return True
        except Exception, e:
            print traceback.format_exc()
            return False


    def update_sctp_association_in_hlr(self, hlr_name="Auto_HLR_Service",
                                             current_sctp_destination_ip="1.2.3.4", new_sctp_destination_ip=None,
                                             sctp_destination_port=None, sctp_source_port=None,
                                             sctp_max_inbound_streams=None, sctp_max_outbound_streams=None, sctp_adj_point_code=None):
        """
        API used to update SCTP Association to Core Network of HLR Services

        URI: PUT /wsg/api/scg/hlrs/<HLR_service_key>
    
        :param str hlr_name: Name Of the HLR Profile
        :param str current_sctp_destination_ip: original Destination IP address 
        :str sctp_destination_port: Destination Port Number 1 to 16383
        :param str sctp_source_port: Source Port Number 1 to 16383
        :param str sctp_max_inbound_streams: Maximum Inbound Streams 1 to 255 
        :param str sctp_max_outbound_streams: Maximum Outbound Streams 1 to 255
        :param str sctp_adj_point_code: Adjacent Point Code 
        :return: True if SCTP Association to Core Network entry is updated to HLR service else False
        :rtype: boolean

        """

        result = False
        is_found = False
        try:
            hlr_url = ji.get_url(self.req_api_hlr, self.scg_mgmt_ip, self.scg_port)
            hlr_data = self._get_key_for_hlr(name=hlr_name, url=hlr_url)['data_ret']
            if hlr_data["columns"]:
                del hlr_data["columns"]
            sctp_data = copy.deepcopy(hlr_data)

            for j in range(0, len(hlr_data["sctpAssociationsList"])):
                if hlr_data["sctpAssociationsList"][j]["destinationIp"] == current_sctp_destination_ip:
                    is_found = True
                    sctp_data["sctpAssociationsList"][j]["destinationIp"] = \
                            hlr_data["sctpAssociationsList"][j]["destinationIp"] if new_sctp_destination_ip is None else new_sctp_destination_ip
                    sctp_data["sctpAssociationsList"][j]["destinationPort"] = \
                            hlr_data["sctpAssociationsList"][j]["destinationPort"] if sctp_destination_port is None else sctp_destination_port
                    sctp_data["sctpAssociationsList"][j]["sourcePort"] = \
                            hlr_data["sctpAssociationsList"][j]["sourcePort"] if sctp_source_port is None else sctp_source_port
                    sctp_data["sctpAssociationsList"][j]["maxInboundsStreams"] = \
                            hlr_data["sctpAssociationsList"][j]["maxInboundsStreams"] if sctp_max_inbound_streams is None \
                            else int(sctp_max_inbound_streams)
                    sctp_data["sctpAssociationsList"][j]["maxOutboundsStreams"] = \
                            hlr_data["sctpAssociationsList"][j]["maxOutboundsStreams"] if sctp_max_outbound_streams is None \
                            else int(sctp_max_outbound_streams)
                    if hlr_data["localPointCode"] != sctp_adj_point_code:
                        sctp_data["sctpAssociationsList"][j]["adjPointCode"] = \
                               hlr_data["sctpAssociationsList"][j]["adjPointCode"] if sctp_adj_point_code is None else sctp_adj_point_code
                    else:
                        print "local point code and adj point code should not be same"
                        return False
                        break
                    break
            if is_found == False:
                return False
            appended_data = json.dumps(sctp_data)
            api = self.req_api_hlr_update%self._get_key_for_hlr(name=hlr_name, url=hlr_url)['key']
            add_url = ji.get_url(api, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(add_url, self.jsessionid, appended_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result
    
    def delete_sctp_from_hlr(self, hlr_name="Auto_HLR_Service", sctp_destination_ip="1.1.1.1"):
        """
        API used to delete  SCTP Association to Core Network list of HLR Services  

        URI: PUT /wsg/api/scg/hlrs/<HLR_service_key>

        :param str hlr_name: Name of HLR Service
        :param str sctp_destination_ip: Destination IP address
        :return: True if SCTP Association to Core Network entry is deleted in HLR service else False
        :rtype: boolean
        """
 
        result = False
        is_found = False
        try:
            hlr_url = ji.get_url(self.req_api_hlr, self.scg_mgmt_ip, self.scg_port)
            rcv_data = self._get_key_for_hlr(name=hlr_name, url=hlr_url)['data_ret']
            if rcv_data["columns"]:
                del rcv_data["columns"]
            sctp_data = copy.deepcopy(rcv_data)
            for j in range(0, len(sctp_data["sctpAssociationsList"])):
                if sctp_data["sctpAssociationsList"][j]["destinationIp"] == sctp_destination_ip:
                    del sctp_data["sctpAssociationsList"][j]
                    is_found = True
                    break
            if is_found == False:
                return False
            appended_data = json.dumps(sctp_data)
            api = self.req_api_hlr_update%self._get_key_for_hlr(name=hlr_name, url=hlr_url)['key']
            add_url = ji.get_url(api, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(add_url, self.jsessionid, appended_data)

        except Exception, e:
            print traceback.format_exc()
            return False
        return result

    def add_sccp_gtt_list_to_hlr(self, hlr_name="Auto_HLR_Service",
            sccp_gt_digits="1234", 
            sccp_gt_indicator="global_title_includes_translation_type_only", 
            sccp_address_indicator="1235",
            sccp_has_point_code=False, sccp_point_code="1", sccp_has_ssn=True,
            sccp_trans_type='1', sccp_numbering_plan="isdn_mobile_numbering_plan",
            sccp_nature_of_address_indicator="subscriber_number"):
        """
        Adds SCCP GTT entry to HLR service

        URI: PUT /wsg/api/scg/hlrs/<HLR_service_key>
        
        :param str hlr_name: Name of the HLR Service
        :param str sccp_gt_digits: GT digits 
        :param str sccp_gt_indicator: global_title_includes_translation_type_only |
                                              global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator

        :param str sccp_address_indicator: route_on_gt | route_on_ssn
        :param boolean sccp_has_point_code: True | False
        :param str sccp_point_code: Point Code 1 to 16383
        :param boolean sccp_has_ssn: True | False
        :param str sccp_trans_type: Translation Type 1 to 254
        :param str sccp_numbering_plan: isdn_mobile_numbering_plan
        :param str sccp_nature_of_address_indicator: international_number | subscriber_number | reserved_for_national_use | national_significant_number |
                                                             unknown

        :return: True if SCCP GT entry added to HLR service else False
        :rtype: boolean
        """

        result = False
        try:
            hlr_url = ji.get_url(self.req_api_hlr, self.scg_mgmt_ip, self.scg_port)
            rcv_data = self._get_key_for_hlr(name=hlr_name, url=hlr_url)['data_ret']
            if rcv_data["columns"]:
                del rcv_data["columns"]
            sccp_data = copy.deepcopy(rcv_data)

            if sccp_data["localPointCode"] != sccp_point_code:
                sccp_data["sccpGttList"].append({"gtDigits":sccp_gt_digits,
                            "gtIndicator":sccp_gt_indicator, "addressIndicator":sccp_address_indicator,
                            "hasPointCode":sccp_has_point_code, "pointCode":sccp_point_code,
                            "hasSSN":sccp_has_ssn,"transType":int(sccp_trans_type),
                            "numberingPlan":sccp_numbering_plan,"natureOfAddressIndicator":sccp_nature_of_address_indicator})
            else:
                print "local point code and point code should not be same"
                return False

            appended_data = json.dumps(sccp_data)
            api = self.req_api_hlr_update%self._get_key_for_hlr(name=hlr_name, url=hlr_url)['key']
            add_url = ji.get_url(api, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(add_url, self.jsessionid, appended_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def validate_sccp_gtt_list_in_hlr(self, hlr_name="Auto_HLR_Service", sccp_gt_digits=None, sccp_gt_indicator=None,
            sccp_address_indicator=None, sccp_point_code=None, sccp_has_point_code=False, sccp_has_ssn=False,
            sccp_trans_type=None, sccp_numbering_plan=None, sccp_nature_of_address_indicator=None):
        """
        API is used to validate SCCP GTT list in HLR Service
            
        URI: GET /wsg/api/scg/hlrs/
            
        :param str hlr_name: Name of the HLR Service
        :param str sccp_gt_digits: GT digits
        :param str sccp_gt_indicator: global_title_includes_translation_type_only |
                                                      global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator

        :param str sccp_address_indicator: route_on_gt | route_on_ssn
        :param boolean sccp_has_point_code: True | False
        :param str sccp_point_code: Point Code 1 to 16383
        :param boolean sccp_has_ssn: True | False
        :param str sccp_trans_type: Translation Type 1 to 254
        :param str sccp_numbering_plan: isdn_mobile_numbering_plan
        :param str sccp_nature_of_address_indicator: international_number | subscriber_number | reserved_for_national_use | national_significant_number |
                                                                     unknown

        :return: True if SCCP GTT entry validated in HLR service else False
        :rtype: boolean

        """
        
        try:
            url = ji.get_url(self.req_api_hlr, self.scg_mgmt_ip, self.scg_port)

            rcvd_data = self._get_key_for_hlr(name=hlr_name, url=url)['data_ret']
            sccp_data = rcvd_data["sccpGttList"]
            if hlr_name:
                if rcvd_data["name"] != hlr_name:
                    self._print_err_validate('validate_add_sccp_gtt_list_to_hlr', 'hlr_name', 'name', hlr_name,
                            rcvd_data["name"])
                    print "validate_add_sccp_gtt_list_to_hlr(): HLR service name %s not found" % hlr_name
                    return False

            if self._validate_sccp_list(sccp_passed_data=sccp_data, sccp_gt_digits=sccp_gt_digits,
                    sccp_gt_indicator=sccp_gt_indicator, sccp_address_indicator=sccp_address_indicator,
                    sccp_has_point_code=sccp_has_point_code, sccp_point_code=sccp_point_code, sccp_has_ssn=sccp_has_ssn, 
                    sccp_trans_type=sccp_trans_type, sccp_numbering_plan=sccp_numbering_plan, 
                    sccp_nature_of_address_indicator=sccp_nature_of_address_indicator) == False:
                print "validate_add_sccp_gtt_list_to_hlr(): _validate_sccp_list() failed"
                return False

            return True
        except Exception, e:
            print traceback.format_exc()
            return False


    def update_sccp_gtt_list_in_hlr(self,hlr_name="Auto_HLR_Service",
            current_sccp_gt_digits=None, new_sccp_gt_digits=None,
            sccp_gt_indicator=None, sccp_address_indicator=None,
            sccp_has_point_code=None, sccp_point_code=None, sccp_has_ssn=None,
            sccp_trans_type=None, sccp_numbering_plan=None,
            sccp_nature_of_address_indicator=None):
        """
        API is used to update SCCP GTT list to HLR service

        URI: PUT /wsg/api/scg/hlrs/<HLR_service_key>

        :param str hlr_name: Name of the HLR Service
        :param str current_sccp_gt_digits: Original GT digits of SCCP GTT
        :param str new_sccp_gt_digits: New GT digits of SCCP GTT
        :param str sccp_gt_indicator: global_title_includes_translation_type_only |
                                      global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator
        :param str sccp_address_indicator: route_on_gt | route_on_ssn
        :param str sccp_has_point_code: True | False
        :param str sccp_point_code: Point Code of SCCP GTT 1 to 16383
        :param str sccp_has_ssn: True | False
        :param str sccp_trans_type: Translation Type 1 to 254
        :param str sccp_numbering_plan: isdn_mobile_numbering_plan
        :param str sccp_nature_of_address_indicator: international_number | subscriber_number | reserved_for_national_use | national_significant_number |
                                                     unknown
        :return: True if SCCP GTT entry update to HLR service else False 
        :rtype: boolean

        """

        result = False
        try:
            hlr_url = ji.get_url(self.req_api_hlr, self.scg_mgmt_ip, self.scg_port)
            hlr_data = self._get_key_for_hlr(name=hlr_name, url=hlr_url)['data_ret']
            if hlr_data["columns"]:
                del hlr_data["columns"]
            sccp_data = copy.deepcopy(hlr_data)
            for j in range(0, len(hlr_data["sccpGttList"])):
                if hlr_data["sccpGttList"][j]["gtDigits"] == current_sccp_gt_digits:
                    sccp_data["sccpGttList"][j]["gtDigits"] = hlr_data["sccpGttList"][j]["gtDigits"] if new_sccp_gt_digits is None else new_sccp_gt_digits
                    sccp_data["sccpGttList"][j]["gtIndicator"] = \
                        hlr_data["sccpGttList"][j]["gtIndicator"] if sccp_gt_indicator is None else sccp_gt_indicator
                    sccp_data["sccpGttList"][j]["addressIndicator"] = \
                        hlr_data["sccpGttList"][j]["addressIndicator"] if sccp_address_indicator is None else sccp_address_indicator
                    sccp_data["sccpGttList"][j]["hasPointCode"] = \
                        hlr_data["sccpGttList"][j]["hasPointCode"] if sccp_has_point_code is None else sccp_has_point_code
                    sccp_data["sccpGttList"][j]["hasSSN"] = \
                        hlr_data["sccpGttList"][j]["hasSSN"] if sccp_has_ssn is None else sccp_has_ssn
                    sccp_data["sccpGttList"][j]["transType"] = \
                        hlr_data["sccpGttList"][j]["transType"] if sccp_trans_type is None else int(sccp_trans_type)
                    sccp_data["sccpGttList"][j]["numberingPlan"] = \
                        hlr_data["sccpGttList"][j]["numberingPlan"] if sccp_numbering_plan is None else sccp_numbering_plan
                    sccp_data["sccpGttList"][j]["natureOfAddressIndicator"] = \
                        hlr_data["sccpGttList"][j]["natureOfAddressIndicator"] \
                            if sccp_nature_of_address_indicator is None else sccp_nature_of_address_indicator
                    if hlr_data["localPointCode"] != sccp_point_code:
                        sccp_data["sccpGttList"][j]["pointCode"] = \
                            hlr_data["sccpGttList"][j]["pointCode"] if sccp_point_code is None else sccp_point_code
                    else:
                        print "local point code and point code should not be same"
                        return False
                    break

            appended_data = json.dumps(sccp_data)
            api = self.req_api_hlr_update%self._get_key_for_hlr(name=hlr_name, url=hlr_url)['key']
            add_url = ji.get_url(api, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(add_url, self.jsessionid, appended_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def delete_sccp_gtt_list_from_hlr(self, hlr_name="Auto_HLR_Service", sccp_gt_digits="1.1.1.1"):
        """
        API is used to delete SCCP GTT entry in HLR Services

        URI: PUT /wsg/api/scg/hlrs/<HLR_service_key>

        :param str hlr_name: Name of the HLR Service
        :param sccp_gt_digits: GT digits  
        :return: True if SCCP GTT entry update to HLR service else False
        :rtype: boolean

        """
 
        result = False
        is_found = False
        try:
            hlr_url = ji.get_url(self.req_api_hlr, self.scg_mgmt_ip, self.scg_port)
            rcv_data = self._get_key_for_hlr(name=hlr_name, url=hlr_url)['data_ret']
            if rcv_data["columns"]:
                del rcv_data["columns"]
            sccp_data = copy.deepcopy(rcv_data)
            for j in range(0, len(sccp_data["sccpGttList"])):
                if sccp_data["sccpGttList"][j]["gtDigits"] == sccp_gt_digits:
                    del sccp_data["sccpGttList"][j]
                    is_found = True
                    break
            if is_found == False:

                return False
            appended_data= json.dumps(sccp_data)
            api = self.req_api_hlr_update%self._get_key_for_hlr(name=hlr_name, url=hlr_url)['key']
            add_url = ji.get_url(api, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(add_url, self.jsessionid, appended_data)

        except Exception, e:
            print traceback.format_exc()
            return False
        return result

    def update_hlr_service(self,current_hlr_name="Auto_HLR_Service", new_hlr_name=None, description=None,
            sgsn_isdn_address= None, routing_context=None, local_point_code=None,
            local_network_indicator=None, default_point_code_format=None,
            eap_sim_map_version=None, auth_map_version=None,
            source_gt_indicator=None, has_src_point_code=None, source_translation_type=None,
            source_numbering_plan=None,
            source_nature_address_indicator=None, destination_gt_indicator=None,
            destination_translation_type=None, dest_nature_address_indicator=None, dest_gt_point_code=None,
            enable_av_caching=None, enable_auth_caching=None, cleanup_time_hour=None, 
            cleanup_time_minute=None, cache_history_time=None, max_time_reuse=None):
        """
        API is used to Update HLR Services

        URI: PUT /wsg/api/scg/hlrs/<HLR_service_key>
        
        :param str hlr_name: Original Name of the HLR Services 
        :param str new_hlr_name: New Name of the HLR Services
        :param str sgsn_isdn_address: SGSN ISDN Adress
        :param str description: Description
        :param str routing_context: Routing context
        :param str local_point_code: Local point code 1 to 16383
        :param str local_network_indicator: international | international_spare | national | national_spare 
        :param str eap_sim_map_version: version2 | version3
        :param str auth_map_version: version2 | version3
        :param str source_gt_indicator: global_title_includes_translation_type_only | 
                                        global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator
        :param boolean has_src_point_code: True | False
        :param str source_translation_type: Source Translation Type
        :param str source_numbering_plan: isdn_mobile_numbering_plan
        :param str source_nature_address_indicator: international_number | subscriber_number | reserved_for_national_use | national_significant_number |
                                                    unknown
        :param str destination_gt_indicator: global_title_includes_translation_type_only |
                                             global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator
        :param str destination_translation_type: Destination Translation Type
        :param str dest_numbering_plan: isdn_mobile_numbering_plan
        :param str dest_nature_address_indicator: international_number | subscriber_number | reserved_for_national_use |
                                                  national_significant_number | unknown
        :param str dest_gt_point_code: Destination gt point code 
        :param boolean enable_av_caching: True | False
        :param boolean enable_auth_caching: True | False
        :param str cleanup_time_hour: from 0 to 23
        :param str cleanup_time_minute: from 0 t0 59
        :param str cache_history_time: from 0 to 4294967296
        :param str max_time_reuse: 0 to 5
        :return: True if HLR service is updated
        :rtype: boolean

        """

        result = False
        update_data = {}
        try:
            hlr_url = ji.get_url(self.req_api_hlr, self.scg_mgmt_ip, self.scg_port)
            hlr_data = self._get_key_for_hlr(name=current_hlr_name, url=hlr_url)['data_ret']
            update_data.update(self.SJT.get_hlr_template_update())
            #if hlr_data["columns"]:
            #    del hlr_data["columns"]
            #update_data = copy.deepcopy(hlr_data)

            hlr_data_for_route = ji.get_json_data(hlr_url,self.jsessionid)
            for i in range(0,len(hlr_data_for_route["data"]["list"])):
                if routing_context and hlr_data_for_route["data"]["list"][i]["routingContext"] == routing_context:
                    print "duplicate routing context found in %s profile"  % hlr_data["name"]
                    return False
                    break

            update_data["key"] = hlr_data["key"]
            update_data["tenantUUID"] = hlr_data["tenantUUID"]
            update_data["name"] = hlr_data["name"] if new_hlr_name is None else new_hlr_name
            update_data["description"] = hlr_data["description"] if description is None else description
            update_data["sgsnIsdnAddress"] = hlr_data["sgsnIsdnAddress"] if sgsn_isdn_address is None else sgsn_isdn_address
            update_data["routingContext"] = hlr_data["routingContext"] if routing_context is None else int(routing_context)
            update_data["localPointCode"] = hlr_data["localPointCode"] if local_point_code is None else int(local_point_code)
            update_data["localNetworkIndicator"] = hlr_data["localNetworkIndicator"] if local_network_indicator is None else local_network_indicator
            update_data["defaultPointCodeFormat"] = hlr_data["defaultPointCodeFormat"] if not default_point_code_format else default_point_code_format
            update_data["eapSimMapVer"] = hlr_data["eapSimMapVer"] if eap_sim_map_version is None else eap_sim_map_version
            update_data["authMapVer"] = hlr_data["authMapVer"] if auth_map_version is None else auth_map_version
            update_data["srcGtIndicator"] = hlr_data["srcGtIndicator"] if source_gt_indicator is None else source_gt_indicator
            update_data["hasSrcPointCode"] = hlr_data["hasSrcPointCode"] if has_src_point_code is None else has_src_point_code
            update_data["srcTransType"] = hlr_data["srcTransType"] if source_translation_type is None else int(source_translation_type)
            update_data["srcNumberingPlan"] = hlr_data["srcNumberingPlan"] if not source_numbering_plan else source_numbering_plan
            update_data["srcNatureOfAddressIndicator"] = hlr_data["srcNatureOfAddressIndicator"] \
                        if source_nature_address_indicator is None else source_nature_address_indicator
            update_data["destGtIndicator"] = hlr_data["destGtIndicator"] \
                            if destination_gt_indicator is None else destination_gt_indicator
            update_data["destTransType"] = hlr_data["destTransType"] \
                            if destination_translation_type is None else int(destination_translation_type)
            update_data["destNatureOfAddressIndicator"] = hlr_data["destNatureOfAddressIndicator"] \
                            if dest_nature_address_indicator is None else dest_nature_address_indicator
            update_data["gtPointCode"] = hlr_data["gtPointCode"] if dest_gt_point_code is None else int(dest_gt_point_code)

            if (update_data["gtPointCode"] == update_data["localPointCode"]):
                print "local point code and gt point code should not be same"
                return False
            update_data["avCachingEnabled"] = hlr_data["avCachingEnabled"] if enable_av_caching is None else enable_av_caching
            update_data["authorizationCachingEnabled"] = hlr_data["authorizationCachingEnabled"] \
                    if enable_auth_caching is None else enable_auth_caching

            if update_data["authorizationCachingEnabled"] == True or update_data["avCachingEnabled"] == True:
                update_data["cleanUpTimeHour"] = hlr_data["cleanUpTimeHour"] if cleanup_time_hour is None else cleanup_time_hour
                update_data["cleanUpTimeMinute"] = hlr_data["cleanUpTimeMinute"] if cleanup_time_minute is None else cleanup_time_minute
                update_data["historyTime"] = hlr_data["historyTime"] if cache_history_time is None else cache_history_time

            if update_data["avCachingEnabled"] == True:
                update_data["maxReuseTimes"] = hlr_data["maxReuseTimes"] if max_time_reuse is None else int(max_time_reuse)

            update_data["sctpAssociationsList"] = copy.deepcopy(hlr_data["sctpAssociationsList"])
            update_data["sccpGttList"] = copy.deepcopy(hlr_data["sccpGttList"])

            appended_data = json.dumps(update_data)

            api = self.req_api_hlr_update% self._get_key_for_hlr(name=current_hlr_name, url=hlr_url)['key']
            add_url = ji.get_url(api, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(add_url, self.jsessionid, appended_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def delete_hlr_service(self, hlr_name="Auto_HLR_Service"):
        """
        API is used to delete HLR Service 

        URI: DELETE /wsg/api/scg/hlrs/
            
        :param str hlr_name: Name of the HLR Service
        :return: True if HLR Service is deleted
        :rtype: boolean
        """
 
        result = False
        try:
            del_url = ji.get_url(self.req_api_hlr, self.scg_mgmt_ip, self.scg_port)
            del_hlr_api = self.req_api_hlr_update%self._get_key_for_hlr(name=hlr_name, url=del_url)['key']
            del_hlr_url = ji.get_url(del_hlr_api, self.scg_mgmt_ip, self.scg_port)
            result = ji.delete_scg_data(del_hlr_url, self.jsessionid, None)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

        
    def _get_tenant_uuid(self):
        """
        API used to get the tenantUUID 

        URI: GET /wsg/api/scg/session/currentUser?'
        
        :return: tenantUUID
        :rtype: unicode

        """ 
        tenant_uuid = None
        url = ji.get_url(self.req_api_get_tenatuuid, self.scg_mgmt_ip, self.scg_port)
        rcvd_data = ji.get_json_data(url, self.jsessionid)
        tenant_uuid = rcvd_data['data']['tenantUUID']

        if not tenant_uuid:
            raise Exception('_get_tenant_uuid(): tenantUUID not found')
        
        return tenant_uuid

    def _get_bladeuuid_for_map_gateway_settings_in_hlr_service(self, label=None):

        key = None
        url = ji.get_url(self.control_plane_id, self.scg_mgmt_ip, self.scg_port)
        rcvd_data = ji.get_json_data(url, self.jsessionid)

        for i in range(0, len(rcvd_data['data']['list'])):
            if rcvd_data['data']['list'][i]['label'] == label:
                key = rcvd_data['data']['list'][i]['bladeUUID']
                break

        if not key:
            raise Exception("_get_bladeuuid_for_map_gateway_settings_in_hlr_service: label %s not found" % (label))
        return key

    def update_map_gateway_settings_in_hlr_service(self, enable_map_gateway_service=False,
                                                         traffic_mode=None,
                                                         active_map_gateway=None):
        """
        API used to update the Map Gateway Settings in HLR Service

        URI: PUT /wsg/api/scg/hlrs/globalsettings?

        :param boolean enable_map_gateway_service: True | False
        :param str traffic_mode: Load_Share | Override
        :param str active_map_gateway: active_map_gateway
        :return: True if Map  Gateway Settings in HLR Service updated successfully else False
        :rtype: boolean

        """    
        result = False
        fwd_map_gateway={}
        try:
            url = ji.get_url(self.map_gateway_settings, self.scg_mgmt_ip, self.scg_port)
            rcv_data = ji.get_json_data(url, self.jsessionid)
            rcvd_data = copy.deepcopy(rcv_data['data'])
            fwd_map_gateway.update({"mapGatewayEnabled":rcvd_data['mapGatewayEnabled'] if enable_map_gateway_service is None \
                else enable_map_gateway_service})

            if fwd_map_gateway["mapGatewayEnabled"] == True:

                fwd_map_gateway.update({"trafficMode": rcvd_data["trafficMode"] if traffic_mode is None else traffic_mode})
                fwd_map_gateway.update({"mapGateway1":rcvd_data["mapGateway1"] if active_map_gateway is None \
                    else self._get_bladeuuid_for_map_gateway_settings_in_hlr_service(active_map_gateway)})

            fwd_data = json.dumps(fwd_map_gateway)
            result = ji.put_json_data(url, self.jsessionid, fwd_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result


    def create_mnc_to_ndc_map_in_hlr(self, mcc="100", mnc="45", ndc="28"):
        """
        API used to create the MNC to NDC mapping

        URI: PUT /wsg/api/scg/hlrs/mncndc?

        :param str mcc: MCC
        :param str mnc: MNC
        :param str ndc: NDC
        :return: True if MNC to NDC mapping created else False
        :rtype: boolean
        """
 
        result = False
        fwd_mccndc_data = []
        try:
            url = ji.get_url(self.req_api_mncndc, self.scg_mgmt_ip, self.scg_port)
            rcv_mccndc_data = ji.get_json_data(url, self.jsessionid)
            for i in range(0, len(rcv_mccndc_data["data"]["list"])):
                fwd_mccndc_data.append({"key":rcv_mccndc_data["data"]["list"][i]["key"],
                                        "mcc":rcv_mccndc_data["data"]["list"][i]["mcc"],
                                        "mnc":rcv_mccndc_data["data"]["list"][i]["mnc"],
                                        "ndc":rcv_mccndc_data["data"]["list"][i]["ndc"]})

            fwd_mccndc_data.append({"mcc":mcc, "mnc":mnc,"ndc":ndc})  

            data = json.dumps(fwd_mccndc_data)
            result = ji.put_json_data(url, self.jsessionid, data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result
    
    def validate_mnc_to_ndc_map_in_hlr(self, mcc='100', mnc=None, ndc=None):
        """
        API is used to validate MNC to NDC Mappings in HLR Services

        URI: GET /wsg/api/scg/hlrs/mncndc?
        
        :param str mcc: MCC
        :param str mnc: MNC
        :param str ndc: NDC
        :return: True if MNC to NDC mapping is validated in HLR Services else False
        :rtype: boolean
 
        """

        exp_result = (True if mcc else False, True if mnc else False, True if ndc else False)
        try:
            url = ji.get_url(self.req_api_mncndc, self.scg_mgmt_ip, self.scg_port)
            rcvd_data = ji.get_json_data(url, self.jsessionid)
            is_entry_found = False

            for i in range(0, len(rcvd_data["data"]["list"])):
                is_mcc_found = False
                is_mnc_found = False
                is_ndc_found = False

                if mcc and mcc == rcvd_data["data"]["list"][i]["mcc"]:
                    is_mcc_found = True
                if mnc and mnc == rcvd_data["data"]["list"][i]["mnc"]:
                    is_mnc_found = True
                if ndc and ndc == rcvd_data["data"]["list"][i]["ndc"]:
                    is_ndc_found = True

                actual_result = (is_mcc_found, is_mnc_found, is_ndc_found)

                if exp_result == actual_result:
                    is_entry_found = True
                    break
            if is_entry_found == False:
                print "validate_mnc_to_ndc_map_in_hlr(): given %s mcc not found" % mcc
                return False

            return True

        except Exception, e:
            print traceback.format_exc()
            return False


    def _get_key_for_mcc(self, mcc='100'):
        """
        API used to get the key for MNC to NDC Mapping
        
        :param str mcc: MCC
        :param str url: URL
        :return: key of MCC
        :rtype: unicode

        """      
 
        key = None
        url = ji.get_url(self.req_api_mncndc, self.scg_mgmt_ip, self.scg_port)
        rcv_data = ji.get_json_data(url, self.jsessionid)
        for i in range(0, len(rcv_data["data"]["list"])):
            if mcc == rcv_data["data"]["list"][i]["mcc"]:
                key = rcv_data["data"]["list"][i]["key"]
                break
        if not key:
            raise Exception("_get_key_for_mcc(): Key not found for mcc: %s" %(mcc))
        return key

    def update_mnc_to_ndc_map_in_hlr(self, current_mcc="100", new_mcc=None, mnc=None, ndc=None):
        """
        API is used to update MNC to NDC in HLR services

        URI: PUT /wsg/api/scg/hlrs/mncndc? 

        :param str current_mcc: MCC to be updated  
        :param str new_mcc: MCC
        :param str mnc: MNC
        :param str ndc: NDC
        :return: True if MNC to NDC mapping upated else False
        :rtype: boolean

        """

        result = False
        is_mcc_found = False
        try:
            url = ji.get_url(self.req_api_mncndc, self.scg_mgmt_ip, self.scg_port)
            rcv_data = ji.get_json_data(url, self.jsessionid)
            item_list = []
            key = self._get_key_for_mcc(mcc=current_mcc)
            for i in range(0, len(rcv_data["data"]["list"])):
                item_list.append({"key":rcv_data["data"]["list"][i]["key"],
                              "mcc":rcv_data["data"]["list"][i]["mcc"],
                              "mnc":rcv_data["data"]["list"][i]["mnc"],
                              "ndc":rcv_data["data"]["list"][i]["ndc"]})

            for i in range(0, len(rcv_data["data"]["list"])):
                if current_mcc == rcv_data["data"]["list"][i]["mcc"]:
                    is_mcc_found = True
                    item_list[i].update({"key":key,
                                         "mcc":rcv_data["data"]["list"][i]["mcc"] if not new_mcc else new_mcc,
                                         "mnc":rcv_data["data"]["list"][i]["mnc"] if not mnc else mnc,
                                         "ndc":rcv_data["data"]["list"][i]["ndc"] if not ndc else ndc})
                    break

            if not is_mcc_found: 
                print "update_mnc_to_ndc_map_in_hlr(): %s mcc not found" % (current_mcc)
                return False

            data = json.dumps(item_list)
            result = ji.put_json_data(url, self.jsessionid, data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def delete_mnc_to_ndc_from_hlr(self, mcc="100"):
        """
        API used to delete MNC to NDC mapping entry

        URI: PUT /wsg/api/scg/hlrs/mncndc?

        :param str mnc: MNC
        :return: True if MNC to NDC mapping entry deleted else False
        :rtype: boolean
        """

        result = False
        is_mcc_found = False
        try:
            mnc_url = ji.get_url(self.req_api_mncndc, self.scg_mgmt_ip, self.scg_port)
            mnc_data = ji.get_json_data(mnc_url, self.jsessionid)
            fwd_list = []
            for i in range(0,len(mnc_data["data"]["list"])):
                fwd_list.append({"key":mnc_data["data"]["list"][i]["key"],
                                   "mcc":mnc_data["data"]["list"][i]["mcc"],
                                   "ndc":mnc_data["data"]["list"][i]["ndc"],
                                   "mnc":mnc_data["data"]["list"][i]["mnc"]})

            for i in range(0,len(mnc_data["data"]["list"])):
                if mnc_data["data"]["list"][i]["mcc"] == mcc:
                    is_mcc_found = True
                    del fwd_list[i]
                    break

            if not is_mcc_found:
                print "delete_mnc_ndc_in_hlr(): %s mcc not found" % (mcc)
                return False

            appended_data = json.dumps(fwd_list)
            add_url = ji.get_url(self.req_api_mncndc, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(add_url, self.jsessionid, appended_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result
    
    def create_accounting_profile(self, acct_profile_name="Auto_acct_profile",
                                        description=None,
                                        default_acct_service_nomatch_realm='Auto_RadiusAcct_Service',
                                        default_acct_service_no_realm='Auto_RadiusAcct_Service',
                                        realm=None, realm_acctservice_name=None):
        """
        Creates Accounting Profile 

        URI: POST /wsg/api/scg/serviceProfiles/accounting?

        :param str acct_profile_name: Name of the Accounting profile to be created
        :param str description: descrption about the accounting profile
        :param str default_acct_service_nomatch_realm: Default Accounting Service No Matching Realm
        :param str default_acct_service_no_realm: Default Accounting Service No Realm
        :param str realm: Realm name to be added to Accounting Service per Realm
        :param str realm_acctservice_name: Name of Accounting Service in Accounting Service per Realm
        :return: True if Accounting Profile created else False
        :rtype: boolean

        """

        result = False
        acct_service_profile = {}

        try:
            acct_service_url = ji.get_url(self.req_api_acct_service, self.scg_mgmt_ip, self.scg_port)
            acct_url = ji.get_url(self.req_api_accounting, self.scg_mgmt_ip, self.scg_port)
            acct_service_profile.update(self.SJT.accounting_data())

            acctservice_id_norealm, norealm_service_type = None, None
            acctservice_id_nomatch, nomatch_service_type = None, None
            acctservice_id_realm, realm_service_type = None, None

            acct_service_profile.update({"name":acct_profile_name,
                                         "description":description})

            if default_acct_service_no_realm == "NA-Disabled":
                acct_service_profile["noRealmDefaultMapping"].update({"acctServiceId":None,
                                                                      "acctServiceType":"NA"})
            elif not default_acct_service_no_realm:
                acct_service_profile["noRealmDefaultMapping"].update({"acctServiceId":None})
            else:
                acctservice_id_norealm, norealm_service_type = self._get_acct_id_and_type(name=default_acct_service_no_realm, url=acct_service_url)
                if acctservice_id_norealm == None:
                    return False
                acct_service_profile["noRealmDefaultMapping"].update({"acctServiceId":acctservice_id_norealm, 
                                                                      "acctServiceType":norealm_service_type})

            if default_acct_service_nomatch_realm == "NA-Disabled":
                acct_service_profile["noMatchingDefaultMapping"].update({"acctServiceId":None,
                                                                         "acctServiceType":"NA"})

            elif not default_acct_service_nomatch_realm:
                acct_service_profile["noMatchingDefaultMapping"].update({"acctServiceId":None})
            else:
                acctservice_id_nomatch, nomatch_service_type = self._get_acct_id_and_type(name=default_acct_service_nomatch_realm, url=acct_service_url)
                if acctservice_id_nomatch == None:
                    return False
                acct_service_profile["noMatchingDefaultMapping"].update({"acctServiceId":acctservice_id_nomatch, 
                                                                           "acctServiceType":nomatch_service_type})
            acct_service_profile["nonDefaultRealmMappings"] = []

            if not realm or not realm_acctservice_name:
                acct_service_profile["nonDefaultRealmMappings"] = []

            elif realm_acctservice_name and realm_acctservice_name == "NA-Disabled":
                realm_service_type = "NA"
                acctservice_id_realm = None

            elif realm_acctservice_name:
                acctservice_id_realm, realm_service_type = self._get_acct_id_and_type(name=realm_acctservice_name, url=acct_service_url)

            if realm and realm_acctservice_name:
                acct_service_profile["nonDefaultRealmMappings"].append({"realm":realm, 
                                                                        "noRealmDefault": False,
                                                                        "noMatchingDefault": False,
                                                                        "acctServiceId":acctservice_id_realm, 
                                                                        "acctServiceType":realm_service_type})

            data_json = json.dumps(acct_service_profile)
            result = ji.post_json_data(acct_url, self.jsessionid, data_json)

        except Exception, e:
            print "Exception", traceback.format_exc()
            return False

        return result


    def validate_accounting_profile(self, acct_profile_name="Auto_acct_profile",
                                        description=None,
                                        default_acct_service_nomatch_realm=None,
                                        default_acct_service_no_realm=None,
                                        realm=None, realm_acctservice_name=None):
        """
        API used to Validate Accounting Profile                                       
        
        URI: GET /wsg/api/scg/serviceProfiles/accounting/<acct_profile_key>?   
                                                             
        :param str acct_profile_name: Name of the Accounting profile 
        :param str description: descrption about the accounting profile
        :param str default_acct_service_nomatch_realm: Default Accounting Service No Matching Realm
        :param str default_acct_service_no_realm: Default Accounting Service No Realm
        :param str realm: Realm name of Accounting Service per Realm
        :param str realm_acctservice_name: Name of Accounting Service in Accounting Service per Realm
        :return: True if Accounting Profile validated else False
        :rtype: boolean

        """

        try:
            acct_service_url = ji.get_url(self.req_api_acct_service, self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_acct_profile(acct_profile_name)
            if acct_profile_name:
                if rcvd_data["name"] != acct_profile_name:
                    self._print_err_validate('validate_acct_profile', 'acct_profile_name', 'name', acct_profile_name,
                            rcvd_data["name"])
                    return False
            if description:
                if rcvd_data["description"] != description:
                    self._print_err_validate('validate_acct_profile', 'description', 'description', description, rcvd_data["description"])
                    return False
            if default_acct_service_nomatch_realm:
                _acct_id = None
                service_type = None
                if default_acct_service_nomatch_realm == "NA-Disabled":
                    _acct_id = None
                else:
                    _acct_id, service_type = self._get_acct_id_and_type(name=default_acct_service_nomatch_realm, url=acct_service_url)
                if rcvd_data["noMatchingDefaultMapping"]["acctServiceId"] != _acct_id:
                    self._print_err_validate('validate_acct_profile', '_acct_id', 'acctServiceId', _acct_id,
                            rcvd_data["noMatchingDefaultMapping"]["acctServiceId"])
                    return False
            if default_acct_service_no_realm:
                _acct_id = None
                service_type = None
                if default_acct_service_no_realm == "NA-Disabled":
                    _acct_id = None
                else:
                    _acct_id, service_type = self._get_acct_id_and_type(name=default_acct_service_no_realm, url=acct_service_url)

                if rcvd_data["noRealmDefaultMapping"]["acctServiceId"] != _acct_id:
                    self._print_err_validate('validate_acct_profile', '_acct_id', 'acctServiceId', _acct_id, 
                            rcvd_data["noRealmDefaultMapping"]["acctServiceId"])
                    return False
            if realm:
                if rcvd_data["nonDefaultRealmMappings"][0]["realm"] != realm:
                    self._print_err_validate('validate_acct_profile', 'realm', 'realm', realm,
                            rcvd_data["nonDefaultRealmMappings"][0]["realm"])
                    return False
            if realm_acctservice_name:
                _acct_id = None
                service_type = None
                if realm_acctservice_name == "NA-Disabled":
                    _acct_id = None
                else:
                    _acct_id, service_type = self._get_acct_id_and_type(name=realm_acctservice_name , url=acct_service_url)
                if rcvd_data["nonDefaultRealmMappings"][0]["acctServiceId"] != _acct_id:
                    self._print_err_validate('validate_acct_profile', '_acct_id', 'acctServiceId', _acct_id,
                            rcvd_data["nonDefaultRealmMappings"][0]["acctServiceId"])
                    return False

            return True

        except Exception, e:
            print "Exception", traceback.format_exc()
            return False

    def _get_acct_id_and_type(self, name="Auto_Radius_Service", url=None):

        key, service_type = None, None
        data = ji.get_json_data(url,self.jsessionid)
        for i in range(0,len(data[u"data"][u"list"])):   
            if data[u"data"][u"list"][i][u"serviceName"] == name:
                key, service_type = data[u"data"][u"list"][i][u"serviceId"], data[u"data"][u"list"][i]["serviceType"]
                break

        if not key:
            raise Exception("_get_acct_id_and_type(): Key not found for the name :%s" % (name))

        return key, service_type
 
    def _get_key_for_acct_profile(self, name):
        """
        API used to get the key and data of the Accounting profile
        
        URI: GET /wsg/api/scg/serviceProfiles/accounting?

        :param str name: Name of the Accounting profile
        :return: key and data of the Accounting profile
        :rtype: unicode

        """

        key, key_info = None, None
        url  = ji.get_url(self.req_api_acct_profile, self.scg_mgmt_ip, self.scg_port)
        data = ji.get_json_data(url, self.jsessionid)
        for i in range(0,len(data[u"data"][u"list"])):
            if data[u"data"][u"list"][i][u"name"] == name:
                key, key_info = data[u"data"][u"list"][i][u"key"], data[u"data"][u"list"][i]
                break
        if not key:
            raise Exception("_get_key_for_acct_profile(): key not found for the name %s" %(name))
        return key, key_info

    def update_accounting_profile(self, current_acct_name="Auto_acct_profile",
                                        new_acct_name=None,
                                        default_acct_service_nomatch_realm=None,
                                        default_acct_service_no_realm=None):
        """
        API used to update the the Accounting Profile

        URI: PUT /wsg/api/scg/serviceProfiles/accounting/<acct_profile_key>

        :param str current_acct_name: Name of the Accounting profile to be modified
        :param str new_acct_name: New Name of Accounting Profile
        :param str default_acct_service_nomatch_realm: Default Accounting Service no matching realm
        :param str default_acct_service_no_realm: Default Accounting Service no Realm
        :return: True if update success else False
        :rtype: boolean
        """

        result = False
        is_duplicate_found = False
        fwd_acct_data = {}
        try:
            acct_url = ji.get_url(self.req_api_acct_service, self.scg_mgmt_ip, self.scg_port)
            url_get  = ji.get_url(self.req_api_acct_profile, self.scg_mgmt_ip, self.scg_port)
            data = ji.get_json_data(url_get, self.jsessionid)
            for i in range(0, len(data['data']['list'])):
                if data['data']['list'][i]['name'] == new_acct_name:
                    is_duplicate_found = True
                    break
            
            if is_duplicate_found == True:
                print "update_accounting_profile(): Dupliucate name of accounting profile"
                return False

            key, acct_profile_data = self._get_key_for_acct_profile(current_acct_name)
            fwd_acct_data = self.SJT.accounting_data_update()
            fwd_acct_data["key"] = acct_profile_data["key"]
            fwd_acct_data["tenantId"] = acct_profile_data["tenantId"]
            fwd_acct_data["name"] = acct_profile_data["name"] if not new_acct_name else new_acct_name
            fwd_acct_data["description"] = acct_profile_data["description"]
            fwd_acct_data["noRealmDefaultMapping"].update({"acctServiceId": acct_profile_data["noRealmDefaultMapping"]["acctServiceId"],
                                                           "acctServiceType":acct_profile_data["noRealmDefaultMapping"]["acctServiceType"]})
            fwd_acct_data["noMatchingDefaultMapping"].update({"acctServiceId":acct_profile_data["noRealmDefaultMapping"]["acctServiceId"],
                                                              "acctServiceType":acct_profile_data["noRealmDefaultMapping"]["acctServiceType"]})
            for j in range(0, len(acct_profile_data["nonDefaultRealmMappings"])):
                fwd_acct_data["nonDefaultRealmMappings"].append({ "realm":acct_profile_data["nonDefaultRealmMappings"][j]["realm"],
                                                                  "acctServiceId":acct_profile_data["nonDefaultRealmMappings"][j]["acctServiceId"],
                                                                  "acctServiceType":acct_profile_data["nonDefaultRealmMappings"][j]["acctServiceType"],
                                                                  "noRealmDefault":False,
                                                                  "noMatchingDefault":False})


            acctservice_id_norealm, norealm_service_type = None, None
            if default_acct_service_no_realm:
                if default_acct_service_no_realm == "NA-Disabled":
                    acctservice_id_norealm = None
                    norealm_service_type = "NA"

                else:
                    acctservice_id_norealm, norealm_service_type = self._get_acct_id_and_type(name=default_acct_service_no_realm, url=acct_url)

                    if not acctservice_id_norealm:
                        return False

                fwd_acct_data["noRealmDefaultMapping"]["acctServiceId"] = acct_profile_data["noRealmDefaultMapping"]["acctServiceId"]\
                    if not default_acct_service_no_realm  else acctservice_id_norealm

                if acctservice_id_norealm:
                    fwd_acct_data["noRealmDefaultMapping"]["acctServiceType"] = norealm_service_type

            acctservice_id_nomatch, nomatch_service_type = None, None
            if default_acct_service_nomatch_realm:

                if default_acct_service_nomatch_realm == "NA-Disabled":
                    acctservice_id_nomatch = None
                    nomatch_service_type = None
                else:
                    acctservice_id_nomatch, nomatch_service_type = self._get_acct_id_and_type(name=default_acct_service_nomatch_realm, url=acct_url)
                    if not acctservice_id_nomatch:
                        return False

                fwd_acct_data["noMatchingDefaultMapping"]["acctServiceId"] = acct_profile_data["noMatchingDefaultMapping"]["acctServiceId"] \
                        if not default_acct_service_nomatch_realm else acctservice_id_nomatch
                if acctservice_id_nomatch:
                    fwd_acct_data["noMatchingDefaultMapping"]["acctServiceType"] = nomatch_service_type 
         
            json_data = json.dumps(fwd_acct_data)
            url_acct_update = ji.get_url(self.req_api_update_acctprofile%key, self.scg_mgmt_ip, self.scg_port)

            result = ji.put_json_data(url_acct_update, self.jsessionid, json_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def delete_accounting_profile(self, acct_profile_name="Auto_acct_profile"):
        """
        API used to delete the Accounting profile

        URI: DELETE /wsg/api/scg/serviceProfiles/accounting/<acct_profile_key> 

        :param str acct_profile_name: Name of the Accounting profile
        :return: True if Accounting profile deleted successfully else False
        :rtype: boolean
        """
        result = False

        try:
            key, rcv_data = self._get_key_for_acct_profile(acct_profile_name)
            url_delete_acct = ji.get_url(self.req_api_update_acctprofile%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.delete_scg_data(url_delete_acct, self.jsessionid, None)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def add_nondefaultrealm_to_accounting_profile(self, acct_profile_name="Auto_acct_profile", 
                                                        realm="Realm", 
                                                        acct_service_name="Auto_RadiusAcct_Service"):
        """
        Adds Accounting Service per Realm to Accounting profile

        URI: PUT /wsg/api/scg/serviceProfiles/accounting/<acct_profile_key>

        :param str acct_profile_name: Accounting Profile name
        :param str realm: Realm to be added to Accounting Profile
        :param str acct_service_name: Name of Accounting Service
        :return: True if Adds Realm to Accounting Profile
        :rtype: boolean
        """

        result = False
        default_realm_list = {}
        try:
            key, data_realm = self._get_key_for_acct_profile(acct_profile_name)
            default_realm_list.update(self.SJT.accounting_data_update())
            default_realm_list["key"] = data_realm["key"]
            default_realm_list["tenantId"] = data_realm["tenantId"]
            default_realm_list["name"] = data_realm["name"]
            default_realm_list["description"] = data_realm["description"]
            acct_service_url = ji.get_url(self.req_api_acct_service, self.scg_mgmt_ip, self.scg_port)
            default_realm_list["noRealmDefaultMapping"].update({"acctServiceId": data_realm["noRealmDefaultMapping"]["acctServiceId"],
                                                                "acctServiceType":data_realm["noRealmDefaultMapping"]["acctServiceType"]})
            default_realm_list["noMatchingDefaultMapping"].update({"acctServiceId": data_realm["noRealmDefaultMapping"]["acctServiceId"],
                                                                   "acctServiceType":data_realm["noRealmDefaultMapping"]["acctServiceType"]})
            for j in range(0, len(data_realm["nonDefaultRealmMappings"])):
                default_realm_list["nonDefaultRealmMappings"].append({ "realm":data_realm["nonDefaultRealmMappings"][j]["realm"],
                                                                       "acctServiceId":data_realm["nonDefaultRealmMappings"][j]["acctServiceId"],
                                                                       "acctServiceType":data_realm["nonDefaultRealmMappings"][j]["acctServiceType"],
                                                                       "noRealmDefault":False,
                                                                       "noMatchingDefault":False})

            if not acct_service_name:
                return False
            else:
                acctservice_id_realm, service_type = self._get_acct_id_and_type(name=acct_service_name, url=acct_service_url)
                if acctservice_id_realm == None:
                    return False
                default_realm_list["nonDefaultRealmMappings"].append({"realm":realm,
                                                                      "acctServiceId":acctservice_id_realm,
                                                                      "acctServiceType":service_type,
                                                                      "noRealmDefault":False,
                                                                      "noMatchingDefault":False})

            appended_data = json.dumps(default_realm_list)
            url_add_realm = ji.get_url(self.req_api_update_acctprofile%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(url_add_realm, self.jsessionid, appended_data)
        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def validate_nondefaultrealm_in_accounting_profile(self, realm="Realm", 
                                                        acct_profile_name="Auto_acct_profile",
                                                        acct_service_name=None):
        """
        Validate Accounting Service per Realm in Accounting profile

        URI: GET /wsg/api/scg/serviceProfiles/accounting/<acct_profile_key>

        :param str acct_profile_name: Accounting Profile name
        :param str realm: Realm to be validated in Accounting Profile
        :param str acct_service_name: Name of Accounting Service
        :return: True if validate Realm in Accounting Profile else False
        :rtype: boolean
        """

        try:
            key, rcvd_data = self._get_key_for_acct_profile(acct_profile_name)
            acct_service_url = ji.get_url(self.req_api_acct_service, self.scg_mgmt_ip, self.scg_port)
            _realm_exist = False
            if not realm:
                if acct_service_name:
                    print "invalid input realm not given"
                    return False
            exp_result = (True if realm else False, True if acct_service_name else False)
            actual_result = None

            acct_service_id = None 
            if acct_service_name and acct_service_name == "NA-Disabled":
                acct_service_id = None
                service_type = "NA"
            elif acct_service_name:
                acct_service_id, service_type = self._get_acct_id_and_type(name=acct_service_name, url=acct_service_url)

            for i in range (0, len(rcvd_data["nonDefaultRealmMappings"])):
                is_realm_found = False
                is_acct_service_name_found = False
                if realm == rcvd_data["nonDefaultRealmMappings"][i]["realm"]:
                    is_realm_found = True
                if acct_service_id == rcvd_data["nonDefaultRealmMappings"][i]["acctServiceId"]:
                    is_acct_service_name_found = True

                actual_result = (is_realm_found, is_acct_service_name_found)
                if exp_result == actual_result:
                    _realm_exist = True
                    break

            if _realm_exist == False:
                self._print_err_validate('validate_nondefaultrealm_to_accounting_profile', 'actual_result', 'exp_result',
                        actual_result, exp_result)
                return False

            return True
             
        except Exception, e:
            print traceback.format_exc()
            return False


    def update_nondefaultrealm_in_accounting_profile(self, current_realm="Realm", 
                                                           new_realm = None,
                                                           acct_profile_name="Auto_acct_profile", 
                                                           realm_acct_service_name=None):
        """
        API used to update the Accounting Service per Realm

        URI: PUT /wsg/api/scg/serviceProfiles/accounting/<acct_profile_key>

        :param str current_realm: Name of the Realm to be updated
        :param str new_realm: New name of Realm
        :param str acct_profile_name: Name of the Accountign profile
        :param str realm_acct_service_name: Accounting Service of Realm
        :return: True if update Realm success else False
        :rtype: boolean

        """ 
        result  = False
        default_realm_list = {}

        try:
            key, data_realm = self._get_key_for_acct_profile(acct_profile_name)
            acct_service_url = ji.get_url(self.req_api_acct_service, self.scg_mgmt_ip, self.scg_port)
            default_realm_list.update(self.SJT.accounting_data_update())
            default_realm_list["key"] = data_realm["key"]
            default_realm_list["tenantId"] = data_realm["tenantId"]
            default_realm_list["name"] = data_realm["name"] if not acct_profile_name else acct_profile_name
            default_realm_list["noRealmDefaultMapping"].update({"acctServiceId": data_realm["noRealmDefaultMapping"]["acctServiceId"],
                                                                "acctServiceType":data_realm["noRealmDefaultMapping"]["acctServiceType"]})
            default_realm_list["noMatchingDefaultMapping"].update({"acctServiceId": data_realm["noRealmDefaultMapping"]["acctServiceId"],
                                                                   "acctServiceType":data_realm["noRealmDefaultMapping"]["acctServiceType"]})
            for j in range(0, len(data_realm["nonDefaultRealmMappings"])):
                default_realm_list["nonDefaultRealmMappings"].append({ "realm":data_realm["nonDefaultRealmMappings"][j]["realm"],
                                                                       "acctServiceId":data_realm["nonDefaultRealmMappings"][j]["acctServiceId"],
                                                                       "acctServiceType":data_realm["nonDefaultRealmMappings"][j]["acctServiceType"],
                                                                       "noRealmDefault":False,
                                                                       "noMatchingDefault":False})
            for i in range(0, len(data_realm["nonDefaultRealmMappings"])):
                if current_realm and data_realm["nonDefaultRealmMappings"][i]["realm"] == current_realm:
                    default_realm_list["nonDefaultRealmMappings"][i]["realm"] = data_realm["nonDefaultRealmMappings"][i]["realm"] if not \
                            new_realm else new_realm
                    is_entry_found = True 
                    acctservice_id_realm, service_type = None, None

                    if realm_acct_service_name and realm_acct_service_name == "NA-Disabled":
                        default_realm_list["nonDefaultRealmMappings"][i]["acctServiceId"] = None
                        default_realm_list["nonDefaultRealmMappings"][i].update({"acctServiceType":"NA"})

                    elif realm_acct_service_name:
                        acctservice_id_realm, service_type = self._get_acct_id_and_type(name=realm_acct_service_name, url=acct_service_url)
                    
                        default_realm_list["nonDefaultRealmMappings"][i]["acctServiceId"] = \
                        data_realm["nonDefaultRealmMappings"][i]["acctServiceId"] if not realm_acct_service_name else acctservice_id_realm
                        default_realm_list["nonDefaultRealmMappings"][i].update({"acctServiceType":service_type})
                    break

            if not is_entry_found:
                print "delete_realm Failed since realm_name: %s does not exist" % current_realm
                return False

            json_data = json.dumps(default_realm_list)
            url_update_realm = ji.get_url(self.req_api_update_acctprofile%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(url_update_realm, self.jsessionid, json_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def delete_nondefaultrealm_from_accounting_profile(self, acct_profile_name="Auto_acct_profile", 
                                                           realm="Realm"):
        """
        API used to delete the Realm in Accounting profile

        URI: PUT /wsg/api/scg/serviceProfiles/accounting/<acct_profile_key>

        :param str acct_profile_name: Name of the Accounting Profile
        :param str realm: Name of the Realm
        :return: True if Realm is deleted else False
        :rtype: boolean
        """

        is_entry_found = False
        default_realm_list = {}
        try:
            key, rcv_data = self._get_key_for_acct_profile(acct_profile_name)
            default_realm_list.update(self.SJT.accounting_data_update())
            default_realm_list["key"] = rcv_data["key"]
            default_realm_list["tenantId"] = rcv_data["tenantId"]
            default_realm_list["name"] = rcv_data["name"] if not acct_profile_name else acct_profile_name
            default_realm_list["noRealmDefaultMapping"].update({"acctServiceId": rcv_data["noRealmDefaultMapping"]["acctServiceId"],
                                                                "acctServiceType":rcv_data["noRealmDefaultMapping"]["acctServiceType"]})
            default_realm_list["noMatchingDefaultMapping"].update({"acctServiceId": rcv_data["noRealmDefaultMapping"]["acctServiceId"],
                                                                   "acctServiceType":rcv_data["noRealmDefaultMapping"]["acctServiceType"]})
            for j in range(0, len(rcv_data["nonDefaultRealmMappings"])):
                default_realm_list["nonDefaultRealmMappings"].append({ "realm":rcv_data["nonDefaultRealmMappings"][j]["realm"],
                                                                       "acctServiceId":rcv_data["nonDefaultRealmMappings"][j]["acctServiceId"],
                                                                       "acctServiceType":rcv_data["nonDefaultRealmMappings"][j]["acctServiceType"],
                                                                       "noRealmDefault":False,
                                                                       "noMatchingDefault":False})
 
            for i in range(0,len(rcv_data["nonDefaultRealmMappings"])):
                if default_realm_list["nonDefaultRealmMappings"][i]["realm"] == realm:
                    del default_realm_list["nonDefaultRealmMappings"][i]
                    is_entry_found = True
                    break

            if not is_entry_found:
                print "delete_realm Failed since realm_name: %s does not exist" % realm
                return False
            
            appended_data = json.dumps(default_realm_list)
            url_delete_realm = ji.get_url(self.req_api_update_acctprofile%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(url_delete_realm, self.jsessionid, appended_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def create_apzone(self, zone_name="Auto_APZone", domain_label='Administration Domain',
                            description=None, 
                            ap_firmware=None,
                            country_code="IN", login_id="admin", password="testing123", 
                            syslog_ip="", syslog_port='514', 
                            enable_mesh='0',
                            mesh_name=None, 
                            mesh_passphrase=None,
                            mesh_uplink_selection=None,
                            radio_2Ghz_channelization="20MHz",          #20MHz or 40MHz
                            radio_2Ghz_channel='0',                       #0(Auto) to 11
                            radio_2Ghz_tx_power="max",                  #full="max" and -1 to -10 ,"min"
                            radio_5Ghz_channelization="40MHz",          #20MHz or 40MHz
                            radio_5Ghz_channel_indoor='0',                #0,36,40,44,48,149,153,157,161
                            radio_5Ghz_channel_outdoor='0',               # 149,153,157,161
                            radio_5Ghz_tx_power="max",                  #full="max" and -1 to -10 ,"min"
                            tunnel_type='1',                              #GRE+UDP:1, GRE:0
                            enable_tunnel_encryption='0',                 #0 or 1
                            wan_interface_mtu='1',                       #tunnel MTU enable:auto(1) or manual (0)
                            mtu_size='1500',                              #in bytes from 850 to 1500
                            channel_mode='0',                             #allow_indoor_channels:1 or 0
                            back_ground_scan_on_2GHz='0',                 #1 or 0
                            back_ground_scan_on_2GHz_timer='20',           #1 to 65535
                            back_ground_scan_on_5GHz='0',                 #1 or 0
                            back_ground_scan_on_5GHz_timer='20',          #1 to 65535
                            enableclbfor2GHz='0', enableclbfor5GHz='0', 
                            adj_radio_threshold_2GHz='43', adj_radio_threshold_5GHz='50',
                            smart_monitor_enable='1', smart_monitor_interval='10', smart_monitor_threshold='3',
			    timezone_system_defined=True,timezone='IST',timezone_user_defined=False,timezone_abbreviation='DEE',
                            gmt_offset='GMT+7',gmt_offset_num='10',daylight_saving_time=False,dst_start_month='1',dst_start='3',dst_start_day='5',
                            dst_end_clk='20',
                            dst_end_month='2',dst_end='4', dst_end_day='6',dst_start_clk='23'):

        """ 
        This API creates AP zone

        URI: POST /wsg/api/scg/zones?

        :param str zone_name: Name of the Zone to be created
        :param str description: Description related to zone
        :param str ap_firmware: AP Firmware
        :param str country_code: Country Code eg: IN
        :param str login_id: For admin login Login ID
        :param str password: For admin login Password 
        :param str syslog_ip: Syslog server ip
        :param str syslog_port: Syslog Port number
        :param str enable_mesh: 0 | 1
        :param str mesh_name: Mesh name or ESSID
        :param str mesh_passphrase: Mesh Passphrase
        :param str mesh_uplink_selection: throughput | rssi
        :param str radio_2Ghz_channelization: 20MHz | 40MHz
        :param str radio_2Ghz_channel: 0 | 1 | 2 | so on upto | 10
        :param str radio_2Ghz_tx_power: max | 1 | 2 | so on upto | 10 | min
        :param str radio_5Ghz_channelization: 20MHz | 40MHz
        :param str radio_5Ghz_channel_indoor: 0 | 36 | 40 | 44 | 48 | 149 | 153 | 157 | 161
        :param str radio_5Ghz_channel_outdoor: 0 | 149 | 153 | 157 | 161
        :param str radio_5Ghz_tx_power: max | -1 | upto | -10
        :param str tunnel_type: 1 | 0
        :param str enable_tunnel_encryption: 0 | 1
        :param str wan_interface_mtu: 1(auto) | 0(manual)
        :param str mtu_size: Size in bytes 850 to 1500
        :param str channel_mode: 0 | 1
        :param str back_ground_scan_on_2GHz: 0 | 1
        :param str back_ground_scan_on_2GHz_timer: 0 | 1
        :param str back_ground_scan_on_5GHz: 0 | 1
        :param str back_ground_scan_on_5GHz_timer: 0 to 65535
        :param str enableclbfor2GHz: 0 | 1
        :param str enableclbfor5GHz: 0 | 1
        :param str adj_radio_threshold_2GHz: Adjucent radio threshold of 2.4GHz 
        :param str adj_radio_threshold_5GHz: Adjucent radio threshold of 5GHz
        :param str smart_monitor_enable: 0 | 1
        :param str smart_monitor_interval: Health check interval  5 to 60
        :param str smart_monitor_threshold: Health check retry threshold 1 to 10
	:param str timezone_system_defined: True | False [default: True]
	:param str timezone: TimeZone [default: IST] 
	:param str timezone_user_defined: True | False [default: False]
	:param str timezone_abbreviation: TimeZone Abbreviation
	:param str gmt_offset: GMT offset
	:param str gmt_offset_num: GMT offset number
	:param str daylight_saving_time: True | False [default: False]
	:param str dst_start_month: Dst Start Month  1(January) | 2(Febuary) | 3(march) | 4(April) | ....| 12(December)
	:param str dst_start: Dst start    1 (First) | 2(second) | 3(third) | 4(Fourth) | 5(Last)
	:param str dst_start_day: 0(Sunday) | 1(Monday) | .....| 6(Saturday)
	:param str dst_start_clk: 0 to 23
	:param str dst_end_month:  1(January) | 2(Febuary) | 3(march) | 4(April) | ....| 12(December)
	:param str dst_end:  1 (First) | 2(second) | 3(third) | 4(Fourth) | 5(Last)
	:param str dst_end_day: 0(Sunday) | 1(Monday) | .....| 6(Saturday)
	:param str dst_end_clk: 0 to 23
        :return: True if APZone created else False
        :rtype: boolean
        """
        result = False
        zone_profile = {}
        zone_profile["meshConfig"] = {}
        try:
            url = ji.get_url(self.req_api_zoneprofile, self.scg_mgmt_ip, self.scg_port)
            zone_profile.update(self.SJT.zone_data())
            if not ap_firmware:
                url_firmware = ji.get_url(self.req_api_firmware, self.scg_mgmt_ip, self.scg_port)
                firmware_data = ji.get_json_data(url_firmware, self.jsessionid)
                len_firware_list = len(firmware_data['data']['list'])
                ap_firmware = firmware_data['data']['list'][len_firware_list - 1]['key']

            zone_profile.update({"zoneName":zone_name,
                               "zoneDescription":description,
                               "domainUUID":self.get_domain_uuid(domain_label=domain_label),
                               "fwVersion":ap_firmware})

            zone_profile["commonConfig"].update({"_allowIndoorChannel":int(channel_mode), "apLogin":login_id, "apPass":password,
                                               "countryCode": country_code, "tunnelMtuAutoEnabled":int(wan_interface_mtu), "tunnelMtuSize":int(mtu_size),
                                               "wifi0BgScan":int(back_ground_scan_on_2GHz), "wifi0BgScanTimer":int(back_ground_scan_on_2GHz_timer),
                                               "wifi0Channel":int(radio_2Ghz_channel), "wifi0ChannelWidth":radio_2Ghz_channelization,
                                               "wifi0TxPower":radio_2Ghz_tx_power, "wifi1BgScan":int(back_ground_scan_on_5GHz),
                                               "wifi1BgScanTimer":int(back_ground_scan_on_5GHz_timer), "wifi1Channel":int(radio_5Ghz_channel_outdoor),
                                               "wifi0ClbEnable":int(enableclbfor2GHz), 
                                               "wifi1ClbEnable":int(enableclbfor5GHz),
                                               "wifi0AdjThreshold":int(adj_radio_threshold_2GHz), "wifi1AdjThreshold":int(adj_radio_threshold_5GHz),
                                               "_wifi1Channel_indoor":int(radio_5Ghz_channel_indoor), "wifi1ChannelWidth":radio_5Ghz_channelization,
                                               "wifi1TxPower":radio_5Ghz_tx_power, "syslogIp":syslog_ip, "syslogPort":int(syslog_port),
                                               "smartMonEnable":int(smart_monitor_enable), "smartMonInterval":int(smart_monitor_interval),
                                               "smartMonThreshold":int(smart_monitor_threshold)})

	    if timezone_system_defined:
                zone_profile["commonConfig"].update({"timeZone":timezone})

            elif timezone_user_defined and daylight_saving_time:
                _timezone_abbreviation =  timezone_abbreviation+'(User-defined)'
                zone_profile["commonConfig"].update({"timeZone": _timezone_abbreviation})
                if '-' in gmt_offset:
                    _gmt_offset = gmt_offset.replace('GMT',timezone_abbreviation).replace('-', '+') + ':' + gmt_offset_num + 'UDDT' + ',M'+dst_start_month+ '.'+dst_start+'.'+dst_start_day+'/'+dst_start_clk+',M'+dst_end_month+ '.'+dst_end+'.'+dst_end_day+'/'+dst_end_clk
                    zone_profile["commonConfig"].update({"tzString":_gmt_offset})
                elif '+' in gmt_offset:
                    _gmt_offset = gmt_offset.replace('GMT',timezone_abbreviation).replace('+', '-') + ':' + gmt_offset_num + 'UDDT' + ',M'+dst_start_month+ '.'+dst_start+'.'+dst_start_day+'/'+dst_start_clk+',M'+dst_end_month+ '.'+dst_end+'.'+dst_end_day+'/'+dst_end_clk
                    zone_profile["commonConfig"].update({"tzString":_gmt_offset})


            elif timezone_user_defined:
                _timezone_abbreviation =  timezone_abbreviation+'(User-defined)'
                zone_profile["commonConfig"].update({"timeZone": _timezone_abbreviation})
                if '-' in gmt_offset:
                   _gmt_offset = gmt_offset.replace('GMT',timezone_abbreviation).replace('-', '+') + ':' + gmt_offset_num
                   zone_profile["commonConfig"].update({"tzString":_gmt_offset})
                elif '+' in gmt_offset:
                    _gmt_offset = gmt_offset.replace('GMT',timezone_abbreviation).replace('+', '-') + ':' + gmt_offset_num
                    zone_profile["commonConfig"].update({"tzString":_gmt_offset})
	
            if int(enable_mesh) == 1:
                zone_profile["meshConfig"].update({"meshEnable":int(enable_mesh), "meshSSID":mesh_name, 
                                             "meshPassphrase":mesh_passphrase,
                                             "meshUplinkSelection":mesh_uplink_selection})

            zone_profile["tunnelConfig"].update({"tunnelType":int(tunnel_type), "tunnelEncryption":int(enable_tunnel_encryption)})

            data_json = json.dumps(zone_profile)
            result = ji.post_json_data(url, self.jsessionid, data_json)

        except Exception, e:
            print "Exception", traceback.format_exc()
            return False

        return result

    def validate_apzone(self, zone_name="Auto_APZone", domain_label='Administration Domain', description=None, ap_firmware=None,
                            country_code=None, login_id=None, password=None, enable_external_syslog=None,
                            syslog_ip=None, syslog_port=None, enable_mesh=None,
                            mesh_name=None, mesh_passphrase=None,
                            mesh_uplink_selection=None,
                            radio_2Ghz_channel=None,                       #0(Auto) to 11
                            radio_2Ghz_channelization=None,          #20MHz or 40MHz
                            radio_2Ghz_tx_power=None,                  #full="max" and -1 to -10 ,"min"
                            radio_5Ghz_channel_indoor=None,                #0,36,40,44,48,149,153,157,161
                            radio_5Ghz_channel_outdoor=None,               #0,36,40,44,48,149,153,157,161
                            radio_5Ghz_channelization=None,          #20MHz or 40MHz
                            radio_5Ghz_tx_power=None,                  #full="max" and -1 to -10 ,"min"
                            tunnel_type=None,                              #GRE+UDP:1, GRE:0
                            enable_tunnel_encryption=None,                 #0 or 1
                            wan_interface_mtu=None,                       #tunnel MTU enable:auto(1) or manual (0)
                            mtu_size=None,                              #in bytes from 850 to 1500
                            channel_mode=None,                             #allow_indoor_channels:1 or 0
                            back_ground_scan_on_2GHz=None,                 #1 or 0
                            back_ground_scan_on_2GHz_timer=None,           #1 to 65535
                            back_ground_scan_on_5GHz=None,                 #1 or 0
                            back_ground_scan_on_5GHz_timer=None,
                            enableclbfor2GHz=None, enableclbfor5GHz=None,
                            adj_radio_threshold_2GHz=None, adj_radio_threshold_5GHz=None,
                            smart_monitor_enable=None, smart_monitor_interval=None, smart_monitor_threshold=None
                            ):
        """
        This API creates AP zone

        URI: GET /wsg/api/scg/zones/<apzone_uuid>/config

        :param str zone_name: Name of the Zone to be created
        :param str description: Description related to zone
        :param str ap_firmware: AP Firmware
        :param str country_code: Country Code eg: US
        :param str login_id: For admin login Login ID
        :param str password: For admin login Password 
        :param str syslog_ip: Syslog server ip
        :param str syslog_port: Syslog Port number
        :param str enable_mesh: 0 | 1
        :param str mesh_name: Mesh name or ESSID
        :param str mesh_passphrase: Mesh Passphrase
        :param str mesh_uplink_selection: throughput | rssi
        :param str radio_2Ghz_channelization: 20MHz | 40MHz
        :param str radio_2Ghz_channel: 0 | 1 | 2 | so on upto | 10
        :param str radio_2Ghz_tx_power: max | 1 | 2 | so on upto | 10 | min
        :param str radio_5Ghz_channelization: 20MHz | 40MHz
        :param str radio_5Ghz_channel_indoor: 0 | 36 | 40 | 44 | 48 | 149 | 153 | 157 | 161
        :param str radio_5Ghz_channel_outdoor: 0 | 149 | 153 | 157 | 161
        :param str radio_5Ghz_tx_power: max | -1 | upto | -10
        :param str tunnel_type: 1(GRE+UDP) | 0(GRE)
        :param str enable_tunnel_encryption: 0 | 1
        :param str wan_interface_mtu: 1(auto) | 0(manual)
        :param str mtu_size: Size in bytes 850 to 1500
        :param str channel_mode: 0 | 1
        :param str back_ground_scan_on_2GHz: 0 | 1
        :param str back_ground_scan_on_2GHz_timer: 0 | 1
        :param str back_ground_scan_on_5GHz: 0 | 1
        :param str back_ground_scan_on_5GHz_timer: 0 to 65535
        :param str enableclbfor2GHz: 0 | 1
        :param str enableclbfor5GHz: 0 | 1
        :param str adj_radio_threshold_2GHz: Adjucent radio threshold of 2.4GHz 
        :param str adj_radio_threshold_5GHz: Adjucent radio threshold of 5GHz
        :param str smart_monitor_enable: 0 | 1
        :param str smart_monitor_interval: Health check intervali 5 to 60
        :param str smart_monitor_threshold: Health check retry threshold 1 to 10
        :return: True if APZone created else False
        :rtype: boolean

        """

        try:
            req_zone_url = ji.get_url(self.req_api_update_zoneprofile%self.get_apzone_uuid(apzone_name=zone_name, domain_label=domain_label), \
                    self.scg_mgmt_ip, self.scg_port)
            zone_profile_data = ji.get_json_data(req_zone_url, self.jsessionid)
            rcvd_data = copy.deepcopy(zone_profile_data["data"])

            if zone_name:
                if zone_name != rcvd_data['zoneName']:
                    self._print_err_validate('validate_apzone', 'zone_name', 'zoneName', zone_name, rcvd_data['zoneName'])
                    return False
            if description:
                if description != rcvd_data["zoneDescription"]:
                    self._print_err_validate('validate_apzone', 'description', 'description', description, rcvd_data["zoneDescription"])
                    return False
            if ap_firmware:
                if ap_firmware != rcvd_data["fwVersion"]:
                    self._print_err_validate('validate_apzone', 'ap_firmware', 'fwVersion', ap_firmware, rcvd_data["fwVersion"])
                    return False
            if country_code:
                if country_code != rcvd_data["commonConfig"]["countryCode"]:
                    self._print_err_validate('validate_apzone', 'country_code', 'countryCode', country_code, rcvd_data["commonConfig"]["countryCode"])
                    return False
            if login_id:
                if login_id != rcvd_data["commonConfig"]["apLogin"]:
                    self._print_err_validate('validate_apzone', 'login_id', 'apLogin', login_id, rcvd_data["commonConfig"]["apLogin"])
                    return False
            if password:
                if password != rcvd_data["commonConfig"]["apPass"]:
                    self._print_err_validate('validate_apzone', 'password', 'apPass', password, rcvd_data["commonConfig"]["apPass"])
                    return False
            """
            if enable_external_syslog:
                if enable_external_syslog != rcvd_data["commonConfig"]["_allowIndoorChannel"]:
                    self._print_err_validate('validate_apzone', 'enable_eternal_syslog', '_allowIndoorChannel', enable_external_syslog,
                            rcvd_data["commonConfig"]["_allowIndoorChannel"])
                    return False
            """
            if syslog_ip:
                if syslog_ip != rcvd_data["commonConfig"]["syslogIp"]:
                    self._print_err_validate('validate_apzone', 'syslog_ip', 'syslogIp', syslog_ip, rcvd_data["commonConfig"]["syslogIp"])
                    return False
            if syslog_port:
                if syslog_port != str(rcvd_data["commonConfig"]["syslogPort"]):
                    self._print_err_validate('validate_apzone', 'syslog_port', 'syslogPort', syslog_port, rcvd_data["commonConfig"]["syslogPort"])
                    return False
            if enable_mesh:
                if enable_mesh != str(rcvd_data["meshConfig"]["meshEnable"]):
                    self._print_err_validate('validate_apzone', 'enable_mesh', 'meshEnable', enable_mesh, 
                            rcvd_data["meshConfig"]["meshEnable"])
                    return False
            if enable_mesh == '1':
                if mesh_name:
                    if mesh_name != rcvd_data["meshConfig"]["meshSSID"]:
                        self._print_err_validate('validate_apzone', 'mesh_name', 'meshSSID', mesh_name,
                            rcvd_data["commonConfig"]["meshSSID"])
                        return False
                if mesh_passphrase:
                    if mesh_passphrase != rcvd_data["meshConfig"]["meshPassphrase"]:
                        self._print_err_validate('validate_apzone', 'mesh_passphrase', 'meshPassphrase', mesh_passphrase,
                            rcvd_data["commonConfig"]["meshPassphrase"])
                        return False
                if mesh_uplink_selection:
                    if mesh_uplink_selection != rcvd_data["meshConfig"]["meshUplinkSelection"]:
                        self._print_err_validate('validate_apzone', 'mesh_uplink_selection', 'meshUplinkSelection', mesh_uplink_selection,
                                rcvd_data["commonConfig"]["meshUplinkSelection"])
                        return False
            if radio_2Ghz_channel:
                if radio_2Ghz_channel != str(rcvd_data["commonConfig"]["wifi0Channel"]):
                    self._print_err_validate('validate_apzone', 'radio_2Ghz_channel', 'wifi0Channel', radio_2Ghz_channel,
                            rcvd_data["commonConfig"]["wifi0Channel"])
                    return False
            if radio_2Ghz_channelization:
                if radio_2Ghz_channelization != rcvd_data["commonConfig"]["wifi0ChannelWidth"]:
                    self._print_err_validate('validate_apzone', 'radio_2Ghz_channelization', 'wifi0ChannelWidth', radio_2Ghz_channelization,
                            rcvd_data["commonConfig"]["wifi0ChannelWidth"])
                    return False
            if radio_2Ghz_tx_power:
                if radio_2Ghz_tx_power != rcvd_data["commonConfig"]["wifi0TxPower"]:
                    self._print_err_validate('validate_apzone', 'radio_2Ghz_tx_power', 'wifi0TxPower', radio_2Ghz_tx_power,
                            rcvd_data["commonConfig"]["wifi0TxPower"])
                    return False
            if radio_5Ghz_channel_indoor:
                if radio_5Ghz_channel_indoor != str(rcvd_data["commonConfig"]["_wifi1Channel_indoor"]):
                    self._print_err_validate('validate_apzone', 'radio_5Ghz_channel_indoor', '_wifi1Channel_indoor', radio_5Ghz_channel_indoor,
                            rcvd_data["commonConfig"]["_wifi1Channel_indoor"])
                    return False
            if radio_5Ghz_channel_outdoor:
                if radio_5Ghz_channel_outdoor != str(rcvd_data["commonConfig"]["wifi1Channel"]):
                    self._print_err_validate('validate_apzone', 'radio_5Ghz_channel_outdoor', 'wifi1Channel', radio_5Ghz_channel_outdoor,
                            rcvd_data["commonConfig"]["wifi1Channel"])
                    return False

            if radio_5Ghz_channelization:
                if radio_5Ghz_channelization != rcvd_data["commonConfig"]["wifi1ChannelWidth"]:
                    self._print_err_validate('validate_apzone', 'radio_5Ghz_channelization', 'wifi1ChannelWidth', 
                            radio_5Ghz_channelization, rcvd_data["commonConfig"]["wifi1ChannelWidth"])
                    return False

            if radio_5Ghz_tx_power:
                if radio_5Ghz_tx_power != rcvd_data["commonConfig"]["wifi1TxPower"]:
                    self._print_err_validate('validate_apzone', 'radio_5Ghz_tx_power', 'wifi1TxPower', radio_5Ghz_tx_power,
                            rcvd_data["commonConfig"]["wifi1TxPower"])
                    return False
            if tunnel_type:
                if tunnel_type != str(rcvd_data["tunnelConfig"]["_tunnelType"]):
                    self._print_err_validate('validate_apzone', 'tunnel_type', '_tunnelType', tunnel_type,
                            rcvd_data["tunnelConfig"]["_tunnelType"])
                    return False
            
            if enable_tunnel_encryption:
                if enable_tunnel_encryption != str(rcvd_data["tunnelConfig"]["tunnelEncryption"]):
                    self._print_err_validate('validate_apzone', 'enable_tunnel_encryption', 'tunnelEncryption',
                            enable_tunnel_encryption, rcvd_data["tunnelConfig"]["tunnelEncryption"])
                    return False
            
            if wan_interface_mtu:
                if wan_interface_mtu != str(rcvd_data["tunnelConfig"]["tunnelMtuAutoEnabled"]):
                    self._print_err_validate('validate_apzone', 'wan_interface_mtu', 'tunnelMtuAutoEnabled', wan_interface_mtu,
                            rcvd_data["commonConfig"]["tunnelMtuAutoEnabled"])
                    return False
            if mtu_size:
                if mtu_size != str(rcvd_data["tunnelConfig"]["tunnelMtuSize"]):
                    self._print_err_validate('validate_apzone', 'mtu_size', 'tunnelMtuSize', mtu_size,
                            rcvd_data["tunnelConfig"]["tunnelMtuSize"])
                    return False

            if back_ground_scan_on_2GHz:
                if back_ground_scan_on_2GHz != str(rcvd_data["commonConfig"]["wifi0BgScan"]):
                    self._print_err_validate('validate_apzone', 'back_ground_scan_on_2GHz', 'wifi0BgScan', back_ground_scan_on_2GHz,
                            rcvd_data["commonConfig"]["wifi0BgScan"])
                    return False
            if back_ground_scan_on_2GHz_timer:
                if back_ground_scan_on_2GHz_timer != str(rcvd_data["commonConfig"]["wifi0BgScanTimer"]):
                    self._print_err_validate('validate_apzone', 'back_ground_scan_on_2GHz_timer', 'wifi0BgScanTimer',
                            back_ground_scan_on_2GHz_timer, rcvd_data["commonConfig"]["wifi0BgScanTimer"])
                    return False
            if back_ground_scan_on_5GHz:
                if back_ground_scan_on_5GHz != str(rcvd_data["commonConfig"]["wifi1BgScan"]):
                    self._print_err_validate('validate_apzone', 'back_ground_scan_on_5GHz', 'wifi1BgScan', back_ground_scan_on_5GHz,
                            rcvd_data["commonConfig"]["wifi1BgScan"])
                    return False
            if back_ground_scan_on_5GHz_timer:
                if back_ground_scan_on_5GHz_timer != str(rcvd_data["commonConfig"]["wifi1BgScanTimer"]):
                    self._print_err_validate('validate_apzone', 'back_ground_scan_on_5GHz_timer', 'wifi1BgScanTimer',
                            back_ground_scan_on_5GHz_timer, rcvd_data["commonConfig"]["wifi1BgScanTimer"])
                    return False
            if enableclbfor2GHz:
                if enableclbfor2GHz != str(rcvd_data["commonConfig"]["wifi0ClbEnable"]):
                    self._print_err_validate('validate_apzone', 'enableclbfor2GHz', 'wifi0ClbEnable', enableclbfor2GHz,
                            rcvd_data["commonConfig"]["wifi0ClbEnable"])
                    return False
            if enableclbfor5GHz:
                if enableclbfor5GHz != str(rcvd_data["commonConfig"]["wifi1ClbEnable"]):
                    self._print_err_validate('validate_apzone', 'enableclbfor5GHz', 'wifi1ClbEnable', enableclbfor5GHz, 
                            rcvd_data["commonConfig"]["wifi1ClbEnable"])
                    return False
            if adj_radio_threshold_2GHz:
                if adj_radio_threshold_2GHz != str(rcvd_data["commonConfig"]["wifi0AdjThreshold"]):
                    self._print_err_validate('validate_apzone', 'adj_radio_threshold_2GHz', 'wifi0AdjThreshold',
                            adj_radio_threshold_2GHz, rcvd_data["commonConfig"]["wifi0AdjThreshold"])
                    return False
            if adj_radio_threshold_5GHz:
                if adj_radio_threshold_5GHz != str(rcvd_data["commonConfig"]["wifi1AdjThreshold"]):
                    self._print_err_validate('validate_apzone', 'adj_radio_threshold_5GHz', 'wifi1AdjThreshold',
                            adj_radio_threshold_5GHz, rcvd_data["commonConfig"]["wifi1AdjThreshold"])
                    return False
            if smart_monitor_enable:
                if smart_monitor_enable != str(rcvd_data["commonConfig"]["smartMonEnable"]):
                    self._print_err_validate('validate_apzone', 'smart_monitor_enable', 'smartMonEnable', smart_monitor_enable,
                            rcvd_data["commonConfig"]["smartMonEnable"])
                    return False
            if smart_monitor_interval:
                if smart_monitor_interval != str(rcvd_data["commonConfig"]["smartMonInterval"]):
                    self._print_err_validate('validate_apzone', 'smart_monitor_interval', 'smartMonInterval', smart_monitor_interval,
                            rcvd_data["commonConfig"]["smartMonInterval"])
                    return False
            if smart_monitor_threshold:
                if smart_monitor_threshold != str(rcvd_data["commonConfig"]["smartMonThreshold"]):
                    self._print_err_validate('validate_apzone', 'smart_monitor_threshold', 'smartMonThreshold', smart_monitor_threshold,
                            rcvd_data["commonConfig"]["smartMonThreshold"])
                    return False



            return True
        except Exception, e:
            print "Exception", traceback.format_exc()
            return False

        

    def update_apzone(self, current_zone_name="Auto_APZone", new_zone_name=None, domain_label='Administration Domain', description=None,
                      ap_firmware=None, country_code=None, login_id=None,
                      password=None, syslog_ip=None, syslog_port=None,
                      enable_mesh=None, mesh_name=None, mesh_passphrase=None,
                      mesh_uplink_selection=None,
                      radio_2Ghz_channel=None,                       # 0(Auto) to 11
                      radio_2Ghz_channelization=None,                #20MHz or 40MHz
                      radio_2Ghz_tx_power=None,                      #full="max" and -1 to -10 ,"min"
                      radio_5Ghz_channel_indoor=None,                # 0,36,40,44,48,149,153,157,161
                      radio_5Ghz_channel_outdoor=None,               # 0,36,40,44,48,149,153,157,161
                      radio_5Ghz_channelization=None,                #20MHz or 40MHz
                      radio_5Ghz_tx_power=None,                      #full="max" and -1 to -10 ,"min"
                      tunnel_type=None,                              # GRE+UDP:1, GRE:0
                      enable_tunnel_encryption=None,                 #0 or 1
                      wan_interface_mtu=None,                        # tunnel MTU enable:auto(1) or manual (0)
                      mtu_size=None,                                 #in bytes from 850 to 1500
                      channel_mode=None,                             #allow_indoor_channels:1 or 0
                      back_ground_scan_on_2GHz=None,                 #1 or 0
                      back_ground_scan_on_2GHz_timer=None,           #1 to 65535
                      back_ground_scan_on_5GHz=None,                 #1 or 0
                      back_ground_scan_on_5GHz_timer=None,
                      enableclbfor2GHz=None,
                    enableclbfor5GHz=None,
                    adj_radio_threshold_2GHz=None,
                    adj_radio_threshold_5GHz=None,
                    smart_monitor_enable=None,
                    smart_monitor_interval=None,
                    smart_monitor_threshold=None ):

        """
        This API update AP zone

        URI: POST /wsg/api/scg/zones/<apzone_uuid>/config

        :param str current_zone_name: APZone name to be updated 
        :param str new_zone_name: New name of the Zone 
        :param str description: Description related to zone
        :param str ap_firmware: AP Firmware
        :param str country_code: Country Code eg: US
        :param str login_id: For admin login Login ID
        :param str password: For admin login Password 
        :param str syslog_ip: Syslog server ip
        :param str syslog_port: Syslog Port number
        :param str enable_mesh: 0 | 1
        :param str mesh_name: Mesh name or ESSID
        :param str mesh_passphrase: Mesh Passphrase
        :param str mesh_uplink_selection: throughput | rssi
        :param str radio_2Ghz_channelization: 20MHz | 40MHz
        :param str radio_2Ghz_channel: 0 | 1 | 2 | so on upto | 10
        :param str radio_2Ghz_tx_power: max | 1 | 2 | so on upto | 10 | min
        :param str radio_5Ghz_channelization: 20MHz | 40MHz
        :param str radio_5Ghz_channel_indoor: 0 | 36 | 40 | 44 | 48 | 149 | 153 | 157 | 161
        :param str radio_5Ghz_channel_outdoor: 0 | 149 | 153 | 157 | 161
        :param str radio_5Ghz_tx_power: max | -1 | upto | -10
        :param str tunnel_type: 1(GRE+UDP) | 0(GRE)
        :param str enable_tunnel_encryption: 0 | 1
        :param str wan_interface_mtu: 1(auto) | 0(manual)
        :param str mtu_size: Size in bytes 850 to 1500
        :param str channel_mode: 0 | 1
        :param str back_ground_scan_on_2GHz: 0 | 1
        :param str back_ground_scan_on_2GHz_timer: 0 | 1
        :param str back_ground_scan_on_5GHz: 0 | 1
        :param str back_ground_scan_on_5GHz_timer: 0 to 65535
        :param str enableclbfor2GHz: 0 | 1
        :param str enableclbfor5GHz: 0 | 1
        :param str adj_radio_threshold_2GHz: Adjucent radio threshold of 2.4GHz 
        :param str adj_radio_threshold_5GHz: Adjucent radio threshold of 5GHz
        :param str smart_monitor_enable: 0 | 1
        :param str smart_monitor_interval: Health check interval 5 to 60
        :param str smart_monitor_threshold: Health check retry threshold 1 to 10
        :return: True if APZone updated else False
        :rtype: boolean

        """
        result = False
        fwd_zone_data = {}
        try:
            req_zone_url = ji.get_url(self.req_api_update_zoneprofile%self.get_apzone_uuid(apzone_name=current_zone_name, 
                                                              domain_label=domain_label), self.scg_mgmt_ip, self.scg_port)
            zone_profile_data = ji.get_json_data(req_zone_url, self.jsessionid)
            zone_profile = zone_profile_data["data"]
            fwd_zone_data.update(self.SJT.get_zone_data_update())
            fwd_zone_data["tunnelProfileUUID"] = zone_profile["tunnelProfileUUID"]
            fwd_zone_data["zoneUUID"] = zone_profile["zoneUUID"]
            fwd_zone_data["zoneName"] = zone_profile["zoneName"] if new_zone_name is None else new_zone_name
            fwd_zone_data["fwVersion"] = zone_profile["fwVersion"]
            fwd_zone_data["zoneDescription"] = zone_profile["zoneDescription"] if description is None else description
            fwd_zone_data["tunnelType"] = zone_profile["tunnelType"]
            fwd_zone_data["commonConfig"]["countryCode"] = \
                    zone_profile["commonConfig"]["countryCode"] if country_code is None else country_code

            fwd_zone_data["commonConfig"]["apLogin"] = \
                    zone_profile["commonConfig"]["apLogin"] if login_id is None else login_id

            fwd_zone_data["commonConfig"]["apPass"] = \
                    zone_profile["commonConfig"]["apPass"] if password is None else password

            fwd_zone_data["commonConfig"]["syslogIp"] = \
                    zone_profile["commonConfig"]["syslogIp"] if syslog_ip is None else syslog_ip

            fwd_zone_data["commonConfig"]["syslogPort"] = \
                    zone_profile["commonConfig"]["syslogPort"] if syslog_port is None else int(syslog_port)

            fwd_zone_data["commonConfig"]["_allowIndoorChannel"] = \
                    zone_profile["commonConfig"]["_allowIndoorChannel"] if channel_mode is None else int(channel_mode)


            fwd_zone_data["commonConfig"]["wifi0BgScan"] = \
                    zone_profile["commonConfig"]["wifi0BgScan"] if back_ground_scan_on_2GHz is None else int(back_ground_scan_on_2GHz)

            fwd_zone_data["commonConfig"]["wifi0BgScanTimer"] = \
                    zone_profile["commonConfig"]["wifi0BgScanTimer"] if back_ground_scan_on_2GHz_timer is None else int(back_ground_scan_on_2GHz_timer)

            fwd_zone_data["commonConfig"]["wifi0Channel"] = \
                    zone_profile["commonConfig"]["wifi0Channel"] if radio_2Ghz_channel is None else int(radio_2Ghz_channel)

            fwd_zone_data["commonConfig"]["wifi0ChannelWidth"] = \
                    zone_profile["commonConfig"]["wifi0ChannelWidth"] if radio_2Ghz_channelization is None else radio_2Ghz_channelization

            fwd_zone_data["commonConfig"]["wifi0TxPower"] = \
                    zone_profile["commonConfig"]["wifi0TxPower"] if radio_2Ghz_tx_power is None else radio_2Ghz_tx_power

            fwd_zone_data["commonConfig"]["wifi1BgScan"] = \
                    zone_profile["commonConfig"]["wifi1BgScan"] if back_ground_scan_on_5GHz is None else int(back_ground_scan_on_5GHz)

            fwd_zone_data["commonConfig"]["wifi1BgScanTimer"]= \
                    zone_profile["commonConfig"]["wifi1BgScanTimer"] if back_ground_scan_on_5GHz_timer is None else int(back_ground_scan_on_5GHz_timer)

            fwd_zone_data["commonConfig"]["wifi1Channel"] = \
                    zone_profile["commonConfig"]["wifi1Channel"] if radio_5Ghz_channel_outdoor is None else int(radio_5Ghz_channel_outdoor)

            fwd_zone_data["commonConfig"]["_wifi1Channel_indoor"] = \
                    zone_profile["commonConfig"]["_wifi1Channel_indoor"] if radio_5Ghz_channel_indoor is None else int(radio_5Ghz_channel_indoor)

            fwd_zone_data["commonConfig"]["wifi1ChannelWidth"] = \
                    zone_profile["commonConfig"]["wifi1ChannelWidth"] if radio_5Ghz_channelization is None else radio_5Ghz_channelization

            fwd_zone_data["commonConfig"]["wifi1TxPower"] = \
                    zone_profile["commonConfig"]["wifi1TxPower"] if radio_5Ghz_tx_power is None else radio_5Ghz_tx_power
            fwd_zone_data["meshConfig"] = {}
            if zone_profile["meshConfig"]["meshEnable"] == 1:
                fwd_zone_data["meshConfig"].update({"meshEnable":zone_profile["meshConfig"]["meshEnable"]})

                fwd_zone_data["meshConfig"].update({"meshSSID":zone_profile["meshConfig"]["meshSSID"]})

                fwd_zone_data["meshConfig"].update({"meshPassphrase":zone_profile["meshConfig"]["meshPassphrase"] })
            else:
                fwd_zone_data["meshConfig"].update({"meshEnable":zone_profile["meshConfig"]["meshEnable"] 
                                                                 if enable_mesh is None else int(enable_mesh),
                                                    "meshSSID":zone_profile["meshConfig"]["meshSSID"]
                                                                if mesh_name is None else mesh_name,
                                                    "meshPassphrase":zone_profile["meshConfig"]["meshPassphrase"]
                                                                if mesh_passphrase is None else mesh_passphrase})

            fwd_zone_data["meshConfig"].update({"meshUplinkSelection":zone_profile["meshConfig"]["meshUplinkSelection"] 
                                                                     if not mesh_uplink_selection else mesh_uplink_selection})

            #fwd_zone_data["tunnelConfig"]["tunnelEncryption"] = str(zone_profile["tunnelConfig"]["tunnelEncryption"])
            #fwd_zone_data["tunnelConfig"]["_tunnelType"] = str(zone_profile["tunnelConfig"]["_tunnelType"])

            fwd_zone_data["commonConfig"]["wifi0ClbEnable"] = zone_profile["commonConfig"]["wifi0ClbEnable"] \
                    if not enableclbfor2GHz else int(enableclbfor2GHz)
            fwd_zone_data["commonConfig"]["wifi1ClbEnable"] = zone_profile["commonConfig"]["wifi1ClbEnable"] \
                    if not enableclbfor5GHz else int(enableclbfor5GHz)
            fwd_zone_data["commonConfig"]["wifi0AdjThreshold"] = zone_profile["commonConfig"]["wifi0AdjThreshold"]\
                    if not adj_radio_threshold_2GHz else int(adj_radio_threshold_2GHz)
            fwd_zone_data["commonConfig"]["wifi1AdjThreshold"] = zone_profile["commonConfig"]["wifi1AdjThreshold"]\
                    if not adj_radio_threshold_5GHz else int(adj_radio_threshold_5GHz)
            fwd_zone_data["commonConfig"]["smartMonEnable"] = zone_profile["commonConfig"]["smartMonEnable"] \
                    if not smart_monitor_enable else int(smart_monitor_enable)
            fwd_zone_data["commonConfig"]["smartMonInterval"] = zone_profile["commonConfig"]["smartMonInterval"]\
                    if not smart_monitor_interval else int(smart_monitor_interval)
            fwd_zone_data["commonConfig"]["smartMonThreshold"] = zone_profile["commonConfig"]["smartMonThreshold"]\
                    if not smart_monitor_threshold else int(smart_monitor_threshold)

            json_data = json.dumps(fwd_zone_data)
            result = ji.put_json_data(req_zone_url, self.jsessionid, json_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def delete_apzone(self, zone_name="Auto_APZone", domain_label='Administration Domain'):
        """
        API is used to delete the AP Zone

        URI: DELETE /wsg/api/scg/zones/<recvd_aaa_profile_keys> 

        :param str zone_name: Ap Zone Name
        :param str domain_label: Name of the Domain
        :return: True if Ap Zone is deleted else False
        :rtype: boolean
        
        """
  
        result = False
        key = None
        try:
            del_url = ji.get_url(self.req_zone_api, self.scg_mgmt_ip, self.scg_port)
            zone_data = ji.get_json_data(del_url%self.get_domain_uuid(domain_label=domain_label), self.jsessionid)

            for i in range(0,len(zone_data[u"data"][u"list"])):
                if zone_data[u"data"][u"list"][i][u"mobilityZoneName"] == zone_name:
                    key = zone_data[u"data"][u"list"][i][u"key"]
            if not key:
                raise Exception("delete_apzone(): key not found for the zone_name: %s"%(zone_name))
                return False
            del_zone_url = ji.get_url(self.req_api_del_zoneprofile%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.delete_scg_data(del_zone_url, self.jsessionid, None)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result 
  
    def _get_key_for_profile(self, name='Service_name', url=None):
        """ 
        API used in creating updating wlan_profile
        
        :param str name: Name of the Service
        :param str url: URL
        :return: key and data of Service
        :rtype: dictionary

        """

        key, key_info = None, None
        data = ji.get_json_data(url, self.jsessionid)
    
        for i in range(0,len(data[u"data"][u"list"])):              
            if data[u"data"][u"list"][i][u"name"] == name:
                key, key_info = data[u"data"][u"list"][i][u"key"], data[u"data"][u"list"][i]
                break
        if not key:
            raise Exception("_get_key_for_profile(): Key not found for the name: %s" % (name))

        return {'key':key, 'data_ret':key_info}

    def _get_guest_access_id(self, apzone_name='Auto_APZone',
                                    domain_label='Administration Domain',
                                    guest_access_name=None):

        key = None
        guest_api = '/wsg/api/scg/guestAccess/byZone/%s'
        zone_uuid = self.get_apzone_uuid(apzone_name=apzone_name, domain_label=domain_label)
        data_api = guest_api%zone_uuid
        url = ji.get_url(data_api, self.scg_mgmt_ip, self.scg_port)
        data = ji.get_json_data(url, self.jsessionid)

        for i in range(0, len(data['data']['list'])):
            if data['data']['list'][i]['name'] == guest_access_name:
                key = data['data']['list'][i]['key']
                break
        if not key:
            raise Exception("_get_guest_access_id(): Key not found for the name %s " % guest_access_name)
        return key



    def create_wlan(self,
            wlan_name="Auto_WLAN_Profile",
            ssid="Auto_ssid",
            description=None,
            apzone_name="Auto_APZone",
            domain_label='Administration Domain',
            enable_tunnel='0',                        #0 or 1
            core_network_type="Bridge",               #L30GRE,L20GRE,TTGPDG,Mixed
            authentication_type='0',                  #0:standard, 1:Hotspot(wispr),  3:Hotspot2.0
            auth_type_name='Local DB',
            authentication_method="OPEN",             #OPEN ,802.1x, MAC
            enable_mac_auth_password='0',             #1 or 0
            mac_auth_password=None,
            set_device_mac_address=None,              #1 or 0
            encryption_method="NONE",                 #WPA ,WPA2 ,WPA-MIXED,WEP,NONE
            wpa_version='WPA2',
            wep_key_index=None,                       #1 to 4
            wep_key=None,
            encryption_algorithm="AES",               #TKIP, AUTO, AES
            passphrase=None,
            enable_scg_proxy_for_auth='0',            #0 or 1
            enable_scg_proxy_for_acct='0',            #0 or 1
            acct_profile_name='Disable',              #"acct_auto",
            auth_profile_name='Disable',              #"auth_pro",
            acct_interim_time='10',
            wispr_hotspot_name=None,                  #"Auto_wispr_profile",
            hotspot2_name=None,                       #"Auto_hotspot2_profile",
            frwd_profile_name=None,                   #"Auto_fwd_profile",
            guest_access_name=None,
            acct_ttg_enable='1',                      #0 or 1 - This option is not applicable to scg 3.0 - keep default 1
            nas_id_type="BSSID",                      #BSSID, APMAC, USER
            nas_id_user_def=None,
            radius_request_timeout='3',
            radius_max_retries='2',
            nas_reconnect_primary='5',
            called_sta_id='0',                        #0: BSSID,  1:APMAC
            client_isolation='0',                     # 1:enable,  0:disable
            priority="high",                          #high or low
            rate_limit_uplink="0",                    # disable:0,  or in mbps
            rate_limit_downlink="0",
            vlanid='1',
            dynamic_vlan_enable='0',
            hide_ssid='1',                            #0:broadcast, 0:hide ssid
            proxy_arp='0',                            #1 or 0
            max_clients='100',                    
            support_80211d='0',                       #1 or 0
            enable_dhcp='0',                          #1 or 0
            ofdm_only='0',
            client_tx_rx_statistic='0',               #1 or 0
            inactivity_timeout='120',                 #1 or 0
            enable_client_fingerprint='0',            #1 or 0
            disable_wlan='0',                         #1 or 0
            enable_ofdm_only='0',
            bss_min_rate="0",
            mgmt_tx_rate="2mbps"):
        """ 
        API used to create WLAN 

        URI: POST /wsg/api/scg/wlans/

        :param str wlan_name: Name of WLAN
        :param str ssid: SSID
        :param str description: Description
        :param str apzone_name: Name of APZone
        :param str domain_label: Name of Domain
        :param str enable_tunnel: 0 | 1             
        :param str core_network_type: L30GRE | L20GRE | TTGPDG | Mixed
        :param str authentication_type: 0 - Standard | 1 - Wispr | 3 - Hotspot2.0
        :param str authentication_method: OPEN | 802.1X | MAC
        :param str enable_mac_auth_password: 0 | 1
        :param str mac_auth_password: MAC Authentication
        :param str set_device_mac_address: 0 | 1
        :param str encryption_method: WPA | WPA2 | WPA-MIXED | WEP | NONE
        :param str wpa_vesion: WPA Version
        :param str wep_key_index: WEP key index 1 to 4
        :param str wep_key: WEP Key
        :param str encryption_algorithm: TKIP | AUTO | AES
        :param str passphrase: Passphrase
        :param str enable_scg_proxy_for_auth: 0 | 1
        :param str enable_scg_proxy_for_acct: 0 | 1
        :param str acct_ttg_enable: 0 | 1
        :param str acct_profile_name: Accounting Profile name
        :param str acct_interim_time: 0 - 1440
        :param str auth_profile_name: Authentication Profile name
        :param str wispr_hotspot_name: WISPr Profile name
        :param str enable_hotspot_radius_proxy: 0 | 1  
        :param str hotspot2_name: Hotspot2.0 name
        :param str frwd_profile_name: Name Forwarding profile
        :param str nas_id_type: BSSID | APMAC | USER
        :param str nas_id_user_def: NAS ID used defined
        :param str radius_request_timeout: Radius request timeout
        :param str radius_max_retries: Radius maximum no of retries
        :param str nas_reconnect_primary: NAS Reconnect primary
        :param str called_sta_id: 0 | 1
        :param str acct_delay_time_enable: 0 | 1
        :param str client_isolation: 1<enable> | 0<disable>
        :param str priority: high | low
        :param str rate_limit_uplink: 0<disable> | unit in mbps
        :param str rate_limit_downlink: 0<disable> | unit in mbps
        :param str vlanid: VLAN id
        :param str dynamic_vlan_enable: 0 | 1
        :param str core_qinq_enable: 0 | 1
        :param str vlanmapping_type: VLAN mapping type
        :param str core_add_fixed_svlan: Core add fixed SVLAN
        :param str hide_ssid: 1<broadcast> | 0<hide ssid>
        :param str proxy_arp: 0 | 1    
        :param str max_clients: Maximum clients 
        :param str support_80211d: 0 | 1
        :param str enable_dhcp: 0 | 1
        :param str client_tx_rx_statistic: 0 | 1
        :param str inactivity_timeout: 60 to 600
        :param str enable_client_fingerprint: 0 | 1
        :param str disable_wlan: 0 | 1
        :param str bss_min_rate: BSS minimum bit rate
        :param str mgmt_tx_rate: 1, 2, 5.5, 11 mbps
        :return: True if WLAN created successfully else False
        :rtype: boolean
 
        """

        result = False
        wlan_profile = {}
        wlan_profile = {'configContent': {} }

        try:
            auth_url = ji.get_url(self.req_api_authprofile, self.scg_mgmt_ip, self.scg_port)
            acct_url = ji.get_url(self.req_api_acctprofile, self.scg_mgmt_ip, self.scg_port)

            frwd_url_ttgpdg = ji.get_url(self.req_api_forwardingprofile%"TTGPDG", self.scg_mgmt_ip, self.scg_port)
            frwd_url_L2ogre = ji.get_url(self.req_api_forwardingprofile%"L2oGRE", self.scg_mgmt_ip, self.scg_port)
            frwd_url_L3ogre = ji.get_url(self.req_api_forwardingprofile%"L3oGRE", self.scg_mgmt_ip, self.scg_port)
            frwd_url_mixed = ji.get_url(self.req_api_forwardingprofile%"Advanced", self.scg_mgmt_ip, self.scg_port)
            frwd_url_pmipv6 = ji.get_url(self.req_api_forwardingprofile%"PMIPv6", self.scg_mgmt_ip, self.scg_port)

            radius_uri = ji.get_url(self.req_api_radius_for_wispr, self.scg_mgmt_ip, self.scg_port)
            radius_acct_uri = ji.get_url(self.req_api_radius_acct_for_wispr, self.scg_mgmt_ip, self.scg_port)

            aaa_uri = ji.get_url(self.req_api_aaa_wlan, self.scg_mgmt_ip, self.scg_port)
            aaa_url = aaa_uri%self.get_apzone_uuid(apzone_name=apzone_name, domain_label=domain_label)

            wispr_uri = ji.get_url(self.req_api_wispr_wlan, self.scg_mgmt_ip, self.scg_port)
            wispr_url = wispr_uri%self.get_apzone_uuid(apzone_name=apzone_name, domain_label=domain_label)

            hotspot_uri = ji.get_url(self.req_api_hotspot_wlan, self.scg_mgmt_ip, self.scg_port)
            hotspot_url = hotspot_uri%self.get_apzone_uuid(apzone_name=apzone_name, domain_label=domain_label)
            wlan_url = ji.get_url(self.req_api_configwlan, self.scg_mgmt_ip, self.scg_port)

            wlan_profile.update(self.SJT.get_wlan_template_data())
            wlan_profile["key"] = ""
            wlan_profile.update({"mobilityZoneUUID":self.get_apzone_uuid(apzone_name=apzone_name, domain_label=domain_label), "zoneName":apzone_name})
            wlan_profile["configContent"].update({"Name":wlan_name, "SSID":ssid,"Description":description,
                                                            "TunnelEnabled":int(enable_tunnel),
                                                            "_WLANType":int(authentication_type),
                                                            #"authSCGProxy":int(enable_scg_proxy_for_auth),
                                                            #"acctSCGProxy":int(enable_scg_proxy_for_acct),
                                                            "Authentication":authentication_method,
                                                            "SecurityMethod":encryption_method,
                                                            "WPAVersion":wpa_version,
                                                            "WPAEncryption": encryption_algorithm,
                                                            "NASIdType":nas_id_type,
                                                            "AuthReqTimeout":int(radius_request_timeout),
                                                            "AuthMaxRetry":int(radius_max_retries),
                                                            "AuthRetryPriInvl":int(nas_reconnect_primary),
                                                            "CalledStaIdType":int(called_sta_id),
                                                            "STAIssolation":int(client_isolation),
                                                            "Priority":priority,
                                                            "RatePerStaDnlink":rate_limit_downlink,
                                                            "RatePerStaUplink":rate_limit_uplink,
                                                            "VlanId":int(vlanid),
                                                            "BroadcastSSID":int(hide_ssid),
                                                            "ProxyARP":int(proxy_arp),
                                                            "MaxClients":int(max_clients),
                                                            "80211d":int(support_80211d),
                                                            "IgnoreUnauth":int(client_tx_rx_statistic),
                                                            "InactTimeout":int(inactivity_timeout),
                                                            "STAInfoExtraction":int(enable_client_fingerprint),
                                                            "DisableWLAN":int(disable_wlan),
                                                            "OFDMOnly":int(enable_ofdm_only),
                                                            "MgmtTxRate":mgmt_tx_rate,
                                                            "BSSMinRate":bss_min_rate,
                                                            })
            if core_network_type == "Bridge" or "L2oGRE":
                if enable_dhcp:
                    wlan_profile["configContent"].update({"DhcpOp82":int(enable_dhcp)})

            if nas_id_type and nas_id_type == "USER":
                wlan_profile["configContent"].update({"RadiusNASId":nas_id_user_def})

            if authentication_method != "OPEN":
                wlan_profile["configContent"].update({"DVlanEnabled":int(dynamic_vlan_enable)})

            if encryption_method and encryption_method == "WEP":
                wlan_profile["configContent"].update({"WPAVersion":wpa_version,
                                                      "WEPKeyIndex": wep_key_index,
                                                      "WEPKey":wep_key})
            if enable_ofdm_only and int(enable_ofdm_only) == 1:
                wlan_profile["configContent"].update({"MgmtTxRate":"6mbps"})

            if int(enable_tunnel) == 1:

                wlan_profile["configContent"].update({"coreNetworkType":core_network_type})
                if core_network_type == "TTGPDG":
                    wlan_profile["configContent"].update({"_forwardingServiceProfileId": \
                            self._get_key_for_profile(name=frwd_profile_name, url=frwd_url_ttgpdg)['key']})
                    wlan_profile["configContent"].update({"_WLANType":int(authentication_type),
                                                          "acctSCGProxy":int(enable_scg_proxy_for_acct),
                                                          "Authentication":authentication_method,
                                                          "authSCGProxy":int(enable_scg_proxy_for_auth),
                                                          "acctTTGSession":int(acct_ttg_enable)})
                    authentication_type = 0
                    authentication_method = "802.1X"
                    enable_scg_proxy_for_auth = 1
                    enable_scg_proxy_for_acct = 1
                
                elif core_network_type == "Bridge":
                    if int(authentication_type) != 1 and int(authentication_type) != 4:
                        if enable_scg_proxy_for_acct:
                            wlan_profile["configContent"].update({"acctSCGProxy":int(enable_scg_proxy_for_acct)})
                        if enable_scg_proxy_for_acct and int(enable_scg_proxy_for_acct) == 0:
                            if acct_profile_name == "Disable":
                                wlan_profile["configContent"].update({"_AcctId":""})
                            else:
                                wlan_profile["configContent"].update({"_AcctId": self._get_key_for_profile(name=acct_profile_name, url=aaa_url)['key']})
                                wlan_profile["configContent"].update({"_AcctInterval":int(acct_interim_time)})
                        elif enable_scg_proxy_for_acct and int(enable_scg_proxy_for_acct) == 1:
                            if acct_profile_name == "Disable":
                                wlan_profile["configContent"].update({"acctServiceId":""})
                            else:
                                wlan_profile["configContent"].update({"acctServiceId":self._get_key_for_profile(name=acct_profile_name, 
                                                                                                                url=acct_url)['key']})
                                wlan_profile["configContent"].update({"_AcctInterval":int(acct_interim_time)})

                elif core_network_type == "L2oGRE":
                    if enable_scg_proxy_for_acct:

                        wlan_profile["configContent"].update({"acctSCGProxy":int(enable_scg_proxy_for_acct)})
                    if enable_scg_proxy_for_acct and int(enable_scg_proxy_for_acct) == 0:
                        if acct_profile_name == "Disable":
                            wlan_profile["configContent"].update({"_AcctId":""})
                        else:
                            wlan_profile["configContent"].update({"_AcctId": self._get_key_for_profile(name=acct_profile_name, url=aaa_url)['key']})
                            wlan_profile["configContent"].update({"_AcctInterval":int(acct_interim_time)})
                    elif enable_scg_proxy_for_acct and int(enable_scg_proxy_for_acct) == 1:
                        if acct_profile_name == "Disable":
                            wlan_profile["configContent"].update({"acctServiceId":""})
                        else:
                            wlan_profile["configContent"].update({"acctServiceId":self._get_key_for_profile(name=acct_profile_name, url=acct_url)['key']})
                            wlan_profile["configContent"].update({"_AcctInterval":int(acct_interim_time)})

                    wlan_profile["configContent"].update({"_forwardingServiceProfileId":\
                        self._get_key_for_profile(name=frwd_profile_name, url=frwd_url_L2ogre)['key']})

                elif core_network_type == "L3oGRE":
                    if enable_scg_proxy_for_acct:
                        wlan_profile["configContent"].update({"acctSCGProxy":int(enable_scg_proxy_for_acct)})
                    if enable_scg_proxy_for_acct and int(enable_scg_proxy_for_acct) == 0:
                        if acct_profile_name == "Disable":
                            wlan_profile["configContent"].update({"_AcctId":""})
                        else:
                            wlan_profile["configContent"].update({"_AcctId": self._get_key_for_profile(name=acct_profile_name, url=aaa_url)['key']})
                            wlan_profile["configContent"].update({"_AcctInterval":int(acct_interim_time)})
                    elif enable_scg_proxy_for_acct and int(enable_scg_proxy_for_acct) == 1:
                        if acct_profile_name == "Disable":
                            wlan_profile["configContent"].update({"acctServiceId":""})
                        else:
                            wlan_profile["configContent"].update({"acctServiceId":self._get_key_for_profile(name=acct_profile_name, url=acct_url)['key']})
                            wlan_profile["configContent"].update({"_AcctInterval":int(acct_interim_time)})

                    wlan_profile["configContent"].update({"_forwardingServiceProfileId":self._get_key_for_profile(name=frwd_profile_name,
                                                                                                  url=frwd_url_L3ogre)['key']})
                elif core_network_type == "PMIPv6":
                    wlan_profile["configContent"].update({"acctTTGSession":int(acct_ttg_enable)})
                    if enable_scg_proxy_for_acct:
                        wlan_profile["configContent"].update({"acctSCGProxy":int(enable_scg_proxy_for_acct)})

                    wlan_profile["configContent"].update({"_forwardingServiceProfileId":self._get_key_for_profile(name=frwd_profile_name,
                                                                                        url=frwd_url_pmipv6)['key']})
                    if enable_scg_proxy_for_acct and int(enable_scg_proxy_for_acct) == 0:

                        if acct_profile_name == "Disable":
                            wlan_profile["configContent"].update({"_AcctId":""})
                        else:
                            wlan_profile["configContent"].update({"_AcctId": self._get_key_for_profile(name=acct_profile_name, url=aaa_url)['key']})
                            wlan_profile["configContent"].update({"_AcctInterval":int(acct_interim_time)})
                    elif enable_scg_proxy_for_acct and int(enable_scg_proxy_for_acct) == 1:
                        if acct_profile_name == "Disable":
                            wlan_profile["configContent"].update({"acctServiceId":""})
                        else:
                            wlan_profile["configContent"].update({"acctServiceId":self._get_key_for_profile(name=acct_profile_name, url=acct_url)['key']})
                            wlan_profile["configContent"].update({"_AcctInterval":int(acct_interim_time)})

                elif core_network_type == "Advanced":
                    authentication_type = 0
                    authentication_method = '802.1X'
                    enable_scg_proxy_for_acct = 1
                    enable_scg_proxy_for_auth = 1
                    wlan_profile["configContent"].update({"acctSCGProxy":int(enable_scg_proxy_for_acct)})
                    wlan_profile["configContent"].update({"authSCGProxy":int(enable_scg_proxy_for_auth)})
                    wlan_profile["configContent"].update({"Authentication":authentication_method})
                    wlan_profile["configContent"].update({"_forwardingServiceProfileId":self._get_key_for_profile(name=frwd_profile_name,
                                                                                                  url=frwd_url_mixed)['key']})
                    
            if int(authentication_type) == 0:

                wlan_profile["configContent"].update({"_WLANType":int(authentication_type)})
                if authentication_method == "OPEN" and encryption_method == "NONE":
                    if enable_scg_proxy_for_acct and int(enable_scg_proxy_for_acct) == 0:
                        if acct_profile_name == "Disable":
                            wlan_profile["configContent"].update({"_AcctId":""})
                        else:
                            wlan_profile["configContent"].update({"_AcctId":self._get_key_for_profile(name=acct_profile_name, url=aaa_url)['key']})
                            wlan_profile["configContent"].update({"_AcctInterval":int(acct_interim_time)})
                    elif enable_scg_proxy_for_acct and int(enable_scg_proxy_for_acct) == 1:
                        if acct_profile_name == "Disable":
                            wlan_profile["configContent"].update({"acctServiceId":""})
                        else:
                            wlan_profile["configContent"].update({"acctServiceId":self._get_key_for_profile(name=acct_profile_name, url=acct_url)['key']})
                            wlan_profile["configContent"].update({"_AcctInterval":int(acct_interim_time)})

                if core_network_type != "Bridge":
                    if enable_scg_proxy_for_acct and int(enable_scg_proxy_for_acct) == 0:
                        if acct_profile_name == "Disable":
                            wlan_profile["configContent"].update({"_AcctId":""})
                        else:
                            wlan_profile["configContent"].update({"_AcctId": self._get_key_for_profile(name=acct_profile_name, url=aaa_url)['key']})
                            wlan_profile["configContent"].update({"_AcctInterval":int(acct_interim_time)})
                    elif enable_scg_proxy_for_acct and int(enable_scg_proxy_for_acct) == 1:
                        if acct_profile_name == "Disable":
                            wlan_profile["configContent"].update({"acctServiceId":""})
                        else:
                            wlan_profile["configContent"].update({"acctServiceId":self._get_key_for_profile(name=acct_profile_name, url=acct_url)['key']})
                            wlan_profile["configContent"].update({"_AcctInterval":int(acct_interim_time)})

                    if authentication_method != "OPEN":
                        if enable_scg_proxy_for_auth:
                            wlan_profile["configContent"].update({"authSCGProxy":int(enable_scg_proxy_for_auth)})
                        if enable_scg_proxy_for_auth and int(enable_scg_proxy_for_auth) == 1:
                            wlan_profile["configContent"].update({"authServiceId":self._get_key_for_profile(name=auth_profile_name, url=auth_url)['key']})
                        else:
                            wlan_profile["configContent"].update({"_AAAId":self._get_key_for_profile(name=auth_profile_name, url=aaa_url)['key']})

                if authentication_method != "802.1X" and encryption_method != "NONE":
                    wlan_profile["configContent"].update({"WPAPassphrase":passphrase})
                 
                if authentication_method == "MAC":
                    if enable_mac_auth_password:
                        wlan_profile["configContent"].update({"MacAuthPasswordType":int(enable_mac_auth_password)})
                    wlan_profile["configContent"].update({"MacAuthPassword":mac_auth_password})
                    if set_device_mac_address:
                        wlan_profile["configContent"].update({"MacAuthUsernameType":int(set_device_mac_address)})
                 
            elif authentication_type and int(authentication_type) == 1 :
                wlan_profile["configContent"].update({"_HotspotId":self._get_key_for_profile(name=wispr_hotspot_name, url=wispr_url)['key']})
                enable_scg_proxy_for_auth = 1
                wlan_profile["configContent"].update({"authSCGProxy":int(enable_scg_proxy_for_auth)})
                if enable_scg_proxy_for_acct:
                    wlan_profile["configContent"].update({"acctSCGProxy":int(enable_scg_proxy_for_acct)})
                if auth_profile_name == "Local DB":
                    wlan_profile["configContent"].update({"authServiceId":"11111111-1111-1111-1111-111111111111"})
                elif auth_profile_name == "Always Accept":
                    wlan_profile["configContent"].update({"authServiceId":"22222222-2222-2222-2222-222222222222"})
                else:
                    wlan_profile["configContent"].update({"authServiceId":self._get_key_for_profile(name=auth_profile_name, url=radius_uri)['key']})

                if enable_scg_proxy_for_acct and int(enable_scg_proxy_for_acct) == 0:
                    if acct_profile_name == "Disable":
                        wlan_profile["configContent"].update({"_AcctId":""})
                    elif acct_profile_name:
                        wlan_profile["configContent"].update({"_AcctId":self._get_key_for_profile(name=acct_profile_name, url=radius_acct_uri)['key']})
                        wlan_profile["configContent"].update({"_AcctInterval":int(acct_interim_time)})
                elif enable_scg_proxy_for_acct and int(enable_scg_proxy_for_acct) == 1:
                    if acct_profile_name == "Disable":
                        wlan_profile["configContent"].upesate({"acctServiceId":""})
                    elif core_network_type != "PMIPv6":
                        wlan_profile["configContent"].update({"acctServiceId":self._get_key_for_profile(name=acct_profile_name, 
                            url=radius_acct_uri)['key']})
                        wlan_profile["configContent"].update({"_AcctInterval":int(acct_interim_time)})

                if authentication_method == "MAC":
                    if enable_mac_auth_password:
                        wlan_profile["configContent"].update({"MacAuthPasswordType":int(enable_mac_auth_password)})
                    wlan_profile["configContent"].update({"MacAuthPassword":mac_auth_password})
                    if set_device_mac_address:
                        wlan_profile["configContent"].update({"MacAuthUsernameType":int(set_device_mac_address)})

            elif authentication_type and int(authentication_type) == 3:
                wlan_profile["configContent"].update({"Authentication":"802.1X", 
                                                      "SecurityMethod":"WPA", 
                                                      "WPAEncryption":"AES"})
                if enable_scg_proxy_for_auth:
                    wlan_profile["configContent"].update({"authSCGProxy":int(enable_scg_proxy_for_auth)})
                if enable_scg_proxy_for_acct:
                    wlan_profile["configContent"].update({"acctSCGProxy":int(enable_scg_proxy_for_acct)})
                if enable_scg_proxy_for_acct and int(enable_scg_proxy_for_acct) == 1:
                    if acct_profile_name == "Disable":
                        wlan_profile["configContent"].update({"acctServiceId":""})
                    else:
                        wlan_profile["configContent"].update({"acctServiceId": self._get_key_for_profile(name=acct_profile_name, url=acct_url)['key']})
                        wlan_profile["configContent"].update({"_AcctInterval": int(acct_interim_time)})
                else:
                    if acct_profile_name == "Disable":
                        wlan_profile["configContent"].update({"_AcctId":""})
                    else:
                        wlan_profile["configContent"].update({"_AcctId":self._get_key_for_profile(name=acct_profile_name, url=aaa_url)['key']})
                        wlan_profile["configContent"].update({"_AcctInterval":int(acct_interim_time)})

                if enable_scg_proxy_for_auth and int(enable_scg_proxy_for_auth) == 1:
                    wlan_profile["configContent"].update({"authServiceId":self._get_key_for_profile(name=auth_profile_name, url=auth_url)['key']})
                else:

                    wlan_profile["configContent"].update({"_AAAId":self._get_key_for_profile(name=auth_profile_name, url=aaa_url)['key']})
                wlan_profile["configContent"].update({"_Hotspot20Id":self._get_key_for_profile(name=hotspot2_name, url=hotspot_url)['key']})


            elif authentication_type and int(authentication_type) == 4:

                wlan_profile["configContent"]["clbEnable"] = 1
                if enable_ofdm_only:
                    wlan_profile["configContent"]["OFDMOnly"] = int(enable_ofdm_only)

                wlan_profile.update({"authenticationType":auth_type_name})
                wlan_profile["configContent"].update({"acctSCGProxy":int(enable_scg_proxy_for_acct)})

                if enable_scg_proxy_for_acct and (int(enable_scg_proxy_for_acct) == 0):
                    if acct_profile_name == "Disable":
                        wlan_profile["configContent"].update({"_AcctId":""})
                    elif acct_profile_name:
                        wlan_profile["configContent"].update({"_AcctId":self._get_key_for_profile(name=acct_profile_name, url=aaa_url)['key']})
                        wlan_profile["configContent"].update({"_AcctInterval":int(acct_interim_time)})

                elif enable_scg_proxy_for_acct and (int(enable_scg_proxy_for_acct) == 1):
                    if acct_profile_name == "Disable":
                        wlan_profile["configContent"].update({"acctRADIUSId":""})
                    elif acct_profile_name:
                        wlan_profile["configContent"].update({"acctRADIUSId":self._get_key_for_profile(name=acct_profile_name,
                            url=radius_acct_uri)['key']})
                        wlan_profile["configContent"].update({"acctServiceId":self._get_key_for_profile(name=acct_profile_name,
                            url=radius_acct_uri)['key']})
                        wlan_profile["configContent"].update({"_AcctInterval":int(acct_interim_time)})

                wlan_profile.update({"guestAccessId":self._get_guest_access_id(apzone_name=apzone_name,
                                                                                                domain_label=domain_label,
                                                                                                guest_access_name=guest_access_name)})

                
            if wlan_profile["configContent"]["Authentication"] != "OPEN":
                wlan_profile["configContent"].update({"DVlanEnabled":int(dynamic_vlan_enable)})



            data_json = json.dumps(wlan_profile)
            result = ji.post_json_data(wlan_url, self.jsessionid, data_json)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def validate_wlan(self,
            wlan_name="Auto_WLAN_Profile",
            ssid=None,
            description=None,
            apzone_name="Auto_APZone",
            domain_label="Administration Domain",
            enable_tunnel=None,                         #0 or 1
            core_network_type=None,                     #L30GRE,L20GRE,TTGPDG,Mixed
            authentication_type=None,                   #0:standard, 1:Hotspot(wispr),  3:Hotspot2.0
            authentication_method=None,                 #OPEN ,802.1x, MAC
            enable_mac_auth_password=None,              #1 or 0
            mac_auth_password=None,
            set_device_mac_address=None,                #1 or 0
            encryption_method=None,                     #WPA ,WPA2 ,WPA-MIXED,WEP,NONE
            wpa_version=None,
            wep_key_index=None,                         #1 to 4
            wep_key=None,
            encryption_algorithm=None,                  #TKIP, AUTO, AES
            passphrase=None,
            enable_scg_proxy_for_auth=None,             #0 or 1
            enable_scg_proxy_for_acct=None,             #0 or 1
            acct_ttg_session_enable=None,
            acct_profile_name=None,
            auth_profile_name=None,
            acct_interim_time=None,
            acct_interval=None,                         # 0to 1440
            wispr_hotspot_name=None,
            hotspot2_name=None,
            frwd_profile_name=None,
            nas_id_type=None,                           #BSSID, APMAC, USER
            nas_id_user_def=None,
            radius_request_timeout=None,
            radius_max_retries=None,
            nas_reconnect_primary=None,
            called_sta_id=None,                         #0: BSSID,  1:APMAC
            acct_delay_time_enable=None,
            client_isolation=None,                      # 1:enable,  0:disable
            priority=None,                              #high or low
            rate_limit_uplink=None,                     # disable:0,  or in mbps
            rate_limit_downlink=None,
            vlanid=None,
            dynamic_vlan_enable=None,
            core_qinq_enable=None,
            core_add_fixed_svlan=None,
            hide_ssid=None,                            #0:broadcast, 0:hide ssid
            proxy_arp=None,                            #1 or 0
            max_clients=None,
            support_80211d=None,                       #1 or 0
            enable_dhcp=None,                          #1 or 0
            client_tx_rx_statistic=None,               #1 or 0
            inactivity_timeout=None,                   #1 or 0
            enable_client_fingerprint=None,            #1 or 0
            enable_ofdm_only=None,
            disable_wlan=None,                         #1 or 0
            bss_min_rate=None):
        """ 
        API used to Validate WLAN 

        URI: GET /wsg/api/scg/wlans/byZone/<apzone_uuid>

        :param str wlan_name: Name of WLAN
        :param str ssid: SSID
        :param str description: Description
        :param str zone_name: Name of APZone
        :param str domain_label: Name of Domain
        :param str enable_tunnel: 0 | 1             
        :param str core_network_type: L30GRE | L20GRE | TTGPDG | Mixed
        :param str authentication_type: 0 - Standard | 1 - Wispr | 3 - Hotspot2.0
        :param str authentication_method: OPEN | 802.1X | MAC
        :param str enable_mac_auth_password: 0 | 1
        :param str mac_auth_password: MAC Authentication
        :param str set_device_mac_address: 0 | 1
        :param str encryption_method: WPA | WPA2 | WPA-MIXED | WEP | NONE
        :param str wpa_version: 1 to 4
        :param str wep_key_index: WEP key index
        :param str wep_key: WEP Key
        :param str encryption_algorithm: TKIP | AUTO | AES
        :param str passphrase: Passphrase
        :param str enable_scg_proxy_for_auth: 0 | 1
        :param str enable_scg_proxy_for_acct: 0 | 1
        :param str acct_ttg_session_enable: 0 | 1
        :param str acct_profile_name: Accounting Profile name
        :param str auth_profile_name: Authentication Profile name
        :param str acct_interval: Account Interval, 0 to 1440
        :param str wispr_hotspot_name: WISPr Profile name
        :param str enable_hotspot_radius_proxy: 0 | 1  
        :param str hotspot2_name: Hotspot2.0 name
        :param str frwd_profile_name: Name Forwarding profile
        :param str nas_id_type: BSSID | APMAC | USER
        :param str nas_id_user_def: NAS ID used defined
        :param str radius_request_timeout: Radius request timeout
        :param str radius_max_retries: Radius maximum no of retries
        :param str nas_reconnect_primary: NAS Reconnect primary
        :param str called_sta_id: 0 | 1
        :param str acct_delay_time_enable: 0 | 1
        :param str client_isolation: 1<enable> | 0<disable>
        :param str priority: high | low
        :param str rate_limit_uplink: 0<disable> | unit in mbps
        :param str rate_limit_downlink: 0<disable> | unit in mbps
        :param str vlanid: VLAN id
        :param str dynamic_vlan_enable: 0 | 1
        :param str core_qinq_enable: 0 | 1
        :param str vlanmapping_type: VLAN mapping type
        :param str core_add_fixed_svlan: Core add fixed SVLAN
        :param str hide_ssid: 1<broadcast> | 0<hide ssid>
        :param str proxy_arp: 0 | 1    
        :param str max_clients: Maximum clients 
        :param str support_80211d: 0 | 1
        :param str enable_dhcp: 0 | 1
        :param str client_tx_rx_statistic: 0 | 1
        :param str inactivity_timeout: 60 to 600
        :param str enable_client_fingerprint: 0 | 1
        :param str disable_wlan: 0 | 1
        :param str bss_min_rate: BSS minimum bit rate
        :return: True if Validate WLAN successfull else False
        :rtype: boolean
 
        """

        try:
            wlan_api = self.req_api_deletewlan%self.get_apzone_uuid(apzone_name=apzone_name, domain_label=domain_label)
            wlan_profile_url = ji.get_url(wlan_api, self.scg_mgmt_ip, self.scg_port)
            rcvd_data = self._get_key_for_profile(wlan_name, wlan_profile_url)['data_ret']
            if wlan_name:
                if rcvd_data["name"] != wlan_name:
                    self._print_err_validate('validate_wlan_profile', 'wlan_name', 'name', wlan_name, rcvd_data["name"])
                    return False
            if ssid:
                if rcvd_data["configContent"]["SSID"] != ssid:
                    self._print_err_validate('validate_wlan_profile', 'ssid', 'SSID', ssid, rcvd_data["configContent"]["SSID"])
                    return False
            if description:
                if rcvd_data["configContent"]["Description"] != description:
                    self._print_err_validate('validate_wlan_profile', 'description', 'Description', description, rcvd_data["configContent"]["Description"])
                    return False
            if apzone_name:
                if rcvd_data["zoneName"] != apzone_name:
                    self._print_err_validate('validate_wlan_profile', 'zone_name', 'zoneName', apzone_name, rcvd_data["zoneName"])
                    return False
            if enable_tunnel and int(enable_tunnel) != rcvd_data["configContent"]["TunnelEnabled"]:
                self._print_err_validate('validate_wlan_profile', 'enable_tunnel', 'TunnelEnabled',
                        enable_tunnel, rcvd_data["configContent"]["TunnelEnabled"])
                return False
            if core_network_type and enable_tunnel and int(enable_tunnel) == 1:
                if rcvd_data["configContent"]["coreNetworkType"] != core_network_type:
                    self._print_err_validate('validate_wlan_profile', 'core_network_type', 'coreNetworkType', core_network_type,
                            rcvd_data["configContent"]["coreNetworkType"])
                    return False
            #if core_network_type == "TTGPDG":
                #authentication_type = 0
                #authentication_method = "802.1X"
                #enable_scg_proxy_for_auth = 1
                #enable_scg_proxy_for_acct = 1

            if authentication_type:
                if str(rcvd_data["configContent"]["_WLANType"]) != authentication_type:
                    self._print_err_validate('validate_wlan_profile', 'authentication_type', '_WLANType', str(authentication_type),
                            str(rcvd_data["configContent"]["_WLANType"]))
                    return False

            if authentication_method:
                if str(rcvd_data["configContent"]["Authentication"]) !=  authentication_method:
                    self._print_err_validate('validate_wlan_profile', 'authentication_method', 'Authentication', authentication_method,
                            str(rcvd_data["configContent"]["Authentication"]))
                    return False

            if encryption_method:
                if rcvd_data["configContent"]["SecurityMethod"] != encryption_method:
                    self._print_err_validate('validate_wlan_profile', 'encryption_method', 'SecurityMethod', encryption_method,
                            rcvd_data["configContent"]["SecurityMethod"])
                    return False
            if encryption_algorithm:
                if rcvd_data["configContent"]["WPAEncryption"] != encryption_algorithm:
                    self._print_err_validate('validate_wlan_profile', 'encryption_algorithm', 'WPAEncryption', encryption_algorithm,
                            rcvd_data["configContent"]["WPAEncryption"])
                    return False
            if self._validate_wlan_accounting_service(rcvd_data=rcvd_data["configContent"], zone_name=apzone_name, 
                                                       domain_label=domain_label,
                                                       core_network_type=core_network_type, authentication_type=authentication_type,
                                                       enable_scg_proxy_for_auth=enable_scg_proxy_for_auth, 
                                                       enable_scg_proxy_for_acct=enable_scg_proxy_for_acct, 
                                                       acct_ttg_session_enable=acct_ttg_session_enable,
                                                       acct_profile_name=acct_profile_name, auth_profile_name=auth_profile_name,
                                                       #acct_interval=acct_interval,
                                                       wispr_hotspot_name=wispr_hotspot_name, 
                                                       hotspot2_name=hotspot2_name,
                                                       frwd_profile_name=frwd_profile_name) != True:
                print "validate_wlan_profile(): _validate_wlan_accounting_service() failed"
                return False
            if acct_interim_time:
                if acct_interim_time != rcvd_data["config"]['_AcctInterval']:
                    self._print_err_validate('validate_wlan_profile', 'acct_interim_time', '_AcctInterval',  acct_interim_time,
                            rcvd_data["configContent"]['_AcctInterval'])
                    return False

            if self._validate_wlan_options(rcvd_data=rcvd_data["configContent"], nas_id_type=nas_id_type,
                                                           nas_id_user_def=nas_id_user_def,
                                                           radius_request_timeout=radius_request_timeout,
                                                           radius_max_retries=radius_max_retries,
                                                           nas_reconnect_primary=nas_reconnect_primary,
                                                           called_sta_id=called_sta_id,
                                                           acct_delay_time_enable=acct_delay_time_enable,
                                                           client_isolation=client_isolation,
                                                           priority=priority) != True:
                print "validate_wlan_profile():_validate_wlan_options failed"
                return False
            if self._validate_advanced_options(rcvd_data=rcvd_data["configContent"], 
                                                authentication_method=authentication_method, 
                                                core_network_type=core_network_type,
                                                rate_limit_uplink=rate_limit_uplink,
                                                rate_limit_downlink=rate_limit_downlink,
                                                vlanid=vlanid,
                                                dynamic_vlan_enable=dynamic_vlan_enable,
                                                core_qinq_enable=core_qinq_enable,
                                                core_add_fixed_svlan=core_add_fixed_svlan,
                                                hide_ssid=hide_ssid,
                                                proxy_arp=proxy_arp,
                                                max_clients=max_clients,
                                                support_80211d=support_80211d,
                                                enable_dhcp=enable_dhcp,
                                                client_tx_rx_statistic=client_tx_rx_statistic,
                                                inactivity_timeout=inactivity_timeout,
                                                enable_client_fingerprint=enable_client_fingerprint,
                                                enable_ofdm_only=enable_ofdm_only,
                                                disable_wlan=disable_wlan) != True:
                print "validate_wlan_profile():_validate_advanced_options() failed"
                return False

            if authentication_method and authentication_method == "MAC":
                if enable_mac_auth_password:
                    if enable_mac_auth_password != rcvd_data["configContent"]["MacAuthPasswordType"]:
                        self._print_err_validate('validate_wlan_profile', 'enable_mac_auth_password', 'MacAuthPasswordType',
                                enable_mac_auth_password, rcvd_data["configContent"]["MacAuthPasswordType"])
                        return False

                if mac_auth_password:
                    if mac_auth_password != rcvd_data["configContent"]["MacAuthPassword"]:
                        self._print_err_validate('validate_wlan_profile', 'mac_auth_password', 'MacAuthPassword',
                                mac_auth_password, rcvd_data["configContent"]["MacAuthPassword"])
                        return False
                if set_device_mac_address:
                    if set_device_mac_address != rcvd_data["configContent"]["MacAuthUsernameType"]:
                        self._print_err_validate('validate_wlan_profile', 'set_device_mac_address', 'MacAuthUsernameType',
                                set_device_mac_address, rcvd_data["configContent"]["MacAuthUsernameType"])
                        return False

            if wpa_version:
                if wpa_version != rcvd_data["configContent"]["WPAVersion"]:
                    self._print_err_validate('validate_wlan_profile', 'wpa_version', 'WPAVersion',
                            wpa_version, rcvd_data["configContent"]["WPAVersion"])
                    return False
            if wep_key_index:
                if wep_key_index != rcvd_data["configContent"]["WEPKeyIndex"]:
                    self._print_err_validate('validate_wlan_profile', 'wep_key_index', 'WEPKeyIndex', wep_key_index,
                            rcvd_data["configContent"]["WEPKeyIndex"])
                    return False
            if wep_key:
                if int(wep_key) != rcvd_data["configContent"]["WEPKey"]:
                    self._print_err_validate('validate_wlan_profile', 'wep_key', 'WEPKey', wep_key,
                            rcvd_data["configContent"]["WEPKey"])
                    return False
            if passphrase:
                if passphrase != rcvd_data["configContent"]["WPAPassphrase"]:
                    self._print_err_validate('validate_wlan_profile', 'passphrase', 'WPAPassphrase', passphrase,
                            rcvd_data["configContent"]["WPAPassphrase"])
                    return False

            return True

        except Exception, e:
            print traceback.format_exc()
            return False

    def _validate_wlan_accounting_service(self, rcvd_data=None, zone_name=None, domain_label=None,
                                           core_network_type=None, authentication_type=None,
                                           enable_scg_proxy_for_auth=None, enable_scg_proxy_for_acct=None,
                                           enable_hotspot_radius_proxy=None,
                                           acct_ttg_session_enable=None,
                                           acct_profile_name=None, auth_profile_name=None,
                                           acct_interval=None,
                                           wispr_hotspot_name=None, hotspot2_name=None,
                                           frwd_profile_name=None):
        """
        API used to Validate WLAN Accounting service in WLAN profile

        :param str zone_name: Name of APZone
        :param str rcvd_data: Data passed from validate_wlan()
        :param str domain_label: Name of Domain       
        :param str core_network_type: L30GRE | L20GRE | TTGPDG | Mixed
        :param str authentication_type: 0 - Standard | 1 - Wispr | 3 - Hotspot2.0
        :param str enable_scg_proxy_for_auth: 0 | 1
        :param str enable_scg_proxy_for_acct: 0 | 1
        :param str acct_ttg_session_enable: 0 | 1
        :param str enable_hotspot_radius_proxy: 0 | 1
        :param str acct_profile_name: Accounting Profile name
        :param str auth_profile_name: Authentication Profile name
        :param str acct_interval: Account Interval, 0 to 1440
        :param str wispr_hotspot_name: WISPr Profile name 
        :param str hotspot2_name: Hotspot2.0 name
        :param str frwd_profile_name: Name Forwarding profile
        :return: True if Accounting Service in WLAN is validated else False
        :rtype: boolean

        """

        try:
            auth_url = ji.get_url(self.req_api_authprofile, self.scg_mgmt_ip, self.scg_port)
            acct_url = ji.get_url(self.req_api_acctprofile, self.scg_mgmt_ip, self.scg_port)

            radius_uri = ji.get_url(self.req_api_radius_for_wispr, self.scg_mgmt_ip, self.scg_port)
            radius_acct_uri = ji.get_url(self.req_api_radius_acct_for_wispr, self.scg_mgmt_ip, self.scg_port)

            frwd_url_ttgpdg = ji.get_url(self.req_api_forwardingprofile%"TTGPDG", self.scg_mgmt_ip, self.scg_port)
            frwd_url_L2ogre = ji.get_url(self.req_api_forwardingprofile%"L2oGRE", self.scg_mgmt_ip, self.scg_port)
            frwd_url_L3ogre = ji.get_url(self.req_api_forwardingprofile%"L3oGRE", self.scg_mgmt_ip, self.scg_port)
            frwd_url_mixed = ji.get_url(self.req_api_forwardingprofile%"Mixed", self.scg_mgmt_ip, self.scg_port)

            aaa_uri = ji.get_url(self.req_api_aaa_wlan, self.scg_mgmt_ip, self.scg_port)
            aaa_url = aaa_uri%self.get_apzone_uuid(apzone_name=zone_name, domain_label=domain_label)

            wispr_uri = ji.get_url(self.req_api_wispr_wlan, self.scg_mgmt_ip, self.scg_port)
            wispr_url = wispr_uri%self.get_apzone_uuid(apzone_name=zone_name, domain_label=domain_label)

            hotspot_uri = ji.get_url(self.req_api_hotspot_wlan, self.scg_mgmt_ip, self.scg_port)
            hotspot_url = hotspot_uri%self.get_apzone_uuid(apzone_name=zone_name, domain_label=domain_label)

            if authentication_type and int(authentication_type) != 1 and int(authentication_type) != 4:

                if enable_scg_proxy_for_auth and int(enable_scg_proxy_for_auth) != rcvd_data["authSCGProxy"]:
                    self._print_err_validate('_validate_wlan_accounting_service', 'enable_scg_proxy_for_auth', 'authSCGProxy',
                           enable_scg_proxy_for_auth, rcvd_data["authSCGProxy"])
                    return False

                if enable_scg_proxy_for_acct and int(enable_scg_proxy_for_acct) != rcvd_data["acctSCGProxy"]:
                    self._print_err_validate('_validate_wlan_accounting_service', 'enable_scg_proxy_for_acct', 'acctSCGProxy',
                           enable_scg_proxy_for_acct, rcvd_data["acctSCGProxy"])
                    return False

                if enable_scg_proxy_for_acct and int(enable_scg_proxy_for_acct) == 0:
                    _acct_id = None
                    if acct_profile_name and acct_profile_name == "Disable":
                        _acct_id = None
                    elif acct_profile_name:
                        _acct_id = self._get_key_for_profile(name=acct_profile_name, url=aaa_url)['key']

                    if _acct_id != rcvd_data["_AcctId"]:
                        self._print_err_validate('_validate_wlan_accounting_service', '_acct_id', '_AcctId',
                                _acct_id, rcvd_data["_AcctId"])
                        return False
                elif enable_scg_proxy_for_acct and int(enable_scg_proxy_for_acct) == 1:
                    _acct_id = None
                    if acct_profile_name and acct_profile_name == "Disable":
                        _acct_id = None
                    elif acct_profile_name:
                        _acct_id = self._get_key_for_profile(name=acct_profile_name, url=acct_url)['key']
                    if _acct_id != rcvd_data["acctServiceId"]:
                        self._print_err_validate('_validate_wlan_accounting_service', '_acct_id', 'acctServiceId',
                                _acct_id, rcvd_data["acctServiceId"])
                        return False

                if enable_scg_proxy_for_auth and int(enable_scg_proxy_for_auth) == 1:
                    _auth_id = None
                    if auth_profile_name:
                        _auth_id = self._get_key_for_profile(name=auth_profile_name, url=auth_url)['key']
                    if _auth_id != rcvd_data["authServiceId"]:
                        self._print_err_validate('_validate_wlan_accounting_service', '_auth_id', 'authServiceId', _auth_id,
                                rcvd_data["authServiceId"])
                        return False
                elif auth_profile_name and core_network_type and core_network_type != "Bridge":
                    _auth_id = None
                    _auth_id = self._get_key_for_profile(name=auth_profile_name, url=auth_url)['key']
                    if _auth_id != rcvd_data["authServiceId"]:
                        self._print_err_validate('_validate_wlan_accounting_service', '_auth_id', 'authServiceId',
                                _auth_id, rcvd_data["authServiceId"])
                        return False
                
                #if acct_interval:
                #    if int(acct_interval) != str(rcvd_data["config"]["_AcctInterval"]):
                #        self._print_err_validate('_validate_wlan_accounting_service', 'acct_interval', '_AcctInterval', acct_interval,
                #                str(rcvd_data["configContent"]["_AcctInterval"]))
                #        return False
                

            if authentication_type and int(authentication_type) == 1:
                if enable_scg_proxy_for_auth and int(enable_scg_proxy_for_auth) == 1:
                    _auth_id = None
                    if auth_profile_name and auth_profile_name == "Local DB":
                        _auth_id == "11111111-1111-1111-1111-111111111111"
                    elif auth_profile_name and auth_profile_name == "Always Accept":
                        _auth_id = "22222222-2222-2222-2222-222222222222"
                    elif auth_profile_name:
                        _auth_id = self._get_key_for_profile(name=auth_profile_name, url=radius_uri)['key']

                    if _auth_id != rcvd_data["authServiceId"]:
                        self._print_err_validate('_validate_wlan_accounting_service', '_auth_id', 'authServiceId', _auth_id,
                                rcvd_data["authServiceId"])
                        return False
                _acct_id = None
                if enable_scg_proxy_for_acct and int(enable_scg_proxy_for_acct) == 1:
                    if acct_profile_name and acct_profile_name == "Disable":
                        _acct_id = None
                    elif acct_profile_name:
                        _acct_id = self._get_key_for_profile(name=acct_profile_name, url=radius_acct_uri)['key']
                    if _acct_id != rcvd_data["_AcctId"]:
                        self._print_err_validate('_validate_wlan_accounting_service', '_acct_id', '_AcctId', _acct_id,
                                rcvd_data["_AcctId"])
                        return False

                elif enable_scg_proxy_for_acct and int(enable_scg_proxy_for_acct) == 0:
                    if acct_profile_name and acct_profile_name == "Disable":
                        _acct_id = None
                    elif acct_profile_name:
                        _acct_id = self._get_key_for_profile(name=acct_profile_name, url=aaa_url)['key']
                    if _acct_id != rcvd_data["acctServiceId"]:
                        self._print_err_validate('_validate_wlan_accounting_service', '_acct_id', 'acctServiceId', _acct_id,
                                rcvd_data["acctServiceId"])
                        return False

                if wispr_hotspot_name:
                    _wispr_id = None
                    _wispr_id = self._get_key_for_profile(name=wispr_hotspot_name, url=wispr_url)['key']
                    if _wispr_id != rcvd_data["_HotspotId"]:
                        self._print_err_validate('_validate_wlan_accounting_service', '_wispr_id', '_HotspotId',
                            _wispr_id, rcvd_data["_HotspotId"])
                        return False

            if authentication_type and int(authentication_type) == 3:
                if hotspot2_name:
                    _hotspot2_id = None
                    _hotspot2_id = self._get_key_for_profile(name=hotspot2_name, url=hotspot_url)['key']
                    if _hotspot2_id != rcvd_data["_Hotspot20Id"]:
                        self._print_err_validate('_validate_wlan_accounting_service', '_hotspot2_id', '_Hotspot20Id',
                                _hotspot2_id, rcvd_data["_Hotspot20Id"])
                        return False

            if frwd_profile_name:
                _frwd_profile_id = None
                if core_network_type and core_network_type == "TTGPDG":
                    _frwd_profile_id = self._get_key_for_profile(name=frwd_profile_name, url=frwd_url_ttgpdg)['key']
                    if _frwd_profile_id != rcvd_data["_forwardingServiceProfileId"]:
                        self._print_err_validate('_validate_wlan_accounting_service', '_frwd_profile_id', '_forwardingServiceProfileId',
                            _frwd_profile_id, rcvd_data["_forwardingServiceProfileId"])
                        return False
                elif core_network_type and core_network_type == "L2oGRE":
                    _frwd_profile_id = self._get_key_for_profile(name=frwd_profile_name, url=frwd_url_L2ogre)['key']
                    if _frwd_profile_id != rcvd_data["_forwardingServiceProfileId"]:
                        self._print_err_validate('_validate_wlan_accounting_service', '_frwd_profile_id', '_forwardingServiceProfileId',
                            _frwd_profile_id, rcvd_data["_forwardingServiceProfileId"])
                        return False

                elif core_network_type and core_network_type == "L3oGRE":
                    _frwd_profile_id = self._get_key_for_profile(name=frwd_profile_name, url=frwd_url_L3ogre)['key']
                    if _frwd_profile_id != rcvd_data["_forwardingServiceProfileId"]:
                        self._print_err_validate('_validate_wlan_accounting_service', '_frwd_profile_id', '_forwardingServiceProfileId',
                                _frwd_profile_id, rcvd_data["_forwardingServiceProfileId"])
                        return False
                elif core_network_type and core_network_type == "Mixed":
                    _frwd_profile_id = self._get_key_for_profile(name=frwd_profile_name, url=frwd_url_mixed)['key']
                    if _frwd_profile_id != rcvd_data["_forwardingServiceProfileId"]:
                        self._print_err_validate('_validate_wlan_accounting_service', '_frwd_profile_id', '_forwardingServiceProfileId',
                                _frwd_profile_id, rcvd_data["_forwardingServiceProfileId"])
                        return False

            return True

        except Exception, e:
            print traceback.format_exc()
            return False

    def _validate_wlan_options(self, rcvd_data=None,
            nas_id_type=None,
            nas_id_user_def=None,
            radius_request_timeout=None,
            radius_max_retries=None,
            nas_reconnect_primary=None,
            called_sta_id=None,
            acct_delay_time_enable=None,
            client_isolation=None,
            priority=None):
        """
        API is used to Validate WLAN options in WLAN Profile
       
        :param str rcvd_data: Data passed from validate_wlan()
        :param str nas_id_type: BSSID | APMAC | USER
        :param str nas_id_user_def: NAS ID used defined
        :param str radius_request_timeout: Radius request timeout
        :param str radius_max_retries: Radius maximum no of retries
        :param str nas_reconnect_primary: NAS Reconnect primary
        :param str called_sta_id: 0 | 1
        :param str acct_delay_time_enable: 0 | 1
        :param str client_isolation: 1<enable> | 0<disable>
        :param str priority: high | low
        :return: True if WLAN options in WLAN Profile is validated else False
        :rtype: boolean

        """

        try:
            if nas_id_type:
                if nas_id_type != rcvd_data["NASIdType"]:
                    self._print_err_validate('_validate_options_and_advanced_options', 'nas_id_type', nas_id_type,
                            rcvd_data["NASIdType"])
                    return False
            if nas_id_type == "USER":
                if nas_id_user_def:
                    if nas_id_user_def != rcvd_data["RadiusNASId"]:
                        self._print_err_validate('_validate_options_and_advanced_options', 'nas_id', 'RadiusNASId', nas_id_user_def,
                                rcvd_data["RadiusNASId"])
                        return False
            if radius_request_timeout:
                if radius_request_timeout != str(rcvd_data["AuthReqTimeout"]):
                    self._print_err_validate('_validate_options_and_advanced_options', 'radius_request_timeout',
                            'AuthReqTimeout', radius_request_timeout, rcvd_data["AuthReqTimeout"])
                    return False
            if radius_max_retries:
                if radius_max_retries != str(rcvd_data["AuthMaxRetry"]):
                    self._print_err_validate('_validate_options_and_advanced_options', 'radius_max_retries', 'AuthMaxRetry',
                            radius_max_retries, rcvd_data["AuthMaxRetry"])
                    return False
            if nas_reconnect_primary:
                if nas_reconnect_primary != str(rcvd_data["AuthRetryPriInvl"]):
                    self._print_err_validate('_validate_options_and_advanced_options', 'nas_reconnect_primary', 'AuthRetryPriInvl',
                            nas_reconnect_primary, rcvd_data["AuthRetryPriInvl"])
                    return False
            if called_sta_id:
                if called_sta_id != str(rcvd_data["CalledStaIdType"]):
                    self._print_err_validate('_validate_options_and_advanced_options', 'called_sta_id', 'CalledStaIdType', called_sta_id,
                            rcvd_data["CalledStaIdType"])
                    return False
            if acct_delay_time_enable:
                if acct_delay_time_enable != str(rcvd_data["AcctDelayTime"]):
                    self._print_err_validate('_validate_options_and_advanced_options', 'acct_delay_time_enable', 'AcctDelayTime',
                        acct_delay_time_enable, rcvd_data["AcctDelayTime"])
                    return False
            if client_isolation:
                if str(rcvd_data["STAIssolation"]) != client_isolation:
                    self._print_err_validate('_validate_options_and_advanced_options', 'client_isolation', 'STAIssolation',
                            client_isolation, rcvd_data["STAIssolation"])
                    return False
            if priority:
                if priority != rcvd_data["Priority"]:
                    self._print_err_validate('_validate_options_and_advanced_options', 'priority', 'Priority',
                            priority, rcvd_data["Priority"])
                    return False

            return True

        except Exception, e:
            print traceback.format_exc()
            return False

    def _validate_advanced_options(self, rcvd_data=None, authentication_method=None, core_network_type=None,
                                    rate_limit_uplink=None,
                                    rate_limit_downlink=None,
                                    vlanid=None,
                                    dynamic_vlan_enable=None,
                                    core_qinq_enable=None,
                                    core_add_fixed_svlan=None,
                                    hide_ssid=None,
                                    proxy_arp=None,
                                    max_clients=None,
                                    support_80211d=None,
                                    enable_dhcp=None,
                                    client_tx_rx_statistic=None,
                                    inactivity_timeout=None,
                                    enable_client_fingerprint=None,
                                    enable_ofdm_only=None,
                                    disable_wlan=None):
        """
        API is used to validate Advance Options in WLAN profile

        :param str rcvd_data: Data passed from validate_wlan()
        :param str authentication_method: OPEN | 802.1X | MAC
        :param str core_network_type: L30GRE | L20GRE | TTGPDG | Mixed
        :param str rate_limit_uplink: 0<disable> | unit in mbps
        :param str rate_limit_downlink: 0<disable> | unit in mbps
        :param str vlanid: VLAN id
        :param str dynamic_vlan_enable: 0 | 1
        :param str core_qinq_enable: 0 | 1
        :param str core_add_fixed_svlan: Core add fixed SVLAN
        :param str hide_ssid: 1<broadcast> | 0<hide ssid>
        :param str proxy_arp: 0 | 1    
        :param str max_clients: Maximum clients 
        :param str support_80211d: 0 | 1
        :param str enable_dhcp: 0 | 1
        :param str client_tx_rx_statistic: 0 | 1
        :param str inactivity_timeout: 60 to 600
        :param str enable_client_fingerprint: 0 | 1
        :param str disable_wlan: 0 | 1
        :return: True if validate Advance Options in WLAN profile is successfull else False
        :rtype: boolean
 
        """

        try:
            if rate_limit_uplink:
                if rate_limit_uplink != rcvd_data["RatePerStaUplink"]:
                    self._print_err_validate('_validate_advanced_options', 'rate_limit_uplink', 'RatePerStaUplink', rate_limit_uplink,
                            rcvd_data["RatePerStaUplink"])
                    return False
            if rate_limit_downlink:
                if rate_limit_downlink != rcvd_data["RatePerStaDnlink"]:
                    self._print_err_validate('_validate_advanced_options', 'rate_limit_downlink', 'RatePerStaDnlink',
                            rate_limit_downlink, rcvd_data["RatePerStaDnlink"])
                    return False
            if vlanid:
                if vlanid != str(rcvd_data["VlanId"]):
                    self._print_err_validate('_validate_advanced_options', 'vlanid', 'VlanId', vlanid, rcvd_data["VlanId"])
                    return False
            if dynamic_vlan_enable:
                if authentication_method and authentication_method != "OPEN":
                    if dynamic_vlan_enable != str(rcvd_data["DVlanEnabled"]):
                        self._print_err_validate('_validate_advanced_options', 'dynamic_vlan_enable', 'DVlanEnabled', str(dynamic_vlan_enable),
                            str(rcvd_data["DVlanEnabled"]))
                        return False
            if core_network_type and core_network_type == "TTGPDG":
                if core_qinq_enable:
                    if str(core_qinq_enable) != str(rcvd_data["coreQinQEnabled"]):
                        self._print_err_validate('_validate_advanced_options', 'core_qinq_enable', 'coreQinQEnabled', str(core_qinq_enable),
                                 str(rcvd_data["coreQinQEnabled"]))
                        return False
                    if core_add_fixed_svlan:
                        if core_add_fixed_svlan != rcvd_data["coreAddFixedSVlan"]:
                            self._print_err_validate('_validate_advanced_options', 'core_add_fixed_svlan', 'coreAddFixedSVlan',
                                core_add_fixed_svlan, rcvd_data["coreAddFixedSVlan"])
                            return False
            if hide_ssid:
                if hide_ssid != str(rcvd_data["BroadcastSSID"]):
                    self._print_err_validate('_validate_advanced_options', 'hide_ssid', 'BroadcastSSID',
                            str(hide_ssid), str(rcvd_data["BroadcastSSID"]))
                    return False
            if proxy_arp:
                if proxy_arp != str(rcvd_data["ProxyARP"]):
                    self._print_err_validate('_validate_advanced_options', 'proxy_arp', 'ProxyARP',
                            str(proxy_arp), str(rcvd_data["ProxyARP"]))
                    return False
            if max_clients:
                if max_clients != str(rcvd_data["MaxClients"]):
                    self._print_err_validate('_validate_advanced_options', 'max_clients', 'MaxClients', max_clients,
                            rcvd_data["MaxClients"])
                    return False
            if support_80211d:
                if support_80211d != str(rcvd_data["80211d"]):
                    self._print_err_validate('_validate_advanced_options', 'support_80211d', '80211d', str(support_80211d),
                            str(rcvd_data["80211d"]))
                    return False
            if core_network_type and core_network_type == "Bridge" or "L2oGRE":
                if enable_dhcp:
                    if enable_dhcp != str(rcvd_data["DhcpOp82"]):
                        self._print_err_validate('_validate_advanced_options', 'enable_dhcp', 'DhcpOp82',str(enable_dhcp),
                                str(rcvd_data["DhcpOp82"]))
                        return False
            if client_tx_rx_statistic:
                if client_tx_rx_statistic != str(rcvd_data["IgnoreUnauth"]):
                    self._print_err_validate('_validate_advanced_options', 'client_tx_rx_statistic', 'IgnoreUnauth',
                            client_tx_rx_statistic, rcvd_data["IgnoreUnauth"])
                    return False
            if inactivity_timeout:
                if inactivity_timeout != str(rcvd_data["InactTimeout"]):
                    self._print_err_validate('_validate_advanced_options', 'inactivity_timeout', 'InactTimeout', inactivity_timeout,
                            rcvd_data["InactTimeout"])
                    return False
            if enable_ofdm_only:
                if enable_ofdm_only != str(rcvd_data["OFDMOnly"]):
                    self._print_err_validate('_validate_advanced_options', 'enable_ofdm_only', 'OFDMOnly', enable_ofdm_only, 
                            rcvd_data["OFDMOnly"])
                    return False

            if enable_client_fingerprint:
                if enable_client_fingerprint != str(rcvd_data["STAInfoExtraction"]):
                    self._print_err_validate('_validate_advanced_options', 'enable_client_fingerprint', 'STAInfoExtraction', enable_client_fingerprint,
                        rcvd_data["STAInfoExtraction"])
                    return False

            if disable_wlan:
                if disable_wlan != str(rcvd_data["DisableWLAN"]):
                    self._print_err_validate('_validate_advanced_options', 'disable_wlan', 'DisableWLAN', str(disable_wlan),
                            str(rcvd_data["DisableWLAN"]))
                    return False

            return True

        except Exception, e:
            print traceback.format_exc()
            return False

    def update_wlan(self, current_wlan_name="Auto_WLAN_Profile",
            new_wlan_name=None,
            ssid=None,
            description=None,
            apzone_name='Auto_APZone',
            domain_label='Administration Domain',
            enable_tunnel=None,
            core_network_type=None,
            authentication_type= None,
            authentication_method=None,
            enable_mac_auth_password = None,
            mac_auth_password= None,
            set_device_mac_address=None,
            encryption_method=None,
            wpa_version=None,
            wep_key_index=None,
            wep_key=None,
            encryption_algorithm=None,
            passphrase=None,
            enable_scg_proxy_for_auth=None,
            enable_scg_proxy_for_acct=None,
            acct_profile_name=None,
            auth_profile_name=None,
            acct_interval= None,
            acct_ttg_session='1',
            wispr_hotspot_name=None,
            hotspot2_name=None,
            frwd_profile_name=None,
            nas_id_type=None,
            nas_id=None,
            radius_request_timeout=None,
            radius_max_retries=None,
            nas_reconnect_primary=None,
            called_sta_id=None,
            client_isolation=None,
            priority=None,
            rate_limit_uplink=None,
            rate_limit_downlink=None,
            vlanid=None,
            dynamic_vlan_enable=None,
            core_qinq_enable=None,
            core_add_fixed_svlan=None,
            vlan_mapping_type=None,
            hide_ssid=None,
            proxy_arp=None,
            max_clients=None,
            support_80211d=None,
            enable_dhcp=None,
            ofdm_only=None,
            client_tx_rx_statistic=None,
            inactivity_timeout=None,
            enable_client_fingerprint=None,
            disable_wlan=None,
            bss_min_rate=None,
            scg_version='SCG_3_0',
            usertrfc_name='Factory Default',
            mgmt_tx_rate=None):
        """ 
        API used to update WLAN 

        URI: PUT /wsg/api/scg/wlans/<wlan_key>

        :param str current_wlan_name: Original Name of WLAN
        :param str new_wlan_name: New Name of wlan
        :param str ssid: SSID
        :param str description: Description
        :param str apzone_name: Name of APZone
        :param str domain_label: Name of Domain
        :param str enable_tunnel: 0 | 1             
        :param str core_network_type: L30GRE | L20GRE | TTGPDG | Mixed
        :param str authentication_type: 0 - Standard | 1 - Wispr | 3 - Hotspot2.0
        :param str authentication_method: OPEN | 802.1X | MAC
        :param str enable_mac_auth_password: 0 | 1
        :param str mac_auth_password: MAC Authentication
        :param str set_device_mac_address: 0 | 1
        :param str encryption_method: WPA | WPA2 | WPA-MIXED | WEP | NONE
        :param str wpa_version: 1 to 4
        :param str wep_key_index: WEP key index
        :param str wep_key: WEP Key
        :param str encryption_algorithm: TKIP | AUTO | AES
        :param str passphrase: Passphrase
        :param str enable_scg_proxy_for_auth: 0 | 1
        :param str enable_scg_proxy_for_acct: 0 | 1
        :param str acct_ttg_session_enable: 0 | 1
        :param str acct_profile_name: Accounting Profile name
        :param str auth_profile_name: Authentication Profile name
        :param str acct_interval: Account Interval, 0 to 1440
        :param str wispr_hotspot_name: WISPr Profile name
        :param str enable_hotspot_radius_proxy: 0 | 1  
        :param str hotspot2_name: Hotspot2.0 name
        :param str frwd_profile_name: Name Forwarding profile
        :param str nas_id_type: BSSID | APMAC | USER
        :param str nas_id_user_def: NAS ID used defined
        :param str radius_request_timeout: Radius request timeout
        :param str radius_max_retries: Radius maximum no of retries
        :param str nas_reconnect_primary: NAS Reconnect primary
        :param str called_sta_id: 0 | 1
        :param str acct_delay_time_enable: 0 | 1
        :param str client_isolation: 1<enable> | 0<disable>
        :param str priority: high | low
        :param str rate_limit_uplink: 0<disable> | unit in mbps
        :param str rate_limit_downlink: 0<disable> | unit in mbps
        :param str vlanid: VLAN id
        :param str dynamic_vlan_enable: 0 | 1
        :param str core_qinq_enable: 0 | 1
        :param str vlanmapping_type: VLAN mapping type
        :param str core_add_fixed_svlan: Core add fixed SVLAN
        :param str hide_ssid: 1<broadcast> | 0<hide ssid>
        :param str proxy_arp: 0 | 1    
        :param str max_clients: Maximum clients 
        :param str support_80211d: 0 | 1
        :param str enable_dhcp: 0 | 1
        :param str client_tx_rx_statistic: 0 | 1
        :param str inactivity_timeout: 60 to 600
        :param str enable_client_fingerprint: 0 | 1
        :param str disable_wlan: 0 | 1
        :param str bss_min_rate: BSS minimum bit rate
        :return: True if Validate WLAN successfull else False
        :rtype: boolean
 
        """


        result = False
        fwd_wlan_data = {}
        try:
            auth_url = ji.get_url(self.req_api_authprofile, self.scg_mgmt_ip, self.scg_port)
            acct_url = ji.get_url(self.req_api_acctprofile, self.scg_mgmt_ip, self.scg_port)

            frwd_url_ttg = ji.get_url(self.req_api_forwardingprofile%"TTGPDG", self.scg_mgmt_ip, self.scg_port)
            frwd_url_L2ogre = ji.get_url(self.req_api_forwardingprofile%"L2oGRE", self.scg_mgmt_ip, self.scg_port)
            frwd_url_L3ogre = ji.get_url(self.req_api_forwardingprofile%"L3oGRE", self.scg_mgmt_ip, self.scg_port)
            frwd_url_mixed = ji.get_url(self.req_api_forwardingprofile%"Advanced", self.scg_mgmt_ip, self.scg_port)
            frwd_url_pmipv6 = ji.get_url(self.req_api_forwardingprofile%"PMIPv6", self.scg_mgmt_ip, self.scg_port)

            aaa_uri = ji.get_url(self.req_api_aaa_wlan, self.scg_mgmt_ip, self.scg_port)
            aaa_url = aaa_uri%self.get_apzone_uuid(apzone_name=apzone_name, domain_label=domain_label)

            wispr_uri = ji.get_url(self.req_api_wispr_wlan, self.scg_mgmt_ip, self.scg_port)
            wispr_url = wispr_uri%self.get_apzone_uuid(apzone_name=apzone_name, domain_label=domain_label)

            radius_uri = ji.get_url(self.req_api_radius_for_wispr, self.scg_mgmt_ip, self.scg_port)
            radius_acct_uri = ji.get_url(self.req_api_radius_acct_for_wispr, self.scg_mgmt_ip, self.scg_port)

            hotspot_uri = ji.get_url(self.req_api_hotspot_wlan, self.scg_mgmt_ip, self.scg_port)
            hotspot_url = hotspot_uri%self.get_apzone_uuid(apzone_name=apzone_name, domain_label=domain_label)

            wlan_api = self.req_api_deletewlan%self.get_apzone_uuid(apzone_name=apzone_name, domain_label=domain_label)
            wlan_profile_url = ji.get_url(wlan_api, self.scg_mgmt_ip, self.scg_port)
            wlan_profile = self._get_key_for_profile(current_wlan_name, wlan_profile_url)['data_ret']

            fwd_wlan_data = {}
            fwd_wlan_data.update(self.SJT.get_wlan_template_data_update())

            fwd_wlan_data["mobilityZoneUUID"] = wlan_profile["mobilityZoneUUID"] 
            fwd_wlan_data["key"] = wlan_profile["key"]

            fwd_wlan_data["zoneName"] = wlan_profile["zoneName"] if apzone_name is None else apzone_name

            fwd_wlan_data["configContent"]["Name"] = wlan_profile["configContent"]["Name"] if new_wlan_name is None else new_wlan_name
            fwd_wlan_data["configContent"]["SSID"] = wlan_profile["configContent"]["SSID"] if ssid is None else ssid

            fwd_wlan_data["configContent"]["Description"] = \
                wlan_profile["configContent"]["Description"] if description is None else description

            fwd_wlan_data["configContent"]["TunnelEnabled"] = \
                    wlan_profile["configContent"]["TunnelEnabled"] if enable_tunnel is None else int(enable_tunnel)

            fwd_wlan_data["configContent"]["_enableWlan"] = wlan_profile["configContent"]["_enableWlan"]
            fwd_wlan_data["configContent"]["Availability"] = wlan_profile["configContent"]["Availability"]

            fwd_wlan_data["configContent"]["NASIdType"] = \
                wlan_profile["configContent"]["NASIdType"] if nas_id_type is None else nas_id_type

            if fwd_wlan_data["configContent"]["NASIdType"] == "USER":
                fwd_wlan_data["configContent"].update({"RadiusNASId":wlan_profile["configContent"]["RadiusNASId"] if not nas_id else nas_id})

            fwd_wlan_data["configContent"]["Authentication"] = \
                wlan_profile["configContent"]["Authentication"] if authentication_method is None else authentication_method

            fwd_wlan_data["configContent"]["AuthReqTimeout"] = \
                wlan_profile["configContent"]["AuthReqTimeout"] if radius_request_timeout is None else int(radius_request_timeout)

            fwd_wlan_data["configContent"]["AuthMaxRetry"] = \
                wlan_profile["configContent"]["AuthMaxRetry"] if radius_max_retries is None else int(radius_max_retries)

            fwd_wlan_data["configContent"]["AuthRetryPriInvl"] = \
                wlan_profile["configContent"]["AuthRetryPriInvl"] if nas_reconnect_primary is None else int(nas_reconnect_primary)

            fwd_wlan_data["configContent"]["Authentication"] = \
                wlan_profile["configContent"]["Authentication"] if authentication_method is None else authentication_method

            fwd_wlan_data["configContent"]["SecurityMethod"] = \
                wlan_profile["configContent"]["SecurityMethod"] if encryption_method is None else encryption_method

            fwd_wlan_data["configContent"]["WPAVersion"] = \
                wlan_profile["configContent"]["WPAVersion"] if wpa_version is None else wpa_version

            fwd_wlan_data["configContent"]["WPAEncryption"] = \
                wlan_profile["configContent"]["WPAEncryption"] if encryption_algorithm is None else encryption_algorithm
            fwd_wlan_data["configContent"]["DisableWLAN"] = \
                wlan_profile["configContent"]["DisableWLAN"] if disable_wlan is None else int(disable_wlan)

            fwd_wlan_data["configContent"]["STAInfoExtraction"] = \
                wlan_profile["configContent"]["STAInfoExtraction"] if enable_client_fingerprint is None else int(enable_client_fingerprint)

            fwd_wlan_data["configContent"]["InactTimeout"] = \
                wlan_profile["configContent"]["InactTimeout"] if inactivity_timeout is None else int(inactivity_timeout)

            fwd_wlan_data["configContent"]["IgnoreUnauth"] = \
                wlan_profile["configContent"]["IgnoreUnauth"] if client_tx_rx_statistic is None else int(client_tx_rx_statistic)

            if fwd_wlan_data["configContent"]["TunnelEnabled"] == 1:
                fwd_wlan_data["configContent"]["coreNetworkType"] = \
                    wlan_profile["configContent"]["coreNetworkType"] if core_network_type is None else core_network_type

            if fwd_wlan_data["configContent"]["coreNetworkType"] == "Bridge" or "L2oGRE":
                fwd_wlan_data["configContent"]["DhcpOp82"] = \
                    wlan_profile["configContent"]["DhcpOp82"] if enable_dhcp is None else int(enable_dhcp)

            fwd_wlan_data["configContent"]["80211d"] = \
                wlan_profile["configContent"]["80211d"] if support_80211d is None else int(support_80211d)

            fwd_wlan_data["configContent"]["MaxClients"] = \
                wlan_profile["configContent"]["MaxClients"] if max_clients is None else int(max_clients)

            fwd_wlan_data["configContent"]["ProxyARP"] = \
                wlan_profile["configContent"]["ProxyARP"] if proxy_arp is None else int(proxy_arp)

            fwd_wlan_data["configContent"]["BroadcastSSID"] = \
                wlan_profile["configContent"]["BroadcastSSID"] if hide_ssid is None else int(hide_ssid)

            fwd_wlan_data["configContent"]["VlanId"] = \
                wlan_profile["configContent"]["VlanId"] if vlanid is None else int(vlanid)

            fwd_wlan_data["configContent"]["RatePerStaUplink"] = \
                wlan_profile["configContent"]["RatePerStaUplink"] if rate_limit_uplink is None else rate_limit_uplink

            fwd_wlan_data["configContent"]["RatePerStaDnlink"] = \
                wlan_profile["configContent"]["RatePerStaDnlink"] if rate_limit_downlink is None else rate_limit_downlink

            fwd_wlan_data["configContent"]["Priority"] = \
                wlan_profile["configContent"]["Priority"] if priority is None else priority
            fwd_wlan_data["configContent"]["STAIssolation"] = \
                wlan_profile["configContent"]["STAIssolation"] if client_isolation is None else int(client_isolation)

            fwd_wlan_data["configContent"]["CalledStaIdType"] = \
                wlan_profile["configContent"]["CalledStaIdType"] if called_sta_id is None else int(called_sta_id)
            fwd_wlan_data["configContent"]["OFDMOnly"] = wlan_profile["configContent"]["OFDMOnly"] if not ofdm_only else int(ofdm_only)

            fwd_wlan_data["configContent"]["_WLANType"] = wlan_profile["configContent"]["_WLANType"] \
                if authentication_type is None else int(authentication_type)

            fwd_wlan_data["configContent"].update({"acctSCGProxy":wlan_profile["configContent"]["acctSCGProxy"] if not enable_scg_proxy_for_acct
                                                    else int(enable_scg_proxy_for_acct),
                                                   "authSCGProxy":wlan_profile["configContent"]["authSCGProxy"] if not enable_scg_proxy_for_auth
                                                    else int(enable_scg_proxy_for_auth)})

            fwd_wlan_data["configContent"]["BSSMinRate"] = wlan_profile["configContent"]["BSSMinRate"] if not bss_min_rate else bss_min_rate

            fwd_wlan_data["configContent"]["MgmtTxRate"] = wlan_profile["configContent"]["MgmtTxRate"] if not mgmt_tx_rate else mgmt_tx_rate

            #if fwd_wlan_data["configContent"]["OFDMOnly"] == 1:
            #    fwd_wlan_data["configContent"]["MgmtTxRate"] = "6mbps"

            if fwd_wlan_data["configContent"]["SecurityMethod"] == "WEP":
                fwd_wlan_data["configContent"]["WPAVersion"]=\
                    wlan_profile["configContent"]["WPAVersion"] if wpa_version is None else wpa_version
                fwd_wlan_data["configContent"]["WEPKeyIndex"]=\
                    wlan_profile["configContent"]["WEPKeyIndex"] if wep_key_index is None else int(wep_key_index)
                fwd_wlan_data["configContent"]["WEPKey"]=\
                    wlan_profile["configContent"]["WEPKey"] if wep_key is None else wep_key

            if fwd_wlan_data["configContent"]["TunnelEnabled"] == 1:
                fwd_wlan_data["configContent"]["coreNetworkType"] = \
                    wlan_profile["configContent"]["coreNetworkType"] if core_network_type is None else core_network_type

                if fwd_wlan_data["configContent"]["coreNetworkType"] == "TTGPDG":
                    fwd_wlan_data["configContent"]["_forwardingServiceProfileId"] = \
                        wlan_profile["configContent"]["_forwardingServiceProfileId"]\
                        if frwd_profile_name is None \
                        else self._get_key_for_profile(frwd_profile_name, frwd_url_ttg)['key']

                    fwd_wlan_data["configContent"].update({"_WLANType":0,
                                                           "acctSCGProxy":1,
                                                           "Authentication":"802.1X",
                                                           "authSCGProxy":1, 
                                                           "acctTTGSession":int(acct_ttg_session)})

                    if acct_profile_name == "Disable":
                        fwd_wlan_data["configContent"]["acctServiceId"] = ""
                    else:
                        fwd_wlan_data["configContent"]["acctServiceId"] = wlan_profile["configContent"]["acctServiceId"] \
                            if acct_profile_name is None else \
                            self._get_key_for_profile(acct_profile_name, acct_url)['key']

                        fwd_wlan_data["configContent"]["_AcctInterval"] = wlan_profile["configContent"]["_AcctInterval"] \
                            if not acct_interval else int(acct_interval)

                    fwd_wlan_data["configContent"]["authServiceId"] = wlan_profile["configContent"]["authServiceId"]\
                        if not auth_profile_name else \
                        self._get_key_for_profile(auth_profile_name, auth_url)['key']

                    fwd_wlan_data["configContent"]["_WLANType"] = 0
                    fwd_wlan_data["configContent"]["Authentication"] = "802.1X"
                    fwd_wlan_data["configContent"].update({"acctSCGProxy":1, "authSCGProxy":1})
                    enable_scg_proxy_for_auth = 1
                    enable_scg_proxy_for_acct = 1
                    fwd_wlan_data["configContent"].update({"coreQinQEnabled": wlan_profile["configContent"]["coreQinQEnabled"] if not
                                                                core_qinq_enable else int(core_qinq_enable)})
                    if fwd_wlan_data["configContent"]["coreQinQEnabled"] == 1:
                        fwd_wlan_data["configContent"].update({"vlanMappingType":vlan_mapping_type,
                                                              "coreAddFixedSVlan":core_add_fixed_svlan})

                    
                elif fwd_wlan_data["configContent"]["coreNetworkType"] == "Bridge":

                    if fwd_wlan_data["configContent"]["_WLANType"] == 0 or fwd_wlan_data["configContent"]["_WLANType"] == 2: 
                        if acct_profile_name == "Disable":
                            fwd_wlan_data["configContent"]["acctServiceId"] = ""
                        else:
                            if fwd_wlan_data["configContent"]["acctSCGProxy"] == 1: 
                                fwd_wlan_data["configContent"]["acctServiceId"] = wlan_profile["configContent"]["acctServiceId"] \
                                    if acct_profile_name is None else self._get_key_for_profile(acct_profile_name, acct_url)['key']

                                fwd_wlan_data["configContent"]["_AcctInterval"] = wlan_profile["configContent"]["_AcctInterval"] \
                                        if not acct_interval else int(acct_interval)
                            else:
                                fwd_wlan_data["configContent"]["_AcctId"] = wlan_profile["configContent"]["_AcctId"] if acct_profile_name \
                                        is None else self._get_key_for_profile(acct_profile_name, aaa_url)['key']
                                fwd_wlan_data["configContent"]["_AcctInterval"] = wlan_profile["configContent"]["_AcctInterval"] \
                                        if not acct_interval else int(acct_interval)

                    fwd_wlan_data["configContent"]["coreQinQEnabled"] = None
                    fwd_wlan_data["configContent"].update({"coreQinQEnabled":wlan_profile["configContent"]["coreQinQEnabled"] if not
                                                                             core_qinq_enable else int(core_qinq_enable)})

                    if fwd_wlan_data["configContent"]["coreQinQEnabled"] == 1:
                        fwd_wlan_data["configContent"].update({"vlanMappingType":wlan_profile["configContent"]['vlanMappingType'] if not
                                                                             vlan_mapping_type else vlan_mapping_type,
                                                               "coreAddFixedSVlan":wlan_profile["configContent"]["coreAddFixedSVlan"] if not
                                                                             core_add_fixed_svlan else core_add_fixed_svlan})


                elif fwd_wlan_data["configContent"]["coreNetworkType"] == "L2oGRE":
                    fwd_wlan_data["configContent"]["_forwardingServiceProfileId"] = wlan_profile["configContent"]["_forwardingServiceProfileId"]\
                        if frwd_profile_name is None else\
                        self._get_key_for_profile(frwd_profile_name, frwd_url_L2ogre)['key']
                    wlan_profile["configContent"].update({"acctSCGProxy":int(enable_scg_proxy_for_acct)})

                elif fwd_wlan_data["configContent"]["coreNetworkType"]=="L3oGRE":
                    fwd_wlan_data["configContent"]["_forwardingServiceProfileId"] = wlan_profile["configContent"]["_forwardingServiceProfileId"]\
                        if frwd_profile_name is None else\
                        self._get_key_for_profile(frwd_profile_name, frwd_url_L3ogre)['key']

                elif core_network_type == "PMIPv6":
                    fwd_wlan_data["configContent"]["acctSCGProxy"] = wlan_profile["configContent"]["acctSCGProxy"] if not \
                        enable_scg_proxy_for_acct else int(enable_scg_proxy_for_acct)

                    fwd_wlan_data["configContent"]["_forwardingServiceProfileId"] = wlan_profile["configContent"]["_forwardingServiceProfileId"] \
                            if not frwd_profile_name else self._get_key_for_profile(name=frwd_profile_name, url=frwd_url_pmipv6)['key']
                    if fwd_wlan_data["configContent"]["acctSCGProxy"] == 0:
                        if acct_profile_name and acct_profile_name == "Disable":
                            fwd_wlan_data["configContent"]["_AcctId"] = ""
                        else:
                            fwd_wlan_data["configContent"]["_AcctId"] = wlan_profile["configContent"]["_AcctId"] if not acct_profile_name else \
                                    self._get_key_for_profile(name=acct_profile_name, url=aaa_url)['key']
                            fwd_wlan_data["configContent"]["_AcctInterval"] = wlan_profile["configContent"]["_AcctInterval"] if not acct_interval \
                                    else int(acct_interval)
                    elif fwd_wlan_data["configContent"]["acctSCGProxy"] == 1:
                        if acct_profile_name == "Disable":
                            fwd_wlan_data["configContent"]["acctServiceId"] = ""
                        else:
                            fwd_wlan_data["configContent"]["acctServiceId"] = wlan_profile["configContent"]["acctServiceId"] \
                                    if not acct_profile_name else self._get_key_for_profile(name=acct_profile_name, url=acct_url)['key']
                            fwd_wlan_data["configContent"]["_AcctInterval"] = wlan_profile["configContent"]["_AcctInterval"] if not acct_interval \
                                    else int(acct_interval)

                elif fwd_wlan_data["configContent"]["coreNetworkType"] == "Advanced":
                    fwd_wlan_data["configContent"]["_forwardingServiceProfileId"] = wlan_profile["configContent"]["_forwardingServiceProfileId"]\
                        if frwd_profile_name is None else\
                        self._get_key_for_profile(frwd_profile_name, frwd_url_mixed)['key']

            if fwd_wlan_data["configContent"]["Authentication"] == "MAC":
                fwd_wlan_data["configContent"]["WPAPassphrase"] = wlan_profile["configContent"]["WPAPassphrase"] if passphrase is None else passphrase

                fwd_wlan_data["configContent"]["MacAuthPasswordType"] = wlan_profile["configContent"]["MacAuthPasswordType"] \
                    if enable_mac_auth_password is None else int(enable_mac_auth_password)

                fwd_wlan_data["configContent"]["MacAuthPassword"] = wlan_profile["configContent"]["MacAuthPassword"] \
                    if mac_auth_password is None else mac_auth_password

                fwd_wlan_data["configContent"]["MacAuthUsernameType"] = wlan_profile["configContent"]["MacAuthUsernameType"] \
                    if set_device_mac_address is None else int(set_device_mac_address)

            if fwd_wlan_data["configContent"]["_WLANType"] == 0:
                if fwd_wlan_data["configContent"]["Authentication"] == "OPEN" and fwd_wlan_data["configContent"]["SecurityMethod"] == "NONE":
                    if fwd_wlan_data["configContent"]["acctSCGProxy"] == 0: 
                        if acct_profile_name == "Disable":
                            fwd_wlan_data["configContent"]["_AcctId"] = ""
                        else:
                            fwd_wlan_data["configContent"]["_AcctId"] = wlan_profile["configContent"]["_AcctId"] if not acct_profile_name \
                                else self._get_key_for_profile(acct_profile_name, aaa_url)['key']
                            fwd_wlan_data["configContent"]["_AcctInterval"] = wlan_profile["configContent"]["_AcctInterval"] if not acct_interval \
                                else int(acct_interval)
                    else:
                        if acct_profile_name == "Disable":
                            fwd_wlan_data["configContent"]["acctServiceId"] = ""
                        else:
                            fwd_wlan_data["configContent"]["acctServiceId"] = wlan_profile["configContent"]["acctServiceId"] if not acct_profile_name \
                                    else self._get_key_for_profile(acct_profile_name, acct_url)['key']
                            fwd_wlan_data["configContent"]["_AcctInterval"] = wlan_profile["configContent"]["_AcctInterval"] if not acct_interval \
                                    else int(acct_interval)

                #fwd_wlan_data["configContent"]["acctSCGProxy"] = wlan_profile["configContent"]["acctSCGProxy"] \
                #    if enable_scg_proxy_for_acct is None else int(enable_scg_proxy_for_acct)

                if fwd_wlan_data["configContent"]["acctSCGProxy"] == 0:

                    if acct_profile_name == "Disable":
                        fwd_wlan_data["configContent"]["_AcctId"] = ""
                    else:
                        fwd_wlan_data["configContent"]["_AcctId"] = wlan_profile["configContent"]["_AcctId"] \
                            if acct_profile_name is None \
                            else self._get_key_for_profile(acct_profile_name, aaa_url)['key']
                        fwd_wlan_data["configContent"]["_AcctInterval"] = wlan_profile["configContent"]["_AcctInterval"] \
                                if not acct_interval else int(acct_interval)
                else:
                    if acct_profile_name == "Disable":
                        fwd_wlan_data["configContent"]["acctServiceId"] = ""
                    else:
                        fwd_wlan_data["configContent"]["acctServiceId"] = wlan_profile["configContent"]["acctServiceId"] \
                            if acct_profile_name is None else \
                        self._get_key_for_profile(acct_profile_name, acct_url)['key']

                        fwd_wlan_data["configContent"]["_AcctInterval"] = wlan_profile["configContent"]["_AcctInterval"] \
                                if not acct_interval else int(acct_interval)

                if fwd_wlan_data["configContent"]["Authentication"] != "OPEN":
                    fwd_wlan_data["configContent"]["authSCGProxy"] = wlan_profile["configContent"]["authSCGProxy"] \
                        if enable_scg_proxy_for_auth is None else int(enable_scg_proxy_for_auth)
                    if fwd_wlan_data["configContent"]["authSCGProxy"] == 1:
                        fwd_wlan_data["configContent"]["authServiceId"] = wlan_profile["configContent"]["authServiceId"] \
                            if auth_profile_name is None \
                            else self._get_key_for_profile(auth_profile_name, auth_url)['key']

                    else:
                        fwd_wlan_data["configContent"]["_AAAId"] = wlan_profile["configContent"]["_AAAId"] \
                            if auth_profile_name  is None else \
                            self._get_key_for_profile(auth_profile_name, aaa_url)['key']
                else:
                    fwd_wlan_data["configContent"]["WPAPassphrase"] = wlan_profile["configContent"]["WPAPassphrase"] \
                        if passphrase is None else passphrase

            elif fwd_wlan_data["configContent"]["_WLANType"] == 1:
                fwd_wlan_data["configContent"]["_HotspotId"] = wlan_profile["configContent"]["_HotspotId"] \
                    if wispr_hotspot_name is None else \
                    self._get_key_for_profile(wispr_hotspot_name, wispr_url)['key']


                fwd_wlan_data["configContent"]["authSCGProxy"] = 1
                if auth_profile_name == "Local DB":
                    fwd_wlan_data["configContent"]["authServiceId"] = "11111111-1111-1111-1111-111111111111"
                elif auth_profile_name == "Always Accept":
                    fwd_wlan_data["configContent"]["authServiceId"] = "22222222-2222-2222-2222-222222222222"

                else:
                    fwd_wlan_data["configContent"]["authServiceId"] = wlan_profile["configContent"]["authServiceId"] if not auth_profile_name else \
                    self._get_key_for_profile(auth_profile_name, radius_uri)['key']

                if fwd_wlan_data["configContent"]["acctSCGProxy"] == 0: 
                    if acct_profile_name == "Disable":
                        fwd_wlan_data["configContent"]["_AcctId"] = ""
                    else:
                        fwd_wlan_data["configContent"]["_AcctId"] = wlan_profile["configContent"]["_AcctId"] if not acct_profile_name \
                            else self._get_key_for_profile(acct_profile_name, radius_acct_uri)['key']
                        fwd_wlan_data["configContent"]["_AcctInterval"] = wlan_profile["configContent"]["_AcctInterval"] if not acct_interval \
                            else int(acct_interval)
                else:
                    if acct_profile_name == "Disable":
                        fwd_wlan_data["configContent"]["acctServiceId"] = ""
                    else:
                        fwd_wlan_data["configContent"]["acctServiceId"] = wlan_profile["configContent"]["acctServiceId"] if not acct_profile_name \
                            else self._get_key_for_profile(acct_profile_name, radius_acct_uri)['key']
                        fwd_wlan_data["configContent"]["_AcctInterval"] = wlan_profile["configContent"]["_AcctInterval"] if not acct_interval \
                            else int(acct_interval)

            elif fwd_wlan_data["configContent"]["_WLANType"] == 3:

                fwd_wlan_data["configContent"]["Authentication"] = "802.1X"
                fwd_wlan_data["configContent"]["SecurityMethod"] = "WPA"
                fwd_wlan_data["configContent"]["WPAEncryption"] = "AES"
                fwd_wlan_data["configContent"]["authSCGProxy"] = wlan_profile["configContent"]["authSCGProxy"] \
                    if enable_scg_proxy_for_auth is None else int(enable_scg_proxy_for_auth)
                fwd_wlan_data["configContent"]["acctSCGProxy"] = wlan_profile["configContent"]["acctSCGProxy"] \
                    if enable_scg_proxy_for_acct is None else int(enable_scg_proxy_for_acct)
                if fwd_wlan_data["configContent"]["acctSCGProxy"] == 0: 
                    if acct_profile_name == "Disable":
                        fwd_wlan_data["configContent"]["_AcctId"] = ""
                    else:
                        fwd_wlan_data["configContent"]["_AcctId"] = wlan_profile["configContent"]["_AcctId"] \
                            if acct_profile_name is None else \
                            self._get_key_for_profile(acct_profile_name, aaa_url)['key']
                        fwd_wlan_data["configContent"]["_AcctInterval"] = wlan_profile["configContent"]["_AcctInterval"] \
                                if not acct_interval else acct_interval
                else:
                    if acct_profile_name == "Disable":
                        fwd_wlan_data["configContent"]["acctServiceId"] = ""
                    else:
                    
                        fwd_wlan_data["configContent"]["acctServiceId"] = wlan_profile["configContent"]["acctServiceId"] \
                            if acct_profile_name is None else \
                            self._get_key_for_profile(acct_profile_name, acct_url)['key']
                        fwd_wlan_data["configContent"]["_AcctInterval"] = wlan_profile["configContent"]["_AcctInterval"] \
                                if not acct_interval else int(acct_interval)

                if fwd_wlan_data["configContent"]["authSCGProxy"] == 1: 
                    fwd_wlan_data["configContent"]["authServiceId"] = wlan_profile["configContent"]["authServiceId"] \
                        if auth_profile_name is None else \
                        self._get_key_for_profile(auth_profile_name, auth_url)['key']
                else:
                    fwd_wlan_data["configContent"]["_AAAId"] = wlan_profile["configContent"]["_AAAId"] \
                        if auth_profile_name is None else \
                        self._get_key_for_profile(auth_profile_name, aaa_url)['key']

                fwd_wlan_data["configContent"]["_Hotspot20Id"] = wlan_profile["configContent"]["_Hotspot20Id"] \
                    if hotspot2_name is None else \
                    self._get_key_for_profile(hotspot2_name, hotspot_url)['key']

            elif fwd_wlan_data["configContent"]["_WLANType"] == 4:

                fwd_wlan_data["configContent"]["clbEnable"] = 1
                fwd_wlan_data["configContent"]["OFDMOnly"] = wlan_profile["configContent"]["OFDMOnly"] if not ofdm_only else ofdm_only 


                fwd_wlan_data["configContent"]["_HotspotId"] = wlan_profile["configContent"]["_HotspotId"] \
                        if wispr_hotspot_name is None else self._get_key_for_profile(wispr_hotspot_name, wispr_url)['key']

                fwd_wlan_data["configContent"]["authSCGProxy"] = 1

                if not auth_profile_name:
                    fwd_wlan_data["configContent"]["authServiceId"] = wlan_profile["configContent"]["authServiceId"]
                elif auth_profile_name == "Local DB":
                    fwd_wlan_data["configContent"]["authServiceId"] = "11111111-1111-1111-1111-111111111111"
                elif auth_profile_name == "Always Accept":
                    fwd_wlan_data["configContent"]["authServiceId"] = "22222222-2222-2222-2222-222222222222"
                else:
                    print " %s is Not a valid Authentication Service name" % (auth_profile_name)
                    return False

            if fwd_wlan_data["configContent"]["Authentication"] != "OPEN":
                fwd_wlan_data["configContent"].update({"DVlanEnabled":wlan_profile["configContent"]["DVlanEnabled"] if
                    not dynamic_vlan_enable else int(dynamic_vlan_enable)})

            json_data = json.dumps(fwd_wlan_data)
            api = self.req_api_configwlan_delete%self._get_key_for_profile(current_wlan_name, wlan_profile_url)['key']
            url1 = ji.get_url(api, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(url1, self.jsessionid, json_data)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def delete_wlan(self, wlan_name="Auto_WLAN_Profile", zone_name="Auto_APZone", domain_label='Administration Domain'):
        """ 
        API used to delete WLAN 

        URI: DELETE /wsg/api/scg/wlans/<wlan_key>

        :param str wlan_name: Name of WLAN
        :param str zone_name: Name of APZone
        :param str domain_label: name of Domain
        :return: True if WLAN deleted else False
        :rtype: boolean

        """
 
        result = False

        try:
            del_url = ji.get_url(self.req_api_deletewlan, self.scg_mgmt_ip, self.scg_port)
            del_wlan_url = del_url% self.get_apzone_uuid(apzone_name=zone_name, domain_label=domain_label)
            del_wlan_api = self.req_api_configwlan_delete%self._get_key_for_profile(wlan_name, del_wlan_url)['key']
            del_zone_url = ji.get_url(del_wlan_api, self.scg_mgmt_ip, self.scg_port)
            result = ji.delete_scg_data(del_zone_url, self.jsessionid, None)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def create_mvno_account(self, mvno_domain_name="Auto-MVNO", description=None,
                         account_name="accountname", real_name=None, password="testing123",
                         phone=None, email=None, title=None,
                         aaa_name=None, aaa_type=None, realm=None,
                         aaa_enable_secondary_radius=False,
                         aaa_primary_ip=None, aaa_primary_port=None, aaa_primary_shared_secret=None,
                         aaa_secondary_ip=None, aaa_secondary_port=None, aaa_secondary_shared_secret=None,
                         aaa_request_timeout=None, aaa_max_numof_retries=None, aaa_reconnect_primary=None,
                         apzone_name=None, domain_label='Administration Domain', wlan_name=None):
        """
        API used to create MVNO Account

        URI: POST /wsg/api/scg/tenants?

        :param str mvno_domain_name: Name of MVNO Domain
        :param str domain_label: Name of the Domain
        :param str description: Description 
        :param str account_name: Name of MVNO Account
        :param str real_name: Real Name
        :param str password: Password
        :param str phone: Phone Number
        :param str email: Email
        :param str title: Title
        :param str aaa_name: Name of AAA Server
        :param str aaa_type: RADIUS | TACACS+
        :param str realm: Realm
        :param str aaa_enable_secondary_radius: True | False
        :param str aaa_primary_ip: Primary Server IP
        :param str aaa_primary_port: Primary Server Port 
        :param str aaa_primary_shared_secret: Primary Server Secret
        :param str aaa_secondary_ip: Secondary Server IP
        :param str aaa_secondary_port: Secondary Server Port
        :param str aaa_secondary_shared_secret: Secondary Server Secret
        :param str aaa_request_timeout: Failover policy at NAS Request timeout
        :param str aaa_max_numof_retries: Failover policy at NAS Maximum no of retries
        :param str aaa_reconnect_primary: Failover policy at NAS Reconnect primary
        :param str apzone_name: Name of APZone
        :param str wlan_name: Name of WLAN 
        :return: True if MVNO Account created else False
        :rtype: boolean
        """


        mvno_data = {}
        result = False
        is_duplicate_found = False
        try:
            url = ji.get_url(self.req_api_mvno,self.scg_mgmt_ip,self.scg_port)
            data = ji.get_json_data(url , self.jsessionid)

            for i in range(0,len(data["data"]["list"])):
                if data["data"]["list"][i]["name"] == mvno_domain_name:
                    is_duplicate_found = True
                    break

            if is_duplicate_found == True:
                print "Duplicate MVNO Profile name - %s is found " %mvno_domain_name
                return False

            mvno_url = ji.get_url(self.req_api_mvno, self.scg_mgmt_ip, self.scg_port)

            mvno_data.update(self.SJT.get_mvno_template_data())
            mvno_data.update({"name":mvno_domain_name,
                              "description":description})
            if apzone_name == None: 
                mvno_data["apZoneUUIDList"] = []
            else:
                zone_uuid = self.get_apzone_uuid(apzone_name=apzone_name, domain_label=domain_label)
                mvno_data["apZoneUUIDList"].append(str(zone_uuid))

            if wlan_name and apzone_name:
                wlan_id = self._get_wlan_id(apzone_name, wlan_name)
                mvno_data["wlanUUIDList"].append(str(wlan_id))
            else:
                mvno_data["wlanUUIDList"] = []

            mvno_data["superAdmin"].update({"userName":account_name,
                                            "realName":real_name, 
                                            "passphrase":password,
                                            "phone":phone,
                                            "email":email,
                                            "title":title})
            if aaa_name:
                mvno_data["aaaServers"].append({"createBy":"", "createOn":"", "key": "", 
                                                "createUserName": "", "creatorUUID":"", "tacacsService":"",
                                                "name":aaa_name, "type":aaa_type, "radiusRealm":realm})
                if aaa_type == "TACACS":
                    mvno_data["aaaServers"][0].update({"radiusIP":aaa_primary_ip, 
                                                    "radiusPort":int(aaa_primary_port), 
                                                    "radiusShareSecret":aaa_primary_shared_secret})

                elif aaa_type == "RADIUS":
                    mvno_data["aaaServers"][0].update({"radiusIP":aaa_primary_ip, 
                                                    "radiusPort":int(aaa_primary_port),
                                                    "radiusShareSecret":aaa_primary_shared_secret,
                                                    "enableSecondaryRadius":int(aaa_enable_secondary_radius)})

                    if int(aaa_enable_secondary_radius) == 1:
                        mvno_data["aaaServers"][0].update({"secondaryRadiusIP":aaa_secondary_ip, 
                                                        "secondaryRadiusPort":aaa_secondary_port,
                                                        "secondaryRadiusShareSecret":aaa_secondary_shared_secret,
                                                        "requestTimeout":int(aaa_request_timeout),
                                                        "maxRetries":int(aaa_max_numof_retries),
                                                        "retryPriInvl":int(aaa_reconnect_primary)})
                else:
                    print "create_mvno():invalid AAA type"
                    return False
                
                if aaa_type == "TACACS" and int(aaa_enable_secondary_radius) == 0:
                    mvno_data["aaaServers"][0].update({"enableSecondaryRadius":0,
                                                    "secondaryRadiusIP":"",
                                                    "secondaryRadiusPort":0,
                                                    "secondaryRadiusShareSecret":"",
                                                    "requestTimeout":3, 
                                                    "maxRetries":2, 
                                                    "retryPriInvl":5})

            else: 
                mvno_data["aaaServers"] = []

            append_data = json.dumps(mvno_data)
            result = ji.post_json_data(mvno_url, self.jsessionid, append_data)

        except Exception,e:
            print traceback.format_exc()
            return False

        return result

    def add_wlan_to_mvno(self, mvno_name="Auto-MVNO", apzone_name="Auto-1-apzone", 
                               domain_label="Administration Domain", wlan_name="Auto-1-wlan"):
        """
        API used to add WLAN to MVNO Account

        URI: PUT /wsg/api/scg/tenants/<mvno_account_key>

        :param str mvno_name: Name of MVNO Account
        :param str apzone_name: Name of APZone
        :param str domain_label: Name of Domain 
        :param str wlan_name: Name of the WLAN
        :return: True if WLAN added to MVNO Account else False
        :rtype: boolean

        """
 
        fwd_wlan_data = {}
        result = False
        try:
            url = ji.get_url(self.req_api_mvno, self.scg_mgmt_ip, self.scg_port)
            key, key_info = self._get_key_for_mvno(mvno_name, url)
            fwd_wlan_data.update(self.SJT.add_mvno_template_data())
            fwd_wlan_data['name'] = key_info['name']
            fwd_wlan_data["description"] = key_info["description"]
            fwd_wlan_data["key"] = key_info["key"]
            fwd_wlan_data["apZoneUUIDList"] = key_info["apZoneUUIDList"]
            fwd_wlan_data["wlanUUIDList"] = key_info["wlanUUIDList"]
            fwd_wlan_data["superAdmin"]["key"] = key_info["superAdmin"]["key"]
            fwd_wlan_data["superAdmin"]["userName"] = key_info["superAdmin"]["userName"]
            fwd_wlan_data["superAdmin"]["realName"] =  key_info["superAdmin"]["realName"]
            fwd_wlan_data["superAdmin"]["title"] = key_info["superAdmin"]["title"]
            fwd_wlan_data["superAdmin"]["phone"] = key_info["superAdmin"]["phone"]
            fwd_wlan_data["superAdmin"]["email"] =  key_info["superAdmin"]["email"]
            fwd_wlan_data["superAdmin"]["passphrase"] = key_info["superAdmin"]["passphrase"]
            fwd_wlan_data["superAdminRole"]["key"] = key_info["superAdminRole"]["key"]


            fwd_wlan_data["superAdminRole"]["capabilities"] = copy.deepcopy(key_info["superAdminRole"]["capabilities"])

                
            for i in range(0, len(key_info['aaaServers'])):
                fwd_wlan_data["aaaServers"].append({"createBy":"",
                                                    "createOn": key_info['aaaServers'][i]["createOn"],
                                                  "name":key_info['aaaServers'][i]["name"],
                                                  "key":key_info['aaaServers'][i]["key"],
                                                  "type":key_info['aaaServers'][i]["type"],
                                                  "radiusRealm":key_info['aaaServers'][i]["radiusRealm"],
                                                  "radiusIP":key_info['aaaServers'][i]["radiusIP"],
                                                  "radiusPort":key_info['aaaServers'][i]["radiusPort"],
                                                  "radiusShareSecret":key_info['aaaServers'][i]["radiusShareSecret"],
                                                  "secondaryRadiusIP":key_info['aaaServers'][i]["secondaryRadiusIP"],
                                                 "secondaryRadiusPort":key_info['aaaServers'][i]["secondaryRadiusPort"],
                         "secondaryRadiusShareSecret":key_info['aaaServers'][i]["secondaryRadiusShareSecret"],
                         "requestTimeout":key_info['aaaServers'][i]["requestTimeout"],
                         "maxRetries":key_info['aaaServers'][i]["maxRetries"],
                         "retryPriInvl":key_info['aaaServers'][i]["retryPriInvl"],
                         "enableSecondaryRadius":key_info['aaaServers'][i]["enableSecondaryRadius"],
                         "createUserName":key_info['aaaServers'][i]["createUserName"],
                         "creatorUUID":key_info['aaaServers'][i]["creatorUUID"],
                         "tacacsService":key_info['aaaServers'][i]["tacacsService"]})

            self.set_jsessionid(self.get_jsessionid())

            wlan_uuid = self._get_wlan_id(zone_name=apzone_name, wlan_name=wlan_name)

            fwd_wlan_data["wlanUUIDList"].append(wlan_uuid)

            append_data = json.dumps(fwd_wlan_data)
            fwd_wlan_api = self.req_api_update_mvno%key
            fwd_wlan_url = ji.get_url(fwd_wlan_api, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(fwd_wlan_url, self.jsessionid, append_data)

        except Exception,e:
            print traceback.format_exc()
            return False

        return result

    def add_apzone_to_mvno(self, mvno_name="Auto-MVNO", apzone_name="Auto-1-apzone", domain_label='Administration Domain'):

        """
        Adds the APZone to the MVNO account

        URI: PUT /wsg/api/scg/tenants/<mvno_account_key>

        :param str mvno_name: Name of the MVNO Account
        :param str apzone_name: Name of the APZone to be added
        :param str domain_label: Name of the Domain 
        :return: True if APZone is added to MVNO account else False
        :rtype: boolean

        """
        fwd_mvno_data = {}
        result = False
        try:
            url = ji.get_url(self.req_api_mvno,self.scg_mgmt_ip,self.scg_port)
            key, key_info = self._get_key_for_mvno(mvno_name,url)
            fwd_mvno_data.update(self.SJT.add_mvno_template_data())
            fwd_mvno_data['name'] = key_info['name']
            fwd_mvno_data["description"] = key_info["description"]
            fwd_mvno_data["key"] = key_info["key"]
            fwd_mvno_data["apZoneUUIDList"] = key_info["apZoneUUIDList"]
            fwd_mvno_data["wlanUUIDList"] = key_info["wlanUUIDList"]
            fwd_mvno_data["superAdmin"]["key"] = key_info["superAdmin"]["key"]
            fwd_mvno_data["superAdmin"]["userName"] = key_info["superAdmin"]["userName"]
            fwd_mvno_data["superAdmin"]["realName"] =  key_info["superAdmin"]["realName"]
            fwd_mvno_data["superAdmin"]["title"] = key_info["superAdmin"]["title"]
            fwd_mvno_data["superAdmin"]["phone"] = key_info["superAdmin"]["phone"]
            fwd_mvno_data["superAdmin"]["email"] =  key_info["superAdmin"]["email"]
            fwd_mvno_data["superAdmin"]["passphrase"] = key_info["superAdmin"]["passphrase"]
            fwd_mvno_data["superAdminRole"]["key"] = key_info["superAdminRole"]["key"]

            fwd_mvno_data["superAdminRole"]["capabilities"] = copy.deepcopy(key_info["superAdminRole"]["capabilities"])

            fwd_mvno_data["aaaServers"] = []
            for i in range(0, len(key_info['aaaServers'])):
                fwd_mvno_data["aaaServers"].append({"createBy":"","createOn": key_info['aaaServers'][i]["createOn"],
                                                  "name":key_info['aaaServers'][i]["name"],
                                                  "key":key_info['aaaServers'][i]["key"],
                                                  "type":key_info['aaaServers'][i]["type"],
                                                  "radiusRealm":key_info['aaaServers'][i]["radiusRealm"],
                                                  "radiusIP":key_info['aaaServers'][i]["radiusIP"],
                                                  "radiusPort":key_info['aaaServers'][i]["radiusPort"],
                                                  "radiusShareSecret":key_info['aaaServers'][i]["radiusShareSecret"],
                                                  "secondaryRadiusIP":key_info['aaaServers'][i]["secondaryRadiusIP"],
                                                 "secondaryRadiusPort":key_info['aaaServers'][i]["secondaryRadiusPort"],
                         "secondaryRadiusShareSecret":key_info['aaaServers'][i]["secondaryRadiusShareSecret"],
                         "requestTimeout":key_info['aaaServers'][i]["requestTimeout"],
                         "maxRetries":key_info['aaaServers'][i]["maxRetries"],
                         "retryPriInvl":key_info['aaaServers'][i]["retryPriInvl"],
                         "enableSecondaryRadius":key_info['aaaServers'][i]["enableSecondaryRadius"],
                         "createUserName":key_info['aaaServers'][i]["createUserName"],
                         "creatorUUID":key_info['aaaServers'][i]["creatorUUID"],
                         "tacacsService":key_info['aaaServers'][i]["tacacsService"]})

            self.set_jsessionid(self.get_jsessionid())

            zone_uuid = self.get_apzone_uuid(apzone_name=apzone_name, domain_label=domain_label)
            fwd_mvno_data["apZoneUUIDList"].append(zone_uuid)
            append_data = json.dumps(fwd_mvno_data)
            aaa_api = self.req_api_update_mvno%key
            aaa_url = ji.get_url(aaa_api, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(aaa_url, self.jsessionid, append_data)

        except Exception,e:
            print traceback.format_exc()
            return False

        return result

    def add_aaa_server_to_mvno(self, mvno_name="Auto-MVNO", aaa_name="AAA",aaa_type="RADIUS", aaa_radius_realm="Realm",
                         aaa_primary_ip='1.2.3.4', aaa_primary_port='1812', aaa_primary_shared_secret='testing123',
                         aaa_secondary_ip=None, aaa_secondary_port=None, aaa_secondary_shared_secret=None,
                         aaa_request_time_out=None, aaa_max_retries=None, aaa_reconnect_primary=None,
                         aaa_enable_secondary_radius='0'):
        """
        API used to add the AAA server to MVNO Account

        URI: PUT /wsg/api/scg/tenants/<mvno_key>

        :param str mvno_name: Name of MVNO Account
        :param str aaa_name: AAA Server name
        :param str aaa_type: RADIUS | TACACS
        :param str aaa_radius_realm: Realm
        :param str aaa_primary_ip: Primary IP
        :param str aaa_primary_port: Primary Port number
        :param str aaa_primary_shared_secret: Primary shared secret
        :param str aaa_secondary_ip: Secondary IP
        :param str aaa_secondary_port: Secondary Port number
        :param str aaa_secondary_shared_secre: Secondary shared secret
        :param str aaa_request_time_out: Failover Policy at NAS request timeout
        :param str aaa_max_retries: Failover Policy at NAS Maximum no of Retries
        :param str aaa_reconnect_primary: Failover Policy at NAS Reconnect Primary
        :param str aaa_enable_secondary_radius: 0 | 1
        :return: True if AAA Server added to MVNO Account else False
        :rtype: boolean

        """

        aaa_data = {}
        result = False

        try:
            url = ji.get_url(self.req_api_mvno,self.scg_mgmt_ip,self.scg_port)
            key, key_info = self._get_key_for_mvno(mvno_name,url)
            aaa_data.update(self.SJT.add_mvno_template_data())
            aaa_data['name'] = key_info['name']
            aaa_data["description"] = key_info["description"]
            aaa_data["key"] = key_info["key"]
            aaa_data["apZoneUUIDList"] = key_info["apZoneUUIDList"]
            aaa_data["wlanUUIDList"] = key_info["wlanUUIDList"]
            aaa_data["superAdmin"]["key"] = key_info["superAdmin"]["key"]
            aaa_data["superAdmin"]["userName"] = key_info["superAdmin"]["userName"]
            aaa_data["superAdmin"]["realName"] =  key_info["superAdmin"]["realName"]
            aaa_data["superAdmin"]["title"] = key_info["superAdmin"]["title"]
            aaa_data["superAdmin"]["phone"] = key_info["superAdmin"]["phone"]
            aaa_data["superAdmin"]["email"] =  key_info["superAdmin"]["email"]
            aaa_data["superAdmin"]["passphrase"] = key_info["superAdmin"]["passphrase"]
            aaa_data["superAdminRole"]["key"] = key_info["superAdminRole"]["key"]

            aaa_data["superAdminRole"]["capabilities"] = copy.deepcopy(key_info["superAdminRole"]["capabilities"])

            aaa_data["aaaServers"] = []
            for i in range(0, len(key_info['aaaServers'])):
                aaa_data["aaaServers"].append({"createBy":"","createOn": key_info['aaaServers'][i]["createOn"],
                                              "name":key_info['aaaServers'][i]["name"],
                                              "key":key_info['aaaServers'][i]["key"],
                                              "type":key_info['aaaServers'][i]["type"],
                                              "radiusRealm":key_info['aaaServers'][i]["radiusRealm"],
                                              "radiusIP":key_info['aaaServers'][i]["radiusIP"],
                                              "radiusPort":key_info['aaaServers'][i]["radiusPort"],
                                              "radiusShareSecret":key_info['aaaServers'][i]["radiusShareSecret"],
                                              "secondaryRadiusIP":key_info['aaaServers'][i]["secondaryRadiusIP"],
                                              "secondaryRadiusPort":key_info['aaaServers'][i]["secondaryRadiusPort"],
                                             "secondaryRadiusShareSecret":key_info['aaaServers'][i]["secondaryRadiusShareSecret"],
                                             "requestTimeout":key_info['aaaServers'][i]["requestTimeout"],
                                             "maxRetries":key_info['aaaServers'][i]["maxRetries"],
                                             "retryPriInvl":key_info['aaaServers'][i]["retryPriInvl"],
                                             "enableSecondaryRadius":key_info['aaaServers'][i]["enableSecondaryRadius"],
                                             "createUserName":key_info['aaaServers'][i]["createUserName"],
                                             "creatorUUID":key_info['aaaServers'][i]["creatorUUID"],
                                             "tacacsService":key_info['aaaServers'][i]["tacacsService"]})


            for i in range(0, len(key_info['aaaServers'])):
                
                if key_info['aaaServers'][i]["name"] == aaa_name:
                    print "Duplicate Entery AAA Name  Found"
                    return False
                
                elif key_info['aaaServers'][i]["radiusRealm"] == aaa_radius_realm:
                    print "Duplicate Entery Realm Found"
                    return False

                elif key_info['aaaServers'][i]["radiusIP"] == aaa_primary_ip:
                    #or key_info['aaaServers'][i]["secondaryRadiusIP"] == aaa_secondary_ip: 
                    print "Duplicate Entery IP Address Found"
                    return False
            else:
                aaa_data["aaaServers"].append({"createBy":"","createOn":"","key": "",
                            "name":aaa_name, "type": aaa_type,
                            "radiusRealm":aaa_radius_realm,
                            "radiusIP": aaa_primary_ip,
                            "radiusPort": aaa_primary_port, 
                            "radiusShareSecret":aaa_primary_shared_secret,
                            "secondaryRadiusIP":aaa_secondary_ip, 
                            "secondaryRadiusPort":aaa_secondary_port,
                            "secondaryRadiusShareSecret":aaa_secondary_shared_secret,
                            "requestTimeout":aaa_request_time_out,
                            "maxRetries":aaa_max_retries, 
                            "retryPriInvl":aaa_reconnect_primary,
                            "enableSecondaryRadius":aaa_enable_secondary_radius, 
                            "createUserName":"",
                            "creatorUUID":"", "tacacsServices":""})


            append_data = json.dumps(aaa_data)
            aaa_api = self.req_api_update_mvno%key
            aaa_url = ji.get_url(aaa_api, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(aaa_url, self.jsessionid, append_data)

        except Exception,e:
            print traceback.format_exc()
            return False

        return result

    
    def delete_wlan_from_mvno(self, mvno_name="Auto-MVNO", apzone_name="Auto-1-apzone", wlan_name="Auto-1-wlan", domain_label="Administration Domain"):
        """
        API used to delete the WLAN in MVNO Account

        URI: PUT /wsg/api/scg/tenants/<mvno_key>

        :param str mvno_name: Name of MVNO Account
        :param str apzone_name: Name of APZone 
        :param str wlan_name: Name of WLAN
        :param str domain_label: Name of Domain
        :return: True if WLAN deleted from MVNO Account else False
        :rtype: boolean

        """

        del_wlan_data = {}
        result = False
        is_entry_found = False

        try:
            url = ji.get_url(self.req_api_mvno,self.scg_mgmt_ip,self.scg_port)
            key, key_info = self._get_key_for_mvno(mvno_name,url)
            del_wlan_data.update(self.SJT.add_mvno_template_data())
            del_wlan_data['name'] = key_info['name']
            del_wlan_data["description"] = key_info["description"]
            del_wlan_data["key"] = key_info["key"]
            del_wlan_data["apZoneUUIDList"] = key_info["apZoneUUIDList"]
            del_wlan_data["wlanUUIDList"] = key_info["wlanUUIDList"]

            del_wlan_data["superAdmin"]["key"] = key_info["superAdmin"]["key"]
            del_wlan_data["superAdmin"]["userName"] = key_info["superAdmin"]["userName"]
            del_wlan_data["superAdmin"]["realName"] =  key_info["superAdmin"]["realName"]
            del_wlan_data["superAdmin"]["title"] = key_info["superAdmin"]["title"]
            del_wlan_data["superAdmin"]["phone"] = key_info["superAdmin"]["phone"]
            del_wlan_data["superAdmin"]["email"] =  key_info["superAdmin"]["email"]
            del_wlan_data["superAdmin"]["passphrase"] = key_info["superAdmin"]["passphrase"]
            del_wlan_data["superAdminRole"]["key"] = key_info["superAdminRole"]["key"]


            del_wlan_data["superAdminRole"]["capabilities"] = copy.deepcopy(key_info["superAdminRole"]["capabilities"])

            del_wlan_data["aaaServers"] = []

            for i in range(0, len(key_info['aaaServers'])):
                del_wlan_data["aaaServers"].append({"createBy":"","createOn": key_info['aaaServers'][i]["createOn"],
                                                  "name":key_info['aaaServers'][i]["name"],
                                                  "key":key_info['aaaServers'][i]["key"],
                                                  "type":key_info['aaaServers'][i]["type"],
                                                  "radiusRealm":key_info['aaaServers'][i]["radiusRealm"],
                                                  "radiusIP":key_info['aaaServers'][i]["radiusIP"],
                                                  "radiusPort":key_info['aaaServers'][i]["radiusPort"],
                                                 "secondaryRadiusPort":key_info['aaaServers'][i]["secondaryRadiusPort"],
                         "secondaryRadiusShareSecret":key_info['aaaServers'][i]["secondaryRadiusShareSecret"],
                         "requestTimeout":key_info['aaaServers'][i]["requestTimeout"],
                         "maxRetries":key_info['aaaServers'][i]["maxRetries"],
                         "retryPriInvl":key_info['aaaServers'][i]["retryPriInvl"],
                         "enableSecondaryRadius":key_info['aaaServers'][i]["enableSecondaryRadius"],
                         "createUserName":key_info['aaaServers'][i]["createUserName"],
                         "creatorUUID":key_info['aaaServers'][i]["creatorUUID"],
                         "tacacsService":key_info['aaaServers'][i]["tacacsService"]})

            del_wlan_uuid = self._get_wlan_id(zone_name=apzone_name, wlan_name = wlan_name, domain_label=domain_label)

            for x in range(0,len(key_info["wlanUUIDList"])):
                if del_wlan_uuid == key_info["wlanUUIDList"][x]:
                    is_entry_found = True
                    del key_info["wlanUUIDList"][x]
                    del_wlan_data["wlanUUIDList"] = key_info["wlanUUIDList"]
                    break
            if not is_entry_found:
                print "No match is found - %s ",apzone_name

            append_data = json.dumps(del_wlan_data)
            del_wlan_api = self.req_api_update_mvno%key
            del_wlan_url = ji.get_url(del_wlan_api, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(del_wlan_url, self.jsessionid, append_data)

        except Exception,e:
            print traceback.format_exc()
            return False

        return result

    def delete_apzone_from_mvno(self, mvno_name="Auto-MVNO", apzone_name="Auto-1-apzone", domain_label="Administration Domain"):
        """
        API used to delete APZone from MVNO Account

        URI: PUT /wsg/api/scg/tenants/<mvno_key>

        :param str mvno_name: Name of MVNO Account
        :param str apzone_name: Name of the APZone
        :param str domain_label: Name of the Domain
        :return: True if APZone is deleted from MVNO Account else False
        :rtype: boolean

        """

        del_apzone_data = {}
        result = False
        is_entry_found = False

        try:
            url = ji.get_url(self.req_api_mvno,self.scg_mgmt_ip,self.scg_port)
            key, key_info = self._get_key_for_mvno(mvno_name,url)
            del_apzone_data.update(self.SJT.add_mvno_template_data())
            del_apzone_data['name'] = key_info['name']
            del_apzone_data["description"] = key_info["description"]
            del_apzone_data["key"] = key_info["key"]

            del_apzone_data["wlanUUIDList"] = key_info["wlanUUIDList"]
            del_apzone_data["superAdmin"]["key"] = key_info["superAdmin"]["key"]
            del_apzone_data["superAdmin"]["userName"] = key_info["superAdmin"]["userName"]
            del_apzone_data["superAdmin"]["realName"] =  key_info["superAdmin"]["realName"]

            del_apzone_data["superAdmin"]["key"] = key_info["superAdmin"]["key"]
            del_apzone_data["superAdmin"]["userName"] = key_info["superAdmin"]["userName"]
            del_apzone_data["superAdmin"]["realName"] =  key_info["superAdmin"]["realName"]
            del_apzone_data["superAdmin"]["title"] = key_info["superAdmin"]["title"]
            del_apzone_data["superAdmin"]["phone"] = key_info["superAdmin"]["phone"]
            del_apzone_data["superAdmin"]["email"] =  key_info["superAdmin"]["email"]
            del_apzone_data["superAdmin"]["passphrase"] = key_info["superAdmin"]["passphrase"]
            del_apzone_data["superAdminRole"]["key"] = key_info["superAdminRole"]["key"]
            del_apzone_data["superAdminRole"]["capabilities"] = copy.deepcopy(key_info["superAdminRole"]["capabilities"])
            del_apzone_data["aaaServers"] = []
            for i in range(0, len(key_info['aaaServers'])):
                del_apzone_data["aaaServers"].append({"createBy":"","createOn": key_info['aaaServers'][i]["createOn"],
                                                  "name":key_info['aaaServers'][i]["name"],
                                                  "key":key_info['aaaServers'][i]["key"],
                                                  "type":key_info['aaaServers'][i]["type"],
                                                  "radiusRealm":key_info['aaaServers'][i]["radiusRealm"],
                                                  "radiusIP":key_info['aaaServers'][i]["radiusIP"],
                                                  "radiusPort":key_info['aaaServers'][i]["radiusPort"],
                                                 "secondaryRadiusPort":key_info['aaaServers'][i]["secondaryRadiusPort"],
                         "secondaryRadiusShareSecret":key_info['aaaServers'][i]["secondaryRadiusShareSecret"],
                         "requestTimeout":key_info['aaaServers'][i]["requestTimeout"],
                         "maxRetries":key_info['aaaServers'][i]["maxRetries"],
                         "retryPriInvl":key_info['aaaServers'][i]["retryPriInvl"],
                         "enableSecondaryRadius":key_info['aaaServers'][i]["enableSecondaryRadius"],
                         "createUserName":key_info['aaaServers'][i]["createUserName"],
                         "creatorUUID":key_info['aaaServers'][i]["creatorUUID"],
                         "tacacsService":key_info['aaaServers'][i]["tacacsService"]})

            zone_uuid = self.get_apzone_uuid(apzone_name=apzone_name, domain_label=domain_label)
            for x in range(0,len(key_info["apZoneUUIDList"])):
                if zone_uuid == key_info["apZoneUUIDList"][x]:
                    is_entry_found = True
                    del key_info["apZoneUUIDList"][x]
                    del_apzone_data["apZoneUUIDList"] = key_info["apZoneUUIDList"]
                    break

            if not is_entry_found:
                print "No match is found - %s ",apzone_name

            append_data = json.dumps(del_apzone_data)
            del_wlan_api = self.req_api_update_mvno%key
            del_wlan_url = ji.get_url(del_wlan_api, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(del_wlan_url, self.jsessionid, append_data)

        except Exception,e:
            print traceback.format_exc()
            return False

        return result
    
    def delete_aaa_server_from_mvno(self, mvno_name="Auto-MVNO", aaa_name="AAA"):
        """
        API used to delete AAA server from MVNO Account

        URI: PUT /wsg/api/scg/tenants/<mvno_key>

        :param str mvno_name: Name of the MVNO Account
        :param str aaa_name: Name of AAA Server
        :return: True if AAA Server deleted from MVNO else False
        :rtype: boolean

        """

        del_aaa_data = {}
        result = False
        is_entry_found = False

        try:
            url = ji.get_url(self.req_api_mvno,self.scg_mgmt_ip,self.scg_port)
            key, key_info = self._get_key_for_mvno(mvno_name,url)
            del_aaa_data.update(self.SJT.add_mvno_template_data())
            del_aaa_data['name'] = key_info['name']
            del_aaa_data["description"] = key_info["description"]
            del_aaa_data["key"] = key_info["key"]

            del_aaa_data["wlanUUIDList"] = key_info["wlanUUIDList"]
            del_aaa_data["superAdmin"]["key"] = key_info["superAdmin"]["key"]
            del_aaa_data["superAdmin"]["userName"] = key_info["superAdmin"]["userName"]
            del_aaa_data["superAdmin"]["realName"] =  key_info["superAdmin"]["realName"]
            del_aaa_data["apZoneUUIDList"] = key_info["apZoneUUIDList"]

            del_aaa_data["superAdmin"]["key"] = key_info["superAdmin"]["key"]
            del_aaa_data["superAdmin"]["userName"] = key_info["superAdmin"]["userName"]
            del_aaa_data["superAdmin"]["realName"] =  key_info["superAdmin"]["realName"]
            del_aaa_data["superAdmin"]["title"] = key_info["superAdmin"]["title"]
            del_aaa_data["superAdmin"]["phone"] = key_info["superAdmin"]["phone"]
            del_aaa_data["superAdmin"]["email"] =  key_info["superAdmin"]["email"]
            del_aaa_data["superAdmin"]["passphrase"] = key_info["superAdmin"]["passphrase"]
            del_aaa_data["superAdminRole"]["key"] = key_info["superAdminRole"]["key"]

            del_aaa_data["superAdminRole"]["capabilities"] = copy.deepcopy(key_info["superAdminRole"]["capabilities"])

            del_aaa_data["aaaServers"] = []
            for i in range(0, len(key_info['aaaServers'])):
                if key_info['aaaServers'][i]["name"] == aaa_name:
                    is_entry_found = True
                    del key_info['aaaServers'][i]
                    for i in range(0, len(key_info['aaaServers'])):
                        del_aaa_data["aaaServers"].append({"createBy":"","createOn": key_info['aaaServers'][i]["createOn"],
                                                  "name":key_info['aaaServers'][i]["name"],
                                                  "key":key_info['aaaServers'][i]["key"],
                                                  "type":key_info['aaaServers'][i]["type"],
                                                  "radiusRealm":key_info['aaaServers'][i]["radiusRealm"],
                                                  "radiusIP":key_info['aaaServers'][i]["radiusIP"],
                                                  "radiusPort":key_info['aaaServers'][i]["radiusPort"],
                                                  "radiusShareSecret":key_info['aaaServers'][i]["radiusShareSecret"],
                                                  "secondaryRadiusIP":key_info['aaaServers'][i]["secondaryRadiusIP"],
                                                 "secondaryRadiusPort":key_info['aaaServers'][i]["secondaryRadiusPort"],
                         "secondaryRadiusShareSecret":key_info['aaaServers'][i]["secondaryRadiusShareSecret"],
                         "requestTimeout":key_info['aaaServers'][i]["requestTimeout"],
                         "maxRetries":key_info['aaaServers'][i]["maxRetries"],
                         "retryPriInvl":key_info['aaaServers'][i]["retryPriInvl"],
                         "enableSecondaryRadius":key_info['aaaServers'][i]["enableSecondaryRadius"],
                         "createUserName":key_info['aaaServers'][i]["createUserName"],
                         "creatorUUID":key_info['aaaServers'][i]["creatorUUID"],
                         "tacacsService":key_info['aaaServers'][i]["tacacsService"]})

                        break

            if not is_entry_found:
                print "No Match Found - %s in %s " %(aaa_name, mvno_name)

            append_data = json.dumps(del_aaa_data)
            del_aaa_api = self.req_api_update_mvno%key
            del_aaa_url = ji.get_url(del_aaa_api, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(del_aaa_url, self.jsessionid, append_data)

        except Exception,e:
            print traceback.format_exc()
            return False

        return result



    def _get_wlan_id(self, zone_name=None, wlan_name=None, domain_label='Administration Domain'):
        """
        API is used to get WLAN ID

        URI: GET /wsg/api/scg/wlans/byZone/<apzone_uuid>

        :param str wlan_name: Name of the WLAN
        :param str zone_name: Name of the APZONE
        :param str domain_label: Name of the Domain
        :return: True if WLAN ID is received else False
        :rtype: unicode

        """
 

        url = ji.get_url(self.req_api_deletewlan, self.scg_mgmt_ip, self.scg_port)
        del_wlan_url = url%self.get_apzone_uuid(apzone_name=zone_name, domain_label=domain_label)

        key = None
        data = ji.get_json_data(del_wlan_url, self.jsessionid)

        for i in range(0,len(data[u"data"][u"list"])):              #Fetch Radius Authentication key using the profile name
            if data[u"data"][u"list"][i][u"name"] == wlan_name:
                key  = data[u"data"][u"list"][i][u"key"]
                break

        if not key:
            raise Exception("_get_key_for_profile(): Key not found for the name: %s" % (wlan_name))

        return key

 
    def _delete_wlan_in_mvno(self, mvno_name="Auto-MVNO"):
        """
        API used to delete the WLAN in MVNO Account
        
        URI: PUT /wsg/api/scg/tenants/<mvno_key>?        
        
        :param str mvno_name: Name of MVNO
        :return: True if WLAN deleted successfully else False
        :rtype: boolean

        """

        result = False
        fwd_data = {}
        key = None

        try:
            url = ji.get_url(self.req_api_mvno, self.scg_mgmt_ip, self.scg_port)
            rcvd_data = ji.get_json_data(url, self.jsessionid)
            rcv_data = copy.deepcopy(rcvd_data['data']['list'])
            fwd_data.update(self.SJT.get_mvno_template_data())

            for i in range(0, len(rcvd_data['data']['list'])):
                if rcvd_data['data']['list'][i]['name'] == mvno_name:
                    rcv_data = rcvd_data['data']['list'][i]
                    fwd_data.update(
                        {"name":rcv_data['name'],
                         "description":rcv_data['description'],
                        "key":rcv_data['key'],
                        "apZoneUUIDList":rcv_data["apZoneUUIDList"],
                        "wlanUUIDList":[],
                        "superAdmin": {"key":rcv_data['superAdmin']['key'],
                                       "userName":rcv_data["superAdmin"]["userName"] ,
                                       "realName":rcv_data["superAdmin"]["realName"],
                                       "title":rcv_data["superAdmin"]["title"],
                                       "phone":rcv_data["superAdmin"]["phone"],
                                       "email":rcv_data["superAdmin"]["email"],
                                       "passphrase":rcv_data["superAdmin"]["passphrase"]},
                        "superAdminRole":{"key":rcv_data['superAdminRole']['key'],
                                          "capabilities":rcv_data["superAdminRole"] ['capabilities']},
                        "aaaServers":[]})
                    key = rcvd_data['data']['list'][i]['key']

            del_url = ji.get_url(self.req_api_update_mvno%key, self.scg_mgmt_ip, self.scg_port)
            json_data = json.dumps(fwd_data)
            result = ji.put_json_data(del_url, self.jsessionid, json_data)
        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def _get_key_for_mvno(self, mvno_name="Auto-MVNO", url=None):
        """
        API used to get the key and data of MVNO Account
        
        :param str mvno_name: Name of MVNO account 
        :param str  url: URL
        :return: key and data of MVNO Account
        :rtype: unicode, dictionary

        """

        key, data = None, None
        rcvd_data = ji.get_json_data(url, self.jsessionid)

        for i in range(0, len(rcvd_data['data']['list'])):
            if rcvd_data['data']['list'][i]['name'] == mvno_name:
                key, data = rcvd_data['data']['list'][i]['key'], rcvd_data['data']['list'][i]

        if not key:
            raise Exception("_get_key_for_mvno(): key not found")

        return key, data


    def delete_mvno(self, mvno_name="Auto-MVNO"):
        """
        API used to delete MVNO Account

        URI: DELETE /wsg/api/scg/tenants/<mvno_key>

        :param str mvno_name: Name of MVNO 
        :return: True if MVNO Account deleted else False
        :rtype: boolean

        """

        result = False
        try:
            res = self._delete_wlan_in_mvno(mvno_name)
            if res == False:
                print "Not possible to delete"
                return False
            url = ji.get_url(self.req_api_mvno, self.scg_mgmt_ip, self.scg_port)
            key, rcvd_data = self._get_key_for_mvno(mvno_name, url)
            del_url = ji.get_url(self.req_api_update_mvno%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.delete_scg_data(del_url, self.jsessionid, None)

        except Exception, e:
            print traceback.format_exc()
            return False
            
        return result
  

    def create_package(self, package_name='Auto_Package',
                            description=None,
                            expiry_interval='DAY',
                            expiry_value='1'):
        """
        Api used to create the Packages

        URI: POST /wsg/api/scg/packages?

        :param str package_name: Name of the package
        :param str description: Description about the Package
        :param str expiry_interval: HOUR | DAY | WEEK | MONTH | YEAR | NEVER
        :param str expiry_value: Expiration  value
        :return: True if Package is created else False
        :rtype: boolean
        """
        result = False
        is_entry_found = False
        fwd_data = {}
        try:
            url = ji.get_url(self.req_api_package, self.scg_mgmt_ip, self.scg_port)
            rcvd_data = ji.get_json_data(url, self.jsessionid)

            for i in range(0, len(rcvd_data['data']['list'])):
                if rcvd_data['data']['list'][i]['name'] == package_name:
                    is_entry_found = True
                    break

            if is_entry_found == True:
                print "Duplicate entry of Package"
                return False

            fwd_data.update({'name':package_name,
                             'info':description,
                             'expirationInterval':expiry_interval})

            if expiry_interval == "NEVER":
                fwd_data.update({'expirationValue':""})
            else:
                fwd_data.update({'expirationValue':int(expiry_value)})

            json_data = json.dumps(fwd_data)
            result = ji.post_json_data(url, self.jsessionid, json_data)

        except Exception,e:
            print traceback.format_exc()
            return False

        return result

    def _id_of_country(self, country_name='INDIA'):
        """
        API used to get the id of Country

        URI: GET /wsg/api/scg/identity/profiles/countries?

        :param str country_name: Name of the country
        :return: country id
        :rtype: unicode 

        """
        
        country_id = None

        url = ji.get_url(self.req_api_country_id, self.scg_mgmt_ip, self.scg_port)
        rcv_data = ji.get_json_data(url, self.jsessionid)
        for i in range(0, len(rcv_data['data']['list'])):
            if rcv_data['data']['list'][i]['name'] == country_name:
                country_id = rcv_data['data']['list'][i]['id']
                break

        if not country_id:
            raise Exception('Country Name %s not found' %(country_name))

        return country_id
    
    def _get_key_for_package(self, package_name='Auto_Package'):
        """
        API used to get the key of the Package
        
        URI: GET /wsg/api/scg/packages?

        :param str package_name: Name of the Package
        :return: key of the Package
        :rtype: unicode 
        
        """
        key, data = None, None
        url = ji.get_url(self.req_api_package, self.scg_mgmt_ip, self.scg_port)
        rcvd_data = ji.get_json_data(url, self.jsessionid)
        for i in range(0, len(rcvd_data['data']['list'])):
            if rcvd_data['data']['list'][i]['name'] == package_name:
                key, data = rcvd_data['data']['list'][i]['key'], rcvd_data['data']['list'][i]
                break

        if not key:
            raise Exception("_get_key_for_package(): Key not found for the name %s" % (package_name))

        return key, data


    def _package_id(self, package_name='Auto_Package'):

        """
        API used to get the key of the Package
        
        URI: GET /wsg/api/scg/packages?

        :param str package_name: Name of the Package
        :return: key of the Package
        :rtype: unicode 
        
        """

        package_id = None

        #url = ji.get_url(self.req_api_get_package, self.scg_mgmt_ip, self.scg_port)
        url_api = '/wsg/api/scg/packages?'
        url = ji.get_url(url_api, self.scg_mgmt_ip, self.scg_port)
        rcv_data = ji.get_json_data(url, self.jsessionid)
        for i in range(0, len(rcv_data['data']['list'])):
            if rcv_data['data']['list'][i]['name'] == package_name:
                package_id = rcv_data['data']['list'][i]['key']
                break

        if not package_id:
            raise Exception('Package Name %s not found' %(package_name))

        return package_id

    def validate_package(self, package_name='Auto_Package',
                            description=None,
                            expiry_interval='DAY',
                            expiry_value='1'):
        """
        Api used to validate the Packages

        URI: GET /wsg/api/scg/packages?

        :param str package_name: Name of the package
        :param str description: Description about the Package
        :param str expiry_interval: HOUR | DAY | WEEK | MONTH | YEAR | NEVER
        :param str expiry_value: Expiration  value
        :return: True if Package is validated else False
        :rtype: boolean
        """
        try:
            key, rcvd_data = self._get_key_for_package(package_name=package_name)
            if package_name:
                if package_name != rcvd_data['name']:
                    self._print_err_validate('validate_package', 'package_name', 'name',
                        package_name, rcvd_data["name"])
                    return False
            if description:
                if description != rcvd_data['info']:
                    self._print_err_validate('validate_package', 'description', 'info', description, rcvd_data["info"])
                    return False
            if expiry_interval:
                if expiry_interval != rcvd_data['expirationInterval']:
                    self._print_err_validate('validate_package', 'expiry_interval', 'expirationInterval',
                            expiry_interval, rcvd_data['expirationInterval'])
                    return False
            if expiry_value:
                if int(expiry_value) != rcvd_data['expirationValue']:
                    self._print_err_validate('validate_package', 'expiry_value', 'expirationValue', expiry_value,
                            rcvd_data['expirationValue'])
                    return False

            return True

        except Exception,e:
            print traceback.format_exc()
            return False


    def delete_package(self, package_name='Auto_Package'):
        """
        API used to delete the package

        URI: DELETE /wsg/api/scg/packages/<package_key>

        :param str package_name: Name of the Package
        :return: True if Package is deleted else False
        :rtype: boolean

        """
        result = False
        try:
            key, data = self._get_key_for_package(package_name=package_name)
            url = ji.get_url(self.req_api_package_del % key, self.scg_mgmt_ip, self.scg_port)
            result = ji.delete_scg_data(url, self.jsessionid, None)

        except Exception,e:
            print traceback.format_exc()
            return False

        return result


    def create_profile_in_identity(self, first_name='FirstName', last_name='LastName',
                             mail_addr='ruckus@gmail.co', phone='1234567890',
                             country_id='US', city='NewYork', address='7th', zipcode=None,
                             state='DISABLED', comment=None,
                             login_name='admin1', login_password='ruckus1!',
                             package_name='Package'):

        """
        API used to create Profile in Identity

        URI: GET /wsg/api/scg/identity/profiles/create? 

        :param str first_name: First Name
        :param str last_name: Last Name
        :param str mail_addr: Email Address
        :param str phone: Phone Number
        :param str country: Name of the Country
        :param str city: Name of the City
        :param str address: Address Details
        :param str zipcode: Zipcode
        :param str state: Name of the State
        :param str comment: Sample Description on Profile
        :param str login_name: Login name
        :param str login_password: Password
        :param str package_name: Package Name
        :return: True if create Profile in Identity Success else False
        :rtype: boolean

        """
        result = False
        fwd_data = {}
        package_id = None
        try:
            uri = '/wsg/api/scg/identity/users'
            #url = ji.get_url(self.req_api_profile, self.scg_mgmt_ip, self.scg_port)
            url = ji.get_url(uri, self.scg_mgmt_ip, self.scg_port)
            #country_id = self._id_of_country(country_name=country)
            package_id = self._package_id(package_name=package_name)

            fwd_data.update({"firstName":first_name,
                             "lastName":last_name,
                             "mailAddress":mail_addr,
                             "primaryPhoneNumber":phone,
                             "country":country_id,
                             "city":city,
                             "address":address,
                             "zipCode":zipcode,
                             "userStatus":state,
                             "comment":comment,
                             "userName":login_name,
                             "loginPassword":login_password,
                             "selectedPackage":package_id})
            data_json = json.dumps(fwd_data)
            print "#############",data_json
            result = ji.post_json_data(url, self.jsessionid, data_json)

        except Exception,e:
            print traceback.format_exc()
            return False

        return result

    def _get_profile_data_in_identity(self, login_name="profile_username"):

        key, data = None, None

        url_str = "start=0&limit=10&criteria=%5B%7B%22columnName%22%3A%22loginName%22%2C%22operator%22%3A%22eq%22%2C%22value%22%3A%22" + \
                login_name + "%22%7D%5D&maxTotalCount=45000"
        profile_data_url = ji.get_url(self.req_api_profile_data + url_str, self.scg_mgmt_ip, self.scg_port)
        rcvd_data = ji.get_json_data(profile_data_url, self.jsessionid)

        for i in range (0, len(rcvd_data['data']['list'])):
            if rcvd_data['data']['list'][i]['loginName'] == login_name:
                key, data = rcvd_data['data']['list'][i]['uniqueId'], rcvd_data['data']['list'][i]
                break

        if not key:
            raise Exception("_get_profile_data_in_identity(): Key not found for name %s" % (login_name))

        return key, data

    def validate_profile_in_identity(self, first_name=None, last_name=None,
                             mail_addr=None, phone=None,
                             country_id=None, city=None, address=None, zipcode=None,
                             state=None, comment=None,
                             login_name='admin1',
                             package_name=None):
        """
        API used to validate Profile in Identity

        :param str first_name: First Name
        :param str last_name: Last Name
        :param str mail_addr: Email Address
        :param str phone: Phone Number
        :param str country_id: Name of the Country
        :param str city: Name of the City
        :param str address: Address Details
        :param str zipcode: Zipcode
        :param str state: Name of the State
        :param str comment: Sample Description on Profile
        :param str login_name: Login name
        :param str package_name: Package Name
        :return: True if validate Profile in Identity Success else False
        :rtype: boolean
        """

        try:
            key, data = self._get_profile_data_in_identity(login_name=login_name)
            if first_name:
                if first_name != data['firstName']:
                    self._print_err_validate('validate_profile_in_identity', 'first_name', 'firstName',
                            first_name, data['firstName'])
                    return False
            if last_name:
                if last_name != data['lastName']:
                    self._print_err_validate('validate_profile_in_identity', 'last_name', 'lastName',
                            last_name, data['lastName'])
                    return False
            if mail_addr:
                if mail_addr != data["mailAddress"]:
                    self._print_err_validate('validate_profile_in_identity', 'mail_addr', 'mailAddress', mail_addr,
                            data["mailAddress"])
                    return False
            if phone:
                if phone != data["primaryPhoneNumber"]:
                    self._print_err_validate('validate_profile_in_identity', 'phone', 'primaryPhoneNumber',
                            phone, data["primaryPhoneNumber"])
                    return False
            if country_id:
                country_id = self._id_of_country(country_name=country_id)
                if country_id != data['country']:
                    self._print_err_validate('validate_profile_in_identity', 'country', 'country',
                            country_id, data['country'])
                    return False
            if city:
                if city != data['city']:
                    self._print_err_validate('validate_profile_in_identity', 'city', 'city',
                            city, data['city'])
                    return False
            if address:
                if address != data['address']:
                    self._print_err_validate('validate_profile_in_identity', 'address', 'address',
                            address, data['address'])
                    return False
            if zipcode:
                if zipcode != str(data['zipCode']):
                    self._print_err_validate('validate_profile_in_identity', 'zipcode', 'zipCode',
                            zipcode, data['zipCode'])
                    return False
            if state:
                if state != data['userStatus']:
                    self._print_err_validate('validate_profile_in_identity', 'state', 'userStatus',
                            state, data['userStatus'])
                    return False
            if comment:
                if comment != data['data']:
                    self._print_err_validate('validate_profile_in_identity', 'comment', 'comment',
                            comment, data['data'])
                    return False
            if login_name:
                if login_name != data['loginName']:
                    self._print_err_validate('validate_profile_in_identity', 'login_name', 'loginName', 
                            login_name, data['loginName'])
                    return False
            if package_name:
                package_id = self._package_id(package_name=package_name) 
                if package_id != data['selectedPackage']:
                    self._print_err_validate('validate_profile_in_identity', 'package_id', 'selectedPackage',
                            package_id, data['selectedPackage'])
                    return False

            return True

        except Exception,e:
            print traceback.format_exc()
            return False


    def delete_profile_in_identity(self, login_name="profile_username"):
        """
        API used to delete Profile in Identity

        URI: DELETE /wsg/api/scg/identity/profiles/<profile_key>/<username>? 

        :param str login_name: Username
        :return: True if profile deleted else False
        :rtype: boolean
        """
        result = False
        try:
            key, data = self._get_profile_data_in_identity(login_name=login_name)
            del_url = ji.get_url(self.req_api_del_profile%(key, login_name), self.scg_mgmt_ip, self.scg_port)
            result = ji.delete_scg_data(del_url, self.jsessionid, None)

        except Exception,e:
            print traceback.format_exc()
            return False

        return result

    def create_guest_pass(self, login_name='Auto_guest',
                                    wlan_name='Auto_WLAN',
                                    domain_label='Administration Domain',
                                    apzone_name='Auto_APZone',
                                    multiple_guest='1',
                                    password_exp_unit='1',
                                    time_interval='DAY',
                                    auto_gen_password=True,
                                    pass_effect_since='0',
                                    max_device_limit='true',
                                    max_allowed_device='1',
                                    comment='GUEST PASS',
                                    req_guest_relogin='0'):
        """
        API used to create the Guest Pass

        URI: PUT /wsg/api/scg/identity/guestpass/generate/generate

        :param str login_name: Guest name
        :param str wlan_name: Name of WLAN to be used
        :param str domain_label: Name of the Domain
        :param str apzone_name: Name of AP Zone
        :param str multiple_guest: Number of multiple guests
        :param str password_expire_unit: Valid upto
        :param str time_interval: Days | Hours | Weeks
        :param boolean auto_gen_password: True | False
        :param str pass_effect_since: password effect since
        :param str max_device_limit: 'true' | 'false'
        :param str max_allowed_device: maximum number of allowed devices
        :param req_guest_relogin: request re-login for guest
        :return: True if Guest Pass created else False
        :rtype: boolean
        """
 
        result = False
        fwd_data = {}
        try:
            api = self.req_api_guest_pass
            url = ji.get_url(api, self.scg_mgmt_ip, self.scg_port)
            wlan_restrct = None
            wlan_apzone_label = '[' + wlan_name + ']' + ' ' + 'of' + ' ' + '[' + apzone_name + ']'
            get_wlan_api = '/wsg/api/scg/identity/guestpass/ssids/%s?'
            extr_api = 'type=&page=1&start=0&limit=45000&sort=[{%22property%22%3A%20%22_sort_value%22%2C%20%22direction%22%3A%20%22ASC%22}]'
            domain_uuid = self.get_domain_uuid(domain_label=domain_label) 

            wlan_url = ji.get_url(get_wlan_api%(domain_uuid)+ extr_api, self.scg_mgmt_ip, self.scg_port) 

            get_data = ji.get_json_data(wlan_url, self.jsessionid)
            for i in range(0, len(get_data['data']['list'])):
                if get_data['data']['list'][i]['label'] == wlan_apzone_label:
                    wlan_restrct = get_data['data']['list'][i]['key']
                    break

            if not wlan_restrct:
                print "create_guest_pass(): WLAN not found"
                return False

            fwd_data.update({"loginName":login_name,
                             "wlanRestriction":wlan_restrct,
                             "multipleGuest":int(multiple_guest),
                             "passwordExpirationUnit":int(password_exp_unit),
                             "timeInterval":time_interval,
                             "autoGeneratePassword":auto_gen_password,
                             "passEffectSince":pass_effect_since,
                             "maxDevLimit":max_device_limit,
                             "maxAllowedDeviceLimitNum":int(max_allowed_device),
                             "comment":comment,
                             "reqGuestRelogin":int(req_guest_relogin)})
            json_data = json.dumps(fwd_data)
            result = ji.put_json_data(url, self.jsessionid, json_data)
        except Exception, e:
            print traceback.format_exc()
            return False
        return result

    def create_guest_access(self, apzone_name='Auto_APZone', domain_label='Administration Domain',
                                guest_access_name='Auto_guest',
                                description=None, language='en_US',
                                start_page='user', start_url=None, sms_gateway_id=None,
                                tc_enabled=False, terms_and_condtn=None,
                                title=None, session_time='1440', grace_period='60',
                                logo_file=None):
        result = False
        guest_data={}
        try:
            url = ji.get_url(self.req_api_guest_access, self.scg_mgmt_ip, self.scg_port)
            guest_data = self.SJT.get_guest_access_template()
            guest_data.update({"name":guest_access_name,
                               "secondRedirect": start_page,
                               "description":description,
                               "language":language,
                               "smsGatewayId":sms_gateway_id,
                               "termsAndConditionsEnabled":tc_enabled,
                               "termsAndConditions":terms_and_condtn,
                               "title":title,
                               "sessionTime":session_time,
                               "gracePeriod":grace_period,
                               "zoneName":apzone_name})
            guest_data.update({"zoneUUID":self.get_apzone_uuid(apzone_name=apzone_name, domain_label=domain_label)})

            fwd_data = json.dumps(guest_data)
            result = ji.post_json_data(url, self.jsessionid, fwd_data)
        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def delete_guest_access_in_apzone(self, apzone_name='Auto_APZone', domain_label='Administration Domain',
            guest_access_name='Auto_Guest'):
        result = False
        try:
            del_api = '/wsg/api/scg/guestAccess/%s'
            key = self._get_guest_access_id(apzone_name=apzone_name, domain_label=domain_label, guest_access_name=guest_access_name)
            url = ji.get_url(del_api%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.delete_scg_data(url, self.jsessionid, None)
        except Exception, e:
            print traceback.format_exc()
            return False
        return result



    def logout(self):

        result = False
        try:

            logout_url = ji.get_url(self.req_api_logout, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(logout_url, self.jsessionid, None)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result
 
