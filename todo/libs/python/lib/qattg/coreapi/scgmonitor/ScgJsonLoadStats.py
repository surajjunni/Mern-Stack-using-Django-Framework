import json
import copy
import traceback
import qa.ttgcommon.coreapi.common.json_interface as ji

class ScgJsonLoadStats():

    def __init__(self):
        self.jsessionid = None
        self.GTP_C_API='/wsg/api/scg/diagnostics/stats/ggsn/gtpc?&criteria=&start=0&limit=20&maxTotalCount=4500'
        self.RAD_PROXY='/wsg/api/scg/diagnostics/stats/radius/proxy?&criteria=&page=1&start=0&limit=20'
        self.LIC_UE_API = '/wsg/api/scg/globalSettings/license?'
        self.GRE_TUN_COUNT = '/wsg/api/scg/planes/data?&criteria=&page=1&start=0&limit=2147483647'
	self.NODE_AF_API='/wsg/api/scg/nodeaffinity/'
	self.NAF_PROFILE='/wsg/api/scg/nodeaffinity/profile/?&criteria=&page=1&start=0&limit=2147483647'
        self.FTP_API='/wsg/api/scg/ftpservice'
        self.GET_FTP_API='/wsg/api/scg/ftpservice?&page=1&start=0&limit=45000'
        self.GET_BLADE_ID='/wsg/api/scg/planes/control/ids?&page=1&start=0&limit=45000'
        self.SAVE_REPORT='/wsg/api/scg/reports'
        self.req_api_domains = '/wsg/api/scg/session/currentUser/domainList?includeSelf=true'
        self.req_ap_zone_api = '/wsg/api/scg/domains/'
        self.req_api_apzones = '/wsg/api/scg/zones/byDomain/%s'
        pass

    def login_scgc(self, scg_mgmt_ip='127.0.0.2', scg_port='8443',
            username='admin', password='ruckus', **kwargs):
        """
        Login to SCG-C GUI with given username and password
        """

        req_api_login = "/wsg/api/scg/session/login"
        req_api_login_validation = '/wsg/api/scg/session/validation?'

        data = { "userName":"", "password":"",}

        data['userName'] = username
        data['password'] = password
        url = ji.get_url(req_api_login, scg_mgmt_ip, scg_port)
        data_json = json.dumps(data)
        jsessionid = ''

        try:
            jsessionid = ji.get_jsessionid(dict(req_uri=req_api_login_validation,
                                                      scg_mgmt_ip=scg_mgmt_ip,
                                                      scg_port=scg_port,
                                                      proto='https'))

            result, jsessionid = ji.put_json_data(url, jsessionid, data_json, login=True)
        except Exception:
            print traceback.format_exc()
            return False, None

        self.jsessionid = jsessionid
        self.scg_mgmt_ip = scg_mgmt_ip
        self.scg_port = scg_port
        return result, jsessionid

    def enable_node_afinity(self,nafp_name="",zone_name="",no_of_zone=10):

        url=ji.get_url(self.NODE_AF_API,self.scg_mgmt_ip,self.scg_port)
    
     	naf_key  = self.get_nodeprofile(naf_p_name=nafp_name)
        data = {"enable":True,
		"numOfRetries":3,
		"zoneIdToNAPIdMap":{}
               }
        new_zone = {}
        for i in range(1,int(no_of_zone) + 1):
            zone_key = self.get_apzone_uuid(apzone_name=zone_name + "_" +  str(i))
	    tmp_zone = {zone_key:naf_key}
            new_zone.update(tmp_zone)
            print new_zone

        data["zoneIdToNAPIdMap"] = copy.deepcopy(new_zone)
        data_json = json.dumps(data)
        print data_json

        try: 
            result = ji.put_json_data(url,self.jsessionid, data_json)
        except Exception:
            print traceback.format_exc()
            return False, None

    def disable_node_afinity(self):

        url=ji.get_url(self.NODE_AF_API,self.scg_mgmt_ip,self.scg_port)
    
        data = {"enable":False,"numOfRetries":3,"zoneIdToNAPIdMap":{}}
        data_json = json.dumps(data)

        try: 
            result = ji.put_json_data(url,self.jsessionid, data_json)
        except Exception:
            print traceback.format_exc()
            return False, None

    def get_nodeprofile(self, naf_p_name):

        url=ji.get_url(self.NAF_PROFILE,self.scg_mgmt_ip,self.scg_port)
        naf_profile_data = ji.get_json_data(url,self.jsessionid)

        for naf_p in naf_profile_data["data"]["list"]:
            if naf_p_name == naf_p["name"]:
                nafp_key = naf_p["key"]

        print nafp_key
        return nafp_key

    def get_jsessionid(self):
        return self.jsessionid 

    def get_gre_tun_count(self):

        url=ji.get_url(self.GRE_TUN_COUNT,self.scg_mgmt_ip,self.scg_port)
        dblade_data = ji.get_json_data(url,self.jsessionid)
        total_gre_tun_count = 0

	print dblade_data

        for dblade in dblade_data["data"]["list"]:
            total_gre_tun_count = total_gre_tun_count + int(dblade["greTunnels"])
          
        print total_gre_tun_count

        return total_gre_tun_count

    def get_initial_ggsn_stats(self,ggsn_ip):
 
        #self._build_params(stats_param=stats_param)
        url=ji.get_url(self.GTP_C_API,self.scg_mgmt_ip,self.scg_port)
        stats_data = ji.get_json_data(url,self.jsessionid)

        for _sdata in stats_data["data"]["list"]:
            if ggsn_ip == _sdata["ggsnIp"]:
                no_of_act_pdp = _sdata["numActPdp"]

        print no_of_act_pdp

    def get_initial_radius_stats(self,radius_ip,scg_c_name):
 
        url=ji.get_url(self.RAD_PROXY,self.scg_mgmt_ip,self.scg_port)
        stats_data = ji.get_json_data(url,self.jsessionid)


        for _sdata in stats_data["data"]["list"]:
            if radius_ip == _sdata["aaaIp"]:
                if scg_c_name == _sdata["cBladeName"]:
                    no_of_acct_req_sent = _sdata["numAccRqSntAaa"]


        return no_of_acct_req_sent

    def get_rad_stats(self,radius_ip,scg_c_name, initial_stats):

        url=ji.get_url(self.RAD_PROXY,self.scg_mgmt_ip,self.scg_port)
        stats_data = ji.get_json_data(url,self.jsessionid)

        for _sdata in stats_data["data"]["list"]:
            if radius_ip == _sdata["aaaIp"]:
                if scg_c_name == _sdata["cBladeName"]:
                    no_of_acct_req_sent = _sdata["numAccRqSntAaa"]

        if initial_stats == no_of_acct_req_sent:
            raise Exception("No accounting requests sent to AAA")

        rad_stats =  int(no_of_acct_req_sent) - int(initial_stats)

        return rad_stats

    def get_license_count(self):

        url = ji.get_url(self.LIC_UE_API,self.scg_mgmt_ip,self.scg_port)
        lic_data = ji.get_json_data(url,self.jsessionid)
        for licd in lic_data["data"]["licenseUsageList"]:
            if licd["type"] == "UE":
                ue_lic_consumed = licd["usedCount"]


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

    def create_ftp(self,ftp_ip="",ftp_username="",ftp_password="",ftp_directory=""):

        url = ji.get_url(self.FTP_API, self.scg_mgmt_ip, self.scg_port)
        data = {"key":"","ftpName":"auto_sp","ftpProtocol":"FTP",
	"ftpHost":ftp_ip,"ftpPort":"21",
	"ftpUserName":ftp_username,"ftpPassword":ftp_password,
	"ftpRemoteDirectory":ftp_directory
	}

        data_json = json.dumps(data)
        try: 
            result = ji.post_json_data(url,self.jsessionid, data_json)
        except Exception:
            print traceback.format_exc()
            return False, None

        return True

    def get_ftp(self,ftp_name):

        url = ji.get_url(self.GET_FTP_API,self.scg_mgmt_ip,self.scg_port)
        _data = ji.get_json_data(url,self.jsessionid)
        for ftp in _data["data"]["list"]:
            if ftp["ftpName"] == ftp_name:
                ftp_key = ftp["key"]

        return  ftp_key

    def get_cblade_id(self, cblade_name):

        url = ji.get_url(self.GET_BLADE_ID,self.scg_mgmt_ip,self.scg_port)
        _data = ji.get_json_data(url,self.jsessionid)
        for blade in _data["data"]["list"]:
            if blade["label"] == cblade_name + "-C":
                _key = blade["bladeUUID"]

        return  _key

    def create_save_report(self, ftp_name="", leader_name="", follower_name=""):

        url = ji.get_url(self.SAVE_REPORT,self.scg_mgmt_ip,self.scg_port)
        data = {"title":"auto_sp_report",
	"description":"",
	"reportType":"Active TTG Sessions",
	"domainUUID":self.get_domain_uuid(),
	"pdfFormat":True,"csvFormat":True,
	"timeFilter":{"interval":"FIFTEEN_MIN","timeUtil":"HOURS","timeSpan":8},
	"deviceFilter":{"resourceType":"PLANE",
		"resourceEntity":[{"label":leader_name + "-C","value":self.get_cblade_id(leader_name)},
			{"label":follower_name + "-C","value":self.get_cblade_id(follower_name)}]},
	"scheduleEnable":True,
	"schedules":[{"interval":"DAILY"}],"notificationEnable":False,"notifiedMailList":[],"ftpEnable":"true",
	"ftpServer":{"key":self.get_ftp(ftp_name)}
	}
        data_json = json.dumps(data)

        try: 
            result = ji.post_json_data(url,self.jsessionid, data_json)
        except Exception:
            print traceback.format_exc()
            return False, None


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

if __name__ == '__main__':

     sl = ScgJsonLoadStats()
     sl.login_scgc(scg_mgmt_ip='10.1.228.11', scg_port='8443',
            username='admin', password='ruckus1!')
     #sl.get_gre_tun_count()
     #sl.disable_node_afinity()
     #naf_key  = sl.get_nodeprofile(naf_p_name="tom")
     #sl.get_initial_radius_stats(radius_ip="10.1.226.33", scg_c_name="Spike-11-C")
     #zone_id = sl.get_apzone_uuid(apzone_name='P1_ZONE_1', domain_label='Administration Domain')
     #sl.enable_node_afinity(nafp_name="tom",zone_name="P1_ZONE",no_of_zone=2)
     sl.create_save_report(ftp_name="auto_sp", leader_name="Spike-11", follower_name="Spike-12")
