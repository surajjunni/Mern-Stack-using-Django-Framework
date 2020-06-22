import json
import traceback
import time

from qattg.coreapi.common.ScgJsonLogin import ScgJsonLogin
from qattg.coreapi.scgconfig.ScgJsonConfig import ScgJsonConfig
from qattg.coreapi.common.ScgJsonAdminAppStatus import ScgJsonAdminAppStatus
import qa.ttgcommon.coreapi.common.json_interface as ji
from ScgJsonSyslogTemplate import ScgJsonSyslogTemplate

class ScgJsonSyslog():
    def __init__(self, scg_mgmt_ip="127.0.0.2", scg_port="8443"):

        self.scg_mgmt_ip = scg_mgmt_ip
        self.scg_port = scg_port
        self.jsessionid = ''
        self.req_api_syslog = '/wsg/api/scg/globalSettings/system/remoteSyslogSettings'
        self.req_api_update_ap='/wsg/api/scg/aps/%s/config'
        self.req_api_app_log_level='/wsg/api/scg/diagnostics/applications'
        self.sjst = ScgJsonSyslogTemplate()
        self.SJC = ScgJsonConfig(scg_mgmt_ip=scg_mgmt_ip, scg_port=scg_port)
        self.SJAAS = ScgJsonAdminAppStatus(scg_mgmt_ip=scg_mgmt_ip, scg_port=scg_port)

    def _login(self, username='admin', password='ruckus', **kwargs):
        l = ScgJsonLogin()
        result, self.jsessionid = l.login(scg_mgmt_ip=self.scg_mgmt_ip, scg_port=self.scg_port,username=username, password=password)
        self.SJC.jsessionid = self.jsessionid
        self.SJAAS.jsessionid = self.jsessionid
        return result

    def set_jsessionid(self, jsessionid):
        self.jsessionid = jsessionid
        self.SJC.jsessionid = jsessionid
        self.SJAAS.jsessionid = jsessionid

#to get application status#
    def set_app_log_level(self, scg_host_name='hostname',app_config_name='appConfigName',log_root_level='logRootLevel'):
        """
        
        Set app log level 
                
        :param str scg_host_name: SCG HOST NAME
        
        :param str app_config_name: API | CaptivePortal | Cassandra | ... | Configurer | ... |Web
        
        :param str log_root_level: ERROR | WARN | INFO | DEBUG
        
        :return: True: if app log level updated 
        
        :rtype: boolean
        
        """
        cblade_label = scg_host_name + '-C' 
        try:
            app_status = self.SJAAS.get_app_status(cblade_label)

            for item in app_status:
                if str(item['appConfigName'])==app_config_name:
                    item['logRootLevel']=log_root_level
                    break
            data_json = json.dumps(item)
            url = ji.get_url(self.req_api_app_log_level, self.scg_mgmt_ip, self.scg_port)
            status = ji.put_json_data(url, self.jsessionid, data_json)    
            
            return status
        except Exception, e:
            print traceback.format_exc()
            return False


    def verify_syslog_event_filter(self,event_filter = "1"):
        """
        
        Verify Syslog Event Filter 
                
        :param str event_filter: 0|1|2 - Default: 1
        
        :return: True: if event checked initially 
        
        :rtype: boolean
        
        """
        url = ji.get_url(self.req_api_syslog,self.scg_mgmt_ip, self.scg_port)
        response_data = ji.get_json_data(url, self.jsessionid)

        if response_data['data']['event_syslog_enable'] == 'true':
            return None

        return response_data['data']['forwardUEEventsType'] == event_filter 
     
    def verify_syslog_facility(self,enable='false', facility="LOCAL0", facility_type=''):
        """
        
        Verify Syslog Facility
        
        :param str facility: LOCAL0|LOCAL1|...|LOCAL7 - Default: LOCAL0
        
        :return: True: if facility is selected
        
        :rtype: boolean  
        
        """
        
        url = ji.get_url(self.req_api_syslog, self.scg_mgmt_ip, self.scg_port)
        response_data = ji.get_json_data(url, self.jsessionid)
        
        if response_data['data']['enable'] != enable:
            return None
        
        if facility_type == "appfacility":
            return response_data["data"]["applog_syslog_facility"] == facility
        elif facility_type == "auditfacility":
            return response_data["data"]["audit_syslog_facility"] == facility
        else:
            return response_data["data"]["event_syslog_facility"] == facility
                                        
    
    def set_syslog_setting(self, enable=True, syslog_host="127.0.0.1", syslog_port=514, event_filter="1",event_syslog_severity="", syslog_facility="LOCAL0", admin_active_log_facility='', app_log_facility='', **priority):
        """
        
        Set Syslog Settings
        
        :param boolean enable: True|False (Default : True)
        
        :param str syslog_host: Syslog server ip address
        
        :param int syslog_port: Syslog server port number (Default : 514)
        
        :param str event_filter: 0|1|2
        
        :param str event_syslog_severity: Critical|Major|Minor|Warning|Informational|Debug
        
        :param str syslog_facility: LOCAL0|LOCAL1|...|LOCAL7
        
        :param str admin_active_log_facility: LOCAL0|LOCAL1|...|LOCAL7
        
        :param str app_log_facility: LOCAL0|LOCAL1|...|LOCAL7
        
        :param Dictionary priority: severity and priority as key value pair 
        
        :return: True: if Syslog server created
        
        :rtype: boolean
        
        """
        try:
            data={}
            enable=str(enable).lower()
            
            if enable:
                data =  self.sjst.get_syslog_template_data()          
                data["enable"] = enable
                data["host"] = syslog_host
                data["port"] = syslog_port
                data["forwardUEEventsType"] = event_filter
                if event_filter == "2":
                    if event_syslog_severity :
                        data["event_syslog_severity"]=event_syslog_severity
                    else:
                        return False
                    
                    
                data["event_syslog_facility"] = syslog_facility
                data["audit_syslog_facility"] = syslog_facility if admin_active_log_facility == '' else admin_active_log_facility
                data["applog_syslog_facility"] = syslog_facility if app_log_facility =='' else app_log_facility
                
                if priority:
                    for item in priority.keys():
                        data["severityPriorityMapping"][item]=priority[item]
                        
                pri_str = ",".join("\"{0}\":\"{1}\"".format(key,val) for key, val in sorted(data["severityPriorityMapping"].items()))            
                data["severityPriorityMapping"]="{" + pri_str + "}"
            else:
                data["enable"] = enable
            data_json = json.dumps(data)
            syslog_facility_check=0
            status = False
            while syslog_facility_check <5:
                url = ji.get_url(self.req_api_syslog, self.scg_mgmt_ip, self.scg_port)
                status = ji.put_json_data(url, self.jsessionid, data_json)
                if status:
                    time.sleep(5)
                    print "Checking syslog facility %s/5"%(syslog_facility_check)
                    facility_status = self.verify_syslog_facility(enable=enable, facility=syslog_facility)
                    if facility_status:
                       break
                syslog_facility_check += 1 
            return status
        
        except Exception, e:
            print traceback.format_exc()
            return False

    def verify_apzone_syslog_facility(self, zone_name="Syslog-Test", facility="-1", domain_label='Administration Domain'):
        """
        
        Verify AP Zone Syslog Facility
        
        :param str zone_name: AP Zone name
        
        :param str facility: -1|16|17|18|19|20|21|22|23 (default : -1)
        
        :param str domain_label: APZone Domain name
        
        :return: True: if facility is selected
        
        :rtype: boolean  
        
        """
        
        try:
            req_zone_url = ji.get_url(self.SJC.req_api_update_zoneprofile%self.SJC.get_apzone_uuid(apzone_name=zone_name, 
                                                              domain_label=domain_label), self.scg_mgmt_ip, self.scg_port)
            zone_profile_data = ji.get_json_data(req_zone_url, self.jsessionid)
            zone_profile = zone_profile_data["data"]
            if zone_profile["commonConfig"]["syslogFacility"] == int(facility):
                return True
            return False
        
        except Exception, e:
            print traceback.format_exc()
            return False
    
    def set_apzone_syslog_setting(self, zone_name="Syslog-Test", domain_label='Administration Domain', syslogIp="", syslogPort="514", syslogFacility="-1", syslogRLevel="3"):
        """
        
        Set Ap zone syslog setting
        
        :param str zone_name: AP zone name
        
        :param str domain_label: APZone Domain name
        
        :param str syslogIp: Syslog server ip address
        
        :param str syslogPort: Syslog server port
        
        :param str syslogFacility: -1|16|17|18|19|20|21|22|23 (default : -1)
        
        :param str syslogRLevel: 0|1|..|7 (default : 3)
        
        """
        result = False
        try:
            req_zone_url = ji.get_url(self.SJC.req_api_update_zoneprofile%self.SJC.get_apzone_uuid(apzone_name=zone_name, 
                                                              domain_label=domain_label), self.scg_mgmt_ip, self.scg_port)
            zone_profile_data = ji.get_json_data(req_zone_url, self.jsessionid)
            zone_profile = zone_profile_data["data"]
            zone_profile["commonConfig"]["syslogIp"] = syslogIp
            zone_profile["commonConfig"]["syslogPort"] = syslogPort
            zone_profile["commonConfig"]["syslogFacility"] = int(syslogFacility)
            zone_profile["commonConfig"]["syslogRLevel"] = int(syslogRLevel)

            json_data = json.dumps(zone_profile)
            result = ji.put_json_data(req_zone_url, self.jsessionid, json_data)
            
        except Exception, e:
            print traceback.format_exc()
            return False
        return result

    def cluster_backup(self):

        recvd_data = None
        validate_data = None
        self.json_url = "/wsg/api/scg/backup/cluster"
        self.validate_status = "/wsg/api/scg/patches/upgrade/status"

        try:
            data = ''
            url = ji.get_url(self.json_url, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.post_json_data(url, self.jsessionid, data)
            #recvd_data=True
            if not recvd_data:
                return None
            else:
                while True:
                    validate_url = ji.get_url(self.validate_status, self.scg_mgmt_ip, self.scg_port)
                    validate_data = ji.get_json_data(validate_url, self.jsessionid)
                    if "data" in validate_data.keys():
                        if validate_data["data"]["previousOperationRecord"]["success"] == True:
                            return True
                    print "Backup operation is in progress. Sleeping for 30 sec..."
                    time.sleep(30)
        except Exception, e:
            #print "COMING INSIDE EXCEPTION"
            print traceback.format_exc()
            return None
        
    def verify_access_point_syslog_facility(self, ap_mac="", facility="-1"):
        """
        
        Verify Access Point Syslog Facility
        
        :param str ap_mac: AP mac
        
        :param str facility: -1|16|17|18|19|20|21|22|23 (default : -1)
        
        :return: True: if facility is selected
        
        :rtype: boolean  
        
        """
        try:
            req_ap_url = ji.get_url(self.req_api_update_ap % ap_mac, self.scg_mgmt_ip, self.scg_port)
            ap_profile_data = ji.get_json_data(req_ap_url, self.jsessionid)
            ap_profile = ap_profile_data["data"]
            print type(ap_profile["config"]["syslogFacility"])
            if ap_profile["config"]["syslogFacility"] == int(facility):
                return True
            return False
        
        except Exception, e:
            print traceback.format_exc()
            return False

    def set_access_point_syslog_setting(self,  ap_mac="", syslogIp="", syslogPort="514", syslogFacility="-1", syslogRLevel="3"):
        """
        
        Set Ap syslog setting
        
        :param str ap_mac: AP Mac
        
        :param str syslogIp: Syslog server ip address
        
        :param str syslogPort: Syslog server port
        
        :param str syslogFacility: -1|16|17|18|19|20|21|22|23 (default : -1)
        
        :param str syslogRLevel: 0|1|..|7 (default : 3)
        
        """
        result = False
        ap_profile = {}
        try:
            req_ap_url = ji.get_url(self.req_api_update_ap % ap_mac, self.scg_mgmt_ip, self.scg_port)
            ap_profile_data = ji.get_json_data(req_ap_url, self.jsessionid)
            
            ap_profile["mac"] = ap_profile_data["data"]["mac"]
            ap_profile["description"] = ap_profile_data["data"]["description"]
            ap_profile["fwVersion"] = ap_profile_data["data"]["fwVersion"]
            ap_profile["model"] = ap_profile_data["data"]["model"]
            ap_profile["mobilityZoneUUID"] = ap_profile_data["data"]["mobilityZoneUUID"]
            ap_profile["clientAdmissionConfig"] = ap_profile_data["data"]["clientAdmissionConfig"]
            ap_profile["config"] = ap_profile_data["data"]["config"]

            if syslogIp:
                ap_profile["config"]["syslogIp"] = syslogIp
                ap_profile["config"]["syslogPort"] = int(syslogPort)
                ap_profile["config"]["syslogFacility"] = int(syslogFacility)
                ap_profile["config"]["syslogRLevel"] = int(syslogRLevel)
            else:
                for conf in ("syslogIp","syslogPort","syslogFacility","syslogRLevel"):
                    if ap_profile["config"].has_key(conf):
                        del ap_profile["config"][conf]

            json_data = json.dumps(ap_profile)
            print json_data
            result = ji.put_json_data(req_ap_url, self.jsessionid, json_data)
            
        except Exception, e:
            print traceback.format_exc()
            return False
        return result       
"""  
if __name__ == '__main__':   
    syslog_obj = ScgJsonSyslog('172.19.16.180')
    syslog_obj._login('admin','ruckus1!')
    #print syslog_obj.set_syslog_setting("172.19.7.165")
    #print syslog_obj.reset_syslog_setting()
    #print syslog_obj.verify_apzone_syslog_facility(ap_zone_name="AP Zone for Syslog")
    #print syslog_obj.verify_syslog_event_filter()
    print syslog_obj.set_app_log_level(scg_host_name='SCG', app_config_name='Web', log_root_level='INFO')
    
"""

