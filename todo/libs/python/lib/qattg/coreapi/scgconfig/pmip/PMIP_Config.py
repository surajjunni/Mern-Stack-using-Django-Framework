import json
import traceback
from PMIP_Template import PMIP_Template
from qattg.coreapi.common.ScgJsonLogin import ScgJsonLogin
import qa.ttgcommon.coreapi.common.json_interface as ji


class PMIP_Config():

    def __init__(self, scg_mgmt_ip="127.0.0.2", scg_port="8443"):

        self.req_api_pmip='/wsg/api/scg/globalSettings/lma'
        self.req_api_lma='/wsg/api/scg/serviceProfiles/forwarding?'
        self.req_api_lma_validation='/wsg/api/scg/serviceProfiles/forwarding?type=PMIPv6'
        self.req_api_lma_updt_del='/wsg/api/scg/serviceProfiles/forwarding/%s'
        self.jsessionid=''
        self.SJT = PMIP_Template()
        self.scg_mgmt_ip = scg_mgmt_ip
        self.scg_port = scg_port

    def _login(self, username='admin', password='ruckus', **kwargs):

        l = ScgJsonLogin()
        result, self.jsessionid = l.login(scg_mgmt_ip=self.scg_mgmt_ip, scg_port=self.scg_port,
                username=username, password=password)

        return result

    def set_jsessionid(self, jsessionid=''):
        self.jsessionid = jsessionid 

    def create_pmipv6_service_profile(self,
            pmipv6_name="Auto_PMIPv6_Profile",
            description='Automation PMIPv6',
            lma_primary_ip="1.1.1.1",
            lma_secondary_ip="2.2.2.2",
            mnid_type="NAI_From_Authentication",
            mac48_type=None,
            lma_apn="ruckus.com",
             mac48_hex_delimiter="No"):
        """ 
        Creates the PMIPv6 service profile
        
        URI: POST /wsg/api/scg/serviceProfiles/forwarding?

        :param str pmipv6_name: PMIPv6 Profile Name
        :param str lma_primary_ip: Primary IP Address of LMA
        :param str lma_secondary_ip: Secondary IP Address of LMA
        :param str mnid_type: NAI_From_Authentication | MAC48_At_APN 
        :param mac48_type: Decimal | Hexadecimal
        :param lma_apn: APN name 
        :return: True if PMIPv6 created else False
        :rtype: boolean
        """
        
        lma_profile = {}
        result=False
        try:
            url = ji.get_url(self.req_api_lma,self.scg_mgmt_ip,self.scg_port)
            lma_profile.update(self.SJT.get_lma_template_data())

            lma_profile.update({"name":pmipv6_name,
                                "description":description,
                                "lmaPrimaryIp":lma_primary_ip,
                                "lmaSecondaryIp":lma_secondary_ip,
                                "mnIdType":mnid_type,
                                "apn":lma_apn})

            if lma_profile["mnIdType"] == "MAC48_At_APN":
                lma_profile.update({"mac48Type":mac48_type})
                if lma_profile["mac48Type"] == "Hexadecimal":
                    lma_profile.update({"delimiter":mac48_hex_delimiter})
            
            

            data_json = json.dumps(lma_profile)
            result = ji.post_json_data(url, self.jsessionid, data_json)

        except Exception,e:
            print traceback.format_exc()
	    return False

        return result


    def update_pmipv6_service_profile(self,
            pmipv6_profile_name="LMA Profile",
            new_pmipv6_profile_name=None,
            description=None,
            lma_primary_ip=None,
            lma_secondary_ip=None,
            mnid_type=None,
            mac48_type=None,
            lma_apn=None,
            mac48_hex_delimiter="No"):

        """ 
        Update the PMIP profile with given parameters
        
        URI: PUT /wsg/api/scg/serviceProfiles/forwarding/<>

        :param str pmipv6_name: PMIPv6 Profile Name
        :param str lma_primary_ip: Primary IP Address of LMA
        :param str lma_secondary_ip: Secondary IP Address of LMA
        :param str mnid_type: NAI_From_Authentication | MAC48_At_APN 
        :param mac48_type: Decimal | Hexadecimal
        :param lma_apn: APN name 
        :return: True if PMIPv6 Updated else False
        :rtype: boolean

        """

        key, data = None, None
        lma_update = {}
        result=False
        try:
            url = ji.get_url(self.req_api_lma_validation, self.scg_mgmt_ip,self.scg_port)
            key, rcv_data = self._get_key_for_pmipv6_service(url=url, name=pmipv6_profile_name)
            lma_update["key"]=rcv_data["key"]
            lma_update["tenantId"]=rcv_data["tenantId"]
            lma_update["profileType"]=rcv_data["profileType"]

            lma_update["name"] = rcv_data["name"] if not new_pmipv6_profile_name else new_pmipv6_profile_name
            lma_update["description"]=rcv_data["description"] if not description else description
            lma_update["lmaPrimaryIp"]=rcv_data["lmaPrimaryIp"] if not lma_primary_ip else lma_primary_ip

            lma_update["lmaSecondaryIp"]=rcv_data["lmaSecondaryIp"] if not lma_secondary_ip else lma_secondary_ip
            
            lma_update["apn"]=rcv_data["apn"] if not lma_apn else lma_apn

            lma_update["mnIdType"]=rcv_data["mnIdType"] if not mnid_type else mnid_type
            if lma_update["mnIdType"] == "MAC48_At_APN":
                lma_update["mac48Type"]=rcv_data["mac48Type"] if not mac48_type else mac48_type
                if lma_update["mac48Type"] == "Hexadecimal":
                    lma_update["delimiter"]=rcv_data["delimiter"] if not mac48_hex_delimiter else mac48_hex_delimiter
            else:
                lma_update["mac48Type"] = None
             
            
            json_data = json.dumps(lma_update)
            url_lma_update = ji.get_url(self.req_api_lma_updt_del%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(url_lma_update, self.jsessionid, json_data)

        except Exception,e:
            print traceback.format_exc()
            return False

        return result

    def _get_key_for_pmipv6_service(self, url=None, name="LMA_service"):
        """ 
        Return the Key for given LMA Name
        """
        key, data = None, None

        rcv_data = ji.get_json_data(url, self.jsessionid)
        for i in range(0, len(rcv_data["data"]["list"])):
            if rcv_data["data"]["list"][i]["name"] == name:
                key, data = rcv_data["data"]["list"][i]["key"], rcv_data["data"]["list"][i]
                break

        if not key:
            raise Exception("_get_key_for_pmipv6_service():Key not found for the name: %s" % (name))

        return key, data


    def validate_pmipv6_service_profile(self,
            pmipv6_profile_name=None,
            description=None,
            lma_primary_ip=None,
            lma_secondary_ip=None,
            mnid_type=None,
            mac48_type=None,
            lma_apn=None,
            mac48_hex_delimiter=None):
        """ 
        Validate the PMIP profile with given parameters
        """

        try:
            url = ji.get_url(self.req_api_lma_validation, self.scg_mgmt_ip,self.scg_port)
            key, rcv_data = self._get_key_for_pmipv6_service(url=url, name=pmipv6_profile_name)
            
            if pmipv6_profile_name:
                if rcv_data["name"] != pmipv6_profile_name:
                    self._print_err_validate('validate_pmipv6_service_profile_service', 'pmipv6_profile_name', 'name',
                            pmipv6_profile_name, rcv_data["name"])
                    return False
            if description:
                if rcv_data["description"] != description:
                    self._print_err_validate('validate_pmipv6_service_profile_service', 'lma_description', 'description',
                            description, rcv_data["description"])
                    return False
            if lma_primary_ip:
                if rcv_data["lmaPrimaryIp"] != lma_primary_ip:
                    self._print_err_validate('validate_pmipv6_service_profile_service', 'lma_primary_ip', 'lmaPrimaryIp',
                            lma_primary_ip, rcv_data["lmaPrimaryIp"])
                    return False
            if lma_secondary_ip:
                if rcv_data["lmaSecondaryIp"] != lma_secondary_ip:
                    self._print_err_validate('validate_pmipv6_service_profile_service', 'lma_secondary_ip', 'lmaSecondaryIp',
                            lma_secondary_ip, rcv_data["lmaSecondaryIp"])
                    return False
            if rcv_data["mnIdType"] != mnid_type:
                self._print_err_validate('validate_pmipv6_service_profile_service', 'mnid_type', 'mnIdType',
                        mnid_type, rcv_data["mnIdType"])
                return False
            
            if rcv_data["apn"] != lma_apn:
                    self._print_err_validate('validate_pmipv6_service_profile_service', 'lma_apn', 'apn',
                            lma_apn, rcv_data["apn"])
                    return False
            
            if rcv_data["mnIdType"] == "MAC48_At_APN":
                if rcv_data["mac48Type"] != mac48_type:
                    self._print_err_validate('validate_pmipv6_service_profile_service', 'mac48_type', 'mac48Type',
                            mac48_type, rcv_data["mac48Type"])
                    return False
            if mac48_hex_delimiter and rcv_data["mnIdType"] == "MAC48_At_APN":    
                if rcv_data["mac48Type"] == mac48_type:
                    if rcv_data["delimiter"] != mac48_hex_delimiter:
                        self._print_err_validate('validate_pmipv6_service_profile_service', 'mac48_hex_delimiter', 'delimiter',
                                mac48_hex_delimiter, rcv_data["delimiter"])
                        return False
                
            return True
        except Exception,e:
            print traceback.format_exc()
            return False
    

    def delete_pmipv6_service_profile(self, pmipv6_profile_name="LMA service"):
        """ 
        Delete the PMIP profile with given LMA Name 
        """
        result = False
        try:
            url = ji.get_url(self.req_api_lma_validation, self.scg_mgmt_ip,self.scg_port)
            key, rcv_data = self._get_key_for_pmipv6_service(url=url, name=pmipv6_profile_name)
            del_lma_url = ji.get_url(self.req_api_lma_updt_del % key, self.scg_mgmt_ip, self.scg_port)
            result = ji.delete_scg_data(del_lma_url, self.jsessionid, None)
        except Exception, e:
            print traceback.format_exc()
            return False
        return result

    def update_global_lma_mag(self,lma_key="pmipv6GlobalSetting",
                                lma_keepalive_interval=None,
                                lma_keepalive_retry=None,
                                binding_refreshtime=None):
        """ 
        Update MAG Global Value with given parameter 
        """
        pmip_profile = data_pmip = {}
        try:

            url = ji.get_url(self.req_api_pmip,self.scg_mgmt_ip,self.scg_port)
            recv_data_pmip=ji.get_json_data(url,self.jsessionid)
            data_pmip = recv_data_pmip["data"]
            pmip_profile.update(self.SJT.get_global_lma_mag_template_data())

            pmip_profile["key"]=pmip_profile["key"] if not data_pmip["key"] else data_pmip["key"]
            pmip_profile["key"]=pmip_profile["key"] if not lma_key else lma_key
            pmip_profile["lmaKeepAliveInterval"]=pmip_profile["lmaKeepAliveInterval"] if not data_pmip["lmaKeepAliveInterval"] else \
                        data_pmip["lmaKeepAliveInterval"]
            pmip_profile["lmaKeepAliveInterval"]=pmip_profile["lmaKeepAliveInterval"] if not lma_keepalive_interval else lma_keepalive_interval
            pmip_profile["lmaKeepAliveRetry"]=pmip_profile["lmaKeepAliveRetry"] if not data_pmip["lmaKeepAliveRetry"] else data_pmip["lmaKeepAliveRetry"]
            pmip_profile["lmaKeepAliveRetry"]=pmip_profile["lmaKeepAliveRetry"] if not lma_keepalive_retry else lma_keepalive_retry
            pmip_profile["bindingRefreshTime"]=pmip_profile["bindingRefreshTime"] if not data_pmip["bindingRefreshTime"] else \
                        data_pmip["bindingRefreshTime"]
            pmip_profile["bindingRefreshTime"]=pmip_profile["bindingRefreshTime"] if not binding_refreshtime else binding_refreshtime

            data_json = json.dumps(pmip_profile)
            result=ji.put_json_data(url,self.jsessionid,data_json)

        except Exception,e:
            print traceback.format_exc()
            return False

        return result


    def validate_global_lma_mag(self,
            lma_keepalive_interval=None,
            lma_keepalive_retry=None,
            binding_refreshtime=None):
        """ 
        Valdate MAG Global Value with given parameter 
        """

        url = ji.get_url(self.req_api_pmip,self.scg_mgmt_ip,self.scg_port)
        recv_data_pmip=ji.get_json_data(url,self.jsessionid)
        data_pmip = recv_data_pmip["data"]
        try:
            if lma_keepalive_interval:
                if int(data_pmip["lmaKeepAliveInterval"]) != int(lma_keepalive_interval):
                    self._print_err_validate('validate_mag_timer', 'lma_keepalive_interval', 'lmaKeepAliveInterval', 
                            lma_keepalive_interval, data_pmip["lmaKeepAliveInterval"])
                    return False
            if lma_keepalive_retry:
                if int(data_pmip["lmaKeepAliveRetry"]) != int(lma_keepalive_retry):
                    self._print_err_validate('validate_mag_timer', 'lma_keepalive_retry', 'lmaKeepAliveRetry',
                        lma_keepalive_retry, data_pmip["lmaKeepAliveRetry"])
                    return False
            if binding_refreshtime:
                if int(data_pmip["bindingRefreshTime"]) != int(binding_refreshtime):
                    self._print_err_validate('validate_mag_timer', 'binding_refreshtime', 'bindingRefreshTime',
                            binding_refreshtime, data_pmip["bindingRefreshTime"])
                    return False
            return True
        except Exception,e:
            print traceback.format_exc()
            return False

    def _print_err_validate(self, fname, xvar, yvar, x, y):
        print "%s:: userdata:%s[%s] != serverdata:%s[%s]" % (fname, xvar, x, yvar, y)

