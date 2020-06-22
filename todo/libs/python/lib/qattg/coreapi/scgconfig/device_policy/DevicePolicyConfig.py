import json
import copy
import traceback
from qattg.coreapi.common.ScgJsonLogin import ScgJsonLogin
import qa.ttgcommon.coreapi.common.json_interface as ji
from DevicePolicyTemplate import DevicePolicyTemplate

class DevicePolicyConfig():

    def __init__(self, scg_mgmt_ip="127.0.0.2", scg_port="8443"):
        self.req_api_domains = '/wsg/api/scg/session/currentUser/domainList?includeSelf=true'
        self.req_api_get_tenatuuid = '/wsg/api/scg/session/currentUser?'
        self.req_api_apzones = '/wsg/api/scg/zones/byDomain/%s'
        self.api_create_devicepolicy = '/wsg/api/scg/devicepolicy'
        self.api_delete_devicepolicy = '/wsg/api/scg/devicepolicy/%s'
        self.api_add_rule_get = '/wsg/api/scg/devicepolicy/byzone/%s'
        self.api_add_rule_put = '/wsg/api/scg/devicepolicy/%s'
        self.jsessionid=''
        self.DPT = DevicePolicyTemplate()
        self.scg_mgmt_ip = scg_mgmt_ip
        self.scg_port = scg_port

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

    def create_device_policy(self, dp_name='DevicePolicyName',
                                description='automation',
                                default_action='ALLOW', 
                                apzone_name='TEST',
                                domain_label='Administration Domain'):
        result = False
        dp_profile = {}
        
        try:
            url = ji.get_url(self.api_create_devicepolicy, self.scg_mgmt_ip, self.scg_port)
            dp_profile.update(self.DPT.get_template_data_for_devicepolicy())

            dp_profile.update({"name":dp_name,
                               "description": description,
                               "defaultAction":default_action})

            dp_profile.update({"zoneUUID":self.get_apzone_uuid(apzone_name=apzone_name, domain_label=domain_label),
                                "tenantUUID":self._get_tenant_uuid()})

            data_json = json.dumps(dp_profile)
            result = ji.post_json_data(url, self.jsessionid, data_json)

        except Exception,e:
            print traceback.format_exc()
            return False

        return result

    def get_key_and_data_for_device_policy(self, name='DevicePolicyName', apzone_name='TEST', domain_label='Administration Domain'):
        key, data = None, None
        is_found = False

        get_url = ji.get_url(self.api_add_rule_get%self.get_apzone_uuid(apzone_name=apzone_name, domain_label=domain_label), 
                                self.scg_mgmt_ip, self.scg_port)
        rcvd_data = ji.get_json_data(get_url, self.jsessionid)
        for i in range(0, len(rcvd_data['data']['list'])):
            if rcvd_data['data']['list'][i]['name'] == name:
                key, data = rcvd_data['data']['list'][i]['key'], rcvd_data['data']['list'][i]
                is_found = True
                break

        if not is_found:
            print "get_key(): Failed"
            return key, data

        return key, data


    def add_rule_to_device_policy(self, device_policy_name='DevicePolicyName',
                                        rule_description='DP_rule',
                                        action='ALLOW',
                                        device_type='1',
                                        uplink='500000',
                                        downlink='2000000',
                                        vlan=None,
                                        apzone_name='TEST',
                                        domain_label='Administration Domain'):
        result = False
        get_data = {}
        add_rule = {}
        key = None
        try:
            key, get_data = self.get_key_and_data_for_device_policy(name=device_policy_name, apzone_name=apzone_name, domain_label=domain_label)
            add_rule.update(get_data)
            add_rule['rule'].append({"description":rule_description,
                                     "action":action,
                                     "deviceType":int(device_type),
                                     "uplink":uplink,
                                     "downlink":downlink})
            if vlan:
                add_rule['rule'].append({"vlan":int(vlan)})
            data_json = json.dumps(add_rule)
            put_url = ji.get_url(self.api_add_rule_put%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(put_url, self.jsessionid, data_json)

        except Exception,e:
            print traceback.format_exc()
            return False

        return result

    def update_rule_to_device_policy(self, device_policy_name="DevicePolicyName",
                                            apzone_name="TEST",
                                            domain_label="Administration Domain",
                                            rule_description='DP_rule',
                                            new_rule_description=None,
                                            action=None,
                                            device_type=None,
                                            uplink=None,
                                            downlink=None,
                                            vlan=None):
        result = False
        get_data = {}
        update_rule = {}
        key = None
        try:
            key, get_data = self.get_key_and_data_for_device_policy(name=device_policy_name, apzone_name=apzone_name, domain_label=domain_label)
            update_rule = copy.deepcopy(get_data)
            rcvd_rule_data = {}
            element = None
            for i in range(0, len(get_data['rule'])):
                if get_data['rule'][i]['description'] == rule_description:
                    rcvd_rule_data = get_data['rule'][i]
                    element = i
                    break
            update_rule['rule'][element]["description"] = rcvd_rule_data["description"] if not new_rule_description else new_rule_description
            update_rule['rule'][element]["action"] = rcvd_rule_data["action"] if not action else action
            update_rule['rule'][element]["deviceType"] = rcvd_rule_data["deviceType"] if not device_type else int(device_type)
            update_rule['rule'][element]["uplink"] = rcvd_rule_data["uplink"] if not uplink else uplink
            update_rule['rule'][element]["downlink"] = rcvd_rule_data["downlink"] if not downlink else downlink
            update_rule['rule'][element]["vlan"] = rcvd_rule_data["vlan"] if not vlan else int(vlan)

            data_json = json.dumps(update_rule)
            put_url = ji.get_url(self.api_add_rule_put%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(put_url, self.jsessionid, data_json)

        except Exception,e:
            print traceback.format_exc()
            return False

        return result

    def detele_rule_to_device_policy(self, device_policy_name="DevicePolicyName",
                                            apzone_name="TEST",
                                            domain_label="Administration Domain",
                                            rule_description='DP_rule'):

        result = False
        get_data = {}
        update_rule = {}
        key = None
        try:
            key, get_data = self.get_key_and_data_for_device_policy(name=device_policy_name, apzone_name=apzone_name, domain_label=domain_label)
            update_rule = copy.deepcopy(get_data)
            for i in range(0, len(update_rule['rule'])):
                if update_rule['rule'][i]['description'] == rule_description:
                    del update_rule['rule'][i]
                    break
            data_json = json.dumps(update_rule)
            put_url = ji.get_url(self.api_add_rule_put%key, self.scg_mgmt_ip, self.scg_port)
            result = ji.put_json_data(put_url, self.jsessionid, data_json)

        except Exception,e:
            print traceback.format_exc()
            return False

        return result

    def delete_device_policy(self, device_policy_name="DevicePolicyName",
                                    domain_label="Administration Domain",
                                    apzone_name="TEST"):
        result = False
        try:
            key, data = self.get_key_and_data_for_device_policy(name=device_policy_name, apzone_name=apzone_name, domain_label=domain_label)
            del_dp_url = ji.get_url(self.api_delete_devicepolicy%key , self.scg_mgmt_ip, self.scg_port)
            result = ji.delete_scg_data(del_dp_url, self.jsessionid, None)

        except Exception, e:
           print traceback.format_exc()
           return False

        return result

    def _print_err_validate(self, fname, xvar, yvar, x, y):
        print "%s:: userdata:%s[%s] != serverdata:%s[%s]" % (fname, xvar, x, yvar, y)


