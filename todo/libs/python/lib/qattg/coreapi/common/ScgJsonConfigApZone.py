import copy
import json
import sys,time
import traceback

import qa.ttgcommon.coreapi.common.json_interface as ji
from ScgJsonLogin import ScgJsonLogin
from ScgJsonConfigApTemplate import ScgJsonConfigApTemplate

class ScgJsonConfigApZone():
    def __init__(self, scg_mgmt_ip="127.0.0.2", scg_port="8443"):

        self.scg_mgmt_ip = scg_mgmt_ip
        self.scg_port = scg_port
        self.jsessionid = ''
        self.req_api_domains = '/wsg/api/scg/session/currentUser/domainList?includeSelf=true'
        self.req_api_apzones = '/wsg/api/scg/zones/byDomain/%s'
        self.req_api_fetch_ap_firmwares_in_apzone = '/wsg/api/scg/zones/%s/fetchfirmwaresforchanging/%s'
        self.req_api_ap_info = '/wsg/api/scg/aps/byDomain/%s'
        self.req_api_ap_move = '/wsg/api/scg/aps/%s/move/%s'
        self.req_api_ap_config = '/wsg/api/scg/aps/%s/config'
        self.SJT = ScgJsonConfigApTemplate()

    def _login(self, username='admin', password='ruckus', **kwargs):

        l = ScgJsonLogin()
        result, self.jsessionid = l.login(scg_mgmt_ip=self.scg_mgmt_ip, scg_port=self.scg_port,
                username=username, password=password)

        return result

    def set_jsessionid(self, jsessionid):
        self.jsessionid = jsessionid

    def get_domain_uuid(self, domain_label='Administration Domain'):

        is_entry_found = False
        uuid = None

        try:
            url = ji.get_url(self.req_api_domains, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.get_json_data(url, self.jsessionid)

            if len(recvd_data['data']['list']) >= 1:
                for data in recvd_data['data']['list']:
                    if data['label'] == domain_label:
                        uuid = data['key']
                        is_entry_found = True
                        break
            else:
                print "get_domain_uuid(): No data.list recvd"
                return uuid

            if not is_entry_found:
                print "get_domain_uuid(): domain_label: %s not found" % domain_label
                return uuid

        except Exception:
            print traceback.format_exc()
            return uuid

        return uuid

    def get_apzone_uuid(self, domain_label='Administration Domain', apzone_name='APZone-1'):

        is_entry_found = False
        domain_uuid = None
        uuid = None

        try:
            domain_uuid = self.get_domain_uuid(domain_label=domain_label)
            if not domain_uuid:
                print "get_domain_uuid(): domain_label: %s failed" % domain_label
                return domain_uuid

            url = ji.get_url(self.req_api_apzones % domain_uuid, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.get_json_data(url, self.jsessionid)

            if len(recvd_data['data']['list']) >= 1:
                for data in recvd_data['data']['list']:
                    if data['mobilityZoneName'] == apzone_name:
                        uuid = data['key']
                        is_entry_found = True
                        break
            else:
                print "get_apzone_uuid(): No data.list recvd"
                return uuid

            if not is_entry_found:
                print "get_apzone_uuid(): apzone: %s not found" % apzone_name
                return uuid

        except Exception:
            print traceback.format_exc()
            return uuid

        return uuid


    def get_ap_fwversion_in_apzone(self, domain_label='Administration Domain', apzone_name='APZone-1'):

        is_entry_found = False
        domain_uuid = None
        fwversion = None

        try:
            domain_uuid = self.get_domain_uuid(domain_label=domain_label)
            if not domain_uuid:
                print "get_domain_uuid(): domain_label: %s failed" % domain_label
                return domain_uuid

            url = ji.get_url(self.req_api_apzones % domain_uuid, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.get_json_data(url, self.jsessionid)

            if len(recvd_data['data']['list']) >= 1:
                for data in recvd_data['data']['list']:
                    if data['mobilityZoneName'] == apzone_name:
                        fwversion = data['fmVersion']
                        is_entry_found = True
                        break
            else:
                print "get_ap_fwversion_in_apzone(): No data.list recvd"
                return fwversion

            if not is_entry_found:
                print "get_ap_fwversion_in_apzone(): apzone: %s not found" % apzone_name
                return fwversion

        except Exception:
            print traceback.format_exc()
            return fwversion

        return fwversion


    def get_ap_firmwares_in_apzone(self,  domain_label='Administration Domain', apzone_name='APZone-1'):
        
        apzone_uuid = None
        ap_fw_list = []

        try:
            apzone_uuid = self.get_apzone_uuid(domain_label=domain_label, apzone_name=apzone_name)
            if not apzone_uuid:
                print "get_apzone_uuid(): domain_label: %s apzone_name: %s failed" %(
                        domain_label, apzone_name)
                return ap_fw_list

            current_ap_fwversion = self.get_ap_fwversion_in_apzone(domain_label=domain_label, 
                    apzone_name=apzone_name)
            if not current_ap_fwversion:
                print "get_ap_fwversion_in_apzone(): apzone_name: %s failed" % apzone_name
                return ap_fw_list

            url = ji.get_url(self.req_api_fetch_ap_firmwares_in_apzone % (apzone_uuid, current_ap_fwversion), 
                    self.scg_mgmt_ip, self.scg_port)

            recvd_data = ji.get_json_data(url, self.jsessionid)

            ap_fw_list = recvd_data['data']['list']

            return ap_fw_list

        except Exception:
            print traceback.format_exc()
            return ap_fw_list

        return ap_fw_list

    def get_ap_info(self, domain_label='Administration Domain', ap_mac=None, ap_ip=None):

        is_entry_found = False
        domain_uuid = None
        ap_info = None

        if ap_mac is None and ap_ip is None:
            print "get_ap_info(): ap_mac and ap_ip is None"
            return ap_info

        try:
            domain_uuid = self.get_domain_uuid(domain_label=domain_label)
            if not domain_uuid:
                print "get_domain_uuid() domain_label: %s failed" % domain_label
                return domain_uuid

            url = ji.get_url(self.req_api_ap_info % domain_uuid, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.get_json_data(url, self.jsessionid)

            if len(recvd_data['data']['list']) >= 1:
                for data in recvd_data['data']['list']:
                    if ap_mac:
                        if data['apMac'] == ap_mac:
                            is_entry_found = True
                            ap_info = copy.deepcopy(data)
                            break
                    elif ap_ip:
                        if data['ip'] == ap_ip:
                            is_entry_found = True
                            ap_info = copy.deepcopy(data)
                            break
            else:
                print "get_ap_info(): No data.list recvd"
                return ap_info

            if not is_entry_found:
                print "get_ap_info(): AP: %s not found" % (ap_mac if ap_mac else ap_ip)
                return ap_info

        except Exception:
            print traceback.format_exc()
            return ap_info

        return ap_info

    def get_ap_configuration_status(self, domain_label='Administration Domain', ap_mac=None, apzone_name=None):

        ap_info = None
        configStatus = None

        if ap_mac is None:
            print "get_ap_configuration_status(): ap_mac is None"
            return ap_info
        try:
            ap_info = self.get_ap_info(domain_label=domain_label, ap_mac=ap_mac)

            if not ap_info:
                print "get_ap_info(): domain_label: %s ap_mac: %s failed" %(domain_label, ap_mac)
                return ap_info
            else:
                configStatus = ap_info["configStatus"]

            if apzone_name:
                if apzone_name == ap_info["zoneName"] and ap_mac == ap_info["apMac"]:
                    configStatus = ap_info["configStatus"]
                else:
                    return None

        except Exception:
            print traceback.format_exc()
            return None

        return configStatus

    def move_ap_to_apzone(self, domain_label='Administration Domain', apzone_name="APZone-1", ap_mac=None, 
            wait_preconfig_status="NotApplicable", wait_preconfig_retries='30', wait_preconfig_sleeptime='16', 
            wait_postmove_retries='15', wait_postmove_sleeptime='30'):

        ap_info = None
        recvd_status = None
        apzone_uuid = None

        if ap_mac is None:
            print "move_ap_to_apzone(): ap_mac is None"
            return ap_info

        try:
            if wait_preconfig_status != "NotApplicable":
                _is_status_ok = False
                for i in range(int(wait_preconfig_retries)):
                    recvd_status = self.get_ap_configuration_status(domain_label=domain_label, ap_mac=ap_mac)
                    if recvd_status != wait_preconfig_status:
                        print "Waiting to get the updated AP Configuration Status. Sleeping for %s, recvd_status - %s" % (wait_preconfig_sleeptime, recvd_status)
                        time.sleep(int(wait_preconfig_sleeptime))
                    else:
                        _is_status_ok = True
                        break
                if not _is_status_ok:
                    print 'move_ap_to_apzone: Error - AP configuration Status is incorrect' 
                    return None
            apzone_uuid = self.get_apzone_uuid(domain_label=domain_label, apzone_name=apzone_name)
            if not apzone_uuid:
                print "get_apzone_uuid(): domain_label: %s apzone_name: %s failed" %(
                        domain_label, apzone_name)
                return ap_info

            data = ''
            url = ji.get_url(self.req_api_ap_move % (ap_mac, apzone_uuid), self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.put_json_data(url, self.jsessionid, data)
            
            if recvd_data:
                is_ap_moved = False
                for i in range(int(wait_postmove_retries)):
                    ap_info = self.get_ap_info(domain_label=domain_label, ap_mac=ap_mac)
                    if ap_info["zoneName"] != apzone_name:
                        print "Waiting for the AP configuration status to get completed after move. Sleeping for %s" % wait_postmove_sleeptime
                        time.sleep(int(wait_postmove_sleeptime))
                    else:
                        is_ap_moved = True
                        break
                if not is_ap_moved:
                    return None

        except Exception:
            print traceback.format_exc()
            return ap_info

        return ap_info


    def wait_ap_status(self, ap_mac='01:02:03:04:05:06', status='completed',
            sleep_interval=30, retries=20):

        i = 0
        ret = False
        _retries = int(retries)

        while i < _retries:
            if self.get_ap_configuration_status(ap_mac=ap_mac) == status:
                ret = True
                break
            time.sleep(int(sleep_interval))
            i = i + 1

        return ret


    def get_ap_config(self, ap_mac='01:02:03:04:05:06'):
        recvd_data = {}
        try:
            url = ji.get_url(self.req_api_ap_config % ap_mac, self.scg_mgmt_ip, self.scg_port)
            _resp = ji.get_json_data(url, self.jsessionid)
            recvd_data = _resp['data']
            print recvd_data

        except Exception, e:
            print traceback.format_exc()
            return recvd_data

        return recvd_data


    def update_ap_config(self, ap_mac='01:02:03:04:05:06',
            domain_label='Administration Domain',
            location='bangalore', wait_ap_status='completed'
            ):
        
        try:
            curr_ap_cfg = self.get_ap_config(ap_mac=ap_mac)
            if not curr_ap_cfg:
                print "update_ap_config(): get_ap_config() failed. ap_mac: %s " % ap_mac
                return False

            ap_info = self.get_ap_info(domain_label=domain_label, ap_mac=ap_mac)
            if not ap_info:
                print "update_ap_config(): _get_ap_info() failed. ap_mac: %s " % ap_mac
                return False

            ap_data = self.SJT.get_ap_config_template_data()

            ap_data['fwVersion'] = curr_ap_cfg['fwVersion']
            ap_data['model'] = curr_ap_cfg['model']
            ap_data['mobilityZoneUUID'] = curr_ap_cfg['mobilityZoneUUID']
            ap_data['mac'] = ap_mac
            ap_data['description'] = curr_ap_cfg['description']

            ap_data['config'] = curr_ap_cfg['config'].copy()
            ## Remove spurious keys that are not to be copied over...
            ap_data['config'].pop("apLogin", None)
            ap_data['config'].pop("apPass", None)
            ap_data['config'].pop("isDualRadio", None)
            ap_data['config'].pop("wifi1ChannelWidth", None)
            ap_data['config'].pop("wifi0ChannelWidth", None)
            ap_data['config'].pop("syslogIpv6", None)


            ap_data['config']['deviceName'] = ap_info['deviceName']
            ap_data['config']['deviceLocation'] = location
            #ap_data['config']['deviceIpSetting'] = ap_info['specificationConfiguration']['deviceIpSetting']

            url = ji.get_url(self.req_api_ap_config % ap_mac, 
                    self.scg_mgmt_ip, self.scg_port)
            data_json = json.dumps(ap_data)
            result = ji.put_json_data(url, self.jsessionid, data_json)


            if ap_info["zoneName"] != "Staging Zone":
                if not self.wait_ap_status(ap_mac=ap_mac.upper(), status=wait_ap_status):
                    print "wait_ap_status() AP status is not up-to-date"
                    return False

            return result

        except Exception, e:
            print traceback.format_exc()
            return False


if __name__ == '__main__':

    domain_name = 'Administration Domain'
    apzone_name = 'Auto-1-EVO'
    ap_mac = '50:A7:33:14:6B:20'

    sjc = ScgJsonConfigApZone(scg_mgmt_ip='172.19.16.199', scg_port='8443')

    if not sjc._login(username='admin', password='ruckus1!'):
        print "user login() failed"
        sys.exit(1)
    else:
        print "scg login success"

    ap_fw_list = sjc.get_ap_firmwares_in_apzone(domain_label=domain_name, apzone_name=apzone_name)
    if not ap_fw_list:
        print "get_ap_firmwares_in_apzone(): failed"
        sys.exit(1)
    else:
        print "current list of AP firmwares in apzone: %s and domain: %s is: %s" % (
                apzone_name, domain_name, ap_fw_list)

    ap_move = sjc.move_ap_to_apzone(domain_label=domain_name, apzone_name=apzone_name , ap_mac=ap_mac)
    if not ap_move:
        print "Failed: move ap %s to ap zone %s failed" % (ap_mac, apzone_name)
    else:
        print ap_move

    ap_getconfigStatus = sjc.get_ap_configuration_status(domain_label=domain_name, apzone_name=apzone_name, ap_mac=ap_mac)
    if not ap_getconfigStatus:    
        print "Failed: failed to get configuration status of ap_mac %s" % ap_mac
    else:
        print ap_getconfigStatus
