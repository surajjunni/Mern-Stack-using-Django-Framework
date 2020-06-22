import sys
import json
import urllib, urllib2
import traceback
import time
import calendar

import qa.ttgcommon.coreapi.common.json_interface as ji
from qattg.coreapi.common.ScgJsonLogin import ScgJsonLogin
from qattg.coreapi.common.ScgJsonAdminAppStatus import ScgJsonAdminAppStatus
from qattg.coreapi.common.ScgJsonConfigApZone import ScgJsonConfigApZone
from ScgJsonMonitorEventsTemplate import ScgJsonMonitorEventsTemplate

class ScgJsonMonitorEvents():
    def __init__(self, scg_mgmt_ip="127.0.0.2", scg_port="8443"):

        self.scg_mgmt_ip = scg_mgmt_ip
        self.scg_port = scg_port
        self.jsessionid = ''
        self.req_api_monitor_system_events = '/wsg/api/scg/events/system?criteria=%s'
        self.req_api_monitor_client_events = '/wsg/api/scg/events/client?criteria=%s'
        self.req_api_monitor_client_events_35 = '/wsg/api/public/v5_0/alert/event/list'
        self.SJT = ScgJsonMonitorEventsTemplate()
        self.blade_api = None
        self.apzone_api = None

    def _login(self, username='admin', password='ruckus', **kwargs):

        l = ScgJsonLogin()
        result, self.jsessionid = l.login(scg_mgmt_ip=self.scg_mgmt_ip, scg_port=self.scg_port,
                username=username, password=password)
            
        return result

    def set_jsessionid(self, jsessionid):
        self.jsessionid = jsessionid

    def _create_blade_info_api(self, jsessionid=None):
        self.blade_api = ScgJsonAdminAppStatus(scg_mgmt_ip=self.scg_mgmt_ip, 
                scg_port=self.scg_port)
        self.blade_api.set_jsessionid(jsessionid)

    def _create_apzone_info_api(self, jsessionid=None):
        self.apzone_api = ScgJsonConfigApZone(scg_mgmt_ip=self.scg_mgmt_ip, 
                scg_port=self.scg_port)
        self.apzone_api.set_jsessionid(jsessionid)

    def _get_cp_mac(self, cblade_label=None):
        return self.blade_api.get_control_plane_mac(cblade_label=cblade_label)

    def _get_dp_mac(self, dblade_label=None):
        return self.blade_api.get_data_plane_mac(dblade_label=dblade_label)

    def _get_apzone_uuid(self, domain_label=None, ap_zone=None):
        return self.apzone_api.get_apzone_uuid(domain_label=domain_label, apzone_name=ap_zone)

    def get_events(self, 
            source_filter='cluster',
            start_time_epoch=None,
            end_time_epoch=None, 
            severity=None,
            category=None, 
            event_type=None,
            domain_label='Administration Domain',
            ap_zone=None,
            ap_mac=None, 
            client_mac=None, 
            cblade_label=None, 
            dblade_label=None, 
            ):

        """
        APIis used to Get Events Info

        :param str source_filter: ap | client  | cluster | scg_system | mvno_system |
        :param str start_time_epoch: Start Time in seconds
        :param str end_time_epoch: End Time in seconds
        :param str severity: Severity
        :param str category: Category Name
        :param str event_type: EventType for the selected category
        :param str domain_label: APZone Domain name
        :param str ap_zone: APZone Name
        :param str ap_mac: AP MAC Address
        :param str client_mac: Client MAC if source filter is 'Client'
        :param str cblade_label: SCG Control Plane Name if source filter is 'scg_system'
        :param str dblade_label: SCG Data Plane Name if source filter is 'scg_system'
        :return: list of Events if found else None
        :rtype: list

        """
        try:
            ev_list = []
            criteria = []
            url = None

            q_source = self.SJT.get_query_source(source_filter=source_filter)
            if not q_source:
                print "get_events(): Error - Invalid source_filter: %s" % source_filter
                return ev_list

            if source_filter == 'client':
                if client_mac is not None:
                    q_source['value'] = client_mac.upper()
                else:
                    print "get_events(): Error - client_mac should be set by user"
                    return ev_list

            criteria.append(q_source)

            q_source_param = {}

            if source_filter == 'scg_system':
                scg_cp_mac = None
                scg_dp_mac = None
                self._create_blade_info_api(jsessionid=self.jsessionid)

                if cblade_label is not None:
                    scg_cp_mac = self._get_cp_mac(cblade_label=cblade_label)
                    if not scg_cp_mac:
                        print "get_events(): Error - Could not fetch CP MAC for CP Name: %s" % cblade_label
                        return ev_list
                elif dblade_label is not None:
                    scg_dp_mac = self._get_dp_mac(dblade_label=dblade_label)
                    if not scg_dp_mac:
                        print "get_events(): Error - Could not fetch DP MAC for DP Name: %s" % dblade_label
                        return ev_list
                else:
                    print "get_events(): Error - Either cblade_label or dblade_label should be set by user"
                    return ev_list

                q_source_param = self.SJT.get_query_scg_system_filter(node_filter='cp' if cblade_label is not None else 'dp')
                q_source_param['value'] = scg_cp_mac if scg_cp_mac is not None else scg_dp_mac
                criteria.append(q_source_param)
            elif source_filter == 'ap':
                q_source_param = self.SJT.get_query_ap_filter(ap_filter='ap_zone' if ap_zone is not None else 'ap_mac')
                zone_uuid = None 
                #get the zone UUID
                if ap_zone is not None:
                    self._create_apzone_info_api(jsessionid=self.jsessionid)
                    zone_uuid = self._get_apzone_uuid(domain_label=domain_label, ap_zone=ap_zone)
                    if not zone_uuid:
                        print "get_events(): Error - Could not fetch zoneUUID for ap_zone: %s" % ap_zone
                        return ev_list
                    q_source_param['value'] = zone_uuid
                elif ap_mac is not None:
                    q_source_param['value'] = ap_mac.upper()
                else:
                    print "get_events(): Error - Either ap_zone or ap_mac should be set by user"
                    return ev_list

                criteria.append(q_source_param)

            if start_time_epoch is not None:
                q_start_time = self.SJT.get_query_start_time_epoch()
                q_start_time['value'] = long(round (float(start_time_epoch) * 1000))
                criteria.append(q_start_time)

            if end_time_epoch is not None:
                if start_time_epoch is not None:
                    q_end_time = self.SJT.get_query_end_time_epoch()
                    q_end_time['value'] = long(round (float(end_time_epoch) * 1000))
                    criteria.append(q_end_time)
                else:
                    print "get_events(): Error - start_time_epoch shall not be None if end_time_epoch is not None"
                    return ev_list

            if severity is not None:
                q_severity = self.SJT.get_query_severity()
                q_severity['value'] = severity
                criteria.append(q_severity)

            if category is not None:
                q_category = self.SJT.get_query_category()
                q_category['value'] = category
                criteria.append(q_category)

            if event_type is not None:
                q_event_type = self.SJT.get_query_event_type()
                q_event_type['value'] = event_type
                criteria.append(q_event_type)

            print "SCG Events URL query: %s" % criteria

            if source_filter == 'client':
                url = ji.get_url(self.req_api_monitor_client_events % urllib.quote_plus(json.dumps(criteria)), 
                    self.scg_mgmt_ip, self.scg_port)
            else:
                url = ji.get_url(self.req_api_monitor_system_events % urllib.quote_plus(json.dumps(criteria)), 
                    self.scg_mgmt_ip, self.scg_port)

            recvd_data = ji.get_json_data(url, self.jsessionid)

            ev_list = recvd_data['data']['list']

            return ev_list

        except Exception, e:
            print traceback.format_exc()
            return None
        
    def get_events_35private(self, 
            source_filter='cluster',
            start_time_epoch=None,
            event_type=None,
            event_code=None,
            category=None
            ):

        """
        APIis used to Get Events Info

        :param str source_filter: ap | client  | cluster | scg_system | mvno_system |
        :param str start_time_epoch: Start Time in seconds
        :param str event_type: EventType for the selected category
        :return: list of Events if found else None
        :rtype: list

        """
        try:
            ev_list = []
            criteria = {"criteria":"",
                        #"filters":[{"type":"CATEGORY","value":""}],
                        "fullTextSearch":{"type":"AND","value":""},
                        "sortInfo":{"sortColumn":"insertionTime","dir":"DESC"},
                        "page":0,
                        "start":0,
                        "limit":20
                        }
            url = None

            #criteria["filters"][0]["value"]=source_filter
            event_code_man = ""
            if category:
                event_code_man = event_code_man+category+""
            if event_code:
                event_code_man = event_code_man+event_code


            if event_code_man:
                criteria["fullTextSearch"]["value"]=event_code_man.strip()
            #elif event_type:
            #    criteria["fullTextSearch"]["value"]=event_type
                
            print "SCG Events URL query: %s" % criteria

            url = ji.get_url(self.req_api_monitor_client_events_35, self.scg_mgmt_ip, self.scg_port)
            
            data = json.dumps(criteria)
            recvd_data = self.post_json_data(url, self.jsessionid, data)

            ev_list = recvd_data['list']
            ev_list_filtered = []
            for ev in ev_list:
                if ev["insertionTime"] >= long(round (float(start_time_epoch) * 1000)) and str(ev["eventCode"])==event_code:
                    if event_type:
                        if event_type!=ev["eventType"]:
                            continue
                    ev_list_filtered.append(ev)

            return ev_list_filtered

        except Exception, e:
            print traceback.format_exc()
            return None

    def verify_event_code(self, event_code = 0, events=None):
        print events,"*****"
        if events:
            for item in events:
                print item['eventCode']
                if(item['eventCode'] == event_code):
                    return True
                else: return False
        else:
            return False

    def convert_time(self,timestamp=None):
        if(timestamp):
            return calendar.timegm(time.strptime(timestamp,"%Y-%m-%d %H:%M:%S %Z"))
        else:
            return None

    def verify_eventcodes_comments_status(self, event_codes = None, events_out = None):
        print "Given events_list:", event_codes
        print "Given events_output:", events_out
        if event_codes and events_out:
            for item in events_out:
                if item['eventCode'] in event_codes:
                    event_codes.remove(item['eventCode'])
                if not event_codes: break
            if not event_codes: return True
            else: return False
        else: return False

    def post_json_data(self,url, jsessionid, data):

        req = urllib2.Request(url, data, {'content-type':'application/json'})
    
        req.add_header('cookie', jsessionid)
    
        print 'Method:%s URL=%s' % ('POST', url)
        print 'Request:HEADERS: %s' % (req.headers)
        print 'Request:CONTENT: %s' % (data)
    
        try:
            response = urllib2.urlopen(req)
            print "Response CODE: ", response.code 
        except urllib2.URLError, e:
            raise Exception("post json data[%s] to url[%s] failed, due to error[%s]" % (data, url, e))
    
        response_data = json.load(response)
    
        if response.code != 200:
            return False
    
        return response_data

"""
if __name__ == '__main__':
    import time
    #scg_mgmt_ip = '10.1.33.2'
    scg_mgmt_ip = '172.19.16.93'
    sjc = ScgJsonMonitorEvents(scg_mgmt_ip=scg_mgmt_ip, scg_port='8443')

    if not sjc._login(username='admin', password='ruckus1!'):
        print "user login() failed"
        sys.exit(1)
    else:
        print "scg login success"

    source_filter = 'Control_Plane'
    #source_filter = 'ap'
    #source_filter = 'scg_system'
    #source_filter = 'mvno_system'
    #source_filter = 'client'

    client_mac='01:02:c3:4D:5E:99'
    ap_zone = 'Auto-3-SPY'
    ap_mac = '2C:E6:CC:08:46:70'
    #ap_zone = None
    #start_time_epoch = time.mktime(time.strptime("02.12.2013 18:13:35", "%d.%m.%Y %H:%M:%S"));
    #start_time_epoch = time.time()
    start_time_epoch = 1479268389
    end_time_epoch = None
    #cblade_label = 'spyder-C'
    cblade_label = None
    #dblade_label = 'spyder-D1'
    dblade_label = None

    #severity='Informational'
    #severity='Major'
    severity = None
    #category='AP State Change'
    #category='System Authentication'
    category='Cluster'
    event_type = None
    #event_type = 'upgradeEntireClusterSuccess'
    event_code="1627"
    '
    #ev_list = sjc.get_events(source_filter=source_filter, 
    #        ap_zone=ap_zone if source_filter is 'ap' else None,
    #        ap_mac=ap_mac,
    #        client_mac=client_mac,
    #        start_time_epoch=start_time_epoch,
    #        end_time_epoch=end_time_epoch,
    #        severity=severity,
    #        category=category,
    #        event_type=event_type,
    #        cblade_label=cblade_label,
    #        dblade_label=dblade_label,
    #        )
    
    ev_list = sjc.get_events_35private(source_filter=source_filter, 
            start_time_epoch=start_time_epoch,
            event_type=event_type,
            event_code=event_code,
            
            )
    if not ev_list:
        print "get_events(): No events received"
    else:
        print "get_events() success. total_events: %d for source_filter: %s" % (len(ev_list), source_filter)
        #print ev_list
        for ev in ev_list:
            print "event_code: %s event_type %s" % (
                    ev['eventCode'], ev['eventType'])


"""
