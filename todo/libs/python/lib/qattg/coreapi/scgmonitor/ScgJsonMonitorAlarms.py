import sys
import json
import urllib, urllib2
import traceback
import time

from ScgJsonMonitorAlarmsTemplate import ScgJsonMonitorAlarmsTemplate
from qattg.coreapi.common.ScgJsonConfigApZone import ScgJsonConfigApZone
from qattg.coreapi.common.ScgJsonLogin import ScgJsonLogin
import qattg.coreapi.scgconfig.ScgJsonConfig as sjc
import qa.ttgcommon.coreapi.common.json_interface as ji

class ScgJsonMonitorAlarms():
    def __init__(self, scg_mgmt_ip="127.0.0.2", scg_port="8443"):

        self.scg_mgmt_ip = scg_mgmt_ip
        self.scg_port = scg_port
        self.jsessionid = ''
        self.req_api_monitor_alarms = '/wsg/api/scg/alarms/system?criteria=%s'
        self.req_api_monitor_alarms_ap = '/wsg/api/scg/alarms/ap/%s?criteria=%s'
        self.req_api_monitor_alarms_35 = '/wsg/api/public/v5_0/alert/alarm/list'
        self.req_api_system_summary = '/wsg/api/scg/planes/systemSummary'
        self.req_api_scg_system_time = '/wsg/api/scg/globalSettings/system/systemTime'
        self.req_api_chk_aps_dataplane_details = '/wsg/api/scg/aps/%s/tunnel'
        self.req_alarm_auto_clear = '/wsg/api/scg/alarms/clear'
        self.req_alarm_auto_clear_35 = '/wsg/api/public/v5_0/alert/alarm/clear'
        self.sz_req_alarm_auto_clear = '/wsg/api/scg/alarmsE/clear'
        self.req_alarm_auto_ack = '/wsg/api/scg/alarms/ack'
        self.req_alarm_auto_ack_35 = '/wsg/api/public/v5_0/alert/alarm/ack'
        self.req_schdule_back_up = '/wsg/api/scg/backup/config/backupschedule'
        self.req_auto_back_up = '/wsg/api/scg/backup/config/backupsettings'
        self.req_wait_back_up = '/wsg/api/scg/backup/config?criteria=&page=1&start=0&limit=200'
        self.req_del_back_up = '/wsg/api/scg/backup/config/%s'
        self.sz_req_api_monitor_alarms = '/wsg/api/scg/alarmsE?searchType=%s&searchValue=%s&criteria=&page=1&start=0&limit=200'
        self.SJT = ScgJsonMonitorAlarmsTemplate()
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

    def get_alarms(self, 
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
            dblade_label=None, status=None, ack_time_epoch=None, acknowledged=None):

        """
        APIis used to Get Events Info

        :param str source_filter: ap | client  | cluster | scg_system | mvno_system | control_plane
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
            al_list = []
            criteria = []
            url = None

            q_source = self.SJT.get_query_source(source_filter=source_filter)
            print "testing q_source",q_source
            if not q_source:
                print "get_alarms(): Error - Invalid source_filter: %s" % source_filter
                return al_list

            if source_filter == 'client':
                if client_mac is not None:
                    q_source['value'] = client_mac.upper()
                else:
                    print "get_alarms(): Error - client_mac should be set by user"
                    return al_list

            criteria.append(q_source)

            q_source_param = {}

            if source_filter == 'scg_system':
                scg_cp_mac = None
                scg_dp_mac = None
                self._create_blade_info_api(jsessionid=self.jsessionid)

                if cblade_label is not None:
                    scg_cp_mac = self._get_cp_mac(cblade_label=cblade_label)
                    if not scg_cp_mac:
                        print "get_alarms(): Error - Could not fetch CP MAC for CP Name: %s" % cblade_label
                        return al_list
                elif dblade_label is not None:
                    scg_dp_mac = self._get_dp_mac(dblade_label=dblade_label)
                    if not scg_dp_mac:
                        print "get_alarms(): Error - Could not fetch DP MAC for DP Name: %s" % dblade_label
                        return al_list
                else:
                    print "get_alarms(): Error - Either cblade_label or dblade_label should be set by user"
                    return al_list

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
                        print "get_alarms(): Error - Could not fetch zoneUUID for ap_zone: %s" % ap_zone
                        return al_list
                    q_source_param['value'] = zone_uuid
                elif ap_mac is not None:
                    q_source_param['value'] = ap_mac.upper()
                    print "coming inside", q_source_param
                else:
                    print "get_alarms(): Error - Either ap_zone or ap_mac should be set by user"
                    return al_list
                criteria.append(q_source_param)
            elif source_filter == 'control_plane':
                q_source_param = self.SJT.get_query_cdinterface(category_value='Control_Plane')
                criteria.append(q_source_param)
                print criteria

            if start_time_epoch is not None:
                q_start_time = self.SJT.get_query_start_time_epoch()
                #q_start_time['value'] = long(round (start_time_epoch * 1000))
                q_start_time['value'] = int(round (float(start_time_epoch) * 1000))
                criteria.append(q_start_time)

	    
            if status is not None:
                q_status = self.SJT.get_query_alarm_status()
                q_status['value'] = status
                criteria.append(q_status)
            
            if ack_time_epoch is not None:
                q_ack_time = self.SJT.get_query_ack_time_epoch()
                q_ack_time['value'] = int(round (float(ack_time_epoch) * 1000 ))
                criteria.append(q_ack_time)


            if end_time_epoch is not None:
                if start_time_epoch is not None:
                    q_end_time = self.SJT.get_query_end_time_epoch()
                    q_end_time['value'] = long(round (float(end_time_epoch) * 1000))
                    criteria.append(q_end_time)
                else:
                    print "get_alarms(): Error - start_time_epoch shall not be None if end_time_epoch is not None"
                    return al_list

            if severity is not None:
                q_severity = self.SJT.get_query_severity()
                q_severity['value'] = severity
                criteria.append(q_severity)

            if category is not None:
                q_category = self.SJT.get_query_category()
                q_category['value'] = category
                criteria.append(q_category)

            if event_type is not None:
                q_event_type = self.SJT.get_query_event_type(event_type)
                criteria.append(q_event_type)
                
            if acknowledged:
                q_acknowledged = self.SJT.get_query_acknowledged()
                q_acknowledged['value'] = acknowledged
                criteria.append(q_acknowledged)
                
            print "SCG Alarms URL query: %s" % criteria

            if source_filter == 'client':
                url = ji.get_url(self.req_api_monitor_client_events % urllib.quote_plus(json.dumps(criteria)), 
                    self.scg_mgmt_ip, self.scg_port)
            elif source_filter == 'ap':
                url = ji.get_url(self.req_api_monitor_alarms_ap % (ap_mac,urllib.quote_plus(json.dumps(criteria))), self.scg_mgmt_ip, self.scg_port)
            else:
                url = ji.get_url(self.req_api_monitor_alarms % urllib.quote_plus(json.dumps(criteria)), 
                    self.scg_mgmt_ip, self.scg_port)

            recvd_data = ji.get_json_data(url, self.jsessionid)

            al_list = recvd_data['data']['list']

            return al_list

        except Exception, e:
            print traceback.format_exc()
            return None
        
    def get_alarms_35private(self, 
            source_filter='cluster',
            start_time_epoch=None,
            alarm_type=None,
            alarm_code=None,
            status=None, ack_time_epoch=None, acknowledged=None, severity=None, event_type=None, is_verify_alarm_code=True,category=None):
        """
        APIis used to Get Events Info

        :param str source_filter: ap | client  | cluster | scg_system | mvno_system | control_plane
        :param str start_time_epoch: Start Time in seconds
        :param str event_type: EventType for the selected category
        :param str alarm_code:AlarmCode
        :return: list of Events if found else None
        :rtype: list

        """
        alarm_code_man = ""
        if alarm_code:
            alarm_code_man = alarm_code + " "
        if event_type:
            alarm_code_man = alarm_code_man+event_type+" "
        if status:
            alarm_code_man = alarm_code_man+status+" "
        if severity:
            alarm_code_man = alarm_code_man+severity+" "
        if category:
            alarm_code_man = alarm_code_man+category
        try:
            al_list = []
            criteria = {"criteria":"",
                        "filters":[],
                        "fullTextSearch":{"type":"AND","value":""},
                        "sortInfo":{"sortColumn":"insertionTime","dir":"DESC"},
                        "page":0,
                        "start":0,
                        "limit":20
                        }
            
            url = None
            
            #criteria["filters"][0]["value"]=source_filter
            if alarm_code_man:
                criteria["fullTextSearch"]["value"]=alarm_code_man.rstrip()
            #elif event_type:
            #    criteria["fullTextSearch"]["value"]=event_type
            
                
            print "SCG Alarms URL query: %s" % criteria


            url = ji.get_url(self.req_api_monitor_alarms_35, self.scg_mgmt_ip, self.scg_port)
            
            data = json.dumps(criteria)

            recvd_data = self.post_json_data(url, self.jsessionid, data)

            al_list = recvd_data['list']
            print "all received event list is : %s" %str(al_list) 
            al_list_filtered = []
            for al in al_list:
                if start_time_epoch:
                    if al["insertionTime"] < long(round (float(start_time_epoch) * 1000)):
                        continue
                if alarm_type:
                    if alarm_type != al["alarmType"]: 
                        continue
                if alarm_code and is_verify_alarm_code:
                    if alarm_code != str(al["alarmCode"]):
                        continue
                if acknowledged:
                    if acknowledged.lower() != str(al["acknowledged"]).lower():
                        continue
                if ack_time_epoch:
                    if al["ackTime"] < long(round (float(ack_time_epoch) * 1000)):
                        continue
                al_list_filtered.append(al)

            return al_list_filtered

        except Exception, e:
            print traceback.format_exc()
            return None
        
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

    def verify_alarms_auto_clear(self, alarm_code=None, alarm_out=None):

        """
        API's used to verify alarm code is Auto cleared or not
        :param str alarm_type: contains type of alarm
        :param str alarm_out: contains the output of all alarm wrt alarm_type
        :return: boolean if alarm auto cleard returns True else False
        :rtype: boolean

        """
        if alarm_code and alarm_out:
            for item in alarm_out:
                #if item['alarmType'] == alarm_type and item['clearComment'] == "Auto Cleared":
                if str(item['alarmCode']) == alarm_code and item['clearComment'] == "Auto Cleared":
                    return True
            else: 
                return None
        else: 
            return None

    def verify_alarmcodes_comments_status(self, alarm_codes = None, alarms_out = None):
        """
        API's used to verify alarm codes which are passed to this method been auto cleared or not 
        :return: boolean if alarm_codes is auto cleared return True else False
        :rtype: boolean
        """
        
        #print "Given alarms_list:", alarm_codes
        #print "Given alarms_output:", alarms_out
        if alarm_codes and alarms_out:
            for item in alarms_out:
                if item['eventCode'] in alarm_codes: 
                    alarm_codes.remove(item['eventCode'])
                if not alarm_codes: break
            if not alarm_codes: return True
            else: return None
        else: return None
        
    def get_scg_epoch_time(self):
        """
        API's used to get current SCG epoch time in 10 digits
        :return: epoch integer digits if system time is running else None
        :rtype: integer
        """
        #scg time {u'data': {u'currentSystemTimeUTCString': u'2014-07-02 11:47:48 UTC', u'currentSystemTimeString': u'2014-07-02 11:47:48 UTC', u'ntpServer': u'pool.ntp.org', u'currentSystemTime': 1404301668650, u'currentSystemTimeUTC': 1404301668650, u'offset': 0, u'timezone': u'UTC'}, u'success': True, u'error': None}
 
        scg_epoch_url = ji.get_url(self.req_api_scg_system_time, self.scg_mgmt_ip, self.scg_port)
        recvd_data = ji.get_json_data(scg_epoch_url,self.jsessionid)
        #print "scg time",recvd_data
        if(recvd_data['success'] == True and recvd_data['error'] == None):
            if recvd_data['data']['currentSystemTime']:
                epoch = (recvd_data['data']['currentSystemTime'])/1000
                return epoch
            else: return None
        else: return None
     
    def get_aps_dataplane_details(self, ap_mac=None):
        if ap_mac:
            aps_data_plane_url = ji.get_url(self.req_api_chk_aps_dataplane_details % (ap_mac), self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.get_json_data(aps_data_plane_url, self.jsessionid)
            if recvd_data['success'] == True and recvd_data['error'] == None:
                if recvd_data['data']['list']:
                    for item in recvd_data['data']['list']:
                        if(item['dpMac']):
                            return item['dpMac']
        return None

    def acknowledge_alarm(self, alarm_list, partial=False):

        result=False
        data= []
        alarm_key = None
        alarm_count = len(alarm_list)
        if partial:
            clear_count = alarm_count / 2
            for i in range(0, clear_count):
                alarm_key = self.get_alarm_key(alarm_list[i])
                data.append(alarm_key)
        else:
            for i in range((alarm_count / 2), alarm_count):
                alarm_key = self.get_alarm_key(alarm_list[i])
                data.append(alarm_key)

        print '###',data
        try:
            url=ji.get_url(self.req_alarm_auto_ack, self.scg_mgmt_ip, self.scg_port)
            res=json.dumps(data)
            result = ji.put_json_data(url, self.jsessionid, res)
        except Exception, e:
            print traceback.format_exc()
            return False
        time.sleep(2)
        return result

    def acknowledge_alarm_35(self, alarm_list, partial=False):

        result=False
        data_dict = {}
        data= []
        alarm_key = None
        alarm_count = len(alarm_list)
        if partial:
            clear_count = alarm_count / 2
            for i in range(0, clear_count):
                alarm_key = self.get_alarm_key(alarm_list[i],'id')
                data.append(alarm_key)
        else:
            for i in range((alarm_count / 2), alarm_count):
                alarm_key = self.get_alarm_key(alarm_list[i],'id')
                data.append(alarm_key)

        print '###',data
        try:
            url=ji.get_url(self.req_alarm_auto_ack_35, self.scg_mgmt_ip, self.scg_port)
            data_dict.update({'idList':data})
            res=json.dumps(data_dict)
            result = ji.put_json_data(url, self.jsessionid, res)
        except Exception, e:
            print traceback.format_exc()
            return False
        time.sleep(2)
        return result


    def clear_alarm(self, alarm_list, clear_comment="cleared by automation",  partial=False):
        result=False
        data= []
        data_final = {}
        alarm_key = None
        alarm_count = len(alarm_list)
        if partial:
            clear_count = alarm_count / 2
            for i in range(0, clear_count):
                alarm_key = self.get_alarm_key(alarm_list[i])
                data.append(alarm_key)
        else:
            for i in range((alarm_count / 2), alarm_count):
                alarm_key = self.get_alarm_key(alarm_list[i])
                data.append(alarm_key)
        print '###',data
        data_final.update({"alarmUUIDS":data,
                           "clearComment":clear_comment})
        try:
            url=ji.get_url(self.req_alarm_auto_clear, self.scg_mgmt_ip, self.scg_port)
            res=json.dumps(data_final)
            result = ji.put_json_data(url, self.jsessionid, res)
        except Exception, e:
            print traceback.format_exc()
            return False
        time.sleep(10)
        return result

    def clear_alarm_35(self, alarm_list, clear_comment="cleared by automation",  partial=False):
        result=False
        data= []
        data_final = {}
        alarm_key = None
        alarm_count = len(alarm_list)
        if partial:
            clear_count = alarm_count / 2
            for i in range(0, clear_count):
                alarm_key = self.get_alarm_key(alarm_list[i],'id')
                data.append(alarm_key)
        else:
            for i in range((alarm_count / 2), alarm_count):
                alarm_key = self.get_alarm_key(alarm_list[i],'id')
                data.append(alarm_key)
        print '###',data
        data_final.update({"idList":data,
                           "comment":clear_comment})
        if len(data)>0:
            try:
                url=ji.get_url(self.req_alarm_auto_clear_35, self.scg_mgmt_ip, self.scg_port)
                res=json.dumps(data_final)
                result = ji.put_json_data(url, self.jsessionid, res)
            except Exception, e:
                print traceback.format_exc()
                return False
            time.sleep(10)
            return result
        else:
            return True
    
    def sz100_clear_alarm(self, alarm_list, clear_comment="cleared by automation",  partial=False):
        result=False
        data= []
        data_final = {}
        alarm_key = None
        alarm_count = len(alarm_list)
        if partial:
            clear_count = alarm_count / 2
            for i in range(0, clear_count):
                alarm_key = self.get_alarm_key(alarm_list[i])
                data.append(alarm_key)
        else:
            for i in range((alarm_count / 2), alarm_count):
                alarm_key = self.get_alarm_key(alarm_list[i])
                data.append(alarm_key)
        print '###',data
        data_final.update({"alarmUUIDS":data,
                           "clearComment":clear_comment})
        try:
            url=ji.get_url(self.sz_req_alarm_auto_clear, self.scg_mgmt_ip, self.scg_port)
            res=json.dumps(data_final)
            result = ji.put_json_data(url, self.jsessionid, res)
        except Exception, e:
            print traceback.format_exc()
            return False
        time.sleep(2)
        return result

    def get_alarm_raise_time(self,alarm=None):
        alarm_time = alarm['timestamp']
        return alarm_time

    def get_alarm_key(self,alarm=None,key ='key'):

        alarm_time = alarm[key]
        return alarm_time


    def get_alarm_ack_time(self,alarm=None):

        alarm_ack_time = alarm['ackTimestamp']
        return alarm_ack_time

    def get_last_raised_alarm(self,source_filter='cluster',start_time_epoch=None,end_time_epoch=None,severity=None,category=None,event_type=None,domain_label='Administration Domain',ap_zone=None,ap_mac=None,
                                  client_mac=None,cblade_label=None,dblade_label=None,status=None,ack_time_epoch=None):
        result=False
        alarm_list=self.get_alarms(source_filter=source_filter, start_time_epoch=start_time_epoch,  end_time_epoch=None, severity=severity, category='Cluster', event_type=event_type, domain_label='Administration Domain',
                                                ap_zone=None,ap_mac=None, client_mac=None, cblade_label=None, dblade_label=None,ack_time_epoch=ack_time_epoch,status=None)
        print "######", alarm_list
        return alarm_list[0]

    def auto_export_backup(self, autoExportEnabled="true", ftpServerName=None):
        result=False
        aut_backup={}
        aut_backup1={}
        try:
            scg_json = sjc.ScgJsonConfig(scg_mgmt_ip=self.scg_mgmt_ip, scg_port=self.scg_port)
            scg_json.set_jsessionid(self.jsessionid)
            url = ji.get_url(self.req_auto_back_up, self.scg_mgmt_ip, self.scg_port)
            aut_backup1.update({"ftpEnabled":autoExportEnabled,
				    "ftpSettingKey":"",
                    "ftpSettins":None})
            if autoExportEnabled == "true":
                ftpServerKey, recv_data = scg_json._get_key_for_ftp_service(ftpServerName)
                aut_backup.update({"key": ftpServerKey})
                aut_backup1.update({"ftpSettins":aut_backup})
                aut_backup1.update({"ftpSettingKey":ftpServerKey})
            aut_backup1 = json.dumps(aut_backup1)
            result = ji.post_json_data(url, self.jsessionid, aut_backup1)
        except Exception, e:
            print traceback.format_exc()
            return False
        return result

    def schedule_backup(self,sch_schedules=1,sch_interval=None,sch_dateOfMonth=None,sch_dayOfWeek=None,sch_hour=None,sch_minute=None,sch_scheduleEnabled='True'):
        result=False
        sch_backup={}
        sch_backup1={}
        try:
            url = ji.get_url(self.req_schdule_back_up, self.scg_mgmt_ip, self.scg_port)
            sch_backup.update({"schedules":sch_backup1})
            if sch_schedules == 1:
               sch_backup1.update({"interval":sch_interval,
                                "dateOfMonth":sch_dateOfMonth,
                                "dayOfWeek":sch_dayOfWeek,
                                "hour":sch_hour,
                                "minute":sch_minute,
				"scheduleEnabled":sch_scheduleEnabled
                                })
            self.sch_backup = json.dumps(sch_backup)
            print "###",self.sch_backup
            result = ji.post_json_data(url, self.jsessionid, self.sch_backup)
        except Exception, e:
            print traceback.format_exc()
            return False
        return result
    
    def get_backup_list(self):
        result = False
        data=[]
        try:
            url=ji.get_url(self.req_wait_back_up, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.get_json_data(url, self.jsessionid)
        except Exception, e:
            print traceback.format_exc()
            return False

        return recvd_data['data']['list']

    def delete_backup_list(self):
        result = True
        data=[]
        data = self.get_backup_list()
        for entry in data:
            key = entry['key']
            try:
                url=ji.get_url(self.req_del_back_up % key, self.scg_mgmt_ip, self.scg_port)
                recvd_data = ji.delete_scg_data(url, self.jsessionid,None)
            except Exception, e:
                print traceback.format_exc()
                return False

        return result
    
    def get_sz100_current_time(self):
        scg_epoch_url = ji.get_url(self.req_api_scg_system_time, self.scg_mgmt_ip, self.scg_port)
        recv_data = ji.get_json_data(scg_epoch_url,self.jsessionid)
        #print "scg time",recvd_data
        if(recv_data['success'] == True and recv_data['error'] == None):
            if recv_data['data']['currentSystemTimeString']:
                epoch=(recv_data['data']['currentSystemTimeString'])
#                epoch=epoch[0:19]
                epoch=epoch[0:len(epoch)-4]
                print "##### ##",epoch
                return epoch
            else: return None
        else: return None

    def sz100_get_alarms(self, search_value, search_type="and"):
        sz_get_alarm_url = ji.get_url(self.sz_req_api_monitor_alarms %(search_type, search_value), self.scg_mgmt_ip, self.scg_port)
        recv_data = ji.get_json_data(sz_get_alarm_url,self.jsessionid)
        al_list = recv_data['data']['list']
        return al_list


 
if(__name__ == "__main__"):

    import time
    #scg_mgmt_ip = '10.1.33.2'
    scg_mgmt_ip = '172.19.16.93'
    sja = ScgJsonMonitorAlarms(scg_mgmt_ip=scg_mgmt_ip, scg_port='8443')

    if not sja._login(username='admin', password='ruckus1!'):
        print "user login() failed"
        sys.exit(1)
    else:
        print "scg login success"
	start_time = 1479268488
    print sja.get_alarms_35private(source_filter='cluster', start_time_epoch=1479268488, alarm_code="1627")
        ## sja.verify_cluster_status_is_inservice()
        #print "calling cluster backup"
        #sja.get_last_raised_alarm(source_filter='cluster', start_time_epoch=current_time,  end_time_epoch=None, severity='severity', category='Cluster', event_type=None, domain_label='Administration Domain',ap_zone=None,ap_mac=None, client_mac=None, cblade_label=None, dblade_label=None,ack_time_epoch=None,status="status")
	#sja.schdule_back(sch_schedules =1,sch_interval="DAILY",sch_dateOfMonth=None,sch_dayOfWeek=None,sch_hour=14,sch_minute=10,sch_scheduleEnabled="true")
	#sja.auto_back(aut_autoexports=1,aut_ftpserver=("Clear" or "Reload"),aut_autoexportEnabled="true")
	#sja.wait_for_backup()
    #sja.delete_backup_list()

        

"""
    source_filter = 'cluster'
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
    start_time_epoch = None
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
    #event_type = None
    event_type = 'upgradeEntireClusterSuccess'

    al_list = sjc.get_events(source_filter=source_filter, 
            domain_label='Administration Domain',
            ap_zone=ap_zone if source_filter is 'ap' else None,
            ap_mac=ap_mac,
            client_mac=client_mac,
            start_time_epoch=start_time_epoch,
            end_time_epoch=end_time_epoch,
            severity=severity,
            category=category,
            event_type=event_type,
            cblade_label=cblade_label,
            dblade_label=dblade_label,
            
            )
    if not al_list:
        print "get_events(): No events received"
    else:
        print "get_events() success. total_events: %d for source_filter: %s" % (len(al_list), source_filter)
        #print al_list
        for al in al_list:
            print "event_code: %s event_type: %s fromVersion: %s toVersion: %s" % (
                    al['attributes']['eventCode'], al['attributes']['eventType'], 
                     al['attributes']['fromVersion'],  al['attributes']['toVersion'])

"""
