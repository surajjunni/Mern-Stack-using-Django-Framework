

class ScgJsonMonitorAlarmsTemplate:

    def __init__(self):
        pass


    def get_query_source(self, source_filter=None):
        if source_filter == 'ap':
            return {"columnName": "mainCategory", "value": "AP", "operator": "eq"}
        elif source_filter == 'client':
            return {"columnName":"clientMac","value":"","operator":"eq"}
        elif source_filter == 'cluster':
            return {"columnName":"mainCategory","value":"Cluster","operator":"eq"}
        elif source_filter == 'mvno_system':
            return {"columnName":"filterDomain","value":"MVNO_System","operator":"eq"}
        elif source_filter == 'scg_system':
            return {"columnName":"filterDomain","value":"system","operator":"eq"}
        elif source_filter == 'control_plane':
            #return {"columnName":"nodeMac","value":"all","operator":"eq"}
            return {"columnName":"mainCategory","value":"Control_Plane","operator":"eq"}
        else:
            print "get_query_source(): Invalid source_filter: %s" % source_filter
        return {}
    #aq_source_param = self.SJT.get_query_ap_filter(ap_filter='ap_zone' if ap_zone is not None else 'ap_mac')


    def get_query_ap_filter(self, ap_filter = None, ap_value=None):
        if ap_filter == 'ap_zone':
            return {"columnName":"zoneUUID","value":"","operator":"eq"}
        elif ap_filter == 'ap_mac':
            return {"columnName":"apMac","value":"","operator":"eq"}
        else:
            print "get_query_ap_filter(): Invalid ap_filter: %s" % ap_filter
        return {}

    def get_query_category(self,category_value = ''):
        return {"columnName":"category","value":category_value,"operator":"eq"}

    def get_query_event_type(self, event_value = ''):
        return {"columnName":"alarmType","value":event_value ,"operator":"eq"}
    
    def get_query_alarm_status(self, status = ''):
        return {"columnName":"alarmState","value":status ,"operator":"eq"}
    
    def get_query_severity(self,severity = ''):
        return {"columnName":"alarmSeverity","value":severity,"operator":"eq"}

    def get_query_start_time_epoch(self, start_time_value = ''):
        return {"columnName":"timestamp","value":start_time_value,"operator":"gte"}

    def get_query_ack_time_epoch(self, ack_time_epoch = ''):
        return {"columnName":"ackTimestamp","value":ack_time_epoch,"operator":"gte"}
    
    def get_query_cdinterface(self,category_value = ''):
        return {"columnName": "mainCategory", "value": category_value, "operator": "eq"}  

    def get_query_acknowledged(self,acknowledge = ''):
        return {"columnName": "acknowledged", "value": acknowledge, "operator": "eq"}  
