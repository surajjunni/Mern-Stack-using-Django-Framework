
class ScgJsonMonitorEventsTemplate:
    def __init__(self):
        pass

    def get_query_source(self, source_filter=None):
        if source_filter == 'ap':
            return {"columnName":"filterDomain","value":"zone","operator":"eq"}
        elif source_filter == 'client':
            return {"columnName":"clientMac","value":"","operator":"eq"}
        elif source_filter == 'cluster':
            return {"columnName":"filterDomain","value":"Cluster","operator":"eq"}
        elif source_filter == 'mvno_system':
            return {"columnName":"filterDomain","value":"MVNO_System","operator":"eq"}
        elif source_filter == 'scg_system':
            return {"columnName":"filterDomain","value":"system","operator":"eq"}
        elif source_filter == 'control_plane':
            return {"columnName":"nodeMac","value":"all","operator":"eq"}
        else:
            print "get_query_source(): Invalid source_filter: %s" % source_filter
        return {}

    def get_query_ap_filter(self, ap_filter=None):
        if ap_filter == 'ap_zone':
            return {"columnName":"zoneUUID","value":"","operator":"eq"}
        elif ap_filter == 'ap_mac':
            return {"columnName":"apMac","value":"","operator":"eq"}
        else:
            print "get_query_ap_filter(): Invalid ap_filter: %s" % ap_filter
        return {}
            
    def get_query_scg_system_filter(self, node_filter=None):
        if node_filter == 'cp':
            return {"columnName":"nodeMac","value":"","operator":"eq"}
        elif node_filter == 'dp':
            return {"columnName":"dpMac","value":"","operator":"eq"}
        else:
            print "get_query_scg_system_filter(): Invalid node_filter: %s" % node_filter
        return {}

    def get_query_start_time_epoch(self):
        return {"columnName":"timestamp","value":"","operator":"gte"}

    def get_query_end_time_epoch(self):
        return {"columnName":"timestamp","value":"","operator":"lte"}

    def get_query_severity(self):
        return {"columnName":"severity","value":"","operator":"eq"}

    def get_query_category(self):
        return {"columnName":"category","value":"","operator":"eq"}

    def get_query_event_type(self):
        return {"columnName":"eventType","value":"","operator":"eq"}
