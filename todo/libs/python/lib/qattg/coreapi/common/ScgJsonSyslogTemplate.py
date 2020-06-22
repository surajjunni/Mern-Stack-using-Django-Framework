
class ScgJsonSyslogTemplate:
    
    def __init__(self):
        pass
    
    def get_syslog_template_data(self):
        
        _data = { 
                  "enable" : False,
                  "applog_syslog_facility": "LOCAL0",
                  "audit_syslog_facility" : "LOCAL0",
                  "event_syslog_facility" : "LOCAL0",
                  "forwardUEEventsType" : "1",
                  "host" : "",
                  "port" : 514,
                  "severityPriorityMapping" : { "Critical" : "ERROR",
                                                "Major" : "ERROR",
                                                "Minor" : "WARN",
                                                "Warning" : "WARN",
                                                "Informational" : "INFO",
                                                "Debug" : "DEBUG"
                                                }
                 }
        
        return _data
