
class ScgJsonReportTemplate():
    def __init__(self):
        pass

    def get_report_template_data(self):
        _data = \
            {

               "title": "ln_report",

               "description": "AutomationReport",

               "reportType": "Client Number",

               "domainUUID": None,

               "pdfFormat": False,

               "csvFormat": False,

               "timeFilter": {

                  "interval": "FIFTEEN_MIN",

                  "timeUtil": "HOURS",

                  "timeSpan": 8

               },

               "scheduleEnable": False,

               "schedules": [

                  {

                     "interval": "DAILY",
                     "dateOfMonth": None,
                     "dayOfWeek": None,
                     "hour": 2,
                     "minute": 10

                  }

               ],

               "notificationEnable": False,

               "notifiedMailList": [],

               "ftpEnable": "false"

            }

        return _data

    def get_filter_template_data(self):
        _data = \
               {

                  "resourceType": "DOMAIN",

                  "resourceEntity": [

                     {

                        "label": "Administration Domain",

                        "value": None

                     }

                  ]

               }

        return _data


