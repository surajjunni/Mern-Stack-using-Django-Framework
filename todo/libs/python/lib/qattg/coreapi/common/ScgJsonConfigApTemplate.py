
class ScgJsonConfigApTemplate():
    def __init__(self):
        pass

    def get_ap_config_template_data(self):
        _data = \
            {
               "mac": "",

               "description": "",

               "fwVersion": "",

               "model": "ZF7363",

               "mobilityZoneUUID": "",

               "config": {

                  "deviceName": "RuckusAP",

                  "deviceLocation": "",

                  "deviceIpSetting": "keep",

                  "clientAdmMinClientCount24": 0,

                  "clientAdmMaxRadioLoad24": 0,

                  "clientAdmMinClientThroughput24": 0,

                  "clientAdmMinClientCount50": 0,

                  "clientAdmMaxRadioLoad50": 0,

                  "clientAdmMinClientThroughput50": 0,

                  "wifi0WlanService": 0,

                  "wifi1WlanService": 0,

                  "venueNameList": [],

                  "countryCode": "US",

                  "deviceGps": ""
               }
            }
        return _data
