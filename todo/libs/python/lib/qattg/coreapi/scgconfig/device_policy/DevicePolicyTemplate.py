class DevicePolicyTemplate():
    def __init__(self):
        pass

    def get_template_data_for_devicepolicy(self):
        data = {"name":"DP_Name",
                "description":"",
                "key":"",
                "tenantId":"",
                "createDateTime":"",
                "creatorId":"",
                "creatorUsername":"",
                "zoneUUID":"",
                "defaultAction":"ALLOW",
                "rule":[],
                "tenantUUID":""}

        return data

    def dp_update_template(self):
        data = {"rule":[{"description":"DP_Rule",
                 "action":'BLOCK',
                 "deviceType":1,
                 "uplink":'0',
                 "downlink":'0',
                 "vlan":None}]}
 
        return data


