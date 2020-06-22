
class ScgJsonConfigSnmpAgentTemplate:
    def __init__(self):
        pass

    def get_snmpv2_agent_template_data(self):
        snmp_agent_data = \
            {

               "enabled": True,

               "communityName": "",

               "readPrivilege": False,

               "writePrivilege": False,

               "trapPrivilege": False,

               "communities": [

                  {

                     "communityName": "",

                     "readPrivilege": False,

                     "writePrivilege": False,

                     "trapPrivilege": False,

                     "traps": [{"targetAddress":"1.2.3.4","targetPort":"162"}]

                  }

               ],

               "users": []

            }

        return snmp_agent_data
                    
    def get_snmpv3_agent_template_data(self):
        snmp_agent_data = \
            {
               "enabled": True,

               "communityName": "",

               "readPrivilege": False,

               "writePrivilege": False,

               "targetAddress": "",

               "targetPort": "",

               "userName": "",

               "localizationEngineID": "",

               "status": "",

               "storageType": "",

               "authProtocol": "",

               "authPassword": "",

               "privProtocol": "",

               "privPassword": "",

               "communities": [],

               "users": [

                  {

                     "userName": "",

                     "localizationEngineID": "",

                     "status": "",

                     "storageType": "",

                     "authProtocol": "",

                     "authPassword": "",

                     "privPassword": "",

                     "privProtocol": "",

                     "readPrivilege": False,

                     "writePrivilege": False,

                     "trapPrivilege": False,

                     "traps": []

                  }

               ]

        }
        return snmp_agent_data
