from qattg.coreapi.common.ScgJsonLogin import ScgJsonLogin
import qattg.coreapi.scgconfig.snmp.ScgJsonConfigSnmpAgent as SJS
from qattg.coreapi.scgconfig.ScgJsonConfig import ScgJsonConfig

class RWQATTGRobotScgJsonConfigSnmpAgentKeywords():
    """
    This Library allows to Configure the SCG using JSON API
    It conatains the Configuration APIs such as create, validate, update, and delete of configuration objects.
    """

    def __init__(self):
        self.sjcs = None
        self.sjc = None
        pass

    def login_to_scg(self, scg_mgmt_ip='127.0.0.2', scg_port='8443',
                            username='admin', password='ruckus',
                            ):
        """
        API used to login to SCG.

        :param str scg_mgmt_ip: SCG Management IP

        :param str scg_port: SCG https port

        :param str username: username (admin or mvno user)

        :param str password: password (admin or mvno password)

        :return: jsessionid if login is successful else Exception

        :rtype: string

        Example:
        | Login to SCG | scg_mgmt_ip=172.19.18.150 | username=admin | password=ruckus |


        """

        sjl = ScgJsonLogin()
        res, jsessionid = sjl.login(scg_mgmt_ip=scg_mgmt_ip, scg_port=scg_port,
                username=username, password=password)

        if not res:
            raise AssertionError("Failed to Login to SCG")

        self.set_scg_session(scg_mgmt_ip=scg_mgmt_ip, scg_port=scg_port, jsessionid=jsessionid)

        return jsessionid

    def set_scg_session(self, scg_mgmt_ip='127.0.0.2', scg_port='8443', 
            jsessionid=None):
        """
        Creates an instance of scg json config for SCG IP and https port.
        This keyword shall be used if login is not done from this class instance
        and user knows the jsessionid. This API is helpful if the JSON API is available across
        multiple library files.

        :param str scg_mgmt_ip: SCG Management IP

        :param str scg_port: SCG https port

        :param str jsessionid: jsessionid returned by a successful login to SCG

        :return: None

        :rtype: None

        Example:
        | Set SCG Session | scg_mgmt_ip=172.19.18.150 | jsessionid=${JSESSIONID} |

        """
        print jsessionid
        self.sjcs = SJS.ScgJsonConfigSnmpAgent(scg_mgmt_ip=scg_mgmt_ip, scg_port=scg_port)
        self.sjc = ScgJsonConfig(scg_mgmt_ip=scg_mgmt_ip, scg_port=scg_port)

        self.sjcs.set_jsessionid(jsessionid)
        self.sjc.set_jsessionid(jsessionid)


    def create_snmpv2_agent(self, **kwargs):
        """ 
        API used to create SNMPv2 Agent

        URI: PUT /wsg/api/scg/globalSettings/mvno/snmp

        :param str community: SNMPv2 Community

        :param bool read_privilege: make True if API used to create SNMPv2 agent as read privilege else False

        :param bool write_privilege: make True if API used to create SNMPv2 agent as write privilege else False

        :param bool trap_privilege: make True if API used to create SNMPv2 agent as trap privilege else False

        :param str trap_target_ip: Trap target IP address

        :param str trap_target_port: Trap target port

        :return: True if  SNMPv2 agent created else False

        :rtype: boolean

        Example:
        | create snmpv2 agent | community=public 

        """

        res = self.sjcs.create_snmpv2_agent(**kwargs)
        if not res:
            raise AssertionError("Failed to Create SNMPv2 Agent")

        return True

    def delete_snmpv2_agent(self,**kwargs):

        res = self.sjcs.delete_snmpv2_agent(**kwargs)
        if not res:
            raise AssertionError("Failed to delete snmpv2 agent")

        return True

    def configure_event_notification(self, **kwargs):
       
        """ 
        API used to configure event notification 

        URI: PUT /wsg/api/scg/globalSettings/mvno/snmp

        :param str event_code: code of the event

        :param bool trigger_trap: make True if API used to enable snmp trap for the event else False

        :return: True if event configured else False 

        :rtype: boolean

        Example:
        | configure event notification | trigger_trap=true 

        """

        res = self.sjcs.configure_event_notification(**kwargs)

        if not res:
            raise AssertionError("Failed to Configure event")

        return True

    def start_snmptrapd(self, **kwargs):
        """
        API used to start snmp trapd service
        
        :param str mibfile: Event MIB file with full path

        :param str snmptrap_logfile: Trap log file name

        :param str config_file: SNMPTrapd configuration file

        :return True if snmptrapd starts properly else False

        :type: boolean

        Example:
        | start snmptrapd | mibfile=/tmp/RUCKUS-SCG-EVENT-MIB.txt
        """
        
        res = self.sjcs.start_snmptrapd(**kwargs)
        if not res:
            raise AssertionError("Failed to start SNMPTrapd service")

        return True

    def clean_log(self,**kwargs):

        res = self.sjcs.clean_log(**kwargs)
        if not res:
            raise AssertionError("Failed to clean log")

        return True


    def trigger_event_cgf(self, **kwargs):
        """
        API used to create CGF Service

        URI: POST /wsg/api/scg/cgfs?

        :param str cgf_service_name: CGF service name

        :param str server_ip: CGF server ip address

        :param str server_port: CGF server port
        
        :return True if CGF service created else False

        :type: boolean

        Example:
        | trigger event cgf | cgf_service_name=CGF
        """
        
        res = self.sjcs.trigger_event_cgf(**kwargs)
        if not res:
            raise AssertionError("Failed to trigger event cgf")
            
        return True
 
    def create_cgf_service(self,**kwargs):
        res = self.sjc.create_cgf_service(**kwargs)

        if not res:
            raise AssertionError("Failed to create the cgf service")

        return True
    
    def delete_cgf_service(self,**kwargs):
    
        """
        API used to delete CGF Services

        URI: DELETE /wsg/api/scg/cgfs/<cgf_service_keys> 

        :param str cgf_service_name: Name of the CGF service Profile
        :return: True if CGF service is deleted successfully else False
        :rtype: boolean

        """
        res = self.sjc.delete_cgf_service(**kwargs)

        if not res:
            raise AssertionError("Failed to delete cgf")

        return True

    def change_map_gateway_settings_in_hlr_service(self):
        """
        API used to update the Map Gateway Settings in HLR Service

        URI: PUT /wsg/api/scg/hlrs/globalsettings?

        :param boolean enable_map_gateway_service: True | False
        :param str traffic_mode: Load_Share | Override
        :param str active_map_gateway: active_map_gateway
        :return: True if Map  Gateway Settings in HLR Service updated successfully else False
        :rtype: boolean

        """    

        res = self.sjcs.change_map_gateway_settings_in_hlr()

        if not res:
            raise AssertionError("Failed to update map gateway settings in hlr service")

        return True
 
    def validate_snmp_trap(self, **kwargs):
        """
        API used to validate snmp trap
        
        :param str snmpv2_community: SNMPv2 community string

        :param str event_severity: Severity of the event

        :param str event_type: Type of the event

        :param str event_description: Description of the event

        :parap str snmptrap_logfile: snmptrap log file name

        :param str sleep_time: Seconds to sleep for each iteration to validate trap

        :param str max_sleep_time: Maximum sleep time

        :param boolean is_find_trap: true if Trap should be sent else false

        :return True if SNMP Trap validated else False

        :type: boolean

        Example:
        | validate snmp trap | snmpv2_community=public | event_type=cnxnToCgfFailed
        """
        res = self.sjcs.validate_snmp_trap(**kwargs)
        if not res:
            raise AssertionError("Failed to validate SNMP Trap")

        return True

if __name__ == '__main__':
    obj = RWQATTGRobotScgJsonConfigSnmpAgentKeywords()
    obj.login_to_scg(scg_mgmt_ip='172.19.16.199',username='admin',password='ruckus1!')
    #obj.configure_event_notification(event_code='1610',trigger_trap='true')
    #obj.delete_cgf_service(cgf_service_name="CGFFail")
    #obj.start_snmptrapd(snmptrap_logfile='/tmp/snmptrap-custom.log')
    #obj.validate_snmp_trap(snmptrap_logfile='/tmp/snmptrap-custom.log',is_find_trap='false',max_sleep_time=10)
    obj.update_map_gateway_settings_in_hlr_service()
