import os
import re
import traceback
from qattg.coreapi.common.ScgJsonLogin import ScgJsonLogin
import qattg.coreapi.scgconfig.ScgJsonConfig as SJ
import qattg.coreapi.scgreport.ScgJsonReport as SR
import qattg.coreapi.scgmonitor.ScgJsonMonitorClient as SM
import qattg.coreapi.scgmonitor.ScgJsonMonitorEvents as SE
import qattg.coreapi.common.ScgJsonConfigApZone as SA
import qattg.coreapi.scgconfig.pmip.PMIP_Config as PC
from qattg.coreapi.license import LicenseLib as LL
import qattg.coreapi.common.ScgJsonSyslog as SS
import qattg.coreapi.scgconfig.snmp.ScgJsonConfigSnmpAgent as SN
import qattg.coreapi.scgmonitor.ScgJsonMonitorAlarms as SALARM
import qa.ttgcommon.coreapi.common.json_interface as ji
import time
from qa.ttgcommon.coreapi.simulators import WSGCAgent as wsgc
from qa.ttgcommon.publicapi_v2 import SCG200PublicApiV2 as PA
from robot.libraries.BuiltIn import BuiltIn, register_run_keyword
IS_PUBLIC=False
PUBLIC_FALSE = False
API_VERSION=os.getenv("API_VERSION","v4_0")
PUBLIC=os.environ.get("PUBLIC_API","True")
if re.search("true",PUBLIC.lower()):
    IS_PUBLIC=True        
GET_ZONEID_API="Get Zone"
MODIFY_ZONE_INFO_API="Modify Basic Apzone Info"
MODIFY_ZONE_LOGIN_API="Modify Apzone Login"
MODIFY_AP_USER_LOCATION_INFO="Modify_Ap_User_Location_Info"
MODIFY_AP_BASIC_INFO="Modify Ap Basic Info"
MODIFY_AP_LOGIN="Modify_Ap_Login"
GET_AP_OPERATIONAL_INFO="Get AP Operational Info"
GET_APZONE_API="Get Zone name by ID"
GET_SCG_TIME_EPOCH_API="SCG Time Epoch"
GET_SCG_VERSION_API="SCG Version"
GET_SCG_ID_API="SCG Id"
REBOOT_APMAC_API="Reboot Ap"
#SCG_UP_TIME_API="SCG Up Time"
UPDATE_WISPR_API="Update Hotspot Service"
DELETE_WISPR_API="Delete Hotspot Service"
UPDATE_AUTHENTICATION_API="Update Auth Profile Realm Service"
AUTO_EXPORT_API="Modify Auto Export Backup"
SCHEDULE_API="Modify Scheduled Backup"
GET_BACKUP_LIST_API="Retrive Configuration Backup"
DELETE_BACKUP_LIST_API="Delete Configuration Backup"
MODIFY_AP_SYSLOG_OVERRIDE="Modify_AP_Syslog_Override"
MODIFY_APZONE_SYSLOG="Modify Apzone Syslog"
VERIFY_AP_SYSLOG_FACILITY="Verify AP Syslog Facility"
VERIFY_APZONE_SYSLOG_DEFAULT_FACILITY="Verify Apzone Syslog Default Facility"
UPDATE_WLAN_ACCESS_TUNNEL="Update WLAN Access Tunnel"
UPDATE_WLAN_CORE_TUNNEL="Update WLAN Core Tunnel"
UPDATE_WLAN_ENCRYPTION="Update WLAN Encryption"
UPDATE_ACCTSERVICE_OF_WLAN="Update Acctservice of WLAN"
UPDATE_AUTHSERVICE_OF_WLAN="Update Authservice of WLAN"
MODIFY_WLAN_ADVANCED_OPTIONS="Modify WLAN Advanced Options"
PUBLIC_API_LOGIN="Login SCG System"
UPDATE_WLAN_CORE_TUNNEL_TTG="Update WLAN Core Tunnel TTG"
MODIFY_WLAN_PORTAL_PROFILE="Modify WLAN Portal Profile"
SET_WLANID_AND_ZONEID="Set WlanId And ZoneId"
CREATE_TUNNEL_PROFILE="Create Tunnel Profile"
DELETE_TUNNEL_PROFILE="Delete Tunnel Profile"
SET_APP_LOG_LEVEL="Modify Log Level"
MOVE_AP="QA Move AP With Status"
DEFAULT_DOMAIN_ID="8b2081d5-9662-40d9-a3db-2a3cf4dde3f7"
class RWQATTGRobotScgJsonConfigKeywords():
    """
    This Library allows to Configure the SCG using JSON API
    It conatains the Configuration APIs such as create, validate, update, and delete of configuration objects.
    """

    def __init__(self):
        self.sjc = None
        self.sjm = None
        self.sjr = None
        self.sje = None
        self.sja = None
        self.sjs = None
        self.snmp = None
        self.sjalarm = None
        self.pc = None
        self.ll = None
        self.ru = None
        self.wsgc= None
        self.req_api_ap_move = '/wsg/api/scg/aps/%s/move/%s'
        register_run_keyword('RWQATTGRobotScgJsonConfigKeywords','RWQATTGRobotScgJsonConfigKeywords.call_robot_keywords',1)
        pass

    def call_robot_keywords(self, keyword, *args):
        BuiltIn().run_keyword(PUBLIC_API_LOGIN,  os.getenv("SCG_ADMIN_USERNAME", "admin"), os.getenv("SCG_ADMIN_PASSWORD","ruckus1!"))
        return BuiltIn().run_keyword(keyword, *args) 

    def login_to_scg(self, scg_mgmt_ip='127.0.0.2', scg_port='8443',
                            username='admin', password='ruckus', model="carrier", pubapi_version=API_VERSION
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
        
        self.pubapi=PA.SCG200PublicApiV2(scg_mgmt_ip,model,pubapi_version)
        self.pubapi.login_to_publicapi(scg_mgmt_ip=scg_mgmt_ip,username=username,password=password)

        sjl = ScgJsonLogin()
        res, jsessionid = sjl.login(scg_mgmt_ip=scg_mgmt_ip, scg_port=scg_port,
                username=username, password=password)

        if not res:
            raise AssertionError("Failed to Login to SCG")

        self.set_scg_session(scg_mgmt_ip=scg_mgmt_ip, scg_port=scg_port, jsessionid=jsessionid)

        return jsessionid

    def login_to_scg_private_api(self, scg_mgmt_ip='127.0.0.2', scg_port='8443',
                                        username='admin', password='ruckus', model="carrier", pubapi_version="v3_1"
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
        try:
            self.pubapi=PA.SCG200PublicApiV2(scg_mgmt_ip,model,pubapi_version)
            self.pubapi.login_to_publicapi(scg_mgmt_ip=scg_mgmt_ip,username=username,password=password)
        except:
            pass
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

        if not jsessionid:
            raise AssertionError("Invalid jsessionid: %s" % jsessionid)

        self.sjc = SJ.ScgJsonConfig(scg_mgmt_ip=scg_mgmt_ip, scg_port=scg_port)
        self.sjm = SM.ScgJsonMonitorClient(scg_mgmt_ip=scg_mgmt_ip, scg_port=scg_port)
        self.sjr = SR.ScgJsonReport(scg_mgmt_ip=scg_mgmt_ip, scg_port=scg_port)
        self.sje = SE.ScgJsonMonitorEvents(scg_mgmt_ip=scg_mgmt_ip, scg_port=scg_port)
        self.sja = SA.ScgJsonConfigApZone(scg_mgmt_ip=scg_mgmt_ip, scg_port=scg_port)
        self.pc = PC.PMIP_Config(scg_mgmt_ip=scg_mgmt_ip, scg_port=scg_port)
        self.ll = LL.LicenseLib(scg_mgmt_ip=scg_mgmt_ip, scg_port=scg_port)
        self.sjs = SS.ScgJsonSyslog(scg_mgmt_ip=scg_mgmt_ip, scg_port=scg_port)
        self.snmp = SN.ScgJsonConfigSnmpAgent(scg_mgmt_ip=scg_mgmt_ip, scg_port=scg_port)
        self.sjalarm = SALARM.ScgJsonMonitorAlarms(scg_mgmt_ip=scg_mgmt_ip, scg_port=scg_port)
        self.wsgc = wsgc.WSGCAgent()
        self.sjc.set_jsessionid(jsessionid)
        self.sjm.set_jsessionid(jsessionid)
        self.sjr.set_jsessionid(jsessionid)
        self.sje.set_jsessionid(jsessionid)
        self.sja.set_jsessionid(jsessionid)
        self.pc.set_jsessionid(jsessionid)
        self.ll.set_jsessionid(jsessionid)
        self.sjs.set_jsessionid(jsessionid)
        self.snmp.set_jsessionid(jsessionid)
        self.sjalarm.set_jsessionid(jsessionid)


    def create_ggsn_service(self, **kwargs):
        """ 
        API used to create GGSN service

        URI: PUT /wsg/api/scg/ggsn/

        :param str domain_name: APN Resolution Domain Name

        :param str ggsn_ip: IP Address to Domain Name

        :param bool is_mvno_account: make True if API used to create GGSN in MVNO Account else False

        :return: True if GGSN created else False

        :rtype: boolean

        Example:
        | Create Ggsn Service | domain_name=ruckus.com | ggsn_ip=1.1.1.1 |

        """

        res = self.sjc.create_ggsn(**kwargs)
        if not res:
            raise AssertionError("Failed to Create GGSN")
            

        return True

    def set_application_log_level_python(self, *args):
            return self.call_robot_keywords(SET_APP_LOG_LEVEL, *args)
        
    ## available in 3.4 230 build
    def set_application_log_level(self, *args):
        """
        API used to set applications logs

        URI: PUT /wsg/api/scg/diagnostics/applications

        :param str scg_host_name: SCG HOST NAME

        :param str app_config_name: API | CaptivePortal | Cassandra | ... | Configurer | ... |Web

        :param str log_root_level: ERROR | WARN | INFO | DEBUG

        :return: True: if app log level updated

        :rtype: boolean

        Example
        | set_application_level(scg_host_name=172.19.16.180 | app_config_name=Configurer | log_root_level=ERROR |

        """
        if IS_PUBLIC:
            self.set_application_log_level_python(*args)
            return True
        else:
            res= self.sjs.set_app_log_level(*args)
        if not res:
            raise AssertionError("Failed to set application log level")


        return True

    def verify_syslog_facility(self, **kwargs):
        """
        verification of syslog facility
        """

        res= self.sjs.verify_syslog_facility(enable='true',**kwargs)
        if not res:
            raise AssertionError("Failed to verify application syslog facility")

        return True



    def update_ggsn_service(self, **kwargs):
        """
        API used to update GGSN Service

        URI: PUT /wsg/api/scg/ggsn/

        :param str t3response_timer: 2 to 5 [default: 3]

        :param str number_of_retries: 3 to 6 [default: 5]

        :param str echo_request_timer: 60 to 300 [default: 60]

        :param str response_timeout: 1 to 10 [default: 3]

        :param str dnsnumber_of_retries: 1 to 10 [default: 3]

        :param str domain_name: Domain Name 

        :param str ggsn_ip: IP Address of GGSN

        :param boolean is_mvno_account: True if MVNO Account else False

        :return: True if GGSN updated else False

        :rtype: boolean

        Example:

        | Update Ggsn Service | t3response_timer=3 | number_of_retries=5 | echo_request_timer=60 | response_timeout=3 | dnsnumber_of_retries=3 | 

        """
        res = self.sjc.update_ggsn(**kwargs)
        if not res:
            raise AssertionError("update GGSN Failed")
            

        return True

    def validate_ggsn_service(self, **kwargs):
        """
        API is used to validate GGSN Profile

        URI: GET /wsg/api/scg/ggsn/

        :param str t3response_timer: 2 to 5

        :param str number_of_retries: 3 to 6

        :param str echo_request_timer: 60 to 300

        :param str response_timeout: 1 to 10

        :param str dnsnumber_of_retries: 1 to 10

        :param str domain_name: Domain Name

        :param str ggsn_ip: IP Address of GGSN

        :param boolean is_mvno_account: True if MVNO Account else False

        :return: True if GGSN Profile is validated else False

        :rtype: boolean

        Example:

        | Validate Ggsn Service | t3response_timer=3 | number_of_retries=5 | echo_request_timer=60 | response_timeout=3 | dnsnumber_of_retries=3 |

        """

        res = self.sjc.validate_ggsn(**kwargs)
        if not res:
            raise AssertionError("validate GGSN failed")
            

        return True

    def add_dns_server_to_ggsn_service(self, **kwargs):

        """
        Add DNS Server ip to GGSN

        URI: PUT  /wsg/api/scg/ggsn/
        
        :param str dns_ip: DNS ip address can be added to GGSN service

        :return: True if add DNS ip success else False

        :rtype: boolean

        Example:

        | Add Dns Server To Ggsn Service | dns_ip=2.3.4.5 |

        """
        res = self.sjc.add_dns_server_to_ggsn(**kwargs)
        if not res:
            raise AssertionError("Failed to add DNS server ip to GGSN")
            

        return True


    def validate_dnsip_in_ggsn_service(self, **kwargs):
        """
        API is used to validate DNS IP in GGSN Profile
        
        URI: GET /wsg/api/scg/ggsn/

        :param str dns_ip: IP Address of DNS IP 

        :return: True if DNS IP Address is validated else False

        :rtype: boolean

        Example:

        | Validate Dnsip In Ggsn Service | dns_ip=2.3.4.5 |

        """

        res = self.sjc.validate_dnsip_in_ggsn(**kwargs)
        if not res:
            raise AssertionError("Validate DNS server ip in GGSN Failed")

        return True


    def update_dns_serverip_in_ggsn_service(self, **kwargs):
        """
        API used to update DNS Server in GGSN

        URI: PUT /wsg/api/scg/ggsn/
        
        :param str current_dns_ip: DNS IP address

        :param str new_dns_ip: New IP address of DNS Server

        :param str new_priority: New Priority of DNS IP

        :return: True if DNS Server in GGSN is updated else False

        :rtype: boolean

        Example:

        | Update Dns Serverip In Ggsn Service | current_dns_ip=2.3.4.5 | new_dns_ip=3.4.5.6 | new_priority=1 |

        """
        res = self.sjc.update_dns_server_in_ggsn(**kwargs)
        if not res:
            raise AssertionError("Failed to update DNS server ip in GGSN Service")
            
        return True

    def delete_dns_server_in_ggsn_service(self, **kwargs):
        """
        API is used to delete dns servers in GGSN

        URI: PUT /wsg/api/scg/ggsn/

        :param str dns_ip: dns server IP Address of GGSN

        :param boolean is_mvno_account: True | False

        :return: if dns servers in GGSN is deleted else False

        :rtype: boolean

        Example:

        | Delete Dns Serverip From Ggsn Service | dns_ip=3.4.5.6 |

        """
        res = self.sjc.delete_dns_server_in_ggsn(**kwargs)
        if not res:
            raise AssertionError("Failed to delete DNS server ip in GGSN service")
            
        return True

    def delete_ggsn_service(self, **kwargs):
        """
        API is used to delete GGSN Profile

        URI: GET /wsg/api/scg/ggsn/ 

        :param str domain_name: Domain Name

        :return: True if GGSN Profile is deleted else False

        :rtype: boolean

        Example:

        | Delete Ggsn Service | domain_name=ruckus.com |

        """
        res = self.sjc.delete_ggsn(**kwargs)
        if not res:
            raise AssertionError("Failed to delete GGSN Service")
            
        return True


    def create_radius_service(self, is_public_api=IS_PUBLIC, **kwargs):
        """ 
        API used to create RADIUS Service

        URI: POST /wsg/api/scg/aaaServers/proxy/

        :param str service_name: Name of Radius Service

        :param str description: Description

        :param str service_type: RADIUS | RADIUSAcct [default: RADIUS]

        :param str radius_accounting_support_backup: 0 | 1 [default: 0]

        :param str radius_support_backup: 0 | 1 [default: 0]

        :param str response_window: Response Window [default: 20]

        :param str zombie_period: ZombiePeriod [default: 40]

        :param str revive_interval: Revive Interval [default: 120]

        :param str noresponse_fail: No Response Fail [default: false]

        :param str primary_ip: Primary Server IP

        :param str primary_port: Primary Server Port  [default: 1812]

        :param str primary_share_secret: Primary Server Secret

        :param str secondary_ip: Secondary Server IP

        :param str secondary_port: Secondary Server Port

        :param str secondary_share_secret: Secondary Server Secret

        :return: True if RADIUS service created else False

        :rtype: boolean

        Example:

        | Create Radius Service | service_name=Auto_Radius_Server | service_type=RADIUS | radius_accounting_support_backup=0 | radius_support_backup=0 |
        |                       | primary_ip=1.2.3.4 | primary_port=1812 | primary_share_secret=testing123 |

        """

        if is_public_api == True:
            res=self.pubapi.create_radius_service(**kwargs)  
        else:
            res = self.sjc.create_radius_service(**kwargs)

        if not res:
            raise AssertionError("Create Radius Service Failed")

        return True

    def validate_radius_service(self, **kwargs):
        """
        API is used to Validate Radius Service
           
        URI: GET /wsg/api/scg/aaaServers/proxy/

        :param str service_name: Name of Radius Service

        :param str description: Description

        :param str service_type: RADIUS | RADIUSAcct

        :param str radius_accounting_support_backup: 0 | 1

        :param str radius_support_backup: 0 | 1 

        :param str response_window: Response Window 

        :param str zombie_period: ZombiePeriod

        :param str revive_interval: Revive Interval

        :param str noresponse_fail: No Response Fail

        :param str primary_ip: Primary Server IP

        :param str primary_port: Primary Server Port

        :param str primary_share_secret: Primary Server Secret

        :param str secondary_ip: Secondary Server IP

        :param str secondary_port: Secondary Server Port

        :param str secondary_share_secret: Secondary Server Secret

        :return: True if RADIUS service is validated else False

        :rtype: boolean

        Example:

        | Validate Radius Service | service_name=Auto_Radius_Server | service_type=RADIUS | radius_accounting_support_backup=0 | radius_support_backup=0 |
        |                          | primary_ip=1.2.3.4 | primary_port=1812 | primary_share_secret=testing123 |

        """
        res = self.sjc.validate_radius_service(**kwargs)
        if not res:
            raise AssertionError("Validate Radius Service Failed")
            

        return True


    def update_radius_service(self, is_public_api=IS_PUBLIC, **kwargs):
        """ 
        API used to update the RADIUS Service
        
        URI: PUT /wsg/api/scg/aaaServers/proxy/<radius_service_key>

        :param str current_service_name: Name of Radius Service

        :param str new_service_name: New Radius service name

        :param str description: Description

        :param str service_type: RADIUS | RADIUSAcct

        :param str radius_accounting_support_backup: 0 | 1

        :param str radius_support_backup: 0 | 1 

        :param str response_window: Response Window

        :param str zombie_period: ZombiePeriod

        :param str revive_interval: Revive Interval

        :param str noresponse_fail: No Response Fail

        :param str primary_ip: Primary Server IP

        :param str primary_port: Primary Server Port

        :param str primary_share_secret: Primary Server Secret

        :param str secondary_ip: Secondary Server IP

        :param str secondary_port: Secondary Server Port

        :param str secondary_share_secret: Secondary Server Secret

        :return: True if RADIUS service updated else False 

        :rtype: boolean

        Example:

        | Update Radius Service | current_service_name=Auto_Radius_Server | radius_support_backup=1 | secondary_ip=2.2.2.2 | secondary_port=1812 | 
        |                       | secondary_share_secret=testing098 |
    
        """
        
        if is_public_api == True:
            res=self.pubapi.update_radius_service(**kwargs)  
        else:
            res = self.sjc.update_radius_service(**kwargs)
        if not res:
            raise AssertionError("Update Radius Service Failed")
            

        return True


    def delete_radius_service(self, is_public_api=IS_PUBLIC, **kwargs):
        """ 
        API used to delete the Radius Service

        URI: DELETE /wsg/api/scg/aaaServers/proxy/<radius_service_key>

        :param str radius_service_name: Name of Radius Service

        :return: True if Radius Service deleted else False

        :rtype: boolean

        Example:

        | Delete Radius Service | radius_service_name=Auto_Radius_Server |

        """
        
        if is_public_api == True:
            res=self.pubapi.delete_radius_service(**kwargs)  
        else:
            res = self.sjc.delete_radius_service(**kwargs)
        if not res:
            raise AssertionError("Delete Radius Service Failed")
            
        return True

    def create_cgf_service(self, is_public_api=IS_PUBLIC, **kwargs):
        """
        API used to create CGF Service

        URI: POST /wsg/api/scg/cgfs?

        :param str cgf_service_name: Name of CGF Service 

        :param str description: Descrption 

        :param str charging_service_type: SEVER | LOCAL_BINARY_FILE | BOTH [default = SERVER]

        :param str gtp_echo_timeout: 60 to 300 [default: 60]

        :param str no_of_gtpecho_response: 3 to 6 [default: 5]

        :param str max_no_of_cdr_per_request: 1 to 10  [default: 1]

        :param str cdr_response_timeout: 5 to 300  [default: 5]

        :param str cdr_no_of_retries: 1 to 10  [default: 3]

        :param str record_limit: 1 to 65535  [default: 1000]

        :param str file_time_limit: 1 to 65535  [default: 60]

        :param str file_lifetime: 1 to 80  [default: 5]

        :param str server_ip: IP Address of Server

        :param str server_port: Port number

        :param str auto_export_ftp: True | False

        :param str ftp_host_ip: FTP Host

        :param str ftp_port: FTP Port

        :param str ftp_username: Username
        
        :param str ftp_password: Password

        :param str remote_directory: Remote Directory

        :param str interval: Daily | Hourly 

        :param str hour: Hours

        :param str minute: Minutes

        :param boolean enable_cdr_for_ttg: True | False

        :param boolean enable_cdr_for_direct_ip_access: True | False

        :param str cdr_type: Default_CDR | S_CDR  [default: Default_CDR]

        :param boolean send_sgsn_address: True | False

        :param boolean send_apn_network_identifier: True | False

        :param boolean send_pdp_type: True | False

        :param boolean send_served_pdp_address: True | False

        :param boolean send_diagnostic: True | False

        :param boolean send_cdr_node_id: True | False

        :param boolean send_cdr_local_record_sequence_number: True | False

        :param boolean send_apn_selection_mode: True | False

        :param boolean send_apn_operator_identifier: True | False

        :param boolean send_msisdn: True | False

        :param boolean send_charging_character_selection_mode: True | False

        :param boolean send_dynamic_mode_address_flag: True | False 

        :param boolean send_rat_type: True | False

        :param boolean list_of_traffic_volumes: True | False

        :param str cdr_node_id: CDR Node ID 

        :param boolean send_sgsn_plmn_id: True | False

        :param boolean send_wlan_node_id: True | False

        :param boolean send_wlan_local_record_sequence_number: True | False

        :param str lbo_node_id: LBO Node ID 

        :return: True if CGF Service created else False

        :rtype: boolean

        Example:

        | Create Cgf Service | cgf_service_name=Auto_CGF_Service | charging_service_type=SERVER | server_ip=3.3.3.3 | server_port=1812 |
        |                    | enable_cdr_for_ttg=True | cdr_type=Default_CDR |

        """
        if is_public_api == True  and os.getenv("API_VERSION", 'v4_0') == 'v5_0':
            res=self.pubapi.create_cgf_service(**kwargs)
        else:
            res = self.sjc.create_cgf_service(**kwargs)
        if not res:
            raise AssertionError("Failed to create CGF Service")
            
        return True

    def validate_cgf_service(self, **kwargs):
        """
        API used to validate CGF Service

        URI: GET /wsg/api/scg/cgfs?

        :param str cgf_service_name: Name of CGF Service

        :param str description: Descrption

        :param str charging_service_type: SEVER | LOCAL_BINARY_FILE | BOTH

        :param str gtp_echo_timeout: 60 to 300

        :param str no_of_gtpecho_response: 3 to 6

        :param str max_no_of_cdr_per_request: 1 to 10

        :param str cdr_response_timeout: 5 to 300

        :param str cdr_no_of_retries: 1 to 10

        :param str record_limit: 1 to 65535

        :param str file_time_limit: 1 to 65535

        :param str file_lifetime: 1 to 80

        :param str server_ip: IP Address of Server

        :param str server_port: Port number

        :param str auto_export_ftp: True | False

        :param str ftp_host_ip: FTP Host

        :param str ftp_port: FTP Port

        :param str ftp_username: Username

        :param str ftp_password: Password

        :param str remote_directory: Remote Directory

        :param str interval: Daily | Hourly

        :param str hour: Hours

        :param str minute: Minutes

        :param boolean enable_cdr_for_ttg: True | False

        :param boolean enable_cdr_for_direct_ip_access: True | False

        :param str cdr_type: Default_CDR | S_CDR

        :param boolean send_sgsn_address: True | False

        :param boolean send_apn_network_identifier: True | False

        :param boolean send_pdp_type: True | False

        :param boolean send_served_pdp_address: True | False

        :param boolean send_diagnostic: True | False

        :param boolean send_cdr_node_id: True | False

        :param boolean send_cdr_local_record_sequence_number: True | False

        :param boolean send_apn_selection_mode: True | False

        :param boolean send_apn_operator_identifier: True | False

        :param boolean send_msisdn: True | False

        :param boolean send_charging_character_selection_mode: True | False

        :param boolean send_dynamic_mode_address_flag: True | False 

        :param boolean send_rat_type: True | False 

        :param boolean list_of_traffic_volumes: True | False

        :param str cdr_node_id: CDR Node ID 

        :param boolean send_sgsn_plmn_id: True | False

        :param boolean send_wlan_node_id: True | False

        :param boolean send_wlan_local_record_sequence_number: True | False

        :param str lbo_node_id: LBO Node ID 

        :return: True if CGF Service created else False

        :rtype: boolean

        Example:

        | Validate Cgf Service | cgf_service_name=Auto_CGF_Service | charging_service_type=SERVER | server_ip=3.3.3.3 | server_port=1812 |
        |                      | enable_cdr_for_ttg=True | cdr_type=Default_CDR |

        """

        res = self.sjc.validate_cgf_service(**kwargs)
        if not res:
            raise AssertionError("Validate CGF Service Failed")
            

        return True


    def add_server_ip_to_cgf_service(self, **kwargs):
        """
        Adds Server IP to CGF Service if  charging service is SERVER

        URI: PUT /wsg/api/scg/cgfs/<cgf_service_key>

        :param str cgf_service_name: Name of CGF Service

        :param str server_ip: IP of the server

        :param str server_port: Port number

        :return: True if Service IP is added to the CGF service else False

        :rtype: boolean

        Example:

        | Add Server Ip To Cgf Service | server_ip=5.5.5.5 | server_port=1812 |

        """
        res = self.sjc.add_server_ip_to_cgf_service(**kwargs)
        if not res:
            raise AssertionError("Failed to add Server IP to cgf service")
            
        return True

    def validate_server_ip_in_cgf_service(self, **kwargs):
        """
        API used to validate the Server IP in CGF Service
        
        URI: GET /wsg/api/scg/cgfs? 

        :param str cgf_service_name: Name of CGF Service

        :param str server_ip: IP of the server

        :param str server_port: Port number

        :return: True if Server IP is validated in CGF service else False

        :rtype: boolean

        Example:

        | Validate Server Ip In Cgf Service | server_ip=5.5.5.5 | server_port=1812 |
                                                            
        """
        res = self.sjc.validate_server_ip_to_cgf_service(**kwargs)
        if not res:
            raise AssertionError("Validate server ip in CGF service Failed")
            
        return True


    def update_server_ip_in_cgf_service(self, **kwargs):
        """   
        API used to update Server IP in CGF Service 
              
        URI: PUT /wsg/api/scg/cgfs/<cgf_service_key>
              
        :param str cgf_service_name: Name of CGF Service

        :param str current_server_ip: IP of Sever to be changed

        :param str new_server_ip: IP of the server

        :param str new_server_port: Port number

        :param str new_priority: Priority of IP

        :return: True if Server IP is updated to the CGF service else False

        :rtype: boolean

        Example:
        
        | Update Server Ip In Cgf Service | cgf_service_name=Auto_CGF_Service | current_server_ip=5.5.5.5 | new_server_ip=5.6.4.5 | new_server_port=1813 |

        """ 
        res = self.sjc.update_server_ip_in_cgf_service(**kwargs)
        if not res:
            raise AssertionError("Failed to update ServerIP in ")
            
        return True

    def delete_server_from_cgf_service(self, **kwargs):
        """
        API used to delete Server IP from CGF service

        URI: PUT /wsg/api/scg/cgfs/<cgf_service_key>

        :param str cgf_service_name: Name of CGF Service

        :param str server_ip: IP Address

        :return: True if Server IP from CGF service deleted else False

        :rtype: boolean

        Example:

        | Delete Server Ip From Cgf Service | cgf_service_name=Auto_CGF_Service | server_ip=5.6.4.5 |

        """
        res = self.sjc.delete_server_from_cgf_service(**kwargs)
        if not res:
            raise AssertionError("Failed to delete Server IP in CGF Service")
            
        return True

    def update_cgf_service(self, **kwargs):
        """
        API used to update CGF Service

        URI: PUT /wsg/api/scg/cgfs?

        :param str current_cgf_service_name: Name of CGF Service

        :param str new_cgf_service_name: New CGF Service Name

        :param str description: Descrption

        :param str charging_service_type: SEVER | LOCAL_BINARY_FILE | BOTH

        :param str gtp_echo_timeout: 60 to 300

        :param str no_of_gtpecho_response: 3 to 6

        :param str max_no_of_cdr_per_request: 1 to 10

        :param str cdr_response_timeout: 5 to 300

        :param str cdr_no_of_retries: 1 to 10

        :param str record_limit: 1 to 65535

        :param str file_time_limit: 1 to 65535

        :param str file_lifetime: 1 to 80

        :param str server_ip: IP Address of Server

        :param str server_port: Port number

        :param str auto_export_ftp: True | False

        :param str ftp_host_ip: FTP Host

        :param str ftp_port: FTP Port

        :param str ftp_username: Username

        :param str ftp_password: Password

        :param str remote_directory: Remote Directory

        :param str interval: Daily | Hourly 

        :param str hour: Hours

        :param str minute: Minutes

        :param boolean enable_cdr_for_ttg: True | False

        :param boolean enable_cdr_for_direct_ip_access: True | False

        :param str cdr_type: Default_CDR | S_CDR

        :param boolean send_sgsn_address: True | False

        :param boolean send_apn_network_identifier: True | False

        :param boolean send_pdp_type: True | False

        :param boolean send_served_pdp_address: True | False

        :param boolean send_diagnostic: True | False

        :param boolean send_cdr_node_id: True | False

        :param boolean send_cdr_local_record_sequence_number: True | False

        :param boolean send_apn_selection_mode: True | False

        :param boolean send_apn_operator_identifier: True | False

        :param boolean send_msisdn: True | False

        :param boolean send_charging_character_selection_mode: True | False

        :param boolean send_dynamic_mode_address_flag: True | False

        :param boolean send_rat_type: True | False

        :param boolean list_of_traffic_volumes: True | False

        :param str cdr_node_id: CDR Node ID

        :param boolean send_sgsn_plmn_id: True | False

        :param boolean send_wlan_node_id: True | False

        :param boolean send_wlan_local_record_sequence_number: True | False 

        :param str lbo_node_id: LBO Node ID

        :return: True if CGF Service is updated else False

        :rtype: boolean 

        Example:

        | Update Cgf Service | current_cgf_service_name=Auto_CGF_Service | new_cgf_service_name=Auto_CGF | enable_cdr_for_ttg=True | cdr_type=S_CDR |
        |                    | send_sgsn_plmn_id=True |


        """
        res = self.sjc.update_cgf_service(**kwargs)
        if not res:
            raise AssertionError("Failed to Update CGF Service")
            
        return True

    def delete_cgf_service(self, is_public_api=IS_PUBLIC, **kwargs):
        """
        API used to delete CGF Services

        URI: DELETE /wsg/api/scg/cgfs/<cgf_service_keys>

        :param str cgf_service_name: Name of the CGF service Profile

        :return: True if CGF service is deleted successfully else False

        :rtype: boolean

        Example:

        | Delete Cgf Servie | cgf_service_name=Auto_CGF |

        """
        if is_public_api == True  and os.getenv("API_VERSION", 'v4_0') == 'v5_0':
            res=self.pubapi.delete_cgf_service(**kwargs)
        else:
            res = self.sjc.delete_cgf_service(**kwargs)
        if not res:
            raise AssertionError("Failed to delete CGF Service")
            
        return True

    def create_authentication_profile(self, is_public_api=IS_PUBLIC, **kwargs):
        """
        API used to create Authentication profile 

        URI: POST /wsg/api/scg/serviceProfiles/authentication/

        :param str auth_profile_name: Name of the Authentication Profile

        :param str description: Description about the profile

        :param str enable_3gpp_support: True | False

        :param str enable_hosted_aaa_support: True | False

        :param str mobile_country_code: Mobile Country Code

        :param str mobile_network_code: Mobile Network Code

        :param str interim_acct_interval: Interim Accounting interval 

        :param str session_timeout: Session timeout in hosted AAA Radius settings

        :param str session_idle_timeout: Session Idle time out int hosted AAA Radius settings

        :param str default_auth_service_nomatch_realm: Name of default Authentication service

        :param str nomatch_realm_auth_method: GPPCallFlow | NonGPPCallFlow

        :param str dynamic_vlanid_nomatch_realm: Dynamic VLAN id 

        :param str default_auth_service_no_realm: Name of default Authentication service

        :param str norealm_auth_method: GPPCallFlow | NonGPPCallFlow

        :param str dynamic_vlanid_no_realm: Dynamic VLAN id

        :param str realm_authservice_name: Authentication Service name

        :param str realm: Realm name

        :param str realm_dynamic_vlanid: Dynamic VLAN id of Realm

        :param str realm_auth_method: GPPCallFlow | NonGPPCallFlow

        :return: True if Athentication profile created else False

        :rtype: boolean

        Example:

        | Create Authentication Profile | auth_profile_name=Auto_auth_profile | default_auth_service_nomatch_realm=Auto_Radius_Server |
        |                                | default_auth_service_no_realm=Auto_Radius_Server | realm=relam.3gpp.org | 
        |                                | realm_authservice_name=Auto_Radius_Server |

        """

        if is_public_api == True  and os.getenv("API_VERSION", 'v4_0') == 'v5_0':
            no_realm_type= self.pubapi.get_any_auth_service_type(service_name=kwargs["default_auth_service_no_realm"])
            no_match_realm_type= self.pubapi.get_any_auth_service_type(service_name=kwargs["default_auth_service_nomatch_realm"])
            kwargs['no_realm_type']= no_realm_type
            kwargs['no_match_realm_type']= no_match_realm_type
            res=self.pubapi.create_authentication_profile(**kwargs)
        
        elif is_public_api == True:
            norealm_id,norealm_type = self.sjc._get_auth_service_id_and_type(service_name=kwargs["default_auth_service_no_realm"])
            nomatchrealm_id,nomatchrealm_type = self.sjc._get_auth_service_id_and_type(service_name=kwargs["default_auth_service_nomatch_realm"])
            res=self.pubapi.create_authentication_profile(no_realm_type=norealm_type,no_match_realm_type=nomatchrealm_type,**kwargs)
        
        else:
            res = self.sjc.create_authentication_profile(**kwargs)
        if not res:
            raise AssertionError("Failed to create Authentication profile")
            
        return True

    def validate_authentication_profile(self, **kwargs):
        """
        API used to validate Authentication profile 
                  
        URI: GET /wsg/api/scg/serviceProfiles/authentication/
                  
        :param str auth_profile_name: Name of the Authentication Profile

        :param str description: Description about the profile

        :param str enable_3gpp_support: True | False

        :param str enable_hosted_aaa_support: True | False

        :param str mobile_country_code: Mobile Country Code

        :param str mobile_network_code: Mobile Network Code

        :param str interim_acct_interval: Interim Accounting interval 

        :param str session_timeout: Session timeout in hosted AAA Radius settings

        :param str session_idle_timeout: Session Idle time out int hosted AAA Radius settings

        :param str default_auth_service_nomatch_realm: Name of default Authentication service

        :param str nomatch_realm_auth_method: Authorization method

        :param str dynamic_vlanid_nomatch_realm: Dynamic VLAN id 

        :param str default_auth_service_no_realm: Name of default Authentication service

        :param str norealm_auth_method: Authorization method

        :param str dynamic_vlanid_no_realm: Dynamic VLAN id

        :param str realm_authservice_name: Authentication Service name

        :param str realm: Realm name 

        :param str realm_dynamic_vlanid: Dynamic VLAN id of Realm

        :param str realm_auth_method: Authorization Method

        :return: True if Athentication profile validated else False

        :rtype: boolean

        Example:

        | Validate Authentication Profile | auth_profile_name=Auto_auth_profile | default_auth_service_nomatch_realm=Auto_Radius_Server |
        |                                | default_auth_service_no_realm=Auto_Radius_Server | realm=relam.3gpp.org | 
        |                                | realm_authservice_name=Auto_Radius_Server |

        """
        res = self.sjc.validate_authentication_profile(**kwargs)
        if not res:
            raise AssertionError("Validate Auth profile Failed")
            
        return True


    def add_authentication_service_per_realm_to_authentication_profile(self, is_public_api=IS_PUBLIC, **kwargs):
        """
        Adds Realm to Authentication Service per Realm in Authentication profile

        URI: PUT /wsg/api/scg/serviceProfiles/authentication/<auth_profile_key>

        :param str realm: Realm to be added

        :param str auth_profile_name: Authentication profile name 

        :param str auth_service_name: Authentication Service name to be added

        :param str auth_method: Authentication Method

        :param str dynamic_vlan_id: Dynamic VLAN ID of adding Realm

        :return: True if Realm added to Authentication Service per Realm else False

        :rtype: boolean
        
        Example: 

        | Add Authentication Service Per Realm To Authentication Profile | realm=realm.com | auth_profile_name=Auto_auth_profile | 
        |                                                                | auth_service_name=Auto_Radius_Server | dynamic_vlan_id=2 |
        """
        
        if is_public_api == True and os.getenv("API_VERSION", 'v4_0') == 'v5_0':
            realm_type= self.pubapi.get_any_auth_service_type(service_name=kwargs["auth_service_name"])
            kwargs['realm_type']=realm_type
            res=self.pubapi.add_nondefaultrealm_to_authentication_profile(**kwargs)
        
        elif is_public_api == True:
            realm_id,realm_type = self.sjc._get_auth_service_id_and_type(service_name=kwargs["auth_service_name"])
            res=self.pubapi.add_nondefaultrealm_to_authentication_profile(realm_type=realm_type,**kwargs)
        
        else:
            res = self.sjc.add_nondefaultrealm_to_authentication_profile(**kwargs)
        if not res:
            raise AssertionError("Failed to add Authentication Servie per Realm ")
            
        return True

    def validate_authentication_service_per_realm_in_authentication_profile(self, **kwargs):
        """
        API used to Validate the NonDefaultRealm in Authentication Profile

        URI: GET /wsg/api/scg/serviceProfiles/authentication/

        :param str auth_profile_name: Name of the Authentication Profile

        :param str auth_service_realm: Realm name

        :param str auth_method: NonGPPCallFlow | GPPCallFlow | RestoreData | NoAutz | UpdateGPRSLocation

        :param str realm_auth_service_name: Name of Authentication Service of Realm

        :param str dynamic_vlan_id: Dynamic VLAN id

        :return: True if Validate NonDefaultRealm is success else False

        :rtype: boolean

        Example: 

        | Validate Authentication Service Per Realm In Authentication Profile | realm=realm.com | auth_profile_name=Auto_auth_profile |
        |                                                                     | auth_service_name=Auto_Radius_Server | dynamic_vlan_id=2 |

        """
        res = self.sjc.validate_nondefaultrealm_in_authentication_profile(**kwargs)
        if not res:
            raise AssertionError("Validate auth service per Realm is fail")
            
        return True


    def update_authentication_service_per_realm_in_authentication_profile(self, *args):
        """
        API used to Update the NonDefaultRealm in Authentication Profile

        URI: PUT /wsg/api/scg/serviceProfiles/authentication/<auth_profile_key>

        :param str current_realm: Name of Realm to be updated

        :param str new_realm: Name of Realm 

        :param str auth_profile_name: Name of the Authentication Profile

        :param str auth_method: NonGPPCallFlow | GPPCallFlow | RestoreData | NoAutz | UpdateGPRSLocation

        :param str realm_auth_service_name: Name of Authentication Service of Realm

        :param str dynamic_vlan_id: Dynamic VLAN id
        
        :return: True if Validate NonDefaultRealm is success else False

        :rtype: boolean

        Example:

        | Update Authentication Service Per Realm In Authentication Profile | auth_profile_name=Auto_auth_profile | current_realm=realm.com | 
        |                                                                    | new_realm=testrealm.com | dynamic_vlan_id=3 |

        """
        if IS_PUBLIC:
             self.update_authentication_profile_python(*args)
             return True
        else:
            res = self.sjc.update_nondefaultrealm_in_authentication_profile(**kwargs)
        if not res:
            raise AssertionError("Failed to Update auth service per Realm")
            
        return True

    def delete_authentication_service_per_realm_from_authentication_profile(self, **kwargs):
        """
        API used to delete the NonDefaultRealm entry in Authentication Profile

        URI: PUT /wsg/api/scg/serviceProfiles/authentication/<auth_profile_key>

        :param str auth_profile_name: Name of the Authentication Profile

        :param str realm: Name of Realm to be deleted

        :return: True if Realm deleted else False

        :rtype: boolean

        Example:

        | Delete Authentication Service Per Realm From Authentication Profile | auth_profile_name=Auto_auth_profile | realm=testrealm.com |

        """
        res = self.sjc.delete_nondefaultrealm_from_authentication_profile(**kwargs)
        if not res:
            raise AssertionError("Failed to delete Auth service per Realm")
            
        return True
    
    def update_authentication_profile_python(self, *args):
        return self.call_robot_keywords(UPDATE_AUTHENTICATION_API, *args)
    
    def update_authentication_profile(self, *args):
        """
        API used to update the Authentication profile

        URI: PUT /wsg/api/scg/serviceProfiles/authentication/<auth_profile_key>
        
        :param str current_auth_name: Name of the Authentication Profile to be updated

        :param str new_auth_name: Name of New Authentication Profile

        :param str description: Description about the profile

        :param str enable_3gpp_support: True | False

        :param str enable_hosted_aaa_support: True | False

        :param str mobile_country_code: Mobile Country Code

        :param str mobile_network_code: Mobile Network Code

        :param str interim_acct_interval: Interim Accounting interval 

        :param str session_timeout: Session timeout in hosted AAA Radius settings

        :param str session_idle_timeout: Session Idle time out int hosted AAA Radius settings

        :param str default_auth_service_nomatch_realm: Name of default Authentication service

        :param str nomatch_realm_auth_method: Authorization method

        :param str dynamic_vlanid_nomatch_realm: Dynamic VLAN id 

        :param str default_auth_service_no_realm: Name of default Authentication service

        :param str norealm_auth_method: Authorization method

        :param str dynamic_vlanid_no_realm: Dynamic VLAN id

        :return: True if Athentication profile updated else False

        :rtype: boolean

        Example:

        | Update Authentication Profile | current_auth_profile_name=Auto_auth_profile | default_auth_service_nomatch_realm=Auto_Radius |
        |                               | default_auth_service_no_realm=Auto_Radius | norealm_auth_method=Non3GPPSupport |

        |auth_profile_name=auth_prof | service_name=None | service_type=NA | realm=NO Match | auth_method=GPPCallFlow |
        """
        if  IS_PUBLIC:
            self.update_authentication_profile_python(*args)
            return True
        else:
            res = self.sjc.update_authentication_profile(**kwargs)
        if not res:
            raise AssertionError("update Auth Profile failed")
            
        return True

    def delete_authentication_profile(self, is_public_api=IS_PUBLIC, **kwargs):
        """
        API used to Delete the Authentication Profile

        URI: DELTE /wsg/api/scg/serviceProfiles/authentication/<auth_profile_key>

        :param str auth_profile_name: Name of Authentication profile to be Deleted

        :return: True if Authentication Profile deleted else False

        :rtype: boolean

        Example:

        | Delete Authentication Profile | auth_profile_name=Auto_auth_profile |

        """
        
        if is_public_api == True:
            res=self.pubapi.delete_authentication_profile(**kwargs)  
        else:
            res = self.sjc.delete_authentication_profile(**kwargs)
        if not res:
            raise AssertionError("Delete Auth Profile Failed")
            
        return True

    def create_accounting_profile(self, is_public_api=IS_PUBLIC, **kwargs):
        """
        API used to creates Accounting Profile

        URI: POST /wsg/api/scg/serviceProfiles/accounting?

        :param str acct_profile_name: Name of the Accounting profile to be created

        :param str description: descrption about the accounting profile

        :param str default_acct_service_nomatch_realm: Default Accounting Service No Matching Realm

        :param str default_acct_service_no_realm: Default Accounting Service No Realm

        :param str realm: Realm name to be added to Accounting Service per Realm

        :param str realm_acctservice_name: Name of Accounting Service in Accounting Service per Realm

        :return: True if Accounting Profile created else False

        :rtype: boolean

        Example: 

        | Create Accounting Profile | acct_profile_name=Auto_acct_profile | default_acct_service_nomatch_realm=Auto_RadiusAcct |
        |                           | default_acct_service_no_realm=Auto_RadiusAcct |

        """
        
        if is_public_api == True and os.getenv("API_VERSION", 'v4_0') == 'v5_0':
            if "default_acct_service_no_realm" in kwargs and kwargs['default_acct_service_no_realm']:
                norealm_service_type= self.pubapi.get_any_acct_service_type(service_name=kwargs["default_acct_service_no_realm"])

            if "default_acct_service_nomatch_realm" in kwargs and kwargs['default_acct_service_nomatch_realm']:
                nomatch_service_type= self.pubapi.get_any_acct_service_type(service_name=kwargs["default_acct_service_nomatch_realm"])
            
            kwargs['norealm_service_type']=norealm_service_type
            kwargs['nomatch_service_type']=nomatch_service_type                                
            res=self.pubapi.create_accounting_profile(**kwargs)
            
        elif is_public_api == True:
            if "default_acct_service_nomatch_realm" in kwargs or "default_acct_service_no_realm" in kwargs:
                if kwargs["default_acct_service_nomatch_realm"]:
                    acctservice_type = self.sjc._get_acct_details(name=kwargs["default_acct_service_nomatch_realm"])["serviceType"]
                    nomatch_service_type = acctservice_type
                    kwargs['nomatch_service_type']= nomatch_service_type
                
                if kwargs["default_acct_service_no_realm"]:
                    acctservice_type = self.sjc._get_acct_details(name=kwargs["default_acct_service_no_realm"])["serviceType"]
                    norealm_service_type = acctservice_type
                    kwargs['norealm_service_type']= norealm_service_type
            res=self.pubapi.create_accounting_profile(**kwargs)
        else:
            res = self.sjc.create_accounting_profile(**kwargs)
            
        if not res:
            raise AssertionError("create Accounting Profile Failed")
            
        return True

    def validate_accounting_profile(self, **kwargs):
        """
        API used to Validate Accounting Profile
        
        URI: GET /wsg/api/scg/serviceProfiles/accounting/<acct_profile_key>?
                                                             
        :param str acct_profile_name: Name of the Accounting profile

        :param str description: descrption about the accounting profile 

        :param str default_acct_service_nomatch_realm: Default Accounting Service No Matching Realm

        :param str default_acct_service_no_realm: Default Accounting Service No Realm

        :param str realm: Realm name of Accounting Service per Realm

        :param str realm_acctservice_name: Name of Accounting Service in Accounting Service per Realm

        :return: True if Accounting Profile validated else False

        :rtype: boolean

        Example:

        | Validate Accounting Profile | acct_profile_name=Auto_acct_profile | default_acct_service_nomatch_realm=Auto_RadiusAcct |
        |                           | default_acct_service_no_realm=Auto_RadiusAcct |


        """
        res = self.sjc.validate_accounting_profile(**kwargs)
        if not res:
            raise AssertionError("validate accounting profile failed")
            
        return True


    def add_accounting_service_per_realm_to_accounting_profile(self, is_public_api=IS_PUBLIC, **kwargs):
        """
        Adds Accounting Service per Realm to Accounting profile 

        URI: PUT /wsg/api/scg/serviceProfiles/accounting/<acct_profile_key> 

        :param str acct_profile_name: Accounting Profile name

        :param str realm: Realm to be added to Accounting Profile

        :param str acct_service_name: Name of Accounting Service

        :return: True if Adds Realm to Accounting Profile

        :rtype: boolean 

        Example:

        | Add Accounting Service Per Realm To Accounting Profile | acct_profile_name=Auto_acct_profile | realm=acctrealm.com | 
        |                                                        | acct_service_name=Auto_RadiusAcct |

        """
        
        if is_public_api == True and os.getenv("API_VERSION", 'v4_0') == 'v5_0':
            if "acct_service_name" in kwargs and kwargs['acct_service_name']:
                service_type= self.pubapi.get_any_acct_service_type(service_name=kwargs["acct_service_name"])
                kwargs['service_type']=service_type 
            res=self.pubapi.add_nondefaultrealm_to_accounting_profile(**kwargs)
        
        elif is_public_api == True:
            if "acct_service_name" in kwargs:
                if kwargs["acct_service_name"]:
                    acctservice_type = self.sjc._get_acct_details(name=kwargs["acct_service_name"])["serviceType"]
                    res=self.pubapi.add_nondefaultrealm_to_accounting_profile(service_type=acctservice_type,**kwargs)
                else:
                    res=self.pubapi.add_nondefaultrealm_to_accounting_profile(**kwargs)
            else:
                    res=self.pubapi.add_nondefaultrealm_to_accounting_profile(**kwargs)
                      
        else:
            res = self.sjc.add_nondefaultrealm_to_accounting_profile(**kwargs)
        if not res:
            raise AssertionError("Faled to add acct service per Realm")
            
        return True

    def validate_accounting_service_per_realm_in_accounting_profile(self, **kwargs):
        """
        Validate Accounting Service per Realm in Accounting profile

        URI: GET /wsg/api/scg/serviceProfiles/accounting/<acct_profile_key>

        :param str acct_profile_name: Accounting Profile name

        :param str realm: Realm to be validated in Accounting Profile

        :param str acct_service_name: Name of Accounting Service

        :return: True if validate Realm in Accounting Profile else False

        :rtype: boolean

        Example:

        | Validate Accounting Service Per Realm In Accounting Profile | acct_profile_name=Auto_acct_profile | realm=acctrealm.com | 
        |                                                              | acct_service_name=Auto_RadiusAcct |

        """
        res = self.sjc.validate_nondefaultrealm_in_accounting_profile(**kwargs)
        if not res:
            raise AssertionError("Validate acct service per Realm failed")
            
        return True



    def update_accounting_service_per_realm_in_accounting_profile(self, **kwargs):
        """
        API used to update the Accounting Service per Realm

        URI: PUT /wsg/api/scg/serviceProfiles/accounting/<acct_profile_key>

        :param str current_realm: Name of the Realm to be updated

        :param str new_realm: New name of Realm

        :param str acct_profile_name: Name of the Accountign profile

        :param str realm_acct_service_name: Accounting Service of Realm

        :return: True if update Realm success else False

        :rtype: boolean

        Example:

        | Update Accounting Service Per Realm In Accounting Profile | current_realm=acctrealm.com | new_realm=new_realm.com | 
        r                                                           | acct_profile_name=Auto_acct_profile | realm_acct_service_name=Auto_RadiusAcct |

        """
        res = self.sjc.update_nondefaultrealm_in_accounting_profile(**kwargs)
        if not res:
            raise AssertionError("update acct service per Realm failed")
            

        return True

    def delete_accounting_service_per_realm_from_accounting_profile(self, **kwargs):
        """
        API used to delete the Realm in Accounting profile

        URI: PUT /wsg/api/scg/serviceProfiles/accounting/<acct_profile_key>

        :param str acct_profile_name: Name of the Accounting Profile

        :param str realm: Name of the Realm

        :return: True if Realm is deleted else False

        :rtype: boolean

        Example:

        | Delete Accounting Service Per Realm From Accounting Profile | acct_profile_name=Auto_acct_profile | realm=new_realm.com |

        """
        res = self.sjc.delete_nondefaultrealm_from_accounting_profile(**kwargs)
        if not res:
            raise AssertionError("Failed to delete acct service per Realm")
            

        return True

    def update_accounting_profile(self, **kwargs):
        """
        API used to update the the Accounting Profile

        URI: PUT /wsg/api/scg/serviceProfiles/accounting/<acct_profile_key>

        :param str current_acct_name: Name of the Accounting profile to be modified

        :param str new_acct_name: New Name of Accounting Profile

        :param str default_acct_service_nomatch_realm: Default Accounting Service no matching realm

        :param str default_acct_service_no_realm: Default Accounting Service no Realm

        :return: True if update success else False

        :rtype: boolean

        Example: 

        | Update Accounting Profile | current_acct_name=Auto_acct_profile | default_acct_service_nomatch_realm=Auto_RadiusAcct-2 | 
        |                           | default_acct_service_no_realm=Auto_RadiusAcct-3 |

        """
        res = self.sjc.update_accounting_profile(**kwargs)
        if not res:
            raise AssertionError("update accounting profile failed")
            

        return True

    def delete_accounting_profile(self, is_public_api=IS_PUBLIC, **kwargs):
        """
        API used to delete the Accounting profile

        URI: DELETE /wsg/api/scg/serviceProfiles/accounting/<acct_profile_key>

        :param str acct_profile_name: Name of the Accounting profile

        :return: True if Accounting profile deleted successfully else False

        :rtype: boolean

        Example:

        | Delete Accounting Profile | acct_profile_name=Auto_acct_profile |

        """
        
        if is_public_api == True:
            res=self.pubapi.delete_accounting_profile(**kwargs)  
        else:
            res = self.sjc.delete_accounting_profile(**kwargs)
        if not res:
            raise AssertionError("Failed to delete accounting profile")
            

        return True

    def create_hotspot_profile(self, is_public_api=IS_PUBLIC, **kwargs):
        """
        API used to create Hotspot profile

        URI: POST /wsg/api/scg/hotspotsProfile?

        :param str hotspot_profile_name: Name of Hotspot Profile

        :param str access_type: INTERNAL | EXTERNAL

        :param str smart_client_mode: enable | none | only

        :param str smart_client_info: Information about the smart client

        :param str second_redirect_type: start | user

        :param str authentication_url: Logon URL

        :param str redirect_url: Start Page URL

        :param str session_time: Session Timeout, 2 to 14400 [default: 1440] 

        :param str grace_period: Grace Period, 1 to 143999 [default: 60]

        :param str location_name: Name of the location

        :param str location_id: Location ID

        :return: True if Hotspot created else False

        :rtype: boolean

        Example:

        | Create Hotspot Profile | hotspot_profile_name=Auto_hotspot_profile | access_type=INTERNAL |

        """  
        
        if is_public_api == True:
            res=self.pubapi.create_hotspot_profile(**kwargs)  
        else:     
            res = self.sjc.create_hotspot_profile(**kwargs)
        if not res:
            raise AssertionError("Failed to create Hotdpot profile")
            

        return True

    def validate_hotspot_profile(self, **kwargs):
        """
        API is used to validate Hotspot Profile
        
        URI: GET /wsg/api/scg/hotspotsProfile? 

        :param str hotspot_profile_name: Name of Hotspot Profile

        :param str access_type: INTERNAL | EXTERNAL

        :param str smart_client_mode: enable | none | only

        :param str smart_client_info: Information about the smart client

        :param str second_redirect_type: start | user

        :param str authentication_url: Logon URL

        :param str redirect_url: Start Page URL

        :param str session_time: Session Timeout

        :param str grace_period: Grace Period

        :param str location_name: Name of the location

        :param str location_id: Location ID

        :return: True if Hotspot Profile is validated else False

        :rtype: boolean

        Example:

        | Validate Hotspot Profile | hotspot_profile_name=Auto_hotspot_profile | access_type=INTERNAL | smart_client_mode=none | second_redirect_type=start |

        """
        res = self.sjc.validate_hotspot_profile(**kwargs)
        if not res:
            raise AssertionError("Failed to Validate Hotspot profile")
            

        return True


    def add_walledgarden_to_hotspot_profile(self, **kwargs):
        """
        API used to add the WalledGarden to Hotspot Profile

        URI: PUT /wsg/api/scg/hotspotsProfile/<hotspot_profile_key>

        :param str hotspot_profile_name: Name of the Hotspot Profile

        :param str walledgarden: ip or iprange 

        :return: True if WalledGarden addedd successfully else False

        :rtype: boolean

        Example:

        | Add Walledgarden To Hotspot Profile | hotspot_profile_name=Auto_hotspot_profile | walledgarden=1.1.1.1 |

        """
        res = self.sjc.add_walledgarden_to_hotspot_profile(**kwargs)
        if not res:
            raise AssertionError("Failed to add walledgarden to hotspot profile")
            

        return True

    def validate_walledgarden_in_hotspot_profile(self, **kwargs):
        """
        API used to validate the WalledGarden in Hotspot Profile

        URI: GET /wsg/api/scg/hotspotsProfile?

        :param str hotspot_profile_name: Name of the Hotspot Profile

        :param str walledgarden: ip or iprange

        :return: True if validation success else False

        :rtype: boolean

        Example:

        | Validate Walledgarden In Hotspot Profile | hotspot_profile_name=Auto_hotspot_profile | walledgarden=1.1.1.1 |

        """
        res = self.sjc.validate_walledgarden_in_hotspot(**kwargs)
        if not res:
            raise AssertionError("Failed to Validate walledgarden")
            
        return True


    def update_walledgarden_in_hotspot_profile(self, **kwargs):
        """
        API used to update the WalledGarden in Hotspot Profile

        URI: PUT /wsg/api/scg/hotspotsProfile/<hotspot_profile_key>

        :param str hotspot_profile_name: Name of the Hotspot Profile

        :param str current_walledgarden: ip or iprange 

        :param str new_walledgarden: ip or iprange

        :return: True if WalledGarden updated successfully else False

        :rtype: boolean

        Example:

        | Update Walledgarden In Hotspot Profile |  hotspot_profile_name=Auto_hotspot_profile | current_walledgarden=1.1.1.1 | new_walledgarden=2.2.2.2 |

        """
        res = self.sjc.update_walledgarden_in_hotspot(**kwargs)
        if not res:
            raise AssertionError("Update walledgarden inhotspot profile failed")
            

        return True

    def delete_walledgarden_entry_from_hotspot_profile(self, **kwargs):
        """
        API used to delete the WalledGarden from Hotspot Profile

        URI: PUT /wsg/api/scg/hotspotsProfile/<hotspot_profile_key>

        :param str hotspot_profile_name: Name of the Hotspot Profile

        :param str walledgarden: ip or iprange 

        :return: True if WalledGarden deleted successfully else False

        :rtype: boolean

        Example:

        | Delete Walledgarden From Hotspot Profile | hotspot_profile_name=Auto_hotspot_profile | walledgarden=2.2.2.2 |

        """
        res = self.sjc.delete_walledgarden_entry_from_hospot_profile(**kwargs)
        if not res:
            raise AssertionError("delete walledgarden failed")
            

        return True

    def update_hotspot_profile(self, **kwargs):
        """
        API is used to update Hotspot Profile

        URI: /wsg/api/scg/hotspotsProfile/<hotspot_recvd_keys>

        :param str current_profile_name: Original Name of Hotspot Profile

        :param str new_profile_name: New Name of Hotspot Profile

        :param str new_descripton: New Description of Hotspot Profile

        :param str access_type: INTERNAL | EXTERNAL

        :param str smart_client_mode: enable | none | only

        :param str smart_client_info: Information about the smart client

        :param str second_redirect_type: start | user

        :param str authentication_url: Logon URL

        :param str redirect_url: Start Page URL

        :param str session_time: Session Timeout

        :param str grace_period: Grace Period

        :param str location_id: Location id

        :param str location_name: Name of the Location

        :return: True if Hotspot created else False

        :rtype: boolean

        Example:

        | Update Hotspot Profile | current_profile_name=Auto_hotspot_profile | smart_client_mode=enable | session_time=1000 | grace_period=60 |

        """
        res = self.sjc.update_hotspot_profile(**kwargs)
        if not res:
            raise AssertionError("Falied to update Hotspot Profile")
            

        return True

    def delete_hotspot_profile(self, **kwargs):
        """
        API used to delete Hotspot profile

        URI: DELETE /wsg/api/scg/hotspotsProfile/<hotspot_profile_key>

        :param str hotspot_name: Name of Hotspot profile

        :return: True if Hotspot Profile deleted else False

        :rtype: boolean

        Example: 

        | Delete Hotspot Profile | hotspot_name=Auto_hotspot_profile |

        """
        res = self.sjc.delete_hotspot_profile(**kwargs)
        if not res:
            raise AssertionError("Failed to Delete Hotspot Profile")
            

        return True
    
    def create_aaa_profile_in_apzone(self, is_public_api=IS_PUBLIC, **kwargs):
        """
        Create the AAA with respective AP zone

        URI: POST /wsg/api/scg/aaaServers/zone/

        :param str aaa_name: Name of AAA to be created

        :param str zone_name: Name of the AP zone 

        :param str radius_type: RADIUS | RADIUSAcct

        :param str enable_secondary_radius: 0 | 1

        :param str primary_radius_ip: primary server ip address 

        :param str primary_radius_port: primary server port number

        :param str primary_radius_share_secret: primary server shared secret

        :param str response_window: Health check policy Response Window

        :param str zombie_period: Health check policy Zombie Period

        :param str revive_interval: Health check policy Revive Interval

        :param str noresponse_fail: true | false

        :param str secondary_radius_ip: secondary server ip address

        :param str secondary_radius_port: secondary server port number

        :param str secondary_radius_share_secret: secondary server shared secret
        
        :param str ad_ip: Oracle Active Directory Server IP
        
        :param str global_catalog_ad: some property Oracle Active Directory Server
        
        :param str windows_domainname: Windows OS case domain name for Oracle Active Directory Server
        
        :param str admin_domainname: Windows OS case administrator domain name for Oracle Active Directory Server
        
        :param str admin_domainname: Windows OS case administrator password  for Oracle Active Directory Server
        
        :param str ldap_ip: IP of open LDAP Server
        
        :param str ldap_domainname: Domain Name open LDAP Server Ex: dc=ruckus,dc=com
        
        :param str ldap_search_filter: search filter when fetching station user info LDAP Server
        
        :param str key_attr: key attribute when fetching station user info LDAP Server

        :return: True if AAA created else False

        :rtype: boolean

        Example:

        | Create Aaa Profile In Apzone | aaa_name=Auto_aaa | zone_name=Auto_apzone | radius_type=RADIUS | primary_radius_ip=1.1.1.1 | 
        |                              | primary_radius_port=1812 | primary_radius_share_secret=testing123 |

        """
        
        if is_public_api == True:
            res=self.pubapi.create_aaa_profile(**kwargs)  
        else:
            res = self.sjc.create_aaa_profile(**kwargs)
        if not res:
            raise AssertionError("Failed to create aaa profile")
            

        return True


    def validate_aaa_profile_in_apzone(self, **kwargs):
        """
        
        API is used to validate AAA Profile

        URI: GET /wsg/api/scg/aaaServers/zone/byZone/  

        :param str aaa_name: Name of the AAA Profile

        :param str domain_label: Name of the Domain

        :param str zone_name: Name of the AP zone 

        :param str radius_type: RADIUS | RADIUSAcct

        :param str enable_secondary_radius: 0 | 1

        :param str primary_radius_ip: primary server ip address 

        :param str primary_radius_port: primary server port number

        :param str primary_radius_share_secret: primary server shared secret

        :param str response_window: Health check policy Response Window

        :param str zombie_period: Health check policy Zombie Period

        :param str revive_interval: Health check policy Revive Interval

        :param str noresponse_fail: True | False

        :param str secondary_radius_ip: secondary server ip address

        :param str secondary_radius_port: secondary server port number

        :param str secondary_radius_share_secret: secondary server shared secret

        :return: True if AAA profile is validated  else False

        :rtype: boolean

        Example:              
                              
        | Validate Aaa Profile In Apzone | aaa_name=Auto_aaa | zone_name=Auto_apzone | radius_type=RADIUS | primary_radius_ip=1.1.1.1 | 
        |                                | primary_radius_port=1812 | primary_radius_share_secret=testing123 |

        """
        res = self.sjc.validate_aaa_profile(**kwargs)
        if not res:
            raise AssertionError(" Failed to validate aaa profile")
            
        return True


    def update_aaa_profile_in_apzone(self, **kwargs):

        """
        API used to update AAA profile

        URI: PUT '/wsg/api/scg/aaaServers/zone/<aaa_profile_key>
        
        :param str current_aaa_name: Name of AAA profile

        :param str new_aaa_name: New Name of AAA profile

        :param str zone_name: Name of the AP zone 

        :param str domain_label: Name of the Domain

        :param str enable_secondary_radius: 0 | 1

        :param str primary_radius_ip: primary server ip address 

        :param str primary_radius_port: primary server port number

        :param str primary_radius_share_secret: primary server shared secret

        :param str response_window: Health check policy Response Window

        :param str zombie_period: Health check policy Zombie Period

        :param str revive_interval: Health check policy Revive Interval

        :param str noresponse_fail: true | false

        :param str secondary_radius_ip: secondary server ip address

        :param str secondary_radius_port: secondary server port number

        :param str secondary_radius_share_secret: secondary server shared secret

        :return: True if AAA created else False

        :rtype: boolean

        Example:

        | Update Aaa Profile In Apzone | current_aaa_name=Auto_aaa | new_aaa_name=Auto_aaa_updated | zone_name=Auto_apzone |
        |                              | response_window=25 | enable_secondary_radius=0 | primary_radius_ip=2.2.2.2 |
        |                              | primary_radius_port=1812 | primary_radius_share_secret=testing123 |

        """
        res = self.sjc.update_aaa_profile(**kwargs)
        if not res:
            raise AssertionError("Failed to update aaa profile")
            

        return True


    def delete_aaa_profile_from_apzone(self, is_public_api=IS_PUBLIC, **kwargs):
        """ 
        API used to delete AAA profile

        URI: DELETE /wsg/api/scg/aaaServers/zone/<aaa_profile_key>

        :param str aaa_name: Name of AAA profile

        :param str zone_name: Name of APZone

        :param str domain_label: Name of Domain

        :return: True if AAA profile deleted else False

        :rtype: boolean

        Example:

        | Delete Aaa Profile From Apzone | aaa_name=Auto_aaa_updated | zone_name=Auto_apzone |

        """
                
        if is_public_api == True:
            aaa_type = self.sjc.get_type_for_aaa_profile(zone_name=kwargs["zone_name"], name=kwargs["aaa_name"])
            res=self.pubapi.delete_aaa_profile(aaa_type=aaa_type, **kwargs)  
        else:
            res = self.sjc.delete_aaa_profile(**kwargs)
        if not res:
            raise AssertionError("Failed to delete aaa profile")
            

        return True


    def create_thirdparty_apzone(self, **kwargs):
        """
        API used to create Third Party APZone

        URI: POST /wsg/api/scg/zones/thirdparty?

        :param str zone_name: Name of Third Party APZone

        :param str domain_label: Name of Domain

        :param str access_network: QinQL2 | L2oGRE

        :param str core_network: TTGPDG | Bridge

        :param str auth_service_type: Open | x8021 | WISPr

        :param str network_traffic_name: Network Traffic Profile

        :param str acct_name: Accounting profile name

        :param str auth_name: Authentication Profile name

        :param str forwarding_profile_name: Name of Forwarding profile

        :param str hotspot_name: Name of Hotspot profile

        :param str vlan_map_type: MapSPreserveC | StripAll | StripSPreserveC | StripAllAddFixedSingle

        :param str default_shared_secret: Radius Client option Default Share Secret

        :param str shared_secret: Shared Secret

        :param str ip_type: SingleIP | IPRange | Subnet

        :param str ip_address: IP Address

        :param str core_add_fixed_valn: Core add fixed VLAN

        :param str start_ip: start IP

        :param str end_ip: end IP

        :param str subnet: subnet

        :param str network: network

        :param str ap_ip_type: SingleIP | IPRange | Subnet

        :param str ap_ip: IP Address

        :param str ap_start_ip: start IP

        :param str ap_end_ip: end IP

        :param str ap_subnet: subnet

        :param str ap_network: network

        :param boolean acct_ttgsession_enable: True | False

        :param boolean core_qinq_enable: True | False

        :param str start_cvlan: Start CVLAN

        :param str end_cvlan: End CVLAN

        :param str start_svaln: Start SVLAN

        :param str end_svlan: End SVLAN

        :return: True if Third Party APZone created else False

        :rtype: boolean

        Example:

        | Create Thirdparty Apzone | zone_name=Auto_Thrdprty_apzone | access_network=QinQL2 | core_network=TTGPDG | auth_service_type=x8021 |
        |                          | network_traffic_name=Network_Traffic | acct_name=Auto_acct | auth_name=Auto_auth | forwarding_profile_name=fwd_profile |
        |                          | vlan_map_type=StripAll | default_shared_secret=12345678 | shared_secret=testing123 | ip_type=SingleIP |
        |                          | ip_addr=1.1.1.1 | start_cvlan=10 | end_cvlan=10 | start_svlan=11 |
        |                          | end_svlan=11 |

        """
        res = self.sjc.create_thirdparty_apzone(**kwargs)
        if not res:
            raise AssertionError("Failed to create thirdparty apzone")
            
        return True

    def validate_thirdparty_apzone(self, **kwargs):
        """
        API is used to validate Third Party AP Zone

        URI: GET /wsg/api/scg/zones/thirdparty/byDomain/<domain_uuid>
        
        :param str zone_name: Name of Third Party APZone

        :param str domain_label: Name of Domain

        :param str access_network: QinQL2 | L2oGRE

        :param str core_network: TTGPDG | Bridge

        :param str auth_service_type: Open | x8021 | WISPr

        :param str network_traffic_name: Network Traffic Profile

        :param str acct_name: Accounting profile name

        :param str auth_name: Authentication Profile name

        :param str forwarding_profile_name: Name of Forwarding profile

        :param str acct_update_interval: interval of time to send accounting interim 

        :param str hotspot_name: Name of Hotspot profile

        :param str vlan_map_type: MapSPreserveC | StripAll | StripSPreserveC | StripAllAddFixedSingle

        :param str default_shared_secret: Radius Client option Default Share Secret

        :param str shared_secret: Shared Secret

        :param str ip_type: SingleIP | IPRange | Subnet

        :param str ip_address: IP Address

        :param str core_add_fixed_valn: Core add fixed VLAN

        :param str start_ip: start IP

        :param str end_ip: end IP

        :param str subnet: subnet

        :param str network: network

        :param boolean acct_ttgsession_enable: True | False

        :param boolean core_qinq_enable: True | False
        
        :param str start_cvlan: Start CVLAN

        :param str end_cvlan: End CVLAN

        :param str start_svaln: Start SVLAN

        :param str end_svlan: End SVLAN

        :return: True if Third Party APZone is validated else False

        :rtype: boolean

        Example:

        | Validate Thirdparty Apzone | zone_name=Auto_Thrdprty_apzone | access_network=QinQL2 | core_network=TTGPDG | auth_service_type=x8021 |
        |                          | network_traffic_name=Network_Traffic | acct_name=Auto_acct | auth_name=Auto_auth | forwarding_profile_name=fwd_profile |
        |                          | vlan_map_type=StripAll | default_shared_secret=12345678 | shared_secret=testing123 | ip_type=SingleIP |
        |                          | ip_addr=1.1.1.1 | start_cvlan=10 | end_cvlan=10 | start_svlan=11 |
        |                          | end_svlan=11 |

        """
        res = self.sjc.validate_third_party_apzone(**kwargs)
        if not res:
            raise AssertionError("Failed to validate thirdparty apzone")
            
        return True

    def add_radius_client_ip_to_third_party_apzone(self, **kwargs):
        """       
        Adds Radius Client ip address to third party apzone

        URI: PUT /wsg/api/scg/zones/thirdparty/<thirdparty_apzonbe_key>

        :param str zone_name: Name of the third party ap zone

        :param str ip_type: SingleIP | IPRange | Subnet

        :param str ip_addr: ip address to be added

        :param str start_ip: if ip_type is IPRange then pass the starting ip address 

        :param str end_ip: if ip_type is IPRange then pass the ending ip address

        :param str network: if ip_type is Subnet then pass ip address of the network

        :param str subnet: if ip_type is Subnet then pass ip address of subnet

        :param str secret: secret key 

        :return: True if Radius Client ip added to third party apzone else False

        :rtype: boolean

        Example:
        | Add Radius Client Ip To Third Party Apzone | zone_name=Auto_Thrdprty_apzone | ip_type=IPRange | start_ip=3.3.3.3 | end_ip=3.3.3.5 |
        |                                            | secret=testing123 |

        """
        res = self.sjc.add_radius_client_ip_to_third_party_apzone(**kwargs)
        if not res:
            raise AssertionError("Failed to add radius client to thirdparty apzone")
            

        return True

    def validate_radius_client_ip_in_third_party_apzone(self, **kwargs):
        """
        API is used to validate Radius Client Address in Third Party AP

        URI: GET /wsg/api/scg/zones/thirdparty/byDomain/<domain_uuid> 
        
        :param str zone_name: Name of the third party ap zone

        :param str domain_label: Name of the Domain

        :param str ip_type: SingleIP | IPRange | Subnet

        :param str ip_addr: ip address to be added

        :param str start_ip: if ip_type is IPRange then pass the starting ip address 

        :param str end_ip: if ip_type is IPRange then pass the ending ip address

        :param str network: if ip_type is Subnet then pass ip address of the network

        :param str subnet: if ip_type is Subnet then pass ip address of subnet

        :param str secret: secret key 

        :return: True if Radius Client ip to third party apzone is validated else False

        :rtype: boolean

        Example:

        | Validate Radius Client Ip In Third Party Apzone | zone_name=Auto_Thrdprty_apzone | ip_type=IPRange | start_ip=3.3.3.3 | end_ip=3.3.3.5 |
        |                                                 | secret=testing123 |

        """
        res = self.sjc.validate_radius_client_ip_in_third_party_apzone(**kwargs)
        if not res:
            raise AssertionError("Failed to validate radius client ip in thirdparty apzone")
            

        return True

    def update_radius_client_ip_in_third_party_apzone(self, **kwargs):
        """
        API is used to update Radius Client IP Address in Third Party AP

        URI: PUT /wsg/api/scg/zones/thirdparty/<thirdparty_apzonbe_key>

        :param str zone_name: Name of the third party ap zone

        :param str domain_label: Name of the Domain 

        :param str curr_ip_type: Original ip_type SingleIP | IPRange | Subnet

        :param str curr_ip_addr: Original IP address

        :param str curr_start_ip: Original ip_type if ip_type is IPRange then pass the starting ip address

        :param str curr_end_ip: Original ip_type if ip_type is IPRange then pass the ending ip address

        :param str curr_subnet: Original ip_type if ip_type is Subnet then pass ip address of subnet

        :param str curr_network: Original ip_type if ip_type is Subnet then pass ip address of the network

        :param str ip_type: SingleIP | IPRange | Subnet

        :param str ip_addr: ip address to be added 

        :param str start_ip: if ip_type is IPRange then pass the starting ip address 

        :param str end_ip: if ip_type is IPRange then pass the ending ip address

        :param str network: if ip_type is Subnet then pass ip address of the network

        :param str subnet: if ip_type is Subnet then pass ip address of subnet

        :param str secret: secret key 

        :return: True if Radius Client ip address is updated to third party apzone else False

        :rtype: boolean

        Example:

        | Update Radius Client Ip In Third Party Apzone | zonename=Auto_Thrdprty_apzone | curr_ip_type=IPRange | curr_start_ip=3.3.3.3 |
        |                                               | curr_end_ip=3.3.3.5 | ip_type=SingleIP | ip_addr=5.5.5.5 |

        """
        res = self.sjc.update_radius_client_ip_in_third_party_apzone(**kwargs)
        if not res:
            raise AssertionError("failed to update radius client ip in thirtparty apzone")
            

        return True

    def delete_radius_ip_from_third_party_apzone(self, **kwargs):
        """
        API used to delete the Radius Client enrty form thirdparty APZone

        URI: PUT /wsg/api/scg/zones/thirdparty/<third_party_apzone_key>

        :param str zone_name: Thirdparty APZone name

        :param str domain_label: Name of Domain

        :param str ip_type: SingleIP | IPRange | Subnet

        :param str ip_addr: IP Address

        :param str start_ip: Start IP Address

        :param str end_ip: End IP Address

        :param str subnet: Subnet

        :param str network: network

        :param str secret: Secret

        :return: True if Radius Client enrty deleted from thirdparty APZone else False

        :rtype: boolean

        Example:

        | Delete Radius Client Ip From Thirdparty Apzone | zone_name=Auto_Thrdprty_apzone | ip_type=SingleIP | ip_addr=5.5.5.5 |

        """

        res = self.sjc.delete_radius_ip_from_third_party_apzone(**kwargs)
        if not res:
            raise AssertionError("Failed to delete radius client ip from thirdparty apzone")
            

        return True


    def add_ap_ipaddr_to_third_party_apzone(self, **kwargs):
        """       
        Adds AP ip address to third party apzone

        URI: PUT /wsg/api/scg/zones/thirdparty/<thirdparty_apzonbe_key>

        :param str zone_name: Name of the third party ap zone

        :param str ip_type: SingleIP | IPRange | Subnet

        :param str ip_addr: ip address to be added

        :param str start_ip: if ip_type is IPRange then pass the starting ip address 

        :param str end_ip: if ip_type is IPRange then pass the ending ip address

        :param str network: if ip_type is Subnet then pass ip address of the network

        :param str subnet: if ip_type is Subnet then pass ip address of subnet

        :return: True if AP ip address added to third party apzone else False

        :rtype: boolean

        Example:

        | Add Ap Ipaddr To Thirdparty Apzone | zone_name=Auto_Thrdprty_apzone | ip_type=SingleIP | ip_addr=6.6.6.6 |

        """
        res = self.sjc.add_ap_ipaddr_to_third_party_apzone(**kwargs)
        if not res:
            raise AssertionError("Failed to add AP ip to thirdparty apzone")
            

        return True

    def validate_ap_ipaddr_in_third_party_apzone(self, **kwargs):
        """
        API is used to validate AP IP Address in Third Party AP

        URI: GET /wsg/api/scg/zones/thirdparty/byDomain/<domain_uuid> 
        
        :param str zone_name: Name of the third party ap zone

        :param str domain_label: Name of the Domain

        :param str ip_type: SingleIP | IPRange | Subnet

        :param str ip_addr: ip address to be added

        :param str start_ip: if ip_type is IPRange then pass the starting ip address 

        :param str end_ip: if ip_type is IPRange then pass the ending ip address

        :param str network: if ip_type is Subnet then pass ip address of the network

        :param str subnet: if ip_type is Subnet then pass ip address of subnet

        :return: True if AP IP validated in third party apzone else False

        :rtype: boolean

        Example:                              
                                              
        | Validate Ap Ipaddr In Thirdparty Apzone | zone_name=Auto_Thrdprty_apzone | ip_type=SingleIP | ip_addr=6.6.6.6 |

        """
        res = self.sjc.validate_ap_ipaddr_in_third_party_apzone(**kwargs)
        if not res:
            raise AssertionError("Failed to validate ap ipaddr in thirdparty apzone")
            

        return True

    def update_ap_ipaddr_in_third_party_apzone(self, **kwargs):
        """
        API is used to update AP IP Address in Third Party AP

        URI: PUT /wsg/api/scg/zones/thirdparty/<thirdparty_apzonbe_key>

        :param str zone_name: Name of the third party ap zone

        :param str domain_label: Name of the Domain 

        :param str curr_ip_type: Original ip_type SingleIP | IPRange | Subnet

        :param str curr_ip_addr: Original IP address

        :param str curr_start_ip: Original ip_type if ip_type is IPRange then pass the starting ip address

        :param str curr_end_ip: Original ip_type if ip_type is IPRange then pass the ending ip address

        :param str curr_subnet: Original ip_type if ip_type is Subnet then pass ip address of subnet

        :param str curr_network: Original ip_type if ip_type is Subnet then pass ip address of the network

        :param str ip_type: SingleIP | IPRange | Subnet

        :param str ip_addr: ip address to be added 

        :param str start_ip: if ip_type is IPRange then pass the starting ip address 

        :param str end_ip: if ip_type is IPRange then pass the ending ip address

        :param str network: if ip_type is Subnet then pass ip address of the network

        :param str subnet: if ip_type is Subnet then pass ip address of subnet

        :return: True if AP ip address is updated to third party apzone else False

        :rtype: boolean

        Example:

        | Update Ap Ipaddr In Thirdparty Apzone | zone_name=Auto_Thrdprty_apzone | curr_ip_type=SingleIP | curr_ip_addr=6.6.6.6 |
        |                                       | ip_type=IPRange | start_ip=7.7.7.7 | end_ip=7.7.7.10 |

        """
        res = self.sjc.update_ap_ipaddr_in_third_party_apzone(**kwargs)
        if not res:
            raise AssertionError("Failed to update AP ip in thirparty apzone")
            
        return True

    def delete_ap_ipaddr_from_third_party_apzone(self, **kwargs):
        """
        API used to delete the AP enrty form thirdparty APZone

        URI: PUT /wsg/api/scg/zones/thirdparty/<third_party_apzone_key>

        :param str zone_name: Thirdparty APZone name

        :param str domain_label: Name of Domain

        :param str ip_type: SingleIP | IPRange | Subnet

        :param str ip_addr: IP Address

        :param str start_ip: Start IP Address

        :param str end_ip: End IP Address

        :param str subnet: Subnet

        :param str network: network

        :param str secret: Secret

        :return: True if AP IP enrty deleted from thirdparty APZone else False

        :rtype: boolean

        Example:

        | Delete Ap Ipaddr From Thirdparty Apzone | zone_name=Auto_Thrdprty_apzone | ip_type=IPRange | start_ip=7.7.7.7 | end_ip=7.7.7.10 |

        """
        res = self.sjc.delete_ap_ipaddr_from_third_party_apzone(**kwargs)
        if not res:

            raise AssertionError("Failed to delete AP ip from thirdparty apzone")
            

        return True

    def add_svlan_cvlan_to_third_party_apzone(self, **kwargs):
        """
        Adds Access SVALN range and CVLAN range to third party apzone

        URI: PUT /wsg/api/scg/zones/thirdparty/<third_party_apzone_key>

        :param str zone_name: Name of Thirdparty APzone

        :param str start_cvlan: Access CVLAN range start value

        :param str end_cvlan: Access CVLAN range end value

        :param str start_svaln: Access SVLAN range start value

        :param str end_svlan: Access SVLAN range end value

        :return: True if SVLAN and CVLAN addedd to Thirdparty apzone

        :rtype: boolean

        Example:

        | Add Svlan Cvlan To Thirdparty Apzone | zone_name=Auto_Thrdprty_apzone | start_cvlan=10 | end_cvlan=11 | 
        |                                      | start_svlan=15 | end_svlan=20 |

        """
        res = self.sjc.add_svlan_cvlan_to_third_party_apzone(**kwargs)
        if not res:
            raise AssertionError("Failed to add svlan and cvlan to thirparty apzone")
            
        return True

    def validate_svlan_cvlan_to_third_party_apzone(self, **kwargs):
        """                                       
        API used to validate Access SVALN range and CVLAN range in third party apzone
                                                  
        URI: PUT /wsg/api/scg/zones/thirdparty/byDomain/<domain_uuid>
                                                  
        :param str zone_name: Name of Thirdparty APzone

        :param str domain_label: Name of the Domain

        :param str start_cvaln: Access CVLAN range start value

        :param str end_cvlan: Access CVLAN range end value

        :param str start_svlan: Access SVLAN range start value

        :param str end_svlan: Access SVLAN range end value

        :return: True if SVLAN and CVLAN validated in Thirdparty apzone else False

        :rtype: boolean

        Example:            
                            
        | Validate Svlan Cvlan In Thirdparty Apzone | zone_name=Auto_Thrdprty_apzone | start_cvlan=10 | end_cvlan=11 | 
        |                                           | start_svlan=15 | end_svlan=20 |

        """
        res = self.sjc.validate_svlan_cvlan_to_third_party_apzone(**kwargs)
        if not res:
            raise AssertionError("Falied to validate svlan cvlan in thirdparty apzone")
            
        return True

    def update_svlan_cvlan_to_third_party_apzone(self, **kwargs):
        """
        updates Access SVALN range and CVLAN range to Third party APZone
                                                  
        URI: PUT /wsg/api/scg/zones/thirdparty/<third_party_apzone_key>
                                                  
        :param str zone_name: Name of Thirdparty APzone

        :param str domain_label: Name of the Domain

        :param str access_svlan_start: Access SVLAN start value

        :param str access_svlan_end: Access SVLAN end value

        :param str start_cvlan: Access CVLAN range start value

        :param str end_cvlan: Access CVLAN range end value

        :param str start_svaln: Access SVLAN range start value

        :param str end_svlan: Access SVLAN range end value

        :return: True if SVLAN and CVLAN updated to Thirdparty apzone else False

        :rtype: boolean

        Example:
        | Update Svlan Cvlan In Thirdparty Apzone | zone_name=Auto_Thrdprty_apzone | access_svlan_start=15 | access_svlan_end=20 |
        |                                         | start_cvlan=31 | end_cvlan=35 | start_svaln=36 |
        |                                         | end_svlan=40 |
        """
        res = self.sjc.update_svlan_cvlan_to_third_party_apzone(**kwargs)
        if not res:
            raise AssertionError("Failed to update svlan cvlan in thirdparty apzone")
            
        return True

    def delete_svlan_cvlan_in_third_party_apzone(self, **kwargs):
        """
        API used to delete SVLAN and CVLAN entry from Thirdparty APZone

        URI: PUT /wsg/api/scg/zones/thirdparty/<third_party_apzone_key>

        :param str zone_name: Thirdparty APZone name

        :param str domain_label: name of the Domain

        :param str svlan_start: SVLAN start value

        :param str svlan_end: SVLAN end value

        :return: True if SVLAN and CVLAN entry deleted from Thirdparty APZone else False

        :rtype: boolean

        Example:

        | Delete Svlan Cvlan From Thirdparty Apzone | zone_name=Auto_Thrdprty_apzone | svlan_start=36 | svlan_end=40 |

        """
        res = self.sjc.delete_svlan_cvlan_in_third_party_apzone(**kwargs)
        if not res:
            raise AssertionError("Failed to delete svlan cvlan from Thirdparty apzone")
            

        return True

    def update_third_party_apzone(self, **kwargs):

        """
        API used to update Third Party APZone

        URI: PUT /wsg/api/scg/zones/thirdparty/<third_party_apzone_key>

        :param str zone_name: Name of Third Party APZone

        :param str domain_label: Name of Domain

        :param str new_zone_name: New name of Third Party APZone

        :param str access_network: QinQL2 | L2oGRE

        :param str core_network: TTGPDG | Bridge

        :param str auth_service_type: Open | x8021 | WISPr

        :param str network_traffic_name: Name of Network Traffic Profile

        :param str acct_name: Accounting profile name

        :param str auth_name: Authentication Profile name

        :param str forwarding_profile_name: Name of Forwarding profile

        :param str hotspot_name: Name of Hotspot profile

        :param str vlan_map_type: MapSPreserveC | StripAll | StripSPreserveC | StripAllAddFixedSingle

        :param str default_shared_secret: Radius Client option Default Share Secret

        :param str core_add_fixed_valn: Core add fixed VLAN

        :param boolean acct_ttgsession_enable: True | False

        :param boolean core_qinq_enable: True | False

        :return: True if Third Party APZone updated else False

        :rtype: boolean

        Example:
        | Update Thirdparty Apzone | zone_name=Auto_Thrdprty_apzone | new_zone_name=Auto_thrdparty_updated | core_network=Bridge | auth_service_type=Open |
        |                          | acct_name=Disable |
 
        """
        res = self.sjc.update_third_party_apzone(**kwargs)
        if not res:
            raise AssertionError("Failed to update thirdparty apzone")
            

        return True

    def delete_thirdparty_apzone(self, **kwargs):
        """
        API used to delete Thirdparty APzone

        URI: DELETE /wsg/api/scg/zones/thirdparty/<thirdparty_apzonbe_key>

        :param str thirdparty_apzone_name: Name of Thirdparty APzone

        :param str domain_label: Name of Doamin

        :return: True if Thirdparty APzone deleted else False

        :rtype: boolean

        Example:

        | Delete Thirdparty Apzone | thirdparty_apzone_name=Auto_thrdparty_updated | domain_label=Administration Domain |

        """
        res = self.sjc.delete_thirdparty_apzone(**kwargs)
        if not res:
            raise AssertionError("Failed to delete thirdparty apzone")
            
        return True

    def create_mvno_account(self, **kwargs):
        """
        API used to create MVNO Account

        URI: POST /wsg/api/scg/tenants?

        :param str mvno_domain_name: Name of MVNO Domain

        :param str domain_label: Name of the Domain

        :param str description: Description 

        :param str account_name: Name of MVNO Account

        :param str real_name: Real Name

        :param str password: Password

        :param str phone: Phone Number

        :param str email: Email

        :param str title: Title

        :param str aaa_name: Name of AAA Server

        :param str aaa_type: RADIUS | TACACS+

        :param str realm: Realm

        :param str aaa_enable_secondary_radius: True | False

        :param str aaa_primary_ip: Primary Server IP

        :param str aaa_primary_port: Primary Server Port 

        :param str aaa_primary_shared_secret: Primary Server Secret

        :param str aaa_secondary_ip: Secondary Server IP

        :param str aaa_secondary_port: Secondary Server Port

        :param str aaa_secondary_shared_secret: Secondary Server Secret

        :param str aaa_request_timeout: Failover policy at NAS Request timeout

        :param str aaa_max_numof_retries: Failover policy at NAS Maximum no of retries

        :param str aaa_reconnect_primary: Failover policy at NAS Reconnect primary

        :param str apzone_name: Name of APZone

        :param str wlan_name: Name of WLAN 

        :return: True if MVNO Account created else False

        :rtype: boolean

        Example:

        | Create Mvno Account | mvno_domain_name=Auto_MVNO | account_name=Auto_acct | password=ruckus1! |

        """
        res = self.sjc.create_mvno_account(**kwargs)
        if not res:
            raise AssertionError("Failed to create MVNO Account")
            

        return True

    def add_wlan_to_mvno_account(self, **kwargs):
        """
        API used to add WLAN to MVNO Account

        URI: PUT /wsg/api/scg/tenants/<mvno_account_key>

        :param str mvno_name: Name of MVNO Account

        :param str apzone_name: Name of APZone

        :param str domain_label: Name of Domain 

        :param str wlan_name: Name of the WLAN

        :return: True if WLAN added to MVNO Account else False

        :rtype: boolean

        | Add Wlan To Mvno Account | mvno_name=Auto_MVNO | apzone_name=Auto_APZone | wlan_name=Auto_WLAN_Profile |

        """

        res = self.sjc.add_wlan_to_mvno(**kwargs)
        if not res:
            raise AssertionError("Failed to add WLAN to MVNO account")
            
        return True

    def add_apzone_to_mvno_account(self, **kwargs):
        """
        Adds the APZone to the MVNO account

        URI: PUT /wsg/api/scg/tenants/<mvno_account_key>

        :param str mvno_name: Name of the MVNO Account

        :param str apzone_name: Name of the APZone to be added

        :param str domain_label: Name of the Domain 

        :return: True if APZone is added to MVNO account else False

        :rtype: boolean

        | Add Apzone To Mvno Account | mvno_name=Auto_MVNO | apzone_name=Auto_APZone |

        """
        res = self.sjc.add_apzone_to_mvno(**kwargs)
        if not res:
            raise AssertionError("Failed to add WLAN to MVNO account")
            
        return True

    def add_aaa_server_to_mvno_account(self, **kwargs):
        """
        API used to add the AAA server to MVNO Account

        URI: PUT /wsg/api/scg/tenants/<mvno_key>

        :param str mvno_name: Name of MVNO Account

        :param str aaa_name: AAA Server name

        :param str aaa_type: RADIUS | TACACS

        :param str aaa_radius_realm: Realm

        :param str aaa_primary_ip: Primary IP

        :param str aaa_primary_port: Primary Port number

        :param str aaa_primary_shared_secret: Primary shared secret

        :param str aaa_secondary_ip: Secondary IP

        :param str aaa_secondary_port: Secondary Port number

        :param str aaa_secondary_shared_secret: Secondary shared secret

        :param str aaa_request_time_out: Failover Policy at NAS request timeout

        :param str aaa_max_retries: Failover Policy at NAS Maximum no of Retries

        :param str aaa_reconnect_primary: Failover Policy at NAS Reconnect Primary

        :param str aaa_enable_secondary_radius: 0 | 1

        :return: True if AAA Server added to MVNO Account else False

        :rtype: boolean

        Example:

        | Add Aaa Server To Mvno Account | mvno_name=Auto_MVNO | aaa_name=AAA | aaa_type=RADIUS | aaa_radius_realm=realm1 |
        |                                | aaa_primary_ip=1.1.1.1 | aaa_primary_port=1812 | aaa_primary_shared_secret=testing123 |

        """
        res = self.sjc.add_aaa_server_to_mvno(**kwargs)
        if not res:

            raise AssertionError("Failed to add AAA server to MVNO account")
            

        return True

    def delete_wlan_from_mvno_account(self, **kwargs):
        """
        API used to delete the WLAN in MVNO Account

        URI: PUT /wsg/api/scg/tenants/<mvno_key>

        :param str mvno_name: Name of MVNO Account

        :param str apzone_name: Name of APZone 

        :param str wlan_name: Name of WLAN

        :param str domain_label: Name of Domain

        :return: True if WLAN deleted from MVNO Account else False

        :rtype: boolean

        Example:

        | Delete Wlan From Mvno Account | mvno_name=Auto_MVNO | apzone_name=Auto_APZone | wlan_name=Auto_WLAN_Profile |

        """
        res = self.sjc.delete_wlan_from_mvno(**kwargs)
        if not res:
            raise AssertionError("Failed to delete WLAN from MVNO account")
            
        return True

    def delete_apzone_from_mvno_account(self, **kwargs):
        """
        API used to delete APZone from MVNO Account

        URI: PUT /wsg/api/scg/tenants/<mvno_key>

        :param str mvno_name: Name of MVNO Account

        :param str apzone_name: Name of the APZone

        :param str domain_label: Name of the Domain

        :return: True if APZone is deleted from MVNO Account else False

        :rtype: boolean

        Example:

        | Delete Apzone From Mvno Account | mvno_name=Auto_MVNO | apzone_name=Auto_APZone |

        """
        res = self.sjc.delete_apzone_from_mvno(**kwargs)
        if not res:
            raise AssertionError("Failed to delete apzone from MVNO account")
            
        return True

    def delete_aaa_server_from_mvno_account(self, **kwargs):
        """
        API used to delete AAA server from MVNO Account

        URI: PUT /wsg/api/scg/tenants/<mvno_key>

        :param str mvno_name: Name of the MVNO Account

        :param str aaa_name: Name of AAA Server

        :return: True if AAA Server deleted from MVNO else False

        :rtype: boolean

        Example:

        | Delete Aaa Server From Mvno Account | mvno_name=Auto_MVNO | aaa_name=AAA |

        """
        res = self.sjc.delete_aaa_server_from_mvno(**kwargs)
        if not res:
            raise AssertionError("Failed to delete AAA server from MVNO account")
            
        return True

    def delete_mvno_account(self, **kwargs):
        """
        API used to delete MVNO Account

        URI: DELETE /wsg/api/scg/tenants/<mvno_key>

        :param str mvno_name: Name of MVNO 

        :return: True if MVNO Account deleted else False

        :rtype: boolean

        Example:

        | Delete Mvno Account | mvno_name=Auto_MVNO |

        """
        res = self.sjc.delete_mvno(**kwargs)
        if not res:
            raise AssertionError("Failed to delete MVNO account")
            
        return True


    def create_package(self, **kwargs):
        """
        Api used to create the Packages

        URI: POST /wsg/api/scg/packages?

        :param str package_name: Name of the package

        :param str description: Description about the Package

        :param str expiry_interval: HOUR | DAY | WEEK | MONTH | YEAR | NEVER

        :param str expiry_value: Expiration  value

        :return: True if Package is created else False

        :rtype: boolean

        Example:

        | Create Package | package_name=Auto_package | expiry_interval=DAY | expiry_value=2 |

        """
        res = self.sjc.create_package(**kwargs)
        if not res:
            raise AssertionError("Failed to create package")
            

        return True

    def validate_package(self, **kwargs):
        """
        Api used to validate the Packages

        URI: GET /wsg/api/scg/packages?

        :param str package_name: Name of the package

        :param str description: Description about the Package

        :param str expiry_interval: HOUR | DAY | WEEK | MONTH | YEAR | NEVER

        :param str expiry_value: Expiration  value

        :return: True if Package is validated else False

        :rtype: boolean
    
        Example:

        | Validate Package | package_name=Auto_package | expiry_interval=DAY | expiry_value=2 |

        """
        res = self.sjc.validate_package(**kwargs)
        if not res:
            raise AssertionError("Failed to validate package")
            
        return True

    def delete_package(self, **kwargs):

        """
        API used to delete the package

        URI: DELETE /wsg/api/scg/packages/<package_key>

        :param str package_name: Name of the Package

        :return: True if Package is deleted else False

        :rtype: boolean

        Example:

        | Delete Package | package_name=Auto_Package |

        """

        res = self.sjc.delete_package(**kwargs)
        if not res:
            raise AssertionError("Failed to delete package")
            

        return True

    def create_guest_pass(self, **kwargs):
        """
        API used to create the Guest Pass

        URI: PUT /wsg/api/scg/identity/guestpass/generate/generate

        :param str login_name: Guest name

        :param str wlan_name: Name of WLAN to be used

        :param str domain_label: Name of the Domain

        :param str apzone_name: Name of AP Zone

        :param str multiple_guest: Number of multiple guests

        :param str password_expire_unit: Valid upto

        :param str time_interval: Days | Hours | Weeks

        :param boolean auto_gen_password: True | False

        :param str pass_effect_since: password effect since

        :param str max_device_limit: 'true' | 'false'

        :param str max_allowed_device: maximum number of allowed devices

        :param req_guest_relogin: request re-login for guest

        :return: True if Guest Pass created else False

        :rtype: boolean

        """
        res = self.sjc.create_guest_pass(**kwargs)
        if not res:
            raise AssertionError("Failed to create GuestPass")
            
        return True

    def delete_guest_pass(self, **kwargs):
        """
        API used to delete the Guest Pass

        URI: DELETE /wsg/api/scg/identity/guestpass/<guest_pass key>

        :param str login_name: Guest name

        :return: True if Guest Pass deleted else False

        :rtype: boolean

        """
        res = self.sjc.delete_guest_pass(**kwargs)
        if not res:
            raise AssertionError("Failed to delete GuestPass")
            
        return True

    def create_guest_access(self, is_public_api=IS_PUBLIC, **kwargs):
        """
        API used to create the Guest Access

        URI: PUT /wsg/api/scg/guestAccess

        :param str apzone_name: APzone name

        :param str domain_label: Name of the Domain

        :param str guest_access_name: Name of guest access

        :param str language: default - en_US

        :param str start_page: default - user

        :param str start_url: default - None

        :param str sms_gateway_id: default - None

        :param bool tc_enabled: default - False

        :param str terms_and_condtn: default - None

        :param str title: default - None

        :param str session_time: default - 1440

        :param str grace_period: default - 60

        :param str logo file: default - None

        :return: True if Guest Access created else False

        :rtype: boolean

        """
        
        if is_public_api == True:
            res=self.pubapi.create_guest_access(**kwargs)  
        else:
            res = self.sjc.create_guest_access(**kwargs)
        if not res:
            raise AssertionError("Failed to create GuestAccess")
            
        return True

    def create_web_authentication(self, is_public_api=IS_PUBLIC, **kwargs):
        """
        API used to create the Web Authentication

        URI: PUT /wsg/api/scg/webAuthentication

        :param str apzone_name: APzone name

        :param str domain_label: Name of the Domain

        :param str web_auth_name: Name of web authentication
        
        :param str description: description of web authentication

        :param str language: default - en_US

        :param str second_redirect: default - user

        :param str start_url: default - None

        :param str session_timeout: default - 1440

        :param str grace_period: default - 60

        :return: True if Web Authentication created else False

        :rtype: boolean

        """
        
        if is_public_api == True:
            res=self.pubapi.create_web_authentication(**kwargs)  
        else:
            res = self.sjc.create_web_authentication(**kwargs)
        if not res:
            raise AssertionError("Failed to create Web Authentication profile")
            
        return True
    
    def delete_webauth(self,is_public_api=IS_PUBLIC, **kwargs):
        """
        API used to delete the Web Authentication in APzone

        URI: DELETE /wsg/api/scg/webAuthentication/<web auth name>

        :param str web_auth_name: web authentication profile name name

        :param str apzone_name: APzone name

        :param str domain_label: Name of the Domain

        :return: True if Web Authentication deleted else False

        :rtype: boolean

        """
        
        if is_public_api == True:
            res=self.pubapi.delete_webauth(**kwargs)  
        else:
            res = self.sjc.delete_webauth(**kwargs)
        if not res:
            raise AssertionError("Failed to delete Web authentication profile")
            
        return True
    
    def create_user_agent_blacklist(self, **kwargs):
        """
        API used to create the Web Authentication

        URI: PUT /wsg/api/scg/webAuthentication

        :param str apzone_name: APzone name

        :param str domain_label: Name of the Domain

        :param str web_auth_name: Name of web authentication
        
        :param str description: description of web authentication

        :param str language: default - en_US

        :param str second_redirect: default - user

        :param str start_url: default - None

        :param str session_timeout: default - 1440

        :param str grace_period: default - 60

        :return: True if Web Authentication created else False

        :rtype: boolean

        """
        res = self.sjc.create_user_agent_blacklist(**kwargs)
        if not res:
            raise AssertionError("Failed to create Web Authentication profile")
            
        return True
    
    def delete_user_agent_blacklist(self, **kwargs):
        """
        API used to delete the Web Authentication in APzone

        URI: DELETE /wsg/api/scg/webAuthentication/<web auth name>

        :param str web_auth_name: web authentication profile name name

        :param str apzone_name: APzone name

        :param str domain_label: Name of the Domain

        :return: True if Web Authentication deleted else False

        :rtype: boolean

        """
        res = self.sjc.delete_user_agent_blacklist(**kwargs)
        if not res:
            raise AssertionError("Failed to delete Web authentication profile")
            
        return True

    
    def delete_guest_access_in_apzone(self, is_public_api=IS_PUBLIC, **kwargs):
        """
        API used to delete the Guest Access in APzone

        URI: DELETE /wsg/api/scg/guestAccess/<guestaccess_key>

        :param str apzone_name: APzone name

        :param str domain_label: Name of the Domain

        :return: True if Guest Access deleted else False

        :rtype: boolean

        """
        
        if is_public_api == True:
            res=self.pubapi.delete_guest_access_in_apzone(**kwargs)  
        else:
            res = self.sjc.delete_guest_access_in_apzone(**kwargs)
        if not res:
            raise AssertionError("Failed to delete GuestAccess")
            
        return True

    def create_profile_in_identity(self, **kwargs):
        """
        API used to create Profile in Identity

        URI: GET /wsg/api/scg/identity/profiles/create? 

        :param str first_name: First Name

        :param str last_name: Last Name

        :param str mail_addr: Email Address

        :param str phone: Phone Number

        :param str country_id: Name of the Country. default - US

        :param str city: Name of the City

        :param str address: Address Details

        :param str zipcode: Zipcode

        :param str state: Name of the State

        :param str comment: Sample Description on Profile

        :param str login_name: Login name

        :param str login_password: Password

        :param str package_name: Package Name

        :return: True if create Profile in Identity Success else False

        :rtype: boolean

        Example:

        | Create Profie In Identity | login_name=admin1 | login_password=ruckus1! | package_name=Package1 |

        """
        res = self.sjc.create_profile_in_identity(**kwargs)
        if not res:
            raise AssertionError("Failed to create Profile in Identity")
            
        return True

    def validate_guest_user_data_identity(self, **kwargs):
        """
        API used to create Profile in Identity

        URI: GET /wsg/api/scg/identity/users? 

        :param str guest_name: Display Name of guest profile
        
        :param str loginPassword: login password of guest profile
        
        :param str wlanName: wlan profile to which guest profile belong

        :param str zoneName: Zone of Wlan profile guest profile
        
        :return: True if found guest user Profile in Identity Success else False

        :rtype: boolean

        Example:

        | Validate Guest User Data In Identity | guest_name=nms123 | loginPassword=Test23 | wlanName=guest_pass-R2 |

        """
        res = self.sjc.validate_guest_user_data_identity(**kwargs)
        if not res:
            raise AssertionError("Failed to Validate Guiest User Data in Identity")
            
        return True
   
    def enable_disable_guest_user(self, **kwargs):
        res = self.sjc.enable_disable_guest_user(**kwargs)
        if not res:
            raise AssertionError("Failed to Validate Guest User Data in Identity")
            
        return True

    def validate_profile_in_identity(self, **kwargs):
        """
        API used to validate Profile in Identity

        :param str first_name: First Name

        :param str last_name: Last Name

        :param str mail_addr: Email Address

        :param str phone: Phone Number

        :param str country_id: Name of the Country.

        :param str city: Name of the City

        :param str address: Address Details

        :param str zipcode: Zipcode

        :param str state: Name of the State

        :param str comment: Sample Description on Profile

        :param str login_name: Login name

        :param str package_name: Package Name

        :return: True if validate Profile in Identity Success else False

        :rtype: boolean

        Example:

        | Validate Profile In Identity | login_name=admin1 | package_name=Package1 |

        """
        res = self.sjc.validate_profile_in_identity(**kwargs)
        if not res:
            raise AssertionError("Failed to validate Profile in Identity")
            

        return True

    def delete_profile_in_identity(self, **kwargs):
        """
        API used to delete Profile in Identity

        URI: DELETE /wsg/api/scg/identity/profiles/<profile_key>/<username>? 

        :param str login_name: Username

        :return: True if profile deleted else False

        :rtype: boolean

        Example:

        | Delete Profile In Identity | login_name=admin1 |

        """
        res = self.sjc.delete_profile_in_identity(**kwargs)
        if not res:
            raise AssertionError("Failed to delete profile in identity")
            
        return True


    ################################################ Wrapper File by Sridevi ################################################

    def create_dhcp_service(self, **kwargs):

        """ 
        API used to Create the DHCP service 

        URI: POST /wsg/api/scg/dhcpserver/ 

        :param str dhcp_service_name: Name of the DHCP service 

        :param str description: Description about the Service 

        :param str primary_server_ip: IP Address of First server 

        :param str secondary_server_ip: IP Address of Second Server 

        :return: True if DHCP Service created else False 

        :rtype: boolean 

        Example: 

        | Create DHCP Service| dhcp_service_name="Auto_Dhcp_Service" | primary_server_ip="1.2.3.4" | secondary_server_ip="5.6.7.8" | 
        
        """
        res = self.sjc.create_dhcp_service(**kwargs)
        if not res:
            raise AssertionError("Create DHCP Failed")
            
        return True 

    def validate_dhcp_service(self, **kwargs):

        """
        API used to Validate the DHCP service 

        URI: GET /wsg/api/scg/dhcpserver/ 

        :param str dhcp_service_name: Name of the DHCP service 

        :param str description: Description about the Service 

        :param str primary_server_ip: IP Address of First server 

        :param str secondary_server_ip: IP Address of Second Server 

        :return: True if DHCP Service validated else False 

        :rtype: boolean 
        
         Example: 

        | Validate Dhcp Service | dhcp_service_name="Auto_Dhcp_Service" | primary_server_ip="1.2.3.4" | secondary_server_ip="5.6.7.8" |
        

        """

        res = self.sjc.validate_dhcp_service(**kwargs)
        if not res:
            raise AssertionError("Validate DHCP Failed")
            
        return True

    def update_dhcp_service(self, **kwargs):

        """
        API used to Update the DHCP Service 

        URI: PUT /wsg/api/scg/dhcpserver/<dhcp_service_key> 

        :param str current_dhcp_name: Name of the DHCP Service to be modified 

        :param str new_dhcp_name: New name of DHCP Service 

        :param str description: Description about the DHCP Service 

        :param str primary_server_ip: IP Address of the First Server 

        :param str secondary_server_ip: IP Address of the Second Server

        :return: True if DHCP Service updated else False 

        :rtype: boolean 

        Example:

        | Update Dhcp Service | current_dhcp_name="Auto_Dhcp_Service" | new_dhcp_name="Update_Dhcp_Service" | primary_server_ip="1.2.3.4" |
        |                     | secondary_server_ip="5.6.7.8" |
        

        """
    
        res = self.sjc.update_dhcp_service(**kwargs)
        if not res:
            raise AssertionError("Update DHCP Failed")
             
        return True

    def delete_dhcp_service(self, **kwargs):

        """
        API used to delete the DHCP Service 

        URI: DELETE /wsg/api/scg/dhcpserver/<dhcp_service_key> 

        :param str dhcp_service_name: Name of the DHCP Service to be deleted 

        :return: True if DHCP Service deleted else False 

        :rtype: boolean 

        Example:

        | Delete DHCP | dhcp_service_name="Auto_Dhcp_Service" |

        """

        res = self.sjc.delete_dhcp_service(**kwargs)
        if not res:
            raise AssertionError("Delete DHCP Failed")
            

        return True 


    def create_hlr_service(self, is_public_api=IS_PUBLIC, **kwargs):

        """
        API used to create HLR service 

        URI: POST /wsg/api/scg/hlrs/ 

        :param str hlr_name: Name of the HLR service 

        :param str description: Description of the HLR service 

        :param str sgsn_isdn_address: SGSN ISDN Adress 

        :param str routing_context: Routing context 

        :param str local_point_code: from 1 to 16383 

        :param str local_network_indicator: international | international_spare | national | national_spare [default:international] 

        :param str default_point_code_format: integer | dotted [default: dotted] 

        :param str eap_sim_map_version: version2 | version3 [default:version3] 

        :param str auth_map_version: version2 | version3 [default:version3] 

        :param str source_gt_indicator: global_title_includes_translation_type_only | 
                                        global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator 
                                        [default:global_title_includes_translation_type_only] 

        :param boolean has_src_point_code: True | False  [default: True] 

        :param str source_translation_type: from 1 to 254

        :param str source_numbering_plan: isdn_mobile_numbering_plan [default: isdn_mobile_numbering_plan] 

        :param str source_nature_address_indicator: international_number | subscriber_number | reserved_for_national_use | national_significant_number |
                                                    unknown [default: subscriber_number]  

        :param str destination_gt_indicator: global_title_includes_translation_type_only |
                                             global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator 
                                             [default: global_title_includes_translation_type_only] 
        :param str destination_translation_type: from 1 to 254 

        :param str dest_numbering_plan: isdn_mobile_numbering_plan  [default:isdn_mobile_numbering_plan] 

        :param str dest_nature_address_indicator: international_number | subscriber_number | reserved_for_national_use |
                                                  national_significant_number | unknown [default:international_number] 

        :param str dest_gt_point_code: from 1 to 16383 

        :param str sctp_destination_ip: Destination IP Address  

        :param str sctp_destination_port: Destination Port Number from 1 to 65535 

        :param str sctp_source_port: Source Port Address  from 1 to 65535 

        :param str sctp_max_inbound_streams: Maxium Inbound Streams  1 to 255 

        :param str sctp_max_outbound_streams:  Maxium outbound Streams  1 to 255 

        :param str sctp_adj_point_code: adjacent point code from 1 to 16383 

        :param str sccp_gt_digits: gt digits of SCCP GTT 

        :param str sccp_gt_indicator: global_title_includes_translation_type_only |
                                      global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator 

        :param str sccp_address_indicator: route_on_gt | route_on_ssn 

        :param str sccp_point_code: Point Code of SCCP GTT from 1 to 16383 

        :param boolean sccp_has_ssn: True | False 

        :param str sccp_trans_type: from 1 to 254

        :param str sccp_numbering_plan: isdn_mobile_numbering_plan 

        :param str sccp_nature_of_address_indicator: international_number | subscriber_number | reserved_for_national_use | national_significant_number |
                                                     unknown 

        :param boolean enable_av_caching: True | False [default: False]

        :param boolean enable_auth_caching: True | False [default: False]

        :param str cleanup_time_hour: from 0 to 23 [default: 0] 

        :param str cleanup_time_minute: from 0 t0 59 [default: 0]

        :param str cache_history_time: from  1 to 4294967296 [default: 0]

        :param str max_time_reuse:from 0 to 5 [default: 0]

        :return: True if HLR Service is created  else False 

        :rtype: boolean 

        Example:

        | Create Hlr Service | hlr_name="Auto_HLR_Service" | sgsn_isdn_address="1234" | routing_context="1" | local_point_code="10" | 
        |                    | local_network_indicator="international" | source_translation_type="10" | dest_gt_point_code="20" |
        |                    | sctp_destination_ip="1.2.3.4" | sctp_destination_port="1234"| sctp_source_port="1235" | sctp_max_inbound_streams="1" | 
        |                    | sctp_max_outbound_streams="1" | sctp_adj_point_code="1" | sccp_gt_digits="1111" | 
        |                    | sccp_gt_indicator="global_title_includes_translation_type_only" | sccp_address_indicator="route_on_gt" | 
        |                    | sccp_has_point_code=True | sccp_point_code="111" | sccp_has_ssn=False | sccp_trans_type="10" | 
        |                    | sccp_numbering_plan="isdn_mobile_numbering_plan" | sccp_nature_of_address_indicator="international_number" | 

        """

        if is_public_api == True and os.getenv("API_VERSION", 'v4_0') == 'v5_0':
            res=self.pubapi.create_hlr_service(**kwargs)
        else:
            res = self.sjc.create_hlr_service(**kwargs)
        
        if not res:
           raise AssertionError("Create HLR Service Failed")
            
        return True 

    def validate_hlr_service(self, **kwargs):

        """
        API used to validate HLR services

        URI: GET /wsg/api/scg/hlrs/

        :param str hlr_name: Name of the HLR service 

        :param str description: Description of the HLR service 

        :param str sgsn_isdn_address: SGSN ISDN Adress 

        :param str routing_context: Routing context 

        :param str local_point_code: from 1 to 16383 

        :param str local_network_indicator: international | international_spare | national | national_spare [default:international] 

        :param str default_point_code_format: integer | dotted [default: dotted] 

        :param str eap_sim_map_version: version2 | version3 [default:version3] 

        :param str auth_map_version: version2 | version3 [default:version3] 

        :param str source_gt_indicator: global_title_includes_translation_type_only | 
                                        global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator 
                                        [default:global_title_includes_translation_type_only] 

        :param boolean has_src_point_code: True | False  [default: True] 

        :param str source_translation_type: from 1 to 254

        :param str source_numbering_plan: isdn_mobile_numbering_plan [default: isdn_mobile_numbering_plan] 

        :param str source_nature_address_indicator: international_number | subscriber_number | reserved_for_national_use | national_significant_number |
                                                    unknown [default: subscriber_number]  

        :param str destination_gt_indicator: global_title_includes_translation_type_only |
                                             global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator 
                                             [default: global_title_includes_translation_type_only] 
        :param str destination_translation_type: from 1 to 254 

        :param str dest_numbering_plan: isdn_mobile_numbering_plan  [default:isdn_mobile_numbering_plan] 

        :param str dest_nature_address_indicator: international_number | subscriber_number | reserved_for_national_use |
                                                  national_significant_number | unknown [default:international_number] 

        :param str dest_gt_point_code: from 1 to 16383 

        :param str sctp_destination_ip: Destination IP Address  

        :param str sctp_destination_port: Destination Port Number from 1 to 65535 

        :param str sctp_source_port: Source Port Address  from 1 to 65535 

        :param str sctp_max_inbound_streams: Maxium Inbound Streams  1 to 255 

        :param str sctp_max_outbound_streams:  Maxium outbound Streams  1 to 255 

        :param str sctp_adj_point_code: adjacent point code from 1 to 16383 

        :param str sccp_gt_digits: gt digits of SCCP GTT 

        :param str sccp_gt_indicator: global_title_includes_translation_type_only |
                                      global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator 

        :param str sccp_address_indicator: route_on_gt | route_on_ssn 

        :param str sccp_point_code: Point Code of SCCP GTT from 1 to 16383 

        :param boolean sccp_has_ssn: True | False 

        :param str sccp_trans_type: from 1 to 254

        :param str sccp_numbering_plan: isdn_mobile_numbering_plan 

        :param str sccp_nature_of_address_indicator: international_number | subscriber_number | reserved_for_national_use | national_significant_number |
                                                     unknown 

        :param boolean enable_av_caching: True | False 

        :param boolean enable_auth_caching: True | False 

        :param str cleanup_time_hour: from 0 to 23 [default: 0] 

        :param str cleanup_time_minute: from 0 t0 59 [default: 0]

        :param str cache_history_time: from  1 to 4294967296 [default: 0]

        :param str max_time_reuse:from 0 to 5 [default: 0]

        :return: True if HLR service is validated else False 

        :rtype: boolean

        Example:

        | Validate Hlr Service | hlr_name="Auto_HLR_Service" | sgsn_isdn_address="1234" | routing_context="1" | local_point_code="10" | 
        |                    | local_network_indicator="international" | source_translation_type="10" | dest_gt_point_code="20" |  
        |                    | sctp_destination_ip="1.2.3.4" | sctp_destination_port="1234"| sctp_source_port="1235" | sctp_max_inbound_streams="1" | 
        |                    | sctp_max_outbound_streams="1" | sctp_adj_point_code="1" | sccp_gt_digits="1111" | 
        |                    | sccp_gt_indicator="global_title_includes_translation_type_only" | sccp_address_indicator="route_on_gt" | 
        |                    | sccp_has_point_code=True | sccp_point_code="111" | sccp_has_ssn=False | sccp_trans_type="10" | 
        |                    | sccp_numbering_plan="isdn_mobile_numbering_plan" | sccp_nature_of_address_indicator="international_number" | 


        """


        res = self.sjc.validate_hlr_service(**kwargs)
        if not res:
            raise AssertionError("Validate HLR Service Failed")
            
        return True 

## will not migrate to public API as not used in any QA automation
    def update_hlr_service(self, **kwargs):
        """
        API is used to Update HLR Services 

        URI: PUT /wsg/api/scg/hlrs/<HLR_service_key> 
       
        :param str current_hlr_name: Orginal HLR Services Name
        
        :param str new_hlr_name: New HLR Services Name

        :param str description: Description of the HLR service 

        :param str sgsn_isdn_address: SGSN ISDN Adress 

        :param str routing_context: Routing context 

        :param str local_point_code: from 1 to 16383 

        :param str local_network_indicator: international | international_spare | national | national_spare [default:international] 

        :param str default_point_code_format: integer | dotted [default: dotted] 

        :param str eap_sim_map_version: version2 | version3 [default:version3] 

        :param str auth_map_version: version2 | version3 [default:version3] 

        :param str source_gt_indicator: global_title_includes_translation_type_only | 
                                        global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator 
                                        [default:global_title_includes_translation_type_only] 

        :param boolean has_src_point_code: True | False  [default: True] 

        :param str source_translation_type: from 1 to 254

        :param str source_numbering_plan: isdn_mobile_numbering_plan [default: isdn_mobile_numbering_plan] 

        :param str source_nature_address_indicator: international_number | subscriber_number | reserved_for_national_use | national_significant_number |
                                                    unknown [default: subscriber_number]  

        :param str destination_gt_indicator: global_title_includes_translation_type_only |
                                             global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator 
                                             [default: global_title_includes_translation_type_only] 
        :param str destination_translation_type: from 1 to 254 

        :param str dest_numbering_plan: isdn_mobile_numbering_plan  [default:isdn_mobile_numbering_plan] 

        :param str dest_nature_address_indicator: international_number | subscriber_number | reserved_for_national_use |
                                                  national_significant_number | unknown [default:international_number] 

        :param str dest_gt_point_code: from 1 to 16383 

        :param str sctp_destination_ip: Destination IP Address  

        :param str sctp_destination_port: Destination Port Number from 1 to 65535 

        :param str sctp_source_port: Source Port Address  from 1 to 65535 

        :param str sctp_max_inbound_streams: Maxium Inbound Streams  1 to 255 

        :param str sctp_max_outbound_streams:  Maxium outbound Streams  1 to 255 

        :param str sctp_adj_point_code: adjacent point code from 1 to 16383 

        :param str sccp_gt_digits: gt digits of SCCP GTT 

        :param str sccp_gt_indicator: global_title_includes_translation_type_only |
                                      global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator 

        :param str sccp_address_indicator: route_on_gt | route_on_ssn 

        :param str sccp_point_code: Point Code of SCCP GTT from 1 to 16383 

        :param boolean sccp_has_ssn: True | False 

        :param str sccp_trans_type: from 1 to 254

        :param str sccp_numbering_plan: isdn_mobile_numbering_plan 

        :param str sccp_nature_of_address_indicator: international_number | subscriber_number | reserved_for_national_use | national_significant_number |
                                                     unknown 

        :param boolean enable_av_caching: True | False [default: False]

        :param boolean enable_auth_caching: True | False [default: False]

        :param str cleanup_time_hour: from 0 to 23 [default: 0]

        :param str cleanup_time_minute: from 0 t0 59 [default: 0]

        :param str cache_history_time: from  1 to 4294967296 [default: 0]

        :param str max_time_reuse:from 0 to 5 [default: 0]

        
        :param str hlr_name: Original Name of the HLR service 

        :param str new_hlr_name: New Name of the HLR service 
        
        :return: True if HLR service is updated 

        :rtype: boolean

        Example:

        | Upate Hlr Service | current_hlr_name="Auto_HLR_Service" | new_hlr_name="Update_HLR_Service" | sgsn_isdn_address="1234" | routing_context="1" |
        |                   | local_point_code="10" | local_network_indicator="international" | source_translation_type="10" | dest_gt_point_code="20" |  
        |                   | sctp_destination_ip="1.2.3.4" | sctp_destination_port="1234"| sctp_source_port="1235" | sctp_max_inbound_streams="1" | 
        |                   | sctp_max_outbound_streams="1" | sctp_adj_point_code="1" | sccp_gt_digits="1111" | 
        |                   | sccp_gt_indicator="global_title_includes_translation_type_only" | sccp_address_indicator="route_on_gt" | 
        |                   | sccp_has_point_code=True | sccp_point_code="111" | sccp_has_ssn=False | sccp_trans_type="10" | 
        |                   | sccp_numbering_plan="isdn_mobile_numbering_plan" | sccp_nature_of_address_indicator="international_number" | 

        """


        res = self.sjc.update_hlr_service(**kwargs)
        if not res:
            raise AssertionError("Update HLR Service Failed")
            

        return True 


## will not migrate to public API as not used in any QA automation
    def add_sctp_association_list_to_hlr_service(self, **kwargs):

        """
        Adds SCTP Association entry to HLR service 

        URI: PUT /wsg/api/scg/hlrs/<HLR_service_key> 

        :param str hlr_name: Name of the HLR service 

        :param str sctp_destination_ip: Destination IP address 

        :param str sctp_destination_port: SCTP destination port from 1 to 65535 

        :param str sctp_source_port: SCTP source port from 1 to 65535 

        :param str sctp_max_inbound_streams: Maxium Inbound Streams 1 to 255 

        :param str sctp_max_outbound_streams: Maxium Outbound Streams 1 to 255 

        :param str sctp_adj_point_code: Adjacent Point Code 1 to 16383 

        :return: True if SCTP Association to Core Network entry is added to HLR service else False 

        :rtype: boolean 

        Example:

        | Add Sctp Association List In Hlr Service | hlr_name="Auto_HLR_Service" | sctp_destination_ip="1.2.3.4" | sctp_destination_port="1234"| 
        |                                          | sctp_source_port="1235" | sctp_max_inbound_streams="1" | sctp_max_outbound_streams="1" | 
        |                                          | sctp_adj_point_code="1" |

        """

        

        res = self.sjc.add_sctp_association_to_hlr(**kwargs)
        if not res:
            raise AssertionError("Add Sctp Association List In Hlr Service(): Failed")
            
        return True 

## will not migrate to public API as not used in any QA automation        
    def validate_sctp_association_list_in_hlr_service(self, **kwargs):

        """
        API is used to validate SCTP Association List in HLR Service 

        URI: GET /wsg/api/scg/hlrs/ 
        
        :param str hlr_name: Name of the HLR service 

        :param str sctp_destination_ip: Destination IP address 

        :param str sctp_destination_port: SCTP destination port from 1 to 65535 

        :param str sctp_source_port: SCTP source port from 1 to 65535 

        :param str sctp_max_inbound_streams: Maxium Inbound Streams 1 to 255 

        :param str sctp_max_outbound_streams: Maxium Outbound Streams 1 to 255 

        :param str sctp_adj_point_code: Adjacent Point Code 1 to 16383 

        :return: True if SCTP Association to Core Network entry is validated in HLR service else False 

        :rtype: boolean 

        Example:

        | Validate Sctp Association List In Hlr Service | hlr_name="Auto_HLR_Service" | sctp_destination_ip="1.2.3.4" | sctp_destination_port="1234"| 
        |                                               | sctp_source_port="1235" | sctp_max_inbound_streams="1" | sctp_max_outbound_streams="1" | 
        |                                               | sctp_adj_point_code="1" |


        """

        res = self.sjc.validate_sctp_association_in_hlr(**kwargs)
        if not res:
            raise AssertionError("Validate SCTP Association in HLR Service Failed")

        return True 


## will not migrate to public API as not used in any QA automation
    def update_sctp_association_list_in_hlr_service(self, **kwargs):

        """
        API used to update SCTP Association to Core Network of HLR Services 

        URI: PUT /wsg/api/scg/hlrs/<HLR_service_key> 
    
        :param str hlr_name: Name Of the HLR service 

        :param str current_sctp_destination_ip: original Destination IP address 

        :param str new_sctp_destination_ip: New Destination IP address 
    
        :param str sctp_source_port: SCTP source port from 1 to 65535 

        :param str sctp_max_inbound_streams: Maxium Inbound Streams 1 to 255 

        :param str sctp_max_outbound_streams: Maxium Outbound Streams 1 to 255 

        :param str sctp_adj_point_code: Adjacent Point Code 1 to 16383 

        :return: True if SCTP Association to Core Network entry is updated in HLR service else False 

        :rtype: boolean 

        Example:

        | Update Sctp Association List In Hlr Service | hlr_name="Auto_HLR_Service" | current_sctp_destination_ip="1.2.3.4" | 
        |                                             | new_sctp_destination_ip="1.1.1.1" | sctp_destination_port="1234"| sctp_source_port="1235" | 
        |                                             | sctp_max_inbound_streams="10" | sctp_max_outbound_streams="10" | sctp_adj_point_code="2" |


        """

        res = self.sjc.update_sctp_association_in_hlr(**kwargs)
        if not res:
            raise AssertionError("Update SCTP Association List in HLR Service Failed")
            
        return True 

## will not migrate to public API as not used in any QA automation
    def delete_sctp_association_list_from_hlr_service(self, **kwargs):

        """
        API used to delete  SCTP Association from Core Network list of HLR Services 

        URI: PUT /wsg/api/scg/hlrs/<HLR_service_key> 

        :param str hlr_name: Name of HLR Service 

        :param str sctp_destination_ip: Destination IP address 

        :return: True if SCTP Association in Core Network entry is deleted from HLR service else False 

        :rtype: boolean 

        Example:

        | Delete Sctp Association List In Hlr Service | hlr_name="Auto_HLR_Service" | sctp_destination_ip="1.2.3.4" |

        """

        res = self.sjc.delete_sctp_from_hlr(**kwargs)
        if not res:
            raise AssertionError("Delete SCTP Association List From HLR Service Failed")
            
        return True 


## will not migrate to public API as not used in any QA automation
    def add_sccp_gtt_list_to_hlr_service(self, **kwargs):

        """
        API used to Add  SCCP GTT entry in HLR service 

        URI: PUT /wsg/api/scg/hlrs/<HLR_service_key> 
        
        :param str hlr_name: Name of the HLR Service 

        :param str sccp_gt_digits: GT digits 

        :param str sccp_gt_indicator: global_title_includes_translation_type_only |
                                             global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator 

        :param str sccp_address_indicator: route_on_gt | route_on_ssn 

        :param boolean sccp_has_point_code: True | False 

        :param str sccp_point_code: SCCP point code from 1 to 16383 

        :param boolean sccp_has_ssn: True | False 

        :param str sccp_trans_type:SCCP Translation Type from  1 to 254 

        :param str sccp_numbering_plan: isdn_mobile_numbering_plan

        :param str sccp_nature_of_address_indicator: international_number | subscriber_number | reserved_for_national_use | national_significant_number |
                                                             unknown 

        :return: True if SCCP GTT entry added to HLR service else False 

        :rtype: boolean 

        Example:

        | Add Sccp Gtt List In Hlr Service | hlr_name="Auto_HLR_Service" | sccp_gt_digits="1111" | 
        |                                  | sccp_gt_indicator="global_title_includes_translation_type_only" | sccp_address_indicator="route_on_gt" | 
        |                                  | sccp_has_point_code=True | sccp_point_code="111" | sccp_has_ssn=False | sccp_trans_type="10" | 
        |                                  | sccp_numbering_plan="isdn_mobile_numbering_plan" | sccp_nature_of_address_indicator="international_number" |


        """


        res = self.sjc.add_sccp_gtt_list_to_hlr(**kwargs)
        if not res:
            raise AssertionError("Add SCCP GTT List to HLR Service Failed")
            
        return True 

## will not migrate to public API as not used in any QA automation
    def validate_sccp_gtt_list_in_hlr_service(self, **kwargs):

        """
        API is used to validate SCCP GTT list in HLR service 
            
        URI: GET /wsg/api/scg/hlrs/ 
            
        :return: True if SCCP GTT entry validated in HLR service else False

        :param str hlr_name: Name of the HLR Service 

        :param str sccp_gt_digits: GT digits 

        :param str sccp_gt_indicator: global_title_includes_translation_type_only |
                                             global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator 

        :param str sccp_address_indicator: route_on_gt | route_on_ssn 

        :param boolean sccp_has_point_code: True | False 

        :param str sccp_point_code: SCCP point code from 1 to 16383 

        :param boolean sccp_has_ssn: True | False 

        :param str sccp_trans_type:SCCP Translation Type from  1 to 254 

        :param str sccp_numbering_plan: isdn_mobile_numbering_plan

        :param str sccp_nature_of_address_indicator: international_number | subscriber_number | reserved_for_national_use | national_significant_number |
                                                             unknown 
        :return: True if SCCP GTT entry validated in HLR service else False 

        :rtype: boolean 

        Example:

        | Validate Sccp Gtt List In Hlr Service | hlr_name="Auto_HLR_Service" | sccp_gt_digits="1111" | 
        |                                       | sccp_gt_indicator="global_title_includes_translation_type_only" | sccp_address_indicator="route_on_gt" | 
        |                                       | sccp_has_point_code=True | sccp_point_code="111" | sccp_has_ssn=False | sccp_trans_type="10" | 
        |                                       | sccp_numbering_plan="isdn_mobile_numbering_plan" | 
        |                                       | sccp_nature_of_address_indicator="international_number" |

        """

        res = self.sjc.validate_sccp_gtt_list_in_hlr(**kwargs)

        if not res:
            raise AssertionError("Validate SCCP GTT List in HLR Service Failed")
            
        return True

## will not migrate to public API as not used in any QA automation
    def update_sccp_gtt_list_in_hlr_service(self, **kwargs):

        """
        API is used to update SCCP GTT entry in HLR Service

        URI: PUT /wsg/api/scg/hlrs/<HLR_service_key> 

        :param str hlr_name: Name of the HLR Service 

        :param str current_sccp_gt_digits: Original GT digits of SCCP GTT 

        :param str new_sccp_gt_digits: New GT digits of SCCP GTT 

        :param str sccp_gt_indicator: global_title_includes_translation_type_only |
                                             global_title_includes_translation_type_numbering_plan_encoding_scheme_and_nature_of_address_indicator 

        :param str sccp_address_indicator: route_on_gt | route_on_ssn 

        :param boolean sccp_has_point_code: True | False 

        :param str sccp_point_code: SCCP point code from 1 to 16383 

        :param boolean sccp_has_ssn: True | False 

        :param str sccp_trans_type:SCCP Translation Type from  1 to 254 

        :param str sccp_numbering_plan: isdn_mobile_numbering_plan

        :param str sccp_nature_of_address_indicator: international_number | subscriber_number | reserved_for_national_use | national_significant_number |
                                                             unknown 


        :return: True if SCCP GTT entry update in HLR service else False 

        :rtype: boolean 

        Example:

        | Update Sccp Gtt List In Hlr Service | hlr_name="Auto_HLR_Service" | current_sccp_gt_digits="1111" |  new_sccp_gt_digits="1212" | 
        |                                     | sccp_gt_indicator="global_title_includes_translation_type_only" | sccp_address_indicator="route_on_gt" | 
        |                                     | sccp_has_point_code=True | sccp_point_code="111" | sccp_has_ssn=False | sccp_trans_type="10" | 
        |                                     | sccp_numbering_plan="isdn_mobile_numbering_plan" | sccp_nature_of_address_indicator="international_number" |        
        """

        res = self.sjc.update_sccp_gtt_list_in_hlr(**kwargs)
        if not res:
            raise AssertionError("Update SCCP GTT List in HLR Service Failed")
            
        return True

## will not migrate to public API as not used in any QA automation
    def delete_sccp_gtt_list_from_hlr_service(self, **kwargs):

        """
        API is used to delete SCCP GTT entry from HLR Service 

        URI: PUT /wsg/api/scg/hlrs/<HLR_service_key> 

        :param str hlr_name: Name of the HLR Service 

        :param sccp_gt_digits: GT digits of SCCP GTT 

        :return: True if SCCP GTT entry is deleted in HLR service else False 

        :rtype: boolean 

        Example:
        
        | Delete Sccp Gtt List In Hlr Service | hlr_name="Auto_HLR_Service" | sccp_gt_digits="1212" |
        
        """

        res = self.sjc.delete_sccp_gtt_list_from_hlr(**kwargs)
        if not res:
            raise AssertionError("Delete SCCP GTT List From HLR Service Failed")
            
        return True 


#### Will keep this as private API as no plan to support Public API for this
    def delete_hlr_service(self, is_public_api=IS_PUBLIC, **kwargs):

        """
        API is used to delete HLR Service 

        URI: DELETE /wsg/api/scg/hlrs/ 
            
        :param str hlr_name: Name of the HLR Service 

        :return: True if HLR Service is deleted 

        :rtype: boolean 

        Example:

        | Delete Hlr Service | hlr_name="Auto_HLR_Service" |

        """
        #if is_public_api == True  and os.getenv("API_VERSION", 'v4_0') == 'v5_0':
        if False:   
            res=self.pubapi.delete_hlr_service(**kwargs)
        else:
            res = self.sjc.delete_hlr_service(**kwargs)
        if not res:
            raise AssertionError("Delete HLR Service Failed")
        return True 


    def create_mnc_to_ndc_mapping_in_hlr_service(self, **kwargs):

        """
        API used to create the MNC to NDC mapping 

        URI: PUT /wsg/api/scg/hlrs/mncndc? 

        :param str mcc: MCC Value

        :param str mnc: MNC Value

        :param str ndc: NDC Value

        :return: True if MNC to NDC mapping created else False 

        :rtype: boolean 

        Example:

        | Create Mnc To Ndc Mapping In Hlr Service | mcc="100" | mnc="110" | ndc="28" |
        
        """

        res = self.sjc.create_mnc_to_ndc_map_in_hlr(**kwargs)
        if not res:
            raise AssertionError("Create MNC to NDC Mapping in HLR Service Failed")
            
        return True 

    def validate_mnc_to_ndc_mapping_in_hlr_service(self, **kwargs):

        """
        API is used to validate MNC to NDC Mappings in HLR Services 

        URI: GET /wsg/api/scg/hlrs/mncndc? 
         
        :param str mcc: MCC Value

        :param str mnc: MNC Value

        :param str ndc: NDC Value

        :return: True if MNC to NDC mapping is validated in HLR Services else False 

        :rtype: boolean 
 
        Example: 

        | Validate Mnc To Ndc Mapping In Hlr Service | mcc="100" | mnc="110" | ndc="28" |
        
        """ 
        res = self.sjc.validate_mnc_to_ndc_map_in_hlr(**kwargs)
        if not res:
            raise AssertionError("Validate MNC to NDC Mapping in HLR Service Failed")
             
        return True 

## will not migrate to public API as not used in any QA automation
    def update_mnc_to_ndc_mapping_in_hlr_service(self, **kwargs):

        """
        API is used to update MNC to NDC in HLR services 

        URI: PUT /wsg/api/scg/hlrs/mncndc? 

        :param str current_mcc: Current MCC Value

        :param str new_mcc: New MCC Value

        :param str mnc: MNC Value

        :param str ndc: NDC Value

        :return: True if MNC to NDC mapping upated else False 

        :rtype: boolean 

        Example:

        | Update Mnc To Ndc Mapping In Hlr Service  | current_mcc="100" | new_mcc="100" | mnc="110" | ndc="28" |
        
        """

        res = self.sjc.update_mnc_to_ndc_map_in_hlr(**kwargs)
        if not res:
            raise AssertionError("Update MNC to NDC Mapping in HLR Service Failed")
            
        return True 

    def delete_mnc_to_ndc_mapping_from_hlr_service(self, **kwargs):
        
        """
        API used to delete MNC to NDC mapping entry 

        URI: PUT /wsg/api/scg/hlrs/mncndc? 

        :param str mnc: MNC 

        :return: True if MNC to NDC mapping entry deleted else False 

        :rtype: boolean 

        Example:

        | Delete Mnc To Ndc Mapping In Hlr Service | mcc="100" |
        

        """

        res = self.sjc.delete_mnc_to_ndc_from_hlr(**kwargs)
        if not res:
            raise AssertionError("Delete MNC to NDC Mapping in HLR Service Failed")
            
        return True 


    def create_ttgpdg_forwarding_profile(self, is_public_api=IS_PUBLIC, **kwargs):

        
        """
        API used to create the TTGPDG Forwarding profile

        URI: POST /wsg/api/scg/serviceProfiles/forwarding/

        :param str ttgpdg_profile_name: Name of TTGPDG forwarding profile

        :param str description: Descrption on TTGPDG Forwarding Profile

        :param str apn_format_in_ggsn: APN Format to GGSN String | DNS [default: DNS]

        :param str use_apn_io_for_dns_resolution: True | False [default: False]

        :param str no_of_acct_retry: Number of Accounting retries from 1 to 10 [default: 5]
 
        :param str acct_retry_timeout: Accounting retry timeout from 1 to 30  [default: 5]

        :param str session_idle_timeout: PDG UE session Idle timeout [default: 300]

        :param str apn: Forwarding Policy per Realm APN

        :param str apn_type: NI | NIOI

        :param str route_type: GTPv1 | GTPv2 | PDG

        :param str realm: Realm

        :return: True if TTGPDG Forwarding Profile is created else False

        :rtype: boolean

        Example:

        | Create TTGPDG Forwarding Profile | ttgpdg_profile_name="Auto_TTGPDG_profile" | apn_format_in_ggsn="DNS" | use_apn_io_for_dns_resolution=False | 
        |                                  | apn="www.ttgpdg.com" | apn_type="NI" | route_type="GTPv1" | realm="www.mcc.mnc.3gpp.org" |

        """
        if is_public_api == True  and os.getenv("API_VERSION", 'v4_0') == 'v5_0':
            res = self.pubapi.create_ttgpdg_profile(**kwargs)
        else:
            res = self.sjc.create_ttgpdg_profile(**kwargs)
        if not res:
            raise AssertionError("Create TTGPDG Forwarding Profile Failed")
            
        return True 

## will not migrate to public API as not used in any QA automation
    def update_map_gateway_settings_in_hlr_service(self, **kwargs):

        """
        API used to update the Map Gateway Settings in HLR Service

        URI: PUT /wsg/api/scg/hlrs/globalsettings?

        :param boolean enable_map_gateway_service: True | False 

        :param str traffic_mode: Load_Share | Override

        :param str active_map_gateway: active_map_gateway

        :return: True if Map  Gateway Settings in HLR Service updated successfully else False

        :rtype: boolean

        Example:

        | Update Map Gateway Settings In HLR Service |  enable_map_gateway_service=True | traffic_mode="Load_Share" | active_map_gateway="Dayatona-2-c" |

        """

        res=self.sjc.update_map_gateway_settings_in_hlr_service(**kwargs)
        if not res:
            raise AssertionError("Update Map Gteway Settings Failed")
            
        return True

## will not migrate to public API as not used in any QA automation
    def validate_ttgpdg_forwarding_profile(self, **kwargs):

        
        """
        API is used to Validate TTGPDG Forwarding Profile

        URI: GET /wsg/api/scg/serviceProfiles/forwarding?type=TTGPDG

        :param str ttgpdg_profile_name: Name of TTGPDG forwarding profile

        :param str description: Descrption on TTGPDG Forwarding Profile

        :param str apn_format_in_ggsn: APN Format to GGSN String | DNS [default: DNS]

        :param str use_apn_io_for_dns_resolution: True | False [default: False]

        :param str no_of_acct_retry: Number of Accounting retries from 1 to 10 [default: 5]
 
        :param str acct_retry_timeout: Accounting retry timeout from 1 to 30  [default: 5]

        :param str session_idle_timeout: PDG UE session Idle timeout [default: 300]

        :param str apn: Forwarding Policy per Realm APN

        :param str apn_type: NI | NIOI

        :param str route_type: GTPv1 | GTPv2 | PDG

        :param str realm: Realm

        :return: True if TTGPDG Forwarding Profile is validated else False

        :rtype: boolean

        
        Example:

        | Validate TTGPDG Forwarding Profile | ttgpdg_profile_name=="Auto_TTGPDG_profile" | apn_format_in_ggsn="DNS" | use_apn_io_for_dns_resolution=False |
        |                                    | apn="www.ttgpdg.com" | apn_type="NI" | route_type="GTPv1" | realm="www.mcc.mnc.3gpp.org" |

        """
        res = self.sjc.validate_ttgpdg_profile(**kwargs)
        if not res:
            raise AssertionError("Validate TTGPDG Forwarding Profile Failed")
            
        return True 

## will not migrate to public API as not used in any QA automation
    def update_ttgpdg_forwarding_profile(self, **kwargs):

        """

        API used to update TTGPDG forwarding profile

        URI: PUT /wsg/api/scg/serviceProfiles/forwarding/<fwd_profile_key>

        :param str current_profile_name: Current Name of TTGPDG forwarding profile

        :param str new_profile_name: New name of TTGPDG forwarding profile

        :param str apn_format_in_ggsn: APN Format to GGSN String | DNS [default: DNS]

        :param str use_apn_io_for_dns_resolution: True | False [default: False]

        :param str no_of_acct_retry: Number of Accounting retries from 1 to 10 [default: 5]
 
        :param str acct_retry_timeout: Accounting retry timeout from 1 to 30  [default: 5]

        :param str session_idle_timeout: PDG UE session Idle timeout [default: 300]

        :param str apn: Forwarding Policy per Realm APN

        :param str apn_type: NI | NIOI

        :param str route_type: GTPv1 | GTPv2 | PDG

        :param str realm: Realm

        :return: True if TTGPDG Forwarding Profile is updated else False

        :rtype: boolean

        
        Example:

        | Update TTGPDG Forwarding Profile | current_ttgpdg_profile_name="Auto_TTGPDG_profile" | new_ttgpdg_profile_name="Update_TTGPDG_profile" | 
        |                                  | apn_format_in_ggsn="DNS" | use_apn_io_for_dns_resolution=False | apn="www.ttgpdg.com" | apn_type="NI" |
        |                                  | route_type="GTPv1" | realm="www.mcc.mnc.3gpp.org" |
 
        """
        res = self.sjc.update_ttgpdg_profile(**kwargs)
        if not res:
            raise AssertionError("Update TTGPDG Forwarding Profile Failed")
            
        return True 
    
## will not migrate to public API as not used in any QA automation
    def add_forwarding_policy_per_realm_to_ttgpdg_forwarding_profile(self, **kwargs):

       """ 
        Adds APN to Forwarding Policy per Realm in TTGPDG Forwarding Profile

        URI: PUT /wsg/api/scg/serviceProfiles/forwarding/<fwd_profile_key>
        
        :param str ttgpdg_profile_name: TTGPDG forwading profile name
 
        :param str apn: APN to be added

        :param str apn_type: NI | NIOI

        :param str route_type: GTPv1 | GTPv2 | PDG

        :return: True if APN added  to the Forwarding Policy per Realm else False

        :rtype: boolean

        Example:

        | Add Forwarding Policy Per Realm In Ttgpdg Forwarding Profile | ttgpdg_profile_name="Auto_TTGPDG_profile" | apn="www.ttgpdg2.com" | apn_type="NI" |
        |                                                              | route_type= "GTPv1" |

        """
 
       res = self.sjc.add_forwarding_policy_per_realm_to_ttgpdg_profile(**kwargs)
       if not res:
           raise AssertionError("Add Forwarding Policy Per Realm to TTGPDG Forwarding Profile Failed")
           
       return True
   
## will not migrate to public API as not used in any QA automation
    def validate_forwarding_policy_per_realm_in_ttgpdg_forwarding_profile(self, **kwargs):

        """ 
        API is used to validate Forwarding Policy Per Realm in TTGPDG Forwarding Profile
            
        URI: GET /wsg/api/scg/serviceProfiles/forwarding?type=TTGPDG
        
        :param str ttgpdg_profile_name: TTGPDG forwading profile name 

        :param str apn: APN to be added

        :param str apn_type: NI | NIOI

        :param str route_type: GTPv1 | GTPv2 | PDG

        :return: True if Forwarding Policy Per Realm in TTGPDG Forwarding Profile is validated else False

        :rtype: boolean

        Example:

        | Validate Forwarding Policy Per Realm In Ttgpdg Forwarding Profile | ttgpdg_profile_name="Auto_TTGPDG_profile" | apn="www.ttgpdg2.com" | 
        |                                                                   | apn_type="NI" | route_type= "GTPv1" |
                                                               
        """

        res = self.sjc.validate_forwarding_policy_per_realm_in_ttgpdg_profile(**kwargs)
        if not res:
            raise AssertionError("Validate Forwarding Policy Per Realm in TTGPDG Forwarding Profile Failed")
            
        return True
    
## will not migrate to public API as not used in any QA automation
    def update_forwarding_policy_per_realm_in_ttgpdg_forwarding_profile(self, **kwargs):

        """
        API is used to create Forwarding Policy Per Realm in TTGPDG Forwarding Profile

        URI: /wsg/api/scg/serviceProfiles/forwarding/<ttgpdg_service_keys>
        
        :param str ttgpdg_profile_name: TTGPDG forwading profile name 

        :param str current_apn: Origial APN
 
        :param new_apn: New APN

        :param str apn_type: NI | NIOI

        :param str route_type: GTPv1 | GTPv2 | PDG

        :param str default_nomatch_apn: default APN

        :param str default_norealm_apn: default APN

        :return: True if Forwarding Policy per Realm is updated in TTGPDG Forwarding Profile else False

        :rtype: boolean      

        Example:

        | Update Forwarding Policy Per Realm In Ttgpdg Forwarding Profile | ttgpdg_profile_name="Auto_TTGPDG_profile" | current_apn="www.ttgpdg.com" | 
        |                                                                 | new_apn="update.ttgpdg.com" | apn_type="NI" | route_type= "GTPv1" |
        |                                                                 | default_nomatch_apn="update.ttgpdg.com" | 
        |                                                                 | default_norealm_apn="update.ttgpdg.com" |

        """

        res = self.sjc.update_forwarding_policy_per_realm_in_ttgpdg_profile(**kwargs)
        if not res:
            raise AssertionError("Update Forwarding Policy Per Realm in TTGPDG Forwarding Profile Failed")
            
        return True 
        
## will not migrate to public API as not used in any QA automation
    def delete_forwarding_policy_per_realm_From_ttgpdg_forwarding_profile(self, **kwargs):

        """
        API is used delete Forwarding policy per realm in TTGPDG Forwarding Profile

        URI: PUT /wsg/api/scg/serviceProfiles/forwarding/<ttgpdg_service_keys> 
        
        :param str ttgpdg_profile_name: Name of TTGPDG Forwarding Profile

        :param str del_apn: Default apn 

        :return: if Forwarding policy per realm in TTGPDG Forwarding Profile is deleted else False

        :rtype: boolean
        
        Example:

        | Delete Forwarding Policy Per Realm From Ttgpdg Forwarding Profile | ttgpdg_profile_name="Auto_TTGPDG_profile" | del_apn="www.ttgpdg.com" |        

        """

        res = self.sjc.delete_forwarding_policy_per_realm_from_ttgpdg_profile(**kwargs)
        if not res:
            raise AssertionError("Delete Forwarding Policy Per Realm in TTGPDG Forwarding Profile Failed")
            
        return True


    def add_default_apn_per_realm_entry_to_ttgpdg_forwarding_profile(self, is_public_api=IS_PUBLIC, **kwargs):

        """
 
        Adds defaultAPN and realm to TTGPDG Forwarding Profile.

        URI: PUT /wsg/api/scg/serviceProfiles/forwarding/<fwd_profile_key>

        :param str ttgpdg_profile_name: TTGPDG forwarding profile name  

        :param str realm: realm to be added to profile

        :param str default_apn: default APN per realm

        :return: True if add defaultAPN is success, else False

        :rtype: boolean

        Example:

        | Add Default Apn Per Realm Entry In TTGPDG Forwarding Profile | ttgpdg_profile_name="Auto_TTGPDG_profile" | realm ="www.realm.com" | 
        |                                                              | default_apn="www.ttgpdg.com" |

        """
        if is_public_api == True  and os.getenv("API_VERSION", 'v4_0') == 'v5_0':
            res = self.pubapi.add_defaultapn_per_realm_entry_to_ttgpdg_profile(**kwargs)
        else:
            res = self.sjc.add_defaultapn_per_realm_entry_to_ttgpdg_profile(**kwargs)
        if not res:
            raise AssertionError("Add Default Apn per Realm Entry In  TTGPDG Forwarding Profile")
             
        return True
    
## will not migrate to public API as not used in any QA automation
    def validate_default_apn_per_realm_entry_in_ttgpdg_forwarding_profile(self, **kwargs):

        """ 

        API is used to validate Apn per Realm entry in TTGPDG Forwarding Profile

        URI: GET /wsg/api/scg/serviceProfiles/forwarding?type=TTGPDG
        
        :param str ttgpdg_profile_name: Name of TTGPDG forwarding profile

        :param str description: Descrption on TTGPDG Forwarding Profile

        :param str default_apn: Default Apn 

        :param str realm: Realm

        :return: True if Apn per Realm entry in TTGPDG Forwarding Profile is validated else False

        :rtype: boolean
        
        Example:

        | Validate Default Apn Per Realm Entry In TTGPDG Forwarding Profile | ttgpdg_profile_name="Auto_TTGPDG_profile" | realm ="www.realm.com" | 
        |                                                                   | default_apn="www.ttgpdg.com" |

        """
        

        res = self.sjc.validate_defaultapn_per_realm_entry_in_ttgpdg_profile(**kwargs)
        if not res:
            raise AssertionError("Validate Default Apn per Realm Entry In  TTGPDG Forwarding  Profile")
            
        return True 

## will not migrate to public API as not used in any QA automation
    def update_default_apn_per_realm_entry_in_ttgpdg_forwarding_profile(self, **kwargs):

        """

        API used to update Default APN per realm in TTGPDG Forwarding Profile.

        URI: PUT /wsg/api/scg/serviceProfiles/forwarding/<fwd_profile_key>

        :param str ttgpdg_profile_name: TTGPDG forwarding profile name

        :param str current_realm: realm to be added to profile

        :param str new_realm: New Realm name

        :param str default_apn: default APN per realm

        :return: True if add defaultAPN is success, else False

        :rtype: boolean

        Example:

        | Update Default Apn Per Realm Entry In TTGPDG Forwarding Profile | ttgpdg_profile_name="Auto_TTGPDG_profile" | current_realm ="www.realm.com" | 
        |                                                                 | new_realm="Update.realm.com" | default_apn="www.ttgpdg.com" |


        """

        res = self.sjc.update_defaultapn_per_realm_entry_in_ttgpdg_profile(**kwargs)
        if not res:
            raise AssertionError("Update Default Apn per Realm Entry In  TTGPDG Forwarding Profile")
            
        return True

## will not migrate to public API as not used in any QA automation
    def delete_default_apn_per_realm_entry_From_ttgpdg_forwarding_profile(self, **kwargs):

        """

        API used to delete the Default APN per Realm entry in TTGPDG Forwarding Profile

        URI: PUT /wsg/api/scg/serviceProfiles/forwarding/<ttgpdg_profile_key>

        :param str ttgpdg_profile_name: Name of TTGPDG Forwarding Profile

        :param str del_realm: Realm name

        :return: True if Default APN per Realm entry deleted else False

        :rtype: boolean

        Example:

        | Delete Default Apn Per Realm Entry From TTGPDG Forwarding Profile |  ttgpdg_profile_name="Auto_TTGPDG_profile" | del_realm="www.realm.com" |

        """
        

        res = self.sjc.delete_defaultapn_per_realm_entry_from_ttgpdg_profile(**kwargs)
        if not res:
            raise AssertionError("Delete Default Apn per Realm Entry In  TTGPDG Forwarding Profile")
            
        return True


    def delete_ttgpdg_forwarding_profile(self, is_public_api=IS_PUBLIC, **kwargs):
        
        """ 

        API used to delete the TTGPDG Forwarding Profile 

        URI: DELETE /wsg/api/scg/serviceProfiles/forwarding/<ttgpdg_profile_key>

        :param str ttgpdg_profile_name: Name of TTGPDG forwarding profile

        :return: True if TTGPDG Forwarding Profile deleted else False

        :rtype: boolean

         Example:

        | Delete TTGPDG Forwarding Profile |  ttgpdg_profile_name="Auto_TTGPDG_profile" |

        """        
        if is_public_api == True  and os.getenv("API_VERSION", 'v4_0') == 'v5_0':
            res = self.pubapi.delete_ttgpdg_profile(**kwargs)
        else:
            res = self.sjc.delete_ttgpdg_profile(**kwargs)
        if not res:
            raise AssertionError("Delete TTGPDG Forwarding Profile Failed")
            
        return True


    def create_wlan_profile(self, is_public_api=IS_PUBLIC, **kwargs):

        """ 
        API used to create WLAN 

        URI: POST /wsg/api/scg/wlans/

        :param str wlan_name: Name of the WLAN

        :param str ssid: SSID

        :param str description: Description

        :param str apzone_name: Name of APZone

        :param str domain_label: Name of Domain

        :param str enable_tunnel: 0 | 1  [default: '0']       
    
        :param str core_network_type: L30GRE | L20GRE | TTGPDG | Mixed

        :param str authentication_type: 0 - Standard | 1 - Wispr | 3 - Hotspot2.0 [default: '0']

        :param str authentication_method: OPEN | 802.1X | MAC [default: 'OPEN']

        :param str enable_mac_auth_password: 0 | 1 [default: '0']

        :param str mac_auth_password: MAC Authentication 

        :param str set_device_mac_address: 0 | 1 [default: '0']

        :param str encryption_method: WPA | WPA2 | WPA-MIXED | WEP | NONE [default: 'NONE']

        :param str wpa_version: WPA Version 

        :param str wep_key_index: WEP key index from 1 to 4

        :param str wep_key: WEP Key

        :param str encryption_algorithm: TKIP | AUTO | AES

        :param str passphrase: Passphrase 

        :param str enable_scg_proxy_for_auth: 0 | 1 [default: '0']

        :param str enable_scg_proxy_for_acct: 0 | 1 [default: '0']

        :param str acct_ttg_enable: 0 | 1  [default: '1']

        :param str acct_profile_name: Accounting Profile name [default:'Disable']

        :param str acct_interim_time: 0 - 1440 

        :param str auth_profile_name: Authentication Profile name [default:'Disable']

        :param str wispr_hotspot_name: WISPr Profile name

        :param str enable_hotspot_radius_proxy: 0 | 1  

        :param str hotspot2_name: Hotspot2.0 name

        :param str frwd_profile_name: Name Forwarding profile

        :param str nas_id_type: BSSID | APMAC | USER [default: 'BSSID']

        :param str nas_id_user_def: NAS ID used defined

        :param str radius_request_timeout: Radius request timeout [default: '3']

        :param str radius_max_retries: Radius maximum no of retries [default: '2']

        :param str nas_reconnect_primary: NAS Reconnect primary [default: '5']

        :param str called_sta_id: 0 | 1 [default: '0']

        :param str acct_delay_time_enable: 0 | 1

        :param str client_isolation: 1<enable> | 0<disable> [default: '0']

        :param str priority: high | low [default: 'high']

        :param str rate_limit_uplink: 0<disable> | unit in mbps [default: '0']

        :param str rate_limit_downlink: 0<disable> | unit in mbps [default: '0']

        :param str vlanid: VLAN id [default: '1']

        :param str dynamic_vlan_enable: 0 | 1 

        :param str core_qinq_enable: 0 | 1

        :param str vlanmapping_type: VLAN mapping type

        :param str core_add_fixed_svlan: Core add fixed SVLAN

        :param str hide_ssid: 1<broadcast> | 0<hide ssid> [default: '1']

        :param str proxy_arp: 0 | 1   [default: '0'] 

        :param str max_clients: Maximum clients [default: '100']

        :param str support_80211d: 0 | 1 [default: '0']

        :param str enable_dhcp: 0 | 1 [default: '0']

        :param str client_tx_rx_statistic: 0 | 1 [default: '0']

        :param str inactivity_timeout: 60 to 600 [default: '120']

        :param str enable_client_fingerprint: 0 | 1 [default: '0']

        :param str disable_wlan: 0 | 1 [default: '0']

        :param str bss_min_rate: BSS minimum bit rate [default: '0']

        :return: True if WLAN created successfully else False

        :rtype: boolean

        Example:

        | Create Wlan Profile | wlan_name='Auto_WLAN_Profile' | ssid='Auto_ssid' | apzone_name='Auto_apzone' | domain_label='Administration Domain' | 
        |                     | core_network_type='TTGPDG' | wpa_version='1' | encryption_algorithm='AES' | enable_scg_proxy_for_auth='0' | 
        |                     | enable_scg_proxy_for_acct='0' | acct_ttg_enable='1' | acct_profile_name='Auto_acct_profile' | 
        |                     | wispr_hotspot_name='Auto_hotspot' | 
 
        """

        if is_public_api:
            res=self.pubapi.create_wlan(**kwargs)  
        else:
            res = self.sjc.create_wlan(**kwargs)
            
        if not res:
            raise AssertionError("Create WLAN Failed")
            
        return True

    def get_zone_id_python(self, *args):
        return self.call_robot_keywords(GET_ZONEID_API, *args)

    def modify_basic_apzone_info_python(self, *args):
        return self.call_robot_keywords(MODIFY_ZONE_INFO_API, *args)
     
    def modify_apzone_login_python(self, *args):
        return self.call_robot_keywords(MODIFY_ZONE_LOGIN_API, *args)

    def modify_ap_user_location_info_python(self, *args):
        return self.call_robot_keywords(MODIFY_AP_USER_LOCATION_INFO, *args)

    def modify_ap_basic_info_python(self, *args):
        return self.call_robot_keywords(MODIFY_AP_BASIC_INFO, *args)

    def modify_ap_login_python(self, *args):
        return self.call_robot_keywords(MODIFY_AP_LOGIN, *args)

    def get_ap_configuration_status_python(self, *args):
            return self.call_robot_keywords(GET_AP_OPERATIONAL_INFO, *args)
        
    def move_ap_python(self, *args):
        return self.call_robot_keywords(MOVE_AP, *args) 

    def modify_ap_syslog_override_python(self, *args):
            return self.call_robot_keywords(MODIFY_AP_SYSLOG_OVERRIDE, *args)

    def modify_apzone_syslog_python(self, *args):
            return self.call_robot_keywords(MODIFY_APZONE_SYSLOG, *args)

    def verify_ap_syslog_facility_python(self, *args):
            return self.call_robot_keywords(VERIFY_AP_SYSLOG_FACILITY, *args)

    def verify_apzone_syslog_default_facility_python(self, *args):
            return self.call_robot_keywords(VERIFY_APZONE_SYSLOG_DEFAULT_FACILITY, *args)




    def validate_wlan_profile(self, **kwargs):

        """ 
        API used to Validate WLAN 

        URI: GET /wsg/api/scg/wlans/byZone/<apzone_uuid>

        :param str wlan_name: Name of the WLAN

        :param str ssid: SSID

        :param str description: Description

        :param str apzone_name: Name of APZone

        :param str domain_label: Name of Domain

        :param str enable_tunnel: 0 | 1  [default: '0']       
    
        :param str core_network_type: L30GRE | L20GRE | TTGPDG | Mixed

        :param str authentication_type: 0 - Standard | 1 - Wispr | 3 - Hotspot2.0 [default: '0']

        :param str authentication_method: OPEN | 802.1X | MAC [default: 'OPEN']

        :param str enable_mac_auth_password: 0 | 1 [default: '0']

        :param str mac_auth_password: MAC Authentication 

        :param str set_device_mac_address: 0 | 1 [default: '0']

        :param str encryption_method: WPA | WPA2 | WPA-MIXED | WEP | NONE [default: 'NONE']

        :param str wpa_version: WPA Version 

        :param str wep_key_index: WEP key index from 1 to 4

        :param str wep_key: WEP Key 

        :param str encryption_algorithm: TKIP | AUTO | AES

        :param str passphrase: Passphrase 

        :param str enable_scg_proxy_for_auth: 0 | 1 [default: '0'] 

        :param str enable_scg_proxy_for_acct: 0 | 1 [default: '0'] 

        :param str acct_ttg_enable: 0 | 1 acct_ttg_enable [default: '1'] 

        :param str acct_profile_name: Accounting Profile name [default: 'Disable']

        :param str acct_interim_time: 0 - 1440

        :param str auth_profile_name: Authentication Profile name [default: 'Disable']

        :param str wispr_hotspot_name: WISPr Profile name

        :param str enable_hotspot_radius_proxy: 0 | 1  

        :param str hotspot2_name: Hotspot2.0 name

        :param str frwd_profile_name: Name Forwarding profile

        :param str nas_id_type: BSSID | APMAC | USER [default: 'BSSID']

        :param str nas_id_user_def: NAS ID used defined

        :param str radius_request_timeout: Radius request timeout [default: '3']

        :param str radius_max_retries: Radius maximum no of retries [default: '2']

        :param str nas_reconnect_primary: NAS Reconnect primary [default: '5']

        :param str called_sta_id: 0 | 1 [default: '0']

        :param str acct_delay_time_enable: 0 | 1

        :param str client_isolation: 1<enable> | 0<disable> [default: '0']

        :param str priority: high | low [default: 'high']

        :param str rate_limit_uplink: 0<disable> | unit in mbps [default: '0']

        :param str rate_limit_downlink: 0<disable> | unit in mbps [default: '0']

        :param str vlanid: VLAN id [default: '1']

        :param str dynamic_vlan_enable: 0 | 1 

        :param str core_qinq_enable: 0 | 1

        :param str vlanmapping_type: VLAN mapping type

        :param str core_add_fixed_svlan: Core add fixed SVLAN

        :param str hide_ssid: 1<broadcast> | 0<hide ssid> [default: '1']

        :param str proxy_arp: 0 | 1   [default: '0'] 

        :param str max_clients: Maximum clients [default: '100']

        :param str support_80211d: 0 | 1 [default: '0']

        :param str enable_dhcp: 0 | 1 [default: '0']

        :param str client_tx_rx_statistic: 0 | 1 [default: '0']

        :param str inactivity_timeout: 60 to 600 [default: '120']

        :param str enable_client_fingerprint: 0 | 1 [default: '0']

        :param str disable_wlan: 0 | 1 [default: '0']

        :param str bss_min_rate: BSS minimum bit rate [default: '0']

        :return: True if WLAN Validated else False

        :rtype: boolean

        Example:

        | Validate Wlan Profile| wlan_name='Auto_WLAN_Profile' | ssid='Auto_ssid' | apzone_name='Auto_apzone' | domain_label='Administration Domain' | 
        |                      | core_network_type='TTGPDG' | wpa_version='1' | encryption_algorithm='AES' | enable_scg_proxy_for_auth='0' | 
        |                      | enable_scg_proxy_for_acct='0' | acct_ttg_enable='1' | acct_profile_name='Auto_acct_profile' | 
        |                      | wispr_hotspot_name='Auto_hotspot' | 
        """
        res = self.sjc.validate_wlan(**kwargs)
        if not res:
            raise AssertionError("Validate WLAN Failed")
            
        return True


    def update_wlan_profile(self, is_public_api=IS_PUBLIC, **kwargs):

        """ 
        API used to update WLAN 

        URI: PUT /wsg/api/scg/wlans/<wlan_key>

        :param str current_wlan_name: Original Name of WLAN

        :param str new_wlan_name: New Name of wlan

        :param str description: Description

        :param str apzone_name: Name of APZone

        :param str domain_label: Name of Domain

        :param str enable_tunnel: 0 | 1  [default: '0']       
    
        :param str core_network_type: L30GRE | L20GRE | TTGPDG | Mixed

        :param str authentication_type: 0 - Standard | 1 - Wispr | 3 - Hotspot2.0 [default: '0']

        :param str authentication_method: OPEN | 802.1X | MAC [default: 'OPEN']

        :param str enable_mac_auth_password: 0 | 1 [default: '0']

        :param str mac_auth_password: MAC Authentication 

        :param str set_device_mac_address: 0 | 1 [default: '0']

        :param str encryption_method: WPA | WPA2 | WPA-MIXED | WEP | NONE [default: 'NONE']

        :param str wpa_version: WPA VE+ersion

        :param str wep_key_index: WEP key index from 1 to 4

        :param str wep_key: WEP Key

        :param str encryption_algorithm: TKIP | AUTO | AES

        :param str passphrase: Passphrase 

        :param str enable_scg_proxy_for_auth: 0 | 1 [default: '0'] 

        :param str enable_scg_proxy_for_acct: 0 | 1 [default: '0'] 

        :param str acct_ttg_session: 0 | 1  [default: '1']

        :param str acct_profile_name: Accounting Profile name [default: 'Disable']

        :param str acct_interim_time: 0 - 1440

        :param str auth_profile_name: Authentication Profile name [default: 'Disable']

        :param str wispr_hotspot_name: WISPr Profile name

        :param str enable_hotspot_radius_proxy: 0 | 1  

        :param str hotspot2_name: Hotspot2.0 name

        :param str frwd_profile_name: Name Forwarding profile

        :param str nas_id_type: BSSID | APMAC | USER [default: 'BSSID']

        :param str nas_id_user_def: NAS ID used defined

        :param str radius_request_timeout: Radius request timeout [default: '3']

        :param str radius_max_retries: Radius maximum no of retries [default: '2']

        :param str nas_reconnect_primary: NAS Reconnect primary [default: '5']

        :param str called_sta_id: 0 | 1 [default: '0']

        :param str acct_delay_time_enable: 0 | 1

        :param str client_isolation: 1<enable> | 0<disable> [default: '0']

        :param str priority: high | low [default: 'high']

        :param str rate_limit_uplink: 0<disable> | unit in mbps [default: '0']

        :param str rate_limit_downlink: 0<disable> | unit in mbps [default: '0']

        :param str vlanid: VLAN id [default: '1']

        :param str dynamic_vlan_enable: 0 | 1 

        :param str core_qinq_enable: 0 | 1

        :param str vlanmapping_type: VLAN mapping type

        :param str core_add_fixed_svlan: Core add fixed SVLAN

        :param str hide_ssid: 1<broadcast> | 0<hide ssid> [default: '1']

        :param str proxy_arp: 0 | 1   [default: '0'] 

        :param str max_clients: Maximum clients [default: '100']

        :param str support_80211d: 0 | 1 [default: '0']

        :param str enable_dhcp: 0 | 1 [default: '0']

        :param str client_tx_rx_statistic: 0 | 1 [default: '0']

        :param str inactivity_timeout: 60 to 600 [default: '120']

        :param str enable_client_fingerprint: 0 | 1 [default: '0']

        :param str disable_wlan: 0 | 1 [default: '0']

        :param str bss_min_rate: BSS minimum bit rate [default: '0']
        
        :param str guest_access_name:  Name of Guest Access Profile

        :return: True if WLAN Updated successfully else False

        :rtype: boolean

        Example:

        | Update Wlan Profile| current_wlan_name='Auto_WLAN_Profile' | new_wlan_name='Update_WLAN_Profile' | ssid='Auto_ssid' | apzone_name='Auto_apzone' | 
        |                    | domain_label='Administration Domain' | core_network_type='TTGPDG' | wpa_version='1' | encryption_algorithm='AES' | 
        |                    | enable_scg_proxy_for_auth='0' | enable_scg_proxy_for_acct='0' | acct_ttg_enable='1' | acct_profile_name='Auto_acct_profile' |     
                          | wispr_hotspot_name='Auto_hotspot' |  |guest_access_name = 'guest_pass-R2'|

        """
        if is_public_api == True:
            self.call_robot_keywords(GET_ZONEID_API,kwargs['apzone_name'])
            self.call_robot_keywords(SET_WLANID_AND_ZONEID,kwargs['current_wlan_name'],kwargs['apzone_name'])

            if kwargs.has_key('enable_tunnel') and int(kwargs['enable_tunnel']) == 1:
                self.call_robot_keywords(UPDATE_WLAN_ACCESS_TUNNEL, 'RuckusGRE')
            else:
                print " Access tunnel is not enabled"
         
            if kwargs.has_key('core_network_type') :
                tunnel_type = kwargs['core_network_type']
                frwd_profile_name =''
                operator_realm = ''              
                if kwargs['core_network_type'] == 'TTGPDG':
                    tunnel_type = "TTG_PDG"               
                if kwargs.has_key('frwd_profile_name'):
                    frwd_profile_name = kwargs['frwd_profile_name']                
                if kwargs.has_key('operator_realm'):
                    operator_realm = kwargs['operator_realm']
                self.call_robot_keywords(UPDATE_WLAN_CORE_TUNNEL_TTG, tunnel_type, frwd_profile_name, operator_realm)            
            else:
                print "core network type is not specified"
                
            if kwargs.has_key('authentication_method'):
                if kwargs.has_key('encryption_method') and kwargs['encryption_method'] == 'WPA':
                    if kwargs.has_key('encryption_algorithm'):
                        self.call_robot_keywords(UPDATE_WLAN_ENCRYPTION,'WPA2',None,kwargs['encryption_algorithm'])
                    else:
                        self.call_robot_keywords(UPDATE_WLAN_ENCRYPTION, 'WPA2',None,"AES") 
                elif kwargs.has_key('encryption_method') and kwargs['encryption_method'] == 'NONE':
                    self.call_robot_keywords(UPDATE_WLAN_ENCRYPTION,'None')
            else:
                print "authentication method is not specified"

            if kwargs.has_key('acct_profile_name'):
                if kwargs.has_key('core_network_type') and kwargs['core_network_type'] == 'TTG_PDG':
                    # Passing accountingDelayEnabled as True 
                    self.call_robot_keywords(UPDATE_ACCTSERVICE_OF_WLAN,kwargs['acct_profile_name'],kwargs['enable_scg_proxy_for_acct'],True)
                else:
                    self.call_robot_keywords(UPDATE_ACCTSERVICE_OF_WLAN,kwargs['acct_profile_name'],kwargs['enable_scg_proxy_for_acct'])
            if kwargs.has_key('auth_profile_name'):
                location=True
                if int(kwargs['enable_scg_proxy_for_auth']) != 1:
                    location = False
                if kwargs.has_key('location'):
                    location= True  if  int(kwargs['location']) == 1  else  False  
                self.call_robot_keywords(UPDATE_AUTHSERVICE_OF_WLAN,kwargs['auth_profile_name'],kwargs['enable_scg_proxy_for_auth'],location)
                                
            clientIsolationEnabled=''
            forceDHCPEnabled=''
            pmkCachingEnabled=''
            okcEnabled=''
            if kwargs.has_key('client_isolation'):
                clientIsolationEnabled = kwargs['client_isolation']
            if kwargs.has_key('force_dhcp'):
                forceDHCPEnabled = kwargs['force_dhcp']
            if kwargs.has_key('pmk_enable'):
                pmkCachingEnabled = kwargs['pmk_enable']
            if kwargs.has_key('okc_enable'):
                okcEnabled = kwargs['okc_enable']
                
            self.call_robot_keywords(MODIFY_WLAN_ADVANCED_OPTIONS, kwargs['current_wlan_name'],kwargs['apzone_name'], clientIsolationEnabled, forceDHCPEnabled, pmkCachingEnabled, okcEnabled)
            """
            if kwargs.has_key('guest_access_name'):
                self.call_robot_keywords(MODIFY_WLAN_PORTAL_PROFILE,kwargs['guest_access_name'])
            """
            return True 
        else:
            res = self.sjc.update_wlan(**kwargs)

        if not res:
            raise AssertionError("Update WLAN Failed")
            
        return True


    def delete_wlan_profile(self, is_public_api=IS_PUBLIC, **kwargs):

        """ 
        API used to delete WLAN 

        URI: DELETE /wsg/api/scg/wlans/<wlan_key>

        :param str wlan_name: Name of WLAN

        :param str zone_name: Name of APZone

        :param str domain_label: name of Domain

        :return: True if WLAN deleted else False

        :rtype: boolean

        Example:
        
        | Delete Wlan Profile| wlan_name='Auto_WLAN_Profile' | apzone_name='Auto_apzone' | domain_label='Administration Domain' |

        """
        if is_public_api:
            res=self.pubapi.delete_wlan(**kwargs)  
        else:
            res = self.sjc.delete_wlan(**kwargs)

        if not res:
            raise AssertionError("Delete WLAN Failed")
            
        return True


    def create_wispr_profile(self, is_public_api=IS_PUBLIC, **kwargs):

        """ 
        API used to create the WISPr profile

        URI: POST /wsg/api/scg/hotspots/

        :param str wispr_profile_name: Name of WISPr Profile

        :param str zone_name: Name of the APZone

        :param str domain_label: Name of the Domain

        :param str description: Descrption

        :param str guest_user: 0 | 1 [default: '0']

        :param str smart_client_mode: enable | none | only [default: 'none']

        :param str access_type: INTERNAL | EXTERNAL [default: 'EXTERNAL']

        :param str second_redirect_type: start | user [default: 'user']

        :param str session_time: Session Timeout [default: '1440']

        :param str grace_period: Grace Period [default: '60']

        :param str location_name: Location Name

        :param str location_type: Location Type

        :param str smart_client_info: Information about the smart client

        :param str authentication_url: Logon URL

        :param str redirect_url: Start Page URL

        :param str walled_garden: Walled Garden entry

        :return: True if WISPr profile created else False

        :rtype: boolean
        
        Example:

        | Create Wispr Profile | wispr_profile_name="Auto_wispr_profile" | zone_name="Auto_apzone" | domain_label="Administration Domain" | 
        |                      | location_name='ACMEWISP' | location_type='us'| authentication_url='http://www.ruckuswireless.com' | 
        |                      | redirect_url='http://www.ruckuswireless.com' | walled_garden='1.2.3.4' |

        """

        if is_public_api:
            res=self.pubapi.create_wispr_profile(**kwargs)  
        else:
            res = self.sjc.create_wispr_profile(**kwargs)

        if not res:
            raise AssertionError("Create Wispr Profile Failed")
            
        return True

    def update_wispr_python(self, *args):
        return self.call_robot_keywords(UPDATE_WISPR_API, *args)

    def update_wispr_profile(self, **kwargs):

        """
        
        API used to update the WISPr profile

        URI: PUT /wsg/api/scg/hotspots/<wispr_profile_key> 

        :param str current_wispr_profile_name: Name of WISPr Profile
   
        :param str new_wispr_profile_name: New WISPr profile name

        :param str zone_name: Name of the APZone

        :param str domain_label: Name of the Domain

        :param str description: Descrption

        :param str guest_user: 0 | 1 [default: '0']

        :param str smart_client_mode: enable | none | only [default: 'none']

        :param str access_type: INTERNAL | EXTERNAL [default: 'EXTERNAL']

        :param str second_redirect_type: start | user [default: 'user']

        :param str session_time: Session Timeout [default: '1440']

        :param str grace_period: Grace Period [default: '60']

        :param str location_name: Location Name

        :param str location_type: Location Type

        :param str smart_client_info: Information about the smart client

        :param str authentication_url: Logon URL

        :param str redirect_url: Start Page URL

        :param str walled_garden: Walled Garden entry

        :return: True if WISPr profile created else False

        :rtype: boolean

         Example:

        | Update Wispr Profile | current_wispr_profile_name="Auto_wispr_profile" | new_wispr_profile_name="Update_wispr_profile" | zone_name="Auto_apzone" |
        |                      | domain_label="Administration Domain" | location_name='ACMEWISP' | location_type='us'| 
        |                      | authentication_url='http://www.ruckuswireless.com' | redirect_url='http://www.ruckuswireless.com' |
        |                      | walled_garden='1.2.3.4' |


  
        """
        ## scenarion when changing the wispr from internal to external OR vice-versa can't be supported using public rest all scenation has been verified
        ## this api is written specifically simulate GUI like user operation which are performed using JSON, only public API testsuite use this
        if  False:
            self.update_wispr_python(*args)
            return True
        else:
            res = self.sjc.update_wispr_profile(**kwargs)

        if not res:
            raise AssertionError("Update Wispr Profile Failed")
            
        return True

    def validate_wispr_profile(self, **kwargs):

        """

        API is used to validate WISPr Profile

        URI: GET /wsg/api/scg/hotspots/byZone/
        
        :param str wispr_profile_name: Name of WISPr Profile

        :param str zone_name: Name of the APZone

        :param str domain_label: Name of the Domain

        :param str description: Descrption

        :param str guest_user: 0 | 1 [default: '0']

        :param str smart_client_mode: enable | none | only [default: 'none']

        :param str access_type: INTERNAL | EXTERNAL [default: 'EXTERNAL']

        :param str second_redirect_type: start | user [default: 'user']

        :param str session_time: Session Timeout [default: '1440']

        :param str grace_period: Grace Period [default: '60']

        :param str aaa_server_name: Name of AAA Server 

        :param str account_server_name: Name of Accounting profile

        :param str acct_update_interval: 0 to 1440

        :param str smart_client_info: Information about the smart client

        :param str authentication_url: Logon URL

        :param str redirect_url: Start Page URL

        :param str walled_garden: Walled Garden entry

        :return: True if WISPr profile Validated else False

        :rtype: boolean

         Example:

        | validate Wispr Profile | wispr_profile_name="Auto_wispr_profile" | zone_name="Auto_apzone" | domain_label="Administration Domain" | 
        |                        | location_name='ACMEWISP' | location_type='us'| authentication_url='http://www.ruckuswireless.com' | 
        |                        | redirect_url='http://www.ruckuswireless.com' | walled_garden='1.2.3.4' |

        """

        res = self.sjc.validate_wispr_profile(**kwargs)

        if not res:
            raise AssertionError("Validate Wispr Profile Failed")
            

        return True

    def delete_wispr_python(self, *args):
        return self.call_robot_keywords(DELETE_WISPR_API, *args)
    
    def delete_wispr_profile(self, *args):

        """
        API used to delete WISPr profile

        URI: DELETE /wsg/api/scg/hotspots/<wispr_profile_key>

        :param str wispr_profile_name: Name of WISPr profile

        :param str zone_name: Name of APZone

        :param str domain_label: Name of Domain

        :return: True if WISPr profile deleted else False

        :rtype: boolean

        Example:

        | Delete Wispr Profile | wispr_profile_name="Auto_wispr_profile" | zone_name="Auto_apzone" | domain_label="Administration Domain" |

        """
        if  IS_PUBLIC:
            self.delete_wispr_python(*args)
            return True
        else:
            res = self.sjc.delete_wispr_profile(**kwargs)

        if not res:
            raise AssertionError("Delete  Wispr Profile Failed")
             
        return True


    def add_walled_garden_to_wispr_profile(self, **kwargs):

        """
        API used to add the WalledGarden to Wispr Profile

        URI: PUT /wsg/api/scg/hotspotsProfile/<hotspot_profile_key>

        :param str wispr_profile_name: Name of the Wispr Profile

        :param str zone_name: Apzone Name

        :param str domain_label: Domain Name

        :param str walledgarden: walledgarden value

        :return: True if WalledGarden added to Wispr Profile successfully else False

        :rtype: boolean

        Example:

        | Add Walled Garden To Wispr Profile | wispr_profile_name="Auto_wispr_profile" | zone_name="Auto_apzone" | domain_label="Administration Domain" | 
        |                                    | walledgarden='4.5.6.7' |  

        """
 
        res = self.sjc.add_walledgarden_to_wispr_profile(**kwargs)

        if not res:
            raise AssertionError("Add walledgarden to WISPr profile Failed")
            
        return True

    def update_walled_garden_in_wispr_profile(self, **kwargs):

        """
        API used to update the WalledGarden in Wispr Profile

        URI: PUT /wsg/api/scg/hotspotsProfile/<hotspot_profile_key>?

        :param str wispr_profile_name: Name of the Wispr Profile

        :param str zone_name: Apzone Name

        :param str domain_label: Domain Name

        :param str curent_walledgarden: ip or iprange

        :param str new_walledgarden: ip or iprange

        :return: True if WalledGarden updated successfully else False

        :rtype: boolean

        Example:

        | Update Walled Garden To Wispr Profile | wispr_profile_name="Auto_wispr_profile" | zone_name="Auto_apzone" | domain_label="Administration Domain" |
        |                                       | current_walledgarden='4.5.6.7' |  new_walledgarden='8.9.9.9' |

        """

        
        res = self.sjc.update_walledgarden_in_wispr_profile(**kwargs)

        if not res:
            raise AssertionError("Validate walledgarden in WISPr profile Failed")
            
        return True

    def delete_walled_garden_from_wispr_profile(self, **kwargs):

        """
        API used to update the WalledGarden from Wispr Profile

        URI: PUT /wsg/api/scg/hotspotsProfile/<hotspot_profile_key>?

        :param str wispr_profile_name: Name of the Wispr Profile

        :param str zone_name: Apzone Name

        :param str domain_label: Domain Name

        :param str walledgarden: walledgarden value

        :return: True if WalledGarden updated successfully else False

        :rtype: boolean

        Example:

        | Delete  Walled Garden To Wispr Profile | wispr_profile_name="Auto_wispr_profile" | zone_name="Auto_apzone" | domain_label="Administration Domain" |        |                                        | walledgarden='4.5.6.7' |

        """

        res = self.sjc.delete_walledgarden_from_wispr_profile(**kwargs)

        if not res:
            raise AssertionError("Delete walledgarden form WISPr profile Failed")
            
        return True


    def create_ftp_service(self, is_public_api=IS_PUBLIC, **kwargs):

        """
        API used to create FTP service

        URI: POST /wsg/api/scg/ftpservice?

        :param str ftp_name: Name of FTP service

        :param str ftp_host: IP Address of FTP Service

        :param str ftp_port: Port number [default: 21]

        :param str ftp_username: Username of FTP Service

        :param str ftp_password: Password 

        :param remote_dir: Remote Directory

        :return: True if FTP Service created else False

        :rtype: boolean

        Example:
        
        | Create Ftp Service | ftp_name="BORA" | ftp_host="1.2.3.4" | ftp_port="22" | ftp_username="ruckus" | ftp_password="ruckus1!" | remote_dir="" |

        """
        if is_public_api == True  and os.getenv("API_VERSION", 'v4_0') == 'v5_0':
            res = self.pubapi.create_ftp_service(**kwargs)
        else:
            res = self.sjc.create_ftp_service(**kwargs)
        if not res:
            raise AssertionError("Create FTP service Failed")
            
        return True


## not migrating not used in code
    def validate_ftp_service(self, **kwargs):


        """
        API used to Validate FTP service

        URI: POST /wsg/api/scg/ftpservice?

        :param str ftp_name: Name of FTP service

        :param str ftp_host: IP Address of FTP Service

        :param str ftp_port: Port number [default: 21]

        :param str ftp_username: Username of FTP Service

        :param str ftp_password: Password 

        :param remote_dir: Remote Directory

        :return: True if FTP Service Validated else False

        :rtype: boolean

        Example:
        
        | Validate Ftp Service | ftp_name="BORA" | ftp_host="1.2.3.4" | ftp_port="22" | ftp_username="ruckus" | ftp_password="ruckus1!" | remote_dir="" |

        """

        res = self.sjc.validate_ftp_service(**kwargs)

        if not res:
            raise AssertionError("Validate FTP service Failed")
            
        return True



## not migrating not used in code
    def update_ftp_service(self, **kwargs):

        """
        API is used to update FTP services

        URI: PUT /wsg/api/scg/ftpservice/<ftp_service_key>

        :param str current_ftp_name: Original Name of FTP service

        :param str new_ftp_name: New Name of FTP service

        :param str ftp_host: IP Address of FTP Service

        :param str ftp_port: Port number [default: 21]

        :param str ftp_username: Username of FTP

        :param str ftp_password: Password

        :param remote_dir: Remote Directory

        :return: True if FTP Service is updated else False

        :rtype: boolean 
        
        Example:

        | Update Ftp Service | current_ftp_name="BORA" | new_ftp_name="Update_BORA" | ftp_port="22" | ftp_username="ruckus" | ftp_password="ruckus1!" | 
        |                    | remote_dir="" |

        """

        res = self.sjc.update_ftp_service(**kwargs)

        if not res:
            raise AssertionError("Update FTP service Failed")
            
        return True

    def delete_ftp_service(self, is_public_api=IS_PUBLIC,  **kwargs):

        """
        API is used to delete FTP Service

        URI: DELETE /wsg/api/scg/ftpservice/<ftp_service_keys> 

        :param str ftp_name: Name of the FTP Service

        :return: True if FTP Service is deleted else False

        :rtype: boolean
        
        Example:

        | Delete Ftp Service | ftp_name="BORA" |

        """
        if is_public_api == True  and os.getenv("API_VERSION", 'v4_0') == 'v5_0':
            res = self.pubapi.delete_ftp_service(**kwargs)
        else:
            res = self.sjc.delete_ftp_service(**kwargs)

        if not res:
            raise AssertionError("Delete FTP service Failed")
            
        return True



    def enable_eapaka_service(self, **kwargs):

        """ 
        API used to Enable EAP-AKA Service
        
        URI: PUT /wsg/api/scg/globalSettings/eapaka? 

        :return: True if EAP-AKA Service enabled else False

        :rtype: boolean

        Example:

        | Enable Eapaka Service |

        """

        res = self.sjc.enable_eapaka_service(**kwargs)

        if not res:
            raise AssertionError("Enable EAP-AKA Service Failed")
            
        return True


    def disable_eapaka_service(self, **kwargs):

        
        """ 
        API used to Disable the EAP-AKA Service

        URI: PUT /wsg/api/scg/globalSettings/eapaka?

        :return: True if EAP-AKA Service disabled else False

        :rtype: boolean

        Example:

        | Disable Eapaka Service |
        
        """

        res = self.sjc.disable_eapaka_service(**kwargs)

        if not res:
            raise AssertionError("Disable EAP-AKA Service Failed")
            
        return True

    def update_eapaka_service(self, **kwargs):

        """ 
        API used to update EAP-AKA Service 

        URI: PUT /wsg/api/scg/globalSettings/eapaka?

        :param str eapaka_service_enable: true | false

        :param boolean privacy_support: True | False

        :param boolean fast_reauth: True | False

        :param str secret_key_for_active_key: Active secret key in number

        :param str fast_reauth_realm: Reauthentication Realm

        :param str max_sucreahth: Max successive Reauthentication 1 to 65535

        :param str cleanup: true | false [default: true]

        :param str cleanup_time_hrs: Cache cleanup time in hours 0 to 23 [default: 00]

        :param str cleanup_time_mins: Cache cleanup time in minutes 0 to 59 [default: 00]

        :param str cache_history_len: Cache history length 1 to 744 [default: 256]

        :return: True if  EAP-AKA Service success else False

        :rtype: boolean

        Example:
        
        | Update Eapaka Service | eapaka_service_enable="true" | fast_reauth=False | secret_key_for_active_key='0' | cleanup="true" | cleanup_time_hrs='5' |
        |                       | cleanup_time_mins='50' | cache_history_len='120' |
        
        """

        res = self.sjc.update_eapaka_service(**kwargs)

        if not res:
            raise AssertionError("Update EAP-AKA Service Failed")
                     
        return True              
                                   
    def validate_eapaka_service(self, **kwargs):

        """ 
        API used to validate the EAP-AKA Service 

        URI: PUT /wsg/api/scg/globalSettings/eapaka?

        :param str eapaka_service_enable: true | false

        :param boolean privacy_support: True | False

        :param boolean fast_reauth: True | False

        :param str secret_key_for_active_key: Active secret key in number

        :param str secret_key_entry: secret key for EAP-AKA Secret Key configuration

        :param str fast_reauth_realm: Reauthentication Realm

        :param str max_sucreahth: Max successive Reauthentication 1 to 65535

        :param str cleanup: true | false [default: true]

        :param str cleanup_time_hrs: Cache cleanup time in hours 0 to 23 [default: 00]

        :param str cleanup_time_mins: Cache cleanup time in minutes 0 to 59 [default: 00]

        :param str cache_history_len: Cache history length 1 to 744 [default: 256]

        :return: True if  EAP-AKA Service success else False

        :rtype: boolean

        Example:

        | Validate Eapaka Service | eapaka_service_enable="true" | fast_reauth=False | secret_key_for_active_key='0' | cleanup="true" | 
        |                         | cleanup_time_hrs='5' | cleanup_time_mins='50' | cache_history_len='120' |

        """

        res = self.sjc.validate_eapaka_service(**kwargs)


        if not res:              
            raise AssertionError("Validate EAP-AKA Service Failed")
            
        return True

    def add_secret_key_to_eapaka_configuration(self, **kwargs):

        
        """
        API used to Add Secret Key to EAP-AKA Service

        URI: PUT /wsg/api/scg/globalSettings/eapaka?

        :param str secret_key: Secret Key to be added

        :return: True if Secret Key is added else False

        :rtype: boolean
        
        Example:

        | Add Secret Key to Eapaka Configuration | secret_key='ruckus1.com' |

        """
         
        res = self.sjc.add_secretkey_to_eapaka_configuration(**kwargs)

        if not res:
            raise AssertionError("Add Secret key to EAP-AKA Service Failed")
            
        return True


    def validate_secret_key_in_eapaka_configuration(self, **kwargs):

        
        """
        API used to Validate  Secret Key in EAP-AKA Service

        URI: PUT /wsg/api/scg/globalSettings/eapaka?

        :param str secret_key: Secret Key to be added

        :return: True if Secret Key is added else False

        :rtype: boolean

        Example:
        
        | Validate Secret Key In Eapaka Configuration | secret_key='ruckus1.com' |
        
        """

        res = self.sjc.validate_secretkey_in_eapaka_configuration(**kwargs)

        if not res:
            raise AssertionError("Validate Secret key in EAP-AKA Service Failed")
            
        return True
   
    def update_secret_key_in_eapaka_configuration(self, **kwargs):

        """
        API used to update the Secret Key in EAP-AKA Service
        
        URI: PUT /wsg/api/scg/globalSettings/eapaka?

        :param str current_secret_key: Name of the current secret key 

        :param str new_secret_key: Name of new secret key 

        :return: True if update secret key success else False

        :rtype: boolean

        Example:
        
        | Update Secret Key In Eapaka Configuration | current_secret_key='ruckus1.com' | new_secret_key='update_ruckus1.com' |

        """
 
        res= self.sjc.update_secretkey_in_eapaka_configuration(**kwargs)
        if not res:
            raise AssertionError("Update Secret key in EAP-AKA Service Failed")
            
        return True

        

    def delete_secret_key_from_eapaka_configuration(self, **kwargs):

        """
        API used to delete the Secret key in EAP-AKA Service
        
        URI: PUT /wsg/api/scg/globalSettings/eapaka?

        :param str secret_key: Name of the Secret Key to be deleted

        :return: True if Secret Key deleted else False

        :rtype: boolean

        Example:

        | Delete Secret Key From Eapaka Configuration | secret_key='ruckus1.com' |

        """

        res = self.sjc.delete_secretkey_from_eapaka_configuration(**kwargs)

        if not res:
            raise AssertionError("Delete Secret key from EAP-AKA Service Failed")
            
        return True


    def enable_eapsim_service(self, **kwargs):

        """ 
        API used to Enable EAP-SIM Service
        
        URI: PUT /wsg/api/scg/globalSettings/eapsim? 

        :return: True if EAP-SIM Service enabled else False

        :rtype: boolean

        Example:

        | Enable Eapsim Service |

        """

        res = self.sjc.enable_eapsim_service(**kwargs)

        if not res:
            raise AssertionError("Enable EAP-SIM Service Failed")
            
        return True


    def disable_eapsim_service(self, **kwargs):

        """ 
        API used to Disable the EAP-SIM Service
        
        URI: PUT /wsg/api/scg/globalSettings/eapsim? 
            
        :return: True if EAP-SIM Service disabled else False

        :rtype: boolean

        Example:

        | Disable Eapsim Service |

        """

        res = self.sjc.disable_eapsim_service(**kwargs)


        if not res:
            raise AssertionError("Disable EAP-SIM Service Failed")
            
        return True
    
    def update_eapsim_service(self, **kwargs):

        """ 
        API used to update EAP-SIM Service with given parameters

        URI: PUT /wsg/api/scg/globalSettings/eapsim?

        :param str eapsim_service_enable: true | false

        :param boolean privacy_support: True | False

        :param boolean fast_reauth: True | False

        :param str secret_key_for_active_key: Active secret key in number

        :param str fast_reauth_realm: Reauthentication Realm

        :param str max_sucreahth: Max successive Reauthentication 1 to 65535 [default:256]

        :param str cleanup: true | false [default: true]

        :param str cleanup_time_hrs: Cache cleanup time in hours 0 to 23 [default: 00]

        :param str cleanup_time_mins: Cache cleanup time in minutes 0 to 59 [default: 00]

        :param str cache_history_len: Cache history length 1 to 744 [default: 256]

        :return: True if  EAP-SIM Service Updated else False

        :rtype: boolean

        Example:

        | Update Eapsim Service | eapsim_service_enable="true" | fast_reauth=False | secret_key_for_active_key='0' | cleanup="true" | 
        |                       | cleanup_time_hrs='5' | cleanup_time_mins='50' | cache_history_len='120' | 

        """

        
        res = self.sjc.update_eapsim_service(**kwargs)

        if not res:
            raise AssertionError("Update EAP-SIM Service Failed")
            
        return True

    def validate_eapsim_service(self, **kwargs):

        """ 
        API used to Validate the EAP-SIM Service with given parameters

        URI: PUT /wsg/api/scg/globalSettings/eapsim?

        :param str eapsim_service_enable: true | false

        :param boolean privacy_support: True | False

        :param boolean fast_reauth: True | False

        :param str secret_key_for_active_key: Active secret key in number

        :param str fast_reauth_realm: Reauthentication Realm

        :param str max_sucreahth: Max successive Reauthentication 1 to 65535 [default:256]

        :param str cleanup: true | false [default: true]

        :param str cleanup_time_hrs: Cache cleanup time in hours 0 to 23 [default: 00]

        :param str cleanup_time_mins: Cache cleanup time in minutes 0 to 59 [default: 00]

        :param str cache_history_len: Cache history length 1 to 744 [default: 256]

        :return: True if  EAP-SIM Service Validated else False

        :rtype: boolean

        Example:

        | validate Eapsim Service | eapsim_service_enable="true" | fast_reauth=False | secret_key_for_active_key='0' | cleanup="true" | 
        |                         | cleanup_time_hrs='5' | cleanup_time_mins='50' | cache_history_len='120' |

        """
        
        res = self.sjc.validate_eapsim_service(**kwargs)

        if not res:
            raise AssertionError("Validate EAP-SIM Service Failed")
            
        return True

    def add_secret_key_to_eapsim_configuration(self, **kwargs):
        
        """
        API used to Add Secret Key to EAP-SIM 

        URI: PUT /wsg/api/scg/globalSettings/eapsim?

        :param str secret_key: Secret Key to be added

        :return: True if Secret Key added else False

        :rtype: boolean

        Example:

        | Add Secret Key to Eapsim Configuration | secret_key='ruckus1.com' |

        """

        res = self.sjc.add_secretkey_to_eapsim_configuration(**kwargs)

        if not res:
            raise AssertionError("Add Secret key to EAP-SIM Service Failed")
            
        return True

    def validate_secret_key_in_eapsim_configuration(self, **kwargs):

        """
        API used to Validate Secret Key in EAP-SIM 

        URI: PUT /wsg/api/scg/globalSettings/eapsim?

        :param str secret_key: Secret Key to be added

        :return: True if Secret Key Validated else False

        :rtype: boolean
        
        Example:

        | Validate Secret Key In Eapsim Configuration | secret_key='ruckus1.com' |

        """


        res = self.sjc.validate_secretkey_in_eapsim_configuration(**kwargs)

        if not res:
            raise AssertionError("Validate Secret key in EAP-SIM Service Failed")
            
        return True

    def update_secret_key_in_eapsim_configuration(self, **kwargs):

        """
        API used in update Secret Key in EAP-SIM Service
        
        URI: PUT /wsg/api/scg/globalSettings/eapsim?

        :param str current_secret_key: Name of the current secret key 

        :param str new_secret_key: Name of new secret key 

        :return: True if update secret key success else False

        :rtype: boolean

        Example:

        | Update Secret Key In Eapsim Configuration | current_secret_key='ruckus1.com' | new_secret_key='update_ruckus1.com' |

        """

        res = self.sjc.update_secretkey_in_eapsim_configuration(**kwargs)

        if not res:
            raise AssertionError("Update Secret key in EAP-SIM Service Failed")
            
        return True

    def delete_secret_key_from_eapsim_configuration(self, **kwargs):

        """
        API used from  delete the Secret key in EAP-SIM Service
        
        URI: PUT /wsg/api/scg/globalSettings/eapsim?

        :param str secret_key: Name of the Secret Key to be deleted

        :return: True if Secret Key deleted else False

        :rtype: boolean

        Example:

        | Delete Secret Key From Eapsim Configuration | secret_key='ruckus1.com' |


        """

        res = self.sjc.delete_secretkey_from_eapsim_configuration(**kwargs)

        if not res:
            raise AssertionError("Delete Secret key from EAP-SIM Service Failed")
            
        return True


    def create_apzone(self, is_public_api=IS_PUBLIC, **kwargs):
        
        """
        
        API used to create APZone

        URI: POST /wsg/api/scg/zones?

        :param str zone_name: AP Zone Name

        :param str description: Description

        :param str ap_firmware: AP Firmware

        :param str country_code: Country Code    [default: US]

        :param str login_id: For admin login Login ID

        :param str password: For admin login Password 

        :param str syslog_ip: Syslog server ip

        :param str syslog_port: Syslog Port number

        :param str enable_mesh: 0 | 1   [default: 0]

        :param str mesh_name: Mesh name or ESSID

        :param str mesh_passphrase: Mesh Passphrase

        :param str mesh_uplink_selection: throughput | rssi

        :param str radio_2Ghz_channelization: 20MHz | 40MHz    [default: 20MHz] 

        :param str radio_2Ghz_channel: 0 | 1 | 2 | so on upto | 10      [default: 0]

        :param str radio_2Ghz_tx_power: max | 1 | 2 | so on upto | 10 | min     [default: max]

        :param str radio_5Ghz_channelization: 20MHz | 40MHz     [default: 40MHz]

        :param str radio_5Ghz_channel_indoor: 0 | 36 | 40 | 44 | 48 | 149 | 153 | 157 | 161     [default: 0]

        :param str radio_5Ghz_channel_outdoor: 0 | 149 | 153 | 157 | 161        [default: 0]

        :param str radio_5Ghz_tx_power: max | -1 | upto | -10   [default: max]

        :param str tunnel_type: 1 | 0   [default: 0]

        :param str enable_tunnel_encryption: 0 | 1

        :param str wan_interface_mtu: 1(auto) | 0(manual)

        :param str mtu_size: Size in bytes 850 to 1500

        :param str channel_mode: 0 | 1

        :param str back_ground_scan_on_2GHz: 0 | 1      [default: 0]

        :param str back_ground_scan_on_2GHz_timer: 0 to 65535   [default: 20]

        :param str back_ground_scan_on_5GHz: 0 | 1      [default: 0]

        :param str back_ground_scan_on_5GHz_timer: 0 to 65535   [default: 20]

        :param str enableclbfor2GHz: 0 | 1      [default: 0]

        :param str enableclbfor5GHz: 0 | 1      [default: 0]

        :param str adj_radio_threshold_2GHz: from 1 to 65535

        :param str adj_radio_threshold_5GHz: from 1 to 65535

        :param str smart_monitor_enable: 0 | 1          [default: 0]

        :param str smart_monitor_interval: Health check interval  5 to 60

        :param str smart_monitor_threshold: Health check retry threshold 1 to 10

        :return: True if APZone created else False

        :rtype: boolean

        Example:

        | Create ApZone | zone_name='Auto-1-apzone'| login_id='admin' | password='ruckus1!' | mesh_name='mesh-s8xLjNAE' | 
        |                       | smart_monitor_interval='10'| adj_radio_threshold_2GHz='20'| adj_radio_threshold_5GHz='20' | smart_monitor_threshold='3' | 

        """
        
        if is_public_api:
            res=self.pubapi.create_apzone(**kwargs)  
        else:
            res = self.sjc.create_apzone(**kwargs)

        if not res:
            raise AssertionError("Create AP Zone Failed")
            
        return True
    
    def create_apzone_template(self, **kwargs):
        
        """
        
        API used to create APZone template

        URI: POST /wsg/api/scg/templates2/zone

        :param str zone_name: AP Zone TemplateName
        :return: True if APZone Template created else False

        :rtype: boolean

        Example:

        | Create ApZone Template| zone_template_name='Auto-1-apzone'| login_id='admin' | password='ruckus1!' | mesh_name='mesh-s8xLjNAE' | 
        |                       | smart_monitor_interval='10'| adj_radio_threshold_2GHz='20'| adj_radio_threshold_5GHz='20' | smart_monitor_threshold='3' | 

        """
        res = self.sjc.create_apzone_template(**kwargs)

        if not res:
            raise AssertionError("Create AP Zone Template Failed")
            
        return True

    def apply_zone_template(self, **kwargs):
        
        """
        
        API used to apply APZone template

        URI: POST /wsg/api/scg/templates2/zone/%s

        :param str zone_name: AP Zone Name
        :param str zone_template_name: AP Zone TemplateName
        :return: True if APZone Template created else False

        :rtype: boolean

        Example:

        | Apply ApZone Template| zone_template_name='Auto-1-apzone'| login_id='admin' | password='ruckus1!' | mesh_name='mesh-s8xLjNAE' | 
        |                       | smart_monitor_interval='10'| adj_radio_threshold_2GHz='20'| adj_radio_threshold_5GHz='20' | smart_monitor_threshold='3' | 

        """
        res = self.sjc.apply_zone_template(**kwargs)

        if not res:
            raise AssertionError("apply AP Zone Template Failed")
            
        return True

    def delete_zone_template(self, **kwargs):
        
        """
        
        API used to delete APZone template

        URI: POST /wsg/api/scg/templates2/zone/%s

        :param str zone_template_name: AP Zone TemplateName
        :return: True if APZone Template created else False

        :rtype: boolean

        Example:

        | Delete Zone Template| zone_template_name='Auto-1-apzone'|
        """
        res = self.sjc.delete_zone_template(**kwargs)

        if not res:
            raise AssertionError("delete AP Zone Template Failed")
            
        return True
    
    def validate_apzone(self, **kwargs):

        """
        
        API is used to validate AP Zone

        URI: GET /wsg/api/scg/zones/<apzone_uuid>/config
       
        :param str zone_name: AP ZOne Name

        :param str description: Description

        :param str ap_firmware: AP Firmware

        :param str country_code: Country Code    [default: US]

        :param str login_id: For admin login Login ID

        :param str password: For admin login Password 

        :param str syslog_ip: Syslog server ip

        :param str syslog_port: Syslog Port number

        :param str enable_mesh: 0 | 1   [default: 0]

        :param str mesh_name: Mesh name or ESSID

        :param str mesh_passphrase: Mesh Passphrase

        :param str mesh_uplink_selection: throughput | rssi

        :param str radio_2Ghz_channelization: 20MHz | 40MHz    [default: 20MHz] 

        :param str radio_2Ghz_channel: 0 | 1 | 2 | so on upto | 10      [default: 0]

        :param str radio_2Ghz_tx_power: max | 1 | 2 | so on upto | 10 | min     [default: max]

        :param str radio_5Ghz_channelization: 20MHz | 40MHz     [default: 40MHz]

        :param str radio_5Ghz_channel_indoor: 0 | 36 | 40 | 44 | 48 | 149 | 153 | 157 | 161     [default: 0]

        :param str radio_5Ghz_channel_outdoor: 0 | 149 | 153 | 157 | 161        [default: 0]

        :param str radio_5Ghz_tx_power: max | -1 | upto | -10   [default: max]

        :param str tunnel_type: 1 | 0   [default: 0]

        :param str enable_tunnel_encryption: 0 | 1

        :param str wan_interface_mtu: 1(auto) | 0(manual)

        :param str mtu_size: Size in bytes 850 to 1500

        :param str channel_mode: 0 | 1

        :param str back_ground_scan_on_2GHz: 0 | 1      [default: 0]

        :param str back_ground_scan_on_2GHz_timer: 0 to 65535   [default: 20]

        :param str back_ground_scan_on_5GHz: 0 | 1      [default: 0]

        :param str back_ground_scan_on_5GHz_timer: 0 to 65535   [default: 20]

        :param str enableclbfor2GHz: 0 | 1      [default: 0]

        :param str enableclbfor5GHz: 0 | 1      [default: 0]

        :param str adj_radio_threshold_2GHz: Adjucent radio threshold of 2.4GHz 

        :param str adj_radio_threshold_5GHz: Adjucent radio threshold of 5GHz

        :param str smart_monitor_enable: 0 | 1          [default: 0]

        :param str smart_monitor_interval: Health check interval  5 to 60

        :param str smart_monitor_threshold: Health check retry threshold 1 to 10

        :return: True if APZone Validated else False

        :rtype: boolean

        Example:

        | Validate ApZone | zone_name='Auto-1-apzone'| login_id='admin' | password='ruckus1!' | mesh_name='mesh-s8xLjNAE' | 
        |                       | smart_monitor_interval='10'| adj_radio_threshold_2GHz='20'| adj_radio_threshold_5GHz='20' | smart_monitor_threshold='3' | 

        """ 

        res = self.sjc.validate_apzone(**kwargs)

        if not res:
            raise AssertionError("Validate AP Zone Failed")
            
        return True

    def update_apzone(self, is_public_api=IS_PUBLIC, **kwargs):

        """
        URI: POST /wsg/api/scg/zones/<apzone_uuid>/config

        :param str current_zone_name: Orginal Ap Zone Name

        :param str new_zone_name: New  Ap Zone Name

        :param str description: Description

        :param str ap_firmware: AP Firmware

        :param str country_code: Country Code    [default: US]

        :param str login_id: For admin login Login ID

        :param str password: For admin login Password 

        :param str syslog_ip: Syslog server ip

        :param str syslog_port: Syslog Port number

        :param str enable_mesh: 0 | 1   [default: 0]

        :param str mesh_name: Mesh name or ESSID

        :param str mesh_passphrase: Mesh Passphrase

        :param str mesh_uplink_selection: throughput | rssi

        :param str radio_2Ghz_channelization: 20MHz | 40MHz    [default: 20MHz] 

        :param str radio_2Ghz_channel: 0 | 1 | 2 | so on upto | 10      [default: 0]

        :param str radio_2Ghz_tx_power: max | 1 | 2 | so on upto | 10 | min     [default: max]

        :param str radio_5Ghz_channelization: 20MHz | 40MHz     [default: 40MHz]

        :param str radio_5Ghz_channel_indoor: 0 | 36 | 40 | 44 | 48 | 149 | 153 | 157 | 161     [default: 0]

        :param str radio_5Ghz_channel_outdoor: 0 | 149 | 153 | 157 | 161        [default: 0]

        :param str radio_5Ghz_tx_power: max | -1 | upto | -10   [default: max]

        :param str tunnel_type: 1 | 0   [default: 0]

        :param str enable_tunnel_encryption: 0 | 1

        :param str wan_interface_mtu: 1(auto) | 0(manual)

        :param str mtu_size: Size in bytes 850 to 1500

        :param str channel_mode: 0 | 1

        :param str back_ground_scan_on_2GHz: 0 | 1      [default: 0]

        :param str back_ground_scan_on_2GHz_timer: 0 to 65535   [default: 20]

        :param str back_ground_scan_on_5GHz: 0 | 1      [default: 0]

        :param str back_ground_scan_on_5GHz_timer: 0 to 65535   [default: 20]

        :param str enableclbfor2GHz: 0 | 1      [default: 0]

        :param str enableclbfor5GHz: 0 | 1      [default: 0]

        :param str adj_radio_threshold_2GHz: Adjucent radio threshold of 2.4GHz 

        :param str adj_radio_threshold_5GHz: Adjucent radio threshold of 5GHz

        :param str smart_monitor_enable: 0 | 1          [default: 0]

        :param str smart_monitor_interval: Health check interval  5 to 60

        :param str smart_monitor_threshold: Health check retry threshold 1 to 10

        :return: True if APZone Deleted else False

        :rtype: boolean


        Example:

        | Update ApZone | current_zone_name='Auto-1-apzone' | new_zone_name='update-1-apzone' |login_id='admin' | password='ruckus1!' |
        |                       | mesh_name='mesh-s8xLjNAE' | smart_monitor_interval='10'| adj_radio_threshold_2GHz='20'| adj_radio_threshold_5GHz='20' |
        |                       | smart_monitor_threshold='3' |
        
        """ 
        if  os.getenv("SCG_MODEL","") == 'Enterprise' or os.getenv("SCG_MODEL","") == 'enterprise':
            res = self.sjc.update_apzone(**kwargs)
        elif is_public_api:
            res=self.pubapi.update_apzone(**kwargs)  
        else:
            res = self.sjc.update_apzone(**kwargs)
        if not res:
            raise AssertionError("Validate AP Zone Profile Failed")
            
        return True


    def update_apzone_login(self, *kwargs):
        """
        URI: POST /wsg/api/scg/zones/<apzone_uuid>/config

        :param str zone_name:  Ap Zone Name

        :param str country_code: Country Code    [default: US]

        :param str login_id: For admin login Login ID

        :param str password: For admin login Password 

        :return: True if APZone Updated else False

        :rtype: boolean

        Example:

        | Update ApZone Login | zone_name='Auto-1-apzone' | login_id='admin' | password='ruckus1!' |
        
        """ 
        if IS_PUBLIC:
            self.modify_apzone_login_python(*kwargs) 
            return True 
        else:
            res = self.sjc.update_apzone(*kwargs)
        if not res:
            raise AssertionError("Update AP Zone Login Failed")
            
        return True

    def update_apzone_basic_info(self, *kwargs):
        """
        URI: POST /wsg/api/scg/zones/<apzone_uuid>/config

        :param str zone_name:  Ap Zone Name

        :param str country_code: Country Code    [default: US]

        :param str lattitude: 

        :param str longitude:  

        :return: True if APZone Updated else False

        :rtype: boolean

        Example:

        | Update ApZone Basic Info | zone_name='Auto-1-apzone' | lattitude='admin' | longitude='ruckus1!' |
        
        """ 
        if IS_PUBLIC:
            self.modify_basic_apzone_info_python(*kwargs)
            return True
        else:
            res = self.sjc.update_apzone(*kwargs)
        if not res:
            raise AssertionError("Update AP Zone Basic Info Failed")
            
        return True
    

    def delete_apzone(self, is_public_api=IS_PUBLIC, **kwargs):


        """
        API is used to delete the AP Zone

        URI: DELETE /wsg/api/scg/zones/<recvd_aaa_profile_keys> 

        :param str zone_name: Ap Zone Name

        :param str domain_label: Name of the Domain

        :return: True if Ap Zone is deleted else False

        :rtype: boolean

        Example:

        | Delete ApZone | zone_name='Auto-1-apzone' |
        
        """
        if is_public_api:
            res=self.pubapi.delete_apzone(**kwargs)  
        else:
            res = self.sjc.delete_apzone(**kwargs)
        if not res:
            raise AssertionError("Delete AP Zone Profile Failed")
            
        return True


    def create_report(self, **kwargs):

        """
        API is used to Create Report

        URI POST: /wsg/api/scg/reports

        :Param str report_title: Report Title

        :Param str report_type: Report Type Client Number | Client Number Vs Air Time | Active TTG Sessions [default: Client Number]

        :Param str output_format: Output Format  csv | pdf  [default: csv]

        :Param str time_filter_interval: FIFTEEN_MIN | DAILY | HOURLY | MONTHLY  [default: FIFTEEN_MIN]

        :Param str time_filter_value: from 1 to 48      [default: 8]

        :Param str time_filter_units: HOURS | DAYS |  MONTHS [default: HOURS]

        :Param str is_device_filter: Resource Filter - True     [default: True]

        :Param str device_category: Management Domains | APZONE | Access Point  [default: Management Domains]

        :Param str domain_label: Domain Label Name [default: Administration Domains]

        :Param str ap_zone: Ap Zone Name

        :Param str ap_label: Ap Zone Name

        :Param str ap_ip: Access Point IP

        :Param str cblade_label: Cblade Label Name

        :Param str is_ssid_filter: True | False         [default: False]

        :Param str ssid: SSID

        :Param str is_radio_filter: True | False         [default: False]

        :Param str radio: 2.5G | 5G     [default: 2.5G]

        :Param str enable_schedules:  True | False  [default: False]

        :Param str schedule_interval : DAILY | MONTHLY | WEEKLY | HOURLY        [default: DAILY]

        :Param str schedule_day: schedule Day   [default: 8]

        :Param str schedule_week: schedule Week         [default: 'MONDAY']

        :Param str schedule_hour: from 0 to 23  [default: 0]

        :Param str schedule_min: from 0 to 59   [default: 0]

        :Param str enable_email_notifications: True | False  [default: False]

        :Param str email_id: Email ID

        :Param str enable_export_results: True | False  [default: False]

        :Param str ftp_host: FTP Host IP Address

        :Param str ftp_port: FTP Port Address

        :Param str ftp_username: FTP User Name

        :Param str ftp_password: FTP Password

        :Param str ftp_remote_dir: FTP Remote Directory

        :return: True if Report is created else False

        :rtype: boolean

        Example:

        | Create Report | report_title='myreport' |

        """

        res = self.sjr.create_report(**kwargs)
        if not res:
            raise AssertionError("Create Report Failed")
            
        return True


    def find_report_title(self, **kwargs):

        """
        API is used to Find Report Title

        URI GET: /wsg/api/scg/reports

        :param str report_title: Report Title

        :return: dictionary containing report entry if Report Title Found else None

        :rtype: dictionary

        Example:

        | Find Report Title  | report_title='myreport' |

        """

        report_entry = self.sjr.find_report_title(**kwargs)
        if not report_entry:
            raise AssertionError("Find Report Title Failed")
            
        return report_entry

    def generate_report(self, **kwargs):

        """

        API used to Generate Report

        URI GET: /wsg/api/scg/reports/<report_uuid>/run

        :param str report_title: Report Title

        :return: True if Report Generated else False

        :rtype: boolean

        Example:

        | Generate Report | report_title='myreport' |

        """

        res = self.sjr.generate_report(**kwargs)
        if not res:
            raise AssertionError("Generate Report Failed")
            
        return True

    def delete_report(self, **kwargs):

        """
        API used to Delete Report

        URI DELETE: /wsg/api/scg/reports/<report_uuid>

        :param str report_title: Report Title

        :return: True if Report Deleted else False

        :rtype: boolean

        Example:
        
        | Delete Report  | report_title='myreport' |


        """

        res = self.sjr.delete_report(**kwargs)
        if not res:
            raise AssertionError("Delete Report Failed")
            
        return True

    def get_report_results(self, **kwargs):

        """
        API used to Get Report Results

        URI GET: /wsg/api/scg/reports/<report_uuid>/result

        :param str report_title: Report Title

        :return: List of report results if success else []

        :rtype: list

        Example:

        | Get Report Results | report_title='myreport' |

        """


        result_list = self.sjr.get_report_results(**kwargs)
        if not result_list:
            raise AssertionError("Get Report Results Failed")
            
        return result_list

    def download_report_results(self, **kwargs):
        
        """
        API used to Download Report Results

        :param str report_title: Report Title

        :param str local_path: Path Required to store Downloaded Reports 

        :return: Local filename copied if success else None

        :rtype: str

        Example:

        | Download Report Results | report_title='myreport' | local_path='\temp\' |

        """

        local_filename = self.sjr.download_report_result(**kwargs)
        if not local_filename:
            raise AssertionError("Download Report Results Failed")
            
        return local_filename

###########################

    def search_client(self,**kwargs):

        """
        API is used to Search Client

        URI GET: /wsg/api/scg/clients/byZone/<Zone_uuid>?'

        :param str client_mac: Client MAC Address

        :param str client_ip: Client IP Address

        :param str domain_label: AP Zone Domain Name 

        :param str apzone_name: Name of AP Zone

        :return: Client WLAN information if Client Found else False

        :rtype: dictionary

        Example:

        | Search Client | client_mac='60:36:DD:C5:E5:72' | client_ip=1.2.3.4 | domain_label='Administration Domain'  | apzone_name='Auto-1-apzone'|
        """

        res, client_wlan_info = self.sjm.search_client(**kwargs)
        if not res:
            raise AssertionError("Client Not Found")
        return client_wlan_info


    def get_client_information(self, is_public_api=IS_PUBLIC, **kwargs):
                
        """
        API is used to get Client Info

        :param str client_mac: Client MAC Address
        :param str client_ip: Client IP Address
        :param str domain_label: AP Zone Domain Name
        :param str apzone_name: Name of AP Zone
        :return: Client Information if Client is Found else False
        :rtype: Dictionary

        Example:

        | Get Client Information | client_mac='60:36:DD:C5:E5:72' | client_ip= | domain_label='Administration Domain'  | apzone_name='Auto-1-apzone'|

        """
        if  is_public_api == True:
            client_info=self.pubapi.get_client_info_v5(**kwargs)
        else:
            client_info = self.sjm.get_client_info(**kwargs)
        if not client_info:
            raise AssertionError("Get Client Information Failed")
        return client_info


    def delete_client(self, is_public_api=IS_PUBLIC, **kwargs):
                
        """
        API is used to Delete Client

        URI PUT: /wsg/api/scg/clients/<client_mac>/disconnect

        :param str client_mac: Client MAC Address
        :param str domain_label:AP Zone  Domain Name
        :param str apzone_name: Name of AP Zone
        :return: True if Client Deleted else False
        :rtype: boolean

        Example:

        | Delete Client | client_mac='60:36:DD:C5:E5:72' | domain_label='Administration Domain'  | apzone_name='Auto-1-apzone'|
 
        """
        if  is_public_api == True  and os.getenv("API_VERSION", 'v4_0') == 'v5_0':
            if not kwargs.has_key("ap_mac"):
                kwargs['ap_mac'] = os.getenv("AP_MAC","60:36:DD:C5:E5:72")
            self.pubapi.delete_client(**kwargs)
            return True
        else:        
            res = self.sjm.delete_client(**kwargs)
        if not res:
            raise AssertionError("Delete Client Failed")
        return True
    
    def deauth_client(self, is_public_api=IS_PUBLIC, **kwargs):
                
        """
        API is used to Deauthenticate Client

        URI PUT: /wsg/api/scg/clients/<client_mac>/deauth

        :param str client_mac: Client MAC Address
        :param str domain_label:AP Zone  Domain Name
        :param str apzone_name: Name of AP Zone
        :param str client_ip: Client ip Address
        :return: True if Client Deauthenticated else False
        :rtype: Dictionary



        Example:

        | Deauth Client | client_mac='60:36:DD:C5:E5:72' | domain_label='Administration Domain'  | apzone_name='Auto-1-apzone'|
 
        """
        if  is_public_api == True  and os.getenv("API_VERSION", 'v4_0') == 'v5_0':
            if not kwargs.has_key("ap_mac"):
                kwargs['ap_mac'] = os.getenv("AP_MAC","60:36:DD:C5:E5:72")
            self.pubapi.deauth_client(**kwargs)
            return True 
        else:
            res=self.sjm.deauth_client(**kwargs)
        if not res:
            raise AssertionError("Deauth Client Failed")
        return True

    def is_client_authorized(self,**kwargs):
                
        """
        API is used to get authorization status of Client

        URI PUT: /wsg/api/scg/clients/<client_mac>/deauth

        :param str client_mac: Client MAC Address
        :param str domain_label:AP Zone  Domain Name
        :param str apzone_name: Name of AP Zone
        :param str client_ip: Client ip Address
        :return: True if Client Deauthenticated else False
        :rtype: Dictionary



        Example:

        | Deauth Client | client_mac='60:36:DD:C5:E5:72' | domain_label='Administration Domain'  | apzone_name='Auto-1-apzone'|
 
        """
                
        res=self.sjm.is_client_authorized(**kwargs)
        if not res:
            raise AssertionError("Fetching Authorization status of Client Failed")
        return True
    
    def delete_client_ignore_error(self, is_public_api=IS_PUBLIC, **kwargs):
                
        """
        API is used to Delete Client

        URI PUT: /wsg/api/scg/clients/<client_mac>/disconnect

        :param str client_mac: Client MAC Address
        :param str domain_label:AP Zone  Domain Name
        :param str apzone_name: Name of AP Zone
        :return: True if Client Deleted else False
        :rtype: boolean

        Example:

        | Delete Client | client_mac='60:36:DD:C5:E5:72' | domain_label='Administration Domain'  | apzone_name='Auto-1-apzone'|
 
        """
        try:
            if  is_public_api == True  and os.getenv("API_VERSION", 'v4_0') == 'v5_0':
                if not kwargs.has_key("ap_mac"):
                    kwargs['ap_mac'] = os.getenv("AP_MAC","60:36:DD:C5:E5:72")
                self.pubapi.delete_client(**kwargs)
                return True
            else:        
                res = self.sjm.delete_client(**kwargs)
                           
            if not res:
                return False
            return True
        except Exception as e:
            print "exception occured while deleting client"
            return True


######################


    def get_monitor_events_information(self,**kwargs):
        
        """

        API used to Get Events Info

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

        :return: List of Events if criteria matches else None

        :rtype: list
       
        Example:
        
        | Get Monitor Events Information | source_filter='cluster' | severity='Informational' | category='Cluster' |
                                         | event_type='upgradeEntireClusterSuccess' | domain_label='Administration Domain' | ap_zone='Auto-1-apzone' | 
                                         | ap_mac='2C:E6:CC:08:46:70' | client_mac='01:02:c3:4D:5E:99' | cblade_label='spyder-C' | 
                                         | dblade_label='spyder-D1' |
        """

        #ev_list = self.sje.get_events(**kwargs)   #3.4 private api
        ev_list = self.sje.get_events_35private(**kwargs) # 3.5 private api
        if not ev_list:
            raise AssertionError("Get Events Failed")
        return ev_list

    def get_last_raised_alarm(self, **kwargs):
        alarm = self.sjalarm.get_last_raised_alarm(**kwargs)
        if not alarm:
            raise AssertionError("Get last raised alarm Failed")
        return alarm

    def get_alarms(self, **kwargs):
        alarm = self.sjalarm.get_alarms_35private(**kwargs)
        if not alarm:
            raise AssertionError("Get all raised alarm Failed")
        return alarm
    
    def acknowledge_alarm(self, **kwargs):
        ack_alarm = self.sjalarm.acknowledge_alarm_35(**kwargs)
	if not ack_alarm:
		raise AssertionError("Alarm acknowledge Failed")
        return ack_alarm

    def clear_alarm(self, **kwargs):
        clear_alarm = self.sjalarm.clear_alarm_35(**kwargs)
        if not clear_alarm:
                raise AssertionError("Alarm clear Failed")
        return clear_alarm
    
    def sz100_get_alarms(self, **kwargs):
        alarm = self.sjalarm.sz100_get_alarms(**kwargs)
        if not alarm:
            raise AssertionError("Get all raised alarm Failed")
        return alarm
    
    def sz100_clear_alarm(self, **kwargs):
        clear_alarm = self.sjalarm.sz100_clear_alarm(**kwargs)
        if not clear_alarm:
            raise AssertionError("Alarm clear Failed")
        return clear_alarm

    def auto_export_backup_python(self, *args):
        return self.call_robot_keywords(AUTO_EXPORT_API, *args)

    def auto_export_backup(self, *args):
        if  IS_PUBLIC:
            self.auto_export_backup_python(*args)
            return True
        else:
            auto_backup = self.sjalarm.auto_export_backup(*args)

        if not auto_backup:
            raise AssertionError("auto backup setting Failed")
        return auto_backup
    
    def schedule_backup_python(self, *args):
        return self.call_robot_keywords(SCHEDULE_API, *args)

    def schedule_backup(self, *args):
        if  IS_PUBLIC:
            self.schedule_backup_python(*args)
            return True
        else:
            schedule_back = self.sjalarm.schedule_backup(**kwargs)

        if not schedule_back:
            raise AssertionError("Schedule backup setting Failed")
        return schedule_back
    
    def get_backup_list_python(self, *args):
        return self.call_robot_keywords(GET_BACKUP_LIST_API, *args)

    def get_backup_list(self, *args):
        if  IS_PUBLIC:
            self.get_backup_list_python(*args)
            return True
        else:
            get_backup_list = self.sjalarm.get_backup_list(**kwargs)

        if not get_backup_list:
            raise AssertionError("get backup list Failed")
        return get_backup_list
    
    def delete_backup_list_python(self, *args):
        return self.call_robot_keywords(DELETE_BACKUP_LIST_API, *args)

    def delete_backup_list(self, *args):
        if  IS_PUBLIC:
            self.delete_backup_list_python(*args)
            return True
        else:
            delete_backup_list = self.sjalarm.delete_backup_list(**kwargs)

        if not delete_backup_list:
            raise AssertionError("delete backup list Failed")
        return delete_backup_list
###########################

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

        res = self.snmp.create_snmpv2_agent(**kwargs)
        if not res:
            raise AssertionError("Failed to Create SNMPv2 Agent")

        return True

    def create_snmpv3_agent(self,**kwargs):
        """ 
        API used to create SNMPv3 Agent

        URI: PUT /wsg/api/scg/globalSettings/mvno/snmp

        :param str user: SNMPv3 User

        :param str auth_protocol: Auth Protocol [MD5 | SHA]

        :param str auth_passphrase: Auth Passphrase

        :param str privacy_protocol: Privacy Protocol [DES | AES]

        :param bool read_privilege: make True if API used to create SNMPv3 agent as read privilege else False

        :param bool write_privilege: make True if API used to create SNMPv3 agent as write privilege else False

        :param bool trap_privilege: make True if API used to create SNMPv3 agent as trap privilege else False

        :param str trap_target_ip: Trap target IP address

        :param str trap_target_port: Trap target port

        :return: True if  SNMPv3 agent created else False

        :rtype: boolean

        Example:
        | create snmpv3 agent | user=public 

        """
        res = self.snmp.create_snmpv3_agent(**kwargs)
        if not res:
            raise AssertionError("Failed to create snmpv3 agent")

        return True


    def delete_snmpv2_agent(self,**kwargs):
        """ 
        API used to delete Agent

        URI: PUT /wsg/api/scg/globalSettings/mvno/snmp

        :param str community: SNMPv2 Community

        :return: True if  SNMPv2 agent delete else False

        :rtype: boolean

        Example:
        | delete snmpv2 agent | community=public 

        """


        res = self.snmp.delete_snmpv2_agent(**kwargs)
        if not res:
            raise AssertionError("Failed to delete snmpv2 agent")

        return True

    def delete_snmpv3_agent(self,**kwargs):
        """ 
        API used to delete Agent

        URI: PUT /wsg/api/scg/globalSettings/mvno/snmp

        :param str community: SNMPv3 Community

        :return: True if  SNMPv3 agent delete else False

        :rtype: boolean

        Example:
        | delete snmpv3 agent | community=public 

        """


        res = self.snmp.delete_snmpv3_agent(**kwargs)
        if not res:
            raise AssertionError("Failed to delete snmpv3 agent")

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

        res = self.sjc.configure_event_notification(**kwargs)

        if not res:
            raise AssertionError("Failed to Configure event")

        return True



    def change_map_gateway_settings_in_hlr_service(self, **kwargs):
        """
        API used to update the Map Gateway Settings in HLR Service

        URI: PUT /wsg/api/scg/hlrs/globalsettings?

        :param boolean enable_map_gateway_service: True | False
        :param str traffic_mode: Load_Share | Override
        :param str active_map_gateway: active_map_gateway
        :return: True if Map  Gateway Settings in HLR Service updated successfully else False
        :rtype: boolean

        """

        res = self.sjc.change_map_gateway_settings_in_hlr(**kwargs)

        if not res:
            raise AssertionError("Failed to update map gateway settings in hlr service")

        return True

    def reboot_ap_by_mac_python(self, *args):
       return self.call_robot_keywords(REBOOT_APMAC_API, *args) 
    
    def reboot_ap_by_macaddress(self, *args):
        """
        API used to reboot ap

        URI: GET /wsg/api/scg/aps/ap_mac/reboot

        :param str ap_mac: AP Mac address
        :return: True if ap reboots else False
        :rtype: boolean

       
        Example:
        
        | Reboot ap by macaddress |  ap_mac='2C:E6:CC:08:46:70' |

        """
        if  IS_PUBLIC:
            ap_reboot = self.reboot_ap_by_mac_python(*args)
            return True
        else:
            reboot_ap = self.sjc.reboot_ap_by_macaddress(**kwargs)

        if not reboot_ap:
            raise AssertionError("AP reboot operation Failed")

        return True


##can't support public API
    def reboot_data_plane(self,**kwargs):
        """
        API used to reboot dataplane 

        URI: PUT /wsg/api/scg/planes/data/dp_mac/reboot

        :param str dp_mac: Dataplane Mac address
        :return: True if dataplane reboots else False
        :rtype: boolean

       
        Example:
        
        | Reboot dataplane |  dp_mac='2C:E6:CC:08:46:70' |

        """

        reboot_dp = self.sjc.reboot_data_plane(**kwargs)

        if not reboot_dp:
            raise AssertionError("DP reboot operation Failed")

        return True

    def cluster_backup(self):

        """

        API used to backup the cluster

        :return: True if backup the cluster else False
        :rtype: boolean

       
        Example:
        
        | Cluster backup |

        """

        backup = self.sjc.cluster_backup()

        if not backup:
            raise AssertionError("Cluster backup Failed")

        return True

    def get_data_plane_ip(self,**kwargs):
        """
        API used to get zone name of ap

        URI: GET /wsg/api/scg/planes/data/

        :param str dp_mac: DP Mac address
        :return: Dataplane IP Address
        :rtype: string

       
        Example:
        
        | Get data plane ip |  dp_mac='2C:E6:CC:08:46:70' |

        """


        get_dpinfo = self.sjc.get_data_plane_info(**kwargs)

        if not get_dpinfo:
            raise AssertionError("Get Dataplen info Failed")

        return get_dpinfo["ip"]

    
    def get_apzone_by_apmac_python(self, *args):
        return self.call_robot_keywords(GET_APZONE_API, *args)
       
    def get_apzone_by_macaddress(self, *args):
        """
        API used to get zone name of ap

        URI: GET /wsg/api/scg/aps/byDomain/

        :param str ap_mac: AP Mac address
        :return: Zone name
        :rtype: string
   
        Example:
        
        | Get apzone by macaddress |  ap_mac='2C:E6:CC:08:46:70' |

        """
        if  IS_PUBLIC:
            ap_info = self.get_apinfo_by_apmac(*args)
            zone_uuid = ap_info['zoneId']
            args1 = [zone_uuid]
            zone_name =self.get_apzone_by_apmac_python(*args1)
            return zone_name
        else:
            get_apinfo = self.sja.get_ap_info(*args)
        if not get_apinfo:
            raise AssertionError("Get AP configuration status Failed")
        return get_apinfo["zoneName"]

    def get_apip_by_macaddress(self,*args):
        """
        API used to get ip address of ap

        URI: GET /wsg/api/scg/aps/byDomain/

        :param str ap_mac: AP Mac address
        :return: AP IP Address
        :rtype: string

       
        Example:
        
        | Get apip by macaddress |  ap_mac='2C:E6:CC:08:46:70' |

        """
        if  IS_PUBLIC:
            ap_info = self.get_apinfo_by_apmac(*args)
            return  ap_info['ip']
        else: 
            get_apinfo = self.sja.get_ap_info(**kwargs)

        if not get_apinfo:
            raise AssertionError("Get AP configuration status Failed")

        return get_apinfo["ip"]


    def get_aplocation_by_macaddress(self,*args):

        """
        API used to get ap location

        URI: GET /wsg/api/scg/aps/byDomain/

        :param str ap_mac: AP Mac address
        :return: AP Location
        :rtype: string

       
        Example:
        
        | Get aplocation by macaddress |  ap_mac='2C:E6:CC:08:46:70' |

        """
        if  IS_PUBLIC:
            get_apinfo = self.get_apinfo_by_apmac(*args)
        else:        
            get_apinfo = self.sja.get_ap_info(**kwargs)

        if not get_apinfo:
            raise AssertionError("Get AP configuration status Failed")

        return get_apinfo["location"] if get_apinfo['location'] else ''


    def get_apdescription_by_macaddress(self,*args):

        """
        API used to get description of ap

        URI: GET /wsg/api/scg/aps/byDomain/

        :param str ap_mac: AP Mac address
        :return: AP Description
        :rtype: string

       
        Example:
        
        | Get apdescription by macaddress |  ap_mac='2C:E6:CC:08:46:70' |

        """

        if  IS_PUBLIC:
            ap_info = self.get_apinfo_by_apmac(*args)
            return  ap_info['description'] if ap_info['description'] else ''
        else: 
            get_apinfo = self.sja.get_ap_info(**kwargs)

        if not get_apinfo:
            raise AssertionError("Get AP configuration status Failed")

        return get_apinfo["description"] if get_apinfo["description"] else ''


    def get_apname_by_macaddress(self,*args):

        """
        API used to get name of ap

        URI: GET /wsg/api/scg/aps/byDomain/

        :param str ap_mac: AP Mac address
        :return: AP name
        :rtype: string

       
        Example:
        
        | Get apname by macaddress |  ap_mac='2C:E6:CC:08:46:70' |

        """

        if  IS_PUBLIC:
            ap_info = self.get_apinfo_by_apmac(*args)
            return  ap_info['name']
        else:
            get_apinfo = self.sja.get_ap_info(**kwargs)

        if not get_apinfo:
            raise AssertionError("Get AP configuration status Failed")

        return get_apinfo["deviceName"]

    def verify_cluster_is_inservice(self, is_public_api=IS_PUBLIC):
        """
        API used to verify cluster is in service

        URI: GET /wsg/api/scg/planes/systemSummary

        :return: True if cluster is in service else False
        :rtype: boolean

       
        Example:
        
        | Verify cluster is inservice |

        """
        if is_public_api == True and os.getenv("API_VERSION", 'v4_0') == 'v5_0':
            res= self.pubapi.verify_cluster_is_inservice()
        else:
            res =self.sjc.verify_cluster_is_inservice()
        if not res:
            raise AssertionError("Get Cluster status failed")
        return True

    def move_ap_to_apzone(self, domain_label='Administration Domain', ap_mac=None, apzone_name="APZone-1", 
                wait_preconfig_status="NotApplicable", wait_preconfig_retries='30', wait_preconfig_sleeptime='16',
                            wait_postmove_retries='15', wait_postmove_sleeptime='30',**kwargs):
        
        """

        API used to move AP to different zone

        :param str domain_label: APZone Domain name

        :param str apzone_name: target ap zone name

        :param str ap_mac: AP MAC Address

        :param str wait_preconfig_status: expected status 

        :param str wait_preconfig_retries: check ap config status retry count

        :param str wait_preconfig_sleeptime: sleep time

        :param str wait_postmove_retries: retry count after ap is moved to different zone

        :param str wait_postmove_sleeptime: sleep time to check AP is moved to new zone 

       
        Example:
        
        | move ap to apzone | ap_mac='2C:E6:CC:08:46:70' | apzone_name="APZone-1" |
                                         | wait_preconfig_status="completed" | wait_preconfig_retries='30' | wait_preconfig_sleeptime='6' | 
                                         | wait_postmove_retries='3' | wait_postmove_sleeptime='6' |

        """
        if IS_PUBLIC:
            ap_info = None
            recvd_status = None
            apzone_uuid = None

            if ap_mac is None:
                print "move_ap_to_apzone(): ap_mac is None"
                return ap_info

            try:
                if wait_preconfig_status != "NotApplicable":
                     _is_status_ok = False
                     for i in range(int(wait_preconfig_retries)):
                        result = self.get_ap_configuration_status_python(ap_mac) 
                        recvd_status = result['configState']
                        if recvd_status != wait_preconfig_status:
                            print "Waiting to get the updated AP Configuration Status. Sleeping for %s, recvd_status - %s" % (wait_preconfig_sleeptime, recvd_status)
                            time.sleep(int(wait_preconfig_sleeptime))
                        else:
                             _is_status_ok = True
                             break
                     if not _is_status_ok:
                        print 'move_ap_to_apzone: Error - AP configuration Status is incorrect'
                        return None
                apzone_uuid = self.get_zone_id_python(apzone_name)
                if not apzone_uuid:
                    print "get_apzone_uuid(): apzone_name: %s failed" %(
                             apzone_name)
                    return ap_info

                data = ''
                #url = ji.get_url(self.req_api_ap_move % (ap_mac, apzone_uuid), os.getenv("SCG_MGMT_IP", "172.19.16.170"), os.getenv("SCG_PORT","8443"))
                result = self.move_ap_python(apzone_uuid,ap_mac)
                if  str(result) != 'True':
                    print 'ap move to zone is failed, ap move result is : %s' %str(result)
                    raise AssertionError("Move AP %s to ApZone %s failed" % (ap_mac, apzone_name))
                #recvd_data = ji.put_json_data(url,self.sjc.get_jsessionid(), data)


                is_ap_moved = False
                for i in range(int(wait_postmove_retries)):
                    zone_name = self.get_apzone_by_macaddress(ap_mac)
                    if zone_name != apzone_name:
                        print "Waiting for the AP configuration status to get completed after move. Sleeping for %s" % wait_postmove_sleeptime
                        time.sleep(int(wait_postmove_sleeptime))
                    else:
                        is_ap_moved = True
                        break
                if not is_ap_moved:
                     return None

            except Exception:
                    print traceback.format_exc()
                    return ap_info
 
            return ap_info

        else:
             mv_apzone = self.sja.move_ap_to_apzone(domain_label=domain_label, ap_mac=ap_mac, apzone_name=apzone_name,
                 wait_preconfig_status=wait_preconfig_status, wait_preconfig_retries=wait_preconfig_retries, wait_preconfig_sleeptime=wait_preconfig_sleeptime, 
            wait_postmove_retries=wait_postmove_retries, wait_postmove_sleeptime=wait_postmove_sleeptime, **kwargs)

        if not mv_apzone:
            raise AssertionError("Move AP to ApZone failed")

        return mv_apzone


    def get_ap_configuration_status(self,**kwargs):
        
        """

        API used to top configuration status

        :param str domain_label: APZone Domain name

        :param str apzone_name: target ap zone name

        :param str ap_mac: AP MAC Address

       
        Example:
        
        | get ap configuration status | domain_label='Administration Domain' | apzone_name="APZone-1" | ap_mac='2C:E6:CC:08:46:70' |

        """

        get_configStatus = self.sja.get_ap_configuration_status(**kwargs)

        if not get_configStatus:
            raise AssertionError("Get AP configuration status Failed")

        return get_configStatus
    
    def update_ap_config(self, *kwargs):

        """

        API used to set Location attribute value in AP Configuration

        :param str domain_label: APZone Domain name

        :param str ap_mac: AP MAC Address

        :param str location: Location

       
        Example:
        
        | Update Ap Config | domain_label='Administration Domain' | ap_mac='2C:E6:CC:08:46:70' | location='WISPr Location' |

        """
        if IS_PUBLIC:
            self.modify_ap_basic_info_python(*kwargs)
            return True
        else:
            update_cfg_status = self.sja.update_ap_config(*kwargs)

        if not update_cfg_status:
            raise AssertionError("Update AP configuration Failed")

        return update_cfg_status

    def get_apzone_by_apmac(self, *args):

        """
        Gets name of current APZone to which AP is connected.

        """
        return self.get_apzone_by_macaddress(*args)
    
    def get_apinfo_by_apmac_python(self, *args):
        return self.call_robot_keywords(GET_AP_OPERATIONAL_INFO, *args)

    def get_apinfo_by_apmac(self,*args):

        """
        Gets name of current APZone to which AP is connected.

        """
        if  IS_PUBLIC:
            get_apinfo=self.get_apinfo_by_apmac_python(*args)
        else:
            get_apinfo = self.sja.get_ap_info(*args)

        if not get_apinfo:
            raise AssertionError("Get AP configuration status Failed")

        return get_apinfo

    def make_sure_ap_is_in_apzone(self, domain_label='Administration Domain', apzone_name=None, ap_mac=None,
            ap_config_status='completed', retries='30', sleep_time='30', pre_sleep='False',
            **kwargs):
        """
        Make sure that AP is in APzone with configuration status as up-to-date. If AP is in a different APzone, then move the AP to desired APzone.
        """
        if IS_PUBLIC:
            if pre_sleep=='True':
                print "Sleeping 2 secs before to check AP status as up-to-date"
                time.sleep(2)
            is_ap_uptodate_before = True
            total_sleep_time = 0
            curr_apzone = self.get_apzone_by_apmac(ap_mac)
    
            _moveap = None
    
            if curr_apzone == apzone_name:
                if curr_apzone == "Staging Zone":
                    ap_config_status = "NotApplicable"
                pass
            else:
                if curr_apzone == "Staging Zone":
                    _moveap = self.move_ap_to_apzone(domain_label, ap_mac, apzone_name,  "NotApplicable")
                else:
                    _moveap = self.move_ap_to_apzone(domain_label, ap_mac, apzone_name)
    
                if _moveap and apzone_name != "Staging Zone":
                    ap_config_status="completed"
                
            _cfg_status = None
            _connect_status = None
            if ap_config_status != "NotApplicable":
                if int(retries) <= 0:
                    ap_info = self.get_apinfo_by_apmac( ap_mac)
                    _connect_status = ap_info["connectionState"]
                    _cfg_status = ap_info["configState"]
                for i in range(0, int(retries)):
                    if _cfg_status != ap_config_status:
                        if i==0:
                           is_ap_uptodate_before = False 
                        print 'Current AP Connection Status: %s and Configuration Status: %s' % (_connect_status,_cfg_status)
                        print 'Sleeping %s seconds before getting ap_config_status' % sleep_time
                        time.sleep(int(sleep_time))
                        total_sleep_time = total_sleep_time + int(sleep_time)
                        print "Total sleep time: %d seconds" %total_sleep_time
                    else:
                        break
                    #_cfg_status = self.get_ap_configuration_status(domain_label=domain_label, apzone_name=apzone_name, ap_mac=ap_mac)
                    ap_info = self.get_apinfo_by_apmac(ap_mac)
                    _connect_status = ap_info["connectionState"]
                    _cfg_status = ap_info["configState"]
            else:
                _cfg_status = "NotApplicable"
    
            if _cfg_status != ap_config_status:
                raise AssertionError('Current AP Configuration Status: %s  !=  Desired AP Status: %s' % (
                    _cfg_status, ap_config_status))
            else:
                print 'AP: %s Configuration Status is %s in ApZone: %s' % (ap_mac, ap_config_status, apzone_name)
                if not is_ap_uptodate_before:
                    print "Sleeping 10 secs after updating ap configuration"
                    time.sleep(10)
        
        else:
            if pre_sleep=='True':
                print "Sleeping 2 secs before to check AP status as up-to-date"
                time.sleep(2)
            is_ap_uptodate_before = True
            total_sleep_time = 0
            get_apinfo = self.sja.get_ap_info(domain_label=domain_label, ap_mac=ap_mac)
            curr_apzone = get_apinfo["zoneName"]
    
            _moveap = None
    
            if curr_apzone == apzone_name:
                if curr_apzone == "Staging Zone":
                    ap_config_status = "NotApplicable"
                pass
            else:
                if curr_apzone == "Staging Zone":
                    _moveap = self.move_ap_to_apzone(domain_label=domain_label, ap_mac=ap_mac, apzone_name=apzone_name, wait_preconfig_status="NotApplicable")
                else:
                    _moveap = self.move_ap_to_apzone(domain_label=domain_label, ap_mac=ap_mac, apzone_name=apzone_name)
    
                if _moveap and apzone_name != "Staging Zone":
                    ap_config_status="completed"

                if not _moveap:
                    raise AssertionError('Failed to mve AP %s to zone %s  !=  Desired AP Status: %s' % (ap_mac, apzone_name))
                    
            _cfg_status = None
            _connect_status = None
            if ap_config_status != "NotApplicable":
                if int(retries) <= 0:
                    ap_info = self.sja.get_ap_info(domain_label=domain_label, ap_mac=ap_mac)
                    _connect_status = ap_info["connectionStatus"]
                    _cfg_status = ap_info["configStatus"]
                for i in range(0, int(retries)):
                    if _cfg_status != ap_config_status:
                        if i==0:
                           is_ap_uptodate_before = False 
                        print 'Current AP Connection Status: %s and Configuration Status: %s' % (_connect_status,_cfg_status)
                        print 'Sleeping %s seconds before getting ap_config_status' % sleep_time
                        time.sleep(int(sleep_time))
                        total_sleep_time = total_sleep_time + int(sleep_time)
                        print "Total sleep time: %d seconds" %total_sleep_time
                    else:
                        break
                    #_cfg_status = self.get_ap_configuration_status(domain_label=domain_label, apzone_name=apzone_name, ap_mac=ap_mac)
                    ap_info = self.sja.get_ap_info(domain_label=domain_label, ap_mac=ap_mac)
                    _connect_status = ap_info["connectionStatus"]
                    _cfg_status = ap_info["configStatus"]
            else:
                _cfg_status = "NotApplicable"
    
            if _cfg_status != ap_config_status:
                raise AssertionError('Current AP Configuration Status: %s  !=  Desired AP Status: %s' % (
                    _cfg_status, ap_config_status))
            else:
                print 'AP: %s Configuration Status is %s in ApZone: %s' % (ap_mac, ap_config_status, apzone_name)
                if not is_ap_uptodate_before:
                    print "Sleeping 10 secs after updating ap configuration"
                    time.sleep(10)
    
    def create_pmipv6_service_profile(self, is_public_api= IS_PUBLIC, **kwargs):
        """ 
        Creates the PMIPv6 service profile
        
        URI: POST /wsg/api/scg/serviceProfiles/forwarding?

        :param str pmipv6_name: PMIPv6 Profile Name

        :param str lma_primary_ip: Primary IP Address of LMA

        :param str lma_secondary_ip: Secondary IP Address of LMA

        :param str mnid_type: NAI_From_Authentication | MAC48_At_APN 

        :param mac48_type: Decimal | Hexadecimal

        :param lma_apn: APN name 

        :return: True if PMIPv6 created else False

        :rtype: boolean

        """
        if is_public_api == True  and os.getenv("API_VERSION", 'v4_0') == 'v5_0':
            result = self.pubapi.create_pmipv6_service_profile(**kwargs)
        else:    
            result = self.pc.create_pmipv6_service_profile(**kwargs)
        if not result:
            raise AssertionError("create_pmipv6_service_profile(): Failed")

        return True

    def update_pmipv6_service_profile(self, is_public_api= IS_PUBLIC, **kwargs):

        """ 
        Update the PMIP profile with given parameters
        
        URI: PUT /wsg/api/scg/serviceProfiles/forwarding/<pmip_keys>

        :param str pmipv6_name: PMIPv6 Profile Name
        
        :param str lma_primary_ip: Primary IP Address of LMA
        
        :param str lma_secondary_ip: Secondary IP Address of LMA
        
        :param str mnid_type: NAI_From_Authentication | MAC48_At_APN 
        
        :param mac48_type: Decimal | Hexadecimal
        
        :param lma_apn: APN name 
        
        :return: True if PMIPv6 Updated else False
        
        :rtype: boolean

        Example:

        | Update Lma In Pmip | lma_primary_ip='1.1.1.1' | lma_secondary_ip='2.2.2.3' |

        """
    
        if is_public_api == True  and os.getenv("API_VERSION", 'v4_0') == 'v5_0':
            result = self.pubapi.update_pmipv6_service_profile(**kwargs)
        else:    
            result = self.pc.update_pmipv6_service_profile(**kwargs)
        if not result:
            raise AssertionError("update_lma_in_pmip Failed")

        return True
    
    def validate_pmipv6_service_profile(self, **kwargs):

        """ 
        Validate the PMIP profile with given parameters
        
        URI: PUT /wsg/api/scg/serviceProfiles/forwarding/<pmip_keys>

        :param str pmipv6_name: PMIPv6 Profile Name
        
        :param str lma_primary_ip: Primary IP Address of LMA
        
        :param str lma_secondary_ip: Secondary IP Address of LMA
        
        :param str mnid_type: NAI_From_Authentication | MAC48_At_APN 
        
        :param mac48_type: Decimal | Hexadecimal
        
        :param lma_apn: APN name 
        
        :return: True if LMA in PMIPv6 validated else False
        
        :rtype: boolean

        Example:

        | validate Lma In Pmip | lma_primary_ip='1.1.1.1' | lma_secondary_ip='2.2.2.3' |

        """
        res = self.pc.validate_pmipv6_service_profile(**kwargs)
        if not res:
            raise AssertionError("validate_lma_in_pmip Failed")
        return res


    def update_global_lma_mag_in_pmip(self, is_public_api= IS_PUBLIC, **kwargs):

        """
        Update Global LMA MAG in PMIP
        
        URI PUT: /wsg/api/scg/globalSettings/lma        

        :param str lma_key: LMA Key

        :param str lma_keepalive_interval: 5 to 60 [ default: 30 ]
                                
        :param str lma_keepalive_retry: 1 to 10  [ default: 5 ]

        :param str binding_refreshtime: 1 to 65535 [ default: 300 ]

        Example:

        | Update Global Lma Mag In Pmip | lma_key="pmipv6GlobalSetting |   
        
        """
        if is_public_api == True  and os.getenv("API_VERSION", 'v4_0') == 'v5_0':
            result = self.pubapi.update_global_lma_mag(**kwargs)
        else:    
            result = self.pc.update_global_lma_mag(**kwargs)
        if not result:
            raise AssertionError("update_global_lma_mag_in_pmip Failed")

        return True

    def validate_global_lma_mag_in_pmip(self, **kwargs):


        """
        Validate Global LMA MAG in PMIP

        URI GET: /wsg/api/scg/globalSettings/lma
        
        :param str lma_keepalive_interval: 5 to 60 [ default: 30 ]
                                
        :param str lma_keepalive_retry: 1 to 10  [ default: 5 ]

        :param str binding_refreshtime: 1 to 65535 [ default: 300 ]

        Example:

        | Validate Global Lma Mag In Pmip |
 
        """
        res = self.pc.update_global_lma_mag(**kwargs)
        if not res:
            raise AssertionError("validate_global_lma_mag_in_pmip Failed")
        return res

    def delete_pmipv6_service_profile(self, is_public_api= IS_PUBLIC, **kwargs):

        """
        Deletes LMA in PMIP

        URI DELETE: /wsg/api/scg/serviceProfiles/forwarding/<pmip_keys>       

        :param str pmipv6_profile_name: PMIPv6 Profile Name

        :return: True if LMA in PMIP Deleted else False

        :rtype: boolean

        Example:

        | Delete Lma In Pmip |

        """
        if is_public_api == True  and os.getenv("API_VERSION", 'v4_0') == 'v5_0':
            result = self.pubapi.delete_pmipv6_service_profile(**kwargs)
        else:    
            result = self.pc.delete_pmipv6_service_profile(**kwargs)
        if not result:
            raise AssertionError("delete_lma_in_pmip Failed")

        return True

    def get_license_status(self):
        """
        """
        res = self.ll.get_license_stats()
        if not res:
            raise AssertionError("get_license_status(): Failed")

        return res

    def check_license_increment(self, **kwargs):
        """
        """
        res = self.ll.count_license_increment(**kwargs)
        if not res:
            raise AssertionError("check_license_increment(): Failed")

        return res

    def check_license_decrement(self, **kwargs):
        """
        """
        res = self.ll.count_license_decrement(**kwargs)
        if not res:
            raise AssertionError("check_license_decrement(): Failed")

        return res

##can't support public API
    def reboot_scg(self,**kwargs):
        """
        API used to Reboot the scg
        """
        res = self.wsgc.reboot_wsgc(**kwargs)
            
    def verify_syslog_default_event_filter(self,**kwargs):
        
        """
        
        Verify syslog default event filter
        
        :param str event_filter: 0|1|2 - Default: 1
        
        Example:
        
        |verify syslog default event filter | event_filter=2|
        
        """
        
        ver_eventfilter = self.sjs.verify_syslog_event_filter(**kwargs)
        if not ver_eventfilter:
            raise AssertionError("Verify Syslog Default Event Filter Failed")
        
    def verify_syslog_default_facility(self,**kwargs):
        """
        
        Verify syslog default Facility
        
        :param str facility: LOCAL0|LOCAL1|...|LOCAL7 - Default: LOCAL0
        
        Example:
        
        |verify syslog default facility | facility=LOCAL4 |
        
        """
        
        ver_facility = self.sjs.verify_syslog_facility(**kwargs)
        if not ver_facility:
            raise AssertionError("Verify Syslog Default Facility Failed")
        
    def set_syslog_setting(self,**kwargs):
        """
        
        Set Syslog Settings
        
        :param boolean enable: True|False (Default : True)
                
        :param str syslog_host: Syslog server ip address
        
        :param int syslog_port: Syslog server port number (Default : 514)
        
        :param str event_filter: 0|1|2
        
        :param str event_syslog_severity: Critical|Major|Minor|Warning|Informational|Debug
        
        :param str syslog_facility: LOCAL0|LOCAL1|...|LOCAL7
        
        :param Dictionary priority: severity and priority as key value pair
        
        Example:
        
        | set syslog setting | syslog_host=172.19.7.165 | event_filter=2 | event_syslog_severity=Critical | syslog_facility=LOCAL0 
                                | Critical=ERROR |
                                
        | set syslog setting | syslog_host=172.19.7.165 | event_filter=1 |syslog_facility=LOCAL0 | Critical=ERROR | Major=ERROR 
                                | Minor=ERROR | Warning=ERROR | Informational=ERROR | Debug=ERROR |
                                
        | set syslog setting | enable=False |
        
        
        """
        
        status = self.sjs.set_syslog_setting(**kwargs)
        if not status:
            raise AssertionError("Set Syslog Setting Failed")
    
    def get_monitor_alarms_information(self,**kwargs):

        """

        API used to Get Events Info

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

        :return: List of Events if criteria matches else None

        :rtype: list
       
        Example:
        
        | Get Monitor Events Information | source_filter='cluster' | severity='Informational' | category='Cluster' |
                                         | event_type='upgradeEntireClusterSuccess' | domain_label='Administration Domain' | ap_zone='Auto-1-apzone' | 
                                         | ap_mac='2C:E6:CC:08:46:70' | client_mac='01:02:c3:4D:5E:99' | cblade_label='spyder-C' | 
                                         | dblade_label='spyder-D1' |
        """
        #al_list = self.sjalarm.get_alarms(**kwargs)
        al_list = self.sjalarm.get_alarms_35private(**kwargs)
        if not al_list:
            raise AssertionError("Get Alarms Failed")
        return al_list

    def convert_time(self,timestamp=None):
        """
        
        :param str time: time in format '%Y-%m-%d %H:%M:%S %Z' eg: '2014-06-18 06:19:19 GMT'

        :return: int epoch time

        :rtype: int
        
        """

        epoch_time = self.sje.convert_time(timestamp)
        if not epoch_time:
                raise AssertionError("Convert time failed")
        return epoch_time
        
    def verify_alarmautoclear(self, **kwargs):
        """
        API used to verify alarm code auto cleared or not
        
        :return: boolean if alrm auto cleard return True else False 
        
        :rtype: boolean
        
        """
        
        result = self.sjalarm.verify_alarms_auto_clear(**kwargs)
        if not result:
            raise AssertionError("No Alarm Auto Clear")
        return result

    def verify_apzone_syslog_default_facility(self,**kwargs):
        """
        
        Verify AP Zone default Facility
        
        :param str zone_name: AP Zone name
        
        :param str facility: -1|16|17|18|19|20|21|22|23 (Default : -1)
        
        Example:
        
        | verify apzone syslog default facility \ zone_name=Syslog-Test | facility=-1 |
        
        """
        ##set to False as can not get default facility using PublicAPI
        if False:
             self.verify_apzone_syslog_default_facility_python(*args)
             return True
        else:
            ver_apzone_facility = self.sjs.verify_apzone_syslog_facility(**kwargs)

        if not ver_apzone_facility:
            raise AssertionError("Verify AP Zone Syslog Default Facility Failed")
        
    def set_apzone_syslog_setting(self,*args):
        """
        
        Set Ap zone syslog setting
        
        :param str zone_name: AP zone name
        
        :param str domain_label: APZone Domain name
        
        :param str syslogIp: Syslog server ip address
        
        :param str syslogPort: Syslog server port
        
        :param str syslogFacility: -1|16|17|18|19|20|21|22|23 (default : -1)
        
        :param str syslogRLevel: 0|1|..|7 (default : 3)
        
        Example:
        
        | set apzone syslog setting | zone_name=Syslog-Test | syslogIP=172.19.7.165 | syslogFacility=16 | syslogRLevel=7 
        
        """
        if IS_PUBLIC:
            self.modify_apzone_syslog_python(*args)
            return True        
        else:
		    status = self.sjs.set_apzone_syslog_setting(*args)
			
        if not status:
            raise AssertionError("Set AP Zone Syslog Setting Failed")
        
    def verify_access_point_syslog_facility(self,**kwargs):
        """
        
        Verify Access Point default Facility
        
        :param str ap_mac: AP mac
        
        :param str facility: -1|16|17|18|19|20|21|22|23 (Default : -1)
        
        Example:
        
        | verify access point syslog default facility \ ap_mac=50:A7:33:14:6B:20 | facility=-1 |
        
        """
        ##set to False as can not get default facility using PublicAPI
        if False:
            self.verify_ap_syslog_facility_python(*args)
            return True
        else:
           ver_access_point_facility = self.sjs.verify_access_point_syslog_facility(**kwargs)

        if not ver_access_point_facility:
            raise AssertionError("Verify Access Point Syslog Facility Failed")
    
    def set_access_point_syslog_setting(self,*args):
        """
        
        Set Ap syslog setting
        
        :param str ap_mac: AP Mac
        
        :param str syslogIp: Syslog server ip address
        
        :param str syslogPort: Syslog server port
        
        :param str syslogFacility: -1|16|17|18|19|20|21|22|23 (default : -1)
        
        :param str syslogRLevel: 0|1|..|7 (default : 3)
        
        Example:
        
        | set access point syslog setting | ap_mac=50:A7:33:14:6B:20 | syslogIP=172.19.7.165 | syslogFacility=16 | syslogRLevel=7 
        
        """
        if IS_PUBLIC:
            self.modify_ap_syslog_override_python(*args)
            return True
        else:
            status = self.sjs.set_access_point_syslog_setting(*args) 

        if not status:
            raise AssertionError("Set AP Syslog Setting Failed")    
        
###########################
    def get_scg_id_python(self):
        return self.call_robot_keywords(GET_SCG_ID_API)

    def get_scg_time_epoch_python(self, *args):
        return self.call_robot_keywords(GET_SCG_TIME_EPOCH_API)
    
    def get_scg_time_epoch(self):
        """
        API's used to get current SCG epoch time in 10 digits
        
        :return: epoch integer digits if system time is running else None
        
        :rtype: integer
        
        """
        ### need to be tested as same testcase worked for sz but not SCG
        if False:
            ap_time = self.get_scg_id_python()
            args1 = [ap_time]
            time_stamp =self.get_scg_time_epoch_python(*args1)
            #return time_stamp
            return time_stamp[0]['timestamp']

        else:
            result = self.sjalarm.get_scg_epoch_time()
        if not result:
            raise AssertionError("Get SCG Epoch Time failed!")
        return result
    
    def get_aps_dataplane_details(self,**kwargs):
        
        dpmac = self.sjalarm.get_aps_dataplane_details(**kwargs)
        if not dpmac:
            raise AssertionError("DataPlane Mac Does not exist the for Given ApMac")
        return dpmac

    def create_bridge_profile(self,**kwargs):
        """ 
        API used to create Bridge profile

        URI: PUT '/wsg/api/scg/serviceProfiles/forwarding'

        :param str bridge_profile_type: Tunnel Profile Type

        :param str bridge_profile_name: Bridge Tunnel Profile Name

        :param str bridge_dhcp_realy_enabled: Bridge DHCP Relay enabled means dhcp request to forward/relay
        
        :param str bridge_dhcp_server_1: DHCP Server IP whom dhcp request to be relayed

        :param str bridge_dhcp_option_82_enabled: DHCP Option 82 to enable

        :return: True if Bridge Profile created else False

        :rtype: boolean

        Example:
        | Create Bridge Profile | bridge_profile_name=bridge_profile | bridge_dhcp_realy_enabled=True | bridge_dhcp_server_1 ="10.1.71.32"

        """
        
        bridge_profile = self.sjc.create_bridge_profile(**kwargs)
        if not bridge_profile:
            raise AssertionError("Create SCG Bridge type tunnel profile Failed")
      
    def delete_bridge_profile(self,**kwargs):
        """ 
        API used to delete Bridge profile

        URI: PUT '/wsg/api/scg/serviceProfiles/forwarding/<bridge_profile_key>'

        :param str bridge_profile_name: Bridge Tunnel Profile Name

        :return: True if Bridge Profile deleted else False

        :rtype: boolean

        Example:
        | Delete Bridge Profile | bridge_profile_name=bridge_profile | 

        """
        
        bridge_profile = self.sjc.delete_bridge_profile(**kwargs)
        if not bridge_profile:
            raise AssertionError("delete SCG Bridge type tunnel profile Failed")   
             
    def get_scg_version_python(self):
        return self.call_robot_keywords(GET_SCG_VERSION_API)
    
    def get_scg_version(self):
        """ 
        API used to get scg version

        URI: PUT '/wsg/api/scg/planes/systemSummary'

        :return: scg_version

        :rtype: string

        Example:
        | Get SCG Version | 

        """
        if  IS_PUBLIC:
            scg_version = self.get_scg_version_python()
        else:
            scg_version = self.sjc.get_scg_version()
        if not scg_version:
            raise AssertionError("get scg version Failed") 
        return scg_version
    
    def delete_latest_cluster_backup_file(self,**kwargs):
        """ 
        API used to delete Cluster backup file

        URI: PUT '/wsg/api/scg/backup/cluster/<backup_id>'

        :param str scg_version: scg version

        :return: True if Cluster backup file deleted else False

        :rtype: boolean

        Example:
        | delete latest cluster backup file | scg_version=3.1.0.0.133 | 

        """
        result = self.sjc.delete_latest_cluster_backup_file(**kwargs)
        if not result:
            raise AssertionError("delete cluster backup file Failed") 

    def config_nbi_portal_password(self,**kwargs):
        """ 
        Configure NBI Portal Interface Password

        URI: PUT '/wsg/api/scg/globalSettings/system/nbSettings'

        :param str nbi_password: password to config for NBI Portal Intarfec

        :return: True if Password configure successfully else False

        :rtype: boolean

        Example:
        | config nbi portal password | nbi_password=ruckus1!| 

        """
        result = self.sjc.config_nbi_portal_password(**kwargs)
        if not result:
            raise AssertionError("config nbi portal password Failed") 
        
    def create_wispr_profile_in_zone_template(self, **kwargs):

        """ 
        API used to create the WISPr profile in zone template

        URI: POST /wsg/api/scg/template2/zone/%s/hotspot/

        :param str wispr_profile_name: Name of WISPr Profile

        :param str zone_name: Name of the APZone

        :param str domain_label: Name of the Domain

        :param str description: Descrption

        :param str guest_user: 0 | 1 [default: '0']

        :param str smart_client_mode: enable | none | only [default: 'none']

        :param str access_type: INTERNAL | EXTERNAL [default: 'EXTERNAL']

        :param str second_redirect_type: start | user [default: 'user']

        :param str session_time: Session Timeout [default: '1440']

        :param str grace_period: Grace Period [default: '60']

        :param str location_name: Location Name

        :param str location_type: Location Type

        :param str smart_client_info: Information about the smart client

        :param str authentication_url: Logon URL

        :param str redirect_url: Start Page URL

        :param str walled_garden: Walled Garden entry

        :return: True if WISPr profile created else False

        :rtype: boolean
        
        Example:

        | Create Wispr Profile in Zone Template | wispr_profile_name="Auto_wispr_profile" | zone_name="Auto_apzone" | domain_label="Administration Domain" | 
        |                      | location_name='ACMEWISP' | location_type='us'| authentication_url='http://www.ruckuswireless.com' | 
        |                      | redirect_url='http://www.ruckuswireless.com' | walled_garden='1.2.3.4' |

        """


        res = self.sjc.create_wispr_profile_in_zone_template(**kwargs)

        if not res:
            raise AssertionError("Create Wispr Profile in Zone Template Failed")
            
        return True

    def create_ap_tunnel_profile_python(self, *args):
        return self.call_robot_keywords(CREATE_TUNNEL_PROFILE, *args)
    
    def create_ap_tunnel_profile(self, **kwargs):
        """
        Create Ap Tunnel Profile in Zone | tunnel_name="" | tunnel_type="" | tunnelMtuSize="" |
        """
        if False:
            res=self.create_ap_tunnel_profile_python(*args)
        else:
            res = self.sjc.create_ap_tunnel_profile(**kwargs)
        if not res:
            raise AssertionError("Create AP Tunnel Failed")
        return True
    
    def delete_tunnel_profile_python(self, *args):
        return self.call_robot_keywords(DELETE_TUNNEL_PROFILE, *args)
    
    def delete_tunnel_profile(self, **kwargs):
        """
        Delete Ap Tunnel Profile in Zone | tunnel_name="" |
        """
        if False:
            res=self.pubapi.delete_tunnel_profile_python(*args)
        else:
            res = self.sjc.delete_tunnel_profile(**kwargs)
        if not res:
            raise AssertionError("Delete Tunnel Profile Failed")                                            
        return True

    def create_node_affinity_profile(self, **kwargs):
        """ 
        API used to Create Node affinity profile

        URI: POST '/wsg/api/scg/nodeaffinity/profile"'

        :return: TRUE | FALSE

        :rtype: BOOLEAN

        Example:
        | create_node_affinity_profile | 

        """

        result = self.sjc.create_node_affinity_profile(**kwargs)
        if not result:
            raise AssertionError("create node affinity profile Failed") 

    def delete_node_affinity_profile(self, **kwargs):
        """ 
        API used to delete Node affinity profile

        URI: DELETE '/wsg/api/scg/nodeaffinity/profile"'

        :return: TRUE | FALSE

        :rtype: BOOLEAN

        Example:
        | delete_node_affinity_profile | 

        """

        result = self.sjc.delete_node_affinity_profile(**kwargs)
        if not result:
            raise AssertionError("delete node affinity profile Failed")


    def get_node_affinity_list(self):
        """ 
        API used to delete Node affinity profile

        URI: GET '/wsg/api/scg/nodeaffinity/profile"'

        :return: node affinity list

        :rtype: LIST

        Example:
        | get_node_affinity_list | 

        """

        result = self.sjc.get_node_affinity_list()
        if not result:
            raise AssertionError("get node list from afifnity profile Failed")
        return result


    def get_affinity_list(self):
        """ 
        API used to delete Node affinity profile

        URI: GET '/wsg/api/scg/nodeaffinity/profile"'

        :return: node affinity list

        :rtype: LIST

        Example:
        | get_node_affinity_list | 

        """
        result = self.sjc.get_affinity_list()
        if not result:
            raise AssertionError("get node list from afifnity profile Failed")
        return result



    def get_node_affinity_profile_id(self, **kwargs):

        """ 
        API used to get Node affinity  profile id

        URI: GET '/wsg/api/scg/nodeaffinity"'

        :return: profile id

        :rtype: LIST

        Example:
        | get_node_affinity_profile_id | 

        """
        result = self.sjc.get_node_affinity_profile_id(**kwargs)

        if not result:
            raise AssertionError("get node list from afifnity profile Failed")
        return result


    def enable_and_disable_node_affinity(self, **kwargs):
        """ 
        API used to enable/disable Node affinity 

        URI: GET '/wsg/api/scg/nodeaffinity"'

        :return: status

        :rtype: LIST

        Example:
        | enable_and_disable_node_affinity | 

        """
        result = self.sjc.enable_and_disable_node_affinity(**kwargs)

        if not result:
            raise AssertionError("enable_and_disable_node_affinity Failed")
        return result

    def config_ntp_server(self, **kwargs):
        """ 
        API used to update ntp server

        :param str ntpServer: ntp server ip/fqdn.

        :rtype: boolean

        Example:
        | Config NTP Server | server_ip=1.1.1.1 |

        """

        res = self.sjc.update_ntp_server(**kwargs)
        if not res:
            raise AssertionError("Failed to Update NTP Server")

        return True

    def get_arc_app_data(self, **kwargs):
        """ 
        API used to get ARC Application Data present on the SCG GUI

        URI: PUT '/wsg/api/public/v5_1/trafficAnalysis/client/app/topapp'

        :return: ARC Application Data

        :rtype: string

        Example:
        | Get Arc App Data | 

        """
        arc_app_data = self.sjc.get_arc_app_data(**kwargs)
        if not arc_app_data:
            raise AssertionError("get ARC App data Failed")
        return arc_app_data

    def get_arc_client_data(self, **kwargs):
        """ 
        API used to get ARC Client Data present on the SCG GUI

        URI: PUT '/wsg/api/public/v5_1/trafficAnalysis/client/app/topclient'

        :return: ARC Client Data

        :rtype: string

        Example:
        | Get Arc Client Data | 

        """
        arc_client_data = self.sjc.get_arc_client_data(**kwargs)
        if not arc_client_data:
            raise AssertionError("get ARC Client data Failed")
        return arc_client_data
