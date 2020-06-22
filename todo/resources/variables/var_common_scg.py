###
### Basic configuration dictionary for SCG API.
###
import os
import random
from robot.libraries.BuiltIn import BuiltIn

#Default port for telnet and ssh.
TELNET_PORT_DFT = 23
SSH_PORT_DFT = 22

### SCG
SCG_LOGIN_DATA = {'username': BuiltIn().get_variable_value('${SCG_ADMIN_USERNAME}', 'admin'),
                  'password': BuiltIn().get_variable_value('${SCG_ADMIN_PASSWORD}', 'ruckus1!'),
                  'timeZoneUtcOffset': '+08:00',
                  }


MOVE_AP_DATA = {'wlanGroup24': {'name': 'default'},
                'wlanGroup50': {'name': 'default'},
                'wlanService24Enabled': True,
                'wlanService50Enabled': True,
                'wifi24': {'channel': 0,        #Auto
                           'channelWidth': 20,   #Auto, for 2.4g only 20 is valid value. "enum" : [20]
                           'txPower': 'Full',   #Max
                           },
                'wifi50': {'channel': 0,
                           'channelWidth': 0,
                           'txPower': 'Full',
                           }
                
                }

MOVE_AP_DATA_2G = {'wlanGroup24': {'name': 'default'},
                   'wlanGroup50': {'name': 'default'},
                   'wlanService24Enabled': True,
                   'wlanService50Enabled': False,
                   'wifi24': {'channel': 0,
                              'channelWidth': 20,   #Auto, for 2.4g only 20 is valid value. "enum" : [20]
                              'txPower': 'Full',
                              }
                   }

MOVE_AP_DATA_5G = {'wlanGroup24': {'name': 'default'},
                   'wlanGroup50': {'name': 'default'},
                   'wlanService24Enabled': False,
                   'wlanService50Enabled': True,
                   'wifi50': {'channel': 0,
                              'channelWidth': 0,
                              'txPower': 'Full',
                              }
                   }

TEST_ZONE_NAME = 'zone_%s_%04d' % (BuiltIn().get_variable_value('${EXEC_SUFFIX_NAME}'), random.randrange(1,9999))
PUBAPI_ZONE_CFG2 = {'name': TEST_ZONE_NAME,
                   'description': 'Zone created by pubapi for apqos auto test',
                   'countryCode': 'US',
                   'login': {'apLoginName': BuiltIn().get_variable_value('${AP_LOGIN_USERNAME}', 'super'),
                             'apLoginPassword': BuiltIn().get_variable_value('${AP_LOGIN_PASSWORD}', '!lab4man1'),}
                   }

### WLAN
STANDARD_OPEN_WLAN_NAME = 'std_open_none_%s_%04d' % (BuiltIn().get_variable_value('${EXEC_SUFFIX_NAME}'), random.randrange(1,9999)) 
STANDARD_OPEN_WLAN_DATA2 = {'name': STANDARD_OPEN_WLAN_NAME,
                           'ssid': STANDARD_OPEN_WLAN_NAME,
                           }
 
#Standalone open-none wlan cfg for station.
STANDARD_OPEN_WLAN_DATA_STA2 = {'ssid': STANDARD_OPEN_WLAN_NAME,
                               'auth': 'OPEN', 
                               'encrypt': 'NONE',
                               }


#Standalone open-none wlan cfg for station.
STANDARD_OPEN_WLAN_DATA_STA_DFT = {'ssid': STANDARD_OPEN_WLAN_NAME,
                                   'auth': 'OPEN',
                                   'encrypt': 'NONE',
                                   }

#AP ethernet port name which connect to switch.
TEST_IF_ETH_NAME = os.environ.get('TEST_IF_ETH_NAME', 'eth0')

#Fixed channel for 2.4G, default is 7.
TEST_CHANNEL_2G = os.environ.get("TEST_CHANNEL_2G", 7)
TEST_CHANNEL_5G = os.environ.get("TEST_CHANNEL_5G", 52)

TEST_PING_TARGET_IP = os.environ.get('PING_TARGET_IP', '10.1.65.21')

#----- Windows stations settings
#Windows WiFi station configuration.
WIFI_WIN_STA1_ETH_IPV4_ADDR = os.environ.get('WIFI_WIN_STA1_ETH_IPV4_ADDR', '10.1.63.13')
WIFI_WIN_STA2_ETH_IPV4_ADDR = os.environ.get('WIFI_WIN_STA2_ETH_IPV4_ADDR', '10.1.63.11')
WIFI_WIN_STA_HTTP_PORT = os.environ.get('WIFI_WIN_STA_HTTP_PORT', '8888')

TEST_STA_IP_ADDR = WIFI_WIN_STA1_ETH_IPV4_ADDR
TEST_STA_IP_ADDR2 = WIFI_WIN_STA2_ETH_IPV4_ADDR


### PUBLCI API VARIABLES ###
PUBLIC_API_VERSION = 'v2_1'
publicapi_password = SCG_LOGIN_DATA['password']
create_success_code = 201
bad_request_code = 400
internal_server_error_code = 500
unathorized_request_code = 401
maximum_num_zones = 8
zoneName = PUBAPI_ZONE_CFG2['name']
timezone = 'IST'
diff_timezone = 'PST'
description = 'description'
country_code = PUBAPI_ZONE_CFG2['countryCode']
ap_version = '3.1.1.0.413'
newZoneName = 'pubzone-update'
apLogin = SCG_LOGIN_DATA['username']
apPass = SCG_LOGIN_DATA['password']
apLogin_max_len = 64
apPass_max_len = 63
zonename_max_len = 32
apLogin_min_len = 2
apPass_min_len = 7
zonename_min_len = 2
passwd_special_char = '!~#*&^)(/,.:$'
special_char_space = '!~# *&^)(/,.:$'
special_char = '!~#*&^)(/,.:$'
zone_regex = ['\\s*2.4GHz\\s*:\\s*Disabled', '\\s*5GHz\\s*:\\s*Disabled']
sun = ['00:15-01:15','07:00-08:30','10:45-12:00']
skip_request_validation =  'skip_request_validation'

primary_radius_ip=  '10.1.1.1'
primary_radius_share_secret = 'testing123'
std_authentication_type = 0
hotspot_authentication_type = 1
guestaccess_authentication_type = 4
hotspot2_authentication_type = 3
webauth_authentication_type = 5
open_authentication_method = 'OPEN'
#802_authentication_method = '802.1X'
mac_authentication_method = 'MAC'
default_enable_mac_auth_password = 0

ap_serial_no = '271403002345'
ap_model = 'R700'
ap_name = 'RuckusAP'
ap_lattitude = 22
ap_longitude = 114
ap_location = 'Bangalore'
ap_administrativeState = 'Unlocked'
approvisionChecklist = 'test'

#physical_ap_mac =   50:A7:33:14:6B:20   # SCG physical AP required for some test cases
#sz_physical_ap_mac =  2C:E6:CC:07:CE:10  # SZ physical AP required for some test cases

SCG_MANAGEMENT_IP = os.environ.get('SCG_MANAGEMENT_IP', '172.19.16.121')
SCG_CONTROL_IP = os.environ.get('SCG_CONTROL_IP', '10.1.65.11')
AP_IP = os.environ.get('AP1_IP', '10.1.65.41')
AP2_IP = os.environ.get('AP2_IP', '10.1.65.31')
SCG_ADMIN_USERNAME = SCG_LOGIN_DATA['username']
SCG_ADMIN_PASSWORD = SCG_LOGIN_DATA['password']
SCG_ADMIN_ENABLE_PASSWORD = SCG_ADMIN_PASSWORD
SCG_HOSTNAME = os.environ.get('SCG_HOSTNAME', 'vscg1')
SSH_PORT = 22
SCG_CLI_PROMPT = SCG_HOSTNAME
SCG_CONTROLLER_NAME = SCG_HOSTNAME
#${physical_ap_mac}   %{AP_MAC}
#${physical_ap_mac1}   %{AP_MAC2}

####################################Login test cases variables start##############################################################################

SUPER_ADMIN_ROLE = 'Super Admin'  #super admin role
ADMINISTRATIVE_DOMAIN = 'Administration Domain'  # Administration domain
ADMIN_DOMAIN_NAME = ADMINISTRATIVE_DOMAIN
#SCG_SPECIAL_CHARACTERS = ['`','~','!','#','$','%','^','&','*','(',')','-','_','=','+','[',']','{','}','|',';',':','"','\,','.','<','>','/']

SCG_SPECIAL_CHARACTERS = ['~','!','#','%','^','&','*','(',')','-','_','=','+','[',']','|',';',':','\,','.','<','>','/']

LOGIN_SUCCESS_CODE = 200  #login success code is 200
SCG_PORT = 8443
SCG_GUI_PORT = SCG_PORT  # SCG GUI access Port

VALID_USERNAME = SCG_LOGIN_DATA['username']
VALID_PASSWORD = SCG_LOGIN_DATA['password']

VALID_TIMEZONEUTCOFFSET = '+08:00'  # SCG timezone offset
VALID_TIMEZONEUTCOFFSET_C1 = '+10:00'  # SCG timezone offset

SCG_API_VERSION_REGEX = '\\d+\\.\\d+\\.\\d+\\.\\d+\\.\\d+'  # API version  regex pattern

######################################Login test cases variables end##################################################################################

############################################Get AP zone and validate start###########################################################################

get_success_code =  200  #get success code
Guest_Role = 'Guest Pass Generator'  #Gust role, only view access
Regex_Special_space = '^.+(?=.*[`~!#$%^&*()-_=+[\\]{}|;:",.<>/?@])(?=.*[\\s])[^ ]{2,}.+$'  #Validate AP zone entries has atleast one special character and white space
Regex_lengthy_Chars = '^.{32}$'  #validate lengthy characters
name_regex = '^.{2,32}$'  #validate name entry length
Get_Failure_code = 401
Get_Zone_Error_code = 201
get_NonExisting_code = 422
get_NonExisting_Error_code = 301
get_NoPermission_code = 403
get_NonPermission_Error_code = 212
get_NoResponse_Code = 404
Resource_Not_Found_Code = 301  #nnn
Bad_Request_Code = 101  #nnn
get_ServiceUnavailable_Code = 503
invalid_url = 'https://172.19.16.100:7443/api/publii/v1_0'
wlanSSID_API = 'wlanPublicAP'
mon = ['00:15-01:15','07:00-08:30','10:45-12:00']
############################################Get AP zone and validate end##############################################################################

##########################################Delete method and validate variables start###########################################################################
delete_success_code = 204  # delete success code
Resource_Not_Found_Code = 301
Bad_Request_Error_Code = 101
Lack_Of_Admin_Privilage_Code = 211
MVNO_role = 'MVNO Super Admin'
Method_Not_allowed_Code = 405
Invaild_HTTP_Request_Body_Code = 103
##########################################Delete method and validate variables start###########################################################################
############################################Modify method and validate variables start###########################################################################
update_success_code = 204
Bussiness_Rule_Violation_Error_Code = 302

SCG_WITH_AP_DISCOVERED = '172.19.16.180'
SCG_WITH_AP_DISCOVERED_PWD = 'ruckus1!'

controller_node_not_in_service = 151
cluster_not_in_service = 150

############################################Modify method and validate variables end###########################################################################

#############################################################Sz 100 variables start###############################################################

default_zone_name = 'Default Zone'
mvnoDefaultRole = 'Guest Pass Generator'
MODEL =  'enterprise'
###############################################################Sz 100 variables end###############################################################
domain_name = 'doamin@ruckuswireless.com'

###############################################################Capture AP settings###############################################################
#Capture ap login information
CAPTURE_AP_IP_ADDR = os.environ.get("CAPTURE_AP_IP_ADDR", "10.1.64.22")
CAPTURE_AP_TELNET_PORT = os.environ.get("CAPTURE_AP_TELNET_PORT", BuiltIn().get_variable_value('${TELNET_PORT_DFT}',TELNET_PORT_DFT))
CAPTURE_AP_SSH_PORT = os.environ.get("CAPTURE_AP_SSH_PORT", BuiltIn().get_variable_value('${SSH_PORT_DFT}',SSH_PORT_DFT))
CAPTURE_AP_USERNAME = os.environ.get("CAPTURE_AP_USERNAME", "super")
CAPTURE_AP_PASSWORD = os.environ.get("CAPTURE_AP_PASSWORD", "sp-admin")

#Wlan if variables for capture ap. Capture AP is always standalone ap with 9.8 build.
CAPTUREAP_TEST_IF_WLAN_2G = os.environ.get('CAPTUREAP_TEST_IF_WLAN_2G', 'wlan0')
TEST_WLAN_IF_CAPTURE_2G = os.environ.get("TEST_WLAN_IF_CAPTURE_2G", "wlan100")
CAPTUREAP_TEST_IF_WLAN_5G = os.environ.get('CAPTUREAP_TEST_IF_WLAN_5G', 'wlan9')
TEST_WLAN_IF_CAPTURE_5G = os.environ.get("TEST_WLAN_IF_CAPTURE_5G", "wlan101")

#scan_radio Timeout
Timeout  = os.environ.get("Timeout",150)
PCAP_FILE_LOC=os.environ.get("PCAP_FILE_LOC", "/opt/tftpboot/capture.pcap0")
XML_FILE_LOC=os.environ.get("XML_FILE_LOC", "/opt/tftpboot/capture_bgs.xml")
PCAP_FILE_LOC_5G=os.environ.get("PCAP_FILE_LOC_5G", "/opt/tftpboot/capture.pcap1")
TEST_CAPTURE_IF_WLAN_2G_SSID = os.environ.get('TEST_CAPTURE_IF_WLAN_2G_SSID', 'qatest_apcap_007_2g')
TEST_CAPTURE_IF_WLAN_5G_SSID = os.environ.get('TEST_CAPTURE_IF_WLAN_5G_SSID', 'qatest_apcap_007_5g')

#Test engine configuration.
TEST_ENGINE_IP_ADDR = os.environ.get('TEST_ENGINE_IPV4_ADDR', '172.19.16.111')
TEST_ENGINE_TELNET_PORT = os.environ.get('TEST_ENGINE_TELNET_PORT', BuiltIn().get_variable_value('${TELNET_PORT_DFT}',TELNET_PORT_DFT))
TEST_ENGINE_USERNAME = os.environ.get('TEST_ENGINE_USERNAME', 'administrator')
TEST_ENGINE_PASSWORD = os.environ.get('TEST_ENGINE_PASSWORD', 'ruckus')
TEST_ENGINE_ROOT_PASSWORD = os.environ.get('TEST_ENGINE_ROOT_PASSWORD', 'ruckus')
TEST_ENGINE_TFTP_BOOT = os.environ.get('TEST_ENGINE_TFTP_BOOT', "/opt/tftpboot")
#TEST_ENGINE_PROMPT = '\[(%s|root)@(dl-te|[^\s]+) [~\w\.\-]+\]#' % BuiltIn().get_variable_value('${TEST_ENGINE_USERNAME}',TEST_ENGINE_USERNAME)
TEST_ENGINE_PROMPT = '\[?(%s|root)@(dl-te|[^\s]+).*?\]?#' % BuiltIn().get_variable_value('${TEST_ENGINE_USERNAME}',TEST_ENGINE_USERNAME)
