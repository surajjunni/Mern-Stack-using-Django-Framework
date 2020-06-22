import DeviceMacDictionary as dev
import MacDetailsDictionary as macdic
#PREREQUISITES FOR EXECUTION
SZ_MGMT_IP = "11.1.2.42"
#Must check iPAddress of external auth server for the controller IP mentioned in this file.
W_EXT_URL = "http://11.1.3.52:9997/SubscriberPortal/login"
SZ_VERSION = "5.1.1.0.186"
VERSION = "v8_1"
ZONE_NAME = "ipdual_test"
DEFAULT_ZONE = "Default Zone"
AP_MACC = ['F0:3E:90:36:D3:00','F0:3E:90:36:D3:00']
AP_IP = "11.1.2.10"
AP2_IP = "11.1.2.10"
AP_IPV6_IP="2001:192:168:10::57"
AP_IPV6_IP2="2001:192:168:10::57"
AP_VERSION= "5.1.0.0.521"
NBI_PASSWORD= "Password1!"
#By default both should be false for IPv4 zone. Modify based on required zone(IPV6/Dual). Dont keep both of them true at the same time, if you keep always IPV6 only zone will be created.
#IS_IPV6_ZONE=False
IS_DUAL_ZONE=False

AP_MODEL = "R320"
AP2_MODEL = "R510"
#80-80MHz and 160 MHz Supported AP list.
SUPPORTED_APS = ['R610','R720']
SCG_HOSTNAME = "admin"
SZ_LOGIN_PWD = "ruckus1!"
AP_PASSWORD = "Password1!"
WLAN = "IPV6_IOT_5.0"
WLAN2 = "IPV6_OPEN_5.0"
#Mark True or False.This enables/disables the dora capture process
AP_PKT_CNT = [1,1,1,1] #[DISCOVERY,OFFER,REQUEST,ACKNOWLEDGMENT]
DHCP_PKT_CNT = [1,1,1,1] #[DISCOVERY,OFFER,REQUEST,ACKNOWLEDGMENT]
CHECK_DORA_PROCESS = False
DHCP_SERVER_IP = "11.1.1.6"
DHCP_SERVER_USR = "root"
DHCP_SERVER_PWD = "ruckus1!"
TE_IP = "11.1.1.28"
TE_USERNAME = "root"
TE_PASSWORD = "ruckus"
APPIUM_IP = "10.137.40.126"
APPIUM_UNAME = "iotauto"
APPIUM_PWD = "Password1"
DEFAULT_WLAN_GROUP = "default"
CHANNEL_24 = 1
CHANNEL_50 = 36
MAC_SNIFFER_HOST="11.1.5.43"
MAC_USERNAME="root"
MAC_PASSWORD="Password1"

#Note:Please fetch the device's corresponding id from the DeviceMacDictionary.py in the current path itself and provide the id in the below list "dev_details"

dev_details = [63]

#MAC_IP must be given in single quotations. Atleast two entries are mandatory. If no device, mention 'NA'
#MAC_IP=['NA','NA']
MAC_USR=["root"]
MAC_PWD=["Password1"]

#////////////////////////// // WIRESHARK CAPTURE PARAMTER FIELDS ///////////////////
get_capture_filename = "tcpdump_mac_cap_ipv6.pcap"
get_dhcp_capture_filename="tcpdump_dhcp.pcap"
filter_capture_filename = "filter_mac_ipv6.pcap"
filter_dhcpcap_filename = "filter_dhcp.pcap"
capxml_filename = "cap_mac_ipv6.xml"
capxml_dhcp_filename = "cap_dhcp.xml"


#PING PATH
ping_filename = "ping_file_mac_mactest.txt"
ping_path = "/var/lib/jenkins/"

#ios variables
SEETEST_IP = "10.137.40.230"
SEETEST_UNAME = "aricent"
SEETEST_PWD = "Password1!"

AAA_PROFILE_NPS = "NPS_MAC"                                         
AAA_PROFILE_SBR = "SBR_MAC"                                          
AAA_PROFILE = "FR_MAC"
AAA_PROFILE_IPV6 = "FR_IPV6"
PROXY_AAA_PROFILE = "FR_PROXY"
PROXY_EAAA_PROFILE = "FR_PROXY"

#Chariot Variables
CHARIOT_IP = "10.137.40.249"
CHARIOT_UNAME = "aricent"
CHARIOT_PWD = "Password1"

#Tunnel Profile Parameters
ACCESSTUNNELTYPE = "RuckusGRE"
SOFTGRETUNNELTYPE = "SoftGRE"
GRE_PROFILE = "Default Tunnel Profile"
RUCKUS_GRE_PROFILE =  "RuckusGrEAuto"
RUCKUS_GRE_PROFILE_MANUAL =  "RuckusGrEManual"
SOFT_GRE_PROFILE = "SoftGrEAuto"
SOFT_GRE_PRIMARY_GW = "11.1.3.175"

#External DPSK Parameters
PC_IP = "11.1.3.40"
U_NAME = "aricent"
PASSWD = "Password1"
EDPSKEY = "87654321"
#######################################################PREREQUISITES DONE#################################################################

CHANNEL_WIDTH24 = 20
CHANNEL_WIDTH50 = 40
CHANNEL_WIDTH160 = 160
CHANNEL_WIDTH80 = 80
CHANNEL_WIDTH8080 = 8080
CHANNEL_WIDTH20 = 20

CHANNEL_RANGE = [52,56,60]
CHANNEL_CH=[64,153]
CHANNEL_GB=[64,104]
CHANNEL_IN=[64,153]
CHANNEL_JP=[64,104]
CHANNEL_US=[64,104,153]
CHANNEL_Z2=[64]

#CHANNEL_RANGE = [48,52,56]
L2_ACL_RESTRICTION = "ALLOW"

SZ_LOGIN_UNAME = "admin"

MODEL = "enterprise"
RD = "US"
#urls working for mac : http://python.org , word to search downloads, http://bing.com , word to search : Languages

HTTP_IP = "http://11.1.0.1"
HTTP_IP_DATA = "NETGEAR"

HTTP_URL = "http://11.1.0.1"
HTTP_DATA = "NETGEAR"

HTTP_URL2 = "http://11.1.0.1"
HTTP_DATA2  = "NETGEAR"

HTTPS_DATA1 = "Yahoo"
HTTPS_URL1 = "https://in.yahoo.com"


HTTPS_URL2 = "https://in.yahoo.com"
HTTPS_DATA2 = "Yahoo"

HTTP_DUAL_URL = "http://[2001:192:168:10::254]:8080"
HTTP_DUAL_DATA = "Jenkins"

FIXED_URL = "http://11.1.0.3"
FIXED_DATA = "NETGEAR"

WALLED_URL = "*.bing.com"

WALLED_URL_PASS = "http://bing.com"
WALLED_DATA = "Languages"

HTTPS_URL_ID = "https://in.yahoo.com"
HTTPS_DATA_ID = "Yahoo"

HTTP_URL_ID = "http://11.1.0.1"
HTTP_DATA_ID = "NETGEAR"

FIXED_DUAL_URL = "http://[2001:192:168:10::254]:8080"
FIXED_DUAL_DATA = "Jenkins"

FIXED_URL_ID = "http://11.1.0.3"
FIXED_DATA_ID = "NETGEAR"

MAC_5g="f0:b0:52:9c:1c:5d"


PSKKEY = "QWERTYUI"
LD = "Local DB"

AAA_SERVER = "11.1.0.100"
AAA_SECRET = "secret"
AAA_UNAME = "GrE"
AAA_PWD = "GrE"

AAA_SERVER_IPV6 = "2001:192:168:10::215"
AAA_SECRET_IPV6 = "testing123"
AAA_UNAME = "GrE"
AAA_PWD = "GrE"

'''AAA_SERVER = "11.1.0.100"
AAA_SECRET = "secret"
AAA_UNAME = "GrE"
AAA_PWD = "GrE"'''
RADIUS_SERVER_USERNAME = "root"
RADIUS_SERVER_PASSWD = "Password1"

EAAA_SERVER = "10.137.40.250"
EAAA_SECRET = "testing123"
EAAA_UNAME = "GrE"
EAAA_PWD = "GrE"

'''
EAAA_SERVER = "11.1.0.100"
EAAA_SECRET = "secret"
EAAA_UNAME = "GrE"
EAAA_PWD = "GrE"



'''
AAA_SERVER_SBR = "172.19.28.100"
AAA_SECRET_SBR = "12345678"
AAA_UNAME_SBR = "test"
AAA_PWD_SBR = "password"


AAA_SERVER_NPS = "11.1.1.209"
AAA_SECRET_NPS = "12345678"
AAA_UNAME_NPS = "test2"
AAA_PWD_NPS = "Password1"

COUNT_DUMMY = 5
WEP64_KEY = "1234567890"
WEP128_KEY = "12345678901234567890123456"
LDAP_PROFILE = "LDAP"
TLSENABLED=False
LDAP_UNAME = "ppratomo"
LDAP_PWD = "SomePassword"
LDAP_SERVER = "11.1.4.126"
LDAP_PORT = 389
LDAP_BASE_DOMAIN= "ou=people,dc=maxcrc,dc=com"
LDAP_ADMIN_DOMAIN= "cn=Manager,dc=maxcrc,dc=com" 
LDAP_SERVER_PWD= "secret"   
LDAP_KEY_ATTRIBUTE= "uid"
LDAP_FILTER= "objectClass=*"
G_KEY = "RWGUEST"


PROXY_AAA_UNAME = "GrE"
PROXY_AAA_PWD = "GrE"
PROXY_PORT = 1812
PROXY_SECRET = "secret"

IDENTITY_USER= "test1"   
IDENTITY_PWD= "Password123!"

PLATFORM = "Android"

#Application Denial Policy
PORT_RULE_TYPE="PORT_ONLY"
RULE_TYPE="DENY"
APP_TYPE="HTTP_DOMAIN_NAME"
APPLICATION_TYPE="SIGNATURE"
USER_APP_TYPE="USER_DEFINED"
SYS_TYPE="SYSTEM"
USERCATID="32768"
USERAPPID="1"
CATID="24"
APPID="3"
APP_URL="http://www.facebook.com"
APP_DATA="Facebook"
PORT="PORT"
PORT_NUMBER=443
PROTOCOL="TCP"
CONTENT="google.com"
PRIORITY=2
APP_DELETE_DOMAIN="DOMAIN"
APP_DELETE_VALUE="d0d495e1-de50-40e3-8d09-e4bbeb4b4722"


#Device Policy
DEFAULT_ACTION="BLOCK"
ALLOW_ACTION="ALLOW"
DESCRIPTION="ruleOne"
DESCRIPTION2="ruleTwo"
DEVICETYPE="Android"
IOSDEVTYPE="Apple_iOS"
UPLINK=2
DOWNLINK=4
VLAN=None
VLAN_IP="11.1.1"
VLAN_LIST=["11.1.2","11.1.3"]

#VLAN Pooling
ALGO="MAC_HASH"
POOL="12,13"
POOL1="12"
VLAN11=11
#VLAN15=15
ACCESSVLAN=1
OVERRIDE=False
ip="11.1.2"


'''AAA_IP = "11.1.0.100"
AAA_PC_USER = "root"
AAA_PC_PWD = "Password1"'''

AAA_IP = "10.137.40.250"
AAA_PC_USER = "root"
AAA_PC_PWD = "Password1"

AAA_PATH = "/usr/local/etc/raddb"
AAA_NAME = "radiusd"

AD_PROFILE = "ADPROFILE"
AD_SERVER = ""
AD_PORT = 389
AD_SECRET = "Ruckus100$"
AD_UNAME = "ad"
AD_PWD = "ruckus12@"

IN_CHANNEL = 0
OUT_CHANNEL = 0
OUTDOOR_CH_RANGE = [149,153,157]
INDOOR_CH_RANGE = [36,40,44]
PKG_EXPIRATION = 1
EXPIRATION_INTERVAL = "HOUR"

#STA_IP_RANGE = "120.0."
 
SCG_MANAGEMENT_IP = "11.1.0.44"
SSH_PORT = 22
SCG_ADMIN_USERNAME = "admin"
SCG_ADMIN_PASSWORD = "Password1!"
SCG_CLI_PROMPT = "SZv"
SCG_ADMIN_ENABLE_PASSWORD = "Password1!"
SCG_CONTROLLER_NAME = "SZv"
SSH_PORT = 22
SCG_PORT = 8443
SCG_API_PORT = 7443
ADMINISTRATIVE_DOMAIN = 'Administration Domain'  # Administration domain
ADMIN_DOMAIN_NAME = ADMINISTRATIVE_DOMAIN
MAC = "0C:F4:D5:27:27:C0"

#AP_IP2 = "11.1.4.88"
STREAM_TIME = 120
CHARIOT_TIMEOUT = 120
CONSOLE_TIMEOUT = 60
CHARIOT_TRAFFIC = "uavc"
CHARIOT_TRAFFIC_BE = "be"
CHARIOT_TRAFFIC_VIDEO="video"
CHARIOT_TRAFFIC_VOICE="voice"
CHARIOT_TRAFFIC_THROUGHPUT="throughput"
CHARIOT_MULTICAST_TRAFFIC="multicast_streaming"
CONTINUOUS_CONNECT_TIME =10
#ip_list="[11.1.4.76,11.1.4.79]"
PING_TIMEOUT = 120
#STREAM_URL = "https//www.youtube.com/watch?v=MqEFnxMiTEo"
STREAM_URL = "https://youtu.be/F4wRZDbSfcQ"
pcap_file_name = "radius_capture.pcap"
UAVC_PORT = 6010
UAVC_ALLOW_PORT = 5000


NO_MAC = 1
duration = 20
CHANNEL_SELECT_MODE = "ChannelFly"
DEV_MGR_PATH = "../devicemgr"
CONF = "common-settings"

#IOS Variables
SSID = "seetest"
USER = "windows"
PASSWORD = "testing123"
WEP_KEY = "1234567890"
WEP128_KEY = "12345678901234567890123456"
PEAPWLAN = "!IOTPEAP"
TTLSWLAN = "!IOTTTLS"
TLS_PROFILE = "console"
TTLS_PROFILE = "TTLS"
PEAP_PROFILE = "PEAP"
IP_SRC = "120.0.249.130" 
G_PASS =  "aaaa"
PING_IP = "11.1.0.100"
GA_LANG = "en_US"
GA_TITLE = "Welcome to the Guest Access login page."
GA_LOGO = "test"
GA_TERMS = "test"
GA_REDIRECT_URL = "https://www.amazon.com/"

L2_ACL_BLOCK = "BLOCK"
L2_ACL_RESTRICTION = "ALLOW"
iOS_device_alias = ['ios1']
iOS_ports = ['8889']



class Common_var(object):
	w11r = True
	w11r_disabled = False
	mobility_id = 1
	zero_it = False
	client_isolation = False
	hidden_ssid = False
	hidden_ssid_enabled = True
	device_policy = False
	access_vlan = 1
	client_load = False
	proxy_arp = False
	max_clients = 100
	w11d = True
	w11k = True
	force_dhcp = False
	f_dhcp = True
	dhcp_option_82 = False
	client_txrx = False
	client_idle = 120
	fingerprint = True
	uncheck_fingerprint = False
	ofdm_only = False
	band_balance = False
	istrue = True
	isfalse = False
	bypassCNA = True
	dtim_min = 1
	dtim = 122
	dtim_max = 255
	pmkCaching = False
	okc = False
	gmtOffset = 4
	gmtOffsetMinute = 40
	pass_key_size = 8
	
class Wep_var(object):
	key_index = 1

class Fdhcp_var(object):
	force_dhcp = 5

class Client_iso_var(object):
	client_iso = True


class Guest_multi_pass(object):
	pass_time = 1
	number_passes = 1

class Guest_var(object):
	timeout = 10
	g_timeout = 2
	grace = 1
	term_required_false = False
	term_required_true = True

class Guest_grace(object):
	timeout = 25
	grace = 15

class Guest_session(object):
	session = 2
	timeout = 3

class Guest_single_pass(object):
	dev_limit = 1

class Wispr_var(object):
	timeout =10
	grace = 1
	mac_format = 0

class Wispr_mac(object):
	mac_format = 2

 	
class Wispr_grace(object):
	timeout =25
	grace = 15

class Wispr_session(object):
	session = 3

class Web_var(object):
	timeout = 10
	session = 3
	grace = 1

class Web_grace(object):
	timeout = 25
	grace = 15



class AD_var(object):
	globalCatalogEnabled = False

common_var = Common_var()
wep_var = Wep_var()
fdhcp_var = Fdhcp_var()
client_iso_var = Client_iso_var()
guest_multi_pass = Guest_multi_pass()
guest_var = Guest_var()
guest_grace = Guest_grace()
guest_session = Guest_session()
guest_single_pass = Guest_single_pass()
wispr_var = Wispr_var()
wispr_mac = Wispr_mac()
wispr_grace = Wispr_grace()
wispr_session = Wispr_session()
web_var = Web_var()
web_grace = Web_grace()
ad_var = AD_var()


