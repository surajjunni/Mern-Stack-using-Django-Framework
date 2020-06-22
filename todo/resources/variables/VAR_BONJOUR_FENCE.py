#Ruckus Highly Confidential Information, Copyright (C) 2014 Ruckus Wireless, Inc. All rights reserved.
import random
import os
from copy import deepcopy
import time
from var_common_scg import *

WIFI_MAC_STA1_ETH_IPV4_ADDR=os.environ.get("WIFI_MAC_STA1_ETH_IPV4_ADDR", "10.1.63.35")
WIFI_MAC_STA2_ETH_IPV4_ADDR=os.environ.get("WIFI_MAC_STA2_ETH_IPV4_ADDR", "10.1.63.36")
BF_VLAN1=int(os.environ.get("BF_VLAN1","10"))
BF_VLAN2=int(os.environ.get("BF_VLAN2","20"))
bonjour_fname = 'Bonjour_Fencing1'
bonjour_frule1 = {'description': 'rule1', 'deviceType': 'Wireless', 'serviceType':'WWW_HTTP', 'fencingRange':'SameAp'}
bonjour_frule_list = [bonjour_frule1]
bonjour_gname = 'Bonjour_Group1'
bonjour_grule1 = {"bridgeService":"WWW_HTTP", "fromVlan": int(65), "toVlan": int(70), "notes": "rule1"}
bonjour_grule_list = [bonjour_grule1]
bonjour_frule_all = [ "AIRDISK", "AIRPLAY", "AIRPORT_MANAGEMENT", "AIRPRINT", "AIRTUNES", "APPLE_FILE_SHARING", "APPLE_MOBILE_DEVICES", "APPLETV", "ICLOUD_SYNC", "ITUNES_REMOTE", "ITUNES_SHARING", "OPEN_DIRECTORY_MASTER", "OPTICAL_DISK_SHARING", "SCREEN_SHARING", "SECURE_FILE_SHARING", "SECURE_SHELL", "WWW_HTTP", "WWW_HTTPS", "WORKGROUP_MANAGER", "XGRID"]
bonjour_some_frule_hop0 = [ "AIRDISK", "AIRPLAY", "AIRPORT_MANAGEMENT"]
bonjour_some_frule_hop1 = [ "AIRPRINT", "AIRTUNES", "APPLE_FILE_SHARING"]
