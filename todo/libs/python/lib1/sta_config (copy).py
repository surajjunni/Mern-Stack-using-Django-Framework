import sys
import argparse
import json
import logging as log
import os


def create_config_file(platform,path):
    try:
        if path:
	    if platform == "Android":
                jsonfile_path=path+"/../devicemgr/device_cfg_android.json"
                print jsonfile_path
	    else:
		jsonfile_path=path+"/../devicemgr/device_cfg_ios.json"
                print jsonfile_path
        else:
            if platform == "Android":
                jsonfile_path = "/home/administrator/Aricent_Automation/tools/devicemgr/device_cfg_android.json"
	    else:
	        jsonfile_path = "/home/administrator/Aricent_Automation/tools/devicemgr/device_cfg_ios.json" 
        with open(jsonfile_path, 'w+') as f:
	    f.write('{ "devices" :[')
            os.chmod(jsonfile_path,0o777)
    except:
	log.error("Failed to load file")
	raise Exception("Failed to load file")

def update_config_file(ssid=None,authentication=None,encryption=None,wpa_algorithm=None,passphrase=None,enterprise_type=None,
enterprise_username=None,enterprise_password=None,webauth_type=None,guest_key=None,web_username=None,web_password=None,web_portal=None,
device_eth_ip=None,windows_username=None,windows_password=None,url=None,url_data=None,serialid=None,port=None,device_type=None,device_alias=None,path=None,platform=None,ios_devicename=None):
    
    jsonfile_path = None
    data = {'ssid' : ssid, 'authentication' : authentication,'encryption' : encryption, 'wpa_algorithm' : wpa_algorithm, 'passphrase' : passphrase, 'enterprise_type' : enterprise_type, 'enterprise_username' : enterprise_username, 'enterprise_password' : enterprise_password, 'webauth_type' : webauth_type, 'guest_key' : guest_key, 'web_username' : web_username, 'web_password' : web_password, 'web_portal' :  web_portal, 'device_eth_ip' : device_eth_ip, 'windows_username' : windows_username, 'windows_password' : windows_password, 'serialid' : serialid, 'port' : port, 'device_type' : device_type, 'device_alias' : device_alias, 'url' : url, 'url_data' : url_data, 'ios_devicename' : ios_devicename }
    print "\n---- Updated json configurations ----",data
    print "\n device to run ----",platform
    try:
	if path:
	    if platform == "Android":
	        jsonfile_path=path+"/../devicemgr/device_cfg_android.json"
	        print jsonfile_path
	    else:
		print "iOS "
		jsonfile_path=path+"/../devicemgr/device_cfg_ios.json"
	        print jsonfile_path
	else:
            if platform == "Android":
                jsonfile_path = "/home/administrator/Aricent_Automation/tools/devicemgr/device_cfg_android.json"
	    else:
	        jsonfile_path = "/home/administrator/Aricent_Automation/tools/devicemgr/device_cfg_ios.json" 
	
	    
	with open(jsonfile_path, 'a+') as f:
	    print "file updated"
            json.dump(data, f, indent=4)
	
    except:
	log.error("Failed to load file")
	raise Exception("Failed to load file")
    #print "Hi hello world!!"


def close_config_file(platform,path):
    try:
        if path:
            if platform == "Android":
	        jsonfile_path=path+"/../devicemgr/device_cfg_android.json"
	        print jsonfile_path
	    else:
		jsonfile_path=path+"/../devicemgr/device_cfg_ios.json"
	        print jsonfile_path
        else:
            if platform == "Android":
                jsonfile_path = "/home/administrator/Aricent_Automation/tools/devicemgr/device_cfg_android.json"
	    else:
	        jsonfile_path = "/home/administrator/Aricent_Automation/tools/devicemgr/device_cfg_ios.json"
        with open(jsonfile_path, 'a+') as f:
	    f.write(']}')
    except:
	log.error("Failed to load file")
	raise Exception("Failed to load file")
