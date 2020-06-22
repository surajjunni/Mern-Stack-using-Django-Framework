import sys
import argparse
import json
import logging as log
import os
import re

def parse_values(data):	
    #line = sys.argv()
    #var1 =  re.findall("is:\d+\.\d+", str(sys.argv))
    thru_list = []
    var1 =  re.findall("is:.*", str(data))
    print var1
    var2 =  re.findall("\d+\.\d+", str(var1))
    print "var2 is :",var2
    for i in var2:
	#print i
	thru_list.append(i)
	#print thru_list
    return thru_list



def create_config_file(path):
    try:
        if path:
	    jsonfile_path=path+"/../ioT_devicemgr/device_cfg.json"
            print jsonfile_path
        else:
	    jsonfile_path = "/home/administrator/Aricent_Automation/tools/ioT_devicemgr/device_cfg.json" 
        with open(jsonfile_path, 'w+') as f:
	    f.write('{ "devices" :[')
            os.chmod(jsonfile_path,0o777)
        f.close()
    except:
	log.error("Failed to load file")
	raise Exception("Failed to load file")

def update_config_file(ssid=None,authentication=None,encryption=None,wpa_algorithm=None,passphrase=None,enterprise_type=None,
enterprise_username=None,enterprise_password=None,webauth_type=None,guest_key=None,web_username=None,web_password=None,web_portal=None,
device_eth_ip=None,username=None,password=None,url=None,url_data=None,serialid=None,port=None,device_type=None,device_alias=None,path=None,ios_devicename=None,device_mac=None,ios_version=None):
    
    jsonfile_path = None
    data = {'ssid' : ssid, 'authentication' : authentication,'encryption' : encryption, 'wpa_algorithm' : wpa_algorithm, 'passphrase' : passphrase, 'enterprise_type' : enterprise_type, 'enterprise_username' : enterprise_username, 'enterprise_password' : enterprise_password, 'webauth_type' : webauth_type, 'guest_key' : guest_key, 'web_username' : web_username, 'web_password' : web_password, 'web_portal' :  web_portal, 'device_eth_ip' : device_eth_ip, 'username' : username, 'password' : password, 'serialid' : serialid, 'port' : port, 'device_type' : device_type, 'device_alias' : device_alias, 'url' : url, 'url_data' : url_data, 'ios_devicename' : ios_devicename, 'device_mac' : device_mac, 'ios_version' : ios_version}
    print "\n---- Updated json configurations ----",data

    try:
	if path:
	    jsonfile_path=path+"/../ioT_devicemgr/device_cfg.json"
	    print jsonfile_path
	else:
            jsonfile_path = "/home/administrator/Aricent_Automation/tools/ioT_devicemgr/device_cfg.json"
	    
	    
	with open(jsonfile_path, 'a+') as f:
	    print "file updated"
            json.dump(data, f, indent=4)
	f.close()
    except:
	log.error("Failed to load file")
	raise Exception("Failed to load file")
    #print "Hi hello world!!"


def close_config_file(path):
    try:
        if path:
            jsonfile_path=path+"/../ioT_devicemgr/device_cfg.json"
	    print jsonfile_path
        else:
            jsonfile_path = "/home/administrator/Aricent_Automation/tools/ioT_devicemgr/device_cfg.json"

        with open(jsonfile_path, 'a+') as f:
	    f.write(']}')
	f.close()
    except:
	log.error("Failed to load file")
	raise Exception("Failed to load file")
