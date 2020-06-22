import logging as log
import sshclient as ssh_client 
import re


def do_ssh_conn(ip_addr=None , username=None, password=None):

    sshclient = None
    try:
        sshclient = ssh_client.sshclient(ip_addr, username=username, password=password)
    except Exception :
        log.Error("SSH Connection to Windows PC : %s Connected Android Devices failed" %ip_addr)
        raise Exception ("ssh connection to windows pc %s failed" %ip_addr)

    return sshclient

def start_chariot_console(ip_addr=None , windows_username=None, windows_password=None, traffic=None, ip_list=None, timeout=None):

	sshclient = None
	connect_cmd = None
	timeout = str(60)
	sshclient = do_ssh_conn(ip_addr=ip_addr, username = windows_username, password=windows_password)
	if sshclient:
		connect_cmd =  "dev-mgmt-adb.py" + " -b "+ traffic + " -o " +  timeout  + " -i "  + ip_list + " -t " + " start_chariot_console " 
		print "connect command:%s" %connect_cmd
		res = sshclient.read_until('$',10)
        	sshclient.write("pwd\n")
        	res = sshclient.read_until('$',10)
        	res = sshclient.read_until('$',10)
		print res
		sshclient.write("/cygdrive/c/Python27/python.exe " + connect_cmd + "\n")
        	res = sshclient.read_until('$',1000)
		print res
		return res
