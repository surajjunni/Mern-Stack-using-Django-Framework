# Copyright (C) 2008 Ruckus Wireless, Inc. All rights reserved.
# Please make sure the following module docstring is accurate since it is used
# by database initialization scripts as the TestbedComponent description.

"""
RuckusAP interfaces with and controls any Ruckus Access Point via telnet CLI.
For wlan interface specific commands such as 'set ssid wlan_if', wlan interface ID
(wlan0, wlan1, etc) is used as argument.

Usage Example:

    from ratenv import *
    dd = dict(ip_addr='192.168.0.200', username='admin', password='admin', init=False)
    apx = RuckusAP.RuckusAP(dd)
    apx.initlialize()
    print "AP Mgmt_VLan: %s" % ap.get_mgmt_vlan()

"""

#import os
import logging
import time
import re
import socket
import telnetlib
#import tarfile
#import ftplib
#import shutil
import paramiko
import pdb
#import requests

INTERNAL_WLAN = {
    'name': ['meshd', 'meshu', 'recovery-ssid', 'wlan50', 'wlan51', ],
    'type': ['MON', '???'], # has wlan50 and wlan51
}
CM_NAME = "RuckusAP"

class RuckusAP():
    feature_update = {}


    def __init__(self,  ip_addr = '192.168.0.1', 
                        username = 'super', 
                        password = 'sp-admin', 
                        ap_staging_zone_username = 'admin' , 
                        ap_staging_zone_password = 'admin'):
        """
        Connect to the Ruckus AP at the specified IP address via telnet.
        The specified login credentials will be used.
        All subsequent CLI operations will be subject to the specified default timeout.
        If log_file is specified then out CLI output will be logged to the specified file.
        This will enable telnet if telnet is not already enabled.
        """
        self.ip_addr = ip_addr
        self.username = str(username)
        self.password = str(password) 
        self.timeout = 10
        self.ftpsvr = '' 
        self.log_file = ''
        self.init = True
        self.debug = False 
        self.telnet = True 
        self.port = 23
        self.force_telnet = False
        self.ssh_port = 22
        self.ap_staging_zone_username = str(ap_staging_zone_username)
        self.ap_staging_zone_password =str(ap_staging_zone_password)

        self.tcpdump_pid = None
        self.tcpdump_file = "/root/tmp/tcpdump_in_ap.pcap"
        self.ap_serial = ''
        self.access_key = ''

        if self.init:
            self.initialize()


    def __del__(self):
        #self.stop_sniffer()
        #self.delete_tcpdump_file()
        self.close()

    def initialize(self):
        if self.debug: 
            pdb.set_trace()
 
        self.prompt = "rkscli:"
        self.base_mac_addr = '00:00:00:00:00:00'

        # global pause seconds to overwrite default pause/sleep times
        self.pausedict = dict(after_reboot=10)

        if self.telnet:
            self.login(self.port)
        else:
            self.login_via_ssh(self.ssh_port)

        self.ap_serial = self.get_serial()
    
        self.CPU_USAGE_INFO = 0
        self.MEMORY_INFO = 1

        # for display we would not talk to AP; use the first one
        self.base_mac_addr = self.get_base_mac().lower()

    def log(self, txt):
        """Log specified text if a log_file is configured"""
        if self.log_file:
            stime = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
            self.log_file.write("\r%s\r%s" % (stime, txt))

    def try_times(self, times = 3, interval = 2):
        for t in range(1, times + 1):
            yield t
            time.sleep(interval)

    def get_username(self):
        return self.username

    def get_password(self):
        return self.password

    def get_ip_addr(self):
        return self.ip_addr

    def expect(self, expect_list, timeout = 0):
        """
        A wrapper around the telnetlib expect().
        This uses the configured timeout value and logs the results to the log_file.
        Returns the same tuple as telnetlib expect()
        """
        if not timeout:
            timeout = self.timeout
        ix, mobj, rx = (-1, None, "")
        ix, mobj, rx = self.tn.expect(expect_list, timeout)
        self.log(rx)
        return (ix, mobj, rx)


    def expect_prompt(self, timeout = 0, prompt = ""):
        """Expect a prompt and raise an exception if we don't get one. Returns only input."""
        if not prompt:
            target_prompts = [self.prompt]
        elif type(prompt) is list:
            target_prompts = prompt
        else:
            target_prompts = [prompt]

        ix, mobj, rx = self.expect(target_prompts, timeout = timeout)
        if ix:
            # mesh AP seems to response slower; give it another try anyway
            ix, mobj, rx = self.expect(target_prompts, timeout=30)
            if ix:
                raise Exception("Prompt %s not found" % prompt)
        return rx


    def login(self, port=22, interval = 2):
        '''
        . Login to AP. If a telnet session is already active this will close
          that session and create a new one.
          allow to change default interval sleep before try another login to 120 if set_factory is called
        '''
        for z in self.try_times(3, interval):
            try:
                print "ip addr", self.ip_addr
                print "porttt", port
                self.tn = telnetlib.Telnet(self.ip_addr, port)
                break
            except:
                # if force_telnet = True, it means only using telnet to connect.
                # No enable telnet via ssh
                if not self.force_telnet:
                    self.enable_telnet_via_ssh()
                if z == 3:
                    #log_trace()
                    print(CM_NAME, "login", 'Unable to login to AP  [%s %s] ' \
                                    % (self.base_mac_addr, self.ip_addr))
                    raise

        ix,mobj,rx = self.expect(["login"])
        if ix == -1:
            try:
                # special condition for sim-ap which started up in shell mode
                self.tn.write("rkscli\n")
            except:
                pass
        else:
            self.tn.write(self.username+"\n")
            ix2,mobj,rx = self.expect(["password"])
            if ix or ix2:
                raise Exception("Login Error")
            self.tn.write(self.password+"\n")

        self.expect_prompt(30)
        self.set_timeout() # set default timeout for AP



    def _wait_for(self, chan, text, recv_bufsize=1024, retry=200, pause=0.02):
        '''
        quick and dirty excpect substitute for paramiko channel;
        Raise exception if text not found.
        ssh=dict(pause=0.02, retry=200, recv_bufsize=1024, port=22),
        '''
        for x in range(retry):
            if chan.recv_ready():
                data = chan.recv(recv_bufsize)
#                if text in chan.recv(recv_bufsize):
#                    return data # success
                if text in data:
                    return data # success
            time.sleep(pause) # 100*.02 = approx 2 seconds total
        raise Exception("SSH expect")


    def _ssh(self, port, is_enabling=True, retries=3):

        for i in self.try_times(retries, 5):
            chan = None
            t = None
            
            if i == (retries):
                self.username = self.ap_staging_zone_username
                self.password = self.ap_staging_zone_password

            try:
                t = paramiko.Transport((self.ip_addr, port))
                t.connect(username = "", password = "", hostkey = None)
                chan = t.open_session()
                chan.get_pty()
                chan.invoke_shell()
                self._wait_for(chan, 'login')
                chan.send(self.username + "\n")
                self._wait_for(chan, 'password')
                chan.send(self.password + "\n")
                self._wait_for(chan, 'rkscli:')


                if is_enabling:
                    chan.send("set rpmkey telnetd-port-number %s\n" % self.port)
                    self._wait_for(chan, 'OK')
                    chan.send("set telnet disable\n")
                    self._wait_for(chan, 'OK')
                    chan.send("set telnet enable\n")
                    self._wait_for(chan, 'OK')
                    print 'Enable telnet success'

                chan.close()
                t.close()
                del chan, t
                return

            except Exception as e:
                # Close ssh chan and connection when connect fail
                if chan:    
                    chan.close()
                if t:    
                    t.close()


        msg = "_ssh", "Unable to login ssh via [%s:%s]" % (self.ip_addr, port)
        print(CM_NAME, "_ssh", msg)
        raise # Exception(msg)

    def enable_telnet_via_ssh(self):
        return self._ssh(self.ssh_port, is_enabling=True)


    def login_via_ssh(self, port=22):
        return self._ssh(port, is_enabling=False)


    def close(self):
        """Terminate the telnet session"""
        try:
            self.tn.close()
        except:
            pass


    def do_cmd(self, cmd_text, timeout = 0, prompt = ""):
        return self.cmd(cmd_text, timeout = timeout, prompt = prompt, return_list = False)


    def cmd(self, cmd_text, timeout=0, prompt = "", return_list = True, blocking_mode=True):
        if not prompt:
            prompt = self.prompt

        try:
            # empty input buffer and log if necessary
            #self.log(self.tn.read_very_eager())
            # issue command
            self.tn.write(cmd_text + "\n")

            if not blocking_mode:
                return

            # get result
            r = self.expect_prompt(prompt = prompt, timeout = timeout)  # logs as side-effect
        except (EOFError, Exception, socket.error):
            logging.info("Telnet session had been disconnected. Try to relogin to the AP [%s %s]" % (self.base_mac_addr, self.ip_addr))
            try:
                self.login()
            except:
                self.enable_telnet_via_ssh()
                self.login()
            self.tn.write(cmd_text + "\n")
            r = self.expect_prompt(prompt = prompt, timeout=30)

        if return_list:
            # split at newlines
            rl = r.split('\n')
            # remove any trailing \r
#            rl = [x.rstrip('\r') for x in rl]
            rl = [x.replace('\r','') for x in rl]
            # filter empty lines and prompt
            rl = [x for x in rl if x and not x.endswith(prompt)]
            return rl[1:] # remove cmd_text from output
        else:
            return r


    def get_base_mac(self):
        """
        Return the device Mac address of the AP
        """
        return [x.split()[-1] for x in self.cmd('get boarddata') if re.search('base ([0-9,a-f,A-F]+:*)*', x)][0]

    def get_model(self):
        """
        Return the model of the AP
        """
        return [x.split()[-1] for x in self.cmd('get boarddata') if re.search('Model:', x)][0]
    def get_serial(self):
        """
        Return the serial of the AP
        """
        return [x.split()[-1] for x in self.cmd('get boarddata') if re.search('Serial#:', x)][0]

    def get_version(self):
        """Return the AP Software version string reported by 'get version'"""
        ss = self.cmd("get version", return_list=False)
        mm = re.search(r'version:\s*([\d.]+)', ss, re.I)
        if mm:
            return mm.group(1)

        return '0.0.0.0.0'


    def get_system_description(self):
        """Return the detailed AP Software version string reported by 'get version'"""
        ret = self.cmd("get version")
        system_description = "%s/SW %s" % (ret[0], ret[1])

        return system_description


    def get_country_code(self):
        """Return the AP country code string reported by 'get countrycode'"""

        ss = self.cmd("get countrycode", return_list=False)
        mm = re.search(r'Country is\s([A-Z][A-Z])', ss, re.I)
        if not mm:
            raise Exception("Failed to get country code")
        return mm.group(1)


    def get_tunnel_type(self,retry=3):
        """Return the AP tunnel type string reported by 'get tunnelmgr'"""
        while retry:
            for x in self.cmd('get tunnelmgr'):
                mm = re.search(r'GRE over UDP', x, re.I)
                if mm:
                    return 0 if re.search(r'No GRE over UDP', x, re.I) else 1
            retry -= 1
            time.sleep(10)
        raise Exception("Failed to get tunnel type")


    def get_mesh_enable(self):
        """Return the AP mesh string reported by 'get mesh'"""

        ss = self.cmd("get mesh", return_list=False)
        return False if re.search(r'Mesh is not enabled', ss, re.I) else True


    def get_channel_id(self, wlan_no):
        """Return the AP tunnel type string reported by 'get channel'"""

        for x in self.cmd("get channel wifi%d" % wlan_no):
            mm = re.search(r'wifi%d Channel\:\s*([0-9]+)' % wlan_no, x, re.I)
            if mm:
                str_channel_id = mm.group(0).rsplit(' ')[-1]
                return int(str_channel_id)

        raise Exception("Failed to get channel ID")


    def get_device_name(self):
        """Return the AP name string reported by 'get device-name'"""

        for x in self.cmd("get device-name"):
            mm = re.search(r'device name : \'(.*)\'', x, re.I)
            if mm:
                return mm.group(1)
#                return x.split("Device location : ")[-1].strip('\'')

        raise Exception("Failed to get device name")


    def get_device_gps(self):
        """Return the AP GPS string reported by 'get device-gps'"""

        for x in self.cmd("get device-gps"):
            mm = re.search(r'GPS coordinates : ([\d\s,\.]*)', x, re.I)
            if mm:
                return mm.group(1)
#                str_device_gps = x.split()[-1]
#                return None if str_device_gps == ':' else str_device_gps

        raise Exception("Failed to get device GPS")


    def get_device_location(self):
        """Return the AP location string reported by 'get device-location'"""

        for x in self.cmd("get device-location"):
            mm = re.search(r'Device location : \'(.*)\'', x, re.I)
            if mm:
                return mm.group(1)
#                return x.split("Device location : ")[-1].strip('\'')

        raise Exception("Failed to get device location")


    def get_provisioning_tag(self):
        """Return the AP provision tag string reported by 'get provisioning-tag'"""

        for x in self.cmd("get provisioning-tag"):
            mm = re.search(r'(current provisioning tag:\s.+\.|provisioning tag not set.)', x, re.I)
            if mm:
                res = mm.group(0).strip("current provisioning tag: ").rstrip('.')
                return None if res == '' else res

        raise Exception("Failed to get provisioning tag")


    def get_ipaddr_wan(self):
        """Return the AP IP address info by 'get ipaddr wan'"""

        for item in self.cmd("get ipaddr wan"):
            mobj = re.search("IP Address: \((.*)\), IP: ([\d\.]+)  Netmask ([\d\.]+)  Gateway ([\d\.]+)", item, re.I)
            if mobj is not None:
                ipaddr_wan_cfg = {
                    "IP Address": mobj.group(1),
                    "IP": mobj.group(2),
                    "Netmask": mobj.group(3),
                    "Gateway": mobj.group(4)
                }
                return ipaddr_wan_cfg

        raise Exception("Failed to get IP address info")


    def get_lldp_cfg(self):
        """Return the AP LLDP configuration reported by 'get lldp'"""

        lldp_cfg = {}
        is_eth_interface = False

        ret = self.cmd("get lldp")

        for item in ret[:-1]:
            item_list = re.split('[\s]?: ', item)
#            if len(item_list) != 2:
            if not is_eth_interface and re.search('LLDP interface', item):
                is_eth_interface = True
                lldp_cfg.setdefault('interface', {})
                continue
            if not is_eth_interface:
                lldp_cfg.setdefault(item_list[0].strip('LLDP '), item_list[1])
            else:
                lldp_cfg['interface'].setdefault(item_list[0].strip('LLDP on '), item_list[1])

        return lldp_cfg


    def get_lldp_neighbors_list(self):
        """Return the AP LLDP configuration list reported by 'get lldp neighbors'"""

        raw_ret = self.cmd("get lldp neighbors")
        ret = raw_ret[2:-2]

        if len(ret) == 0:
            return None

        lldp_neighbors_list = []
        lldp_neighbors_cfg = None
        is_new_cfg = False
        upper_key = None

# Parse the general config
        for line in ret:
            if re.search('^--+', line):
                lldp_neighbors_cfg = {}
                lldp_neighbors_list.append(lldp_neighbors_cfg)
                is_new_cfg = True
                continue

            if is_new_cfg:
                gen_ret = re.split(',', line, 3)
                for item in gen_ret:
                    [key, value] = re.split(':\s*', item, 1)
                    lldp_neighbors_cfg.setdefault(key.lstrip(' '), value)
                is_new_cfg = False
            else:
# Parse the Chassis config
                [key, value] = re.split(':\s*', line, 1)
                if value == '':
                    upper_key = key.lstrip(' ')
                    lldp_neighbors_cfg.setdefault(upper_key, {})
                else:
                    key_no_space = key.lstrip(' ')
                    if lldp_neighbors_cfg[upper_key].has_key(key_no_space):
                        lldp_neighbors_cfg[upper_key][key_no_space] = lldp_neighbors_cfg[upper_key][key_no_space] + '; %s' % value
                    else:
                        lldp_neighbors_cfg[upper_key].setdefault(key_no_space, value)

#        for lldp_neighbors in lldp_neighbors_list:
#            chassis_id = lldp_neighbors['Chassis']['ChassisID']
#            lldp_neighbors['Chassis']['ChassisID'] = re.split(' ', chassis_id)[-1].upper()

        return lldp_neighbors_list


    def get_eth(self):
        """ Return AP ethernet interface by 'get eth'"""
        ret = self.cmd("get eth")
        if re.match("Port\s+Interface\s+802.1X\s+Logical Link\s+Physical Link\s+Label", ret[0]) is None:
            raise Exception("Fail to find the correct information")
        title_list = re.split('\s\s+', ret[0])

        eth_cfg_list = []
        for line in ret[2:-1]:
            eth_cfg = dict()
            index = 0
            for item in re.split('\s\s+', line):
                eth_cfg.setdefault(title_list[index], item)
                index += 1
            eth_cfg_list.append(eth_cfg)

        return eth_cfg_list


    def get_wlaninfo(self):
        """Return the AP wlan info dictionary reported by 'get wlaninfo'"""

        raw_ret = self.cmd("get wlaninfo")
        ret = raw_ret[:-2]

        if len(ret) == 0:
            return None

        wlaninfo_cfg_dict = dict()
        wlaninfo_cfg = None
        for line in ret:
            if re.search('wlan[\d]+', line):
                mobj = re.search('(wlan[\d]+)[\s]+SSID / BSSID: ([\w\S]+) / ([0-9a-fA-F:]{17})', line)
                if not mobj:
                    raise Exception("Fail to find SSID/BSSID in %s" % line)

                wlaninfo_cfg = {}
                wlaninfo_cfg.setdefault('SSID', mobj.group(2))
                wlaninfo_cfg.setdefault('BSSID', mobj.group(3).upper())
                wlaninfo_cfg_dict.setdefault(mobj.group(1), wlaninfo_cfg)
            else:
                if not re.search(':\s', line):
                    continue
                [key, value] = re.split(': ', line, 1)
                wlaninfo_cfg.setdefault(key.lstrip(' '), value.rstrip(' '))

        return wlaninfo_cfg_dict


    def get_encryption(self, wlan_if):
        """Return the AP encryption type reported by 'get encryption'"""

        raw_ret = self.cmd("get encryption %s" % wlan_if)
        ret = raw_ret[:-1]

        encryption_cfg = dict()
        if re.search('SSID[\s]+:', ret[0]):
            for line in ret:
                if not re.search(':', line):
                    continue
                [key, value] = re.split('[\s]*:[\s]*', line, 1)
                encryption_cfg.setdefault(key.lstrip(' \t'), value.rstrip(' '))

        return encryption_cfg


    def get_interface_mac(self, eth_if):
        """Return the AP mac address in a specific ethernet port"""

        ret = self.do_shell_cmd('ip link show dev %s' % eth_if)
        for line in ret:
            mobj = re.search('link/ether ([0-9a-fA-F:]{17}) brd ff:ff:ff:ff:ff:ff', line)
            if mobj:
                return mobj.group(1)

        return None


    def set_lldp_holdtime(self, holdtime):
        """
        Set lldp hold time
        """

        for line in self.cmd('set lldp holdtime %d'% holdtime):
            if re.match('Error:', line):
                raise Exception("%s" % line)


    def set_lldp_interval(self, interval):
        """
        Set lldp interval
        """

        for line in self.cmd('set lldp interval %d'% interval):
            if re.match('Error:', line):
                raise Exception("%s" % line)


    def set_lldp_ifname_enable(self, eth_if, enable):
        """
        Set lldp interface enable/disable
        """

        for line in self.cmd('set lldp ifname %s %s'% (eth_if, ("enable" if enable else "disable"))):
            if re.match('Error:', line):
                raise Exception("%s" % line)


    def set_lldp_mgmt_enable(self, enable):
        """
        Set lldp management address enable/disable
        """

        self.cmd('set lldp mgmt %s'% ("enable" if enable else "disable"))


    def set_device_name(self, device_name):
        """
        Set the device name
        """

        self.cmd('set device-name %s'% device_name)


    def set_ipaddr_wan(self, params):
        """
        Set ipaddr wan
        """

        self.cmd('set ipaddr wan %s'% params, blocking_mode = False)
#        for line in :
#            if re.search('Error: parameter error', line):
#                raise Exception("Setting fail with params [%s] " % params)


    def goto_shell(self):
        """ Enter into the shell
        """
        #check AP's version 
        shell_key_login = 0
        b_string = self.get_version().split('.')
        b_v = int(b_string.pop(-1))
        scg_build = '.'.join(b_string)
        if scg_build == '2.5.0.1':
            shell_key_login = 1 
        elif scg_build == '2.5.0.0':
            if b_v >= 441:
                shell_key_login = 1
            else:
                shell_key_login = 0
        
        #if int(self.get_version().split('.')[-1]) >= 441:
        if shell_key_login == 1:
            # get key from server
            self.get_access_key()

            self.tn.write("ruckus\n")
            time.sleep(2)
            self.tn.write("%s\n"% self.access_key)
            r, m, rr = self.expect(['grrr'])
            if r == -1:
                print(CM_NAME, "goto_shell", "Set access key fail: [%s]"% rr)
                raise Exception("Can not into shell mode, set access key fail!")
            else:
                self.cmd("!v54!", prompt = "What's your chow")
                self.cmd("", prompt = "#")

        else:
            self.cmd("set rpmkey cli_esc2shell_ok t")
            self.cmd("!v54!", prompt = "#")

    def exit_shell(self):
        """ Exit the shell and log back into CLI
        """
        try:
#            self.cmd('exit', 0, 'Please login')
            self.cmd('rkscli', 0, self.prompt)
#            self.tn.write('\n')
        except Exception:
            pass
 #       self.login()

    def do_shell_cmd(self, cmd_text, timeout = 0, return_list = True):
        """
        Execute shell command.
        """
        self.goto_shell()
        result = self.cmd(cmd_text, prompt = "#", timeout = timeout, return_list = return_list)
        self.exit_shell()

        return result

    def set_timeout(self, timeout = 3600):
        self.cmd("set timeout %d" % timeout)
        time.sleep(1)

    def set_factory(self, login=True):
        """
        Set factory default for AP
        """
        print(CM_NAME, "set_factory", "Reset AP to factory")

        res = self.cmd("set factory")
        if "OK" in res:
            #aapi.reboot(login=login) #(factory = True)
            self.reboot(login=login) #(factory = True)
            time.sleep(20)
            print(CM_NAME, 'set_factory', "Set default factory OK")
        else:
            XLogger.error(CM_NAME, 'set_factory', "Can not set default factory for AP")
            raise Exception("Can not set default factory for AP")


    def set_lldp_enable(self, enable):
        """
        enable/disable LLDP
        """

        self.cmd("set lldp %s" % ("enable" if enable else "disable"))
        time.sleep(1)


    def reboot(self, timeout=180, login=True, telnet=True, exit_on_pingable=False):
        """
        Rebooting AP
        """
        print(CM_NAME, 'reboot', "Start to reboot")
        if not timeout:
            timeout = self.timeout

        self.tn.write('reboot\n')
        time.sleep(self.pausedict['after_reboot'])

        if login:
            self.wait_for_ap_boot_up(timeout, exit_on_pingable)
            print(CM_NAME, 'reboot',"AP has been rebooted and re-login successfully")
        else:
            print(CM_NAME, 'reboot',"AP has been rebooted successfully")


    def wait_for_ap_boot_up(self, timeout=180, exit_on_pingable=False):
        logging.info("Wait until the AP [%s %s] boots up" % (self.base_mac_addr, self.ip_addr))
        time.sleep(5)

        is_ping_able = False
        for z in try_interval(timeout, 2):
            if not is_ping_able:
                if "Timeout" not in ping(self.ip_addr):
                    logging.info("Device is pingable. Wait until the SSH/telnet services are up and running.")
                    is_ping_able = True
                    if exit_on_pingable:
                        logging.info("AP is pingable, exiting reboot procedure.")
                        return
            else:
                try:
                    # no need to sleep this long
                    time.sleep(timeout/3)
                    self.login(interval=timeout/3)
                    logging.info("Login to the AP [%s %s] successfully" \
                                 % (self.base_mac_addr, self.ip_addr))
                    return
                except:
                    pass
        if is_ping_able:
            raise Exception("Unable to connect to the ping-able AP [%s %s]" % \
                            (self.base_mac_addr, self.ip_addr))

        msg = "Unable to ping the AP [%s %s] after rebooting %s seconds" % \
            (self.base_mac_addr, self.ip_addr, timeout)

        raise Exception(msg)


    def set_ssid(self, wlan_if, ssid):
        res = self.cmd("set ssid %s %s" % (wlan_if, ssid))[-1]
        if res.lower() != "ok":
            wlan_name = self.wlan_if_to_name(wlan_if)
            self.cmd("set ssid %s %s" % (wlan_name, ssid))



    def get_bssid_by_ssid(self, ssid):
        wlan_if = self.ssid_to_wlan_if(ssid)
        for x in self.get_wlan_list():
            if x[3] == wlan_if:
                return x[-1]
        return ''

    def enable_wlan(self, wlan_if):
        res = self.cmd("set state %s up" % (wlan_if))

    def disable_wlan(self, wlan_if):
        res = self.cmd("set state %s down" % (wlan_if))


    def get_wlan_list(self):
        """
        DO NOT use this method. Use get_wlan_info_dict instead.
        return list version of 'get wlanlist' cli command
        """
        # only interested in the lines with MAC Address in it.
        return [x.split() for x in self.cmd("get wlanlist")if re.search('([0-9a-fA-F:]{17})', x)]


    def ssid_to_wlan_if(self, ssid):
        for (wlan_id, wlan) in self.get_wlan_info_dict().iteritems():
            if wlan['name'] in INTERNAL_WLAN['name'] or \
            wlan['type'] in INTERNAL_WLAN['type']:
                continue

            #Behavior change start from 9.5
            if wlan['bssid'] == '00:00:00:00:00:00':
                continue

            _ssid = self.get_ssid(wlan_id)

            logging.debug("ssid of %s is %s" % (wlan_id, _ssid))
            if _ssid == ssid:
                return wlan['wlanID']


    def get_wlan_info_dict(self):
        '''
        Get all info from cmd 'get wlanlist'
        '''
        result = {}
        list_info = []
        for x in self.cmd("get wlanlist"):
            if re.search('bssid',x):
                list_info = x.split()

            if re.search('([0-9a-fA-F:]{17})',x):
                # result of list_value : ['svcp', 'up', 'AP', 'wlan0', '00:1F:41:24:6E:B8']
                list_value = x.split()
                temp = {}
                for i in range(len(list_info)):
                    temp[list_info[i]] = list_value[i]

                result[list_value[3]] = temp
        return result


    def get_wlan_list_with_ssid(self):
        '''
        Get all info from cmd 'get wlanlist'
        '''
        result = []
        list_info = []
        for x in self.cmd("get wlanlist"):
            if re.search('bssid',x):
                list_info = x.split()
                list_info.append('ssid')

            if re.search('([0-9a-fA-F:]{17})',x):
                # result of list_value : ['svcp', 'up', 'AP', 'wlan0', '00:1F:41:24:6E:B8', 'ssid']
                list_value = x.split()
                list_value.append( self.get_ssid(list_value[3]))
                temp = {}
                for i in range(len(list_info)):
                    temp[list_info[i]] = list_value[i]

                result.append(temp)
        return result


    def get_ssid(self, wlan_if):
        res = self.cmd("get ssid %s" % wlan_if)
        if res[-1].lower() != "ok":
            wlan_if_name = self.wlan_if_to_name(wlan_if)
            res = self.cmd("get ssid %s" % wlan_if_name)

        return res[0].split(':')[-1].strip(' ')
#        return res[0].split(' ')[-1]


    def wlan_if_to_name(self, wlan_if):
        """return the internal AP wlan name (e.g. 'svcp') given a wlan_if (wlanXX)  name
        """
        for (wlan_id, wlan) in self.get_wlan_info_dict().iteritems():
            # verify each line in 'get wlanlist' has column wlanID
            if wlan['wlanID'] and wlan['wlanID'] == wlan_if:
                return wlan['name']

        raise Exception("Convert wlan interface %s to name failed. Wlan interface not found in 'get wlanlist' "
                        % wlan_if)


    def get_scg_controller_ip(self):
        res = self.cmd('get sshtunnel', return_list=False)
        mobj = re.search('SSH tunnel connected to (\d+\.\d+\.\d+\.\d+)', res)
        return (None if mobj is None else mobj.group(1))


    def get_scg_data_plane_ip(self):
        res = self.cmd('get tunnelmgr', return_list=False)
        m = re.search('Current connected SCG-D:\s*(?P<ip>\d+\.\d+\.\d+\.\d+)\r', res)
        return (None if not m else m.group(1))


    def get_scg_state(self):
        '''
        # Get SCG state.
        '''

        for line in self.cmd('get scg'):
            mobj = re.search("State:[\s]+(.+)", line)
            if mobj:
                return mobj.group(1)

        raise Exception("Fail to get correct info in finding SCG state")


    def get_scg_server_list(self):
        '''
        # Get SCG server list.
        '''

        for line in self.cmd('get scg'):
            mobj = re.search("Server List:[\s]+(.+)", line)
            if mobj:
                res = mobj.group(1)
                return None if re.search("reset", res) else res

        raise Exception("Fail to find SCG server list")


    def get_scg_failover_list(self):
        '''
        # Get SCG failover list.
        '''

        for line in self.cmd('get scg'):
            mobj = re.search("Failover List:[\s]+(.+)", line)
            if mobj:
                res = mobj.group(1)
                if re.search("Not found", res):
                    return None
                else:
                    return re.split(';', res)

        raise Exception("Fail to find SCG failover list")


    def get_scg_interval(self):
        res = self.cmd('get scg', return_list = False)
        mobj = re.search('intervals:\s+(\d+)\|(\d+)\|(\d+)\|(\d+)', res)
        if not mobj:
            raise Exception("Fail to find SCG interval")

        scg_interval_cfg = {
            'config': mobj.group(1),
            'heartbeat': mobj.group(2),
            'mesh status': mobj.group(3),
            'status': mobj.group(4),
        }
        return scg_interval_cfg


    def get_config_interval(self):
        scg_interval_cfg = self.get_scg_interval()
        return scg_interval_cfg['config']


    def get_heartbeat_interval(self):
        scg_interval_cfg = self.get_scg_interval()
        return scg_interval_cfg['heartbeat']


    def get_mesh_status_interval(self):
        scg_interval_cfg = self.get_scg_interval()
        return scg_interval_cfg['mesh status']


    def get_status_interval(self):
        scg_interval_cfg = self.get_scg_interval()
        return scg_interval_cfg['status']

    def set_sshtunnel_disable(self):
        self.cmd('set sshtunnel disable')

    def set_sshtunnel_enable(self):
        self.cmd('set sshtunnel enable')

    def set_scg_disable(self):
        self.cmd('set scg ip reset')
        self.cmd('set scg disable')


    def set_scg_enable(self, scg_ipaddr=None):
        msg = 'SCG IP: %s' % scg_ipaddr
        if scg_ipaddr:
            msg = self.cmd('set scg ip %s'% scg_ipaddr)
            print(CM_NAME, "_set_scg_enable", msg)

        self.cmd('set scg enable')
      

    def set_scg_interval(self, interval=30):
        self.cmd('set scg heartbeat interval %d' % interval)
        self.cmd('set scg config interval %d' % interval)
        self.cmd('set scg status interval %d' % interval)

    def set_cm_led_mode(self, led_mode=1):
        msg = "Set led mode: %d done.." % led_mode
        res = self.cmd('set cm led-mode %d' % led_mode, return_list = False)
        if "OK" in res:
            print(CM_NAME, "set_cm_led_mode", msg )
        else:
            XLogger.error(CM_NAME, 'set_cm_led_mode', "Can not set cm led-mode to %d" % led_mode)
            raise Exception("Can not set cm led-mode to %d" % led_mode)
        

    def set_rpmkey(self, key, value):
        self.cmd('set rpmkey %s %s'% (key, value))


    def get_rpmkey(self, key):
        value = None
        ret_array = self.cmd('get rpmkey %s'% key)
        msg = 'key: %s len:(%d)'% (ret_array, len(ret_array))
        print(CM_NAME, 'check_reboot_reason', msg)

        if len(ret_array) > 0:
            ret = ret_array[0]
            if '=' in ret:
                value = re.split('\s+=\s+', ret)[1]

        return value


    def check_reboot_reason(self, reason='AP lost gateway more than'):
        result = []
        ret = False

        self.goto_shell()

        reboot_reason = self.cmd("cat /writable/etc/system/reboot_reason", prompt = "#")
        line = reboot_reason[-1]

        msg = 'reason[%s]'% line
        print(CM_NAME, 'check_reboot_reason', msg)

        if (reason.lower() in line.lower()):
            self.cmd("cd /writable/etc/system/", prompt = "#")
            self.cmd("mv reboot_reason reboot_reason.old", prompt = "#")
            ret = True
        else:
            msg = 'Can\'t found string in reason file [%s]'% reason
            print(CM_NAME, 'check_reboot_reason', msg)
        
        self.exit_shell()

        return ret


    def get_tunnel_establishment(self):
        search_key = 'Tunnel Establishment'
        val = self.get_tunnelmgr_val( search_key)
        if val == 'Enabled':
            return True    

        if val is None:
            msg = 'no such attribute [%s]'% (search_key)
        else:
            msg = '%s: [%s] (expect: %s)'% (search_key, val, 'Enable')

        print(CM_NAME, 'get_tunnel_type', msg)
        return False



    def get_mtu(self, interface):
        value = None
        res = self.cmd('get mtu %s'% interface)
        msg = '%s mtu: [%s]'% (interface, res[0])
        print(CM_NAME, 'get_mtu', msg)
        tmpstr = res[0].replace(')','')
        if ':' in tmpstr:
            value = tmpstr.split(' ')[-1]

        return value
    
    def get_background_scanning_setting(self,wifi_if):
        '''
        wifi_if='wifi0'/'wifi1'
        return [background_scanning_enable,scanning_timer]
        (for example [0,20]means not enable,[1,20]means background scanning enabled and scanning timer is 20)
        '''
        cmd = 'rpm -a|grep background |grep %s'%wifi_if
        res = self.do_shell_cmd(cmd)
        return [res[0].split(':')[1],res[1].split(':')[1]]

    
    def get_wan_mtu_setting_status(self):
        '''
        return [anto_enable,mtu_size]
        '''
        cmd = 'rpm -a|grep mtu'
        res = self.do_shell_cmd(cmd)
        return [res[1].split(':')[1],res[0].split(':')[1]]
        #return [res[2].split(':')[1],res[1].split(':')[1],res[0].split(':')[1]]
    
    def get_radio_tx_power(self,radio):
        if radio not in [5, 2.4, '5', '2.4']:
            raise('wrong parameter radio:%s'%radio)
        self.goto_shell()
        buf = self.cmd("iwconfig", prompt = "#")
        self.exit_shell()
        radio_str='Frequency:%s'%radio
        for lineNum in range(len(buf)):
            if radio_str in buf[lineNum]:
                power=int(buf[lineNum].split()[4].split(':')[1])
                logging.info('power is %s'%power)
                break
        logging.info('radio %s power is %s'%(radio,power))
        return power
    
    def get_wifi_if_channel(self,wifi_if):
        res = self.do_cmd('get channel %s'%wifi_if)
        channel = res.split(':')[1].split('(')[0].strip()
        return channel


    def get_log(self, filter=None, type_code_only=True):
        result = []

        self.goto_shell()

        if type_code_only:
            cmd = 'logread | grep @@'
        else:
            cmd = 'logread'
            
        logs = self.cmd(cmd, prompt = "#")
        if filter is not None:
            for line in logs:
                if filter in line:
                    result.append(line)

            result.reverse()
        else:
            result = logs

        msg = 'log [%s]'% result
        print(CM_NAME, 'get_log', msg)
        
        self.exit_shell()

        return result


    def get_shaper(self, ssid, debug = False):
        """ Return the ratelimiting information of a give wlan_if
        @param ssie: ssid of the WLAN
        @param debug: True:
                      False:
        @return: a dictionary of ratelimitng information"""
        if debug:
            pdb.set_trace()
        wlan_if = ""
        try:
            wlan_if = self.ssid_to_wlan_if(ssid)
        except Exception, e:
            msg = "Exception on ssid_to_wlan_if(%s): %s" % (ssid, e.message)
            print(CM_NAME, 'get_shaper', msg)
            raise Exception(msg)
        shaper = {'down': None , 'up': None}
        
        #downstream ratelimiting
        #EGRESS    to WLAN: (   100 kbps shared per station)
        dn_ptn = r"EGRESS\s+to\s+WLAN:\s+\(\s+(\d+)\s+(.bps)\s+shared\s+per\s+station\)"
        
        #upstream ratelimiting
        #INGRESS from WLAN: (   100 kbps shared per station)
        up_ptn = r"INGRESS\s+from\s+WLAN:\s+\(\s+(\d+)\s+(.bps)\s+shared\s+per\s+station\)"
        
        #disable ratelimiting
        #"Traffic Shaping Config for 'wlan32':  DISABLED"
        disabled_ptn = r"Traffic\s+Shaping\s+Config\s+for\s+'wlan\d+':\s+DISABLED"
        for line in self.cmd("get shaper %s" % wlan_if):
            m1 = re.match(dn_ptn, line, re.I)
            m2 = re.match(up_ptn, line, re.I)
            m3 = re.match(disabled_ptn, line, re.I)
            if m3:
                shaper = {'down': 'disabled' , 'up': 'disabled'}
            else:
                if m1:
                    shaper['down'] = m1.group(1) + m1.group(2)
                if m2:
                    shaper['up'] = m2.group(1) + m2.group(2)

        return shaper


    def check_ap_status(self, state, retries=10):
        '''
        # Check AP status in AP 
        '''

# Sometimes, it fail to find the 'State' field, re-try for more times
        while True:
            retries -= 1
            try:
                ret = self.get_scg_state()
                break
            except Exception:
                if not retries:
                    raise
                time.sleep(1)

        return True if ret == state else False



    def get_tunnelmgr(self):
        res = self.cmd('get tunnelmgr', return_list = True)
        tunnel_cfg = {}
        for line in res:
            if '--' not in line:
                data = line.split(':')
                if len(data) > 1:
                    tunnel_cfg.update( { data[0].strip(): data[1].strip() })

        return tunnel_cfg


    def get_tunnelmgr_val(self, attr):
        tunnel_cfg = self.get_tunnelmgr()

        return tunnel_cfg.get(attr, None)


    """ Given lines as below:
        ['------- Smart Monitor Configration -------',
         'Smart Montior      : Enabled',
         'Interval           : 5',
         'Threshold          : 3',
         '------- Smart Monitor Stats -------',
         'Check Msg Sent Cnt : 13788',
         'Check Msg Lost Cnt : 60',
         'Total WLAN Off Cnt : 1',
         'Last Uplink Lost Time    : Feb 26 02:26:05 2014',
         'Last Uplink Recover Time : Feb 26 02:31:49 2014',
         'OK']

    Will return dictionary:
        {'Check Msg Lost Cnt': '60',
         'Check Msg Sent Cnt': '13788',
         'Interval': '5',
         'Last Uplink Lost Time': 'Feb 26 02:26:05 2014',
         'Last Uplink Recover Time': 'Feb 26 02:31:49 2014',
         'Smart Montior': 'Enabled',
         'Threshold': '3',
         'Total WLAN Off Cnt': '1'}
    """
    def __parse_cmd_return_lines(self, lines):
        res = dict()
        for l in lines:
            m = re.match('(?P<key>[^:]*):(?P<value>.*)', l)
            if m:
                k, v = m.groups()
                res.update({k.strip(): v.strip()})
        return res


    """ Get smart monitor configurations. """
    def get_smartmon(self):
        ret = self.cmd('get smart-mon')
        return self.__parse_cmd_return_lines(ret)


    """ Get the value of smart monitor configurations. """
    def get_smartmon_val(self, key):
        mon_cfg = self.get_smartmon()
        return mon_cfg.get(key, None)


    def enable_smartmon(self):
        self.cmd('set smart-mon enable')


    def disable_smartmon(self):
        self.cmd('set smart-mon disable')


    def check_tunnel_type(self, type_name):
        search_key = 'Tunnel Type'
        val = self.get_tunnelmgr_val(search_key)
        if val == type_name:
            return True    

        if val is None:
            msg = 'no such attribute [%s]'% (search_key)
        else:
            msg = '%s: [%s] (expect: %s)'% (search_key, val, type_name)

        print(CM_NAME, 'check_tunnel_type', msg)
        return False


    def check_tunnel_session_connected(self):
        search_key = 'Current Session UpTime'
        val = self.get_tunnelmgr_val(search_key)
        if val != 'N/A':
            return True    

        if val is None:
            msg = 'no such attribute [%s]'% (search_key)
        else:
            msg = '%s: [%s] (expect: %s)'% (search_key, val, 'N/A')

        print(CM_NAME, 'check_tunnel_session_connected', msg)
        return False

    def check_tunnel_session_gateway(self, gateway):
        search_key = 'Current connected Remote Server'
        val = self.get_tunnelmgr_val(search_key)
        if val == gateway:
            return True    

        if val is None:
            msg = 'no such attribute [%s]'% (search_key)
        else:
            msg = '%s: [%s] (expect: %s)'% (search_key, val, gateway)

        print(CM_NAME, 'check_tunnel_session_gateway', msg)
        return False


    def block_ip_traffic(self, ip):
        self.do_shell_cmd('iptables -A INPUT -s %s -j DROP'% ip)

        ret = self.do_shell_cmd('iptables --list')
        for line in ret:
            m_ip = re.search(ip, line)
            m_act = re.search('DROP', line)
            if m_ip and m_act:
                print(CM_NAME, 'block_ip_traffic: %s', line)
                return True

        raise Exception("Add block entry to iptable fail: %s" % ip)


    def unblock_ip_traffic(self, ip):
        # Remove same entries in iptable to avoid check fail in `iptables --list`
        while True:
            unblock_ret = self.do_shell_cmd('iptables -D INPUT -s %s -j DROP' % ip)
            if len(unblock_ret):
                # No this entry in iptable
                break

        ret = self.do_shell_cmd('iptables --list')
        for line in ret:
            m_ip = re.search(ip, line)
            m_act = re.search('DROP', line)
            if m_ip and m_act:
                raise Exception("Remove block entry to iptable fail: %s" % ip)

        return True
    
    def get_bssid_from_ssid(self,ssid):
        res={'ng':'',
             'na':''}
        info = self.get_wlaninfo()
        for wlan in info:
            if info[wlan]['SSID']==ssid:
                if int(info[wlan]['Channel'])>20:
                    res['na']=info[wlan]['BSSID']
                if int(info[wlan]['Channel'])<20:
                    res['ng']=info[wlan]['BSSID']
        return res

    def get_access_key(self):
        if len(self.ap_serial):
            if len(self.access_key) == 0: 
                try:
                    url = 'http://172.16.14.252/fq.asp?f=shell_key&vendor=ruckus&serial=%s'% self.ap_serial
                    r = requests.get(url)
                    self.access_key = str(r.text.strip('\n').split(' ')[-1])
                except Exception:
                    print(CM_NAME, 'get_passcode', 'Retrieve access key fail! Please check the url: [%s]'% url )
        else:
            print(CM_NAME, 'get_passcode', 'No ap_serial: %s'% self.ap_serial )

        print(CM_NAME, 'get_passcode', 'Get access_key: %s'% self.access_key )
                        




