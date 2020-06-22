from qattg.coreapi.common.ScgJsonLogin import ScgJsonLogin
from qa.ttgcommon.coreapi.common import json_interface as ji
import RuckusAP as RAP
from qa.ttgcommon.coreapi.common import SshClient as ssh_client
import time
import re
class Roaming_Utils():
    def __init__(self, scg_mgmt_ip='', scg_port=''):

        self.scg_mgmt_ip = scg_mgmt_ip
        self.scg_port = scg_port
        self.jsessionid = ''

    def get_jsessionid(self):
        return self.jsessionid

    def set_jsessionid(self, jsessionid):
        self.jsessionid = jsessionid

    def _login(self, username = 'admin', password = 'ruckus'):
        l = ScgJsonLogin()

        result, self.jsessionid = l.login(scg_mgmt_ip=self.scg_mgmt_ip, scg_port=self.scg_port,
                username=username, password=password)
        return result

    def set_roaming_params(self, ap_ip='192.168.0.1', 
                                    ap_user='super',
                                    ap_pwd='sp-admin',
                                    ap_staging_zone_username='super',
                                    ap_staging_zone_password='sp-admin'):

        self.ap_ip=ap_ip
        self.ap_user=ap_user
        self.ap_pwd=ap_pwd
        self.ap_staging_zone_username=ap_staging_zone_username
        self.ap_staging_zone_password=ap_staging_zone_password

        self.rck_ap_obj = RAP.RuckusAP(ip_addr=self.ap_ip,
                        username = self.ap_user,
                        password = self.ap_pwd,
                        ap_staging_zone_username = self.ap_staging_zone_username,
                        ap_staging_zone_password = self.ap_staging_zone_password)


    def current_ap_dblade_reboot(self):

        ap_tunnel = self._get_ap_gre_tunnel(ap_ip=self.ap_ip, ap_pwd=self.ap_pwd, ap_user=self.ap_user)
        current_d = ap_tunnel["current_d"]
        cluster_d_info = {}
        cluster_d_info = self._get_cluster_d_staus()

        for i in range(0, len(cluster_d_info[u"data"][u"list"])):
            if cluster_d_info[u"data"][u"list"][i][u"ip"] == current_d:
                self._set_ap_k_interval(ap_ip=self.ap_ip, 
                                        ap_user=self.ap_user,
                                        ap_pwd=self.ap_pwd,
                                        kinterval='2')
                self._set_ap_k_limit(ap_ip=self.ap_ip, ap_user=self.ap_user, ap_pwd=self.ap_pwd, klimit='1')
                reboot_api = "/wsg/api/scg/planes/data/" + cluster_d_info[u"data"][u"list"][i][u"key"] + "/reboot"
                url = ji.get_url(reboot_api, self.scg_mgmt_ip, self.scg_port)
                data = None
                res_put = ji.put_json_data(url, self.jsessionid, data, login=False)
                if not res_put:
                    print "current_ap_dblade_reboot(): Failed Data PUT method"

                self._set_ap_gre_tunnel_disable(ap_ip=self.ap_ip, ap_user=self.ap_user, ap_pwd=self.ap_pwd)
                self._set_ap_gre_tunnel_enable(ap_ip=self.ap_ip, ap_user=self.ap_user, ap_pwd=self.ap_pwd)
                ap_tunnel = self._get_ap_gre_tunnel(ap_ip=self.ap_ip, ap_user=self.ap_user, ap_pwd=self.ap_pwd)

                count = 0
                while ap_tunnel['current_d'] == current_d:
                    count = count+1
                    ap_tunnel = self._get_ap_gre_tunnel(ap_ip=self.ap_ip, ap_user=self.ap_user, ap_pwd=self.ap_pwd)
                    time.sleep(1)
                    if count > 40:
                        break
                
                #self._set_ap_k_interval(ap_ip=self.ap_ip, ap_user=self.ap_user, ap_pwd=self.ap_pwd, kinterval='10')
                #self._set_ap_k_limit(ap_ip=self.ap_ip, ap_user=self.ap_user, ap_pwd=self.ap_pwd, klimit='6')
                #print ap_tunnel["current_d"]
                
    def _set_ap_k_interval(self, ap_ip='127.0.0.1', ap_user='admin', ap_pwd='ruckus2!', kinterval='2'):

            self.tunnel_details = {}
            cmmd = 'set tunnelmgr kinterval ' + kinterval
            res = self.rck_ap_obj.cmd(cmmd, return_list = True)
            if res[0] != 'OK' :
                print "_set_ap_k_interval(): fail"
    
    def reboot_ap(self):

            self.tunnel_details = {}
            cmmd = 'reboot'
            res = self.rck_ap_obj.cmd(cmmd)
            if res[0] != 'OK' :
                print "reboot ap(): fail" 
   
    def _cblade_reboot(self,username="admin",password="ruckus1!",cblade_ip='10.1.35.2',prompt='Daytona'):
        self.login_type = 'interactive'
        self.prompt = r"root\S*#\s*"
        self.ssh_trgt_ip = cblade_ip
        #print self.ssh_trgt_ip
        print(self.__module__, "cblade_reboot", " %s will be rebooted" % self.ssh_trgt_ip)
        self.ssh_username = username
        self.ssh_passwd = password
        #self.scg_prompt = r"Daytona>\s*"
        self.scg_prompt = 'r\"' + prompt + '>\\s*\"'
        #self.scg_en_prompt = r"Daytona#\s*"
        self.scg_en_prompt = 'r\"' + prompt + '#\\s*\"'
        self.shell_expect_cmd_list=[[self.scg_prompt, "en", 15.0],[r"Password:\s*",self.ssh_passwd, 15.0],[self.scg_en_prompt, "reload now", 5.0],[r"Do you want to gracefully reboot system immediately\s*", "yes", 5.0],["Server would be rebooted in 0 seconds", None, 5.0]]

        self.clnt = ssh_client.SshClient()
        if not self.clnt.ssh_connect(server=self.ssh_trgt_ip, username=self.ssh_username,
                password=self.ssh_passwd, login_type=self.login_type, shell_prompt=self.scg_en_prompt,
                expect_cmd_list=self.shell_expect_cmd_list):
            print(self.__module__, "leader_cblade_reboot", "ssh_connection failed for server %s" % self.ssh_trgt_ip)
            return False
        cmd = "/etc/init.d/reboot stop"
        expected = None
        result = self.clnt.remote_exec_command(cmd + "\n",expected=expected)
        self.clnt.ssh_close()
        return result         
        
    def stop_dblade_through_cblade(self,username="admin",password="ruckus1!",cblade_ip='10.1.35.2',prompt='Daytona',dblade_no='0'):
        self.login_type = 'interactive'
        self.ssh_trgt_ip = cblade_ip
        print(self.__module__, "stop_dblade_through_cblade", " %s will be stopped" % dblade_no)
        self.ssh_username = username
        self.ssh_passwd = password
        self.scg_prompt = prompt + '>'
        self.scg_en_prompt = prompt + '#'
        #self.scg_en_prompt = 'r\"' + prompt + '#\\s*\"'
        self.shell_expect_cmd_list=[[self.scg_prompt, "en", 15.0],[r"Password:\s*",self.ssh_passwd, 15.0],[self.scg_en_prompt, "!v54!", 10.0],
                [r"Execute wsgcli to login CLI!", "sudo bash", 5.0],["\Sroot\S\w*\s*admin\S#", "oct.linux stop %s " % dblade_no, 15.0], ["\Sroot\S\w*\s*admin\S#", None, 15.0]]

        self.clnt = ssh_client.SshClient()
        if not self.clnt.ssh_connect(server=self.ssh_trgt_ip, username=self.ssh_username,
                password=self.ssh_passwd, login_type=self.login_type, shell_prompt=self.scg_en_prompt,
                expect_cmd_list=self.shell_expect_cmd_list):
            print(self.__module__, "stop_dblade_through_cblade", "ssh_connection failed for server %s" % self.ssh_trgt_ip)
            self.clnt.ssh_close()
            return False

        self.clnt.ssh_close()

        return True

    def start_dblade_through_cblade(self,username="admin",password="ruckus1!",cblade_ip='10.1.35.2',prompt='Daytona',dblade_no='0'):

        self.login_type = 'interactive'
        self.ssh_trgt_ip = cblade_ip
        print(self.__module__, "stop_dblade_through_cblade", " %s will be stopped" % dblade_no)
        self.ssh_username = username
        self.ssh_passwd = password
        self.scg_prompt = prompt + '>'
        self.scg_en_prompt = prompt + '#'
        self.shell_expect_cmd_list=[[self.scg_prompt, "en", 15.0],[r"Password:\s*",self.ssh_passwd, 15.0],[self.scg_en_prompt, "!v54!", 10.0],
                [r"Execute wsgcli to login CLI!", "sudo bash", 5.0],["\Sroot\S\w*\s*admin\S#", "oct.linux start %s" % dblade_no, 15.0], ["\Sroot\S\w*\s*admin\S#", None, 15.0]]

        self.clnt = ssh_client.SshClient()
        if not self.clnt.ssh_connect(server=self.ssh_trgt_ip, username=self.ssh_username,
                password=self.ssh_passwd, login_type=self.login_type, shell_prompt=self.scg_en_prompt,
                expect_cmd_list=self.shell_expect_cmd_list):
            print(self.__module__, "stop_dblade_through_cblade", "ssh_connection failed for server %s" % self.ssh_trgt_ip)
            self.clnt.ssh_close()
            return False

        self.clnt.ssh_close()

        return True

    def _set_ap_k_limit(self, ap_ip='127.0.0.1',ap_user='admin',ap_pwd='ruckus2!', klimit='1'):

            self.tunnel_details = {}
            #print ap_telnet.get_tunnel_type(retry=3)
            cmmd = 'set tunnelmgr kretrylimit ' + klimit
            res = self.rck_ap_obj.cmd(cmmd, return_list = True)
            if res[0] != 'OK' :
                print "_set_ap_k_limit(): fail"

    def _get_cluster_d_staus(self):
            cluster_stat_api = "/wsg/api/scg/planes/data?"
            cluster_stat_url = ji.get_url(cluster_stat_api, self.scg_mgmt_ip, self.scg_port)
            print cluster_stat_url
            cluster_stat_data = ji.get_json_data(cluster_stat_url, self.jsessionid)
            return cluster_stat_data
        
    def _set_ap_gre_tunnel_disable(self, ap_ip='127.0.0.1',ap_user='admin',ap_pwd='ruckus2!'):
            self.tunnel_details = {}
            #print ap_telnet.get_tunnel_type(retry=3)
            cmmd = 'set tunnelmgr disable'
            res = self.rck_ap_obj.cmd(cmmd, return_list = True)
            if res[0] != 'OK' :
                print (self.__module__, '_set_ap_gre_tunnel_disable', '_set_ap_gre_tunnel_disable failed %s' % cmmd )
                return False
            return True
        
    def _set_ap_gre_tunnel_enable(self, ap_ip='127.0.0.1',ap_user='admin',ap_pwd='ruckus2!'):

            #print ap_ip
            self.tunnel_details = {}
            cmmd = 'set tunnelmgr enable'
            res = self.rck_ap_obj.cmd(cmmd, return_list = True)
            if res[0] != 'OK' :
                print (self.__module__, '_set_ap_gre_tunnel_enable', '_set_ap_gre_tunnel_enable failed %s' % cmmd )
                return False
            return True

    def _get_ap_gre_tunnel(self, ap_ip='127.0.0.1', ap_user='admin', ap_pwd='ruckus2!'):

            self.tunnel_details = {}
            self.tunnel_details["ap_ip"]=self.ap_ip
            #print ap_telnet.get_tunnel_type(retry=3)
            res = self.rck_ap_obj.cmd('get tunnelmgr', return_list = True)
            #print res
            for line in res:
                #print line
                if 'SCG-D IP List' in line:
                    ll = line.split()
                    #print ll
                    size_t = len(ll)
                    #print size_t
                    size_t = size_t - 1 
                    #print ll[size_t]
                    d_ip_list = ll[size_t].split(",")
                    #print d_ip_list
                    self.tunnel_details["iplist"] = d_ip_list
                    
                if 'Current connected SCG-D' in line:
                    ll = line.split()
                    size_t = len(ll)
                    #print size_t
                    size_t = size_t -1
                    #print ll[size_t] 
                    #return ll[size_t]
                    self.tunnel_details["current_d"] = ll[size_t]
                            
                if 'status ACTIVE' in line:
                    #print "\n Gre tunnel up \n"   
                    self.tunnel_details["status"] = 'up'
                    
                if 'Keep Alive Interval/Limit:' in line:
                    ll = line.split()
                    size_t = len(ll)
                    #print size_t
                    size_t = size_t -1
                    #print ll[size_t] 
                    self.tunnel_details["keep_alive"] = ll[size_t]
            #print (self.__module__, 'get_ap_current_tunnel', self.tunnel_details)
            return self.tunnel_details                
        
    def configure_ap_tunnel_to_dblade(self, dblade='127.0.0.2', reset=False):
            self._set_ap_k_limit(ap_ip=self.ap_ip, ap_user=self.ap_user, ap_pwd=self.ap_pwd, klimit='1')
            self._set_ap_k_interval(ap_ip=self.ap_ip, ap_user=self.ap_user, ap_pwd=self.ap_pwd, kinterval='1')
            self.rck_ap_obj.do_cmd('set tunnelmgr iplist =1@%s' % dblade)
            print (self.__module__,'configure_ap_tunnel_to_dblade', 'set tunnelmgr iplist %s' % dblade)
            time.sleep(5)
            self.rck_ap_obj.do_cmd('set tunnelmgr disable')
            time.sleep(5)
            print (self.__module__,'disable tunnel manager service','set tunnelmgr disable')
            self.rck_ap_obj.do_cmd('set tunnelmgr enable')
            time.sleep(5)
            print (self.__module__,'enable tunnel manager service','set tunnelmgr enable')
            #print (self.__module__,'configure_ap_tunnel_to_dblade', "Lets Wait 60 Seconds for AP to reconfigure after disable and enable")
            time.sleep(10)
            if not reset:
                if self.get_ap_to_dblade_tunnel_status(dblade=dblade):
                    print ">returning true"
                    return True
                else:
                    print ">>returning false"
                    return False
            else:
                print ">>>returning true"
                return True

    def set_pmk_enable_disable(self, wlan_name='scg_pmip-R2', isEnable=False):
        wlan_text = self.get_wlan_radio_using_wlan_name(wlan_name=wlan_name)
        if isEnable:
            print "executing AP command : %s" %str('set pmk %s enable' %wlan_text)
            self.rck_ap_obj.do_cmd('set pmk %s enable' %wlan_text)
        else:
            print "executing AP command : %s" %str('set pmk %s disable' %wlan_text)
            self.rck_ap_obj.do_cmd('set pmk %s disable' %wlan_text)
        return True    

    def set_okc_enable_disable(self, wlan_name='scg_pmip-R2', isEnable=False):
        wlan_text = self.get_wlan_radio_using_wlan_name(wlan_name=wlan_name)
        if isEnable:
            print "executing AP command : %s" %str('set okc %s enable' %wlan_text)
            self.rck_ap_obj.do_cmd('set okc %s enable' %wlan_text)
        else:
            print "executing AP command : %s" %str('set okc %s disable' %wlan_text)
            self.rck_ap_obj.do_cmd('set okc %s disable' %wlan_text) 
        return True
    
    def get_wlan_radio_using_wlan_name(self,wlan_name):
        wlan_found = False
        wlan_name = ""
        for i in range(0,16):
            wlan_text = "wlan"+str(i)
            res = self.rck_ap_obj.cmd('get wlantext %s' %wlan_text, return_list = False)
            result_list = res.split('\r\n')
            for line in result_list:
                wlan_found = re.search(wlan_name, line)
                if wlan_found:
                    print "wlan %s found" %(wlan_name)
                    break
            if wlan_found:
                break 
        return  wlan_text

    def set_latitude_longitude(self, latitude=None, longitude=None):
        if latitude and longitude:
            print "executing AP command : %s" %str('set device-gps %s,%s' %(latitude,longitude))
            self.rck_ap_obj.do_cmd('set device-gps %s,%s' %(latitude,longitude))
        return True  
            
    def free_dblade_ip(self, dblade_list=[]):
        ap_tunnel = self._get_ap_gre_tunnel(ap_ip=self.ap_ip, ap_pwd=self.ap_pwd, ap_user=self.ap_user)
        current_d = ap_tunnel["current_d"]
        free_dblade = None
        if len(dblade_list)> 0:
            if dblade_list[0] == current_d:
                free_dblade = dblade_list[1]
            elif dblade_list[1] == current_d:
                free_dblade = dblade_list[0]

            else:
                print "free_dblade_ip(): dblade ip list is empty"
        else:
            print "free_dblade_ip(): dblade ip list is empty"

        return free_dblade
          
    def get_ap_to_dblade_tunnel_status(self, dblade='', status='Enabled'):
            estd=False
            cont=False
            count=0
            while(count<61):
                res = self.rck_ap_obj.cmd('get tunnelmgr', return_list = False)
                #print (self.__module__,'get_ap_to_dblade_tunnel_status', res)
                regx_estd = "Tunnel Establishment:\s*%s" % status
                regx_cont = "Current connected SCG-D:\s*%s" % dblade
                get_regx_cont = "Current connected SCG-D:\s*(\d[0-3]{0,3}\S\d[0-5]{0,3}\S\d[0-5]{0,3}\S\d[0-5]{0,3})"
                kw_list = res.split('\r\n')

                for line in kw_list:
                    print (self.__module__,'get_ap_to_dblade_tunnel_status', line)
                    m_estd = re.search(regx_estd, line)
                    m_cont = re.search(regx_cont, line)
                    get_m_cont = re.search(get_regx_cont, line)
                    if m_estd:
                        print (self.__module__,'get_ap_to_dblade_tunnel_status', "Matched Tunnel Establishment")
                        estd=True
                    if get_m_cont:
                        print (self.__module__,'get_ap_to_dblade_tunnel_status', get_m_cont.groups())
                        recvd_ip = get_m_cont.groups()
                        if recvd_ip[0] == dblade:
                            cont=True
                    #if m_cont and m_estd:
                        #print (self.__module__,'get_ap_to_dblade_tunnel_status', "Matched Current Connected SCG IP")
                        #cont=True
                if estd and cont:
                    count=61
                else:
                    count+=1
                    time.sleep(10)
                    
            if estd and cont:
                return True
            else:
                print "get_ap_to_dblade_tunnel_status(): timeout to get the status"
                return False

    def set_ap_scg_ip(self, scg_ip='10.1.35.3'):

        cmd = 'set scg ip ' + str(scg_ip)
        res = self.rck_ap_obj.cmd(cmd, return_list = True)
        time.sleep(2)
        res1 = self.rck_ap_obj.do_cmd('set sshtunnel disable')
        time.sleep(2)
        res2 = self.rck_ap_obj.do_cmd('set sshtunnel enable')
        time.sleep(2)
        if res[0] != 'OK':
            print (self.__module__, 'set_ap_scg_ip failed %s' % cmd )
            return False

        print "Sleep to get ssh tunnel established"
        time.sleep(90)
        return True

"""
a = Roaming_Utils(scg_mgmt_ip='172.19.16.189',
            scg_port='8443',)
a._login(username = 'admin', password = 'ruckus1!')
a.set_roaming_params(
            ap_ip='10.1.71.41',
            ap_user='admin',
            ap_pwd='ruckus1!',
            ap_staging_zone_username = 'Bheem',
            ap_staging_zone_password = 'Bheem')
#ip = a.free_dblade_ip(dblade_list=['10.1.171.41', '10.1.171.42'])
#a.current_ap_dblade_reboot()
#a.get_ap_to_dblade_tunnel_status(dblade=ip)
#a.configure_ap_tunnel_to_dblade(dblade=ip)
#a.get_ap_to_dblade_tunnel_status(dblade=ip)
#a.set_ap_scg_ip(scg_ip='10.1.171.2')
"""
