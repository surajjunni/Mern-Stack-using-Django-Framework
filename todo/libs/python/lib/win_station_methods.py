# Ruckus Highly Confidential Information, Copyright (C) 2014 Ruckus Wireless, Inc. All rights reserved.

r'''Module simple introduction

.. module:: win_station_methods

Win station methods is generated for python files use, anyone who want uses it as HTML library, please use "ap_qa_auto/resources/keywords/Windows_Basic_Keywords.html" as substitute.

:author: zingdai
:create: Jul 17, 2014
:update: Jul 21, 2014

'''
from robot.libraries.BuiltIn import BuiltIn
import time
import re
import sys
import logging
import common_methods as CM
import json
from qa.common import Ratutils as RU

#===============================================================================
# Private method
#===============================================================================
def __get_module_name():
    module_list = __file__.split('/')
    module_name = module_list[-1]
    s_module_name = module_name.split('.')[0]
    return s_module_name

#===============================================================================
# Constant
#===============================================================================
CODING_UTF8 = 'utf-8'
MODULE_NAME = __get_module_name()
BTN = BuiltIn()
sta_disconnct_log = "/tmp/station-assoc.log"

def wireless_station_associate_wlan(wlan_cfg, check_status_timeout = 90, retry = 3, apcli_context_name = ''):
    """
    Configure wireless station to associate WLAN. Please see
    RWWindowsTestAppliance.config_wlan to see the configuration detail.

    == Argument: ==
    - _wlan_cfg_ : A dictionary value of the configuration of WLAN profile
    - _check_status_timeout_: A integer value of associate WLAN idle timeout, default is 90 seconds.
    - _retry_: A integer value of retry if cannot get wireless station WiFi IP address, default is 3 times.

    == Return Value: ==
    - None

    == Example: ==
    | *Setting* | *Value*                                                          |
    | Resource  | R${RootTarget}/resources/keywords/qa/Windows_Basic_Keywords.html |
    
    | *Action*                          | *Argument*        | *Argument*   | *Argument* | *Argument*   |
    | ${cfg}=                           | Create Dictionary | ssid=rw-open | auth=OPEN  | encrypt=NONE |
    | _Wireless station associate WLAN_ | ${cfg}            |              |            |              |
    """
    function_name = sys._getframe().f_code.co_name
    BTN.log(message = "%s %s" %(MODULE_NAME, function_name), level = "DEBUG")
    wifi_station = CM.get_station_instance()
    ssid = wlan_cfg['ssid']
    result = "fail"
    tested_retry = retry
    try:
        apcli = CM.get_apcli_instance(context_name = apcli_context_name)
    except Exception:
        pass
    
    while(retry >= 0):
        try:
            start_time = time.time()
            wifi_station.config_wlan(wlan_cfg)
            wifi_station.connect_wlan(ssid)
            status = wifi_station.get_wlan_status()
            while(status != "connected"):
                time.sleep(3)
                current_time = time.time()
                status = wifi_station.get_wlan_status()
                if current_time - start_time > check_status_timeout:
                    if retry > 0:
                        break;
                    else:
                        raise Exception("After %s retry, WiFi station cannot connect SSID: %s within %s seconds" % (tested_retry, ssid, check_status_timeout))
                else:
                    continue
            
            if (status == "connected"):
                # wait 15 seconds for IP address
                for zz in RU.try_interval(15):
                    ipaddres = wifi_station.get_addresses()                        
                    ip = ipaddres["IP"]
                    ts_pattern = "((25[0-5])|(2[0-4]\d)|(1\d\d)|([1-9]\d)|\d)(\.((25[0-5])|(2[0-4]\d)|(1\d\d)|([1-9]\d)|\d)){3}"
                    res = re.search(ts_pattern, ip)
                    if res and res.group(0).find('169.254') != 0:
                        BTN.log(message = "%s %s" %(MODULE_NAME, function_name) + " get IP: %s" % res.group(0), level = "DEBUG")
                        result = "pass"
                        break
                            
            if result == "pass":
                break
            else:
                if retry >= 0:
                    retry -= 1
                                    
                if apcli:
                    wlan_list = apcli.get_wlan_list_with_ssid()
                    wlans = wifi_station.scan_wlans()
                    BTN.log(message = "%s %s" %(MODULE_NAME, function_name) + " failed in %s run, currently WLAN list in AP CLI: %s, scanned WLANs in station: %s" % (tested_retry - retry , json.dumps(wlan_list, indent = 1), json.dumps(wlans, indent = 1)), level = "INFO")
                    
                if retry < 0:
                    raise Exception( "After %s retry for failed, wireless station cannot associate AP" % (tested_retry))
                    break
                else:
                    remove_all_wlan_from_wireless_station(check_status_timeout = check_status_timeout, retry = retry)
                    continue
                    
        except Exception, ex:
            if retry >= 0:
                retry -= 1
            
            if apcli:
                wlan_list = apcli.get_wlan_list_with_ssid()
                wlans = wifi_station.scan_wlans()
                BTN.log(message = "%s %s" %(MODULE_NAME, function_name) + " failed in %s run, currently WLAN list in AP CLI: %s, scanned WLANs in station: %s" % (tested_retry - retry , json.dumps(wlan_list, indent = 1), json.dumps(wlans, indent = 1)), level = "INFO")
                
            if retry < 0:
                raise Exception( "After %s retry for failed in %s, exception:%s" % (tested_retry, function_name, ex.message))
                break
            else:
                remove_all_wlan_from_wireless_station(check_status_timeout = check_status_timeout, retry = retry)
                continue

def wireless_station_associate_recovery_ssid(wlan_cfg, check_status_timeout = 90, retry = 3, apcli_context_name = ''):
    """
    Configure wireless station to associate WLAN. Please see
    RWWindowsTestAppliance.config_wlan to see the configuration detail.

    == Argument: ==
    - _wlan_cfg_ : A dictionary value of the configuration of WLAN profile
    - _check_status_timeout_: A integer value of associate WLAN idle timeout, default is 90 seconds.
    - _retry_: A integer value of retry if cannot get wireless station WiFi IP address, default is 3 times.

    == Return Value: ==
    - None

    == Example: ==
    | *Setting* | *Value*                                                          |
    | Resource  | R${RootTarget}/resources/keywords/qa/Windows_Basic_Keywords.html |
    
    | *Action*                          | *Argument*        | *Argument*   | *Argument* | *Argument*   |
    | ${cfg}=                           | Create Dictionary | ssid=rw-open | auth=OPEN  | encrypt=NONE |
    | _Wireless station associate WLAN_ | ${cfg}            |              |            |              |
    """
    function_name = sys._getframe().f_code.co_name
    BTN.log(message = "%s %s" %(MODULE_NAME, function_name), level = "DEBUG")
    wifi_station = CM.get_station_instance()
    ssid = wlan_cfg['ssid']
    result = "fail"
    tested_retry = retry
    try:
        apcli = CM.get_apcli_instance(context_name = apcli_context_name)
    except Exception:
        pass
    
    while(retry >= 0):
        try:
            start_time = time.time()
            wifi_station.config_wlan(wlan_cfg)
            wifi_station.connect_wlan(ssid)
            status = wifi_station.get_wlan_status()
            while(status != "connected"):
                time.sleep(3)
                current_time = time.time()
                status = wifi_station.get_wlan_status()
                if current_time - start_time > check_status_timeout:
                    if retry > 0:
                        break;
                    else:
                        raise Exception("After %s retry, WiFi station cannot connect SSID: %s within %s seconds" % (tested_retry, ssid, check_status_timeout))
                else:
                    continue
            
            if (status == "connected"):
                BTN.log(message = "%s %s" %(MODULE_NAME, function_name) + "recovery ssid connected")
                break
            else:
                if retry >= 0:
                    retry -= 1
                                    
                if apcli:
                    wlan_list = apcli.get_wlan_list_with_ssid()
                    wlans = wifi_station.scan_wlans()
                    BTN.log(message = "%s %s" %(MODULE_NAME, function_name) + " failed in %s run, currently WLAN list in AP CLI: %s, scanned WLANs in station: %s" % (tested_retry - retry , json.dumps(wlan_list, indent = 1), json.dumps(wlans, indent = 1)), level = "INFO")
                    
                if retry < 0:
                    raise Exception( "After %s retry for failed, wireless station cannot associate AP" % (tested_retry))
                    break
                else:
                    remove_all_wlan_from_wireless_station(check_status_timeout = check_status_timeout, retry = retry)
                    continue
                    
        except Exception, ex:
            if retry >= 0:
                retry -= 1
            
            if apcli:
                wlan_list = apcli.get_wlan_list_with_ssid()
                wlans = wifi_station.scan_wlans()
                BTN.log(message = "%s %s" %(MODULE_NAME, function_name) + " failed in %s run, currently WLAN list in AP CLI: %s, scanned WLANs in station: %s" % (tested_retry - retry , json.dumps(wlan_list, indent = 1), json.dumps(wlans, indent = 1)), level = "INFO")
                
            if retry < 0:
                raise Exception( "After %s retry for failed in %s, exception:%s" % (tested_retry, function_name, ex.message))
                break
            else:
                remove_all_wlan_from_wireless_station(check_status_timeout = check_status_timeout, retry = retry)
                continue

def wireless_station_reconnect_wlan(wlan_cfg, check_status_timeout = 90, retry = 3, apcli_context_name = ''):
    function_name = sys._getframe().f_code.co_name
    tested_retry = retry    
    while(retry >= 0):
        try:
            remove_all_wlan_from_wireless_station(check_status_timeout = check_status_timeout, retry = retry)
            wireless_station_associate_wlan(wlan_cfg = wlan_cfg, check_status_timeout = check_status_timeout, retry = 0, apcli_context_name = apcli_context_name)
            break
        except Exception, ex:
            retry -= 1
            if retry < 0:
                raise Exception( "After %s retry for failed in %s, exception:%s" % (tested_retry, function_name, ex.message))
                break
            else:
                continue
          
def wireless_station_disconnect_wlan(check_status_timeout = 90, retry = 3):
    wifi_station = CM.get_station_instance()
    function_name = sys._getframe().f_code.co_name
    tested_retry = retry
    result = "fail"
    
    while(retry >= 0):
        try:
            wifi_station.disconnect_wlan()
                        
            start_time = time.time()
            while True:
                status = wifi_station.get_wlan_status()
                if status == "disconnected":
                    result = "pass"
                    break
                
                time.sleep(1)
                if time.time() - start_time > check_status_timeout:
                    if retry > 0:
                        continue
                    else:
                        raise Exception("After %s retry, the station did not disconnect from wireless network within %d seconds" % (tested_retry, check_status_timeout))
            
            if result == "pass":
                msg =  "WiFi station disconnects from the wireless network successfully"
                BTN.log(message = "%s %s" %(MODULE_NAME, function_name) + ' ' + msg, level = "DEBUG")
                break
            else:
                retry -= 1
        except Exception, ex:
            retry -= 1
            if retry < 0:
                raise Exception( "After %s retry for failed, exception:%s" % (tested_retry, ex.message))
                break
            else:
                continue


def _do_shell_cmd(apcli, cmd_text, timeout = 0, return_list = True):
    function_name = sys._getframe().f_code.co_name
    BTN.log(message = "%s %s" %(MODULE_NAME, function_name) + ' cmd: %s' % cmd_text, level = "DEBUG") 
    return apcli.do_cmd(cmd_text, prompt = "#", timeout = timeout, return_list = return_list)

def remove_all_wlan_from_wireless_station(check_status_timeout=60, retry=3):
    """
    Remove all WLAN from wireless station. Please see
    RWWindowsTestAppliance.remove_all_wlan_profiles to see the configuration detail.

    == Argument: ==
    - _check_status_timeout_: A integer value of check wireless station disconnected status idle timeout, default is 60 seconds.
    - _retry_: A integer value of retry if cannot remove all WLAN from wireless station, default is 3 times.

    == Return Value: ==
    - None

    == Example: ==    
    | *Setting* | *Value*                                                          |
    | Resource  | R${RootTarget}/resources/keywords/qa/Windows_Basic_Keywords.html |    
    
    | *Action*                                |
    | _Remove all WLAN from wireless station_ |
    """
    
    wifi_station = CM.get_station_instance()
    function_name = sys._getframe().f_code.co_name
    tested_retry = retry
    
    BTN.log(message = "%s %s" %(MODULE_NAME, function_name), level = "DEBUG")
    result = "fail"
    
    while(retry >= 0):
        try:
            wifi_station.remove_all_wlan_profiles()
            wifi_station.disconnect_wlan()
            
            start_time = time.time()
            while True:
                status = wifi_station.get_wlan_status()
                if status == "disconnected":
                    result = "pass"
                    break
                
                time.sleep(1)
                if time.time() - start_time > check_status_timeout:
                    if retry > 0:
                        continue
                    else:
                        raise Exception("After %s retry, the station did not disconnect from wireless network within %d seconds" % (tested_retry, check_status_timeout))
            
            if result == "pass":
                msg =  "Remove all WLAN profiles from the station and make sure it disconnects from the wireless network successfully"
                BTN.log(message = "%s %s" %(MODULE_NAME, function_name)  + ' ' + msg, level = "DEBUG")
                break
            else:
                retry -= 1
        except Exception, ex:
            retry -= 1
            if retry < 0:
                raise Exception( "After %s retry for failed, exception:%s" % (tested_retry, ex.message))
                break
            else:
                continue

def wireless_station_get_wlan_ip_addr():
    wifi_station = CM.get_station_instance()
    function_name = sys._getframe().f_code.co_name
    
    BTN.log(message = "%s %s" %(MODULE_NAME, function_name), level = "DEBUG")
    addr = wifi_station.get_addresses()
    ip_addr = addr["IP"]
    return ip_addr


def wireless_station_stop_iperf_server():
    wifi_station = CM.get_station_instance()
    function_name = sys._getframe().f_code.co_name

    BTN.log(message = "%s %s" %(MODULE_NAME, function_name), level = "info")
    wifi_station.client_stop_iperf()


def wireless_station_restart_iperf_server(test_udp = False, tradeoff = False, compatibility = False):
    wifi_station = CM.get_station_instance()
    function_name = sys._getframe().f_code.co_name

    BTN.log(message = "%s %s" %(MODULE_NAME, function_name), level = "info")
    wifi_station.client_stop_iperf()
    wifi_station.client_start_iperf(test_udp = test_udp,  packet_len=800, timeout = 60)


#---------------------------------- Stations methods for windows clients. -------------------------------------------------------
def station_start_iperf_server(station, iperf_port, multicast_srv = False, server_addr = '', test_udp = False):
    """
        Start iperf server in wifi station.
        
        == Argument: ==
        - _station_ : windows station instance.
        - _iperf_port_ : port of iperf.
        - _multicast_srv_ : multicast server flag, default is False.
        - _server_addr_ : server address, default is ''.
        - _test_udp_ : test udp flag, default is True.
        
        == Return Value: ==
        - None
        
        == Example: ==
        | *Action* | *Argument* | *Argument* | *Argument* | *Argument* | *Argument* |
        | _Station Start IPerf Server_ | Station | 5001 | False | 192.168.0.252 | True |
    """
    station.client_start_iperf(serv_addr = server_addr, test_udp = test_udp,
                               multicast_srv = multicast_srv, port = iperf_port)

def station_start_zing_client(station, zing_server_ip_addr='', packet_gap = '', packet_len = '',
                              timeout = '', test_udp = False):
    """
        Start zing client in wifi station.
        
        == Argument: ==
        - _station_ : windows station instance.
        - _zing_server_ip_addr_ : zing server ip address.
        - _packet_gap_ : packet gap of traffic.
        - _packet_len_ : packet length of traffic.
        - _timeout_ : timeout of sending traffic.
        - _test_udp_ : test udp flag, default is True.
        
        == Return Value: ==
        - None
        
        == Example: ==
        | *Action* | *Argument* | *Argument* | *Argument* | *Argument* | *Argument* | *Argument* |
        | _Station Start Zing Client_ | station | 192.168.0.252 | 100 | 800 | 60 | True |
    """
    station.client_start_zing(server_addr = zing_server_ip_addr, pkt_gap = packet_gap,
                              pkt_len = packet_len, test_udp = test_udp, timeout = timeout)

def station_verify_tos_value(station, cap_file_name, src_ip_addr, dst_ip_addr, exp_tos_value, proto = 'UDP'):
    """
        Verify tos values in station captured traffic.
        
        == Argument: ==
        - _station_ : windows station instance.
        - _cap_file_name_ : capture file name in station.
        - _src_ip_addr_ : source ip address.
        - _dst_ip_addr_ : destination ip address.
        - _exp_tos_value_ : expect TOS value.
        
        == Return Value: ==
        - None
        
        == Example: ==
        | *Action* | *Argument* | *Argument* | *Argument* | *Argument* | *Argument* |
        | _Station Verify TOS Value _ | station | tcpdump_tos.txt | 192.168.0.252 | 192.168.0.218 | 0x18 |
    """    
    err_msg = ""

    BuiltIn().log(message = MODULE_NAME + " station_verify_tos_value Reading traffic in station", level = "INFO")
    cap_tos_value = station_get_tos_value(station, cap_file_name, src_ip_addr, dst_ip_addr, proto)

    BuiltIn().log(message = MODULE_NAME + " station_verify_tos_value TOS value:%s" % cap_tos_value, level = "DEBUG")

    if cap_tos_value.lower() != exp_tos_value.lower():
        err_msg = "The ToS value in station is incorrect. Expect:%s, Actual:%s" % (exp_tos_value, cap_tos_value)
    else:
        BuiltIn().log(message = MODULE_NAME + " station_verify_tos_value The ToS value at receiver is correct", level = "INFO")

    return err_msg

def station_get_tos_value(station, cap_file_name, src_ip_addr, dst_ip_addr, proto = 'UDP'):
    """
        Get TOS values information in station traffic based on specified source 
        and destination ip address.
        
        == Argument: ==
        - _station_ : windows station instance.
        - _cap_file_name_ : capture file name in station.
        - _src_ip_addr_ : source ip address.
        - _dst_ip_addr_ : destination ip address.        
        
        == Return Value: ==
        - TOS value in the captured traffic.
        
        == Example: ==
        | *Action* | *Argument* | *Argument* | *Argument* | *Argument* |
        | _Station Get TOS Value _ | station | tcpdump_tos.txt | 192.168.0.252 | 192.168.0.218 |
    """
    cap_tos_value = ""

    #try:
    BuiltIn().log(message = MODULE_NAME + " station_get_tos_value Get tos values from the captured traffic in station", level = "INFO")
    cap_traffic_res = station.client_analyze_traffic(file_path = cap_file_name, src_ip = src_ip_addr, dst_ip = dst_ip_addr, proto = proto)

    BuiltIn().log(message = MODULE_NAME + " Traffic:%s" % cap_traffic_res, level = "INFO")
    for res in cap_traffic_res:
        if res.get('src_ip') == src_ip_addr and res.get('dst_ip') == dst_ip_addr:
            if res.has_key('tos'): cap_tos_value = res['tos']
            break

    if not cap_tos_value:
        msg = MODULE_NAME + " station_get_tos_value can not find the matched traffic(src=%s,dst=%s) with in station: %s" \
                % (src_ip_addr, dst_ip_addr, cap_traffic_res)
        raise Exception(msg)

    BuiltIn().log(message = MODULE_NAME + " station_get_tos_value ToS value of captured traffic: %s" % cap_tos_value, level = "INFO")
#    except Exception, ex:
#        BuiltIn().log(message = MODULE_NAME + " station_get_tos_value Exception:%s" % ex.message, level="INFO")        

    return cap_tos_value

def station_verify_empty_traffic(station, cap_file_name, src_ip_addr, dst_ip_addr):
    """
        Verify no any traffic in station based on source and destination ip address.
        
        == Argument: ==
        - _station_ : windows station instance.
        - _cap_file_name_ : capture file name in station.
        - _src_ip_addr_ : source ip address.
        - _dst_ip_addr_ : destination ip address.
        
        == Return Value: ==
        - Error message if there is any traffic in station based on source and destination ip address.
        
        == Example: ==
        | *Action* | *Argument* | *Argument* | *Argument* | *Argument* |
        | _Station Verify Empty Traffic_ | station | tcpdump_tos.txt | 192.168.0.252 | 192.168.0.218 |
    """
    err_msg = ""

    BuiltIn().log(message = MODULE_NAME + " station_verify_empty_traffic Verify no any traffic in station", level = 'INFO')
    traffic_res = station.client_analyze_traffic(file_path = cap_file_name, src_ip = src_ip_addr, dst_ip = dst_ip_addr)

    if traffic_res:
        BuiltIn().log(message = MODULE_NAME + " station_verify_empty_traffic Traffic in station (src=%s,dst=%s): %s" \
                       % (src_ip_addr, dst_ip_addr, traffic_res), level = 'INFO')
        err_msg = "There is traffic goes to station (src=%s,dst=%s): %s" % (src_ip_addr, dst_ip_addr, traffic_res)

    return err_msg

def station_verify_conn_bw_stations(station, sta_info_list, try_times = 10):
    """
        Verify the connection between stations with ping traffic.
        
        == Argument: ==
        - _station_ : windows station instance.
        - _sta_info_list_ : all connected station information list.
        - _try_times_ : try times if failed, default is 5.
        
        == Return Value: ==
        - Error message is station can't ping another station.
        
        == Example: ==
        | *Action* | *Argument* | *Argument* | *Argument* |
        | _Verify Stations Connection_ | station | ${sta info list} | 5 |
    """
    err_list = []

    for sta_info in sta_info_list:
        BuiltIn().log(message = MODULE_NAME + " station_verify_traffic Set station target %s" % sta_info, level = "DEBUG")
        sta_ip_addr = sta_info['sta_ip_addr']
        sta_wifi_ip_addr = sta_info['wifi_ip_addr']
        http_port = sta_info['http_port']

        station.set_target(sta_ip_addr, http_port)

        for sta2_info in sta_info_list:
            sta2_ip_addr = sta2_info['sta_ip_addr']
            sta2_wifi_ip_addr = sta2_info['wifi_ip_addr']
            if sta_ip_addr != sta2_ip_addr:
                BuiltIn().log(message = MODULE_NAME + " station_verify_conn_bw_stations Verify ping traffic from %s to %s" % (sta_wifi_ip_addr, sta2_wifi_ip_addr), level = 'INFO')
                err_ping = ""
                for i in range(0, try_times):
                    err_ping = ''
                    try:
                        res_ping = station.test_ping(sta2_wifi_ip_addr)
                        BuiltIn().log(message = MODULE_NAME + " station_verify_conn_bw_stations Ping response: %s" % (res_ping), level = 'DEBUG')
                    except Exception, ex:
                        err_ping = ex.message

                    #If ping failed, try again; if success, exit.
                    if err_ping: time.sleep(5)
                    else: break

                if err_ping:
                    err_list.append("Failed ping from %s(WIFI:%s) to %s(WIFI:%s):%s"
                                    % (sta_ip_addr, sta_wifi_ip_addr, sta2_ip_addr, sta2_wifi_ip_addr, err_ping))

    return err_list

def station_renew_and_verify_ip(sta_eth_ip, sta_http_port, is_allow = True, check_timeout=120):
    """
        Renew wifi station ip address and verify it is correct.
    
        == Argument: ==
        - _sta_eth_ip_ : station ethernet ip address.
        - _sta_http_port_ : station http port.
        - _is_allow_ : allow get ip address or not. default is true.
        - _check_timeout_ : timeout for waiting get correct ip address. default is 120.
    
        == Return Value: ==
        - None
    
        == Example: ==
        | *Action* | *Argument* | *Argument* | *Argument* | *Argument* |
        | _Station Renew and Verify IP_ | 192.168.1.101 | 8888 | ${true} | ${240} |    
    
    """
    wifi_station = CM.get_station_instance()
    wifi_station.set_target(sta_eth_ip, sta_http_port)
    wifi_station.renew_wifi_ip_address()
    
    is_ipv4_correct = False
    sta_wifi_ip_addr = None
    start_time = time.time()
    while time.time() - start_time < check_timeout:
        sta_addr_dict = wifi_station.get_addresses()
        sta_wifi_ip_addr = sta_addr_dict['IP']
        logging.debug("Get station wifi IP address %s" % sta_wifi_ip_addr)
        
        ptn = '(\d{1,3}\.){3}\d{1,3}$'
        matcher = re.compile(ptn, re.I).match(sta_wifi_ip_addr)
        if matcher:
            if not (sta_wifi_ip_addr== '0.0.0.0' or sta_wifi_ip_addr.startswith('169.254')):
                logging.debug("Station wifi IP address %s is correct" % sta_wifi_ip_addr)
                is_ipv4_correct = True
                break
        
        time.sleep(5)
        
    logging.debug("Verify station wifi ip address, expect:%s, actual ip:%s" % (is_allow, sta_wifi_ip_addr))    
    if is_allow != is_ipv4_correct:
        if is_allow == True:
            raise AssertionError("Didn't get wifi station IP correctly: %s" % sta_wifi_ip_addr)
        else:
            raise AssertionError("Get wifi station IP correctly expect is fail:%s" % sta_wifi_ip_addr)
    else:
        return sta_wifi_ip_addr
    