#Please include the following resources without alias when you use this resource keywords.
#/Rwbot/resources/keywords/qa/Windows_Basic_Keywords.html 
*** Setting ***
Library     Collections
Library     ${ProjectTarget}/libs/python/lib/win_station_methods.py


*** Keyword ***
Set wireless station IP
    [Arguments]    ${station ip}
    set_target    ${station ip}
    
Set wireless station IP and HTTP Port
    [Arguments]    ${station_ip}    ${http_port}=${8888}
    set_target    ${station_ip}    ${http_port}

Configure wireless station to associate WLAN
    [Arguments]    ${wlan cfg}
    Configure and associate to WLAN then check    ${wlan cfg}

Configure wireless station to remove all WLAN
    Remove all WLAN profiles and check

Ping result should be
    [Arguments]    ${target ip}    ${expected}
    ${status}    ${ping result}=    Run Keyword and Ignore Error    Test ping    ${target ip}
    Should Be Equal    ${expected.upper()}    ${status.upper()}

Wireless station ping target, ping should pass
    [Arguments]    ${target ip}  ${retry_time}=2m  ${retry_interval}=0s
    Wait Until Keyword Succeeds    ${retry_time}    ${retry_interval}    Ping result should be    ${target ip}    PASS

Wireless station ping target, ping should fail
    [Arguments]    ${target ip}
    Wait Until Keyword Succeeds    2m    0s    Ping result should be    ${target ip}    FAIL
    
Associate Wireless Stations and Get Wifi Mac Addresses
    [Arguments]    ${sta_ip_list}    ${wlan_cfg}
    ${sta_info}    Create Dictionary
    :FOR    ${sta_eth_ip}    IN    @{sta_ip_list}
    \	Set wireless station IP    ${sta_eth_ip}
    \	Do associate process    ${wlan_cfg}
    \	${sta_address_dict}=    get_addresses
    \	${sta_wifi_mac_addr}=    Set Variable    ${sta_address_dict.get('MAC')}    
    \	Set to Dictionary    ${sta_info}    ${sta_wifi_mac_addr}    ${sta_eth_ip}
    [Return]	${sta_info}
    
Associate Wireless Stations
    [Arguments]    ${sta_ip_list}    ${wlan_cfg}
    ${sta info}    Create Dictionary
    :FOR    ${sta_eth_ip}    IN    @{sta_ip_list}
    \   Set wireless station IP    ${sta_eth_ip}
    \   Do associate process    ${wlan_cfg}
    
Get Wifi IP Address and Check
    ${sta_address_dict}=    get_addresses
    ${sta_wifi_ip_addr}=    Set Variable    ${sta_address_dict.get('IP')}
    Should Match Regexp    ${sta_wifi_ip_addr}    \\d+\.\\d+\.\\d+\.\\d+    msg="invalid IP address"
    [Return]    ${sta_wifi_ip_addr}
    
Associate Station to Wlan and Get Addresses
    [Arguments]    ${wlan_cfg}    
    Do associate process    ${wlan_cfg}
    ${station_address_dict}=    Get Addresses
    ${station_wifi_ip_addr}=    Set Variable    ${station_address_dict.get('IP')}
    ${station_wifi_mac_addr}=    Set Variable    ${station_address_dict.get('MAC')}
    [Return]   ${station_wifi_ip_addr}    ${station_wifi_mac_addr}    
    
Client Add and Change Route
    [Arguments]    ${mcast_network}    ${mcast_mask}    ${gateway}    ${route_metric}
    Client Add Route    ${mcast_network}    ${mcast_mask}    ${gateway}    ${route_metric}
    Client Change Route    ${mcast_network}    ${mcast_mask}    ${gateway}    ${route_metric}    
    
    
Associate Client with Open WLAN
    [Arguments]  ${client_ip}  ${ap_ip}  ${wlan_ssid}
    
    Set wireless station IP  ${client_ip}
    Run Keyword and Ignore Error    Disconnect WLAN
    Remove all WLAN profiles and check
    ${all_wlans}=   Scan wlans
    ${sta_open}=    Create Dictionary    ssid=${wlan_ssid}  auth=OPEN  encrypt=NONE  
    Configure wireless station to associate WLAN    ${sta_open}
    Sleep    5s
    Wireless station ping target, ping should pass    ${ap_ip}


Client Configure Wireless IF
    [Documentation]    Used to configure Wireless Interface of Client
    ...    param string wlan_if_mac   - MAC address of Wireless Interface to be configured
    ...    param string band          - Wireless Band (24bg | 5G | 24b | 5a | 24G-only | 24G | Auto)
    ...    param string ht_mode       - HT Mode to set (disable | HT | VHT)
    [Arguments]    ${wlan_if_mac}  ${band}=Auto  ${ht_mode}=VHT
    
    Remove all WLAN profiles and check
    ${cfg}=    Create Dictionary  mac=${wlan_if_mac}  band=${band}
    Change Band    ${cfg}
    Sleep    30s
    ${cfg}=    Create Dictionary  mac=${wlan_if_mac}  mode=${ht_mode}
    Change HT Mode    ${cfg}
    Sleep    20s
