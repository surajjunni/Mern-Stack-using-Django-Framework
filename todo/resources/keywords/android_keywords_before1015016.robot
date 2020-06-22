*** Settings ***
Variables       ${ProjectTarget}/resources/variables/PublicApiVariables.py
Resource    	${RootTarget}/resources/keywords/qa/apcli_keywords.robot
Resource        ${ProjectTarget}/../../resources/keywords/qa_system/ap_keywords.robot
Library      cli.ApCli    WITH NAME    apcli
Library      SSHLibrary
#    WITH NAME    robot_ssh
*** Keywords ***

Login To Remote PC
	Open Connection   ${APPIUM_IP}
        SSHLibrary.Login   ${APPIUM_UNAME}   ${APPIUM_PWD}
        Write   echo Remote PC Login
	${output}=   Read Until Login
	

AP Logout If Necessary
    Run Keyword If  ${ap_has_login}  Run Keywords
    ...  Logout AP
    ...  AND
    ...  Set Test Variable  ${ap_has_login}  ${false}


AP Login If Necessary
    [Arguments]  ${ap_ip}=${AP_IP}
    ${passed}=  Run Keyword And Return Status
    ...  apcli.send  \n
    Run Keyword Unless  ${passed}  Run Keywords
    ...  Login AP  ${ap_ip}  admin  Password1!
    ...  AND
    ...  Set Test Variable  ${ap_has_login}  ${true}

#Get Client Details

	#${err} =  Execute Command   /cygdrive/c/Python27/python.exe dev.py    stderr    stdout
	#Should Be Empty   ${err}
	#Write   cat connected_dev.txt    
	#${dev}=   Read   
	#Log   ${err}
	#Log   ${dev}
	##Should Contain   ${dev}   asus Nexus 7
	#Should Match Regexp   ${dev}   \\w+\\s*\\w+\\s*\\d*   

Show Client Details

	${err} =   Execute Command   /cygdrive/c/Python27/python.exe dev.py    stderr
	Should Be Empty   ${err} 
	${device} =  Execute Command    cat connected_dev.txt
	Should Not Be Empty   ${device}
	Log   ${device}


Create Client Json File For Single STA

	[Arguments]   ${ssid}=None   ${authentication}=None   ${encryption}=None   ${wpa_algorithm}=None   ${passphrase}=None   ${enterprise_type}=None   ${enterprise_username}=None   ${enterprise_password}=None   ${webauth_type}=None   ${guest_key}=None   ${web_username}=${AAA_UNAME}   ${web_password}=${AAA_PWD}   ${url}=None   ${url_data}=None   ${serialid}=None  ${port}=None  ${alias}=None  ${ios_devicename}=None   ${macip}=None   ${winip}=None  ${win_username}=None  ${win_password}=None   ${web_portal}=None   ${dev_eth_ip}=None    ${username}=None  ${password}=None      ${device_mac}=None    ${ios_version}=None  

	Log   ${RootTarget}
	Remove File   ${RootTarget}/../ioT_devicemgr/device_cfg.json
	create_config_file    ${RootTarget}
	${is_mac} =   Run Keyword and Return Status    Should Contain   ${alias}   mac	
	Run Keyword If   '${serialid}' != 'NA'   update_config_file     ${ssid}   ${authentication}   ${encryption}   ${wpa_algorithm}   ${passphrase}     ${enterprise_type}   ${enterprise_username}   ${enterprise_password}   ${webauth_type}   ${guest_key}   ${web_username}   ${web_password}   ${web_portal}   ${APPIUM_IP}   ${APPIUM_UNAME}   ${APPIUM_PWD}   ${url}    ${url_data}   ${serialid}   ${port}   android   ${alias}   ${RootTarget}    None    ${device_mac}
	Run Keyword If   '${serialid}' == 'NA' and '${ios_devicename}' != 'None'    update_config_file     ${ssid}   ${authentication}   ${encryption}   ${wpa_algorithm}   ${passphrase}     ${enterprise_type}   ${enterprise_username}   ${enterprise_password}   ${webauth_type}   ${guest_key}   ${username}   ${password}   ${web_portal}   ${SEETEST_IP}   ${SEETEST_UNAME}   ${SEETEST_PWD}   ${url}    ${url_data}   None   ${port}   ios   ${alias}   ${RootTarget}   ${ios_devicename}    ${device_mac}   ${ios_version}
        Run Keyword If   '${serialid}' == 'NA' and '${ios_devicename}' == 'None' and '${is_mac}'=='True'   update_config_file     ${ssid}   ${authentication}   ${encryption}   ${wpa_algorithm}   ${passphrase}     ${enterprise_type}   ${enterprise_username}   ${enterprise_password}   ${webauth_type}   ${guest_key}   ${web_username}   ${web_password}   ${web_portal}   ${macip}   @{MAC_USR}[0]   @{MAC_PWD}[0]   ${url}    ${url_data}   None   ${port}   mac   ${alias}   ${RootTarget}   None    ${device_mac}
	Run Keyword If   '${serialid}' == 'NA' and '${ios_devicename}' == 'None' and '${is_mac}'=='False'   update_config_file     ${ssid}   ${authentication}   ${encryption}   ${wpa_algorithm}   ${passphrase}     ${enterprise_type}   ${enterprise_username}   ${enterprise_password}   ${webauth_type}   ${guest_key}   ${web_username}   ${web_password}   ${web_portal}   ${winip}   ${win_username}  ${win_password}  ${url}  ${url_data}   None   ${port}   windows   ${alias}   ${RootTarget}   None    ${device_mac}
	
	close_config_file   ${RootTarget}


Parse Throughput 
	[Arguments]   ${buffer}=None
	${ret}=    parse_values   ${buffer}
	[return]   ${ret}


Create Client Json File using Robot method
	[Arguments]       ${authentication}=None   ${encryption}=None    ${wpa_algorithm}=None   ${passphrase}=None   ${username}=${AAA_UNAME}   ${password}=${AAA_PWD}    ${ssid}=IOT_OPEN    ${webauth_type}=None   ${enterprise_type}=None   ${enterprise_username}=None   ${enterprise_password}=None   ${guest_key}=None

	    ${json_string}=    catenate
    ...  {
    ...      "device_alias" : "None",
    ...      "device_type" : "android",
    ...      "device_eth_ip" : "${CLIENT_IP}",
    ...      "authentication" : "${authentication}",
    ...	     "webauth_type" : "None",
    ...      "encryption":"${encryption}",
    ...      "wpa_algorithm":"${wpa_algorithm}",
    ...      "passphrase" : "None",
    ...      "web_username" : "None",
    ...      "web_password" : "None",
    ...      "web_portal" : "vszap",
    ...      "ssid" : "${ssid}",
    ...      "serialid" : "None",
    ...      "port" :  "None",
    ...	     "enterprise_type"  :  "None",
    ...      "enterprise_username" :  "None",
    ...      "enterprise_password" :  "None",
    ...      "guest_key"  :  "None",
    ...      "windows_username" : "${CLIENT_UNAME}",
    ...      "windows_password" : "${CLIENT_PWD}"
    ...	 }
	
    	#Create File  ${RootTarget}/device_cfg_android.json    {"devices" : [
	Create File   ${RootTarget}/../ioT_devicemgr/device_cfg_android.json    {"devices" : [
    	${count} =    Get Length    ${serialids}
	:FOR   ${index}   IN RANGE   ${count}
	\	${m} =  Set Variable   @{serialids}[${index}]
	\	Log    ${m}  
	\	${n} =  Set Variable   @{ports}[${index}]
	\	Log    ${n}
	\	${o} =  Set Variable   @{alias}[${index}]
	\	Log    ${o}
	\	${p} =  Set Variable   @{ios_devicename}[${index}]
	\	Log    ${p}
    	\	log to console       \nOriginal JSON:\n${json_string}
    	\	${json}=             evaluate        json.loads('''${json_string}''')    json
    	\	set to dictionary    ${json}  device_alias   ${o}
    	\	set to dictionary    ${json}  authentication   ${authentication}
    	\	set to dictionary    ${json}  webauth_type    ${webauth_type} 
   	\	set to dictionary    ${json}  encryption   ${encryption}
    	\	set to dictionary    ${json}  ssid   ${ssid}
    	\	set to dictionary    ${json}  serialid   ${m}
    	\	set to dictionary    ${json}  passphrase   ${passphrase}
    	\	set to dictionary    ${json}  web_username   ${username}
    	\	set to dictionary    ${json}  web_password   ${password} 
    	\	set to dictionary    ${json}  web_portal   vszap
    	\	set to dictionary    ${json}  port   ${n}
	\       set to dictionary    ${json}  enterprise_type   ${enterprise_type}
	\       set to dictionary    ${json}  enterprise_username   ${enterprise_username}
	\       set to dictionary    ${json}  enterprise_password   ${enterprise_password}
	\       set to dictionary    ${json}   guest_key    ${guest_key}
    	\	${json_string}=      evaluate        json.dumps(${json})                 json
    	\	log to console       \nNew JSON string:\n${json_string}
    	\	${count}=   Evaluate   ${count} - 1 
    	\	Log to console    ${count}
    	\	Append To File  ${RootTarget}/../ioT_devicemgr/device_cfg_android.json  ${json_string}
    	\	Run Keyword If   ${count} != 0     Append To File  ${RootTarget}/../ioT_devicemgr/device_cfg_android.json    ,

    	Append To File  ${RootTarget}/../ioT_devicemgr/device_cfg_android.json  ]}
    	Log    ${json_string}	



Create Client Json File 
	[Arguments]   ${ssid}=None   ${authentication}=None   ${encryption}=None   ${wpa_algorithm}=None   ${passphrase}=None   ${enterprise_type}=None   ${enterprise_username}=None   ${enterprise_password}=None   ${webauth_type}=None   ${guest_key}=None   ${web_username}=${AAA_UNAME}   ${web_password}=${AAA_PWD}   ${url}=None   ${url_data}=None   ${web_portal}=None   ${dev_eth_ip}=None    ${username}=None  ${password}=None     
	${count} =    Get Length    ${dev_details}
	Log   ${RootTarget}
	#To create a list of same pskkey incase dpsk is disabled in the wlan configuration
	${pskkey}=  Create List
	${temp} =   Convert To String    ${passphrase}
	${temp} =   Run Keyword and Return Status   Should Not Contain   ${temp}   [
	Log   ${temp}
	:For   ${index}   IN RANGE   ${count}
	\	Run Keyword If   ${temp}   Append To List   ${pskkey}   ${passphrase}
	\	Log   ${pskkey}
	${passphrase} =   Set Variable If   ${temp}   ${pskkey}   ${passphrase}
	
	Remove File   ${RootTarget}/../ioT_devicemgr/device_cfg.json
	#Create File   ${RootTarget}/../ioT_devicemgr/device_cfg.json   {"devices":[
	create_config_file    ${RootTarget}
	:FOR   ${index}   IN RANGE   ${count}
	\	${pos} =  Set variable   @{dev_details}[${index}]
	\	${m} =  Set Variable   ${dev.mac_dict[${pos}][0]['serialid']}
	\	Log    ${m}  
	\	${n} =  Set Variable   ${dev.mac_dict[${pos}][4]['ports']}
	\	Log    ${n}
	\	${o} =  Set Variable   ${dev.mac_dict[${pos}][3]['alias']}
	\	Log    ${o}
	\	${p} =  Set Variable   ${dev.mac_dict[${pos}][5]['ios_devicename']}
	\	Log    ${p}
	\	${q} =  Set Variable   ${dev.mac_dict[${pos}][2]['mac']}
	\	Log    ${q}
	\	${r} =  Set Variable   ${dev.mac_dict[${pos}][10]['ios_version']}
	\	Log    ${r}
	\	${key} =  Set Variable   @{passphrase}[${index}]
	\ 	Log    ${key}  
	\       builtin.log    ${web_portal}
        \       builtin.log    ${dev_eth_ip}
	\	${is_mac} =   Run Keyword and Return Status    Should Contain   ${dev.mac_dict[${pos}][3]['alias']}   mac   
	\	Run Keyword If   '${m}' != 'NA'   update_config_file     ${ssid}   ${authentication}   ${encryption}   ${wpa_algorithm}   ${key}     ${enterprise_type}   ${enterprise_username}   ${enterprise_password}   ${webauth_type}   ${guest_key}   ${web_username}   ${web_password}   ${web_portal}   ${APPIUM_IP}   ${APPIUM_UNAME}   ${APPIUM_PWD}   ${url}    ${url_data}   ${m}   ${n}   android   ${o}   ${RootTarget}    None     ${q}   ${r}
	\	Run Keyword If   '${m}' == 'NA' and '${p}' != 'None'    update_config_file     ${ssid}   ${authentication}   ${encryption}   ${wpa_algorithm}   ${key}     ${enterprise_type}   ${enterprise_username}   ${enterprise_password}   ${webauth_type}   ${guest_key}   ${web_username}   ${web_password}   ${web_portal}   ${SEETEST_IP}   ${SEETEST_UNAME}   ${SEETEST_PWD}   ${url}    ${url_data}   None   ${n}   ios   ${o}   ${RootTarget}   ${p}   ${q}   ${r}
	
	\	Run Keyword If   '${m}' == 'NA' and '${p}' == 'None' and '${is_mac}'=='True' and '${authentication}'!='8021x' and '${authentication}'!='8021x_mac'   update_config_file     ${ssid}   ${authentication}   ${encryption}   ${wpa_algorithm}   ${key}     ${enterprise_type}   ${enterprise_username}   ${enterprise_password}   ${webauth_type}   ${guest_key}   ${web_username}   ${web_password}   ${web_portal}   ${dev.mac_dict[${pos}][6]['MAC_IP']}   @{MAC_USR}[0]   @{MAC_PWD}[0]   ${url}    ${url_data}   None   ${n}   mac   ${o}   ${RootTarget}   None     ${q}

	\	Run Keyword If   '${m}' == 'NA' and '${p}' == 'None' and '${is_mac}'=='True' and ('${authentication}'=='8021x' or '${authentication}'=='8021x_mac')   update_config_file     ${ssid}   ${authentication}   ${encryption}   ${wpa_algorithm}   ${key}     ${enterprise_type}   ${enterprise_username}   ${enterprise_password}   ${webauth_type}   ${guest_key}   ${web_username}   ${web_password}   ${web_portal}   ${dev.mac_dict[${pos}][6]['MAC_IP']}   ${macdic.mac_details_dict[${pos}][5]['username']}   ${macdic.mac_details_dict[${pos}][6]['password']}   ${url}    ${url_data}   None   ${n}   mac   ${o}   ${RootTarget}   None     ${q}


	\	Run Keyword If   '${m}' == 'NA' and '${p}' == 'None' and '${is_mac}'=='False'   update_config_file     ${ssid}   ${authentication}   ${encryption}   ${wpa_algorithm}   ${key}     ${enterprise_type}   ${enterprise_username}   ${enterprise_password}   ${webauth_type}   ${guest_key}   ${web_username}   ${web_password}   ${web_portal}   ${dev.mac_dict[${pos}][7]['WIN_IP']}   ${dev.mac_dict[${pos}][8]['WIN_USR']}   ${dev.mac_dict[${pos}][9]['WIN_PWD']}   ${url}    ${url_data}   None   ${n}   windows   ${o}   ${RootTarget}   None    ${q}   ${r}

	\	${count}=   Evaluate   ${count} - 1 
	\	Run Keyword If   ${count} != 0     Append To File  ${RootTarget}/../ioT_devicemgr/device_cfg.json    ,

	close_config_file   ${RootTarget}




Get IP address of STA
	${json}=  OperatingSystem.Get file  ${RootTarget}/../ioT_devicemgr/status.json
	${object}=  Evaluate  json.loads('''${json}''')  json
	Log   ${object["devices"]}
	${count} =  Get Length    ${object["devices"]}  
	Log   ${count} 
	Should not be Equal as Integers  ${count}   0
	${ip} =  Get From Dictionary   ${object["devices"][0]}   wlan_ip
	[return]   ${ip}



Verify connection status of STA  
	[Arguments]   ${status}=None   ${APMAC}=${AP_MACC[0]}    ${wlan}=${WLAN}
	Set Test Variable   ${dev_mac}   None
	${connectionResult}=   Create Dictionary
	Set Test Variable   ${connectionResult}
	${json}=  OperatingSystem.Get file  ${RootTarget}/../ioT_devicemgr/status.json
	${object}=  Evaluate  json.loads('''${json}''')  json
	Log   ${object["devices"]}
	${count} =  Get Length    ${object["devices"]}
	Log   ${count} 
	Should not be Equal as Integers  ${count}   0
	
	${urlParams} =  Create Dictionary    apMac=${APMAC}
	${ap_data} =  aps get operational summary   urlParams=${urlParams}
	#${ap_ip} =  Get From Dictionary   ${ap_data}   externalIp
	${ap_ip} =  Get From Dictionary   ${ap_data}   ip
	Log   ${ap_ip}
	#Run Keyword if '${IS_DUAL_ZONE}'=='True'    Evalusa
	${ipv6} =  Evaluate   '${AP_IPV6_IP}'.split(':')
	${ipv6} =  Evaluate   ':'.join(${ipv6}[:4])
	${ip} =  Evaluate   '${ap_ip}'.split('.')
	${ip} =  Evaluate   '.'.join(${ip}[:2])
	Log   ${ip}

	:FOR   ${d}   IN Range  0   ${count}
	\	${wlan_mac} =  Get From Dictionary   ${object["devices"][${d}]}   wlan_mac   
	\ 	${serialid} =  Get From Dictionary   ${object["devices"][${d}]}   serialid
	\	${ssid} =  Get From Dictionary   ${object["devices"][${d}]}   ssid   
	\	${auth} =  Get From Dictionary   ${object["devices"][${d}]}   auth
	\   	${auth} =  Set Variable If    '${auth}' == 'OPEN_FDHCP'   OPEN   ${auth}   
	\	${con_status} =  Get From Dictionary   ${object["devices"][${d}]}   status 
	\	${wlan_ip_split} =  Get From Dictionary   ${object["devices"][${d}]}   wlan_ip
	\	${wlan_ip_split_list}=  Create List   ${wlan_ip_split}   ${wlan_ip_split}
	\	${wlan_ip}   ${wlan_ipv6} =  Run keyword if  '${status}'=='connected'  String.Split String    ${wlan_ip_split}   /
	\	...			     ELSE  set variable   ${wlan_ip_split_list}
	\	Should Not Be Empty   ${serialid}
	\	Should Not Be Empty   ${wlan_mac}	
	\	Run Keyword If   '${status}' == 'disconnected'
	\	...	Run Keyword And Continue On Failure   Disconnect Check   ${con_status}   ${serialid}   ${ssid}   ${auth}   ${wlan_ip}   ${wlan_mac}   ${wlan}     ${APMAC}
	\	Run Keyword If   '${status}' == 'connected'  
	\	...	Run Keyword and Continue on Failure   Connect Check   ${con_status}   ${serialid}   ${ssid}   ${auth}   ${wlan_ip}   ${ip}   ${wlan_mac}   ${wlan}    ${APMAC}   ${ipv6}   ${wlan_ipv6}
	${reslist_len} =   Get Length   ${ResultList}
	Run Keyword If   '${status}' == 'disconnected'	 	
	...	Run Keyword If   ${reslist_len} > 0   Device Result Seggregation


Get wlan Mac even for disconnected device if Any
	[Arguments]   ${wlan_mac}   ${serialid}
	${count} =    Get Length    ${dev_details}
	:For   ${index}   IN RANGE  ${count}
	\	${pos} =  Set variable   @{dev_details}[${index}]
	\ 	${dev_id} =  Set Variable   ${dev.mac_dict[${pos}][0]['serialid']}
	\	${device_mac} =  Set Variable if     
	\       ...	'${wlan_mac}' == 'none' and '${serialid}' == '${dev_id}'    ${dev.mac_dict[${pos}][2]['mac']}
	[return]    ${device_mac}

	
Device Result Seggregation
	Log List    ${ResultList}
	${count} =    Get Length    ${dev_details}
	:For   ${index}   IN RANGE  ${count}
	\	${pos} =  Set variable   @{dev_details}[${index}]
	\	${device} =  Set Variable   ${dev.mac_dict[${pos}][2]['mac']}
	\       ${device} =   Convert MAC To Lower Case   ${device} 
	\	${mcount} =   Count Values In List   ${ResultList}   ${device}:FAIL
	\	${exe_status} =   Set Variable If   ${mcount}==0   PASS   FAIL
	\       ${name} =   Evaluate   ${device_dict}.get('${device}')
	\	Append To File   ${ProjectTarget}/results/TestExecutionResults.log  ${name}:${exe_status} ${\n}
	Append To File   ${ProjectTarget}/results/TestExecutionResults.log   ---------------------------------- ${\n}
	${ResultList} =    Create List
	Set Suite Variable    ${ResultList}
	
Logging End Result
	${count} =    Get Length    ${dev_details}
	:For   ${index}   IN RANGE  ${count}
	\	${pos} =  Set variable   @{dev_details}[${index}]
	\	${mac} =  Set Variable   ${dev.mac_dict[${pos}][2]['mac']}
	\	${mac} =   Convert MAC To Lower Case   ${mac}
	\       ${name} =   Evaluate   ${device_dict}.get('${mac}')
	\	Append To File   ${ProjectTarget}/results/TestExecutionResults.log   ${name}:NSA ${\n}
	Append To File   ${ProjectTarget}/results/TestExecutionResults.log   ---------------------------------- ${\n}


Disconnect Check
	[Arguments]   ${con_status}   ${serialid}   ${ssid}   ${auth}   ${wlan_ip}   ${wlan_mac}    ${wlan}    ${APMAC}
	${discon_res} =   Set Variable If   '${con_status}'=='disconnected'   PASS   FAIL
	${mac} =   Convert MAC To Lower Case   ${wlan_mac}
	${count} =    Get Length    ${dev_details}
	:For   ${index}   IN RANGE  ${count}
	\	${pos} =  Set variable   @{dev_details}[${index}]
	\ 	${dev_id} =  Set Variable   ${dev.mac_dict[${pos}][0]['serialid']}
	\	Exit For loop If   '${dev_id}' == '${serialid}'
	${dev_mac} =   Set Variable If   '${mac}' == 'none'   ${dev.mac_dict[${pos}][2]['mac']}   ${mac}
	Append To List   ${ResultList}   ${dev_mac}:${discon_res}
	Should Be Equal    ${ssid}   NA
        Should Be Equal    ${auth}   NA
	Should Be Equal    ${con_status}   disconnected
	Should Be Equal    ${wlan_ip}   NA


Connect Check
	[Arguments]   ${con_status}   ${serialid}   ${ssid}   ${auth}   ${wlan_ip}   ${ip}   ${wlan_mac}   ${wlan}    ${APMAC}   ${ipv6}   ${wlan_ipv6}
	${ssid_sta}=    Run keyword and Return Status   Should Be Equal   ${ssid}   ${wlan}	
	#Run Keyword and Continue On Failure   Should Be Equal   ${ssid}   ${wlan}
	Run Keyword and Continue On Failure   List Should Contain Value   [OPEN,OPEN_PMK,8021x,802.1X,CP,GUEST_ACCESS,WEB,web,MAC_Address,WEB_AUTH,8021x_mac]   ${auth}
	#Run Keyword and Continue On Failure   Should Contain    ${wlan_ip}  ${ip}
	#${ip_sta}=    Run keyword and Return Status   Should Contain    ${wlan_ip}  ${ip}
        ${ip_sta}=    Run keyword and Return Status   Should Contain    ${wlan_ip}  ${sta_network}
	#${ipv6_sta}=   set variable if   ${wlan_ipv6} in ${ipv6}   True   False      
	${ipv6_sta}=   Run keyword and Return Status   Should Contain    ${wlan_ipv6}  ${sta_network_ipv6}
	${auth_sta} =    Run keyword and Return Status    Check STA Authorization Status      ${wlan_mac}    AUTHORIZED     ${APMAC}
	${con_status} =    Run keyword and Return Status   Should Be Equal   ${con_status}   connected 
	#${con_sub_res} =   Set Variable If   '${con_status}'=='True' and '${ssid_sta}'=='True' and '${ip_sta}'=='True' and '${auth_sta}'=='True' and '${ipv6_sta}'=='True'    PASS    FAIL
	${con_sub_res}=   Run keyword if   '${con_status}'=='True' and '${ssid_sta}'=='True' and '${ip_sta}'=='True' and '${auth_sta}'=='True' and '${ipv6_sta}'=='True'  set variable   PASS
	...		  ELSE IF    '${con_status}'=='True' and '${ssid_sta}'=='True' and '${ip_sta}'=='True' and '${auth_sta}'=='True' and '${ipv6_sta}'=='False' and '${IS_DUAL_ZONE}'=='False'  set variable   PASS
	...		  ELSE   set variable   FAIL		           	

	${ping_return_sta} =   Run Keyword If   '${con_sub_res}'=='PASS'   Check Ping Status    ${wlan_ip}
	${ping_return_sta_ipv6} =   Run Keyword If   '${con_sub_res}'=='PASS' and '${ipv6_sta}'=='True'   Check Ping Status IPV6   ${wlan_ipv6}
	#${con_res} =   Set Variable If   '${con_sub_res}'=='PASS' and '${ping_return_sta}'=='True' and '${ping_return_sta_ipv6}'=='True'  PASS   FAIL
	${con_res} =   Run Keyword If   '${con_sub_res}'=='PASS' and '${ping_return_sta}'=='True' and '${ping_return_sta_ipv6}'=='True'   set variable    PASS
	...	       ELSE IF   '${con_sub_res}'=='PASS' and '${ping_return_sta}'=='True' and '${ping_return_sta_ipv6}'!='True' and '${IS_DUAL_ZONE}'=='False'   set variable    PASS
        ...	       ELSE    set variable   FAIL
	${mac} =   Convert MAC To Lower Case   ${wlan_mac}
	${count} =    Get Length    ${dev_details}
	Set Test Variable   ${pos}   ${0}
	:For   ${index}   IN RANGE  ${count}
	\	${pos} =  Set variable   @{dev_details}[${index}]
	\ 	${dev_id} =  Set Variable   ${dev.mac_dict[${pos}][0]['serialid']}
	\	Exit For loop If   '${dev_id}' == '${serialid}'
	${dev_mac} =   Set Variable If   '${mac}' == 'none'   ${dev.mac_dict[${pos}][2]['mac']}   ${mac}
	Append To List   ${ResultList}   ${dev_mac}:${con_res}

Check Ping Status IPV6
	[Arguments]   ${ip}
	#SSHLibrary.Switch Connection   ${SCG_SSH_Connection}
  	${ping_data}=   Execute Scg command   ping6 ${ip}\n
	Log   ${ping_data}
	#--- 5 packets transmitted, 5 received
	${ping_data_match}   ${sent}   ${received} =   Run Keyword and Continue on Failure   should match regexp   ${ping_data}   ---\\s*(\\d+)\\s*packets\\s*transmitted\\s*,\\s*(\\d+)\\s+received
	${ping_sta}=   Run Keyword and Return Status   Should Not be Equal As Integers   ${received}   ${0}
	[return]    ${ping_sta}
Login SCG CLI dict
    ${SCG_SSH_Connection}=    SSHLibrary.Open Connection    ${SZ_MGMT_IP}
    set test variable   ${SCG_SSH_Connection}
    SSHLibrary.Login    ${SCG_HOSTNAME}    ${SZ_LOGIN_PWD}
    Sleep    5 sec
    SSHLibrary.Set Client Configuration    timeout=60 sec
    SSHLibrary.Read Until Regexp    .*>
    #robot_ssh.Write    enable
    #robot_ssh.Write    ${admin_enable_password}
    #robot_ssh.Read Until Regexp


Execute Scg command
    [Arguments]   ${cmd}
    Login SCG CLI dict
    SSHLibrary.Set Client Configuration    prompt=>
    Sleep  10s
    SSHLibrary.Write   ${cmd}
    ${data}=    SSHLibrary.Read Until Regexp    .*>
    SSHLibrary.Close connection
    [return]    ${data}
Check Ping Status
	[Arguments]   ${wlan_ip}
	${ping_source} =   Catenate    SEPARATOR=    ${ping_path}    ${ping_filename}
	Operating System.Create file    ${ping_source}
	${Permissions}=   Run   chmod -R 777 ${ping_source}
	${ping_status}=  Run    ping -c 4 ${wlan_ip}>${ping_source}
	${ping_data} =   Operating System.Get file   ${ping_source}
	#--- 4 packets transmitted, 4 received
	Log   ${ping_data}
	#${ping_data_match}   ${sent}   ${received}   should match regexp   ${ping_data}   ---\\s*(\\d+)\\s*packets\\s*transmitted\\s*,\\s*(\\d+)\\s+received
	${ping_data_match}   ${sent}   ${received} =   Run Keyword and Continue on Failure   should match regexp   ${ping_data}   ---\\s*(\\d+)\\s*packets\\s*transmitted\\s*,\\s*(\\d+)\\s+received

	${ping_sta}=   Run Keyword and Return Status   Should Not be Equal As Integers   ${received}   ${0}
	[return]    ${ping_sta}
DHCP Variable Initialization
    Set test variable   ${dhcp_server_handle}   ${EMPTY}

KILLALL TCPdump
	do_shell_cmd   killall tcpdump
	${kill_cmd}=  Set Variable    pkill tcpdump
	run keyword if   '${dhcp_server_handle}'!='${EMPTY}'   SSHLibrary.Switch Connection   ${dhcp_server_handle}
    	run keyword if   '${dhcp_server_handle}'!='${EMPTY}'   SSHLibrary.write   ${kill_cmd}
    	run keyword if   '${dhcp_server_handle}'!='${EMPTY}'   SSHLibrary.Close Connection

Check Wlan List
    [Arguments]   ${context}
    AP Login If Necessary   ${AP_IP}
    ${output}=  apcli.send  get wlanlist
    AP Logout If Necessary
    [Return]    ${output}

DORA Process Keyword
    	APCLI Create and Save Context OK   ${AP_IP}  23  ${SCG_HOSTNAME}  ${AP_PASSWORD}
	${source_mac_5G}=    RWQAAPCLIKeywords.get_wlan_bssid_via_ssid  ${WLAN}   5G
	${cli_output}=    Check Wlan List    qaAPCLI
	${wlan_id}   ${wlan_interface}=   should match regexp   ${cli_output}   (wlan\\d+)\\s*up.*${WLAN}\\s*
	Log   ${cli_output}
	Log   Associating STA
	${dhcp_server_handle}=   SSHLibrary.Open Connection   ${DHCP_SERVER_IP}   prompt=#
    	SSHLibrary.Login    ${DHCP_SERVER_USR}   ${DHCP_SERVER_PWD}
        ${cmd}=  Set Variable    ifconfig
    	SSHLibrary.write   ${cmd}
    	${ifconfig_Response}=   SSHLibrary.readuntilprompt
    	${ens_details}    ${ens}=   should match regexp   ${ifconfig_Response}   (ens\\d+):\\s+f
    	Log   ${ens}
    	${tcpdump_cmd}=    set variable   nohup tcpdump -i ${ens} -w ${get_dhcp_capture_filename} &\n
    	SSHLibrary.write   ${tcpdump_cmd}
	do_shell_cmd   nohup tcpdump -i ${wlan_interface} -w /writable/${get_capture_filename} &
	Run Keyword and Continue on Failure    Connect STA
    	sleep   10s
	SSHLibrary.readuntilprompt
	${kill_cmd}=  Set Variable    pkill tcpdump
    	SSHLibrary.write   ${kill_cmd}
    	SSHLibrary.readuntilprompt
    	SSHLibrary.get file   ${get_dhcp_capture_filename}   /opt/tftpboot/
	
    	do_shell_cmd   killall tcpdump	  
    	download_file_to_ap   ${TE_IP}  ${TE_USERNAME}  ${TE_PASSWORD}  /writable/${get_capture_filename}  /opt/tftpboot
	@{client_mac}=    Get Dictionary Keys   ${device_dict}
	

	:For   ${m}  in   @{client_mac}
	\	Log   ${m}
    	\	Filter_pcap    file_pcap=/opt/tftpboot/${get_capture_filename}    filter_pcap=/opt/tftpboot/${filter_capture_filename}   read_filter=(bootp.hw.mac_addr==${m})
	\	${dataframe_pdml_buf}=    Get Pdml Buffer From Pcap    pcap_file=/opt/tftpboot/${filter_capture_filename}    pdml_file=/opt/tftpboot/${capxml_filename}    ppcap_read_filter=bootp_clientmac==${m}
	\	${ap_parsed_data}=    check_for_dora_process    pdmlbuf=${dataframe_pdml_buf}    bootp_clientmac=${m}
	\	Log    ${ap_parsed_data}	
	\	${ap_disc_length}=   get length    ${ap_parsed_data['discoverypackets']}
	\	${ap_offer_length}=   get length    ${ap_parsed_data['offer']}
	\	${ap_request_length}=   get length    ${ap_parsed_data['request']}
	\	${ap_ack_length}=   get length    ${ap_parsed_data['ack']}
	\	${AP_DORA_RESULT}=   set variable if    ${ap_disc_length}==${AP_PKT_CNT[0]} and ${ap_offer_length}==${AP_PKT_CNT[1]} and ${ap_request_length}==${AP_PKT_CNT[2]} and ${ap_ack_length}==${AP_PKT_CNT[3]}   PASS   FAIL
	\	Filter_pcap    file_pcap=/opt/tftpboot/${get_dhcp_capture_filename}    filter_pcap=/opt/tftpboot/${filter_dhcpcap_filename}   read_filter=(bootp.hw.mac_addr==${m})
	\	${dhcp_dataframe_pdml_buf}=    Get Pdml Buffer From Pcap    pcap_file=/opt/tftpboot/${filter_dhcpcap_filename}    pdml_file=/opt/tftpboot/${capxml_dhcp_filename}    ppcap_read_filter=bootp_clientmac==${m}
	\	${dhcp_parsed_data}=    check_for_dora_process    pdmlbuf=${dhcp_dataframe_pdml_buf}    bootp_clientmac=${m}
	\	${dhcp_disc_length}=   get length    ${dhcp_parsed_data['discoverypackets']}
	\	${dhcp_offer_length}=   get length    ${dhcp_parsed_data['offer']}
	\	${dhcp_request_length}=   get length    ${dhcp_parsed_data['request']}
	\	${dhcp_ack_length}=   get length    ${dhcp_parsed_data['ack']}
	\	${DHCP_DORA_RESULT}=   set variable if    ${dhcp_disc_length}==${DHCP_PKT_CNT[0]} and ${dhcp_offer_length}==${DHCP_PKT_CNT[1]} and ${dhcp_request_length}==${DHCP_PKT_CNT[2]} and ${dhcp_ack_length}==${DHCP_PKT_CNT[3]}   PASS   FAIL
	\	${DORA_RESULT}=   set variable if    '${AP_DORA_RESULT}'=='PASS'   PASS   FAIL
	\       Append To List   ${ResultList}   ${m}:${DORA_RESULT}
	
	
Convert MAC To Lower Case
	[Arguments]   ${wlan_mac}
	${wlan_mac} =   String.Replace String Using Regexp   ${wlan_mac}   [A]   a
	${wlan_mac} =   String.Replace String Using Regexp   ${wlan_mac}   [B]   b
	${wlan_mac} =   String.Replace String Using Regexp   ${wlan_mac}   [C]   c
	${wlan_mac} =   String.Replace String Using Regexp   ${wlan_mac}   [D]   d
	${wlan_mac} =   String.Replace String Using Regexp   ${wlan_mac}   [E]   e
	${wlan_mac} =   String.Replace String Using Regexp   ${wlan_mac}   [F]   f
	${wlan_mac} =   String.Replace String Using Regexp   ${wlan_mac}   [N]   n
	${wlan_mac} =   String.Replace String Using Regexp   ${wlan_mac}   [O]   o
	${wlan_mac} =   String.Replace String Using Regexp   ${wlan_mac}   [M]   m
	[return]    ${wlan_mac}


Connect STA

	${connect} =  Run   python ${RootTarget}/../ioT_devicemgr/devicemgr.py -c ${RootTarget}/../ioT_devicemgr/device_cfg.json -a connect -t 500 -p -d
	Log   ${connect}
	Should Not Contain   ${connect}   Traceback
        Should Not Contain   ${connect}   ERROR   ignore_case=False  
	#Should Not Contain   ${connect}   error  
	#List Should Not Contain Value    [Traceback, ERROR]   ${connect}

Generate External DPSK
	${key} =   Run   python ${RootTarget}/../ioT_devicemgr/GenerateExternalDpsk.py
	Log    ${key}
	${res} =   Get lines Containing String    ${key}    EDPSK key
	Log    ${res}
	${ext_dpsk1} =  Get Substring   ${res}   11
        ${ext_dpsk} =  Remove string   ${ext_dpsk1}   ${SPACE}
	Log    ${ext_dpsk}
	[return]    ${ext_dpsk}

#Niveditha-For 11n protection cases
Connect Non HT STA
	${status} =    Run   python ${RootTarget}/../ioT_devicemgr/ConnectNonHTClient.py -a connect
	Log    ${status}

Disconnect Non HT STA
	${status} =    Run   python ${RootTarget}/../ioT_devicemgr/ConnectNonHTClient.py -a disconnect
	Log    ${status}

Connect STA and Verify Application Deny

	${connect} =  Run   python ${RootTarget}/../ioT_devicemgr/devicemgr.py -c ${RootTarget}/../ioT_devicemgr/device_cfg.json -a connect -t 500 -p -d
	Log   ${connect}
	Should Not Contain   ${connect}   Traceback
        Should Contain   ${connect}   ERROR   ignore_case=False  

Get Status 
	Remove File   ${RootTarget}/../ioT_devicemgr/status.json
	${status} =   Run   python ${RootTarget}/../ioT_devicemgr/devicemgr.py -c ${RootTarget}/../ioT_devicemgr/device_cfg.json -p -a status -o ${RootTarget}/../ioT_devicemgr/status.json -t 500 -d
	Log   ${status} 
	Should not Contain    ${status}    Traceback   
   	Should Not Contain   ${status}   ERROR   ignore_case=False
	#List Should Not Contain Value    [Traceback, ERROR]   ${status}

Start TCP iPerf Client 
	[Arguments]    ${traffic}   ${traffic_direction}   ${timeout}   ${SERVER_ADDR}=${APPIUM_IP}
	${iperf_status} =   Run   python ${RootTarget}/../ioT_devicemgr/devicemgr.py -c ${RootTarget}/../ioT_devicemgr/device_cfg.json -a iperftraffic -i start -ip ${SERVER_ADDR} -b ${traffic} -td ${traffic_direction} -to ${timeout} -d
	Log   ${iperf_status}
	${res} =   Get lines Containing String    ${iperf_status}    Iperf Result 
	Log    ${res}
	${val} =    run keyword and return status    Should Not Be Empty   ${res}
	Run keyword if   ${val}     Evaluate IPerf Output   ${res}

Start UDP iPerf Client 
	[Arguments]    ${traffic}   ${traffic_direction}   ${timeout}  ${bandwidth}=1000M   ${SERVER_ADDR}=${APPIUM_IP}
	${iperf_status} =   Run   python ${RootTarget}/../ioT_devicemgr/devicemgr.py -c ${RootTarget}/../ioT_devicemgr/device_cfg.json -a iperftraffic -i start -ip ${SERVER_ADDR} -b ${traffic} -td ${traffic_direction} -to ${timeout} -bw ${bandwidth} -d
	Log   ${iperf_status} 
	${res} =   Get lines Containing String    ${iperf_status}    Iperf Result 
	Log    ${res}
	${val} =    run keyword and return status    Should Not Be Empty   ${res}
	Run keyword if   ${val}     Evaluate IPerf Output   ${res}

Stop iPerf Client
	[Arguments]    ${traffic_direction}=upstream
	${iperf_status} =   Run   python ${RootTarget}/../ioT_devicemgr/devicemgr.py -c ${RootTarget}/../ioT_devicemgr/device_cfg.json -a iperftraffic -i stop -td ${traffic_direction}
	Log   ${iperf_status} 
	Should not Contain    ${iperf_status}    Traceback   
   	Should Not Contain   ${iperf_status}   ERROR

Start iperf Console
	[Arguments]     ${APPIUM_IP}   ${APPIUM_UNAME}    ${APPIUM_PWD}   ${traffic}    ${traffic_direction}=downstream   ${bandwidth}=1000M
	${stdout} =   Run   python ${RootTarget}/../ioT_devicemgr/devicemgr.py -c ${RootTarget}/../ioT_devicemgr/device_cfg.json -a iperftraffic -i start -b ${traffic} -td ${traffic_direction} -bw ${bandwidth} -ip ${APPIUM_IP} -us ${APPIUM_UNAME} -ps ${APPIUM_PWD} -d
	Log   ${stdout}

Kill iPerf Console
	[Arguments]     ${APPIUM_IP}   ${APPIUM_UNAME}    ${APPIUM_PWD}   ${traffic_direction}=downstream 
	${stdout} =   Run   python ${RootTarget}/../ioT_devicemgr/devicemgr.py -c ${RootTarget}/../ioT_devicemgr/device_cfg.json -a iperftraffic -i stop -td ${traffic_direction} -ip ${APPIUM_IP} -us ${APPIUM_UNAME} -ps ${APPIUM_PWD} -d
	Log   ${stdout}
	${res} =   Get lines Containing String    ${stdout}    Iperf Result 
	Log    ${res}
	${val} =    run keyword and return status    Should Not Be Empty   ${res}
	Run keyword if   ${val}     Evaluate IPerf Output   ${res}

Evaluate IPerf Output
	[Arguments]    ${res}
	${result} =   Get Substring   ${res}   15   37 
	Append To List    ${ResultList}   ${result}
	${result} =   Get Substring   ${res}   53
	Append To List    ${ResultList}   ${result}
	Log    ${result}

Start Chariot
	[Arguments]   ${traffic}=None
	${chariot_status} =   Run   python ${RootTarget}/../ioT_devicemgr/devicemgr.py -c ${RootTarget}/../ioT_devicemgr/device_cfg.json -a chariotendpoint -e start -b ${traffic} -s ${streamtime} -t 500 -d
	Log   ${chariot_status} 
	Should not Contain    ${chariot_status}    Traceback   
   	Should Not Contain   ${chariot_status}   ERROR

# From device mgr tool
Start Chariot Console1
	[Arguments]   ${ip_list}   ${traffic}   ${timeout}
	${console_status} =   Run   python ${RootTarget}/../ioT_devicemgr/devicemgr.py -c ${RootTarget}/../ioT_devicemgr/device_cfg.json -a startchariotconsole -b ${traffic} -s ${timeout} -n ${ip_list} -x console -t 500 -d
	Log   ${console_status}
	Should not Contain    ${console_status}    Traceback
   	Should Not Contain   ${console_status}   ERROR
	

Chariot Console
	[Arguments]      ${APPIUM_IP}   ${APPIUM_UNAME}    ${APPIUM_PWD}   ${traffic}   ${ip_list}   ${timeout}
	${stdout}= 	start_chariot_console 	${APPIUM_IP}   ${APPIUM_UNAME}    ${APPIUM_PWD}   ${traffic}   ${ip_list}   ${timeout}
	[return]   ${stdout}
	

Clear Chrome Browser History
	${clear_status} =   Run   python ${RootTarget}/../ioT_devicemgr/devicemgr.py -c ${RootTarget}/../ioT_devicemgr/device_cfg.json -a clearhistory -g clear -t 300 
	Log   ${clear_status} 
	Should not Contain    ${clear_status}    Traceback   
   	Should Not Contain   ${clear_status}   ERROR
	

Youtube Stream
	[Arguments]    ${streamtime}
	${stream} =    	Run   python ${RootTarget}/../ioT_devicemgr/devicemgr.py -c ${RootTarget}/../ioT_devicemgr/device_cfg.json -a youtubestream -y play -s ${streamtime} -t 600 -d 
	Log   ${stream}
	Should not Contain    ${stream}    Traceback   
   	Should Not Contain   ${stream}   ERROR

Get Ping Status
	[Arguments]   ${ip}=${AP_IP}    ${timeout}=${PING_TIMEOUT}
	${ping_status} =   Run   python ${RootTarget}/../ioT_devicemgr/devicemgr.py -c ${RootTarget}/../ioT_devicemgr/device_cfg.json -a ping -n ${ip} -t 300 -s ${timeout} -d
	Log   ${ping_status}
	Should Contain    ${ping_status}    Traceback

Get Connectivity Status of iOS STA
	${status} =   Run   python ${RootTarget}/../ioT_devicemgr/devicemgr.py -c ${RootTarget}/../ioT_devicemgr/device_cfg.json -a status -o ${RootTarget}/../ioT_devicemgr/status.json -t 300 
	Log   ${status}

Disconnect STA
	${disconnect} =  Run    python ${RootTarget}/../ioT_devicemgr/devicemgr.py -c ${RootTarget}/../ioT_devicemgr/device_cfg.json -p -a disconnect -t 300 -d
	Log    ${disconnect}
	Should Not Contain   ${disconnect}   Traceback
        Should Not Contain   ${disconnect}   ERROR
	#List Should Not Contain Value    [Traceback, ERROR]   ${disconnect}

Show disconnect status  
	[Arguments]    ${ssid}=None   ${auth}=None    ${con_status}=None
	Should Be Equal   ${ssid}   NA  
	Should Be Equal   ${auth}   NA
	Should Be Equal   ${con_status}   disconnected

Show connect status  
	[Arguments]    ${ssid}=None   ${auth}=None    ${con_status}=None
	Should Be Equal   ${ssid}   ${WLAN}
	Should Contain Match   [Open,WPA2,MIXED,8021x,CP,GA,WEB]   ${auth}   
	Should Be Equal   ${con_status}   connected

Join STA to Open Network

        [Arguments]   ${TYPE}   ${WLAN}  
        ${err} =   Execute Command   /cygdrive/c/Python27/python.exe multiple_arg.py -n ${TYPE} -s ${WLAN}   stderr
	#${err} =   Execute Command   /cygdrive/c/Python27/python.exe and_connectivity.py -n ${TYPE} -s ${WLAN}   stderr
        Should Be Empty    ${err}

Join STA to WPA-PSK Network

	[Arguments]   ${TYPE}   ${WLAN}   ${PSKKEY}   ${FLAG}
	${err} =  Execute Command  /cygdrive/c/Python27/python.exe multiple_arg.py -n ${TYPE} -s ${WLAN} -k ${PSKKEY} -f ${FLAG}  stderr
        Should Be Empty    ${err}

Join STA to WEP Network

	[Arguments]   ${TYPE}   ${WLAN}   ${WEP_KEY}
        #${err} =  Execute Command  /cygdrive/c/Python27/python.exe and_connectivity.py -n ${TYPE} -s ${WLAN} -k ${WEP_KEY}  stderr
	${err} =  Execute Command  /cygdrive/c/Python27/python.exe multiple_arg.py -n ${TYPE} -s ${WLAN} -k ${WEP_KEY}  stderr
        Should Be Empty    ${err}

Disconnect STA from Network

	Login To Remote PC
	${err} =  Execute Command   /cygdrive/c/Python27/python.exe multiple_disconnect.py ${WLAN}   stderr
        Should Be Empty    ${err}


Join STA to 802.1x Network

        [Arguments]   ${TYPE}   ${WLAN}   ${AAA_USER}   ${AAA_PWD}
        #${err} =   Execute Command   /cygdrive/c/Python27/python.exe and_connectivity.py -n ${TYPE} -s ${WLAN} -u ${AAA_USER} -p ${AAA_PWD}   stderr
	${err} =   Execute Command   /cygdrive/c/Python27/python.exe multiple_arg.py -n ${TYPE} -s ${WLAN} -u ${AAA_USER} -p ${AAA_PWD}   stderr
        Should Be Empty    ${err}

Join STA to MacAuth Network

        [Arguments]   ${TYPE}   ${WLAN}   
        #${err} =   Execute Command   /cygdrive/c/Python27/python.exe and_connectivity.py -n ${TYPE} -s ${WLAN} -u ${AAA_USER} -p ${AAA_PWD}   stderr
	${err} =   Execute Command   /cygdrive/c/Python27/python.exe multiple_arg.py -n ${TYPE} -s ${WLAN}   stderr
        Should Be Empty    ${err}


Connect STA and Do Guest Auth with fixed redirection

	[Arguments]    ${NTYPE}   ${WLAN}   ${AUTH}   ${TYPE}   ${URL_VAL_DATA}   ${GUEST_KEY}
	${err}=  Execute Command  /cygdrive/c/Python27/python.exe GA_SCG.py -nw ${NTYPE} -s ${WLAN} -a ${AUTH} -sf ${TYPE} -d ${URL_VAL_DATA} -g ${GUEST_KEY}   stderr
	Should Be Empty    ${err}

Connect STA and Do Guest Auth

	[Arguments]    ${NTYPE}   ${WLAN}   ${AUTH}   ${TYPE}   ${URL}   ${URL_VAL_DATA}   ${GUEST_KEY}
	${err}=  Execute Command  /cygdrive/c/Python27/python.exe multiple_auth.py -nw ${NTYPE} -s ${WLAN} -a ${AUTH} -sf ${TYPE} -u ${URL} -d ${URL_VAL_DATA} -g ${GUEST_KEY}   stderr
        Should Be Empty    ${err}

Connect STA and Do Wispr Auth with fixed redirection

        [Arguments]    ${NTYPE}   ${WLAN}   ${AUTH}   ${TYPE}   ${URL_VAL_DATA}   ${AAA_UNAME}   ${AAA_PWD}   ${IP}
        #${err}=  Execute Command  /cygdrive/c/Python27/python.exe GA_SCG.py -nw ${NTYPE} -s ${WLAN} -a ${AUTH} -sf ${TYPE} -d ${URL_VAL_DATA} -n ${AAA_UNAME} -p ${AAA_PWD} -i ${IP}   stderr
	${err}=  Execute Command  /cygdrive/c/Python27/python.exe multiple_auth.py -nw ${NTYPE} -s ${WLAN} -a ${AUTH} -sf ${TYPE} -d ${URL_VAL_DATA} -n ${AAA_UNAME} -p ${AAA_PWD} -i ${IP}   stderr
        Should Be Empty    ${err}


Connect STA and Do Wispr Auth with walled garden

	 [Arguments]    ${NTYPE}   ${WLAN}   ${AUTH}   ${TYPE}   ${URL}   ${URL_VAL_DATA}  
        ${err}=  Execute Command  /cygdrive/c/Python27/python.exe multiple_auth.py -nw ${NTYPE} -s ${WLAN} -a ${AUTH} -sf ${TYPE} -u ${URL} -d ${URL_VAL_DATA}   stderr
	Should Be Empty    ${err}

Connect STA and Do Wispr Auth

	[Arguments]    ${NTYPE}   ${WLAN}   ${AUTH}   ${TYPE}   ${URL}   ${URL_VAL_DATA}   ${AAA_UNAME}   ${AAA_PWD}   ${IP}
	${err}=  Execute Command  /cygdrive/c/Python27/python.exe multiple_auth.py -nw ${NTYPE} -s ${WLAN} -a ${AUTH} -sf ${TYPE} -u ${URL} -d ${URL_VAL_DATA} -n "${AAA_UNAME}" -p ${AAA_PWD} -i ${IP}   stderr
        Should Be Empty    ${err}


Connect STA and Do Web Auth with fixed redirection

        [Arguments]    ${NTYPE}   ${WLAN}   ${AUTH}   ${TYPE}   ${URL_VAL_DATA}   ${AAA_UNAME}   ${AAA_PWD}   ${IP}
        ${err}=  Execute Command  /cygdrive/c/Python27/python.exe multiple_auth.py -nw ${NTYPE} -s ${WLAN} -a ${AUTH} -sf ${TYPE} -d ${URL_VAL_DATA} -n ${AAA_UNAME} -p ${AAA_PWD} -i ${IP}    stderr
        Should Be Empty    ${err}


Connect STA and Do Web Auth

        [Arguments]    ${NTYPE}   ${WLAN}   ${AUTH}   ${TYPE}   ${URL}   ${URL_VAL_DATA}   ${AAA_UNAME}   ${AAA_PWD}   ${IP}
        ${err}=  Execute Command  /cygdrive/c/Python27/python.exe GA_SCG.py -nw ${NTYPE} -s ${WLAN} -a ${AUTH} -sf ${TYPE} -u ${URL} -d ${URL_VAL_DATA} -n "${AAA_UNAME}" -p ${AAA_PWD} -i ${IP}    stderr
        Should Be Empty    ${err}
      

Connect STA and Do Wispr Mac-by-pass Auth

        [Arguments]    ${NTYPE}   ${WLAN}   ${AUTH}   ${URL}   ${URL_VAL_DATA}
        ##${err}=  Execute Command  /cygdrive/c/Python27/python.exe GA_SCG.py -nw ${NTYPE} -s ${WLAN} -a ${AUTH} -u ${URL} -d ${URL_VAL_DATA}    stderr
	${err}=  Execute Command  /cygdrive/c/Python27/python.exe GA_SCG.py -nw ${NTYPE} -s ${WLAN} -a ${AUTH} -u ${URL} -d ${URL_VAL_DATA}    stderr
        Should Be Empty    ${err}


Login to Radius PC

	SSHLibrary.Open Connection   ${AAA_IP}
        SSHLibrary.Login   ${AAA_PC_USER}   ${AAA_PC_PWD}
        SSHLibrary.Write   echo Remote RADIUS Login
	${output}=   SSHLibrary.Read Until   Login
	

Get MACADDR of clients and add to Radius

	${status} =   Run   python ${RootTarget}/../ioT_devicemgr/devicemgr.py -c ${RootTarget}/../ioT_devicemgr/device_cfg.json -p -a status -o ${RootTarget}/../ioT_devicemgr/status.json -t 500   
	Log   ${status} 
	Should not Contain    ${status}    Traceback

	@{mac} =  Get MacAddr Of Clients

	Login to Radius PC
	:For   ${m}  in   @{mac}
	\	Log   ${m}
	\	SSHLibrary.Execute Command    echo ${m} Cleartext-Password := \\"${m}\\" >> ${AAA_PATH}/authorize
	SSHLibrary.Execute Command    killall ${AAA_NAME}
	SSHLibrary.Start Command    ${AAA_NAME} -xX > /home/mac1.txt


Get MACADDR of clients and add edpsk entries to Radius
	
	[Arguments]     ${edpsk}
	${len} =   Get Length   ${dev_details}
	${mac} =   Create List
	:For   ${d}   IN RANGE   0   ${len}
	\	${pos} =  Set variable   @{dev_details}[${d}]
	\	Append To list   ${mac}   ${dev.mac_dict[${pos}][2]['mac']}
	Log    ${mac}
	#@{mac} =  Get MacAddr Of Clients
	Login to Radius PC
	:For   ${m}  in   @{mac}
	\	Log   ${m}
	\	SSHLibrary.Write    sed -e "/${m} Cleartext-Password := /Id" ${AAA_PATH}/authorize
	\       ${m} =    Convert MAC To Lower Case   ${m}
	\	${m1} =    Remove String   ${m}   :   
	\	SSHLibrary.Write    sed -i "/${m1} Cleartext-Password := /d" ${AAA_PATH}/authorize

	:For   ${m}  in   @{mac}
	\	Log   ${m}
	\	${m} =    Convert MAC To Lower Case   ${m}
	\	${m1} =     Remove String   ${m}   :   
	\	SSHLibrary.Write    sed -i "/${m1} User-Password:=/,+2d" ${AAA_PATH}/authorize

	#@{mac} =  Get MacAddr Of Clients
	Login to Radius PC
	:For   ${m}  in   @{mac}
	\	Log   ${m}
	\	${m} =    Convert MAC To Lower Case   ${m}
	\	${m1} =    Remove String   ${m}   :  
	\	SSHLibrary.Execute Command    echo ${m1} Cleartext-Password:=${m1}$'\n\t'Ruckus-Dpsk=0x00${edpsk} >> ${AAA_PATH}/authorize
	SSHLibrary.Execute Command    killall ${AAA_NAME}
	SSHLibrary.Start Command    ${AAA_NAME} -xX > /home/mac1.txt


Get MACADDR of clients and remove edpsk entries to Radius
	@{mac} =  Get MacAddr Of Clients
	Login to Radius PC
	:For   ${m}  in   @{mac}
	\	SSHLibrary.Write   sed -i 'N;$!P;$!D;$d' ${AAA_PATH}/authorize

	#Adding mac auth entries at the end of test case
	Login to Radius PC
	:For   ${m}  in   @{mac}
	\	Log   ${m}
	\	${m} =    Convert MAC To Lower Case   ${m}
	\	${m1} =    Remove String   ${m}   :   
	\	SSHLibrary.Execute Command    echo ${m1} Cleartext-Password := \\"${m1}\\" >> ${AAA_PATH}/authorize
	SSHLibrary.Execute Command    killall ${AAA_NAME}
	SSHLibrary.Start Command    ${AAA_NAME} -xX > /home/mac1.txt


Get MACADDR of clients and check in Radius

	${status} =   Run   python ${RootTarget}/../ioT_devicemgr/devicemgr.py -c ${RootTarget}/../ioT_devicemgr/device_cfg.json -p -a status -o ${RootTarget}/../ioT_devicemgr/status.json -t 500 
	Log   ${status} 
	Should not Contain    ${status}    Traceback

	@{mac} =  Get MacAddr Of Clients

	Login to Radius PC
	:For   ${m}  in   @{mac}
	\	Log   ${m}
	\	${out} =  SSHLibrary.Execute command   sudo sed -i"users" "/${m}/d" ${AAA_PATH}/authorize

	SSHLibrary.Execute Command    killall ${AAA_NAME}
	SSHLibrary.Start Command    ${AAA_NAME} -xX > /home/mac1.txt

	

Remove client mac details from Radius

	@{mac} =  Get MacAddr Of Clients
	Login to Radius PC
	:For   ${m}  in   @{mac}
	\	SSHLibrary.Write   sed -i '$d' ${AAA_PATH}/authorize
	
 
Setup device for validating single guest pass use
	
	Execute Command   sed -i "3,$d" connected_dev.txt

Get MacAddr Of Clients
	
	${json}=  OperatingSystem.Get file  ${RootTarget}/../ioT_devicemgr/status.json
	${object}=  Evaluate  json.loads('''${json}''')  json
	Log   ${object["devices"]}

	${count} =  Get Length    ${object["devices"]}  
	Log   ${count} 
	@{wlan_maclist}=   Create List
	:FOR   ${d}   IN Range  0   ${count}
	\	${wlan_mac} =  Get From Dictionary   ${object["devices"][${d}]}   wlan_mac
	\	Append To List  ${wlan_maclist}    ${wlan_mac}
	[return]    ${wlan_maclist}

Get Devicetype Of Clients
	
	${json}=  OperatingSystem.Get file  ${RootTarget}/../ioT_devicemgr/device_cfg.json
	${object}=  Evaluate  json.loads('''${json}''')  json
	Log   ${object["devices"]}

	${count} =  Get Length    ${object["devices"]}  
	Log   ${count} 
	@{devtype_list}=   Create List
	:FOR   ${d}   IN Range  0   ${count}
	\	${devtype} =  Get From Dictionary   ${object["devices"][${d}]}   device_type
	\	Append To List  ${devtype_list}    ${devtype}

	[return]    ${devtype_list}

Get Chariot PC IPAddress
	
	${json}=  OperatingSystem.Get file  ${RootTarget}/../ioT_devicemgr/device_cfg.json
	${object}=  Evaluate  json.loads('''${json}''')  json
	Log   ${object["devices"]}

	${count} =  Get Length    ${object["devices"]}  
	Log   ${count} 
	@{ip_list}=   Create List
	:FOR   ${d}   IN Range  0   ${count}
	\	${ip} =  Get From Dictionary   ${object["devices"][${d}]}   device_eth_ip
	\	Append To List  ${ip_list}    ${ip}

	[return]    ${ip_list}


Get IPAddr Of Clients
	
	${json}=  OperatingSystem.Get file  ${RootTarget}/../ioT_devicemgr/status.json
	${object}=  Evaluate  json.loads('''${json}''')  json
	Log   ${object["devices"]}

	${count} =  Get Length    ${object["devices"]}  
	Log   ${count} 
	@{wlan_iplist}=   Create List
	:FOR   ${d}   IN Range  0   ${count}
	\	${wlanip} =  Get From Dictionary   ${object["devices"][${d}]}   wlan_ip
	\	Append To List  ${wlan_iplist}    ${wlanip}

	[return]    ${wlan_iplist}

Get Ios Device Name 
	${json}=  OperatingSystem.Get file  ${RootTarget}/../ioT_devicemgr/device_cfg.json
	${object}=  Evaluate  json.loads('''${json}''')  json
	Log   ${object["devices"]}

	${count} =  Get Length    ${object["devices"]}  
	Log   ${count} 
	@{ios_devicename}=   Create List
	:FOR   ${d}   IN Range  0   ${count}
	\	${device_name} =  Get From Dictionary   ${object["devices"][${d}]}   ios_devicename
	\	Run Keyword If    '${device_name}' == 'None'   Continue For Loop
	\	Append To List  ${ios_devicename}    ${device_name}

	[return]    ${ios_devicename}
	
	
	
Get Client Fingerprint Details

	[Arguments]    ${fingerprint_status}=None        
        ${client-mac}=   Get MacAddr Of Clients
	${ios_devicename}=   Get Ios Device Name
	Log   ${client-mac}
        ${index}=  Convert to Integer   0
        ${urlParams}=   Create Dictionary   apMac=${AP_MACC[0]}
        ${clients_data}=   aps get clients   urlParams=${urlParams}
        Log   ${clients_data}


        #${c}=   Get Dictionary Values   ${clients}
        #Log   ${c}

	${clients} =  Set Variable   ${clients_data['list']}
	Log    ${clients}

	${client_count} =  Get Length   ${clients}
        
	:FOR   ${index}   IN RANGE   ${client_count}

        \	${i}=   Get From List  ${clients}   ${index}
        \       Log   ${i}

        \	${mac} =  Set Variable   ${i['mac']}
	\       Log   ${mac}
	\	${status}  ${value} =   Run Keyword and ignore error    List Should Contain Value   ${client-mac}   ${mac}
	\	Log    ${status}
	\	Run Keyword If    '${status}' == 'FAIL'     Continue For Loop
        \       ${os}=   Get From Dictionary   ${i}   osType
	\	${lowercase_mac}=   Convert MAC to Lower Case   ${mac}
	\	${os_sta}=   set variable if   '${os}'!='Unknown'   PASS   FAIL
	\	${os_sta_uncheck}=   set variable if   '${os}'=='Unknown'   PASS   FAIL  		
        \       ${host-name}=   Get From Dictionary   ${i}   hostName
        \       ${mac}=   Get From Dictionary   ${i}   mac
	\       ${stats}  ${vale} =   Run keyword and ignore error   should contain    ${os}    Windows  
	\	Run Keyword If	  '${fingerprint_status}' == 'unchecked'   Append To List   ${ResultList}   ${lowercase_mac}:${os_sta_uncheck}   
	\	...                ELSE   Append To List   ${ResultList}   ${lowercase_mac}:${os_sta}
	\	Run Keyword If   '${fingerprint_status}' == 'unchecked'   
	\	...	Run Keyword and continue on Failure   Check fingerprint uncheck details of client   ${os}   ${host-name}
	\	Run Keyword If   '${fingerprint_status}' == 'None' and '${os}' == 'Android'      
	\	...	Run Keyword and continue on Failure   Should Not Be True    '${host-name}'=='${None}'
	\	Run Keyword If   '${fingerprint_status}' == 'None' and '${os}' == 'iOS'   
	\	...	Run Keyword and continue on Failure   List Should Contain Value    ${ios_devicename}   ${host-name}
	\	Run Keyword If   '${fingerprint_status}' == 'None' and '${os}' == 'Mac'
	\	...	Run Keyword and continue on Failure   Should Not Be Empty   ${host-name}
	\	Run Keyword If    '${stats}' == 'PASS' and '${fingerprint_status}' == 'None'    
	\	...	Run Keyword and continue on Failure   Should Not Be True    '${host-name}'=='${None}'

Check fingerprint uncheck details of client
        [Arguments]   ${os}   ${host-name}
	Should Contain   ${os}   Unknown   
	Should Be True    '${host-name}'=='${None}' or '${host-name}'=='N/A'

Check STA Authorization Status  
	
	[Arguments]   ${client_wlan_mac}    ${sta_status}=UNAUTHORIZED     ${APMAC}=${AP_MACC[0]}
	${client-mac}=   Get MacAddr Of Clients
	${ios_devicename}=   Get Ios Device Name
	Log   ${client-mac}
        ${index}=  Convert to Integer   0
        ${urlParams}=   Create Dictionary   apMac=${APMAC}
        ${clients_data}=   aps get clients   urlParams=${urlParams}
        Log   ${clients_data}
	${client_list}=  get_obj_by_key_in_list   ${clients_data['list']}  key=mac  value=${client_wlan_mac}
	#Log   ${client_list['status']}
	${auth_status}=    Run Keyword if   "${client_list}"!="None"   set variable   ${client_list['status']}
	${status}  ${value} =   Run Keyword and ignore error    List Should Contain Value   ${client-mac}   ${client_wlan_mac}
	Run Keyword If   '${sta_status}' == 'UNAUTHORIZED'
	...	Run Keyword
	...	Should Be Equal   ${auth_status}   UNAUTHORIZED
	Run Keyword If   '${sta_status}' == 'AUTHORIZED'
	...	Run Keyword
	...	Should Be Equal   ${auth_status}   AUTHORIZED

Check STA Connectivity

	${d} =  Execute Command    cat connected_dev.txt
	@{devices} =  Split to Lines   ${d}
	:For   ${dev}  in   @{devices}
	\	Write   cat ${dev}_result.txt
	\	Run Keyword and Continue On Failure   Read Until   Pass   
	 	
	
Check STA Connectivity for FDHCP

	Write   cat result.txt
	Read Until   Fail


Check Auth Success

	${d} =  Execute Command    cat connected_dev.txt
	@{devices} =  Split to Lines   ${d}
	:For   ${dev}  in   @{devices}
	\	Write   cat ${dev}_auth_result.txt
	\	Run Keyword and Continue On Failure   Read Until   Pass 

Check Single Guest Auth Success

	${d} =  Execute Command    cat connected_dev.txt
	@{devices} =  Split to Lines   ${d}
	Write   cat @{devices}[0]
	${output} =  Read
	Run Keyword if   '${output}' != 'Fail'  
	...    Run Keywords 
	...    Write   cat @{devices}[1]
	...    Read Until   Fail

Check Session Timeout Success

	Write   cat session_result.txt
        Read Until   Pass

Check Grace Period Success

	Write   cat grace_result.txt
        Read Until   Pass

Check Ping Success after Auth

	Write   cat ping_result1.txt
        Read Until   Pass
	
	
Check Ping Failure before Auth

	Write   cat ping_result.txt
        Read Until   Fail

Check Walled Garden Success

        Write   cat walled_result.txt
        Read Until   Pass


Check page details
	
	[Arguments]    ${URL}   
	${d} =  Execute Command    cat connected_dev.txt
	@{devices} =  Split to Lines   ${d}
	:For   ${dev}  in   @{devices}
	\	Write   cat ${dev}_webpage_log.txt
	\	Run Keyword and Continue On Failure   Read Until   ${URL}   
	#Write   cat webpage_log.txt
 	#Read Until   ${URL}
	
	
Check page details for FDHCP
	
	${out}=  Execute command   cat webpage_log.txt
	Should not Contain    ${out}    ${HTTP_URL}
