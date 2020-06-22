*** Settings ***

Variables       ${ProjectTarget}/resources/variables/PublicApiVariables.py
Library         ${RootTarget}/libs/python/lib/qa/Sniffer/RWSniffer.py
Library         qa/Pcap80211Parser.py
Library		${RootTarget}/libs/python/lib/qa/Sniffer/RWMacSnifferTestAppliance.py
Library         qa/ttgcommon/RWQATTGRobotPcapParserKeywords.py
Library         RWQAAPCLIKeywords.py
Library         ${RootTarget}/libs/python/lib/RWQAAPCLIKeywords.py
Resource    	${RootTarget}/resources/keywords/qa/apcli_keywords.robot
*** Keywords  ***

Create Public Api Session
        ${login-data}=   Create Dictionary   username=${SZ_LOGIN_UNAME}    password=${SZ_LOGIN_PWD}
        session login   ${login-data}

Delete Public Api Session
        session logout

Create SoftGrE Tunnel Profile If Not Exists
	${soft_gre_tunnels}=     profiles_get_soft_gre_tunnel_list
	${soft_gre_info}=     Convert To String   ${soft_gre_tunnels}
	${res}=   run keyword and return status   should match regexp  ${soft_gre_info}  ${SOFT_GRE_PROFILE}
	run keyword if   '${res}'=='True'    Retrieve SoftGreTunnel Id
        run keyword if   '${res}'=='False'   Create SoftGrE Tunnel Profile


Create RuckusGrE Tunnel Profile If Not Exists
	[Arguments]    ${name}=${RUCKUS_GRE_PROFILE}
	${ruckus_gre_tunnels}=     profiles_get_ruckus_gre_list
	${ruckus_gre_info}=     Convert To String   ${ruckus_gre_tunnels}
	${res}=   run keyword and return status   should match regexp  ${ruckus_gre_info}  ${name}
	run keyword if   '${res}'=='True'    Retrieve RuckusGreTunnel Id   ${name}
        run keyword if   '${res}'=='False'   Create RuckusGrE Tunnel Profile   ${name}

Retrieve RuckusGreTunnel Id
	[Arguments]    ${name}=${RUCKUS_GRE_PROFILE}
	${ruckus_gre_tunnels}=     profiles_get_ruckus_gre_list
	${tunnel}=   get_obj_by_key_in_list   ${ruckus_gre_tunnels['list']}  key=name  value=${name}
	${tunnel_id}=    Get From Dictionary    ${tunnel}    id
	Set Suite Variable  ${ruckusgre_id}  ${tunnel_id}
	

Retrieve SoftGreTunnel Id
	${soft_gre_tunnels}=     profiles_get_soft_gre_tunnel_list
	${tunnel}=   get_obj_by_key_in_list   ${soft_gre_tunnels['list']}  key=name  value=${SOFT_GRE_PROFILE}
	${tunnel_id}=    Get From Dictionary    ${tunnel}    id
	Set Suite Variable  ${softgre_id}  ${tunnel_id}

Create RuckusGrE Tunnel Profile
	[Arguments]    ${name}=${RUCKUS_GRE_PROFILE}
	
    	${body}=  Create Dictionary

    	...  name=${name}

    	...  description=RuckusGRE tunnel profile ${name}

	...  tunnelMode=GRE

	...  tunnelEncryption=AES256

	...  tunnelMtuAutoEnabled=AUTO

   	${tunnel_id}=    profiles_create_ruckus_gre_tunnel   ${body}

   	Log    ${tunnel_id}

   	Should Not Be Equal    ${tunnel_id}    none    "ERROR:Unable to Create RuckusGre profile"

   	Set Suite Variable  ${ruckusgre_id}  ${tunnel_id}


	
Create SoftGrE Tunnel Profile
	[Arguments]    ${name}=${SOFT_GRE_PROFILE}    ${primary}=${SOFT_GRE_PRIMARY_GW}
	
    	${body}=  Create Dictionary

    	...  name=${name}

    	...  description=SoftGRE tunnel profile ${name}

    	...  primaryGateway=${primary}

	 ...  tunnelMtuAutoEnabled=AUTO

    	...  keepAlivePeriod=${10}

    	...  keepAliveRetry=${5}
 
   	${tunnel_id}=    profiles_create_soft_gre_tunnel   ${body}

   	Log    ${tunnel_id}

   	Should Not Be Equal    ${tunnel_id}    none    "ERROR:Unable to Create SoftGre profile"

   	Set Suite Variable  ${softgre_id}  ${tunnel_id}


Create Zone 
	[Arguments]    ${zone}=${ZONE_NAME}

        ${ap_login_data}=  Create Dictionary  apLoginName=${SZ_LOGIN_UNAME}  apLoginPassword=${SZ_LOGIN_PWD}

        ${data}=  Create Dictionary  name=${zone}  login=${ap_login_data}     
	
        ${suite_zone_id}=    rkszones_create  ${data}

        Should Not Be Empty  ${suite_zone_id}

        Set Suite Variable  ${zone_id}  ${suite_zone_id}

Create Dual Zone 
	[Arguments]    ${zone}=${ZONE_NAME}

        ${ap_login_data}=  Create Dictionary  apLoginName=${SZ_LOGIN_UNAME}  apLoginPassword=${SZ_LOGIN_PWD}

        ${data}=  Create Dictionary  name=${zone}  login=${ap_login_data}     
	
        ${suite_zone_id}=    rkszones_create_dual  ${data}

        Should Not Be Empty  ${suite_zone_id}

        Set Suite Variable  ${zone_id}  ${suite_zone_id}


Create IPV6 Zone 
	[Arguments]    ${zone}=${ZONE_NAME}

        ${ap_login_data}=  Create Dictionary  apLoginName=${SZ_LOGIN_UNAME}  apLoginPassword=${SZ_LOGIN_PWD}

        ${data}=  Create Dictionary  name=${zone}  login=${ap_login_data}     
	
        ${suite_zone_id}=    rkszones_create_ipv6  ${data}

        Should Not Be Empty  ${suite_zone_id}

        Set Suite Variable  ${zone_id}  ${suite_zone_id}

Update Zone with Soft Gre Tunnel Profile
        ${zone_id}=  Get Zone ID by name   zone_name=${ZONE_NAME}
	${soft_gre_tunnel} =    Create Dictionary    id=${softgre_id}    name=${SOFT_GRE_PROFILE}
	${soft_gre} =    Create List    ${soft_gre_tunnel}
	${soft_gre_list} =   Create Dictionary    softGreTunnelProflies=${soft_gre}
	${urlParams} =   Create Dictionary   id=${zone_id}
	rkszones update    ${soft_gre_list}    urlParams=${urlParams}

Update Zone with Ruckus Gre Tunnel Profile old
        [Arguments]    ${PROFILE_NAME}=${GRE_PROFILE}
        ${zone_id}=  Get Zone ID by name   zone_name=${ZONE_NAME}
        ${ruckus_gre_tunnels} =    profiles_get_ruckus_gre_list
        ${tunnel}=   get_obj_by_key_in_list   ${ruckus_gre_tunnels['list']}  key=name  value=${PROFILE_NAME}
        ${tunnel_id}=    Get From Dictionary    ${tunnel}    id
        ${ruckus_gre_tunnel} =    Create Dictionary    id=${tunnel_id}    name=${PROFILE_NAME}
        ${ruckus_gre_list} =   Create Dictionary    tunnelType=${ACCESSTUNNELTYPE}    tunnelProfile=${ruckus_gre_tunnel}
        ${urlParams} =   Create Dictionary   id=${zone_id}
        rkszones update    ${ruckus_gre_list}    urlParams=${urlParams}


Update Zone with Ruckus Gre Tunnel Profile
        [Arguments]    ${PROFILE_NAME}=${GRE_PROFILE}
        ${zone_id}=  Get Zone ID by name   zone_name=${ZONE_NAME}
        ${ruckus_gre_tunnels} =    profiles_get_ruckus_gre_list
        ${tunnel}=   get_obj_by_key_in_list   ${ruckus_gre_tunnels['list']}  key=name  value=${PROFILE_NAME}
        ${tunnel_id}=    Get From Dictionary    ${tunnel}    id
        ${ruckus_gre_tunnel} =    Create Dictionary    id=${tunnel_id}    name=${PROFILE_NAME}
        ${ruckus_gre_list} =   Create Dictionary    ruckusGreTunnelProfile=${ruckus_gre_tunnel}
        ${urlParams} =   Create Dictionary   id=${zone_id}
        rkszones update    ${ruckus_gre_list}    urlParams=${urlParams}



Delete Zone
	[Arguments]  ${zone_delete}=${ZONE_NAME}	

        ${zone_id}=    Get Zone ID by name   zone_name=${zone_delete}

        ${url_params}=  Create Dictionary   id=${zone_id}

        rkszones_delete  urlParams=${url_params}

	[Return]    false

Get Zone ID by name
        [Arguments]  ${zone_name}=${ZONE_NAME}
	log    ${zone_name}
        ${zone_data}=   rkszones get list
        ${zone_id}=  get_obj_by_key_in_list   ${zone_data['list']}  key=name  value=${zone_name}
        Log   ${zone_id}
        Log   ${zone_id['id']}
        [Return]    ${zone_id['id']}


Move AP

    [Arguments]  ${zone_id}  ${ap_mac}

    ${data}=  Create Dictionary  zoneId=${zone_id}

    ${url_params}=  Create Dictionary  apMac=${ap_mac}

    aps_update  ${data}  urlParams=${url_params}

    Wait Until Keyword Succeeds   250s   60s    sz_setup.Check AP Config Status Completed    ${ap_mac}  ${zone_id}

 

 

Check AP Config Status Completed

    [Arguments]  ${ap_mac}  ${zone_id}=None

    ${url_params}=  Create Dictionary  apMac=${ap_mac}

    aps_get_operational_summary  urlParams=${url_params}

    ${res}=  get response

    Should Be Equal  ${res['configState']}  completed

    Should Be Equal  ${res['connectionState']}  Connect
 

    Run Keyword If  '${zone_id}' != 'None'

    ...  Should Be Equal  ${res['zoneId']}  ${zone_id}


Get WLAN ID by name
        
	${zone-id}=  Get Zone ID by name
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}
	${wlan_data}=   rkszones get wlans   urlParams=${urlParams}
        ${wlan_id}=  get_obj_by_key_in_list   ${wlan_data['list']}  key=name  value=${WLAN}
        Log   ${wlan_id}
        Log   ${wlan_id['id']}
        [Return]    ${wlan_id['id']}

Get Zone by ID
        [Arguments]   ${zoneId}
        ${urlParams}=  Create Dictionary   id=${zoneId}
        ${zone-res}=   rkszones get   urlParams=${urlParams}
        [Return]   ${zone-res}

Set default WLAN group to AP
	[Arguments]   ${APMAC}=${AP_MACC[0]}
        ${zone-id}=  Get Zone ID by name
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}
        ${wlan_groups}=   rkszones get_wlan_groups   urlParams=${urlParams}
        Log   ${wlan_groups}
        ${wlan_grp_id}=   get_obj_by_key_in_list   ${wlan_groups['list']}  key=name  value=${DEFAULT_WLAN_GROUP}
        Log   ${wlan_grp_id['id']}
        ${ap-wlan-grp}=   Create Dictionary   id=${wlan_grp_id['id']}   name=${DEFAULT_WLAN_GROUP}
        ${ap-wlan-grp-24}=   Create Dictionary   wlanGroup24=${ap-wlan-grp}

        ${urlParams}=  Create Dictionary   apMac=${APMAC}

	${ap-wlan-grp}=   Create Dictionary   id=${wlan_grp_id['id']}   name=${DEFAULT_WLAN_GROUP}
        ${ap-wlan-grp-50}=   Create Dictionary   wlanGroup50=${ap-wlan-grp}
        aps update   ${ap-wlan-grp-50}   urlParams=${urlParams}
        aps update   ${ap-wlan-grp-24}   urlParams=${urlParams}


Show STA list on AP
	[Arguments]   ${count}   ${apMac}
	${urlParams} =  Create Dictionary    apMac=${apMac}
	${res} =  aps get clients    urlParams=${urlPArams}
	Log   ${res}
	${sta_count} =  Get from Dictionary   ${res}   totalCount
	Should Be Equal As Strings  ${sta_count}   ${count}

Check Client list on AP
	[Arguments]   ${count}   ${apMac}=${AP_MAC}   
	Wait Until Keyword Succeeds   120s   60s    Show STA list on AP   ${count}   ${apMac}   

Get STA details

	${urlParams} =  Create Dictionary    apMac=${AP_MAC}
	${ap_data} =  aps get operational summary   urlParams=${urlParams}
	${ap_ip} =  Get From Dictionary   ${ap_data}   externalIp
	Log   ${ap_ip}
	${ip} =  Evaluate   '${ap_ip}'.split('.')
	${ip} =  Evaluate   '.'.join(${ip}[:2])
	Log   ${ip}
	
	${res} =  aps get clients    urlParams=${urlPArams}
	Log   ${res}
	${total_count} =  Get From Dictionary   ${res}   totalCount
	Wait Until Keyword Succeeds  20s   10s   Should Not be Equal As Integers  ${total_count}   0

	${client_list} =   Get from Dictionary   ${res}   list
	Log   ${client_list}
	Login to Remote PC
	${mac_addr} =  Execute Command    cat and_mac_detail.txt
	Should Not Be Empty   ${mac_addr}
	@{mac} =  Split to Lines   ${mac_addr}
	:FOR   ${m}   IN    @{mac}
	\	Log    ${m}
	\	Verify STA details    ${client_list}   ${m}   ${total_count}   ${ip}


Verify STA details
	
	[Arguments]    ${client_list}   ${c_mac}   ${total_count}  ${ap_ip}

	Log   ${client_list}   
	Log   ${c_mac}
	Log   ${total_count}
	:FOR  ${i}  IN RANGE  0  ${total_count}
	\	${data} =   Get From List   ${client_list}   ${i}
	\	${c}=   Get From Dictionary   ${data}   mac
	\	Continue For Loop If   '${c_mac}' != '${c}'
	\       Exit For Loop
	${os} =   Get From Dictionary   ${data}   osType
        ${host-name} =   Get From Dictionary   ${data}   hostName
	${ip_addr} =   Get From Dictionary   ${data}   ipAddress
        ${mac}=   Get From Dictionary   ${data}   mac
        Should Be Equal   ${os}   Android
        Should Contain    ${host-name}   android
	Should Contain    ${ip_addr}   ${ap_ip}


Configure 50 Radio of AP
	[Arguments]    ${channelwidth}=${CHANNEL_WIDTH50}   ${APMACC}=${AP_MACC[${0}]}   ${txPower}=Full    ${wlan}=${WLAN}
	Log    ${APMACC}
	#${lib} =  Get Library Instance   test_var
        ${zone-id}=   Get Zone ID by name
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}

        ${wlan_groups}=   rkszones get_wlan_groups   urlParams=${urlParams}
        Log   ${wlan_groups}
        ${wlan_grp_id}=   get_obj_by_key_in_list   ${wlan_groups['list']}  key=name  value=${wlan}
        Log   ${wlan_grp_id['id']}

	@{channel_range1}=   Create List
	Append To List  ${channel_range1}    ${CHANNEL_50}
	@{availableChannelRange}=   Create List
	Append To List  ${availableChannelRange}    ${CHANNEL_50}

	#@{channel_range1} =   Create Dictionary    channelRange=${CHANNEL_50}    availableChannelRange=${CHANNEL_50}
        #${wifi50_data}=  Create Dictionary   txPower=Full  channelWidth=${channelwidth}  channel=${CHANNEL_50}   channelRange=@{channel_range1}    availableChannelRange=@{availableChannelRange}   # not working in 3.5.0.0.730 hence removed availableChannelRange
	
	${wifi50_data}=  Create Dictionary   txPower=${txPower}  channelWidth=${channelwidth}  channel=${CHANNEL_50}   channelRange=@{channel_range1}
        ${data}=  Create Dictionary   wifi50=${wifi50_data}
        #${ap_length}=   get length    ${APMACC}
	${urlParams}=  Create Dictionary   apMac=${APMACC}
        aps update   ${data}   urlParams=${urlParams}

	${wifi24_data}=  Create Dictionary   txPower=${txPower}  channelWidth=${CHANNEL_WIDTH24}  channel=${CHANNEL_24}
        ${data}=  Create Dictionary   wifi24=${wifi24_data}
        ${urlParams}=  Create Dictionary   apMac=${APMACC}
        aps update   ${data}   urlParams=${urlParams}

        ${ap-wlan-grp}=   Create Dictionary   id=${wlan_grp_id['id']}   name=${wlan}
        ${ap-wlan-grp-50}=   Create Dictionary   wlanGroup50=${ap-wlan-grp}
        aps update   ${ap-wlan-grp-50}   urlParams=${urlParams}

        #${service50}=   Convert to Boolean   true
        ${service-data50}=   Create Dictionary   wlanService50Enabled=${common_var.istrue}
        aps update   ${service-data50}   urlParams=${urlParams}

        #${service24}=   Convert to Boolean   false
        ${service-data24}=   Create Dictionary   wlanService24Enabled=${common_var.isfalse}
        aps update   ${service-data24}   urlParams=${urlParams}
        Sleep   20s



Create Non-Proxy Auth Server Via GUI

    [Arguments]  ${radius_ip}  ${radius_secret}  ${radius_name}

    ${zone_id}=  Get Zone ID by name

    ${url_params}=  Create Dictionary  zoneId=${zone_id}

    ${primary}=  Create Dictionary  ip=${radius_ip}  port=${1812}  sharedSecret=${radius_secret}

    ${data}=  Create Dictionary  name=${radius_name}  primary=${primary}

    ${aaa_server_list}=   rkszones_get_authentication_server_list   urlParams=${url_params}

    ${aaa_server_info}=    Convert to String   ${aaa_server_list}

    Log   ${aaa_server_info}
    

    #${aaa_server_count}=   Run Keyword and return status   List Should Not Contain Value   ${aaa_server_list['list']}   ${radius_ip}\

    ${res}=   run keyword and return status   should match regexp  ${aaa_server_info}  ${radius_name}

    run keyword if   '${res}'!='False'   Delete AAA Server If Any   ${aaa_server_list}   ${zone_id}   ${radius_name}

    ${radius_id}=  rkszones_create_authentication_server  ${data}  urlParams=${url_params}

    Should Not Be Empty  ${radius_id}

    Set Suite Variable    ${non_proxy_auth_radius_id}    ${radius_id}

    Set Suite Variable    ${non_proxy_auth_server}    ${radius_name}


Delete AAA Server If Any
    
    [Arguments]   ${aaa_server_list}   ${zone_id}   ${radius_name}

    ${radi_id}=   get_obj_by_key_in_list   ${aaa_server_list['list']}   key=name   value=${radius_name}

    Log   ${radi_id}

    ${url_params1}=  Create Dictionary   zoneId=${zone_id}   id=${radi_id['id']}

    rkszones_delete_authentication_server   urlParams=${url_params1}

Create Proxy Auth Server Via GUI

    [Arguments]  ${radius_ip}  ${radius_secret}  ${radius_name}
    
    ${primary}=  Create Dictionary  ip=${radius_ip}  port=${1812}  sharedSecret=${radius_secret}
    
    ${auth_values}=  Create Dictionary  name=${radius_name}  primary=${primary}

    ${auth_service_list}=   services_get_radius_authentications

    Log   ${auth_service_list}

    ${aaa_server_info}=    Convert to String   ${auth_service_list}

    Log   ${aaa_server_info}
    
    ${res}=   run keyword and return status   should match regexp  ${aaa_server_info}  ${radius_name}

    run keyword if   '${res}'=='False'   Create AAA Proxy Service   ${auth_values}

    run keyword if   '${res}'!='False'   Get AAA Proxy Service Id   ${auth_service_list}  ${radius_name}

    Set Suite Variable  ${radius_server_primary}  ${radius_name}

Create AAA Proxy Service

    [Arguments]   ${auth_values}	
	
    ${proxy_auth_radius_id}=  services_create_radius_authentication_service  ${auth_values}
    
    Should Not Be Empty  ${proxy_auth_radius_id}

    Set Suite Variable  ${proxy_auth_radius_id}  ${proxy_auth_radius_id}

Get AAA Proxy Service Id
    [Arguments]   ${auth_service_list}   ${radius_name}

    ${proxy_auth_radius_id}=   get_obj_by_key_in_list   ${auth_service_list['list']}   key=name   value=${radius_name}

    Log   ${proxy_auth_radius_id}

    Should Not Be Empty  ${proxy_auth_radius_id}

    Set Suite Variable  ${proxy_auth_radius_id}  ${proxy_auth_radius_id['id']}



Delete AAA Service If Any

    [Arguments]   ${auth_service_list}   ${radius_name}

    ${radi_id}=   get_obj_by_key_in_list   ${auth_service_list['list']}   key=name   value=${radius_name}

    Log   ${radi_id}

    ${url_params1}=  Create Dictionary   id=${radi_id['id']}

    services_delete_authentication_service   urlParams=${url_params1}

Delete Proxy AAA Server Via GUI backup

    [Arguments]  ${radius_id}

    #${zone_id}=  Get Zone ID by name

    ${url_params}=  Create Dictionary  id=${radius_id}

    services_delete_authentication_service  urlParams=${url_params}

Delete Proxy AAA Server Via GUI

    [Arguments]  ${radius_id}
    
    Log   Deletion of Proxy Server is avoided to avoid conflicts with zones
Create Non-Proxy Acct Server Via GUI

    [Arguments]  ${radius_ip}=${RADIUS_SERVER1_IP}  ${radius_secret}=${RADIUS_SERVER_PRIMARY_SECRET}   ${radius_name}=${proxy_radius_name}

    ${url_params}=  Create Dictionary  zoneId=${zone_id}

    ${primary}=  Create Dictionary  ip=${radius_ip}  port=${1813}  sharedSecret=${radius_secret}

    ${data}=  Create Dictionary  name=${radius_name}  primary=${primary}

    ${params}=  Create Dictionary  forAccounting=${True}

    ${radius_id}=  api.call_pub  rkszones_create_authentication_server  ${data}  urlParams=${url_params}  params=${params}

    Should Not Be Empty  ${radius_id}

    Set Suite Variable    ${non_proxy_acct_radius_id}    ${radius_id}

    Set Suite Variable    ${non_proxy_acct_server}    ${radius_name}

             

Delete Non-Proxy AAA Server Via GUI

    [Arguments]  ${radius_id}

    ${zone_id}=  Get Zone ID by name

    ${url_params}=  Create Dictionary  zoneId=${zone_id}  id=${radius_id}

    rkszones_delete_authentication_server  urlParams=${url_params}

 

Delete Non-Proxy RADIUS Accounting

    [Arguments]  ${radius_id}

    ${url_params}=  Create Dictionary  zoneId=${zone_id}  id=${radius_id}

    api.call_pub  rkszones_delete_authentication_server  urlParams=${url_params}





Configure 24 Radio of AP
	[Arguments]    ${channelwidth}=${CHANNEL_WIDTH24}   ${APMACC}=${AP_MACC[${0}]}   ${txPower}=Full    ${protectionMode}=RTS_CTS
        ${zone-id}=   Get Zone ID by name
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}

        ${wlan_groups}=   rkszones get_wlan_groups   urlParams=${urlParams}
        Log   ${wlan_groups}
        ${wlan_grp_id}=   get_obj_by_key_in_list   ${wlan_groups['list']}  key=name  value=${WLAN}
        Log   ${wlan_grp_id['id']}


	@{channel_range1}=   Create List
	Append To List  ${channel_range1}    ${CHANNEL_24}
	Log   ${channel_range1}
	@{availableChannelRange}=   Create List
	Append To List  ${availableChannelRange}    ${CHANNEL_24}

	${wifi24_data}=  Create Dictionary   txPower=${txPower}  channelWidth=${channelwidth}  channel=${CHANNEL_24}   channelRange=@{channel_range1}
        ${data}=  Create Dictionary   wifi24=${wifi24_data}
        ${urlParams}=  Create Dictionary   apMac=${APMACC}
        aps update   ${data}   urlParams=${urlParams}

	${wifi50_data}=  Create Dictionary   txPower=${txPower}  channelWidth=${CHANNEL_WIDTH50}  channel=${CHANNEL_50}
        ${data}=  Create Dictionary   wifi50=${wifi50_data}
        ${urlParams}=  Create Dictionary   apMac=${APMACC}
        aps update   ${data}   urlParams=${urlParams}

        ${ap-wlan-grp}=   Create Dictionary   id=${wlan_grp_id['id']}   name=${WLAN}
        ${ap-wlan-grp-24}=   Create Dictionary   wlanGroup24=${ap-wlan-grp}
        aps update   ${ap-wlan-grp-24}   urlParams=${urlParams}

        #${service24}=   Convert to Boolean   true
        ${service-data24}=   Create Dictionary   wlanService24Enabled=${common_var.istrue}
        aps update   ${service-data24}   urlParams=${urlParams}

        ${service50}=   Convert to Boolean   false
        ${service-data50}=   Create Dictionary   wlanService50Enabled=${common_var.isfalse}
        aps update   ${service-data50}   urlParams=${urlParams}
        #Sleep   20s

        #Niveditha-Adding protection mode field to update AP with different protection mechanisms
	${ptmode24}=   Create Dictionary   protectionMode24=${protectionMode}
	${urlParams}=  Create Dictionary   apMac=${APMACC}
	aps update   ${ptmode24}    urlParams=${urlParams}
	sleep    20s

Disable 24 Radio Protection Mode Override
	[Arguments]     ${APMACC}=${AP_MACC[${0}]}
	${urlParams}=  Create Dictionary   apMac=${APMACC}
	aps disable_override_v6_since    urlParams=${urlParams}  

Delete WLAN
        [Arguments]    ${wlan}=${WLAN}
        ${zone-id}=  Get Zone ID by name
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}
        ${wlans}=   rkszones get_wlans   urlParams=${urlParams}
        Log   ${wlans}
        ${wlan_id}=   get_obj_by_key_in_list   ${wlans['list']}  key=name  value=${wlan}
        Log   ${wlan_id['id']}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}  id=${wlan_id['id']}
        rkszones delete_wlan   urlParams=${urlParams}

Delete WLAN WLAN Prioritization TC

        ${zone-id}=  Get Zone ID by name
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}
        ${wlans}=   rkszones get_wlans   urlParams=${urlParams}
        Log   ${wlans}
        ${wlan_id}=   get_obj_by_key_in_list   ${wlans['list']}  key=name  value=${WLAN}
        Log   ${wlan_id['id']}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}  id=${wlan_id['id']}
        rkszones delete_wlan   urlParams=${urlParams}

	${wlan_id}=   get_obj_by_key_in_list   ${wlans['list']}  key=name  value=IOTRWSZ1
        Log   ${wlan_id['id']}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}  id=${wlan_id['id']}
        rkszones delete_wlan   urlParams=${urlParams}


Delete PEAPWLAN

        ${zone-id}=  Get Zone ID by name
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}
        ${wlans}=   rkszones get_wlans   urlParams=${urlParams}
        Log   ${wlans}
        ${wlan_id}=   get_obj_by_key_in_list   ${wlans['list']}  key=name  value=${PEAPWLAN}
        Log   ${wlan_id['id']}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}  id=${wlan_id['id']}
        rkszones delete_wlan   urlParams=${urlParams}

Delete TTLSWLAN

        ${zone-id}=  Get Zone ID by name
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}
        ${wlans}=   rkszones get_wlans   urlParams=${urlParams}
        Log   ${wlans}
        ${wlan_id}=   get_obj_by_key_in_list   ${wlans['list']}  key=name  value=${TTLSWLAN}
        Log   ${wlan_id['id']}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}  id=${wlan_id['id']}
        rkszones delete_wlan   urlParams=${urlParams}

Delete WLAN group
	[Arguments]    ${wlan}=${WLAN}
        ${zone-id}=  Get Zone ID by name
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}
        ${wlan_groups}=   rkszones get_wlan_groups   urlParams=${urlParams}
        Log   ${wlan_groups}
        ${wlan_grp_id}=   get_obj_by_key_in_list   ${wlan_groups['list']}  key=name  value=${wlan}
        Log   ${wlan_grp_id['id']}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}   id=${wlan_grp_id['id']}
        rkszones delete_wlan_group   urlParams=${urlParams}


Delete Hotspot profile

        ${zone-id}=  Get Zone ID by name
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}
        ${wispr_list}=   rkszones get_hotspot_portals   urlParams=${urlParams}
        Log   ${wispr_list}
        ${wispr_id}=   get_obj_by_key_in_list   ${wispr_list['list']}  key=name  value=${WLAN}
        Log   ${wispr_id['id']}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}   id=${wispr_id['id']}
        rkszones delete_hotspot   urlParams=${urlParams}

Delete Guest profile

        ${zone-id}=  Get Zone ID by name
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}
        ${guest_list}=   rkszones get_guest_access_list   urlParams=${urlParams}
        Log   ${guest_list}
        ${guest_id}=   get_obj_by_key_in_list   ${guest_list['list']}  key=name  value=${WLAN}
        Log   ${guest_id['id']}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}   id=${guest_id['id']}
        rkszones delete_guest_access   urlParams=${urlParams}


Create Identity User profile    
	#No support for Local DB

        ${subscriber_datas}=   identity get_package_list
        Log   ${subscriber_datas}
        ${subscriber_data}=  get_obj_by_key_in_list   ${subscriber_datas['list']}  key=packageExpiration   value=Never Expires
        Log   ${subscriber_data}
        ${dict}=   get_from_dictionary   ${subscriber_data}   subscriberPackage
        Log   ${dict}
        ${sub-id}=   get_from_dictionary   ${dict}   id
        log   ${sub-id}
        ${sub-package}=  Create Dictionary   id=${sub-id}
        ${data}=  Create dictionary   firstName=ruckus   lastName=ruckus   countryName=UNITED STATES   userName=${IDENTITY_USER}   password=${IDENTITY_PWD}     isDisabled=NO   subscriberPackage=${sub-package}
        ${user-id}=  identity create_user  ${data}
        Log  ${user-id}
        Should Not Be Equal  ${user-id}   None


Create Identity User profile For Wispr With Expiration Package  
	#No support for Local DB

        ${subscriber_datas}=   identity get_subscription_package_list
        Log   ${subscriber_datas}
        ${subscriber_data}=  get_obj_by_key_in_list   ${subscriber_datas['list']}  key=name   value=${WLAN}
        Log   ${subscriber_data}
        ${data_id}=   get_obj_by_key_in_list   ${subscriber_datas['list']}  key=name  value=${WLAN}
        ${package_id}=    Set Variable   ${data_id['id']}
        log   ${package_id}

        ${sub-package}=  Create Dictionary   id=${package_id}
        ${data}=  Create dictionary   firstName=ruckus   lastName=ruckus   countryName=UNITED STATES   userName=${IDENTITY_USER}   password=${IDENTITY_PWD}     isDisabled=NO   subscriberPackage=${sub-package}
        ${user-id}=  identity create_user  ${data}
        Log  ${user-id}
        Should Not Be Equal  ${user-id}   None


Delete Identity User profile
	${data} =    identity get_user_list
	Log    ${data}
	${user_id}=   get_obj_by_key_in_list   ${data['list']}  key=userName   value=${IDENTITY_USER}
	${urlparam}=  Create dictionary   id=${user_id['id']}
	identity delete_user   urlParams=${urlparam}




Get Zone Details

        ${zone-list} =  rkszones get list
        Log   ${zone-list}

Zone Configuration

        ${zone-id} =    Get Zone ID by name
        Log   ${zone-id}
        Should Not Be Equal As Strings   ${zone-id}   None

        ${country-code}=   Create Dictionary   countryCode=${RD}
        ${urlParams} =   Create Dictionary   id=${zone-id}
        rkszones update    ${country-code}    urlParams=${urlParams}
	
	${ap-login-data}=   Create Dictionary   apLoginName=admin   apLoginPassword=Password1!
        ${ap-data}=   Create Dictionary   login=${ap-login-data}
        rkszones update   ${ap-data}   urlParams=${urlParams}

        ${res} =   Get Zone by ID  ${zone-id}
        Log   ${res}
        Log   ${res['login']}
        Should Be Equal   ${res['countryCode']}  ${RD}
        #${apuser} =  rkszones get
        #${usr}   Convert to String   admin
        #List Should Contain Value    ${res['login']}   ${usr}
        #Should Be Equal   ${res['apLoginPassword']}  Password1!


Create Ldap Profile

	${data}=  Create Dictionary  name=${LDAP_PROFILE}  tlsEnabled=${TLSENABLED}   ip=${LDAP_SERVER}    port=${LDAP_PORT}    baseDomainName=${LDAP_BASE_DOMAIN}     adminDomainName=${LDAP_ADMIN_DOMAIN}    password=${LDAP_SERVER_PWD}    keyAttribute=${LDAP_KEY_ATTRIBUTE}     searchFilter=${LDAP_FILTER}
	${ldap}=    services create_ldap_authentication_service    ${data} 
	[return]    ${ldap}

Delete Ldap Profile
	${ldap_list}=    services get_ldap_authentications
	Log   ${ldap_list}
	${ldap_id}=    get_obj_by_key_in_list   ${ldap_list['list']}  key=name  value=${LDAP_PROFILE}
	Log   ${ldap_id['id']}
	${urlParams}=   Create Dictionary   id=${ldap_id['id']}
	services delete_ldap_authentication_service    urlParams=${urlParams}



Create Open WLAN

	[Arguments]    ${priority}=High    ${ssid}=${WLAN}    ${dtim}=${common_var.dtim_min}
        ${adv-opt}=   Create Dictionary   priority=${priority}  mgmtTxRateMbps=2 mbps   clientIsolationEnabled=${common_var.client_isolation}    hideSsidEnabled=${common_var.hidden_ssid}   proxyARPEnabled=${common_var.proxy_arp}   maxClientsPerRadio=${common_var.max_clients}   support80211dEnabled=${common_var.w11d}   support80211kEnabled=${common_var.w11k}   dhcpOption82Enabled=${common_var.dhcp_option_82}   unauthClientStatsEnabled=${common_var.client_txrx}   clientIdleTimeoutSec=${common_var.client_idle}   clientFingerprintingEnabled=${common_var.fingerprint}   ofdmOnlyEnabled=${common_var.ofdm_only}   bssMinRateMbps=Disable   bandBalancing=UseZoneSetting    dtimInterval=${dtim}
        Log   ${adv-opt}
 
	${zone-id}=   Get Zone ID by name
        Log   ${zone-id}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}
        ${wlan-data}=   Create Dictionary   name=${ssid}   ssid=${ssid}
        ${wlan_id}=   rkszones create_wlan_standard_open   ${wlan-data}   urlParams=${urlParams}

	${urlParams}=   Create Dictionary   zoneId=${zone-id}  id=${wlan_id}
	${data}=    Create Dictionary   advancedOptions=${adv-opt}
	Log    ${data}
        rkszones update_wlan  ${data}  urlParams=${urlParams}

Create WPA2 WLAN with DPSK Enabled
	[Arguments]    ${priority}=High    ${ssid}=${WLAN}    ${dtim}=${common_var.dtim_min}   ${mfp}=disabled    ${11r}=${common_var.w11r}   ${dpskEnabled}=${common_var.istrue}   ${length}=${common_var.pass_key_size}   ${dpskType}=NumbersOnly
	

        ${adv-opt}=   Create Dictionary   priority=${priority}  mgmtTxRateMbps=2 mbps   clientIsolationEnabled=${common_var.client_isolation}    hideSsidEnabled=${common_var.hidden_ssid}   proxyARPEnabled=${common_var.proxy_arp}   maxClientsPerRadio=${common_var.max_clients}   support80211dEnabled=${common_var.w11d}   support80211kEnabled=${common_var.w11k}   dhcpOption82Enabled=${common_var.dhcp_option_82}   unauthClientStatsEnabled=${common_var.client_txrx}   clientIdleTimeoutSec=${common_var.client_idle}   clientFingerprintingEnabled=${common_var.fingerprint}   ofdmOnlyEnabled=${common_var.ofdm_only}   bssMinRateMbps=Disable   bandBalancing=UseZoneSetting    dtimInterval=${dtim}

        Log   ${adv-opt}
 
	${zone-id}=   Get Zone ID by name
        Log   ${zone-id}

	${wlan-enc-data} =   Create Dictionary   method=WPA2   algorithm=AES  passphrase=${PSKKEY}   mfp=${mfp}    support80211rEnabled=${11r}   mobilityDomainId=${common_var.mobility_id}
	${dpsk_details} =    Create Dictionary   dpskEnabled=${dpskEnabled}   length=${length}   dpskType=${dpskType}   
	${wlan-data}=   Create Dictionary   name=${ssid}   ssid=${ssid}   encryption=${wlan-enc-data}   dpsk=${dpsk_details}   advancedOptions=${adv-opt}
	${urlParams}=   Create Dictionary   zoneId=${zone-id}
        rkszones create_wlan_standard_open    ${wlan-data}   urlParams=${urlParams}

Modify EAP Encryption
	[Arguments]   ${mfp}=disabled    ${11r}=${common_var.w11r}
	#${lib} =  Get Library Instance   test_var
	${zone_id}=   Get Zone ID by name
        Log   ${zone_id}
        ${wlan_id}=   Get WLAN ID by name
        Log   ${wlan_id}
        #${wlan-enc-data} =   Create Dictionary   method=WPA2   algorithm=AES  passphrase=${PSKKEY}   mfp=${mfp}    support80211rEnabled=${11r}   mobilityDomainId=${common_var.mobility_id}
	${wlan-enc-data} =   Create Dictionary   method=WPA2   algorithm=AES   mfp=${mfp}    support80211rEnabled=${11r}   mobilityDomainId=${common_var.mobility_id}
        ${wlan-enc} =   Create Dictionary   encryption=${wlan-enc-data}
        ${urlParams}=   Create Dictionary   zoneId=${zone_id}  id=${wlan_id}
        rkszones update wlan   ${wlan-enc}   urlParams=${urlParams}



Modify Open WLAN to WPA2 WLAN
	[Arguments]   ${mfp}=disabled    ${11r}=${common_var.w11r}   ${algorithm}=AES
	#${lib} =  Get Library Instance   test_var
	${zone_id}=   Get Zone ID by name
        Log   ${zone_id}
        ${wlan_id}=   Get WLAN ID by name
        Log   ${wlan_id}
        ${wlan-enc-data} =   Create Dictionary   method=WPA2   algorithm=${algorithm}  passphrase=${PSKKEY}   mfp=${mfp}    support80211rEnabled=${11r}   mobilityDomainId=${common_var.mobility_id}
        ${wlan-enc} =   Create Dictionary   encryption=${wlan-enc-data}
        ${urlParams}=   Create Dictionary   zoneId=${zone_id}  id=${wlan_id}
        rkszones update wlan   ${wlan-enc}   urlParams=${urlParams}


Generate DPSK
	${zone_id}=   Get Zone ID by name
        Log   ${zone_id}
        ${wlan_id}=   Get WLAN ID by name
        Log   ${wlan_id}
	${count} =   Get Length   ${dev_details}
	${dpsk} =   Create Dictionary   amount=${count}   vlanId=${ACCESSVLAN}
	${urlParams}=    Create Dictionary   zoneId=${zone_id}  id=${wlan_id}
	rkszones batch_gen_unbound_dpsk   ${dpsk}   urlParams=${urlParams}

Get DPSK List for WPA2 WLAN
	[return]   ${passphrase_keys}
	${zone_id}=   Get Zone ID by name
        Log   ${zone_id}
        ${wlan_id}=   Get WLAN ID by name
        Log   ${wlan_id}
	${urlParams}=    Create Dictionary   zoneId=${zone_id}  id=${wlan_id}
	${dpsk_list_info}=   rkszones get_dpsk_info_by_wlan   urlParams=${urlParams}
	Log   ${dpsk_list_info}
	#${dpsk_list}=   get_obj_by_key_in_list   ${dpsk_list_info['list']}   key=wlanId   value=${wlan_id}
	${dpsk_list}=   Set Variable   ${dpsk_list_info['list']}
	Log   ${dpsk_list}
	${count}=   Get length   ${dpsk_list}
	${passphrase_keys}=   Create List
	:FOR   ${key}   IN RANGE   0    ${count}
	\	Log    ${key}
	\	${psk}=   Get From Dictionary   @{dpsk_list}[${key}]   passphrase
	\	Append To List    ${passphrase_keys}   ${psk}
	\	Log   ${passphrase_keys}


Delete Generated DPSK List for WPA2 WLAN
	${zone_id}=   Get Zone ID by name
        Log   ${zone_id}
        ${wlan_id}=   Get WLAN ID by name
        Log   ${wlan_id}
	${urlParams}=    Create Dictionary   zoneId=${zone_id}  id=${wlan_id}
	${dpsk_list_info}=   rkszones get_dpsk_info_by_wlan   urlParams=${urlParams}
	Log   ${dpsk_list_info}
	${dpsk_list}=   Set Variable   ${dpsk_list_info['list']}
	Log   ${dpsk_list}
	${count}=   Get length   ${dpsk_list}
	${dpsk_ids}=   Create List
	:FOR   ${key}   IN RANGE   0    ${count}
	\	Log    ${key}
	\	${psk_id}=   Get From Dictionary   @{dpsk_list}[${key}]   id
	\	Run Keyword   Append To List   ${dpsk_ids}   ${psk_id}
	${id_list} =    Create Dictionary   idList=${dpsk_ids}
	${urlParams}=    Create Dictionary   zoneId=${zone_id}   id=${wlan_id}
	rkszones delete_dpsk_info_by_id   ${id_list}   urlParams=${urlParams}
	

Modify Open WLAN to WPA-Mixed WLAN
	#Modifying TKIP_AES TO AUTO for testcase flow integrity27112017
	[Arguments]   ${mfp}=disabled    ${11r}=${common_var.w11r}
	#${lib} =  Get Library Instance   test_var
        ${zone_id}=   Get Zone ID by name
        Log   ${zone_id}
        ${wlan_id}=   Get WLAN ID by name
        Log   ${wlan_id}
        ${wlan-enc-data} =   Create Dictionary   method=WPA_Mixed   algorithm=AES  passphrase=${PSKKEY}   mfp=disabled    support80211rEnabled=${11r}   mobilityDomainId=${common_var.mobility_id}
        ${wlan-enc} =   Create Dictionary   encryption=${wlan-enc-data}
        ${urlParams}=   Create Dictionary   zoneId=${zone_id}  id=${wlan_id}
        rkszones update wlan   ${wlan-enc}   urlParams=${urlParams}

Modify Open WLAN to WEP128 WLAN

	#${lib} =  Get Library Instance   test_var
	${zone_id}=   Get Zone ID by name
        Log   ${zone_id}
	${wlan_id}=   Get WLAN ID by name
	Log   ${wlan_id}
	${wlan-enc-data} =   Create Dictionary   method=WEP_128   keyIndex=${wep_var.key_index}  keyInHex=${WEP128_KEY}
        ${wlan-enc} =   Create Dictionary   encryption=${wlan-enc-data}
        ${urlParams}=   Create Dictionary   zoneId=${zone_id}  id=${wlan_id}
	rkszones update wlan   ${wlan-enc}   urlParams=${urlParams}


Modify Open WLAN to WEP64 WLAN

	#${lib} =  Get Library Instance   test_var        
	${zone_id}=   Get Zone ID by name
        Log   ${zone_id}
        ${wlan_id}=   Get WLAN ID by name
        Log   ${wlan_id}
        ${wlan-enc-data} =   Create Dictionary   method=WEP_64   keyIndex=${wep_var.key_index}  keyInHex=${WEP64_KEY}
        ${wlan-enc} =   Create Dictionary   encryption=${wlan-enc-data}
        ${urlParams}=   Create Dictionary   zoneId=${zone_id}  id=${wlan_id}
        rkszones update wlan   ${wlan-enc}   urlParams=${urlParams}


Enable ForceDHCP on WLAN

	#${lib} =  Get Library Instance   test_var	
	${zone-id}=   Get Zone ID by name
	Log   ${zone-id}
	${wlan_id}=   Get WLAN ID by name
	Log   ${wlan_id}
	${urlParams}=   Create Dictionary   zoneId=${zone-id}  id=${wlan_id}
	${adv-opt}=   Create Dictionary   forceClientDHCPTimeoutSec=${fdhcp_var.force_dhcp}
	${data}=    Create Dictionary   advancedOptions=${adv-opt}
	rkszones update_wlan  ${data}  urlParams=${urlParams}


Create EAP WLAN
	[Arguments]    ${radius_profile}   ${priority}=High    ${ssid}=${WLAN}   ${pmkCachingEnabled}=${Common_var.istrue}    ${okcEnabled}=${Common_var.istrue}
	#${lib} =  Get Library Instance   test_var
        ${zone-id}=   Get Zone ID by name
        Log   ${zone-id}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}
        ${auth-data}=   Create Dictionary   throughController=${common_var.isfalse}    name=${radius_profile}
        ${wlan-data}=   Create Dictionary   name=${ssid}   ssid=${ssid}   authServiceOrProfile=${auth-data}   description=1xProfile
	Log   ${wlan-data}
        ${wlan_id}=  rkszones create_wlan_standard8021_x    ${wlan-data}   urlParams=${urlParams}
        Log   ${wlan_id}

        ${adv-opt}=   Create Dictionary   priority=${priority}  mgmtTxRateMbps=2 mbps   clientIsolationEnabled=${common_var.client_isolation}    hideSsidEnabled=${common_var.hidden_ssid}   proxyARPEnabled=${common_var.proxy_arp}   maxClientsPerRadio=${common_var.max_clients}   support80211dEnabled=${common_var.w11d}   support80211kEnabled=${common_var.w11k}   dhcpOption82Enabled=${common_var.dhcp_option_82}   unauthClientStatsEnabled=${common_var.client_txrx}   clientIdleTimeoutSec=${common_var.client_idle}   clientFingerprintingEnabled=${common_var.fingerprint}   ofdmOnlyEnabled=${common_var.ofdm_only}   bssMinRateMbps=Disable   bandBalancing=UseZoneSetting   pmkCachingEnabled=${pmkCachingEnabled}   okcEnabled=${okcEnabled}

        Log   ${adv-opt}
	${urlParams}=   Create Dictionary   id=${wlan_id}   zoneId=${zone-id}
        ${data}=    Create Dictionary   advancedOptions=${adv-opt}
        rkszones update_wlan  ${data}  urlParams=${urlParams}

	#${aaa_vlan_override} =   Create Dictionary   aaaVlanOverride=${common_var.isfalse}
	#${data} =   Create Dictionary   vlan=${aaa_vlan_override}
	#rkszones update_wlan  ${data}  urlParams=${urlParams}


Create IOS PEAP WLAN

	#${lib} =  Get Library Instance   test_var
        ${zone-id}=   Get Zone ID by name
        Log   ${zone-id}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}
        ${auth-data}=   Create Dictionary   throughController=${common_var.isfalse}    name=${AAA_PROFILE}
        ${wlan-data}=   Create Dictionary   name=${PEAPWLAN}   ssid=${PEAPWLAN}   authServiceOrProfile=${auth-data}   description=1xProfile
        ${wlan_id}=  rkszones create_wlan_standard80211    ${wlan-data}   urlParams=${urlParams}
        Log   ${wlan_id}

        ${adv-opt}=   Create Dictionary   priority=High  mgmtTxRateMbps=2 mbps   clientIsolationEnabled=${common_var.client_isolation}    hideSsidEnabled=${common_var.hidden_ssid}   proxyARPEnabled=${common_var.proxy_arp}   maxClientsPerRadio=${common_var.max_clients}   support80211dEnabled=${common_var.w11d}   support80211kEnabled=${common_var.w11k}   dhcpOption82Enabled=${common_var.dhcp_option_82}   unauthClientStatsEnabled=${common_var.client_txrx}   clientIdleTimeoutSec=${common_var.client_idle}   clientFingerprintingEnabled=${common_var.fingerprint}   ofdmOnlyEnabled=${common_var.ofdm_only}   bssMinRateMbps=Disable   bandBalancing=UseZoneSetting

        Log   ${adv-opt}
	${urlParams}=   Create Dictionary   id=${wlan_id}   zoneId=${zone-id}
        ${data}=    Create Dictionary   advancedOptions=${adv-opt}
        rkszones update_wlan  ${data}  urlParams=${urlParams}


Create IOS TTLS WLAN

	#${lib} =  Get Library Instance   test_var
        ${zone-id}=   Get Zone ID by name
        Log   ${zone-id}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}
        ${auth-data}=   Create Dictionary   throughController=${common_var.isfalse}    name=${AAA_PROFILE}
        ${wlan-data}=   Create Dictionary   name=${TTLSWLAN}   ssid=${TTLSWLAN}   authServiceOrProfile=${auth-data}   description=1xProfile
        ${wlan_id}=  rkszones create_wlan_standard80211    ${wlan-data}   urlParams=${urlParams}
        Log   ${wlan_id}

        ${adv-opt}=   Create Dictionary   priority=High  mgmtTxRateMbps=2 mbps   clientIsolationEnabled=${common_var.client_isolation}    hideSsidEnabled=${common_var.hidden_ssid}   proxyARPEnabled=${common_var.proxy_arp}   maxClientsPerRadio=${common_var.max_clients}   support80211dEnabled=${common_var.w11d}   support80211kEnabled=${common_var.w11k}   dhcpOption82Enabled=${common_var.dhcp_option_82}   unauthClientStatsEnabled=${common_var.client_txrx}   clientIdleTimeoutSec=${common_var.client_idle}   clientFingerprintingEnabled=${common_var.fingerprint}   ofdmOnlyEnabled=${common_var.ofdm_only}   bssMinRateMbps=Disable   bandBalancing=UseZoneSetting

        Log   ${adv-opt}
	${urlParams}=   Create Dictionary   id=${wlan_id}   zoneId=${zone-id}
        ${data}=    Create Dictionary   advancedOptions=${adv-opt}
        rkszones update_wlan  ${data}  urlParams=${urlParams}


Show AP Config State
	[Arguments]    ${APMAC}=${AP_MACC[${0}]}
	${urlParams} =  Create Dictionary   apMac=${APMAC}
	${output} =  aps get operational summary   urlParams=${urlParams}
	#Log   ${output}
	${state} =  Get From Dictionary   ${output}   configState
	Should Be Equal As Strings   ${state}   completed
	APCLI Create and Save Context OK    ip addr=${AP_IP}    port=22    username=${SCG_HOSTNAME}    password=${AP_PASSWORD}
	Ssh Connection Mac Sniffer      mac_ipaddr=${MAC_SNIFFER_HOST}     username=${MAC_USERNAME}  password=${MAC_PASSWORD}
	${source_mac_5G}=    RWQAAPCLIKeywords.get_wlan_bssid_via_ssid  ${WLAN}

Show AP Config State list backup
	[Arguments]    ${APMACC}=${AP_MACC[${0}]}
	${ap_length}=   get length    ${APMACC}
	:FOR   ${index}    IN RANGE    0   ${ap_length}
	\	${urlParams} =  Create Dictionary   apMac=${APMACC[${index}]}
	\	${output} =  aps get operational summary   urlParams=${urlParams}
	\	#Log   ${output}
	\	${state} =  Get From Dictionary   ${output}   configState
	\	Should Be Equal As Strings   ${state}   completed

Get AP Config State 
	[Arguments]    ${APMACC}=${AP_MACC[${0}]}
	Wait Until Keyword Succeeds   10min   10s    Show AP Config State   ${APMACC}


Create MacAuth WLAN
	
	#${lib} =  Get Library Instance   test_var
        ${zone-id}=   Get Zone ID by name
        Log   ${zone-id}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}
        ${auth-data}=   Create Dictionary   throughController=${common_var.isfalse}    name=${AAA_PROFILE}
        ${wlan-data}=   Create Dictionary   name=${WLAN}   ssid=${WLAN}   authServiceOrProfile=${auth-data}   description=MacAuth Profile
        ${wlan_id}=  rkszones create_wlan_standard_mac    ${wlan-data}   urlParams=${urlParams}
        Log   ${wlan_id}

        ${adv-opt}=   Create Dictionary   priority=High  mgmtTxRateMbps=2 mbps   clientIsolationEnabled=${common_var.client_isolation}    hideSsidEnabled=${common_var.hidden_ssid}   proxyARPEnabled=${common_var.proxy_arp}   maxClientsPerRadio=${common_var.max_clients}   support80211dEnabled=${common_var.w11d}   support80211kEnabled=${common_var.w11k}   dhcpOption82Enabled=${common_var.dhcp_option_82}   unauthClientStatsEnabled=${common_var.client_txrx}   clientIdleTimeoutSec=${common_var.client_idle}   clientFingerprintingEnabled=${common_var.fingerprint}   ofdmOnlyEnabled=${common_var.ofdm_only}   bssMinRateMbps=Disable   bandBalancing=UseZoneSetting

        Log   ${adv-opt}
	${urlParams}=   Create Dictionary   id=${wlan_id}   zoneId=${zone-id}
        ${data}=    Create Dictionary   advancedOptions=${adv-opt}
        rkszones update_wlan  ${data}  urlParams=${urlParams}

	${mac_auth} =  Create Dictionary    macAuthMacFormat=UpperColon
	${data}=    Create Dictionary   macAuth=${mac_auth}
        rkszones update_wlan  ${data}  urlParams=${urlParams}
	
	
Create 8021xMacAuth WLAN
	
	#${lib} =  Get Library Instance   test_var
        ${zone-id}=   Get Zone ID by name
        Log   ${zone-id}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}
        ${auth-data}=   Create Dictionary   throughController=${common_var.isfalse}    name=${AAA_PROFILE}
        ${wlan-data}=   Create Dictionary   name=${WLAN}   ssid=${WLAN}   authServiceOrProfile=${auth-data}   description=MacAuth Profile
        ${wlan_id}=  rkszones create_wlan_standard8021_x_mac    ${wlan-data}   urlParams=${urlParams}
        Log   ${wlan_id}

        ${adv-opt}=   Create Dictionary   priority=High  mgmtTxRateMbps=2 mbps   clientIsolationEnabled=${common_var.client_isolation}    hideSsidEnabled=${common_var.hidden_ssid}   proxyARPEnabled=${common_var.proxy_arp}   maxClientsPerRadio=${common_var.max_clients}   support80211dEnabled=${common_var.w11d}   support80211kEnabled=${common_var.w11k}   dhcpOption82Enabled=${common_var.dhcp_option_82}   unauthClientStatsEnabled=${common_var.client_txrx}   clientIdleTimeoutSec=${common_var.client_idle}   clientFingerprintingEnabled=${common_var.fingerprint}   ofdmOnlyEnabled=${common_var.ofdm_only}   bssMinRateMbps=Disable   bandBalancing=UseZoneSetting

        Log   ${adv-opt}
	${urlParams}=   Create Dictionary   id=${wlan_id}   zoneId=${zone-id}
        ${data}=    Create Dictionary   advancedOptions=${adv-opt}
        rkszones update_wlan  ${data}  urlParams=${urlParams}

	${mac_auth} =  Create Dictionary    macAuthMacFormat=UpperColon
	${data}=    Create Dictionary   macAuth=${mac_auth}
        rkszones update_wlan  ${data}  urlParams=${urlParams}
	

Create Hotspot WLAN

	[Arguments]   ${AAA_PROFILE_SZ}=${AAA_PROFILE}   

	#${lib} =  Get Library Instance   test_var

	${adv-opt}=   Create Dictionary   priority=High  mgmtTxRateMbps=2 mbps   clientIsolationEnabled=${common_var.client_isolation}    hideSsidEnabled=${common_var.hidden_ssid}   proxyARPEnabled=${common_var.proxy_arp}   maxClientsPerRadio=${common_var.max_clients}   support80211dEnabled=${common_var.w11d}   support80211kEnabled=${common_var.w11k}   dhcpOption82Enabled=${common_var.dhcp_option_82}   unauthClientStatsEnabled=${common_var.client_txrx}   clientIdleTimeoutSec=${common_var.client_idle}   clientFingerprintingEnabled=${common_var.fingerprint}   ofdmOnlyEnabled=${common_var.ofdm_only}   bssMinRateMbps=Disable   bandBalancing=UseZoneSetting
        Log   ${adv-opt}

	${zone-id}=   Get Zone ID by name
        Log   ${zone-id}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}
        ${wlan-data}=   Create Dictionary   name=${wlan}  ssid=${WLAN}
        ${auth-data}=   Create Dictionary   name=${AAA_PROFILE_SZ}   throughController=${common_var.isfalse}
        ${portalService-data}=  Create Dictionary  name=${WLAN}
        ${cp-data}=  Create Dictionary  name=${WLAN}  ssid=${WLAN}     authServiceOrProfile=${auth-data}  portalServiceProfile=${portalService-data}
        ${wlan_id}=   rkszones create_wlan_hotspot   ${cp-data}   urlParams=${urlParams}
        Should Not Be Equal   ${wlan_id}   None
	
	${urlParams}=   Create Dictionary   zoneId=${zone-id}  id=${wlan_id}
        ${data}=    Create Dictionary   advancedOptions=${adv-opt}
        rkszones update_wlan  ${data}  urlParams=${urlParams}
	${data}=   Create Dictionary   bypassCNA=${common_var.bypassCNA}
	rkszones update_wlan  ${data}  urlParams=${urlParams}





Create WisprMac WLAN

	#${lib} =  Get Library Instance   test_var

	${adv-opt}=   Create Dictionary   priority=High  mgmtTxRateMbps=2 mbps   clientIsolationEnabled=${common_var.client_isolation}    hideSsidEnabled=${common_var.hidden_ssid}   proxyARPEnabled=${common_var.proxy_arp}   maxClientsPerRadio=${common_var.max_clients}   support80211dEnabled=${common_var.w11d}   support80211kEnabled=${common_var.w11k}   dhcpOption82Enabled=${common_var.dhcp_option_82}   unauthClientStatsEnabled=${common_var.client_txrx}   clientIdleTimeoutSec=${common_var.client_idle}   clientFingerprintingEnabled=${common_var.fingerprint}   ofdmOnlyEnabled=${common_var.ofdm_only}   bssMinRateMbps=Disable   bandBalancing=UseZoneSetting
        Log   ${adv-opt}

        ${zone-id}=   Get Zone ID by name
        Log   ${zone-id}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}
        ${wlan-data}=   Create Dictionary   name=${WLAN}  ssid=${WLAN}
        ${auth-data}=   Create Dictionary   name=${AAA_PROFILE}   throughController=${common_var.isfalse}
        ${portalService-data}=  Create Dictionary  name=${WLAN}
        ${cp-data}=  Create Dictionary  name=${WLAN}  ssid=${WLAN}     authServiceOrProfile=${auth-data}  portalServiceProfile=${portalService-data}
        ${wlan_id}=   rkszones create_wlan_hotspot_mac_by_pass   ${cp-data}   urlParams=${urlParams}
        Should Not Be Equal   ${wlan_id}   None
	${urlParams}=   Create Dictionary   zoneId=${zone-id}  id=${wlan_id}
        ${data}=    Create Dictionary   advancedOptions=${adv-opt}
        rkszones update_wlan  ${data}  urlParams=${urlParams}
	${data}=   Create Dictionary   bypassCNA=${common_var.bypassCNA}
	rkszones update_wlan  ${data}  urlParams=${urlParams}

	${mac_auth} =  Create Dictionary    macAuthMacFormat=UpperColon
	${data}=    Create Dictionary   macAuth=${mac_auth}
        rkszones update_wlan  ${data}  urlParams=${urlParams}


Create Guest WLAN

	#${lib} =  Get Library Instance   test_var
	
	${adv-opt}=   Create Dictionary   priority=High  mgmtTxRateMbps=2 mbps   clientIsolationEnabled=${common_var.client_isolation}    hideSsidEnabled=${common_var.hidden_ssid}   proxyARPEnabled=${common_var.proxy_arp}   maxClientsPerRadio=${common_var.max_clients}   support80211dEnabled=${common_var.w11d}   support80211kEnabled=${common_var.w11k}   dhcpOption82Enabled=${common_var.dhcp_option_82}   unauthClientStatsEnabled=${common_var.client_txrx}   clientIdleTimeoutSec=${common_var.client_idle}   clientFingerprintingEnabled=${common_var.fingerprint}   ofdmOnlyEnabled=${common_var.ofdm_only}   bssMinRateMbps=Disable   bandBalancing=UseZoneSetting
        Log   ${adv-opt}

        ${zone-id}=   Get Zone ID by name
        Log   ${zone-id}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}
        ${wlan-data}=   Create Dictionary   name=${WLAN}   ssid=${WLAN}
        ${auth-data}=   Create Dictionary   throughController=${common_var.istrue}    name=Guest
        ${portalService-data}=  Create Dictionary  name=${WLAN}
        ${guest-data}=  Create Dictionary  name=${WLAN}  ssid=${WLAN}     authServiceOrProfile=${auth-data}  portalServiceProfile=${portalService-data}
        ${wlan_id}=   rkszones create_wlan_guest_access   ${guest-data}   urlParams=${urlParams}
	
	${urlParams}=   Create Dictionary   zoneId=${zone-id}  id=${wlan_id}
        ${data}=    Create Dictionary   advancedOptions=${adv-opt}
        rkszones update_wlan  ${data}  urlParams=${urlParams}
	${data}=   Create Dictionary   bypassCNA=${common_var.bypassCNA}
	rkszones update_wlan  ${data}  urlParams=${urlParams}

Create IOS Guest WLAN

	#${lib} =  Get Library Instance   test_var
	
	${adv-opt}=   Create Dictionary   priority=High  mgmtTxRateMbps=2 mbps   clientIsolationEnabled=${common_var.client_isolation}    hideSsidEnabled=${common_var.hidden_ssid}   proxyARPEnabled=${common_var.proxy_arp}   maxClientsPerRadio=${common_var.max_clients}   support80211dEnabled=${common_var.w11d}   support80211kEnabled=${common_var.w11k}   dhcpOption82Enabled=${common_var.dhcp_option_82}   unauthClientStatsEnabled=${common_var.client_txrx}   clientIdleTimeoutSec=${common_var.client_idle}   clientFingerprintingEnabled=${common_var.fingerprint}   ofdmOnlyEnabled=${common_var.ofdm_only}   bssMinRateMbps=Disable   bandBalancing=UseZoneSetting
        Log   ${adv-opt}

        ${zone-id}=   Get Zone ID by name
        Log   ${zone-id}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}
        ${wlan-data}=   Create Dictionary   name=${WLAN}   ssid=${WLAN}
        ${auth-data}=   Create Dictionary   throughController=${common_var.istrue}    name=Guest
        ${portalService-data}=  Create Dictionary  name=${WLAN}
        ${guest-data}=  Create Dictionary  name=${WLAN}  ssid=${WLAN}     authServiceOrProfile=${auth-data}  portalServiceProfile=${portalService-data}
        ${wlan_id}=   rkszones create_wlan_guest_access   ${guest-data}   urlParams=${urlParams}
	
	${urlParams}=   Create Dictionary   zoneId=${zone-id}  id=${wlan_id}
        ${data}=    Create Dictionary   advancedOptions=${adv-opt}
        rkszones update_wlan  ${data}  urlParams=${urlParams}

	${data}=   Create Dictionary   bypassCNA=${common_var.bypassCNA}
	rkszones update_wlan  ${data}  urlParams=${urlParams}

	
Generate Guest Pass

	#${lib} =  Get Library Instance   test_var

        ${wlan_id}=  Get WLAN ID by Name
        #Log   ${wlan_id}
        ${zone_id}=  Get Zone ID by Name
        Log   ${zone_id}

        ${wlan-data}=  Create Dictionary   id=${wlan_id}   name=${WLAN}
        ${zone-data}=  Create Dictionary   id=${zone_id}   name=${ZONE_NAME}
        ${pass-validity}=  Create Dictionary   expirationValue=${guest_multi_pass.pass_time}   expirationUnit=WEEK
        ${device-limit}=  Create Dictionary   maxDevicesAllowed=UNLIMITED
        ${login-again}=  Create Dictionary   requireLoginAgain=${common_var.isfalse}
        ${data}=  Create Dictionary   guestName=${WLAN}  wlan=${wlan-data}  zone=${zone-data}  numberOfPasses=${guest_multi_pass.number_passes}   passValidFor=${pass-validity}  autoGeneratedPassword=${common_var.isfalse}   passValue=${G_KEY}  maxDevices=${device-limit}  sessionDuration=${login-again}   passEffectSince=CREATION_TIME
        ${guestpass-id}=    pubapi.identity generate_guest_pass   ${data}


Generate single Guest Pass

	#${lib} =  Get Library Instance   test_var

        ${wlan_id}=  Get WLAN ID by Name
        #Log   ${wlan_id}
        ${zone_id}=  Get Zone ID by Name
        Log   ${zone_id}

        ${wlan-data}=  Create Dictionary   id=${wlan_id}   name=${WLAN}
        ${zone-data}=  Create Dictionary   id=${zone_id}   name=${ZONE_NAME}
        ${pass-validity}=  Create Dictionary   expirationValue=${guest_multi_pass.pass_time}   expirationUnit=WEEK
        ${device-limit}=  Create Dictionary   maxDevicesAllowed=LIMITED    maxDevicesNumber=${guest_single_pass.dev_limit}
        ${login-again}=  Create Dictionary   requireLoginAgain=${common_var.isfalse}
        ${data}=  Create Dictionary   guestName=${WLAN}  wlan=${wlan-data}  zone=${zone-data}  numberOfPasses=${guest_multi_pass.number_passes}   passValidFor=${pass-validity}  autoGeneratedPassword=${common_var.isfalse}   passValue=${G_KEY}  maxDevices=${device-limit}  sessionDuration=${login-again}   passEffectSince=CREATION_TIME
        ${guestpass-id}=    pubapi.identity generate_guest_pass   ${data}


Create Web WLAN

	#${lib} =  Get Library Instance   test_var
	
	${adv-opt}=   Create Dictionary   priority=High  mgmtTxRateMbps=2 mbps   clientIsolationEnabled=${common_var.client_isolation}    hideSsidEnabled=${common_var.hidden_ssid}   proxyARPEnabled=${common_var.proxy_arp}   maxClientsPerRadio=${common_var.max_clients}   support80211dEnabled=${common_var.w11d}   support80211kEnabled=${common_var.w11k}   dhcpOption82Enabled=${common_var.dhcp_option_82}   unauthClientStatsEnabled=${common_var.client_txrx}   clientIdleTimeoutSec=${common_var.client_idle}   clientFingerprintingEnabled=${common_var.fingerprint}   ofdmOnlyEnabled=${common_var.ofdm_only}   bssMinRateMbps=Disable   bandBalancing=UseZoneSetting
        Log   ${adv-opt}
	
	${zone-id}=   Get Zone ID by name
        Log   ${zone-id}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}
        ${wlan-data}=   Create Dictionary   name=${WLAN}  ssid=${WLAN}
        ${auth-data}=   Create Dictionary   name=${AAA_PROFILE}   throughController=${common_var.isfalse} 
        ${portalService-data}=  Create Dictionary  name=${WLAN}
        ${web-data}=  Create Dictionary  name=${WLAN}  ssid=${WLAN}     authServiceOrProfile=${auth-data}  portalServiceProfile=${portalService-data}
        ${wlan_id}=   rkszones create_wlan_web_auth   ${web-data}   urlParams=${urlParams}
        Should Not Be Equal   ${wlan_id}   None
	${urlParams}=   Create Dictionary   zoneId=${zone-id}  id=${wlan_id}
        ${data}=    Create Dictionary   advancedOptions=${adv-opt}
        rkszones update_wlan  ${data}  urlParams=${urlParams}
	${data}=   Create Dictionary   bypassCNA=${common_var.bypassCNA}
	rkszones update_wlan  ${data}  urlParams=${urlParams}



Delete Web profile

        ${zone-id}=  Get Zone ID by name
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}
        ${web_list}=   rkszones get_web_authentication_portals   urlParams=${urlParams}
        Log   ${web_list}
        ${web_id}=   get_obj_by_key_in_list   ${web_list['list']}  key=name  value=${WLAN}
        Log   ${web_id['id']}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}   id=${web_id['id']}
        rkszones delete_web_authentication   urlParams=${urlParams}


Create WLAN Group

        ${zone-id}=   Get Zone ID by name
        Log   ${zone-id}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}
        ${wlan-grp-data}=   Create Dictionary   name=${WLAN}
        ${wlan_grp_id}=   rkszones create_wlan_group   ${wlan-grp-data}   urlParams=${urlParams}


Map WLAN to WLAN Group

	#${lib} =  Get Library Instance   test_var
        ${zone-id}=   Get Zone ID by name
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}

        ${wlan_groups}=   rkszones get_wlan_groups   urlParams=${urlParams}
        Log   ${wlan_groups}
        ${wlan_grp_id}=   get_obj_by_key_in_list   ${wlan_groups['list']}  key=name  value=${WLAN}
        Log   ${wlan_grp_id['id']}

        ${wlan_data}=   rkszones get_wlans   urlParams=${urlParams}
        Log   ${wlan_data}
        ${wlan_id}=   get_obj_by_key_in_list   ${wlan_data['list']}  key=name  value=${WLAN}
        Log   ${wlan_id['id']}

        ${wlan-grp-mem-data}=   Create Dictionary   id=${wlan_id['id']}   accessVlan=${common_var.access_vlan}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}   id=${wlan_grp_id['id']}
        ${res}=   rkszones add_wlan_group_member   ${wlan-grp-mem-data}   urlParams=${urlParams}

Map WLAN to WLAN Group WLAN Prioritization TC

	#${lib} =  Get Library Instance   test_var
        ${zone-id}=   Get Zone ID by name
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}

        ${wlan_groups}=   rkszones get_wlan_groups   urlParams=${urlParams}
        Log   ${wlan_groups}
        ${wlan_grp_id}=   get_obj_by_key_in_list   ${wlan_groups['list']}  key=name  value=${WLAN}
        Log   ${wlan_grp_id['id']}

        ${wlan_data}=   rkszones get_wlans   urlParams=${urlParams}
        Log   ${wlan_data}
        ${wlan_id}=   get_obj_by_key_in_list   ${wlan_data['list']}  key=name  value=${WLAN}
        Log   ${wlan_id['id']}

        ${wlan-grp-mem-data}=   Create Dictionary   id=${wlan_id['id']}   accessVlan=${common_var.access_vlan}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}   id=${wlan_grp_id['id']}
        ${res}=   rkszones add_wlan_group_member   ${wlan-grp-mem-data}   urlParams=${urlParams}

	${wlan_data}=   rkszones get_wlans   urlParams=${urlParams}
        Log   ${wlan_data}
        ${wlan_id}=   get_obj_by_key_in_list   ${wlan_data['list']}  key=name  value=IOTRWSZ1
        Log   ${wlan_id['id']}

        ${wlan-grp-mem-data}=   Create Dictionary   id=${wlan_id['id']}   accessVlan=${common_var.access_vlan}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}   id=${wlan_grp_id['id']}
        ${res}=   rkszones add_wlan_group_member   ${wlan-grp-mem-data}   urlParams=${urlParams}

Map PEAPWLAN to WLAN Group

	#${lib} =  Get Library Instance   test_var
        ${zone-id}=   Get Zone ID by name
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}

        ${wlan_groups}=   rkszones get_wlan_groups   urlParams=${urlParams}
        Log   ${wlan_groups}
        ${wlan_grp_id}=   get_obj_by_key_in_list   ${wlan_groups['list']}  key=name  value=${WLAN}
        Log   ${wlan_grp_id['id']}

        ${wlan_data}=   rkszones get_wlans   urlParams=${urlParams}
        Log   ${wlan_data}
        ${wlan_id}=   get_obj_by_key_in_list   ${wlan_data['list']}  key=name  value=${PEAPWLAN}
        Log   ${wlan_id['id']}

        ${wlan-grp-mem-data}=   Create Dictionary   id=${wlan_id['id']}   accessVlan=${common_var.access_vlan}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}   id=${wlan_grp_id['id']}
        ${res}=   rkszones add_wlan_group_member   ${wlan-grp-mem-data}   urlParams=${urlParams}


Map TTLSWLAN to WLAN Group

	#${lib} =  Get Library Instance   test_var
        ${zone-id}=   Get Zone ID by name
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}

        ${wlan_groups}=   rkszones get_wlan_groups   urlParams=${urlParams}
        Log   ${wlan_groups}
        ${wlan_grp_id}=   get_obj_by_key_in_list   ${wlan_groups['list']}  key=name  value=${WLAN}
        Log   ${wlan_grp_id['id']}

        ${wlan_data}=   rkszones get_wlans   urlParams=${urlParams}
        Log   ${wlan_data}
        ${wlan_id}=   get_obj_by_key_in_list   ${wlan_data['list']}  key=name  value=${TTLSWLAN}
        Log   ${wlan_id['id']}

        ${wlan-grp-mem-data}=   Create Dictionary   id=${wlan_id['id']}   accessVlan=${common_var.access_vlan}
        ${urlParams}=   Create Dictionary   zoneId=${zone-id}   id=${wlan_grp_id['id']}
        ${res}=   rkszones add_wlan_group_member   ${wlan-grp-mem-data}   urlParams=${urlParams}


Create Zone if Not exists
	
	[Arguments]    ${zone}=${ZONE_NAME}   

	${zone_data}=   rkszones get list

    	${zone_info}=    Convert to String   ${zone_data}

    	Log   ${zone_info}
	
    	${result}=   run keyword and return status   should match regexp  ${zone_info}  ${ZONE_NAME}	
	${res}=     run keyword if   '${result}'=='True'     Check Zone Type
	run keyword if   '${IS_DUAL_ZONE}'=='False' and '${res}'=='False' or '${res}'=='None'   Create Zone
	run keyword if   '${IS_DUAL_ZONE}'=='True' and '${res}'=='False' or '${res}'=='None'   Create Dual Zone
        #run keyword if   '${res}'=='False' and '${IS_IPV6_Zone}'=='False' and '${IS_DUAL_ZONE}'=='False'   Create Zone
	#run keyword if   '${res}'=='False' and '${IS_IPV6_Zone}'=='True' and '${IS_DUAL_ZONE}'=='False'   Create IPV6 Zone
	#run keyword if   '${res}'=='False' and '${IS_IPV6_Zone}'=='False' and '${IS_DUAL_ZONE}'=='True'   Create Dual Zone

Check Zone Type
	${zone_id} =   Get Zone ID by name
	${urlParams}=  Create Dictionary   id=${zone_id}
	${zone_spec_det}=   rkszones get   urlParams=${urlParams}
	
	${ip_mode}=   set variable   ${zone_spec_det['ipMode']}
	#${return_value}=   run keyword if   '${IS_IPV6_ZONE}'=='True' and '${ip_mode}'!='IPV6'   Follow Zone Config Proc  ${zone_id}
	#...		   ELSE IF    '${IS_DUAL_ZONE}'=='True' and '${ip_mode}'!='IPV4_IPV6'   Follow Zone Config Proc  ${zone_id}
	#...		   ELSE IF    '${IS_IPV6_ZONE}'=='False' and '${IS_DUAL_ZONE}'=='False' and '${ip_mode}'!='IPV4'   Follow Zone Config Proc  ${zone_id}
	${return_value}=   run keyword if   '${IS_DUAL_ZONE}'=='True' and '${ip_mode}'!='IPV4_IPV6'   Follow Zone Config Proc  ${zone_id}
	...		   ELSE IF    '${IS_DUAL_ZONE}'=='False' and '${ip_mode}'!='IPV4'   Follow Zone Config Proc  ${zone_id}
	...		   ELSE    set variable   True
	[Return]   ${return_value}    	 	

Follow Zone Config Proc
	[Arguments]   ${zone_id_auto}
	${zone_id} =   Get Zone ID by name   ${DEFAULT_ZONE}
	${params}=   Create Dictionary   zoneId=${zone_id_auto}
	${aplist_zoneid_ret}=   aps_get   params=${params}
	${aplist}=   set variable   ${aplist_zoneid_ret['list']}
	${aplist_length}=   get length   ${aplist}		
	:FOR   ${index}    IN RANGE    0   ${aplist_length}
	\	Move AP   ${zone_id}  ${aplist[${index}]['mac']}
	#Delete WLAN group
	Delete Zone
	[Return]   False
	
SZ SUITE SETUP
	
    	Create Public Api Session   
    	${zone_id} =   Get Zone ID by name
	${ap_length}=   get length    ${AP_MACC}
	${params}=  Create Dictionary   zoneId=${zone_id}    
	${aplist_zoneid}=   aps_get   params=${params}
	#${aplist}=   get_obj_by_key_in_list   ${aplist_zoneids['list']}  key=zoneId  value=${zone_id}
	${aplist_info}=    Convert to String   ${aplist_zoneid}
	:FOR   ${index}    IN RANGE    0   ${ap_length}
	\	${res}=   run keyword and return status   should match regexp  ${aplist_info}  ${AP_MACC[${index}]}
	\	run keyword if   '${res}'=='False'   sz_setup.Move AP   ${zone_id}  ${AP_MACC[${index}]}	
    	Get Zone Details
    	Zone Configuration
    	#Create Open WLAN
    	Create WLAN Group
    	Map WLAN to WLAN Group
	Initialize Result Object
	

Initialize Result Object
	${ResultList} =   Create List
	Set Suite Variable   ${ResultList}
	${device_dict} =   Create Dictionary
	Set Suite Variable   ${device_dict}
	${len} =   Get Length   ${dev_details}
	:For   ${d}   IN RANGE   0   ${len}
	\	${pos} =  Set variable   @{dev_details}[${d}]
	\	Set To Dictionary   ${device_dict}   ${dev.mac_dict[${pos}][2]['mac']}    ${dev.mac_dict[${pos}][1]['name']}
	Log Dictionary   ${device_dict}
	${time} =   Get Time
	Append To File   ${ProjectTarget}/results/TestExecutionResults.log   ${time} ${\n}
	${name} =   Evaluate   '${SUITE NAME}'.replace(' ','-')      	
	Append To File   ${ProjectTarget}/results/TestExecutionResults.log   Test case:${name} ${\n}
	Append To File   ${ProjectTarget}/results/TestExecutionResults.log   ---------------------------------- ${\n}
	 
	
SZ SUITE SETUP WLAN Prioritization TC
	
    	Create Public Api Session
    	Get Zone Details
    	Zone Configuration
    	Create WLAN Group
	Map WLAN to WLAN Group WLAN Prioritization TC

SZ SUITE TEARDOWN
	Log   ${ResultList}
	#${zone_id}=   Get Zone ID by name   zone_name=Default Zone
	${ap_length}=   get length    ${AP_MACC}
	:FOR   ${index}    IN RANGE    0   ${ap_length}
	\	Set default WLAN group to AP   ${AP_MACC[${index}]}
	\	Enable or Disable AP Radio   ${AP_MACC[${index}]}   wlanService50Enabled   ${false}
	\	Enable or Disable AP Radio   ${AP_MACC[${index}]}   wlanService24Enabled   ${false}   
        Delete WLAN
        Delete WLAN group

	#sleep   100s
	#Wait Until Keyword Succeeds   250s   30s   Delete Zone
	

SZ SUITE ROAMING TEARDOWN 
        Set default WLAN group to AP   ${AP_MACC[0]}
	Set default WLAN group to AP   ${AP_MACC[1]}
	Delete WLAN
        Delete WLAN group

SZ SUITE TEARDOWN WLAN Prioritization TC
        Set default WLAN group to AP
        Delete WLAN WLAN Prioritization TC
        Delete WLAN group

SZ PEAP SUITE SETUP
	Create Public Api Session
    	Get Zone Details
    	Zone Configuration
    	Create WLAN Group
    	Map PEAPWLAN to WLAN Group
	


SZ PEAP SUITE TEARDOWN
        Set default WLAN group to AP
        Delete PEAPWLAN
        Delete WLAN group

SZ TTLS SUITE SETUP
	Create Public Api Session
    	Get Zone Details
    	Zone Configuration
    	Create WLAN Group
    	Map TTLSWLAN to WLAN Group
	


SZ TTLS SUITE TEARDOWN
        Set default WLAN group to AP
        Delete TTLSWLAN
        Delete WLAN group

#Niveditha-Added keywords    
Execute Query Criteria
	${session}=   session_get
	Log   ${session}
	${domain}=   Get From Dictionary   ${session}   domainId
	${filter}=   Create Dictionary   type=DOMAIN   value=${domain}
	${list}=   Create List   ${filter}
	${params}=    Create Dictionary   filters=${list}
	[return]   ${params}

Delete Application Policy If Exists
	[Arguments]   ${policy_list}
	${policy_id}=   get_obj_by_key_in_list   ${policy_list['list']}   key=name   value=${WLAN}
	Log   ${policy_id}
	${url_params}=  Create Dictionary   id=${policy_id['id']}
        avc delete_application_policy_by_id    urlParams=${urlParams}

Create Application Denial Policy
        [Arguments]   ${RULE_TYPE}    ${APPLICATION_TYPE}    ${CATID}     ${APPID}   ${PRIORITY}
	${apprules}=    Create Dictionary    ruleType=${RULE_TYPE}    applicationType=${APPLICATION_TYPE}    catId=${CATID}     appId=${APPID}   priority=${PRIORITY}
	@{apprules_list}=   Create list 
	Append To List  ${apprules_list}    ${apprules}
	${data}=   Create Dictionary   name=${WLAN}    applicationRules=${apprules_list}
	${params}=    Execute Query Criteria
	${policy_list}=   query get_application_policy_list   ${params}
        Log   ${policy_list}
	${policy_info}=   Convert To String   ${policy_list}
	${res}=   run keyword and return status   should match regexp   ${policy_info}   ${WLAN}
	run keyword if   '${res}'!='False'   Delete Application Policy If Exists   ${policy_list}
	${avcid}=    avc create_application_policy_by_id     ${data}
	Log    ${avcid}
	Set Suite Variable    ${avcid}
	[Return]    ${avcid}

Delete Application Denial Policy 
	[Arguments]   ${avcid}
	${urlParams}=   Create Dictionary   id=${avcid}
	avc delete_application_policy_by_id    urlParams=${urlParams}

Enable Application Visibility Parameter and UTP
	[Arguments]   ${profile_id}
	${zone_id}=   Get Zone ID by name
        Log   ${zone_id}
        ${wlan_id}=   Get WLAN ID by name
        Log   ${wlan_id}
	${policy}=   Create Dictionary   id=${profile_id}     name=${WLAN}
	${urlParams}=   Create Dictionary   zoneId=${zone_id}  id=${wlan_id}
	${adv-opt}=   Create Dictionary   avcEnabled=${common_var.istrue}    
	${data}=    Create Dictionary   advancedOptions=${adv-opt}
	rkszones update_wlan  ${data}  urlParams=${urlParams}
	${data}=    Create Dictionary   defaultUserTrafficProfile=${policy}
	rkszones update_wlan  ${data}  urlParams=${urlParams}

Create Usertraffic Profile
	[Arguments]   ${avcid}
	${data}=   Create Dictionary   name=${WLAN}    defaultAction=${L2_ACL_RESTRICTION}
	RunKeyword and Ignore Error   Delete Usertraffic Profile
	${profile_id}=     profiles create_user_traffic_profile     ${data}
	Log    ${profile_id}
	${data}=    Create Dictionary   appPolicyId=${avcid}
	${urlParams}=   Create Dictionary    id=${profile_id}
	profiles update_user_traffic_profile    ${data}    urlParams=${urlParams}
	[Return]    ${profile_id}

Delete Usertraffic Profile
	${user_profiles}=    profiles get_user_traffic_profiles
	${user_profiles_info}=   Convert To String   ${user_profiles}
	${res}=   run keyword and return status   should match regexp  ${user_profiles_info}  ${WLAN}
        run keyword if   '${res}'!='False'   Delete Usertraffic Profile If Exists   ${user_profiles}

Delete Usertraffic Profile If Exists
	[Arguments]   ${user_profiles}
	${profile_id}=  get_obj_by_key_in_list   ${user_profiles['list']}  key=name  value=${WLAN}
        Log   ${profile_id['id']}
	${urlParams}=   Create Dictionary   id=${profile_id['id']}
	profiles delete_user_traffic_profile      urlParams=${urlParams}

Create Userdefined AVC
        [Arguments]   ${PORT}
	${uavc}=    Create Dictionary    name=${WLAN}    type=IP_WITH_PORT    destIp=${APPIUM_IP}     netmask=255.255.255.0   destPort=${PORT}   protocol=TCP
        #RunKeyword and Ignore Error   Delete Userdefined AVC   
	${uavcid}=    avc create_user_defined_profile     ${uavc}
	Log    ${uavcid}
	Set Suite Variable    ${uavcid}
	[Return]    ${uavcid}

Delete Userdefined AVC
	[Arguments]    ${uavcid}
	${urlParams}=   Create Dictionary   id=${uavcid}
	avc delete_user_defined_profile   urlParams=${urlParams}

Enable or Disable AP Radio
    [Arguments]    ${ap_mac_addr}    ${wlanService}=wlanService24Enabled   ${flag}=${true}
    ${update_data}=    Create Dictionary    ${wlanService}     ${flag}
    ${ap_url}=    Create Dictionary    apMac=${ap_mac_addr}
    aps_update    ${update_data}    urlParams=${ap_url}

Disconnect Single STA from AP
	[Arguments]     ${client_mac}    ${ap_mac_addr}
	${data} =     Create Dictionary    mac=${client_mac}    apMac=${ap_mac_addr}
	clients disconnect    ${data}
