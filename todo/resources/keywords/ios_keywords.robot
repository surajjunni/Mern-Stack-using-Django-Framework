*** Keywords ***

Login To SeeTest PC
	Open Connection   ${SEETEST_IP}
        Login   ${SEETEST_UNAME}   ${SEETEST_PWD}
        Write   echo Remote PC Login
	${output}=   Read Until   Login
        #Should Be Equal    ${output}    Remote PC Login
      

Show iOS Client Details

	${err} =   Execute Command   /cygdrive/c/Python27/python.exe ./IOS_Seetest_Scripts/connected_dev_info.py    stderr
	#Should Be Empty   ${err} 
	${device} =  Execute Command    cat ./IOS_Seetest_Scripts/connected_devices.txt
	Should Not Be Empty   ${device}
	Log   ${device}

Join STA to Open Network

        [Arguments]    ${WLAN}  
        ${err} =   Execute Command   /cygdrive/c/Python27/python.exe ./IOS_Seetest_Scripts/IOT_Open_ntwk.py -s ${WLAN} -i ${PING_IP}    stderr
        Should Be Empty    ${err}

Join STA to WPA-PSK Network

	${err} =  Execute Command  /cygdrive/c/Python27/python.exe ./IOT_WPA.py  -s ${SSID} -i ${PING_IP} -k ${WEP_KEY}    stderr
        Should Contain   ${err}  Ran 1 test in

Join STA to WEP Network

	[Arguments]     ${WLAN}   ${WEP64_KEY}
        ${err} =   Execute Command   /cygdrive/c/Python27/python.exe ./IOS_Seetest_Scripts/IOT_WEP.py -s ${WLAN} -k ${WEP64_KEY} -i ${PING_IP}   stderr
        Should Be Empty    ${err}

Join STA to WEP128 Network

	[Arguments]     ${WLAN}   ${WEP128_KEY}
        ${err} =   Execute Command   /cygdrive/c/Python27/python.exe ./IOS_Seetest_Scripts/IOT_WEP128.py -s ${WLAN} -k ${WEP128_KEY} -i ${PING_IP}   stderr
        Should Be Empty    ${err}


Join STA to 802.1x Network

        [Arguments]     ${WLAN}   ${USER}   ${PASSWORD}   
        ${err} =   Execute Command   /cygdrive/c/Python27/python.exe ./IOS_Seetest_Scripts/IOT_WPA.py -s ${WLAN} -u ${USER} -p ${PASSWORD} -i ${PING_IP}   stderr
        Should Be Empty    ${err}


Join STA to PEAP 1x Network

        [Arguments]     ${WLAN}   ${PROFILE}  
        ${err} =   Execute Command   /cygdrive/c/Python27/python.exe ./IOS_Seetest_Scripts/IOT_PEAP.py -s ${WLAN} -profile ${PROFILE} -i ${PING_IP}   stderr
        Should Be Empty    ${err}

Join STA to TTLS 1x Network

        [Arguments]     ${WLAN}   ${PROFILE}  
        ${err} =   Execute Command   /cygdrive/c/Python27/python.exe ./IOS_Seetest_Scripts/IOT_TTLS.py -s ${WLAN} -profile ${PROFILE} -i ${PING_IP}   stderr
        Should Be Empty    ${err}

Join STA to TLS 1x Network

        [Arguments]     ${WLAN}   ${USER}   ${PROFILE}  
        ${err} =   Execute Command   /cygdrive/c/Python27/python.exe ./IOS_Seetest_Scripts/IOT_TLS.py -s ${WLAN} -u ${USER} -profile ${PROFILE} -i ${PING_IP}   stderr
        Should Be Empty    ${err}


Connect STA and Do Guest Auth with fixed redirection

	[Arguments]    ${NTYPE}   ${WLAN}   ${AUTH}   ${TYPE}   ${URL_VAL_DATA}   ${GUEST_KEY}
	${err}=  Execute Command  /cygdrive/c/Python27/python.exe GA_SCG.py -nw ${NTYPE} -s ${WLAN} -a ${AUTH} -sf ${TYPE} -d ${URL_VAL_DATA} -g ${GUEST_KEY}    stderr
	Should Be Empty    ${err}

Connect STA and Do Guest Auth Session Timeout

	[Arguments]      ${WLAN}    ${G_KEY}
	${err}=  Execute Command  /cygdrive/c/Python27/python.exe ./IOS_Seetest_Scripts/IOT_GA_Redirect_Session_Timeout.py -s ${WLAN} -gp ${G_KEY}   stderr
        Should Be Empty    ${err}

Connect STA and Do Guest Auth Redirection

	[Arguments]      ${WLAN}    ${G_KEY}
	${err}=  Execute Command  /cygdrive/c/Python27/python.exe ./IOS_Seetest_Scripts/IOT_GA_Redirect.py -s ${WLAN} -gp ${G_KEY}   stderr
        Should Be Empty    ${err}

Connect STA and Do Guest Auth

	[Arguments]      ${WLAN}    ${G_KEY}
	${err}=  Execute Command  /cygdrive/c/Python27/python.exe ./IOS_Seetest_Scripts/IOT_GA_UI.py -s ${WLAN} -gp ${G_KEY}   stderr
        Should Be Empty    ${err}

Connect STA and Do Guest Auth Terms

	[Arguments]      ${WLAN}    ${G_KEY}
	${err}=  Execute Command  /cygdrive/c/Python27/python.exe ./IOS_Seetest_Scripts/IOT_GA_UI_Terms.py -s ${WLAN} -gp ${G_KEY}   stderr
        Should Be Empty    ${err}

Connect STA and Do Wispr Auth with fixed redirection

        [Arguments]    ${NTYPE}   ${WLAN}   ${AUTH}   ${TYPE}   ${URL_VAL_DATA}   ${AAA_UNAME}   ${AAA_PWD}   ${IP}
        ${err}=  Execute Command  /cygdrive/c/Python27/python.exe GA_SCG.py -nw ${NTYPE} -s ${WLAN} -a ${AUTH} -sf ${TYPE} -d ${URL_VAL_DATA} -n ${AAA_UNAME} -p ${AAA_PWD} -i ${IP}   stderr
        Should Be Empty    ${err}


Connect STA and Do Wispr Auth with walled garden

	 [Arguments]    ${NTYPE}   ${WLAN}   ${AUTH}   ${TYPE}   ${URL}   ${URL_VAL_DATA}  
        ${err}=  Execute Command  /cygdrive/c/Python27/python.exe GA_SCG.py -nw ${NTYPE} -s ${WLAN} -a ${AUTH} -sf ${TYPE} -u ${URL} -d ${URL_VAL_DATA}   stderr
	Should Be Empty    ${err}

Connect STA and Do Wispr Auth

	[Arguments]    ${NTYPE}   ${WLAN}   ${AUTH}   ${TYPE}   ${URL}   ${URL_VAL_DATA}   ${AAA_UNAME}   ${AAA_PWD}   ${IP}
	${err}=  Execute Command  /cygdrive/c/Python27/python.exe GA_SCG.py -nw ${NTYPE} -s ${WLAN} -a ${AUTH} -sf ${TYPE} -u ${URL} -d ${URL_VAL_DATA} -n "${AAA_UNAME}" -p ${AAA_PWD} -i ${IP}   stderr
        Should Be Empty    ${err}


Connect STA and Do Web Auth with fixed redirection

        [Arguments]    ${NTYPE}   ${WLAN}   ${AUTH}   ${TYPE}   ${URL_VAL_DATA}   ${AAA_UNAME}   ${AAA_PWD}   ${IP}
        ${err}=  Execute Command  /cygdrive/c/Python27/python.exe GA_SCG.py -nw ${NTYPE} -s ${WLAN} -a ${AUTH} -sf ${TYPE} -d ${URL_VAL_DATA} -n ${AAA_UNAME} -p ${AAA_PWD} -i ${IP}    stderr
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


Get Client Fingerprint Details

        Login To Remote PC
        ${err} =  Execute Command   /cygdrive/c/Python27/python.exe get_interface_details.py    stderr
        ${mac}=   Convert To String   " "
        ${output}=  Execute Command   [ -f ./and_mac_detail.txt ] && echo "Found" || echo "Not Found"
        Should Be Equal   ${output}   Found
        ${mac}=   Execute Command    cat and_mac_detail.txt
        Log   ${mac}
        ${client-mac}=   Convert To String    ${mac}
        ${index}=  Convert to Integer   0
        ${urlParams}=   Create Dictionary   apMac=${AP_MAC}
        ${clients}=   aps get clients   urlParams=${urlParams}
        Log   ${clients}


        ${c}=   Get Dictionary Values   ${clients}
        Log   ${c}
        # Get client data from whole dictionary
        ${c1}=  Get Slice From List  ${c}   2  3
        Log  ${c1}

        # Get Total client count
        ${c2}=  Get From List   ${c}  3
        Log   ${c2}

        #Get all client data
        ${d}=  Get From List   ${c1}   0
        Log   ${d}

        :FOR   ${index}   IN RANGE   ${c2}

        \       # Get first client data
        \       ${i}=   Get From List  ${d}   ${index}
        \       Log   ${i}

        \       # Get Values of key's in the list
        \       ${check}=  Get Dictionary Values   ${i}

	\       Log   ${check}

        \       ${mac}=   Get From Dictionary   ${i}   mac
        \       Log   ${mac}
        #\      Run Keyword If   '${client-mac}' == '${mac}'   Exit For Loop
        \       Continue For Loop If   '${client-mac}' != '${mac}'
        \       Exit For Loop
                ${os}=   Get From Dictionary   ${i}   osType
                ${host-name}=   Get From Dictionary   ${i}   hostName
                ${mac}=   Get From Dictionary   ${i}   mac
                Should Be Equal   ${os}   Android
                Should Contain    ${host-name}   android



        #\      ${os}=   Get From Dictionary   ${i}   osType
        #\      ${host-name}=   Get From Dictionary   ${i}   hostName
        #\      Should Be Equal   ${os}   Android
        #\      Should Contain    ${host-name}   android
        #\      Exit For Loop


Check STA Connectivity

	Write   cat ./IOS_Seetest_Scripts/result.txt
	Read Until    Pass

Check STA Connectivity for FDHCP

	Write   cat result.txt
	Read Until   Fail


Check Auth Success

	Write   cat auth_result.txt
        Read Until   Pass

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
	Write   cat webpage_log.txt
 	Read Until   ${URL}
	
	
Check page details for FDHCP
	
	${out}=  Execute command   cat webpage_log.txt
	Should not Contain    ${out}    ${HTTP_URL}

Create iOS Client Json File
	[Arguments]   ${ssid}=None   ${authentication}=None   ${encryption}=None   ${wpa_algorithm}=None   ${passphrase}=None   ${enterprise_type}=None   ${enterprise_username}=None   ${enterprise_password}=None   ${webauth_type}=None   ${guest_key}=None   ${username}=${AAA_UNAME}   ${password}=${AAA_PWD}   ${url}=None   ${url_data}=None   ${web_portal}=None   ${dev_eth_ip}=${SEETEST_IP}    ${windows_username}=${SEETEST_UNAME}  ${windows_password}=${SEETEST_PWD}   
	${count} =    Get Length    ${iOS_device_alias}
	Log   ${RootTarget}
	
	Remove File   ${RootTarget}/../devicemgr/device_cfg_ios.json
	#Create File   ${RootTarget}/../devicemgr/device_cfg_ios.json   {"devices":[
	create_config_file   ${PLATFORM}   ${RootTarget}
	:FOR    ${ios_devicename}   ${n}   ${o}    IN ZIP      ${ios_devicename}   ${iOS_ports}     ${iOS_device_alias}
        \       builtin.log    ${dev_eth_ip}
	\      builtin.log    ${PLATFORM}
    	\	${output} =   update_config_file     ${ssid}   ${authentication}   ${encryption}   ${wpa_algorithm}   ${passphrase}     ${enterprise_type}   ${enterprise_username}   ${enterprise_password}   ${webauth_type}   ${guest_key}   ${username}   ${password}   ${web_portal}   ${dev_eth_ip}   ${windows_username}   ${windows_password}   ${url}    ${url_data}   None   ${n}   ios   ${o}   ${RootTarget}   ${PLATFORM}   ${ios_devicename} 
	\	Log   ${output}
	\	${count}=   Evaluate   ${count} - 1 
	\	Run Keyword If   ${count} != 0     Append To File  ${RootTarget}/../devicemgr/device_cfg_ios.json    ,
    	#Append To File   ${RootTarget}/../devicemgr/device_cfg_ios.json   ]}
	close_config_file   ${PLATFORM}   ${RootTarget}


Connect iOS STA

	${connect} =  Run   python ${RootTarget}/../devicemgr/devicemgr.py -c ${RootTarget}/../devicemgr/device_cfg_ios.json -a connect -t 300 
	
	Log   ${connect}

Get Connectivity Status of iOS STA
	${status} =   Run   python ${RootTarget}/../devicemgr/devicemgr.py -c ${RootTarget}/../devicemgr/device_cfg_ios.json -a status -o ${RootTarget}/../devicemgr/status.json -t 300 
	Log   ${status}



