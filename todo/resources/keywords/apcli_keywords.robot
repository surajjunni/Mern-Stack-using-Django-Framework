#If you want use this resource keywords, please include the following library.
#RWQAAPCLIKeywords.py
#${RootTarget}/resources/keywords/qa/apcli_keywords.robot
*** Settings ***
Library     SSHLibrary
		
*** Keyword ***
Create open-none WLAN
    [Arguments]    ${wlan if}    ${ssid}
    Set open none WLAN    ${wlan if}    ${ssid}

Turn WiFi radio off
    [Arguments]    ${wlan if}
    Set state    ${wlan if}    down
    ${state}=    Get state    ${wlan if}
    Should Be Equal    ${state}    down

Set AP Wlan Cfg and Get BSSID
    [Arguments]    ${wlan if}    ${wlan cfg}    ${wlan channel}=${EMPTY}
    [Documentation]    Set ap wlan encryption channel and get bssid
    Set Wlan IF    ${wlan if}    ${wlan cfg}
    Run Keyword If    "${wlan channel}"!="${EMPTY}"    Set AP Wlan Channel    ${wlan if}    ${wlan channel}
    ${wlan bssid}=    Wait Until Keyword Succeeds    5 min    5 sec    Get Wlan BSSID    ${wlan if}
    [Return]    ${wlan bssid}

Set AP Wlan Channel
    [Arguments]    ${wlan if}    ${wlan channel}    ${check timeout}=3 m    ${check interval}=10 s
    [Documentation]    Set ap wlan channel and verify channel is set correctly
    Run Keyword IF    "${wlan channel}"!="0" and "${wlan channel}"!=""    Wait Until Keyword Succeeds    ${check timeout}    ${check interval}    Set and Verify AP Wlan Channel    ${wlan if}
    ...    ${wlan channel}

Set and Verify AP Wlan Channel
    [Arguments]    ${wlan if}    ${wlan channel}
    [Documentation]    Set channel and verify channel is same as expected
    Set Channel    ${wlan if}    ${wlan channel}
    Sleep    3s
    ${get channel}    ${channel mode}=    Get Channel    ${wlan if}
    Run Keyword IF    "${channel mode.lower()}"=="auto"    Should Be Equal    ${wlan channel.lower()}    ${channel mode.lower()}    ELSE    Should Be Equal As Integers
    ...    ${wlan channel}    ${get channel}

Backup AP Channel
    [Arguments]    ${wlan if}    ${suite var name wlan channel}=\{ap back channel}
    ${back channel}=    Get Channel    ${wlan if}
    Set Suite Variable    ${suite var name wlan channel}    ${back channel}

Restore AP Channel
    [Arguments]    ${wlan if}    ${suite var name wlan channel}=\{ap back channel}
    ${wlan channel}=    Get Variable Value    ${suite var name wlan channel}
    ${channel value}=    Set Variable If    ${wlan channel}==${None}    ${empty}    "${wlan channel[1].lower()}"=="manual"    ${wlan channel[0]}    "${wlan channel[1].lower()}"=="auto"
    ...    ${wlan channel[1]}    ${empty}
    Set AP Wlan Channel    ${wlan if}    ${channel value}

Get AP Base Mac and Save to Suite Var
    [Arguments]    ${suite varname ap mac addr}=\${ap mac addr}
    ${current ap mac addr}=    Get Base Mac
    Set Suite Variable    ${suite varname ap mac addr}    ${current ap mac addr}
    [Return]    ${current ap mac addr}

APCLI Get Firmware Version
    ${fw version}    RWQAAPCLIKeywords.Get Version
    [Return]    ${fw version}

Check AP Firmware Version
    [Arguments]    ${expect fw version}
    ${fw version}=    APCLI Get Firmware Version
    Should Be Equal    ${fw_version}    ${expect fw version}

Check AP Firmware Version in a Certain Period
    [Arguments]    ${expect fw version}    ${check timeout}=6 m    ${check interval}=10 s
    Wait Until Keyword Succeeds    ${check timeout}    ${check interval}    Check AP Firmware Version    ${expect fw version}

Get Wlan If via SSID
    [Arguments]    ${wlan ssid}    ${radio}=${empty}    ${check state up}=${True}
    ${test wlan if}=    SSID to Wlan If    ${radio}    ${wlan ssid}    check_state_up=${check state up}
    Should Not Be Empty    ${test wlan if}
    [Return]    ${test wlan if}

Get Wlan If via SSID Successfully
    [Arguments]    ${wlan ssid}    ${radio}=${empty}    ${check state up}=${True}    ${check timeout}=${300}    ${check interval}=${10}
    ${wlan if}=    Wait Until Keyword Succeeds    ${check timeout}    ${check interval}    Get Wlan If via SSID    ${wlan ssid}    ${radio}
    ...    ${check state up}
    [Return]    ${wlan if}

Get Max Wlans for Both Radios
    ${max_wlans_2g}    ${max_wlans_5g}=    apcli_get_max_wlans
    [Return]    ${max_wlans_2g}    ${max_wlans_5g}
    
APCLI Check Ethernet Interface is Up
    [Arguments]    ${eth_if}
    ${eth_status}=    Check ETH Status    ${eth if}
    Should Be True    ${eth_status} 
    
APCLI Set SCG Config Interval
    [Arguments]    ${scg_interval} 
    Set WSG Config Interval    interval=${scg_interval}


Check AP Rebooted And Able to Reach
    [Arguments]     ${ap_ip}    ${ap_username}  ${ap_passwd}
    Open Connection     ${ap_ip}
    ${res}=     SSHLibrary.Login   ${ap_username}  ${ap_passwd}
    Should Contain  ${res}      Please login:
    Close Connection


Delete Bond and Reboot AP
    [Arguments]     ${reboot_wait_time}=120 sec

    Configure Bond LACP Rate
    Configure Bond Xmit Hash
    Configure Bond MII Monitoring
    Delete Bond
    Reboot AP
    Sleep  ${reboot_wait_time}


Get Mac of AP Interface
    [Arguments]     ${ifname}

    ${res}=     Get Board Data Item  line_info=${ifname}:
    [Return]    ${res}

Download AP Firmware From Jenkins Server
    ${ap_model_name}=    Get Model Name
    ${fw_download_config}=    Create Dictionary    build_name=${TARGET_BUILD_NAME}    file_name=${IMG_FILE_NAME}    img_path=${UP_SERVER_ROOT}  download_url=${SOURCE_AP_BUILD}    ap_model=${ap_model_name}
    ${relative_file_path}=    Download AP Image and Get Relative File Path    ${fw_download_config}
    Set Suite Variable    ${relative_file_path}

Download AP Image and Get Relative File Path
    [Arguments]    ${download image config}
    ${img_file_full_path}=    download_scg_ap_image_file    ${download_image_config}
    ${relative_file_path}=    Replace String    ${img_file_full_path}    ${download_image_config['img_path']}    ${empty}
    [Return]    ${relative_file_path}

APCLI Upgrade AP Firmware Via TFTP
    Ping    ${TFTP_SERVER_IP}
    ${ap_upgrade_cfg}=    Create Dictionary    host=${TFTP_SERVER_IP}    control=${relative_file_path}    proto=tftp    auto=${false}
    Change FW Setting    ${ap_upgrade_cfg}
    Update AP Fw    ${UP_TIMEOUT}
    Check AP Firmware Version    ${TARGET_BUILD_NAME}

Verify AP Process State
    [Arguments]    ${process_name}   ${state}
    ${res}=    Get AP Process Status    ${process_name}
    Should Be Equal    ${res}    ${state}


Verify USB Power Status
    [Documentation]    Get and verify the status of USB Power in AP
    ...    param string expected_status  - Expected power status (Enabled | Disabled)
    [Arguments]    ${expected_status}

    ${current_status}=    Get USB Power
    Should Match Regexp    ${current_status}  (?i)${expected_status}


Verify RFLOW
    [Documentation]    Get RFLOW value and verify whether expected values are set
    ...   param string uplink_marking_priority		- Uplink Marking Priority (IEEE802_1p | DSCP | BOTH)
    ...   param string uplink_marking_type		- Uplink Marking Type (VOICE | VIDEO | BEST_EFFORT | BACKGROUND)
    ...   param string downlink_classification_type 	- Downlink Classification Type (VOICE | VIDEO | BEST_EFFORT | BACKGROUND)
    [Arguments]    ${application_name}
    ...    ${uplink_ratelimit}=None  ${downlink_ratelimit}=None
    ...    ${uplink_marking_priority}=None  ${uplink_marking_type}=None  ${downlink_classification_type}=None
    ...    ${error_msg}=RFLOW values doesn't match expected data!

    ${uplink_ratelimit}=    Run Keyword IF  "${uplink_ratelimit}" == "None" and "${downlink_ratelimit}" == "None"
    ...    Set Variable  -1
    ...    ELSE IF  "${uplink_ratelimit}" == "None" and "${downlink_ratelimit}" != "None"
    ...    Set Variable  0
    ...    ELSE
    ...    Set Variable  ${uplink_ratelimit}

    ${downlink_ratelimit}=    Run Keyword IF  "${downlink_ratelimit}" == "None" and "${uplink_ratelimit}" == "-1"
    ...    Set Variable  -1
    ...    ELSE IF  "${downlink_ratelimit}" == "None" and "${uplink_ratelimit}" != "-1"
    ...    Set Variable  0
    ...    ELSE
    ...    Set Variable  ${downlink_ratelimit}

    ${uplink_marking_priority}=    Run Keyword IF  "${uplink_marking_priority}" == "IEEE802_1p"  Set Variable  0
    ...    ELSE IF    "${uplink_marking_priority}" == "DSCP"  Set Variable  1
    ...    ELSE IF    "${uplink_marking_priority}" == "BOTH"  Set Variable  2
    ...    ELSE    Set Variable  -1

    ${uplink_marking_type}=    Run Keyword IF  "${uplink_marking_type}" == "BACKGROUND"  Set Variable  0
    ...    ELSE IF    "${uplink_marking_type}" == "BEST_EFFORT"  Set Variable  1
    ...    ELSE IF    "${uplink_marking_type}" == "VIDEO"  Set Variable  2
    ...    ELSE IF    "${uplink_marking_type}" == "VOICE"  Set Variable  3
    ...    ELSE    Set Variable  -1

    ${downlink_classification_type}=    Run Keyword IF  "${downlink_classification_type}" == "BACKGROUND"  Set Variable  0
    ...    ELSE IF    "${downlink_classification_type}" == "BEST_EFFORT"  Set Variable  1
    ...    ELSE IF    "${downlink_classification_type}" == "VIDEO"  Set Variable  2
    ...    ELSE IF    "${downlink_classification_type}" == "VOICE"  Set Variable  3
    ...    ELSE    Set Variable  -1

    ${classification_enabled}=    Run Keyword IF  "${downlink_classification_type}" == "-1"
    ...    Set Variable  -1
    ...    ELSE    Set Variable  1

    ${current_rflow}=    Get Rflow

    Should Match Regexp    ${current_rflow}  \\|\\s*${uplink_marking_priority}\\s*${uplink_marking_type}\\s*${classification_enabled}\\s*${downlink_classification_type}\\s*\\|\\s*${uplink_ratelimit}\\s*${downlink_ratelimit}\\s*\\|\\s*${application_name}\\s*\\|
    ...    msg=${error_msg}
