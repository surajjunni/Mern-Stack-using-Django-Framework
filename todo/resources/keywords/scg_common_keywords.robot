*** Keyword ***
Create and Save Suite SSH and HTTPS Context OK
    Create and Save Suite SSH Context OK
    Create and Save Suite HTTPS Context OK

Create and Save Suite SSH Context OK
    SCG SSH Login OK
    Save Global Context    sshContext
    Disable CLI Pagination

Create and Save Suite SSH Context without rbd OK
    SCG SSH Login without rbd OK
    Save Global Context    sshContext

Create and Save Suite HTTPS Context OK
    User Login OK
    Save Global Context    httpsContext

Create and Save Suite MAC SSH Context OK
    [Arguments]    ${contextName}
    MAC Login OK
    MAC DO First SUDO
    Save Global Context    ${contextName}

Create and Save Suite AP SSH Context OK
    [Arguments]    ${ip}    ${user}    ${password}
    SSH Login OK    ${ip}    22    ${user}    ${password}
    Send    \n
    #Wait Until Keyword Succeeds    1 min    1 sec    Wait AP Console Login Prompt OK
    Wait Until Keyword Succeeds    1 min    1 sec    Expect    Please login:
    Send    ${user}\n
    Expect    password :
    Send    ${password}\n
    Expect    rkscli:
    Save Global Context    apSshContext

Create and Save Suite Client PC SSH Context OK
    [Arguments]    ${contextName}
    Client PC Login OK
    Save Global Context    ${contextName}

Clean Suite MAC SSH Context OK
    [Arguments]    ${contextName}
    Use Global Context    ${contextName}
    MAC Logout

Clean Suite SSH and HTTPS Context OK
    Clean Suite SSH Context OK
    Clean Suite HTTPS Context OK

Clean Suite SSH Context OK
    Use Global Context    sshContext
    SCG SSH Logout OK

Clean Suite AP SSH Context OK
    Use Global Context    apSshContext
    SCG SSH Logout OK

Clean Suite HTTPS Context OK
    Use Global Context    httpsContext
    User Logout OK

User Defined Interface Should Exist
    [Arguments]    ${hostname}
    Use Global Context    httpsContext
    Get User Defined Interface List    ${hostname}
    Status should be    SUCCESS

User Defined Interface Should Not Exist
    [Arguments]    ${hostname}
    Use Global Context    httpsContext
    Get User Defined Interface List    ${hostname}
    Status should be    FAILED

Zone Should Exist
    [Arguments]    ${zoneName}
    Use Global Context    httpsContext
    ${AP Zone UUID}=    Get AP Zone UUID    ${zoneName}
    Should Not Be Empty    ${AP Zone UUID}

Zone Should Not Exist
    [Arguments]    ${zoneName}
    Use Global Context    httpsContext
    ${AP Zone UUID}=    Get AP Zone UUID    ${zoneName}
    Should Be Equal    ${AP Zone UUID}    ${None}

WLAN Group Should Exist
    [Arguments]    ${zoneName}    ${wlanGroupName}
    Use Global Context    httpsContext
    ${wlanGroupConfig}=    Get WLAN Group Config    ${zoneName}    ${wlanGroupName}
    Should Not Be Empty    ${wlanGroupConfig}

WLAN Group Should Not Exist
    [Arguments]    ${zoneName}    ${wlanGroupName}
    Use Global Context    httpsContext
    ${wlanGroupConfig}=    Get WLAN Group Config    ${zoneName}    ${wlanGroupName}
    Should Be Equal    ${wlanGroupConfig}    ${None}

WLAN Should Exist
    [Arguments]    ${zoneName}    ${wlanName}
    Use Global Context    httpsContext
    ${wlanConfig}=    Get WLAN Config    ${zoneName}    ${wlanName}
    Should Not Be Empty    ${wlanConfig}

WLAN Should Not Exist
    [Arguments]    ${zoneName}    ${wlanName}
    Use Global Context    httpsContext
    ${wlanConfig}=    Get WLAN Config    ${zoneName}    ${wlanName}
    Should Be Equal    ${wlanConfig}    ${None}

Hotspot Should Exist
    [Arguments]    ${zoneName}    ${hotspotName}
    Use Global Context    httpsContext
    ${hotspotConfig}=    Get Hotspot Config    ${zoneName}    ${hotspotName}
    Should Not Be Empty    ${hotspotConfig}

Hotspot Should Not Exist
    [Arguments]    ${zoneName}    ${hotspotName}
    Use Global Context    httpsContext
    ${hotspotConfig}=    Get Hotspot Config    ${zoneName}    ${hotspotName}
    Should Be Equal    ${hotspotConfig}    ${None}

AP Group Should Exist
    [Arguments]    ${zoneName}    ${apGroupName}
    Use Global Context    httpsContext
    ${apGroupConfig}=    Get AP Group Config    ${zoneName}    ${apGroupName}
    Should Not Be Empty    ${apGroupConfig}

AP Group Should Not Exist
    [Arguments]    ${zoneName}    ${apGroupName}
    Use Global Context    httpsContext
    ${apGroupConfig}=    Get AP Group Config    ${zoneName}    ${apGroupName}
    Should Be Equal    ${apGroupConfig}    ${None}

AAA Server Should Exist
    [Arguments]    ${zoneName}    ${aaaServerName}
    Use Global Context    httpsContext
    ${aaaServerConfig}=    Get AAA Server Config    ${zoneName}    ${aaaServerName}
    Should Not Be Empty    ${aaaServerConfig}

AAA Server Should Not Exist
    [Arguments]    ${zoneName}    ${aaaServerName}
    Use Global Context    httpsContext
    ${aaaServerConfig}=    Get AAA Server Config    ${zoneName}    ${aaaServerName}
    Should Be Equal    ${aaaServerConfig}    ${None}

Erase and Reboot SCG VM
    [Arguments]    ${ip}=${SCG_MANAGEMENT_IP}    ${port}=${SSH PORT}    ${username}=${SCG ADMIN USERNAME}    ${password}=${SCG ADMIN PASSWORD}    ${prompt}=${SCG CONTROLLER NAME}    ${shell_password}=${SCG V54 PASSWORD}
    ${login_ok}=    Run Keyword And Return Status    SCG SSH Log into Shell OK    ${ip}    ${port}    ${username}    ${password}
    ...    ${prompt}    ${shell_password}
    ${SETUP_IP}=    Get Variable Value    ${SETUP_IP}    ${ip}
    Run Keyword If    not ${login_ok}    SCG SSH Log into Shell OK    ${SETUP_IP}    ${port}    ${SCG DEFAULT ADMIN USERNAME}    ${SCG DEFAULT ADMIN PASSWORD}
    ...    ${SCG DEFAULT CLI PROMPT}    ${shell_password}    ${SCG DEFAULT ADMIN PASSWORD}
    Send    dd if=/dev/zero of=/dev/sda bs=512 count=1; sync; sync; sync; sync; sync; sleep 5; reboot -f\n    #Erase and reboot SCG VM
    Sleep    20

Create AP Zone With Latest AP Firmware
    [Arguments]    ${zonename}    ${apLogin}    ${apPassword}
    User Login OK
    Save Global Context    httpsContext
    ${fwVersion}=    Get Latest AP Firmware Version    ${None}
    Create AP Zone    ${zonename}    ${fwVersion}    ${apLogin}    ${apPassword}
    Status should be    SUCCESS

Delete an existing AP Zone
    [Arguments]    ${zonename}
    User Login OK
    Delete AP Zone    ${zonename}
    Status should be    SUCCESS

Reset AP
    #Execute when any AP test cases fail, then will move AP to staging zone and do factory reset
    Create and Save Suite SSH Context OK
    : FOR    ${i}    IN RANGE    len(@{AP CONSOLE DEVICES})
    \    MAC Login OK
    \    MAC DO First SUDO
    \    ${passed}=    Run Keyword And Return Status    Login AP CLI via Console OK    @{AP CONSOLE DEVICES}[${i}]    ${SCG ADMIN USERNAME}    ${SCG ADMIN PASSWORD}
    \    Run Keyword Unless    ${passed}    AP Login with Cluster Name
    \    Run Keyword Unless    ${passed}    AP Login with Default Name
    \    Run Keyword If    ${passed}    AP Factory Reset via Console
    \    Move AP to Zone via CLI Command    @{AP MAC}[${i}]    "Staging Zone"
    \    Delete AP via CLI Command    @{AP MAC}[${i}]

Ready upgrade SCG
    [Arguments]    ${patch_id}
    ${status}=    Check SCG Image Upload Progress    ${patch_id}
    Run Keyword Unless    '${status}' == 'Completed'    Fail    Not Ready

SCG Upgrade Complete
    ${status}=    Check SCG Upgrade Progress
    Run Keyword If    '${status}' == 'Relogin'    Create and Save Suite HTTPS Context OK    ELSE    Run Keyword Unless    ${status}    Fail
    ...    Not Ready
    Run Keyword If    '${status}' == 'Relogin'    Fail    Not Ready    #Test again, after re-login

Backup Configuration Complete
    Use Global Context    httpsContext
    ${status}=    Check Backup Configuration Progress
    Run Keyword Unless    '${status}' == 'Successful'    Fail    Not Ready

Restore Complete
    Login with HTTPS    ${SCG MANAGEMENT IP}    ${SCG PORT}    ${SCG ADMIN USERNAME}    ${SCG ADMIN PASSWORD}
    ${state}=    Is Whole SCG Control Planes In Service
    Should Be True    ${state}

Change Interface Configuration Complete
    [Arguments]    ${ip}    ${port}    ${username}    ${password}
    Login with HTTPS    ${ip}    ${port}    ${username}    ${password}
    ${state}=    Is Whole SCG Control Planes In Service
    Should Be True    ${state}

Check UE in LMA Server
    [Arguments]    ${ip}    ${user}    ${password}    ${prompt}    @{checkValues}
    SSH Login OK    ${ip}    22    ${user}    ${password}
    Expect Regex    ${prompt}:.*\$
    Send    cd ${LMA SERVER PATH}/bin\n
    Expect Regex    ${prompt}:.*\$
    Send    . pmipProfile\n
    Expect Regex    |${user}@PMIPSIM:.*\$|
    Send    ./DBGConsoleD -socket\n
    Expect    >>
    Send    pmip_get_mn_regs\n
    Sleep    3
    : FOR    ${value}    IN    @{checkValues}
    \    Expect    ${value}    False
    Expect    >>
    Send    quit\n
    Expect Regex    |${user}@PMIPSIM:.*\$|
    Send    exit\n

Start LMA Servers
    : FOR    ${i}    IN RANGE    len(@{LMA SERVER})
    \    SSH Login OK    @{LMA SERVER}[${i}]    22    @{LMA SERVER USERNAME}[${i}]    @{LMA SERVER PASSWORD}[${i}]
    \    Expect Regex    @{LMA SERVER PROMPT}[${i}]:.*\$
    \    Send    cd ${LMA SERVER PATH}/bin\n
    \    Expect Regex    @{LMA SERVER PROMPT}[${i}]:.*\$
    \    Send    . pmipProfile\n
    \    Expect Regex    |@{LMA SERVER USERNAME}[${i}]@PMIPSIM:.*\$|
    \    Send    ./Run\n
    \    Expect    pmip: running as a console application
    \    Save Global Context    lma_server_${i}

Take SCG Diagnostic Snapshot
    [Arguments]    ${ip}=${SCG_MANAGEMENT_IP}    ${username}=${SCG_ADMIN_USERNAME}    ${password}=${SCG_ADMIN_PASSWORD}    ${prompt}=${SCG CLI PROMPT}
    SCG SSH Login OK    ${ip}    22    ${username}    ${password}    ${prompt}
    CLI Command Executed OK    diagnostic    ${prompt}(diagnostic)#
    Send    execute all\n
    Wait Until Keyword Succeeds    10 min    20 sec    expect    Log file archive in snapshot
    Sleep    5
    CLI Command Executed OK    copy snapshot ftp://${FTP USER}:${FTP PASSWORD}@${FTP SERVER}${SNAPSHOT FTP PATH}    Please choose a snapshot log file or 'No' to cancel:
    CLI Command Executed OK    1    ${prompt}(diagnostic)#
    CLI Command Executed OK    delete snapshot    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${prompt}(diagnostic)#

Is DP Ready
    [Arguments]    ${dp name}
    fetch_data_blade_info    ${dp name}
    ${status}=    get_data_blade_info_value    status
    Run Keyword If    '${status}' is not 'Running'    Fail    ${dp name} is managed by SCG but status is ${status}

Send BRI from LMA Server
    [Arguments]    ${ip}    ${user}    ${password}    ${prompt}    ${MNID}    ${MNIDTYPE}=NAI
    ...    ${TRIGTYPE}=1    ${TrigVal}=4    ${ackReq}=0
    SSH Login OK    ${ip}    22    ${user}    ${password}
    Expect Regex    ${prompt}:.*\$
    Send    cd ${LMA SERVER PATH}/bin\n
    Expect Regex    ${prompt}:.*\$
    Send    . pmipProfile\n
    Expect Regex    |${user}@PMIPSIM:.*\$|
    Send    ./DBGConsoleD -socket\n
    Expect    >>
    Send    pmip_send_bri ${MNID} ${MNIDTYPE} ${TRIGTYPE} ${TrigVal} ${ackReq}\n
    Sleep    3
    Expect    >>
    Send    quit\n
    Expect Regex    |${user}@PMIPSIM:.*\$|
    Send    exit\n

SZ Setup
    [Arguments]    ${portGrouping}=1    ${IPType}=2    ${dpIPType}=2
    ${hasDataplane}=    Set Variable If    ${portGrouping}==1    False    True
    ${loginOk}=    Run Keyword And Return Status    SCG SSH Login with Default OK
    Run Keyword If    not ${loginOk}    SCG Factory Reset
    CLI Command Executed OK    setup    Select Port Grouping Configuration (1/2) [1]
    Run Keyword And Ignore Error    CLI Command Executed OK    ${portGrouping}    Enter "confirmed" or press Enter to continue
    Run Keyword And Ignore Error    CLI Command Executed OK    confirmed    Select IP configuration: (1/2)
    Set Interface IP    ${IPType}    ${SCG MANAGEMENT IP}    ${SCG MANAGEMENT NETMASK}    ${SCG MANAGEMENT GATEWAY}
    CLI Command Executed OK    ${SCG PRIMARY DNS}    Secondary DNS:
    Send    ${SCG SECONDARY DNS}\n
    Run Keyword If    ${hasDataplane}==True    Setup DP    ${dpIPType}
    expect without pattern    (C)reate a new cluster or (J)oin an exist cluster: (c/j)    %
    CLI Command Executed OK    c    Cluster Name ([a-zA-Z0-9_-]):
    CLI Command Executed OK    ${SCG CLUSTER NAME}    Controller Description:    30
    CLI Command Executed OK    ${SCG CONTROLLER NAME}    Are these correct? (y/n):
    CLI Command Executed OK    y    Enter the controller name of the blade([a-zA-Z0-9_-]):
    CLI Command Executed OK    ${SCG CONTROLLER NAME}    NTP Server ([a-zA-Z0-9._-]): [pool.ntp.org]
    Run Keyword And Ignore Error    CLI Command Executed OK    pool.ntp.org    Convert ZoneDirector APs in factory settings to
    Run Keyword And Ignore Error    CLI Command Executed OK    n    Enter admin password:
    CLI Command Executed OK    ${SCG ADMIN PASSWORD}    Enter admin password again:
    CLI Command Executed OK    ${SCG ADMIN PASSWORD}    .*enable.* password:
    CLI Command Executed OK    ${SCG ADMIN PASSWORD}    .*enable.* password again:
    CLI Command Executed OK    ${SCG ADMIN PASSWORD}    Reset admin's password done!    600
    Wait Until Keyword Succeeds    40 min    30 sec    Check Cluster In-Service
    Create and Save Suite SSH Context OK
    Send    show license\n
    Expect    ${SCG CONTROLLER NAME}#

Setup DP
    [Arguments]    ${IPType}=1
    Set Interface IP    ${IPType}    ${SCG DP IP}    ${SCG DP NETMASK}    ${SCG DP GATEWAY}

SCG Factory Reset
    SCG SSH Login OK
    CLI Command Executed OK    set-factory    Do you want to do factory reset (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    Succeed to do the system factory reset, and it will be taken effect after reload system
    CLI Command Executed OK    reload now    Do you want to gracefully reboot system immediately (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    Server would be rebooted in 0 seconds
    Wait Until Keyword Succeeds    30 min    1 min    SCG SSH Login with Default OK
