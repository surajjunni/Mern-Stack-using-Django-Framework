*** Keyword ***
CLI Command Executed OK
    [Arguments]    ${command}    ${expect result}    ${timeout}=0
    Send    ${command}\n
    Sleep    ${timeout}
    expect without pattern    ${expect result}    %

CLI Config Mode
    #Sleep    #5    #Work around. Wait CLI config mode ready
    CLI Command Executed OK    config    ${SCG CONTROLLER NAME}(config)#

Default CLI Config Mode
    #Sleep    #5    #Work around. Wait CLI config mode ready
    CLI Command Executed OK    config    ${SCG_DEFAULT_CLI_PROMPT}(config)#

CLI Zone Config Mode OK
    [Arguments]    ${zoneName}
    CLI Config Mode
    CLI Command Executed OK    zone ${zoneName}    ${SCG CONTROLLER NAME}(config-zone)#

CLI WLAN Group Config Mode OK
    [Arguments]    ${zoneName}    ${wlanGroupName}
    CLI Zone Config Mode OK    ${zoneName}
    CLI Command Executed OK    wlan-group ${wlanGroupName}    ${SCG CONTROLLER NAME}(config-zone-wlan-group)#

CLI WLAN Config Mode OK
    [Arguments]    ${zoneName}    ${wlanName}
    CLI Zone Config Mode OK    ${zoneName}
    CLI Command Executed OK    wlan "${wlanName}"    ${SCG CONTROLLER NAME}(config-zone-wlan)#    20

CLI AP Group Config Mode OK
    [Arguments]    ${zoneName}    ${apGroupName}
    CLI Zone Config Mode OK    ${zoneName}
    CLI Command Executed OK    ap-group ${apGroupName}    ${SCG CONTROLLER NAME}(config-zone-ap-group)#

CLI AAA Server Config Mode OK
    [Arguments]    ${zoneName}    ${aaaServerName}
    CLI Zone Config Mode OK    ${zoneName}
    CLI Command Executed OK    aaa ${aaaServerName}    ${SCG CONTROLLER NAME}(config-zone-aaa)#

CLI Exit & Save Certain Config Mode OK
    [Arguments]    ${expect result}
    CLI Command Executed OK    exit    Do you want to save this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${expect result}

CLI Exit & Update Certain Config Mode OK
    [Arguments]    ${expect result}
    CLI Command Executed OK    exit    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${expect result}    5

CLI Exit Without Update To Config Mode OK
    [Arguments]    ${expect result}
    ${ret}=    Run Keyword And Return Status    CLI Command Executed OK    exit    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    Log    ${ret}
    Run Keyword If    ${ret}    CLI Command Executed OK    yes    ${expect result}    5    ELSE
    ...    CLI Command Executed OK    no    ${expect result}    5

Create Zone via CLI Command
    [Arguments]    ${zoneName}    ${firmware}    ${countryCode}=US    ${tunnelType}=ruckus-gre    ${tunnelProfile}="Default Tunnel Profile"
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zoneName}
    CLI Command Executed OK    ap-firmware ${firmware}    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Command Executed OK    ap-logon ${SCG ADMIN USERNAME}    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Command Executed OK    ap-password    New Password:
    CLI Command Executed OK    ${SCG ADMIN PASSWORD}    Retype:
    CLI Command Executed OK    ${SCG ADMIN PASSWORD}    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Command Executed OK    country-code ${countryCode}    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Command Executed OK    tunnel-type ${tunnelType}    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Command Executed OK    tunnel-profile ${tunnelProfile}    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Exit & Save Certain Config Mode OK    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Edit Zone via CLI Command
    [Arguments]    ${zoneName}    @{cmds}
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zoneName}
    : FOR    ${cmd}    IN    @{cmds}
    \    CLI Command Executed OK    ${cmd}    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Exit & Update Certain Config Mode OK    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Edit Zone Attribute via CLI Command
    [Arguments]    ${zoneName}    ${attribute}    ${value}
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zoneName}
    CLI Command Executed OK    ${attribute} ${value}    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Exit & Update Certain Config Mode OK    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Edit Zone Admctl via CLI Command
    [Arguments]    ${zoneName}    @{cmds}
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zoneName}
    : FOR    ${cmd}    IN    @{cmds}
    \    CLI Command Executed OK    ${cmd}    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Exit Without Update To Config Mode OK    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Delete Zone via CLI Command
    [Arguments]    ${zoneName}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    no zone ${zoneName}    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Delet Bridge Profile via CLI Command
    [Arguments]    ${FORWARDING_PROFILE_NAME}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    no bridge-profile ${FORWARDING_PROFILE_NAME}    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Setting RBD info via CLI Command
    Use Global Context    sshContext
    CLI Command Executed Ok    rbd ${BOARD_NAME} ${MODEL_NAME} ${SERIAL_NUMBER} ${MAC_ADDR} ${MAC_COUNT} ${CUSTOMER} \n    ${SCG_DEFAULT_CLI_PROMPT}#
    CLI Command Executed OK    reload    Do you want to gracefully reboot system after 30 seconds (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    Server would be rebooted in 30 seconds

Create Hotspot via CLI Command
    [Arguments]    ${zoneName}    ${hotspotName}    @{cmds}
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zoneName}
    CLI Command Executed OK    hotspot "${hotspotName}"    ${SCG CONTROLLER NAME}(config-zone-hotspot)#
    CLI Command Executed OK    logon-url internal    ${SCG CONTROLLER NAME}(config-zone-hotspot)#
    : FOR    ${cmd}    IN    @{cmds}
    \    CLI Command Executed OK    ${cmd}    ${SCG CONTROLLER NAME}(config-zone-hotspot)#
    CLI Exit & Save Certain Config Mode OK    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Exit & Update Certain Config Mode OK    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Edit Hotspot via CLI Command
    [Arguments]    ${zoneName}    ${hotspotName}    @{cmds}
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zoneName}
    CLI Command Executed OK    hotspot ${hotspotName}    ${SCG CONTROLLER NAME}(config-zone-hotspot)#
    : FOR    ${cmd}    IN    @{cmds}
    \    CLI Command Executed OK    ${cmd}    ${SCG CONTROLLER NAME}(config-zone-hotspot)#
    CLI Exit & Update Certain Config Mode OK    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Exit & Update Certain Config Mode OK    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Delete Hotspot via CLI Command
    [Arguments]    ${zoneName}    ${hotspotName}
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zoneName}
    CLI Command Executed OK    no hotspot ${hotspotName}    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Exit & Update Certain Config Mode OK    ${SCG CONTROLLER NAME}(config)#

Create WLAN via CLI Command
    [Arguments]    ${zoneName}    ${wlanName}    ${ssid}=${WLAN SSID}    @{otherCommands}
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zoneName}
    CLI Command Executed OK    wlan "${wlanName}"    ${SCG CONTROLLER NAME}(config-zone-wlan)#    20
    CLI Command Executed OK    ssid "${ssid}"    ${SCG CONTROLLER NAME}(config-zone-wlan)#
    : FOR    ${cmd}    IN    @{otherCommands}
    \    CLI Command Executed OK    ${cmd}    ${SCG CONTROLLER NAME}(config-zone-wlan)#
    CLI Exit & Save Certain Config Mode OK    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Exit & Update Certain Config Mode OK    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Edit WLAN with RADIUS Server via CLI Command
    [Arguments]    ${zoneName}    ${wlanName}    ${radiusName}
    Use Global Context    sshContext
    CLI WLAN Config Mode OK    ${zoneName}    ${wlanName}
    CLI Command Executed OK    auth-method 8021x    ${SCG CONTROLLER NAME}(config-zone-wlan)#
    CLI Command Executed OK    auth-service ${radiusName}    ${SCG CONTROLLER NAME}(config-zone-wlan)#
    CLI Exit & Update Certain Config Mode OK    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Exit & Update Certain Config Mode OK    ${SCG CONTROLLER NAME}(config)#

Edit WLAN with RADIUS Accounting Server via CLI Command
    [Arguments]    ${zoneName}    ${wlanName}    ${radiusAccountingName}    ${radiusName}
    Use Global Context    sshContext
    CLI WLAN Config Mode OK    ${zoneName}    ${wlanName}
    CLI Command Executed OK    auth-method 8021x    ${SCG CONTROLLER NAME}(config-zone-wlan)#
    CLI Command Executed OK    acct-service ${radiusAccountingName}    ${SCG CONTROLLER NAME}(config-zone-wlan)#
    CLI Command Executed OK    acct-interval 5    ${SCG CONTROLLER NAME}(config-zone-wlan)#
    CLI Command Executed OK    auth-service ${radiusName}    ${SCG CONTROLLER NAME}(config-zone-wlan)#
    CLI Exit & Update Certain Config Mode OK    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Exit & Update Certain Config Mode OK    ${SCG CONTROLLER NAME}(config)#

Edit WLAN Attribute via CLI Command
    [Arguments]    ${zoneName}    ${wlanName}
    Use Global Context    sshContext
    CLI WLAN Config Mode OK    ${zoneName}    ${wlanName}
    CLI Command Executed OK    ${attribute} ${value}    ${SCG CONTROLLER NAME}(config-zone-wlan)#
    CLI Exit & Update Certain Config Mode OK    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Exit & Update Certain Config Mode OK    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    no zone ${zoneName} wlan "${wlanName}"    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Create WLAN Group via CLI Command
    [Arguments]    ${zoneName}    ${wlanGroupName}
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zoneName}
    CLI Command Executed OK    wlan-group ${wlanGroupName}    ${SCG CONTROLLER NAME}(config-zone-wlan-group)#
    CLI Exit & Save Certain Config Mode OK    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Exit & Update Certain Config Mode OK    ${SCG CONTROLLER NAME}(config)#

Edit WLAN Group Attribute via CLI Command
    [Arguments]    ${zoneName}    ${wlanGroupName}    ${attribute}    ${value}
    Use Global Context    sshContext
    CLI WLAN Group Config Mode OK    ${zoneName}    ${wlanGroupName}
    CLI Command Executed OK    ${attribute} ${value}    ${SCG CONTROLLER NAME}(config-zone-wlan-group)#
    CLI Exit & Update Certain Config Mode OK    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Exit & Update Certain Config Mode OK    ${SCG CONTROLLER NAME}(config)#

Add WLAN into WLAN Group via CLI Command
    [Arguments]    ${zoneName}    ${wlanGroupName}    ${wlanName}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    zone ${zoneName}    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Command Executed OK    wlan-group ${wlanGroupName}    ${SCG CONTROLLER NAME}(config-zone-wlan-group)#
    CLI Command Executed OK    wlan "${wlanName}"    ${SCG CONTROLLER NAME}(config-zone-wlan-group)#
    CLI Command Executed OK    end    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}#

Remove WLAN from WLAN Group via CLI Command
    [Arguments]    ${zoneName}    ${wlanGroupName}    ${wlanName}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    zone ${zoneName}    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Command Executed OK    wlan-group ${wlanGroupName}    ${SCG CONTROLLER NAME}(config-zone-wlan-group)#
    CLI Command Executed OK    no wlan "${wlanName}"    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config-zone-wlan-group)#
    CLI Command Executed OK    end    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}#

Delete WLAN Group via CLI Command
    [Arguments]    ${zoneName}    ${wlanGroupName}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    no zone ${zoneName} wlan-group ${wlanGroupName}    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)#

Create AP Group via CLI Command
    [Arguments]    ${zoneName}    ${apGroupName}
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zoneName}
    CLI Command Executed OK    ap-group ${apGroupName}    ${SCG CONTROLLER NAME}(config-zone-ap-group)#
    CLI Exit & Save Certain Config Mode OK    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Exit & Update Certain Config Mode OK    ${SCG CONTROLLER NAME}(config)#

Edit AP Group Attribute via CLI Command
    [Arguments]    ${zoneName}    ${apGroupName}    ${attribute}    ${value}
    Use Global Context    sshContext
    CLI AP Group Config Mode OK    ${zoneName}    ${apGroupName}
    CLI Command Executed OK    ${attribute} ${value}    ${SCG CONTROLLER NAME}(config-zone-ap-group)#
    CLI Exit & Update Certain Config Mode OK    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Exit & Update Certain Config Mode OK    ${SCG CONTROLLER NAME}(config)#

Delete AP Group via CLI Command
    [Arguments]    ${zoneName}    ${apGroupName}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    no zone ${zoneName} ap-group ${apGroupName}    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)#

Create AAA Server via CLI Command
    [Arguments]    ${zoneName}    ${aaaServerName}    ${aaaServerType}    ${aaaIP1}=${RADIUS SERVER IP}    @{cmds}
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zoneName}
    CLI Command Executed OK    aaa ${aaaServerName}    ${SCG CONTROLLER NAME}(config-zone-aaa)#
    CLI Command Executed OK    type ${aaaServerType}    ${SCG CONTROLLER NAME}(config-zone-aaa)#
    CLI Command Executed OK    ip ${aaaIP1}    ${SCG CONTROLLER NAME}(config-zone-aaa)#
    CLI Command Executed OK    port 1812    ${SCG CONTROLLER NAME}(config-zone-aaa)#
    CLI Command Executed OK    shared-secret ${RADIUS SERVER SECRET}    Retype:
    CLI Command Executed OK    ${RADIUS SERVER SECRET}    ${SCG CONTROLLER NAME}(config-zone-aaa)#
    : FOR    ${cmd}    IN    @{cmds}
    \    CLI Command Executed OK    ${cmd}    ${SCG CONTROLLER NAME}(config-zone-aaa)#
    CLI Exit & Save Certain Config Mode OK    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Exit & Update Certain Config Mode OK    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Edit AAA Server Backup via CLI Command
    [Arguments]    ${zoneName}    ${aaaServerName}
    Use Global Context    sshContext
    CLI AAA Server Config Mode OK    ${zoneName}    ${aaaServerName}
    CLI Command Executed OK    backup    ${SCG CONTROLLER NAME}(config-zone-aaa)#
    CLI Command Executed OK    backup ip ${SECONDARY RADIUS SERVER IP}    ${SCG CONTROLLER NAME}(config-zone-aaa)#
    CLI Command Executed OK    backup port 1812    ${SCG CONTROLLER NAME}(config-zone-aaa)#
    CLI Command Executed OK    backup shared-secret ${SECONDARY RADIUS SERVER SECRET}    Retype:
    CLI Command Executed OK    ${SECONDARY RADIUS SERVER SECRET}    ${SCG CONTROLLER NAME}(config-zone-aaa)#
    CLI Exit & Update Certain Config Mode OK    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Exit & Update Certain Config Mode OK    ${SCG CONTROLLER NAME}(config)#

Delete AAA Server via CLI Command
    [Arguments]    ${zoneName}    ${aaaServerName}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    no zone ${zoneName} aaa ${aaaServerName}    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    Successful operation

Set SCG Network Interfaces via CLI Command
    SSH Login OK    ${SCG MANAGEMENT IP}    22    ${SCG DEFAULT ADMIN USERNAME}    ${SCG DEFAULT ADMIN PASSWORD}
    CLI Command Executed OK    setup    Select IP configuration: (1/2)
    Set Interface IP    1    ${SCG CONTROL IP}    ${SCG CONTROL NETMASK}    ${SCG CONTROL GATEWAY}    #Control Interface
    expect    Select IP configuration: (1/2)
    Set Interface IP    1    ${SCG CLUSTER IP}    ${SCG CLUSTER NETMASK}    ${SCG CLUSTER GATEWAY}    #Cluster Interface
    expect    Select IP configuration: (1/2)
    Set Interface IP    2    ${NONE}    ${NONE}    ${NONE}    #Management Interface
    expect    Select system default gateway (Control, Cluster, Management)?
    CLI Command Executed OK    Control    Primary DNS:
    CLI Command Executed OK    ${SCG PRIMARY DNS}    Secondary DNS:
    CLI Command Executed OK    ${SCG SECONDARY DNS}    restart network
    Send    restart network\n
    Sleep    180
    expect    SCG>
    SSH Login OK    ${SCG MANAGEMENT IP}    22    ${SCG DEFAULT ADMIN USERNAME}    ${SCG DEFAULT ADMIN PASSWORD}

Set SCG Network Interfaces For Real SCG via CLI Command
    SSH Login OK    ${SCG CONTROL IP}    22    ${SCG DEFAULT ADMIN USERNAME}    ${SCG DEFAULT ADMIN PASSWORD}
    CLI Command Executed OK    setup    Select IP configuration: (1/2)
    Set Interface IP    2    ${NONE}    ${NONE}    ${NONE}    #Control Interface
    expect    Select IP configuration: (1/2)
    Set Interface IP    1    ${SCG CLUSTER IP}    ${SCG CLUSTER NETMASK}    ${SCG CLUSTER GATEWAY}    #Cluster Interface
    expect    Select IP configuration: (1/2)
    Set Interface IP    1    ${SCG MANAGEMENT IP}    ${SCG MANAGEMENT NETMASK}    ${SCG MANAGEMENT GATEWAY}    #Management Interface
    expect    Select system default gateway (Control, Cluster, Management)?
    CLI Command Executed OK    Management    Primary DNS:
    CLI Command Executed OK    ${SCG PRIMARY DNS}    Secondary DNS:
    CLI Command Executed OK    ${SCG SECONDARY DNS}    restart network
    Send    restart network\n
    Sleep    180
    expect    SCG>
    SSH Login OK    ${SCG MANAGEMENT IP}    22    ${SCG DEFAULT ADMIN USERNAME}    ${SCG DEFAULT ADMIN PASSWORD}

Set Interface IP
    [Arguments]    ${IPType}    ${IP}    ${Netmask}    ${Gateway}
    Run Keyword If    ${IPType}==1    Set Static IP    ${IP}    ${Netmask}    ${Gateway}
    Run Keyword If    ${IPType}==2    Set DHCP IP

Set DHCP IP
    CLI Command Executed OK    2    Are these correct? (y/n):    30
    Send    y\n

Set Static IP
    [Arguments]    ${IP}    ${Netmask}    ${Gateway}
    CLI Command Executed OK    1    IP Address:
    CLI Command Executed OK    ${IP}    Netmask:
    CLI Command Executed OK    ${Netmask}    Gateway:
    CLI Command Executed OK    ${Gateway}    Are these correct? (y/n):
    Send    y\n

Backup Cluster via CLI Command
    Use Global Context    sshContext
    CLI Command Executed OK    backup    Please note that event, alarm and statistic data will be deleted from the backup file after 7 days. Do you want to backup whole system (or input 'no' to cancel)? [yes/no]
    Send    yes\n
    Sleep    30

Restore Cluster via CLI Command
    [Arguments]    ${restoreVersion}
    Use Global Context    sshContext
    Send    restore\n
    expect    Please choose a backup to restore or 'No' to cancel:    False
    ${backupFileId}=    Get backup file ID    ${restoreVersion}
    Use Global Context    sshContext
    CLI Command Executed OK    ${backupFileId}    This action will reboot the system. Do you want to restore whole cluster system (or input 'no' to cancel)? [yes/no]
    Send    yes\n
    Sleep    30

Delete Cluster Backup File via CLI Command
    [Arguments]    ${backupFileVersion}
    Use Global Context    sshContext
    Send    show backup\n
    expect    ${SCG CONTROLLER NAME}#    False
    ${backupFileId}=    Get backup file ID    ${backupFileVersion}
    Create and Save Suite SSH Context OK    #Login CLI again to ignore previous command
    CLI Command Executed OK    delete backup ${backupFileId}    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}#

Verify AP Config By CLI Command
    [Arguments]    ${ap-mac}
    Use Global Context    sshContext
    CLI Config Mode
    Send    show ap ${ap-mac}\n
    Sleep    3
    Expect    ${SCG CONTROLLER NAME}(config)#

Move AP to Zone via CLI Command
    [Arguments]    ${apMac}    ${zoneName}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    ap ${apMac} move zone ${zoneName}    Do you want to continue to move this AP
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Delete AP via CLI Command
    [Arguments]    ${apMac}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    no ap ${apMac}    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Backup Configuration via CLI Command
    Use Global Context    sshContext
    CLI Command Executed OK    backup config    Do you want to backup configurations (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    Successful operation

Check Configuration Backup File via CLI
    [Arguments]    ${version}
    Use Global Context    sshContext
    Send    show backup-config\n
    expect    ${SCG CONTROLLER NAME}#    False
    ${backupFileId}=    Get backup file ID    ${version}

Restore Configuration via CLI Command
    [Arguments]    ${restoreVersion}
    Use Global Context    sshContext
    Send    restore config\n
    expect    Please choose a backup to restore or 'No' to cancel:    False
    ${backupFileId}=    Get backup file ID    ${restoreVersion}
    Use Global Context    sshContext
    CLI Command Executed OK    ${backupFileId}    This action will restart all SCG service. Do you want to restore configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    Successful operation

Delete Configuration Backup File via CLI Command
    [Arguments]    ${backupFileVersion}
    Use Global Context    sshContext
    Send    show backup-config\n
    expect    ${SCG CONTROLLER NAME}#    False
    ${backupFileId}=    Get backup file ID    ${backupFileVersion}
    Create and Save Suite SSH Context OK    #Login CLI again to ignore previous command
    CLI Command Executed OK    delete backup-config ${backupFileId}    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    Successful operation

Create AP Registration Rule Via CLI Command
    [Arguments]    ${zoneName}    ${description}    ${type}    ${args}
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zoneName}
    CLI Command Executed OK    ap-registration-rule    ${SCG CONTROLLER NAME}(config-zone-ap-registration-rule)#
    CLI Command Executed OK    description ${description}    ${SCG CONTROLLER NAME}(config-zone-ap-registration-rule)#
    CLI Command Executed OK    type ${type}    ${SCG CONTROLLER NAME}(config-zone-ap-registration-rule)#
    CLI Command Executed OK    ${type} ${args}    ${SCG CONTROLLER NAME}(config-zone-ap-registration-rule)#
    CLI Command Executed OK    exit    Do you want to save this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config-zone)
    CLI Command Executed OK    exit    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Edit AP Registration Rule Via CLI Command
    [Arguments]    ${zoneName}    ${old args}    ${new args}
    Use Global Context    httpsContext
    @{args1}=    Split String    ${old args}    ,
    @{args2}=    Get Slice From List    ${args1}    2
    ${rank}=    Get AP Registration Rule Priority    ${zoneName}    @{args1}[1]    @{args2}
    Should Not Be Equal    ${rank}    ${None}
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zoneName}
    CLI Command Executed OK    ap-registration-rule ${rank}    ${SCG CONTROLLER NAME}(config-zone-ap-registration-rule)#
    @{args1}=    Split String    ${new args}    ,
    @{args2}=    Get Slice From List    ${args1}    2
    CLI Command Executed OK    description @{args1}[0]    ${SCG CONTROLLER NAME}(config-zone-ap-registration-rule)#
    CLI Command Executed OK    type @{args1}[1]    ${SCG CONTROLLER NAME}(config-zone-ap-registration-rule)#
    ${var}=    List Join to String    \ \    @{args2}
    CLI Command Executed OK    @{args1}[1] ${var}    ${SCG CONTROLLER NAME}(config-zone-ap-registration-rule)#
    CLI Command Executed OK    exit    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Command Executed OK    exit    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Delete All AP Registration Rule Via CLI Command
    [Arguments]    ${zoneName}
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zoneName}
    CLI Command Executed OK    no ap-registration-rule    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Command Executed OK    exit    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Delete AP Registration Rule Via CLI Command
    [Arguments]    ${zoneName}    ${old args}
    Use Global Context    httpsContext
    @{args1}=    Split String    ${old args}    ,
    @{args2}=    Get Slice From List    ${args1}    2
    ${rank}=    Get AP Registration Rule Priority    ${zoneName}    @{args1}[1]    @{args2}
    Should Not Be Equal    ${rank}    ${None}
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zoneName}
    CLI Command Executed OK    no ap-registration-rule ${rank}    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Command Executed OK    exit    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Disable CLI Pagination
    Use Global Context    sshContext
    CLI Command Executed OK    debug    ${SCG CONTROLLER NAME}(debug)
    CLI Command Executed OK    no screen-pagination    ${SCG CONTROLLER NAME}(debug)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Change CLI Display Format to Json
    Use Global Context    sshContext
    CLI Command Executed OK    debug    ${SCG CONTROLLER NAME}(debug)
    CLI Command Executed OK    display-format json    ${SCG CONTROLLER NAME}(debug)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Change Interface IP Address via CLI Command
    [Arguments]    ${interface}    ${args}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    interface ${interface}    ${SCG CONTROLLER NAME}(config-if)#
    CLI Command Executed OK    ip address ${args}    This command will reload all SCG services. Do you want to continue (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config-if)#    #Successful operation    #Should see success word. But there is a bug in 2.1.0.0.267.

Backup Network via CLI Command
    Use Global Context    sshContext
    CLI Command Executed OK    backup network    Do you want to backup network configurations (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    Successful operation    120

Check Network Backup File via CLI
    [Arguments]    ${version}
    Use Global Context    sshContext
    Send    show backup-network\n
    expect    ${SCG CONTROLLER NAME}#    False
    ${backupFileId}=    Get backup file ID    ${version}
    Should Not Be Equal    ${backupFileId}    ${None}

Restore Network via CLI Command
    [Arguments]    ${restoreVersion}
    SCG SSH Login OK    ${NEW_SCG_MANAGEMENT_IP}
    Save Global Context    sshContext
    CLI Command Executed OK    debug    ${SCG CONTROLLER NAME}(debug)#
    CLI Command Executed OK    all-log-level    ${SCG CONTROLLER NAME}(debug)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#
    CLI Command Executed OK    config    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    logging console cli debug    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#
    Send    show backup-network\n
    Send    show backup-network\n
    Send    show backup-network\n
    expect    ${SCG CONTROLLER NAME}#    False
    ${backupFileId}=    Get backup file ID    ${restoreVersion}
    Should Not Be Equal    ${backupFileId}    ${None}
    Use Global Context    sshContext
    CLI Command Executed OK    restore network    Please choose a backup to restore or 'No' to cancel:
    CLI Command Executed OK    ${backupFileId}    Please confirm this network setting, and this action will restart all services that will cause current SSH connection closed. Do you want to continue (or input 'no' to cancel)? [yes/no]
    Send    yes\n
    Run Keyword And Ignore Error    expect    Not all services are healthy. Do you want to continue (or input 'no' to cancel)? [yes/no]    #For SCG VM. The HIP process will be offline in VM.
    Run Keyword And Ignore Error    Send    yes\n
    Sleep    60

Delete Network Backup File via CLI Command
    [Arguments]    ${backupFileVersion}
    Use Global Context    sshContext
    Send    show backup-network\n
    expect    ${SCG CONTROLLER NAME}#    False
    ${backupFileId}=    Get backup file ID    ${backupFileVersion}
    Should Not Be Equal    ${backupFileId}    ${None}
    Use Global Context    sshContext
    CLI Command Executed OK    delete backup-network ${backupFileId}    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    Successful operation

Create 3rd Party AP Zone via CLI Command
    [Arguments]    ${3rdZoneName}    @{params}
    ${prompt}=    Set Variable    ${SCG CONTROLLER NAME}(config-3rd-zone)#
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    3rd-zone ${3rdZoneName}    ${prompt}
    : FOR    ${cmd}    IN    @{params}
    \    CLI Command Executed OK    ${cmd}    ${prompt}
    CLI Command Executed OK    exit    Do you want to save this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Edit 3rd Party AP Zone via CLI Command
    [Arguments]    ${3rdZoneName}    @{params}
    ${prompt}=    Set Variable    ${SCG CONTROLLER NAME}(config-3rd-zone)#
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    3rd-zone ${3rdZoneName}    ${prompt}
    : FOR    ${cmd}    IN    @{params}
    \    CLI Command Executed OK    ${cmd}    ${prompt}
    CLI Command Executed OK    exit    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Delete 3rd Party AP Zone via CLI Command
    [Arguments]    ${3rdZoneName}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    no 3rd-zone ${3rdZoneName}    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    Successful operation
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Create MVNO via CLI Command
    [Arguments]    ${domain}=${SCG TEST MVNO DOMAIN}    ${admin}=${SCG TEST MVNO ADMIN}    ${password}=${SCG TEST MVNO ADMIN PASSWORD}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    mvno ${domain}    ${SCG CONTROLLER NAME}(config-mvno)#
    CLI Command Executed OK    admin    ${SCG CONTROLLER NAME}(config-mvno-admin)#
    CLI Command Executed OK    name ${admin}    ${SCG CONTROLLER NAME}(config-mvno-admin)#
    CLI Command Executed OK    password ${password}    Retype:
    CLI Command Executed OK    ${password}    ${SCG CONTROLLER NAME}(config-mvno-admin)#
    CLI Command Executed OK    exit    Do you want to save this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config-mvno)#
    CLI Command Executed OK    exit    Do you want to save this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)#

Delete MVNO via CLI Command
    [Arguments]    ${domain}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    no mvno ${domain}    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    Successful operation

Edit MVNO Domain Name via CLI Command
    [Arguments]    ${domain}    ${new domain}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    mvno ${domain}    ${SCG CONTROLLER NAME}(config-mvno)#
    CLI Command Executed OK    name ${new domain}    ${SCG CONTROLLER NAME}(config-mvno)#
    CLI Command Executed OK    exit    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)#

Edit MVNO Admin Password via CLI Command
    [Arguments]    ${domain}    ${admin}    ${new password}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    mvno ${domain}    ${SCG CONTROLLER NAME}(config-mvno)#
    CLI Command Executed OK    admin    ${SCG CONTROLLER NAME}(config-mvno-admin)#
    CLI Command Executed OK    password ${new password}    Retype:
    CLI Command Executed OK    ${new password}    ${SCG CONTROLLER NAME}(config-mvno-admin)#
    CLI Command Executed OK    exit    Do you want to save this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config-mvno)#
    CLI Command Executed OK    exit    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)#

Add Zone to MVNO via CLI Command
    [Arguments]    ${domain}    ${zone}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    mvno ${domain}    ${SCG CONTROLLER NAME}(config-mvno)#
    CLI Command Executed OK    zone ${zone}    ${SCG CONTROLLER NAME}(config-mvno)#
    CLI Command Executed OK    exit    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)#

Add WLAN to MVNO via CLI Command
    [Arguments]    ${domain}    ${wlan}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    mvno ${domain}    ${SCG CONTROLLER NAME}(config-mvno)#
    CLI Command Executed OK    wlan ${wlan}    ${SCG CONTROLLER NAME}(config-mvno)#
    CLI Command Executed OK    exit    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)#

Remove WLAN From MVNO via CLI Command
    [Arguments]    ${domain}    ${zone}    ${wlan}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    mvno ${domain}    ${SCG CONTROLLER NAME}(config-mvno)#
    CLI Command Executed OK    no wlan "${wlan} of zone ${zone}"    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    Successful operation
    CLI Command Executed OK    exit    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)#

Remove Zone From MVNO via CLI Command
    [Arguments]    ${domain}    ${zone}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    mvno ${domain}    ${SCG CONTROLLER NAME}(config-mvno)#
    CLI Command Executed OK    no zone "${zone}"    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    Successful operation
    CLI Command Executed OK    exit    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)#

Create WPA WLAN Via CLI Command
    [Arguments]    ${zoneName}    ${wlanName}    ${ssid}    ${wpaMethod}    ${wpaAlgorithm}    ${wpaPassphrase}
    @{otherCommands}=    Create List    enc-method ${wpaMethod}    enc-algorithm ${wpaAlgorithm}    enc-passphrase ${wpaPassphrase}
    Create WLAN via CLI Command    ${zoneName}    ${wlanName}    ${ssid}    @{otherCommands}

Create WEP WLAN Via CLI Command
    [Arguments]    ${zoneName}    ${wlanName}    ${ssid}    ${wepMethod}    ${wepKeyIndex}    ${wepKey}
    @{otherCommands}=    Create List    enc-method ${wepMethod}    enc-wep-key ${wepKeyIndex} ${wepKey}
    Create WLAN via CLI Command    ${zoneName}    ${wlanName}    ${ssid}    @{otherCommands}

Setup Data Planes Network via CLI Commands
    CLI Command Executed OK    yes    Select IP configuration: (1/2)
    CLI Command Executed OK    2    Are these correct? (y/n):
    Send    y\n
    ${has_second_dp}=    Run Keyword And Return Status    expect    Select IP configuration: (1/2)
    Run Keyword If    ${has_second_dp}    CLI Command Executed OK    2    Are these correct? (y/n):
    Run Keyword If    ${has_second_dp}    Send    y\n

CLI Pmipv6 Config Mode
    [Arguments]    ${SCG_CLUSTER_NAME}
    CLI Command Executed OK    config    ${SCG_CLUSTER_NAME}(config)#

CLI Pmipv6 Config Mode OK
    [Arguments]    ${SCG_CLUSTER_NAME}    ${pmipv6_name}
    CLI Pmipv6 Config Mode    ${SCG_CLUSTER_NAME}
    CLI Command Executed OK    pmipv6-profile ${pmipv6_name}    ${SCG_CLUSTER_NAME}(config-pmipv6-profile)#

Create Pmipv6 via CLI Command
    [Arguments]    ${SCG_CLUSTER_NAME}    ${pmipv6_name}    ${description}    ${lma-ip}    ${mn-id}    ${mac48}
    ...    ${apn}
    Create and Save Suite SSH Context OK
    Use Global Context    sshContext
    CLI Pmipv6 Config Mode OK    ${SCG_CLUSTER_NAME}    ${pmipv6_name}
    CLI Command Executed OK    name ${pmipv6_name}    ${SCG_CLUSTER_NAME}(config-pmipv6-profile)#
    CLI Command Executed OK    description ${description}    ${SCG_CLUSTER_NAME}(config-pmipv6-profile)#
    CLI Command Executed OK    lma-ip ${lma-ip}    ${SCG_CLUSTER_NAME}(config-pmipv6-profile)#
    Run Keyword If    '${mn-id}' == 'nai'    CLI Command Executed OK    mn-id ${mn-id}    ${SCG_CLUSTER_NAME}(config-pmipv6-profile)#
    Run Keyword If    '${mn-id}' == 'mac48'    CLI Command Executed OK    mn-id ${mn-id}    ${SCG_CLUSTER_NAME}(config-pmipv6-profile)#
    Run Keyword If    '${mn-id}' == 'mac48'    CLI Command Executed OK    mac48 ${mac48}    ${SCG_CLUSTER_NAME}(config-pmipv6-profile)#
    Run Keyword If    '${mn-id}' == 'mac48'    CLI Command Executed OK    apn ${apn}    ${SCG_CLUSTER_NAME}(config-pmipv6-profile)#
    CLI Exit & Save Certain Config Mode OK    yes

Delete Pmipv6 via CLI Command
    [Arguments]    ${SCG_CLUSTER_NAME}    ${pmipv6_name}
    Use Global Context    sshContext
    Create and Save Suite SSH Context OK
    CLI Pmipv6 Config Mode    ${SCG_CLUSTER_NAME}
    CLI Command Executed OK    no pmipv6-profile ${pmipv6_name}    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG_CLUSTER_NAME}(config)#
    CLI Command Executed OK    exit    ${SCG_CLUSTER_NAME}
