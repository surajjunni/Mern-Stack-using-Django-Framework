*** Keyword ***
Create AAA Server via CLI
    [Arguments]    ${zone_name}    ${aaa_server_name}    ${aaa_server_type}    ${aaa_ip}    ${aaa_port}    ${aaa_shared_secret}
    ...    @{cmds}
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zone_name}
    CLI Command Executed OK    aaa ${aaa_server_name}    ${SCG CONTROLLER NAME}(config-zone-aaa)#
    CLI Command Executed OK    type ${aaa_server_type}    ${SCG CONTROLLER NAME}(config-zone-aaa)#
    CLI Command Executed OK    ip ${aaa_ip}    ${SCG CONTROLLER NAME}(config-zone-aaa)#
    CLI Command Executed OK    port ${aaa_port}    ${SCG CONTROLLER NAME}(config-zone-aaa)#
    CLI Command Executed OK    shared-secret    Password:
    CLI Command Executed OK    ${aaa_shared_secret}    Retype:
    CLI Command Executed OK    ${aaa_shared_secret}    ${SCG CONTROLLER NAME}(config-zone-aaa)#
    : FOR    ${cmd}    IN    @{cmds}
    \    CLI Command Executed OK    ${cmd}    ${SCG CONTROLLER NAME}(config-zone-aaa)#
    CLI Command Executed OK    end    Do you want to save this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}#

Delete AAA Server via CLI
    [Arguments]    ${zone_name}    ${aaa_server_name}
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zone_name}
    CLI Command Executed OK    no aaa ${aaa_server_name}    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Command Executed OK    end    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}#

Create Radius Service via CLI
    [Arguments]    ${radius_service_name}    ${radius_service_ip}    ${radius_service_secret}    @{cmds}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    radius-service ${radius_service_name}    ${SCG CONTROLLER NAME}(config-radius-service)#
    CLI Command Executed OK    ip ${radius_service_ip}    ${SCG CONTROLLER NAME}(config-radius-service)#
    CLI Command Executed OK    shared-secret    Password:
    CLI Command Executed OK    ${radius_service_secret}    Retype:
    CLI Command Executed OK    ${radius_service_secret}    ${SCG CONTROLLER NAME}(config-radius-service)#
    : FOR    ${cmd}    IN    @{cmds}
    \    CLI Command Executed OK    ${cmd}    ${SCG CONTROLLER NAME}(config-radius-service)#
    CLI Command Executed OK    end    Do you want to save this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}#

Delete Radius Service via CLI
    [Arguments]    ${radius_service_name}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    no radius-service ${radius_service_name}    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Create Auth Profile via CLI
    [Arguments]    ${auth_profile_name}    ${no_match_realm_name}    ${no_realm_name}    @{cmds}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    auth-profile ${auth_profile_name}    ${SCG CONTROLLER NAME}(config-auth-profile)#
    CLI Command Executed OK    default no-match-realm auth ${no_match_realm_name}    ${SCG CONTROLLER NAME}(config-auth-profile)#
    CLI Command Executed OK    default no-realm auth ${no_realm_name}    ${SCG CONTROLLER NAME}(config-auth-profile)#
    : FOR    ${cmd}    IN    @{cmds}
    \    CLI Command Executed OK    ${cmd}    ${SCG CONTROLLER NAME}(config-auth-profile)#
    CLI Command Executed OK    end    Do you want to save this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}#

Delete Auth Profile via CLI
    [Arguments]    ${auth_profile_name}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    no auth-profile ${auth_profile_name}    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    exit    ${SCG CONTROLLER NAME}#

Create WLAN scheduler via CLI
    [Arguments]    ${zone_name}    ${wlanSchedulerName}    @{cmds}
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zone_name}
    CLI Command Executed OK    wlan-scheduler ${wlanSchedulerName}    ${SCG CONTROLLER NAME}(config-zone-wlan-scheduler)#
    : FOR    ${cmd}    IN    @{cmds}
    \    CLI Command Executed OK    ${cmd}    ${SCG CONTROLLER NAME}(config-zone-wlan-scheduler)#
    CLI Command Executed OK    end    Do you want to save this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}#

Delete WLAN Scheduler via CLI
    [Arguments]    ${zone_name}    ${wlan_scheduler_name}
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zone_name}
    CLI Command Executed OK    no wlan-scheduler ${wlan_scheduler_name}    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Command Executed OK    end    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}#

Create VLAN pooling via CLI
    [Arguments]    ${zone_name}    ${vlan_pooling_name}    @{cmds}
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zone_name}
    CLI Command Executed OK    vlan-pooling ${vlan_pooling_name}    ${SCG CONTROLLER NAME}(config-zone-vlan-pooling)#
    : FOR    ${cmd}    IN    @{cmds}
    \    CLI Command Executed OK    ${cmd}    ${SCG CONTROLLER NAME}(config-zone-vlan-pooling)#
    CLI Command Executed OK    end    Do you want to save this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}#

Delete VLAN pooling via CLI
    [Arguments]    ${zone_name}    ${vlan_pooling_name}
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zone_name}
    CLI Command Executed OK    no vlan-pooling ${vlan_pooling_name}    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Command Executed OK    end    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}#

Disable Band Balancing via CLI
    [Arguments]    ${zone_name}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    zone ${zone_name}    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Command Executed OK    no band-balancing 2.4g    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Command Executed OK    end    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}#

Disable Client Load Balancing via CLI
    [Arguments]    ${zone_name}    ${radio_band}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    zone ${zone_name}    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Command Executed OK    no load-balancing ${radio_band}    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Command Executed OK    end    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}#

Setup Client Admission Control via CLI
    [Arguments]    ${zone_name}    ${radio_band}    @{cmds}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    zone ${zone_name}    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Command Executed OK    client-admission-control ${radio_band}    ${SCG CONTROLLER NAME}(config-zone)#
    : FOR    ${cmd}    IN    @{cmds}
    \    CLI Command Executed OK    client-admission-control ${radio_band} ${cmd}    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Command Executed OK    end    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}#

Disable Client Admission Control via CLI
    [Arguments]    ${zone_name}    ${radio_band}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    zone ${zone_name}    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Command Executed OK    no client-admission-control ${radio_band}    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config-zone)#
    CLI Command Executed OK    end    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}#

Enable AP Radio Service via CLI
    [Arguments]    ${ap_mac}    ${radio_band}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    ap ${ap_mac}    ${SCG CONTROLLER NAME}(config-ap)#
    CLI Command Executed OK    radio ${radio_band} wlan-service    ${SCG CONTROLLER NAME}(config-ap)#
    CLI Command Executed OK    end    Do you want to save this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}#

Disable AP Radio Service via CLI
    [Arguments]    ${ap_mac}    ${radio_band}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    ap ${ap_mac}    ${SCG CONTROLLER NAME}(config-ap)#
    CLI Command Executed OK    no radio ${radio_band} wlan-service    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config-ap)#
    CLI Command Executed OK    end    Do you want to save this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}#

Create Zone Temlate from Extracting via CLI
    [Arguments]    ${zone_tmpl_name}    ${zone_name}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    zone-template ${zone_tmpl_name} extract ${zone_name}    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    end    ${SCG CONTROLLER NAME}#

Delete Zone Temlate via CLI
    [Arguments]    ${zone_tmpl_name}
    Use Global Context    sshContext
    CLI Config Mode
    CLI Command Executed OK    no zone-template ${zone_tmpl_name}    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config)#
    CLI Command Executed OK    end    ${SCG CONTROLLER NAME}#


Configure Vlan Pooling in WLAN via CLI
    [Arguments]    ${zone_name}    ${wlan_name}    ${vlan_pooling_name}
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zone_name}
    CLI Command Executed OK    wlan ${wlan_name}    ${SCG CONTROLLER NAME}(config-zone-wlan)#
    CLI Command Executed OK    vlan-pooling ${vlan_pooling_name}    ${SCG CONTROLLER NAME}(config-zone-wlan)#
    CLI Command Executed OK    end    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}#


Disable Vlan Pooling in WLAN via CLI
    [Arguments]    ${zone_name}    ${wlan_name}
    Use Global Context    sshContext
    CLI Zone Config Mode OK    ${zone_name}
    CLI Command Executed OK    wlan ${wlan_name}    ${SCG CONTROLLER NAME}(config-zone-wlan)#
    CLI Command Executed OK    no vlan-pooling    Do you want to continue to delete (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}(config-zone-wlan)#
    CLI Command Executed OK    end    Do you want to update this context configuration (or input 'no' to cancel)? [yes/no]
    CLI Command Executed OK    yes    ${SCG CONTROLLER NAME}#
