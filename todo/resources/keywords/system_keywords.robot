*** Settings ***
# ------------- !!! No Settings Here !!! -----------
# Settings are centralized in keyword_adapters.robot
# --------------------------------------------------


*** Variables ***



*** Keywords ***
Get Cluster Node State List
    ${res}=  cluster_get_cluster_state
    [Return]  ${res}

Check Cluster State In Service
    ${res}=  system_keywords.Get Cluster Node State List
    Should Be Equal  ${res['clusterState']}  In_Service

Check Management Service State In Service
    [Arguments]  ${is_cluster}=${False}
    ${res}=  system_keywords.Get Cluster Node State List
    ${management_service_state_list}=  Get Variable Value  ${res['managementServiceStateList']}
    ${count}=  Get Length  ${management_service_state_list}

    Should Not Be Empty  ${management_service_state_list}
    Run Keyword If  ${is_cluster} and ${count} < 2  Fail  Cluster should has more than 1 node

    :For  ${i}  IN RANGE  0  ${count}
    \  ${node_id}=  Set Variable  '${management_service_state_list[${i}]['nodeId']}'
    \  ${management_service_state}=  Set Variable  '${management_service_state_list[${i}]['managementServiceState']}'
    \  Should Not Be Empty  ${node_id}
    \  Should Not Be Empty  ${management_service_state}
    \  Run Keyword if  ${management_service_state} != 'In_Service'  Fail  The Node [${node_id}] is NOT in Service

Check Node State In Service
    [Arguments]  ${is_cluster}=${False}
    ${res}=  system_keywords.Get Cluster Node State List
    ${node_state_list}=  Get Variable Value  ${res['nodeStateList']}
    ${count}=  Get Length  ${node_state_list}

    Should Not Be Empty  ${node_state_list}
    Run Keyword If  ${is_cluster} and ${count} < 2  Fail  Cluster should has more than 1 node

    :For  ${i}  IN RANGE  0  ${count}
    \  ${node_id}=  Set Variable  '${node_state_list[${i}]['nodeId']}'
    \  ${node_state}=  Set Variable  '${node_state_list[${i}]['nodeState']}'
    \  Should Not Be Empty  ${node_id}
    \  Should Not Be Empty  ${node_state}
    \  Run Keyword if  ${node_state} != 'In_Service'  Fail  The Node [${node_id}] is NOT in Service

Check Cluster Nodes in Service
    [Arguments]  ${is_cluster}=${False}
    system_keywords.Check Cluster State In Service
    system_keywords.Check Node State In Service  ${is_cluster}
    system_keywords.Check Management Service State In Service  ${is_cluster}

Check Cluster In-Service
    [Arguments]  ${is_cluster}=${False}
    ${login_status}  Run Keyword And Return Status    Login SCG  ${SCG_ADMIN_USERNAME}  ${SCG_ADMIN_PASSWORD}
    ${check_status}  Run Keyword And Return Status  Check Cluster Nodes in Service  ${is_cluster}
    Run Keyword If   ${login_status}
    ...  session_keywords.Logout SCG
    Run Keyword Unless    ${check_status}    Fail

Wait Until Cluster In-Service
    [Documentation]  variable is_cluster is used to indicate api to check service should be two node
    [Arguments]  ${timeout}=30 min  ${retry_interval}=5 sec  ${is_cluster}=${False}  ${start_delay}=0 sec
    Sleep  ${start_delay}
    Log  timeout=${timeout}, retry_interval=${retry_interval}
    Wait Until Keyword Succeeds  ${timeout}  ${retry_interval}  system_keywords.Check Cluster In-Service  ${is_cluster}

Set Upgrade Operation Status
    [Arguments]  ${status}  ${failed_reason}
    Set Test Variable  ${upgrade_option_successds}  ${status}
    Set Test Variable  ${upgrade_option_failed_reason}  ${failed_reason}

Get Upgrade Status
    ${res}=  api.call_prv  upgrade_get_upgrade_status
    Set Test Variable  ${res}  ${res}

Get Upgrade Status And Relogin
    ${login_status}  Run Keyword And Return Status    session_kw.run  Login SCG  ${admin_username}  ${admin_password}
    sys_kw.run  Get Upgrade Status
    Run Keyword If   ${login_status}
    ...  session_kw.run  Logout SCG

Check Follower Upgrade Operation Status
    Return From Keyword If  '${res["clusterSubTaskState"]}'=='Completed'
    Return From Keyword If  ${res['bladeProgressArray'][0]['progress']==0} and ${res['bladeProgressArray'][1]['progress']==0}
    Fail  Failed: Cluster is progressing

Check Upgrade Operation Finished
    [Documentation]  Use private api to get backup, upgrade status
    [Arguments]  ${operation_item}  ${reconnect}=${False}
    # SCG disconnect all connection when it do upgrading or restoring
    Run Keyword If  ${reconnect}  sys_kw.run  Get Upgrade Status And Relogin
    ...       ELSE  sys_kw.run  Get Upgrade Status

#    ${res["operation"]}=  Get Variable Value  ${res["operation"]}  None
    Dictionary Should Contain Key  ${res}  operation
    # if ${operation_item} is progressing, res["operation"]=${operation_item}
    Run Keyword If  '${res["operation"]}'=='${operation_item}'
    ...  Fail  Failed: ${operation_item} is progressing ${res["overallProgress"]}%

    # if ${operation_item} is done, res["operation"]="None".
    Run Keyword Unless  '${res["operation"]}'=='None'
    ...  Fail  Failed: ${operation_item} is progressing.

    Dictionary Should Contain Key  ${res}  clusterOperationBlockUI
    Run Keyword If  '${res["clusterOperationBlockUI"]}'=='${True}'
    ...  Fail  Failed: GUI show block message

    # check cluster state, it should wait until cluster state "Completed"
    Run Keyword If  ${has_second_node}  sys_kw.run  Check Follower Upgrade Operation Status

    Dictionary Should Contain Key  ${res}  previousOperationRecord
    # if it finished, it will record in the previous operation.
    # if operation is not the same as your expection, set status False
    Run Keyword Unless  '${res["previousOperationRecord"]["operation"]}'=='${operation_item}'
    ...  sys_kw.run  Set Upgrade Operation Status  ${False}  Failed: Last Operation is ${operation}, not ${operation_item}

    ${upgrade_option_successds}=  Get Variable Value  ${upgrade_option_successds}
    Return From Keyword If  ${upgrade_option_successds==False}

    sys_kw.run  Set Upgrade Operation Status  ${res["previousOperationRecord"]["success"]}    ${operation_item} Message: ${res["previousOperationRecord"]["message"]}

Wait Until Cluster ${operation_item} Process Succeeds
    Run Keyword If  '${operation_item}'=='Upgrade'
    ...  Wait Until Keyword Succeeds  ${upgrade_timeout}  ${upgrade_retry_interval}  sys_kw.run  Check Upgrade Operation Finished  Upgrade  ${True}
    Run Keyword If  '${operation_item}'=='Upload'
    ...  Wait Until Keyword Succeeds  ${upload_timeout}  ${upload_retry_interval}  sys_kw.run  Check Upgrade Operation Finished  Upload
    Run Keyword If  '${operation_item}'=='Upload_AP_Patch'
    ...  Wait Until Keyword Succeeds  ${upload_timeout}  ${upload_retry_interval}  sys_kw.run  Check Upgrade Operation Finished  UploadAPFirmware
    Run Keyword If  '${operation_item}'=='Upload_vDP_Patch'
    ...  Wait Until Keyword Succeeds  ${upload_timeout}  ${upload_retry_interval}  sys_kw.run  Check Upgrade Operation Finished  UploadVDPFirmware
    Run Keyword If  '${operation_item}'=='Backup'
    ...  Wait Until Keyword Succeeds  ${backup_timeout}   ${backup_retry_interval}   sys_kw.run  Check Upgrade Operation Finished  Backup
    Run Keyword If  '${operation_item}'=='Restore'
    ...  Wait Until Keyword Succeeds  ${restore_timeout}  ${restore_retry_interval}  sys_kw.run  Check Upgrade Operation Finished  Restore  ${True}

    Run Keyword Unless  ${upgrade_option_successds}  Fail  ${upgrade_option_failed_reason}

Check IP With Port Should Be Alive
    [Arguments]  ${ip}  ${port}
    ${rc}=  Run And Return Rc  time nc -v -w 5 ${ip} ${port} < /dev/null
    Should Be Equal  ${rc}  ${0}

