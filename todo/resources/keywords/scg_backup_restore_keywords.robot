# Section 0: Some Existing Keyword Set Test Variable, it can not be used by suite level
#            Please add another variable for keep the test value. 
# Section 1: Create config keyword.
#            Example: "Create xxx Before Backup"
# Section 2: Check config create is correct in section 1.
#            Example: "System Should Have The Created xxx Before Backup"
#            Example: "AP Should Have The Created xxx Before Backup"
# Section 3: Delete config keyword.
#            Example: "Delete xxx After Backup"
# Section 4: Check config has been deleted in section 3
#            Example: "System Should Not Have The Created xxx After Backup"
#            Example: "AP Should Not Have The Created xxx After Backup"
# Section 5: Check config has been restored.
#            Example: "System Should Have The Created xxx After Restore"
#            Example: "AP Should Have The Created xxx After Restore"

*** Settings ***
# ------------- !!! No Settings Here !!! -----------
# Settings are centralized in keyword_adapters.robot
# --------------------------------------------------


*** Variables ***
# Requied variables
${need_ap}  ${True}


*** Keywords ***
AP Firmware Should Be Latest
    ${ap_latest_ap_fw_version}=  ap_kw.run  Get AP FW Version
    Wait Until Keyword Succeeds  10 min  10 sec  ap_kw.run  AP Version Should Be Updated
    ...  ${ap_ip}  ${ap_username}  ${ap_password}  ${ap_latest_ap_fw_version}
    Wait Until Keyword Succeeds  5 min  10 sec  ap_kw.run  Check AP Config Status Completed
    ...  ${ap_mac}  ${zone_id}

########## Section 0: Switch Variable ################
Save Variable Before Backup To Suite Variable
    [Documentation]  If your variable need to corss test case, you should add here.
    ...  If you add variable, you also need to add in the keywords 'Set Backup Variable To Test Variable'
    ...  To avoid effcting original variable, you should add before_backup index to your original variable.
    ...  For example, wlan_id should be wlan_id_before_backup.
    Set Suite Variable  ${wlan_id_before_backup}  ${wlan_id}
    Set Suite Variable  ${wlan_base_data_before_backup}  ${wlan_base_data}
    Set Suite Variable  ${wlan_name_before_backup}  ${wlan_name}
    Set Suite Variable  ${wlan_update_data_before_backup}  ${wlan_update_data}

Save Variable Before Backup To Test Variable
    [Documentation]  To a fully teardown, you should import the value to the original parameter
    ${wlan_id}=  Get Variable Value  ${wlan_id_before_backup}
    Set Test Variable  ${wlan_id}  ${wlan_id}

    ${wlan_base_data}=  Get Variable Value  ${wlan_base_data_before_backup}
    Set Test Variable  ${wlan_base_data}  ${wlan_base_data}

    ${wlan_name}=  Get Variable Value  ${wlan_name_before_backup}
    Set Test Variable  ${wlan_name}  ${wlan_name}

    ${wlan_update_data}=  Get Variable Value  ${wlan_update_data_before_backup}
    Set Test Variable  ${wlan_update_data}  ${wlan_update_data}

Set Variable Has Suite Setup To Be True
    [Documentation]  AP usually join zone in the suite scope,
    ...  but backup and restore will do it in the test scope,
    ...  so we need to set variable in the test case
    Set Suite Variable  ${has_suite_setup}  True


########## Section 1: Create Config Before Backup for Each Feature ################

Create Basic AP Zone Before Backup
    tc_kw.run  Create Basic AP Zone

Create Standard Open WLAN Before Backup
    [Documentation]  Set suite variable for other test case to verify
    wlan_kw.run  Create Standard Open WLAN

########## Section 2: Add Check Config Before Backup for Each Feature #############

System Should Have The Created WLAN Before Backup
    ${wlan_id}=  Get Variable Value  ${wlan_id_before_backup}
    ${wlan_base_data}=  Get Variable Value  ${wlan_base_data_before_backup}
    ${wlan_name}=  Get Variable Value  ${wlan_name_before_backup}
    ${wlan_update_data}=  Get Variable Value  ${wlan_update_data_before_backup}

    ${wlan_info}=  wlan_kw.run  Get WLAN Information
    Should Not Be Empty  ${wlan_info}
    Log Dictionary  ${wlan_info}

    ${wlan_input}=  tool.merge_dicts  ${wlan_base_data}  ${wlan_update_data}
    Log Dictionary  ${wlan_input}

    ${pass}=  tool.if_info_contain_input  ${wlan_info}  ${wlan_input}
    Should Be Equal  ${pass}  ${True}

AP Should Have The Created WLAN Before Backup
    Wait Until Keyword Succeeds  3 min  5 sec  apcli.check_wlan_ready  ${wlan_name}

############ Section 3: Delete Config Check After Backup ##########################

Delete WLAN After Backup
    Run Keyword If  ${wlan_id!= None}
    ...  wlan_kw.run  Delete WLAN  ${zone_id}  ${wlan_id}

############ Section 4: Check Config Have Been Deleted Check After Backup #########

System Should Not Have The Created WLAN After Backup
    ${url_params}=  Create Dictionary  zoneId=${zone_id}  id=${wlan_id}
    ${status}=  Run Keyword And Return Status  api.call_pub  rkszones_get_wlan  urlParams=${url_params}
    Should Not Be True  ${status}

AP Should Not Have The Created WLAN After Backup
    ${ap_major_version}=  Set Variable  ${ap_previous_ap_fw_version[:3]}
    Run Keyword If  '${ap_major_version}' == '3.2'
    ...    Wait Until Keyword Succeeds  10 min  30 sec  apcli.check_wlan_ready  ${wlan_name}  down
    ...  ELSE
    ...    Wait Until Keyword Succeeds  10 min  30 sec  ap_kw.run  AP Exclude WLAN  ${wlan_name}

############ Section 5: Check Config Have Been Restored After Restore #############

System Should Have The Created WLAN After Restore
    backup_kw.run  System Should Have The Created WLAN Before Backup

AP Should Have The Created WLAN After Restore
    backup_kw.run  AP Should Have The Created WLAN Before Backup

############ Section 6: Following Keywords Will Be Used by Backup Restore And Upgrade ############
Create Configuration Before Backup
    [Documentation]  Add what you want to varified config,
    ...  and you should set suite variable for other test case to verify

    # [Setion 1]
    backup_kw.run  Create Basic AP Zone Before Backup
    backup_kw.run  Create Standard Open WLAN Before Backup

    # [Setion 0]
    backup_kw.run  Save Variable Before Backup To Suite Variable

System Should Have The Created Configuration Before Backup
    [Documentation]  Verify system properly creat configuration
    backup_kw.run  Save Variable Before Backup To Test Variable
    # [Setion 2]
    backup_kw.run  System Should Have The Created WLAN Before Backup

AP Should Have The Created Configuration Before Backup
    [Documentation]  Verify ap properly apply configuration
    Return From Keyword If  ${need_ap==False}

    backup_kw.run  Save Variable Before Backup To Test Variable
    tc_kw.run  AP Must Join AP Zone

    backup_kw.run  AP Firmware Should Be Latest
    # [Setion 2]
    test_kw.run  AP Test Case Setup
    backup_kw.run  AP Should Have The Created WLAN Before Backup
    test_kw.run  AP Test Case Teardown


Delete Configuration After Backup
    [Documentation]  Verify backup works, we should delete some config after backup.
    backup_kw.run  Save Variable Before Backup To Test Variable
    # [Setion 3]
    backup_kw.run  Delete WLAN After Backup

System Should Have The Created Configuration After Backup
    [Documentation]  Verify system properly creat configuration
    backup_kw.run  Save Variable Before Backup To Test Variable
    # [Setion 4]
    backup_kw.run  System Should Not Have The Created WLAN After Backup

AP Should Have The Created Configuration After Backup
    [Documentation]  Verify ap properly apply configuration
    Return From Keyword If  ${need_ap==False}

    backup_kw.run  Save Variable Before Backup To Test Variable
    tc_kw.run  AP Must Join AP Zone

    backup_kw.run  AP Firmware Should Be Latest
    # [Setion 4]
    test_kw.run  AP Test Case Setup
    backup_kw.run  AP Should Not Have The Created WLAN After Backup
    test_kw.run  Test Case Teardown


System Should Have The Created Configuration After Restore
    [Documentation]  It is the same with what we created before backup
    backup_kw.run  Save Variable Before Backup To Test Variable
    # [Setion 5]
    backup_kw.run  System Should Have The Created WLAN After Restore

AP Should Have The Created Configuration After Restore
    [Documentation]  It is the same with what we created before backup
    Return From Keyword If  ${need_ap==False}

    backup_kw.run  Save Variable Before Backup To Test Variable
    Sleep  5 min
    tc_kw.run  AP Must Join AP Zone

    backup_kw.run  AP Firmware Should Be Latest
    # [Setion 5]
    test_kw.run  AP Test Case Setup
    backup_kw.run  AP Should Have The Created WLAN After Restore
    test_kw.run  Test Case Teardown

############ Backup And Restore ############
System Should Not Have Backup Cluster File
    [Documentation]  If there is any backup file, deleted it
    ${clutser_backup_file_number}=  backup_kw.run  Get Cluster Backup File Number
    Run Keyword If  ${clutser_backup_file_number != 0}
    ...   backup_kw.run  Delete Cluster Backup File

System Should Not Have Backup Config File
    [Documentation]  If it is the same with System Should Not Have Backup Cluster File, just ignore and use a suite keyword name 
    ${config_backup_file_number}=  scg_backup_restore_keywords.Get Config Backup File Number
    Run Keyword If  ${config_backup_file_number != 0}
    ...   scg_backup_restore_keywords.Delete Config Backup File
    ${config_backup_file_number}=  scg_backup_restore_keywords.Get Config Backup File Number
    Should Be Equal  ${config_backup_file_number}  ${0}

System Should Have The Created Backup Cluster File
    [Documentation]  Check Backup Cluster Id is existed, if it needs. Use variable ${backup_id} to verify
    ${clutser_backup_file_number}=  backup_kw.run  Get Cluster Backup File Number
    Should Be Equal  ${clutser_backup_file_number}  ${1}
    backup_kw.run  Cluster Backup File Version Should Be Equal System Version

System Should Have The Created Backup Config File
    [Documentation]  Check Backup Config Id is existed, if it needs. Use variable ${backup_config_id} to verify
    ${config_backup_file_number}=  scg_backup_restore_keywords.Get Config Backup File Number
    Should Be Equal  ${config_backup_file_number}  ${1}
    scg_backup_restore_keywords.Config Backup File Version Should Be Equal System Version

Cluster Backup File Version Should Be Equal System Version
    ${current_scg_fw_version}=  backup_kw.run  Get SCG FW Version
    ${backup_file_version}=  backup_kw.run  Get Cluster Backup File Version
    Should Be Equal  ${current_scg_fw_version}  ${backup_file_version}

Config Backup File Version Should Be Equal System Version
    ${current_scg_fw_version}=  scg_backup_restore_keywords.Get SCG FW Version
    ${backup_config_file_version}=  scg_backup_restore_keywords.Get Config Backup File Version
    Should Be Equal  ${current_scg_fw_version}  ${backup_config_file_version}

Get Carrier OR Vscg Carrier FW Version
    ${res}=  api.call_pub  get_carrier_controller
    Set Test Variable  ${scg_fw_version}  ${res["list"][0]["version"]}

Get Enterpise OR Vscg Enterprise FW Version
    ${res}=  get_enterprise_controller
    Set Test Variable  ${scg_fw_version}  ${res["list"][0]["version"]}

Get SCG FW Version
    Run Keyword If  '${MODEL}' == 'carrier' or '${MODEL}' == 'vscg_carrier'
    ...  scg_backup_restore_keywords.Get Carrier OR Vscg Carrier FW Version
    ...  ELSE  scg_backup_restore_keywords.Get Enterpise OR Vscg Enterprise FW Version
    [Return]  ${scg_fw_version}

Get Cluster Backup File Version
    ${res}=  api.call_prv  backup_get_cluster_backup
    [Return]  ${res["list"][0]["version"]}

Get Config Backup File Version
    ${res}=  get_configuration_backup_list
    [Return]  ${res['list'][0]['scgVersion']}


############ Check Backup And Restore Status ############
Backup Cluster Successd
    [Documentation]  Use to check backup cluster is successful before restore
    ${backup_cluster_status}=  Get Variable Value  ${backup_cluster_status}
    Run Keyword Unless  ${backup_cluster_status}  Fail  Failed to backup cluster, or It does not do backup

Restore Cluster Successd
    [Documentation]  Use to check backup cluster is successful before upgrade
    ${restore_cluster_status}=  Get Variable Value  ${restore_cluster_status}
    Run Keyword Unless  ${restore_cluster_status}  Fail  Failed to restore cluster, or It does not do restore

Backup Config Successd
    [Documentation]  Use to check backup config is successful before restore
    ${backup_config_status}=  Get Variable Value  ${backup_config_status}
    Run Keyword Unless  ${backup_cluster_status}  Fail  Failed to backup config, or It does not do backup

Restore Config Successd
    [Documentation]  Use to check backup config is successful before upgrade
    ${restore_config_status}=  Get Variable Value  ${restore_config_status}
    Run Keyword Unless  ${restore_cluster_status}  Fail  Failed to restore config, or It does not do restore

############ Backup And Restore Keywords ############
Get Cluster Backup File Number
    ${res}=  api.call_prv  backup_get_cluster_backup
    [Return]  ${res["totalCount"]}

Get Config Backup File Number
    ${res}=  get_configuration_backup_list
    [Return]  ${res['totalCount']}

Get Cluster Backup File Info
    ${res}=  backup_get_cluster_backup
    [Return]  ${res["list"][0]["backupID"]}

Get Configuration Backup Info
    ${res}=  get_configuration_backup_list
    [Return]  ${res['list'][0]['id']}

Delete Cluster Backup File
    ${res}=  get_cluster_backup_list
    :FOR  ${index}  IN RANGE  ${res['totalCount']}
    \  ${urlParams}=  Create Dictionary  id=${res['list'][${index}]['id']}
    \  api.call_pub  delete_cluster_backup  urlParams=${urlParams}

Delete Config Backup File
    ${res}=  get_configuration_backup_list
    :FOR  ${idx}  IN RANGE  ${res['totalCount']}
    \  ${id}=  Set Variable  ${res['list'][${idx}]['id']}
    \  ${url_params}=  Create Dictionary  id=${id}
    \  delete_configuration_backup  urlParams=${url_params}

Backup Cluster
    System Should Not Have Backup Cluster File
    api.call_prv  backup_backup_cluster
    Sleep  20 sec
    sys_kw.run  Wait Until Cluster Backup Process Succeeds
    # If backup success, it should have backup file. Set a suite variable for teardown
    System Should Have The Created Backup Cluster File
    ${backup_cluster_id}=  backup_kw.run  Get Cluster Backup File Info

    Set Suite Variable  ${backup_cluster_id}  ${backup_cluster_id}
    Set Suite Variable  ${backup_cluster_status}  ${True}

Backup Configuration
    scg_backup_restore_keywords.System Should Not Have Backup Config File
    create_configuration_backup

    # If backup success, it should have backup file. Set a suite variable for teardown
    Wait Until Keyword Succeeds  5 min  5 sec
    ...  scg_backup_restore_keywords.System Should Have The Created Backup Config File
    ${backup_config_id}=  scg_backup_restore_keywords.Get Configuration Backup Info

    Set Suite Variable  ${backup_config_id}  ${backup_config_id}
    Set Suite Variable  ${backup_config_status}  ${True}

Restore Cluster
    ${backup_cluster_id}=  Get Cluster Backup File Info
    ${urlParams}=  Create Dictionary  id=${backup_cluster_id}
    api.call_pub  restore_cluster_by_id  urlParams=${urlParams}
    Wait Until Keyword Succeeds  5 min  10 sec  backup_kw.run  SCG Service Should Be Restarted

    sys_kw.run  Wait Until Cluster In-Service
    # We do not need to check configuration after restore failed
    Set Suite Variable  ${restore_cluster_status}  ${True}

Restore Configuration
    ${backup_config_id}=  Get Configuration Backup Info
    ${url_params}=  Create Dictionary
    ...  id=${backup_config_id}
    restore_configuration_backup  urlParams=${url_params}
    #Wait Until Keyword Succeeds  40 min  30 sec  SCG Service Should Be Restarted
    Sleep  40 min
    system_keywords.Wait Until Cluster In-Service
    # We do not need to check configuration after restore failed
    Set Suite Variable  ${restore_config_status}  ${True}

SCG Service Should Be Restarted
    ${passed}=  Run Keyword And Return Status  session_keywords.Login SCG  ${SCG_ADMIN_USERNAME}  ${SCG_ADMIN_PASSWORD}
    Run Keyword If  ${passed == True}  session_keywords.Logout SCG
    Should Not Be True  ${passed}
