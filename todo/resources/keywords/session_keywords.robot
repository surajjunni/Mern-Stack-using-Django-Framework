*** Settings ***
# ------------- !!! No Settings Here !!! -----------
# Settings are centralized in keyword_adapters.robot
# --------------------------------------------------


*** Variables ***



*** Keywords ***
#Retried Login
#    [Documentation]  Login keyword wrapper which retry when login fail
#    [Arguments]  ${kw_adapter}=""  ${login_kw}=""  ${logout_kw}=""  ${do_warn_fail}=${True}
#    Should Not Be Empty  ${kw_adapter}
#    Should Not Be Empty  ${login_kw}
#    Should Not Be Empty  ${logout_kw}
    # Retry 5 Times
#    : FOR  ${cnt}  IN RANGE  6
#    \    Sleep  ${cnt}s  Wait ${cnt}s
#    \    ${login_ok}=  Run Keyword And Return Status  ${kw_adapter}.run  ${login_kw}
#    \    Return From Keyword If  ${login_ok}  ${True}
#    \    Run Keyword And Ignore Error  ${kw_adapter}.run  ${logout_kw}
#    ${failed_login}=  util.Fetch From Left  ${login_kw}  Once
#    Run Keyword If  ${do_warn_fail}  Log  Fail to ${failed_login}  warn
#    Fail  Fail to ${failed_login}

Retried Login
    [Documentation]  Login keyword wrapper which retry when login fail
    [Arguments]  ${login_kw}=""  ${logout_kw}=""  ${do_warn_fail}=${True}
    Should Not Be Empty  ${login_kw}
    Should Not Be Empty  ${logout_kw}
    # Retry 5 Times
    : FOR  ${cnt}  IN RANGE  5
    \    ${login_ok}=  Run Keyword And Return Status  ${login_kw}
    \    Return From Keyword If  ${login_ok}  ${True}
    \    Run Keyword And Ignore Error  ${logout_kw}
    \    Sleep  3s  Wait 3s
    ${failed_login}=  util.Fetch From Left  ${login_kw}  Once
    Run Keyword If  ${do_warn_fail}  Log  Fail to ${failed_login}  warn
    Fail  Fail to ${failed_login}

Login SCG
    [Arguments]  ${SCG_ADMIN_USERNAME}  ${SCG_ADMIN_PASSWORD}
    Run Keyword  Retried Login  Login SCG Once   Logout SCG   ${False}

Login SCG Once
    ${data}=  Create Dictionary  username=${SCG_ADMIN_USERNAME}  password=${SCG_ADMIN_PASSWORD}  timeZoneUtcOffset=+08:00
    session_login  ${data}

Logout SCG
    session_logout

Switch SCG
    [Arguments]    ${host}    ${model}=${scg_model}    ${scg_version}=${scg_version}    ${pubapi_version}=${pubapi_version}
    api.select_api_verson    ${host}    ${model}    ${scg_version}    ${pubapi_version}

Login SCG CLI
    [Arguments]  ${login_ip}=${scg_management_ip}  ${hostname}=${scg_hostname}  ${username}=${admin_username}
    ...  ${password}=${admin_password}  ${enable_password}=${admin_enable_password}
    Run Keyword  session_kw.run  Retried Login  session_kw  Login SCG CLI Once   Logout SCG CLI

Login SCG CLI Once
    scgcli.open_connection  ${login_ip}
    scgcli.login
    ...  hostname=${hostname}
    ...  username=${username}
    ...  password=${password}
    ...  enable_password=${enable_password}

Login Fresh SCG CLI
    [Arguments]  ${login_ip}=${setup_ip}
    Run Keyword  session_kw.run  Retried Login  session_kw  Login Fresh SCG CLI Once   Logout SCG CLI   ${False}

Login Fresh SCG CLI Once
    scgcli.open_connection  ${login_ip}
    scgcli.login
    ...  hostname=${scg_default_cli_prompt}
    ...  username=${scg_default_admin_username}
    ...  password=${scg_default_admin_password}
    ...  enable_password=${scg_default_admin_password}

Login Failed Install SCG CLI
    session_kw.run  Login SCG CLI  ${scg_management_ip}  ${scg_hostname}  ${admin_username}
    ...  ${scg_default_admin_password}  ${admin_enable_password}

Login SCG CLI ${time_point} Setup Network
    [Documentation]  after setup scg network but not setup cluster
    ...  session_kw.run  Login SCG cli via different network interface
    ...  time_point is Before, Login scg via setup interface
    ...  time_point is After, Login scg via management interface
    Run Keyword If  '${time_point}' == 'Before'  session_kw.run  Login Fresh SCG CLI
    Run Keyword If  '${time_point}' == 'After'  session_kw.run  Login Fresh SCG CLI  ${scg_management_ip}

Login SCG CLI And Change Diagnostic Mode
    session_kw.run  Login SCG CLI
    scgcli.write_until_regex  diagnostic  \\(diagnostic\\)#  15 seconds

Retry Login SCG CLI Anyway
    Wait Until Keyword Succeeds  3 min  15 sec  session_kw.run  Login SCG CLI Anyway

CLI Login Anyway
    ${passed}=  Run Keyword And Return Status  session_kw.run  Login SCG CLI
    ${passed}=  Run Keyword And Return Status  Run Keyword Unless  ${passed}
    ...  session_kw.run  Login SCG CLI Before Setup Network
    Run Keyword Unless  ${passed}
    ...  session_kw.run  Login SCG CLI After Setup Network

    Return From Keyword If  ${passed}
    Log  SCG CLI Login to Fail  warn
    Run Keyword And Ignore Error  session_kw.run  Logout SCG CLI
    Fail  CLI Login Failed

CLI Login
    ${passed}=  Run Keyword And Return Status  session_kw.run  Login SCG CLI
    Return From Keyword If  ${passed}
    Log  SCG CLI Login to Fail  warn
    Run Keyword And Ignore Error  session_kw.run  Logout SCG CLI
    Fail  CLI Login Failed
#    session_kw.run  Run CLI Change Keyword And Fail To Close Session  session_kw.run  Login SCG CLI

Retry Login SCG CLI
    session_kw.run  Retry Login And Fail To Close Session  session_kw.run  Login SCG CLI

Retry Login SCG Shell
    session_kw.run  Retry Login And Fail To Close Session  session_kw.run  Login SCG Shell

Retry Login SCG CLI And Diagnostic
    session_kw.run  Retry Login And Fail To Close Session  session_kw.run  Login SCG CLI And Change Diagnostic Mode

Retry Login And Fail To Close Session
    [arguments]  ${kw_adapter}  ${kw}
    Wait Until Keyword Succeeds  3 min  15 sec  session_kw.run  Run CLI Change Keyword And Fail To Close Session  ${kw_adapter}  ${kw}

Run CLI Change Keyword And Fail To Close Session
    [arguments]  ${kw_adapter}  ${kw}
    ${passed}=  Run Keyword And Return Status  ${kw_adapter}  ${kw}
    Return From Keyword If  ${passed}
    Log  ${kw} to Fail  warn
    Run Keyword And Ignore Error  session_kw.run  Logout SCG CLI
    Fail  ${kw} Failed

Logout SCG CLI
    scgcli.close_connection

Login SCG Shell
    [Arguments]  ${login_ip}=${scg_management_ip}  ${hostname}=${scg_hostname}  ${username}=${admin_username}
    ...  ${password}=${admin_password}  ${enable_password}=${admin_enable_password}  ${v54_passphrase}=${scg_v54_password}
    scgcli.open_connection  ${login_ip}
    scgcli.login_shell
    ...  hostname=${hostname}
    ...  username=${username}
    ...  password=${password}
    ...  enable_password=${enable_password}
    ...  v54_passphrase=${v54_passphrase}

Logout SCG Shell
    scgcli.close_connection

Login Linux CLI
    linuxcli.open_connection  ${linux_ip}
    linuxcli.login  ${linux_username}  ${linux_password}

Logout Linux CLI
    linuxcli.close_connection

Login Jenkins Server
    [Documentation]  login to host server
    jenkins_hostcli.open_connection  ${jenkins_host_ip}
    jenkins_hostcli.login

Logout Jenkins Server
    [Documentation]  logout to host server
    jenkins_hostcli.logout

Login SCG Shell ${time_point} Setup Network
    [Documentation]  after setup scg network but not setup cluster
    ...  session_kw.run  Login SCG cli via different network interface
    ...  time_point is Before, Login scg via setup interface
    ...  time_point is After, Login scg via management interface
    session_kw.run  Login SCG CLI ${time_point} Setup Network
    scgcli.login_shell_from_cli  ${scg_v54_password}

Login SCG Shell Anyway
    [Documentation]  Login SCG CLI by trying username/password in 3 differnt state (cluster, network, default)
    ${status}=  Run Keyword And Return Status  session_kw.run  Login SCG Shell  hostname=${None}  v54_passphrase=${scg_v54_password}
    ${status}=  Run Keyword And Return Status  Run Keyword Unless  ${status}
    ...  session_kw.run  Login SCG Shell Before Setup Network
    ${status}=  Run Keyword And Return Status  Run Keyword Unless  ${status}
    ...  session_kw.run  Login SCG Shell After Setup Network
    Return From Keyword If  ${status}
    Log  SCG CLI Login to Fail  warn
    Run Keyword And Ignore Error  session_kw.run  Logout SCG CLI
    Fail  session_kw.run  CLI Login Failed

Login SCG CLI Anyway
    [Documentation]  Login SCG CLI by trying username/password in 3 differnt state (cluster, network, default)
    ${status}=  Run Keyword And Return Status  session_kw.run  Login SCG CLI
    ${status}=  Run Keyword And Return Status  Run Keyword Unless  ${status}
    ...  session_kw.run  Login Fresh SCG CLI
    ${status}=  Run Keyword And Return Status  Run Keyword Unless  ${status}
    ...  session_kw.run  Login Failed Install SCG CLI
    ${status}=  Run Keyword And Return Status  Run Keyword Unless  ${status}  session_kw.run  Login SCG CLI After Setup Network
    Return From Keyword If  ${status}
    Log  SCG CLI Login to Fail  warn
    Run Keyword And Ignore Error  session_kw.run  Logout SCG CLI
    Fail  session_kw.run  CLI Login Failed
