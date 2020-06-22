*** Keyword ***
SSH Login OK
    [Arguments]    ${ip}    ${port}    ${username}    ${password}
    SSH Login    ${ip}    ${port}    ${username}    ${password}
    Status should be    SUCCESS

SCG SSH Login OK
    [Arguments]    ${ip}=${SCG MANAGEMENT IP}    ${port}=${SSH PORT}    ${username}=${SCG ADMIN USERNAME}    ${password}=${SCG ADMIN PASSWORD}    ${prompt}=${SCG CLI PROMPT}    ${enable_password}=${SCG ADMIN ENABLE PASSWORD}
    SSH Login OK    ${ip}    ${port}    ${username}    ${password}
    Wait Until Keyword Succeeds    60 sec    5 sec    expect    ${prompt}>
    Send    enable\n
    expect    Password:
    Send    ${enable_password}\n
    expect    ${prompt}#

SCG SSH Login with Default OK
    [Arguments]    ${ip}=${SCG MANAGEMENT IP}    ${port}=${SSH PORT}    ${username}=${SCG DEFAULT ADMIN USERNAME}    ${password}=${SCG DEFAULT ADMIN PASSWORD}    ${prompt}=${SCG DEFAULT CLI PROMPT}
    SSH Login OK    ${ip}    ${port}    ${username}    ${password}
    expect    ${prompt}>
    Send    enable\n
    expect    Password:
    Send    ${SCG DEFAULT ADMIN ENABLE PASSWORD}\n
    expect    ${prompt}#

SCG SSH Login without rbd OK
    [Arguments]    ${ip}=${ACCESS IP WITHOUT RBD}    ${port}=${SSH PORT}    ${username}=${SCG DEFAULT ADMIN USERNAME}    ${password}=${SCG DEFAULT ADMIN PASSWORD}    ${prompt}=${SCG DEFAULT CLI PROMPT}}    ${enable_password}=${SCG DEFAULT ADMIN ENABLE PASSWORD}
    SSH Login OK    ${ip}    ${port}    ${username}    ${password}
    sleep    20 sec
    expect    SCG>
    Send    enable\n
    expect    Password:
    Send    ${SCG DEFAULT ADMIN ENABLE PASSWORD}\n
    expect    SCG#

SCG SSH Log into Shell OK
    [Arguments]    ${ip}=${SCG MANAGEMENT IP}    ${port}=${SSH PORT}    ${username}=${SCG ADMIN USERNAME}    ${password}=${SCG ADMIN PASSWORD}    ${prompt}=${SCG CONTROLLER NAME}    ${shell_password}=${SCG V54 PASSWORD}
    ...    ${enable_password}=${SCG ADMIN ENABLE PASSWORD}
    SCG SSH Login OK    ${ip}    ${port}    ${username}    ${password}    ${prompt}    ${enable_password}
    Send    !v54!\n
    Run Keyword And Ignore Error    expect    Passphrase:
    Run Keyword And Ignore Error    Send    ${shell_password}\n
    Expect Regex    bash-4.1[\\$#]
    Run Keyword And Ignore Error    Send    sudo su\n
    Run Keyword And Ignore Error    Expect Regex    .*root.*\#

SCG SSH Logout OK
    SSH Logout
    Status should be    SUCCESS

Clear SCG-D Cache
    SCG SSH Login OK
    Send    remote dp-cli ${SCG D MAC} \"datacore host gblIdleTMO 1 force\"\n
    Expect    ${SCG CLI PROMPT}#
    ${timeout}=    Get Timeout
    Set Timeout    5
    Wait Until Keyword Succeeds    30 sec    5 sec    SCG D Cache Is Empty
    Send    remote dp-cli ${SCG D MAC} \"datacore host gblIdleTMO 0 force\"\n
    Expect    ${SCG CLI PROMPT}#
    Set Timeout    ${timeout}

SCG D Cache Is Empty
    Send    remote dp-cli ${SCG D MAC} \"datacore host all\"\n
    Expect    ${SCG CLI PROMPT}#    False
    Expect Regex    Total hosts: active=([0-9]+), shown=.*
    ${num}=    Match Group    1
    Run Keyword If    ${num} > 0    FAIL    SCG-D Host Cache is not empty (${num})
