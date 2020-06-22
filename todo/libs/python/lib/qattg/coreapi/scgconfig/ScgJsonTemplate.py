class ScgJsonTemplate:
    """ScgJsonTemplate class contains the functions that returns the dictionary
       that dictionaries are used in creating and updating the profiles
    """

    def __init__(self):
        pass

    def get_login_template_data(self):
        """dictionary contains the keys and values of login data
        """
        login_data = { "userName":"",

                        "password":"",
             }
        return login_data

    def get_ggsn_template_data(self):
        """template contains the dictionary of ggsn post data
        """
        ggsn_data  = {"gtpSettings":{"t3ResponseTimer":3,
                               "numberOfRetries":5,
                               "echoRequestTimer":"60",
                               "responseTimeout":3,
                               "dnsNumberOfRetries":3},
                      "ggsns":[],
                      "dnsServers":[]
                      }
        return ggsn_data

    def get_ggsn_template_data_mvno(self):
        """template contains the dictionary of MVNO ggsn data
        """
        ggsn_data  = {"ggsns":[],
                      "dnsServers":[]
                      }
        return ggsn_data

    def get_ggsn_update_template(self):
        ggsn_data  = {"gtpSettings":{"t3ResponseTimer":"",
                               "numberOfRetries":"",
                               "echoRequestTimer":"",
                               "responseTimeout":"",
                               "dnsNumberOfRetries":""},
                      "ggsns":[],
                      "dnsServers":[]
                      }
        return ggsn_data

    def get_ggsn_update_template_mvno(self):
        ggsn_data  = {"ggsns":[],"dnsServers":[]}
        return ggsn_data

    def get_radius_template_data(self):
        """ dictionary used to create RADIUS profile
        """
        radius_data = {"key":"","tenantId":"",
                  #"type" :"",
                  "name":"", 
                  "description":"testing",
                  "respWindow":20,
                  "zombiePeriod":40,
                  "reviveInterval":120,
                  "maxOutstandingRequestsPerServer":50,
                  "threshold":70,
                  "sanityTimer":10,
                  "radiusIP":"",
                  "radiusPort":"",
                  "radiusShareSecret":"",
                  #"secondaryRadiusEnabled": 0,
                  "outOfBandLDForRuckusAP" : 0,
                  #"groupAttrs":[{"groupAttr": "*", "identityUserRoleId": ""}],

                  }
        return radius_data
    def get_dhcp_template_data(self):
        """ dictionary contains the DHCP profile post data
        """
        dhcp_data = { "key":"",
                "modifierId":"",
                "modifierUsername":"admin",
                "tenantId":"",
                "tenantName":"Super",
                "name":"example",
                "description":"testing",
                "firstServer":"1.2.3.4",
                "secondServer":"127.0.0.2" }
        return dhcp_data

    def get_ttgpdg_template_data(self):
        """template used to create and update the TTG+PDG profile
        """
        ttgpdg_data = {"key":"",
                       "tenantId":"",
                       "profileType":"TTGPDG",
                       "name":"TEST",
                       "description":"testing",
                       "pdgUeIdleTimeout":300,
                       "defaultNoMatchingAPN":"www.abc.com",
                       "defaultNoRealmAPN":"www.abc.com",
                       "apnForwardingRealms":[],
                       "apnRealms":[],
                       "ttgCommonSetting":{"apnFormat2GGSN":"String",
                                           "apnOIInUse":True,
                                           "acctRetry":5,
                                           "acctRetryTimeout":5,
                                           "pdgUeIdleTimeout":300}}
        return ttgpdg_data
    def get_ttgpdg_template_update(self):
        ttgpdg_data = {"key":"",
                       "tenantId":"",
                       "profileType":"TTGPDG",
                       "name":"",
                       "description":"",
                       "pdgUeIdleTimeout":None,
                       "defaultNoMatchingAPN":"",
                       "defaultNoRealmAPN":"",
                       "apnForwardingRealms":[],
                       "apnRealms":[],
                       "ttgCommonSetting":{"apnFormat2GGSN":"",
                                           "apnOIInUse":None,
                                           "acctRetry":None,
                                           "acctRetryTimeout":None,
                                           "pdgUeIdleTimeout":None}}
        return ttgpdg_data


    def add_ttgpdg_template_data(self):
        ttgpdg_data = {"key":"",
                       "tenantId":"",
                       "profileType":"TTGPDG",
                       "name":"TEST",
                       "description":"testing",
                       "pdgUeIdleTimeout":300,
                       "defaultNoMatchingAPN":"www.abc.com",
                       "defaultNoRealmAPN":"www.abc.com",
                       "apnForwardingRealms":[],
                       "apnRealms":[{"realm":"www.mnc.mcc.3gpp.org",
                                     "defaultAPN":"www.abc.com"}],
                       "ttgCommonSetting":{"apnFormat2GGSN":"String",
                                           "apnOIInUse":True,
                                           "acctRetry":5,
                                           "acctRetryTimeout":5,
                                           "pdgUeIdleTimeout":300}}
        return ttgpdg_data

    def get_eapaka_template_update(self):
        eapaka_data = {"enabled":"false",
                       "privacySupport":False,
                       "fastReAuth":False,
                       "cleanUp":"",
                       "secretKeyList":[]
                      }
        return eapaka_data
    def get_eapaka_template_data(self):
        eapaka_data = {"enabled":"false",
                       "privacySupport":False,
                       "fastReAuth":False,
                       "activeKey":"1",
                       "fastReAuthRealm":"testing.com",
                       "maxSucReAhth":256,
                       "cleanUp":"False",
                       "cleanUpTimeHrs":1,
                       "cleanUpTimeMins":1,
                       "cacheHisLen":1,
                       "secretKeyList":[]
                      }
        return eapaka_data

    def get_eapsim_template_data(self):
        eapsim_data = {"enabled":"true",
                        "privacySupport":True,
                        "fastReAuth":True,
                        "activeKey":"0",
                        "fastReAuthRealm":"reauth.com",
                        "maxSucReAhth":256,
                        "cleanUp":"true",
                        "cleanUpTimeHrs":1,
                        "cleanUpTimeMins":1,
                        "cacheHisLen":1,
                        "secretKeyList":[{"keyNum":"",
                                          "secretKey":"lfkhglskdfh",
                                          "createDatetime":""}]}
        return eapsim_data

    def get_wispr_template_data(self):
        """dictionary used to create and update the WISPr profile
        """
        wispr_data = {"zoneUUID":"",
                      "name":"TEST",
                      "description":"testing",
                      #"guestUser":"1",
                      "language": "en_US",
                      "key":"",
                      "bridgeMode":1,
                      "smartClientMode":"none",
                      "spMode":"INTERNAL",
                      "secondRedirect":"user",
                      "sessionTime":1440,
                      "gracePeriod":60,
                      "wisperLocationId":"",
                      "wisperLocationName":"",
                      "walledGarden":",",
                      "redirectUrl":"",
                      "smartClientInfo":"",
                      "zoneName":""}
        return wispr_data

    def get_aaa_template_data(self):
        """ used to create and update the AAA server
        """
        aaa_data = {"key":"",
                 "authType":"WLAN",
                 "name":"TEST",
                 "type":"RADIUS",
                 "respWindow":20,
                 "zombiePeriod":40,
                 "reviveInterval":120,
                 "responseFail":"false",
                 "radiusIP":"1.1.1.1",
                 "radiusPort":1812,
                 "radiusShareSecret":'1234567890',
                 "enableSecondaryRadius":0,
                 "zoneUUID":"",
                 "zoneName":"Auto-1-LN"}
        return aaa_data
    """
    def get_aaa_validate(self):
        aaa_data = {"name":"",
                    "type":"RADIUS",
                     "respWindow":None,
                     "zombiePeriod":None,
                     "reviveInterval":None,
                     "responseFail":"false",
                     "radiusIP":"",
                     "radiusPort":None,
                     "radiusShareSecret":"",
                     "enableSecondaryRadius":0,
                     "zoneName":"",
                     "secondaryRadiusIP":"",
                     "secondaryRadiusPort":None,
                     "secondaryRadiusShareSecret":""}
        return aaa_data
    """
    def get_aaa_template_update(self):
        aaa_data = {"key":"",
                     "authType":"WLAN",
                     "name":"",
                     "type":"",
                     "respWindow":None,
                     "zombiePeriod":None,
                     "reviveInterval":None,
                     "responseFail":"false",
                     "radiusIP":"",
                     "radiusPort":None,
                     "radiusShareSecret":"",
                     "enableSecondaryRadius":None,
                     "zoneUUID":"",
                     "zoneName":""}
        return aaa_data

    def get_cgf_template_data_basic(self):
        basic_data = {"name":"CGF",
                      "description":"testing",
                      "ttgpdgEnabled":False,
                      "chargingServiceType":"SERVER",
                      "lboEnabled":False,
                      "protocolType": "CGF"}
        return basic_data
    def get_cgf_template_data_default_cdr(self):
        default_cdr_data={"cdrType":"default_CDR",
                     "sendApnNetworkIdentifier":False,
                     "sendDiagnostic":False,
                     "sendNodeID":False,
                     "sendLocalRecordSequenceNumber":False,
                     "sendMsisdn":False,
                     "sendChargingCharacteristicsSelectionMode":False,
                     "sgsnPlmnId":False,
                     "nodeId":"1"}
        return default_cdr_data
    def get_cgf_template_data_s_cdr(self):
        s_cdr_data = {"sendSgsnAddress":False,
                 "sendPdpType":False,
                 "sendServedPdpAddress":False,
                 "sendApnSelectionMode":False,
                 "sendApnOperatorIdentifier":False,
                 "sendDynamicModeAddressFlag":False,
                 "sendRatType":False,
                 "listOfTrafficVolumes":False}
        return s_cdr_data
    def get_cgf_template_data_server(self):
        server_data= {"serverOptions":{"gtpEchoTimeout":60,
                                      "numOfRetriesForGtpEchoResponse":5,
                                      "cdrResponseTimeout":5,
                                      "cdrNumOfRetries":3,
                                      "maxNumOfCdrsPerRequest":1,
                                      "serverConfigurationList":[{"priority":"1",
                                                                  "serverIp":"1.2.3.4",
                                                                  "serverPort":"1812"}]}}
        return server_data


    def get_cgf_template_data_binary_server(self):
        ftp_data = {"ftpSettings":{"ftpHost":"10.1.20.12",
                              "ftpPort":"21",
                              "ftpUserName":"root",
                              "ftpPassword":"ruckus",
                              "key":"",
                              "ftpRemoteDirectory":"",},
                     "localBinaryFileOptions":{"autoExportViaFtp":"true",
                                              "recordLimit":1000,
                                              "fileTimeLimit":60,
                                              "fileLifetime":5,
                                              "exportScheduleList":[{"interval":"Daily",
                                                                     "hour":"00",
                                                                     "minute":"00"}],
                                              "ftpServerSettingsKey":""}}

        data = { "localBinaryFileOptions":{"autoExportViaFtp":"true",
                                              "recordLimit":1000,
                                              "fileTimeLimit":60,
                                              "fileLifetime":5,
                                              "exportScheduleList":[{"interval":"Hourly",
                                                                     "hour":"01",
                                                                     "minute":"30"}],
                                              "ftpServerSettingsKey":""}}
        return ftp_data

    def get_guest_pass_template(self):
        guest_pass={"loginName":"guest",
                     "userNamePrefix":"guest",
                     "passwordExpirationUnit":1,
                     "timeInterval":"DAY",
                     "multipleGuest":2,
                     "autoGeneratePassword":"true",
                     "comment":"",
                     "allowSession":False}
        return guest_pass

    def get_hotspot_template_data(self):
        """dictionary used to create and update the hotspot profile
        """
        hotspot_data = {"name":"Auto-hegde",
                        "description":"",
                        "guestUser":"0",
                        "key":"",
                        "bridgeMode":1,
                        "smartClientMode":"none",
                        "spMode":"INTERNAL",
                        "secondRedirect":"user",
                        "sessionTime":1440,
                        "gracePeriod":60,
                        #"aaaId":"22222222-2222-2222-2222-222222222222",
                        #"acctId":"",
                        #"acctUpdateInterval":10,
                        "wisperLocationId":"",
                        "wisperLocationName":"",
                        "walledGarden":",",
                        "redirectUrl":"",
                        "smartClientInfo":""}
        return hotspot_data
    def get_thirdparty_apzone(self):

        thirdparty_apzone_data = {"key":"",
                                  "zoneIntId":"",
                                  "zoneName":"TEST-hegde",
                                  "description":"",
                                  "accessNetworkType":"QinQL2",
                                  "coreNetworkType":"TTGPDG",
                                  "authType":"x8021",
                                  "networkTrafficPackageId":"",
                                  "domainUUID":"",
                                  #"authServiceProfileId":"98fc0b90-6c82-11e3-a4b9-24c9a13ec370",
                                  #"acctServiceProfileId":"a8bd1880-6c82-11e3-a4b9-24c9a13ec370",
                                  "subscriberPackageId":"",
                                  #"forwardingServiceProfileId":"bea0bbc0-6c82-11e3-a4b9-24c9a13ec370",
                                  "vlanMappingType":"StripSPreserveC",
                                  "coreAddFixedVlan":"",
                                  "coreAddFixedSVlan":"",
                                  "coreQinQEnabled":False,
                                  #"qinqVLANTagList":[],
                                  "defaultShareSecret":"12345678",
                                  "ipType":"Single IP",
                                  "ip":"1.2.3.4",
                                  "secret":"12345678",
                                  "acctTTGSessionEnabled":False}
        return thirdparty_apzone_data
    def get_third_party_apzone_update(self):
        thirdparty_apzone_data = {"key":"",
                                  "zoneIntId":"",
                                  "zoneName":"TEST-hegde",
                                  "description":"",
                                  "accessNetworkType":"QinQL2",
                                  "coreNetworkType":"TTGPDG",
                                  "authType":"x8021",
                                  "networkTrafficPackageId":"",
                                  "subscriberPackageId":"",
                                  "vlanMappingType":"",
                                  "coreAddFixedVlan":"",
                                  "coreAddFixedSVlan":"",
                                  "coreQinQEnabled":False,
                                  "qinqVLANTagList":[],
                                  "defaultShareSecret":"",
                                  "ipType":"",
                                  "ip":"",
                                  "secret":"",
                                  "acctTTGSessionEnabled":False}
        return thirdparty_apzone_data
        """
                                  "clientAddressList":[{"ipType":"SingleIP",
                                                        "startIP":"",
                                                        "endIP":"",
                                                        "network":"",
                                                        "subnet":"",
                                                        "ip":"1.2.3.4",
                                                        "secret":"12345678"}],
                                  "domainUUID":"8b2081d5-9662-40d9-a3db-2a3cf4dde3f7",
                                  "qinqVLANTagList":[{"startCVlan":"6",
                                                      "endCVlan":"10",
                                                      "startSVlan":"1",
                                                      "endSVlan":"5"}]}
                                  """
    def get_ftp_template_data(self):
        ftp_data = {"key":"",
                    "ftpName":"BORA",
                    "ftpHost":"1.2.3.4",
                    "ftpPort":"22",
                    "ftpUserName":"ruckus",
                    "ftpPassword":"ruckus1!",
                    "ftpRemoteDirectory":""}
        return ftp_data
    def authentication_data(self):
        data_auth = dict(key = "",
                    tenantId = "",
                    name = "Auto_auth_profile",
                    description = "Automation",
                    gppSuppportEnabled = False,
                    aaaSuppportEnabled = False,
                    noRealmDefaultMapping = {"realm":"norealm",
                                             "authServiceId":None,
                                             "authorizationMethod":"NonGPPCallFlow",
                                             "authServiceType":"NA",
                                             "noRealmDefault":True,
                                             "noMatchingDefault":False,
                                             "dynamicVlanId":765},
                    noMatchingDefaultMapping = {"realm":"norealm",
                                                "authServiceId":None,
                                                "authorizationMethod":"NonGPPCallFlow",
                                                "authServiceType":"NA",
                                                "noRealmDefault":False,
                                                "noMatchingDefault":True,
                                                "dynamicVlanId":765},
                    nonDefaultRealmMappings = [],
                   )

        return data_auth

    def get_hlr_template_data(self):

        #new_hlr_data = {"key":"","tenantUUID":"","type":"HLR",
        new_hlr_data = {"key":"","tenantId":"","type":"HLR",
                        "name":"ww","description":"11","sgsnIsdnAddress":"121213121111",
                        "routingContext":3,"localPointCode":1,"localNetworkIndicator":"international",
                        "defaultPointCodeFormat":"integer","eapSimMapVer":"version3","authMapVer":"version3",
                        "srcGtIndicator":"global_title_includes_translation_type_only",
                        "hasSrcPointCode":"true",
                        "srcTransType":40,"srcNumberingPlan":"isdn_telephony_numbering_plan",
                        "srcNatureOfAddressIndicator":"subscriber_number",
                        "destGtIndicator":"global_title_includes_translation_type_only",
                        "destTransType":40,"destNumberingPlan":"isdn_mobile_numbering_plan",
                        "destNatureOfAddressIndicator":"international_number","gtPointCode":4,
                        "cleanUpTimeHour":"","cleanUpTimeMinute":"","historyTime":"",
                        "maxReuseTimes":"","avCachingEnabled":False,"authorizationCachingEnabled":False,"addressIndicator":"route_on_gt",
                        "groupAttrs" :[{"groupAttr": "*","identityUserRoleId":""}],
                        "sctpAssociationsList":[{"destinationIp":"2.3.2.2","destinationPort":1212,
                                                 "sourcePort":3131,"maxInboundsStreams":30,"maxOutboundsStreams":30,"adjPointCode":"5"}],
                        "sccpGttList":[{"gtDigits":"1111111173625","gtIndicator":"global_title_includes_translation_type_only",
                            "addressIndicator":"route_on_gt","hasPointCode":False,"pointCode":"4","hasSSN":True,
                            "transType":40,"numberingPlan":"isdn_mobile_numbering_plan","natureOfAddressIndicator":"subscriber_number","e164Address":""}]}

        return new_hlr_data
    def get_hlr_template_update(self):
        hlr_data = {"key":"","tenantUUID":"",
                        "name":"ww","description":"11","sgsnIsdnAddress":"121213121111",
                        "routingContext":3,"localPointCode":1,"localNetworkIndicator":"international",
                        "defaultPointCodeFormat":"integer","eapSimMapVer":"version3","authMapVer":"version3",
                        "srcGtIndicator":"global_title_includes_translation_type_only",
                        "hasSrcPointCode":"true",
                        "srcTransType":40,"srcNumberingPlan":"isdn_telephony_numbering_plan",
                        "srcNatureOfAddressIndicator":"subscriber_number",
                        "destGtIndicator":"global_title_includes_translation_type_only",
                        "destTransType":40,"destNumberingPlan":"isdn_mobile_numbering_plan",
                        "destNatureOfAddressIndicator":"international_number","gtPointCode":4,
                        "cleanUpTimeHour":"","cleanUpTimeMinute":"","historyTime":"",
                        "maxReuseTimes":"","avCachingEnabled":False,"authorizationCachingEnabled":False,
                        "sctpAssociationsList":[],
                        "sccpGttList":[]}
        return hlr_data
    def accounting_data(self):
        data_acct =dict(key = "",
                    tenantId = "",
                    name = "",
                    description = "",
                    noRealmDefaultMapping = {"realm":"norealm",
                                             "acctServiceId":"",
                                             "acctServiceType":"",
                                             "noRealmDefault":True,
                                             "noMatchingDefault":False},
                    noMatchingDefaultMapping = {"realm":"norealm",
                                                "acctServiceId":"key",
                                                "acctServiceType":"",
                                                "noRealmDefault":False,"noMatchingDefault":True},
                    nonDefaultRealmMappings = [],
                   )
        return data_acct

    def accounting_data_update(self):
        data_acct = dict(key = "",
                    tenantId = "",
                    name = "",
                    description = "",
                    noRealmDefaultMapping = {"realm":"norealm",
                                             "acctServiceId":"",
                                             "acctServiceType":"",
                                             "noRealmDefault":True,
                                             "noMatchingDefault":False},
                    noMatchingDefaultMapping = {"realm":"norealm",
                                                "acctServiceId":"",
                                                "acctServiceType":"",
                                                "noRealmDefault":False,
                                                "noMatchingDefault":True},
                    nonDefaultRealmMappings = [] )
        return data_acct

    def zone_data(self):
        zone_data = {"zoneDescription":"","zoneName":"Auto-1-hegde","fwVersion":"2.5.0.0.341","domainUUID":"8b2081d5-9662-40d9-a3db-2a3cf4dde3f7","tunnelType":0,"tunnelProfileUUID":"77a20d60-43bf-494c-a6ff-daae10aebce4","commonConfig":{"_allowIndoorChannel":0,"apLogin":"ruckus","apPass":"testing123","countryCode":"US","wifi0BgScan":0,"wifi0BgScanTimer":20,"wifi0Channel":0,"wifi0ChannelWidth":"20MHz","wifi0TxPower":"max","wifi1BgScan":0,"wifi1BgScanTimer":20,"wifi1Channel":0,"_wifi1Channel_indoor":0,"wifi1ChannelWidth":"40MHz","wifi1TxPower":"max","syslogIp":"","syslogPort":514,"syslogFacility":-1,"syslogRLevel":3,"wifi0RoamEnable":1,"wifi1RoamEnable":1,"smartRoamDisconnect":0,"smartMonEnable":0,"wifi0ClbEnable":0,"wifi1ClbEnable":0,"wifi0WeakBypass":"","wifi1WeakBypass":"","wifi0HeadRoom":"","wifi1HeadRoom":""},"tunnelConfig":{"_tunnelType":1,"tunnelEncryption":0},"modelConfig":{"_ZF2741_wifi0ExtAnt":0,"_ZF2741_wifi0ExtAntGain":5,"_ZF2741__lanPortCount":1,"_ZF2741_eth0State":1,"_ZF2741_eth0Type":1,"_ZF2741_eth0UntagId":1,"_ZF2741_eth0VlanMembers":"1-4094","_ZF2741_eth0Role":0,"_ZF2741__authId":"","_ZF2741__acctId":"","_ZF2741__MacBypass":0,"_ZF2741__supplicantType":"mac","_ZF2741__SpUsername":"","_ZF2741__SpPassword":"","_ZF2741_LLDPEnable":0,"_ZF2741_LLDPAdInterval":30,"_ZF2741_LLDPHoldTime":120,"_ZF2741_LLDPMgmtEnable":0,"_ZF2942_eth0State":1,"_ZF2942__lanPortCount":2,"_ZF2942_eth0Type":1,"_ZF2942_eth0UntagId":1,"_ZF2942_eth0VlanMembers":"1-4094","_ZF2942_eth0Role":0,"_ZF2942_eth1State":1,"_ZF2942_eth1Type":1,"_ZF2942_eth1UntagId":1,"_ZF2942_eth1VlanMembers":"1-4094","_ZF2942_eth1Role":0,"_ZF2942_wifi0ExtAnt":0,"_ZF2942_wifi0ExtAntGain":5,"_ZF2942__authId":"","_ZF2942__acctId":"","_ZF2942__MacBypass":0,"_ZF2942__supplicantType":"mac","_ZF2942__SpUsername":"","_ZF2942__SpPassword":"","_ZF2942_LLDPEnable":0,"_ZF2942_LLDPAdInterval":30,"_ZF2942_LLDPHoldTime":120,"_ZF2942_LLDPMgmtEnable":0,"_ZF7025_ledStatus":1,"_ZF7025__lanPortCount":5,"_ZF7025_eth0State":1,"_ZF7025_eth0Type":0,"_ZF7025_eth0UntagId":1,"_ZF7025_eth0VlanMembers":"1-4094","_ZF7025_eth0Role":0,"_ZF7025_eth1State":1,"_ZF7025_eth1Type":0,"_ZF7025_eth1UntagId":1,"_ZF7025_eth1VlanMembers":"1-4094","_ZF7025_eth1Role":0,"_ZF7025_eth2State":1,"_ZF7025_eth2Type":0,"_ZF7025_eth2UntagId":1,"_ZF7025_eth2VlanMembers":"1-4094","_ZF7025_eth2Role":0,"_ZF7025_eth3State":1,"_ZF7025_eth3Type":0,"_ZF7025_eth3UntagId":1,"_ZF7025_eth3VlanMembers":"1-4094","_ZF7025_eth3Role":0,"_ZF7025_eth4State":1,"_ZF7025_eth4Type":1,"_ZF7025_eth4UntagId":1,"_ZF7025_eth4VlanMembers":"1-4094","_ZF7025_eth4Role":0,"_ZF7025__authId":"","_ZF7025__acctId":"","_ZF7025__MacBypass":0,"_ZF7025__supplicantType":"mac","_ZF7025__SpUsername":"","_ZF7025__SpPassword":"","_ZF7025_LLDPEnable":0,"_ZF7025_LLDPAdInterval":30,"_ZF7025_LLDPHoldTime":120,"_ZF7025_LLDPMgmtEnable":0,"_ZF7055_ledStatus":1,"_ZF7055__lanPortCount":5,"_ZF7055_eth0State":1,"_ZF7055_eth0Type":0,"_ZF7055_eth0UntagId":1,"_ZF7055_eth0VlanMembers":"1-4094","_ZF7055_eth0Role":0,"_ZF7055_eth1State":1,"_ZF7055_eth1Type":0,"_ZF7055_eth1UntagId":1,"_ZF7055_eth1VlanMembers":"1-4094","_ZF7055_eth1Role":0,"_ZF7055_eth2State":1,"_ZF7055_eth2Type":0,"_ZF7055_eth2UntagId":1,"_ZF7055_eth2VlanMembers":"1-4094","_ZF7055_eth2Role":0,"_ZF7055_eth3State":1,"_ZF7055_eth3Type":0,"_ZF7055_eth3UntagId":1,"_ZF7055_eth3VlanMembers":"1-4094","_ZF7055_eth3Role":0,"_ZF7055_eth4State":1,"_ZF7055_eth4Type":1,"_ZF7055_eth4UntagId":1,"_ZF7055_eth4VlanMembers":"1-4094","_ZF7055_eth4Role":0,"_ZF7055__authId":"","_ZF7055__acctId":"","_ZF7055__MacBypass":0,"_ZF7055__supplicantType":"mac","_ZF7055__SpUsername":"","_ZF7055__SpPassword":"","_ZF7055_LLDPEnable":0,"_ZF7055_LLDPAdInterval":30,"_ZF7055_LLDPHoldTime":120,"_ZF7055_LLDPMgmtEnable":0,"_ZF7321_eth0State":1,"_ZF7321__lanPortCount":1,"_ZF7321_eth0Type":1,"_ZF7321_eth0UntagId":1,"_ZF7321_eth0VlanMembers":"1-4094","_ZF7321_eth0Role":0,"_ZF7321__authId":"","_ZF7321__acctId":"","_ZF7321__MacBypass":0,"_ZF7321__supplicantType":"mac","_ZF7321__SpUsername":"","_ZF7321__SpPassword":"","_ZF7321_ledStatus":1,"_ZF7321_LLDPEnable":0,"_ZF7321_LLDPAdInterval":30,"_ZF7321_LLDPHoldTime":120,"_ZF7321_LLDPMgmtEnable":0,"_ZF7321U_eth0State":1,"_ZF7321U__lanPortCount":1,"_ZF7321U_eth0Type":1,"_ZF7321U_eth0UntagId":1,"_ZF7321U_eth0VlanMembers":"1-4094","_ZF7321U_eth0Role":0,"_ZF7321U__authId":"","_ZF7321U__acctId":"","_ZF7321U__MacBypass":0,"_ZF7321U__supplicantType":"mac","_ZF7321U__SpUsername":"","_ZF7321U__SpPassword":"","_ZF7321U_ledStatus":1,"_ZF7321U_LLDPEnable":0,"_ZF7321U_LLDPAdInterval":30,"_ZF7321U_LLDPHoldTime":120,"_ZF7321U_LLDPMgmtEnable":0,"_ZF7341_ledStatus":1,"_ZF7341_eth0State":1,"_ZF7341__lanPortCount":1,"_ZF7341_eth0Type":1,"_ZF7341_eth0UntagId":1,"_ZF7341_eth0VlanMembers":"1-4094","_ZF7341_eth0Role":0,"_ZF7341__authId":"","_ZF7341__acctId":"","_ZF7341__MacBypass":0,"_ZF7341__supplicantType":"mac","_ZF7341__SpUsername":"","_ZF7341__SpPassword":"","_ZF7341_LLDPEnable":0,"_ZF7341_LLDPAdInterval":30,"_ZF7341_LLDPHoldTime":120,"_ZF7341_LLDPMgmtEnable":0,"_ZF7341U_ledStatus":1,"_ZF7341U_eth0State":1,"_ZF7341U__lanPortCount":1,"_ZF7341U_eth0Type":1,"_ZF7341U_eth0UntagId":1,"_ZF7341U_eth0VlanMembers":"1-4094","_ZF7341U_eth0Role":0,"_ZF7341U__authId":"","_ZF7341U__acctId":"","_ZF7341U__MacBypass":0,"_ZF7341U__supplicantType":"mac","_ZF7341U__SpUsername":"","_ZF7341U__SpPassword":"","_ZF7341U_LLDPEnable":0,"_ZF7341U_LLDPAdInterval":30,"_ZF7341U_LLDPHoldTime":120,"_ZF7341U_LLDPMgmtEnable":0,"_ZF7351U_ledStatus":1,"_ZF7351U_eth0State":1,"_ZF7351U__lanPortCount":1,"_ZF7351U_eth0Type":1,"_ZF7351U_eth0UntagId":1,"_ZF7351U_eth0VlanMembers":"1-4094","_ZF7351U_eth0Role":0,"_ZF7351U__authId":"","_ZF7351U__acctId":"","_ZF7351U__MacBypass":0,"_ZF7351U__supplicantType":"mac","_ZF7351U__SpUsername":"","_ZF7351U__SpPassword":"","_ZF7351U_LLDPEnable":0,"_ZF7351U_LLDPAdInterval":30,"_ZF7351U_LLDPHoldTime":120,"_ZF7351U_LLDPMgmtEnable":0,"_ZF7351_ledStatus":1,"_ZF7351_eth0State":1,"_ZF7351__lanPortCount":1,"_ZF7351_eth0Type":1,"_ZF7351_eth0UntagId":1,"_ZF7351_eth0VlanMembers":"1-4094","_ZF7351_eth0Role":0,"_ZF7351__authId":"","_ZF7351__acctId":"","_ZF7351__MacBypass":0,"_ZF7351__supplicantType":"mac","_ZF7351__SpUsername":"","_ZF7351__SpPassword":"","_ZF7351_LLDPEnable":0,"_ZF7351_LLDPAdInterval":30,"_ZF7351_LLDPHoldTime":120,"_ZF7351_LLDPMgmtEnable":0,"_ZF7343_ledStatus":1,"_ZF7343_eth0State":1,"_ZF7343__lanPortCount":3,"_ZF7343_eth0Type":1,"_ZF7343_eth0UntagId":1,"_ZF7343_eth0VlanMembers":"1-4094","_ZF7343_eth0Role":0,"_ZF7343_eth1State":1,"_ZF7343_eth1Type":1,"_ZF7343_eth1UntagId":1,"_ZF7343_eth1VlanMembers":"1-4094","_ZF7343_eth1Role":0,"_ZF7343_eth2State":1,"_ZF7343_eth2Type":1,"_ZF7343_eth2UntagId":1,"_ZF7343_eth2VlanMembers":"1-4094","_ZF7343_eth2Role":0,"_ZF7343__authId":"","_ZF7343__acctId":"","_ZF7343__MacBypass":0,"_ZF7343__supplicantType":"mac","_ZF7343__SpUsername":"","_ZF7343__SpPassword":"","_ZF7343_LLDPEnable":0,"_ZF7343_LLDPAdInterval":30,"_ZF7343_LLDPHoldTime":120,"_ZF7343_LLDPMgmtEnable":0,"_ZF7343U_ledStatus":1,"_ZF7343U_eth0State":1,"_ZF7343U__lanPortCount":3,"_ZF7343U_eth0Type":1,"_ZF7343U_eth0UntagId":1,"_ZF7343U_eth0VlanMembers":"1-4094","_ZF7343U_eth0Role":0,"_ZF7343U_eth1State":1,"_ZF7343U_eth1Type":1,"_ZF7343U_eth1UntagId":1,"_ZF7343U_eth1VlanMembers":"1-4094","_ZF7343U_eth1Role":0,"_ZF7343U_eth2State":1,"_ZF7343U_eth2Type":1,"_ZF7343U_eth2UntagId":1,"_ZF7343U_eth2VlanMembers":"1-4094","_ZF7343U_eth2Role":0,"_ZF7343U__authId":"","_ZF7343U__acctId":"","_ZF7343U__MacBypass":0,"_ZF7343U__supplicantType":"mac","_ZF7343U__SpUsername":"","_ZF7343U__SpPassword":"","_ZF7343U_LLDPEnable":0,"_ZF7343U_LLDPAdInterval":30,"_ZF7343U_LLDPHoldTime":120,"_ZF7343U_LLDPMgmtEnable":0,"_ZF7363_ledStatus":1,"_ZF7363_eth0State":1,"_ZF7363__lanPortCount":3,"_ZF7363_eth0Type":1,"_ZF7363_eth0UntagId":1,"_ZF7363_eth0VlanMembers":"1-4094","_ZF7363_eth0Role":0,"_ZF7363_eth1State":1,"_ZF7363_eth1Type":1,"_ZF7363_eth1UntagId":1,"_ZF7363_eth1VlanMembers":"1-4094","_ZF7363_eth1Role":0,"_ZF7363_eth2State":1,"_ZF7363_eth2Type":1,"_ZF7363_eth2UntagId":1,"_ZF7363_eth2VlanMembers":"1-4094","_ZF7363_eth2Role":0,"_ZF7363__authId":"","_ZF7363__acctId":"","_ZF7363__MacBypass":0,"_ZF7363__supplicantType":"mac","_ZF7363__SpUsername":"","_ZF7363__SpPassword":"","_ZF7363_LLDPEnable":0,"_ZF7363_LLDPAdInterval":30,"_ZF7363_LLDPHoldTime":120,"_ZF7363_LLDPMgmtEnable":0,"_ZF7363U_ledStatus":1,"_ZF7363U_eth0State":1,"_ZF7363U__lanPortCount":3,"_ZF7363U_eth0Type":1,"_ZF7363U_eth0UntagId":1,"_ZF7363U_eth0VlanMembers":"1-4094","_ZF7363U_eth0Role":0,"_ZF7363U_eth1State":1,"_ZF7363U_eth1Type":1,"_ZF7363U_eth1UntagId":1,"_ZF7363U_eth1VlanMembers":"1-4094","_ZF7363U_eth1Role":0,"_ZF7363U_eth2State":1,"_ZF7363U_eth2Type":1,"_ZF7363U_eth2UntagId":1,"_ZF7363U_eth2VlanMembers":"1-4094","_ZF7363U_eth2Role":0,"_ZF7363U__authId":"","_ZF7363U__acctId":"","_ZF7363U__MacBypass":0,"_ZF7363U__supplicantType":"mac","_ZF7363U__SpUsername":"","_ZF7363U__SpPassword":"","_ZF7363U_LLDPEnable":0,"_ZF7363U_LLDPAdInterval":30,"_ZF7363U_LLDPHoldTime":120,"_ZF7363U_LLDPMgmtEnable":0,"_ZF7762_internalHeater":0,"_ZF7762_poeOutPort":0,"_ZF7762_ledStatus":1,"_ZF7762_wifi1ExtAnt":0,"_ZF7762_wifi1ExtAntGain":5,"_ZF7762_eth0State":1,"_ZF7762__lanPortCount":2,"_ZF7762_eth0Type":1,"_ZF7762_eth0UntagId":1,"_ZF7762_eth0VlanMembers":"1-4094","_ZF7762_eth0Role":0,"_ZF7762_eth1State":1,"_ZF7762_eth1Type":1,"_ZF7762_eth1UntagId":1,"_ZF7762_eth1VlanMembers":"1-4094","_ZF7762_eth1Role":0,"_ZF7762__authId":"","_ZF7762__acctId":"","_ZF7762__MacBypass":0,"_ZF7762__supplicantType":"mac","_ZF7762__SpUsername":"","_ZF7762__SpPassword":"","_ZF7762_LLDPEnable":0,"_ZF7762_LLDPAdInterval":30,"_ZF7762_LLDPHoldTime":120,"_ZF7762_LLDPMgmtEnable":0,"_ZF7762S_internalHeater":0,"_ZF7762S_poeOutPort":0,"_ZF7762S_ledStatus":1,"_ZF7762S_wifi1ExtAnt":1,"_ZF7762S_wifi1ExtAntGain":5,"_ZF7762S_eth0State":1,"_ZF7762S__lanPortCount":2,"_ZF7762S_eth0Type":1,"_ZF7762S_eth0UntagId":1,"_ZF7762S_eth0VlanMembers":"1-4094","_ZF7762S_eth0Role":0,"_ZF7762S_eth1State":1,"_ZF7762S_eth1Type":1,"_ZF7762S_eth1UntagId":1,"_ZF7762S_eth1VlanMembers":"1-4094","_ZF7762S_eth1Role":0,"_ZF7762S__authId":"","_ZF7762S__acctId":"","_ZF7762S__MacBypass":0,"_ZF7762S__supplicantType":"mac","_ZF7762S__SpUsername":"","_ZF7762S__SpPassword":"","_ZF7762S_LLDPEnable":0,"_ZF7762S_LLDPAdInterval":30,"_ZF7762S_LLDPHoldTime":120,"_ZF7762S_LLDPMgmtEnable":0,"_ZF7762T_internalHeater":0,"_ZF7762T_poeOutPort":0,"_ZF7762T_ledStatus":1,"_ZF7762T_eth0State":1,"_ZF7762T__lanPortCount":2,"_ZF7762T_wifi1ExtAnt":1,"_ZF7762T_wifi1ExtAntGain":5,"_ZF7762T_eth0Type":1,"_ZF7762T_eth0UntagId":1,"_ZF7762T_eth0VlanMembers":"1-4094","_ZF7762T_eth0Role":0,"_ZF7762T_eth1State":1,"_ZF7762T_eth1Type":1,"_ZF7762T_eth1UntagId":1,"_ZF7762T_eth1VlanMembers":"1-4094","_ZF7762T_eth1Role":0,"_ZF7762T__authId":"","_ZF7762T__acctId":"","_ZF7762T__MacBypass":0,"_ZF7762T__supplicantType":"mac","_ZF7762T__SpUsername":"","_ZF7762T__SpPassword":"","_ZF7762T_LLDPEnable":0,"_ZF7762T_LLDPAdInterval":30,"_ZF7762T_LLDPHoldTime":120,"_ZF7762T_LLDPMgmtEnable":0,"_ZF7762AC_internalHeater":0,"_ZF7762AC_poeOutPort":0,"_ZF7762AC_ledStatus":1,"_ZF7762AC_wifi1ExtAnt":0,"_ZF7762AC_wifi1ExtAntGain":5,"_ZF7762AC_eth0State":1,"_ZF7762AC__lanPortCount":2,"_ZF7762AC_eth0Type":1,"_ZF7762AC_eth0UntagId":1,"_ZF7762AC_eth0VlanMembers":"1-4094","_ZF7762AC_eth0Role":0,"_ZF7762AC_eth1State":1,"_ZF7762AC_eth1Type":1,"_ZF7762AC_eth1UntagId":1,"_ZF7762AC_eth1VlanMembers":"1-4094","_ZF7762AC_eth1Role":0,"_ZF7762AC__authId":"","_ZF7762AC__acctId":"","_ZF7762AC__MacBypass":0,"_ZF7762AC__supplicantType":"mac","_ZF7762AC__SpUsername":"","_ZF7762AC__SpPassword":"","_ZF7762AC_LLDPEnable":0,"_ZF7762AC_LLDPAdInterval":30,"_ZF7762AC_LLDPHoldTime":120,"_ZF7762AC_LLDPMgmtEnable":0,"_ZF7762SAC_internalHeater":0,"_ZF7762SAC_poeOutPort":0,"_ZF7762SAC_ledStatus":1,"_ZF7762SAC_wifi1ExtAnt":1,"_ZF7762SAC_wifi1ExtAntGain":5,"_ZF7762SAC_eth0State":1,"_ZF7762SAC__lanPortCount":2,"_ZF7762SAC_eth0Type":1,"_ZF7762SAC_eth0UntagId":1,"_ZF7762SAC_eth0VlanMembers":"1-4094","_ZF7762SAC_eth0Role":0,"_ZF7762SAC_eth1State":1,"_ZF7762SAC_eth1Type":1,"_ZF7762SAC_eth1UntagId":1,"_ZF7762SAC_eth1VlanMembers":"1-4094","_ZF7762SAC_eth1Role":0,"_ZF7762SAC__authId":"","_ZF7762SAC__acctId":"","_ZF7762SAC__MacBypass":0,"_ZF7762SAC__supplicantType":"mac","_ZF7762SAC__SpUsername":"","_ZF7762SAC__SpPassword":"","_ZF7762SAC_LLDPEnable":0,"_ZF7762SAC_LLDPAdInterval":30,"_ZF7762SAC_LLDPHoldTime":120,"_ZF7762SAC_LLDPMgmtEnable":0,"_ZF7761CM_cmLedMode":7,"_ZF7761CM_internalHeater":1,"_ZF7761CM_poeOutPort":1,"_ZF7761CM_ledStatus":1,"_ZF7761CM_wifi1ExtAnt":1,"_ZF7761CM_wifi1ExtAntGain":5,"_ZF7761CM__lanPortCount":2,"_ZF7761CM_eth0State":1,"_ZF7761CM_eth0Type":1,"_ZF7761CM_eth0UntagId":1,"_ZF7761CM_eth0VlanMembers":"1-4094","_ZF7761CM_eth0Role":0,"_ZF7761CM_eth1State":1,"_ZF7761CM_eth1Type":1,"_ZF7761CM_eth1UntagId":1,"_ZF7761CM_eth1VlanMembers":"1-4094","_ZF7761CM_eth1Role":0,"_ZF7761CM__authId":"","_ZF7761CM__acctId":"","_ZF7761CM__MacBypass":0,"_ZF7761CM__supplicantType":"mac","_ZF7761CM__SpUsername":"","_ZF7761CM__SpPassword":"","_ZF7761CM_LLDPEnable":0,"_ZF7761CM_LLDPAdInterval":30,"_ZF7761CM_LLDPHoldTime":120,"_ZF7761CM_LLDPMgmtEnable":0,"_ZF7962_eth0State":1,"_ZF7962__lanPortCount":2,"_ZF7962_eth0Type":1,"_ZF7962_eth0UntagId":1,"_ZF7962_eth0VlanMembers":"1-4094","_ZF7962_eth0Role":0,"_ZF7962_eth1State":1,"_ZF7962_eth1Type":1,"_ZF7962_eth1UntagId":1,"_ZF7962_eth1VlanMembers":"1-4094","_ZF7962_eth1Role":0,"_ZF7962__authId":"","_ZF7962__acctId":"","_ZF7962__MacBypass":0,"_ZF7962__supplicantType":"mac","_ZF7962__SpUsername":"","_ZF7962__SpPassword":"","_ZF7962_LLDPEnable":0,"_ZF7962_LLDPAdInterval":30,"_ZF7962_LLDPHoldTime":120,"_ZF7962_LLDPMgmtEnable":0,"_ZF7982_ledStatus":1,"_ZF7982__lanPortCount":2,"_ZF7982_eth0State":1,"_ZF7982_eth0Type":1,"_ZF7982_eth0UntagId":1,"_ZF7982_eth0VlanMembers":"1-4094","_ZF7982_eth0Role":0,"_ZF7982_eth1State":1,"_ZF7982_eth1Type":1,"_ZF7982_eth1UntagId":1,"_ZF7982_eth1VlanMembers":"1-4094","_ZF7982_eth1Role":0,"_ZF7982__authId":"","_ZF7982__acctId":"","_ZF7982__MacBypass":0,"_ZF7982__supplicantType":"mac","_ZF7982__SpUsername":"","_ZF7982__SpPassword":"","_ZF7982_LLDPEnable":0,"_ZF7982_LLDPAdInterval":30,"_ZF7982_LLDPHoldTime":120,"_ZF7982_LLDPMgmtEnable":0,"_SC8800S__lanPortCount":2,"_SC8800S_poeOutPort":1,"_SC8800S_ledStatus":1,"_SC8800S_wifi0ExtAnt":0,"_SC8800S_wifi0ExtAntGain":6,"_SC8800S_wifi1ExtAnt":0,"_SC8800S_wifi1ExtAntGain":5,"_SC8800S_eth0State":1,"_SC8800S_eth0Type":1,"_SC8800S_eth0UntagId":1,"_SC8800S_eth0VlanMembers":"1-4094","_SC8800S_eth0Role":0,"_SC8800S_eth1State":1,"_SC8800S_eth1Type":1,"_SC8800S_eth1UntagId":1,"_SC8800S_eth1VlanMembers":"1-4094","_SC8800S_eth1Role":0,"_SC8800S__authId":"","_SC8800S__acctId":"","_SC8800S__MacBypass":0,"_SC8800S__supplicantType":"mac","_SC8800S__SpUsername":"","_SC8800S__SpPassword":"","_SC8800S_LLDPEnable":0,"_SC8800S_LLDPAdInterval":30,"_SC8800S_LLDPHoldTime":120,"_SC8800S_LLDPMgmtEnable":0,"_SC8800SAC__lanPortCount":2,"_SC8800SAC_poeOutPort":0,"_SC8800SAC_ledStatus":1,"_SC8800SAC_wifi1ExtAnt":0,"_SC8800SAC_wifi1ExtAntGain":5,"_SC8800SAC_eth0State":1,"_SC8800SAC_eth0Type":1,"_SC8800SAC_eth0UntagId":1,"_SC8800SAC_eth0VlanMembers":"1-4094","_SC8800SAC_eth0Role":0,"_SC8800SAC_eth1State":1,"_SC8800SAC_eth1Type":1,"_SC8800SAC_eth1UntagId":1,"_SC8800SAC_eth1VlanMembers":"1-4094","_SC8800SAC_eth1Role":0,"_SC8800SAC__authId":"","_SC8800SAC__acctId":"","_SC8800SAC__MacBypass":0,"_SC8800SAC__supplicantType":"mac","_SC8800SAC__SpUsername":"","_SC8800SAC__SpPassword":"","_SC8800SAC_LLDPEnable":0,"_SC8800SAC_LLDPAdInterval":30,"_SC8800SAC_LLDPHoldTime":120,"_SC8800SAC_LLDPMgmtEnable":0,"_ZF7782__lanPortCount":2,"_ZF7782_poeOutPort":1,"_ZF7782_ledStatus":1,"_ZF7782_eth0State":1,"_ZF7782_eth0Type":1,"_ZF7782_eth0UntagId":1,"_ZF7782_eth0VlanMembers":"1-4094","_ZF7782_eth0Role":0,"_ZF7782_eth1State":1,"_ZF7782_eth1Type":1,"_ZF7782_eth1UntagId":1,"_ZF7782_eth1VlanMembers":"1-4094","_ZF7782_eth1Role":0,"_ZF7782__authId":"","_ZF7782__acctId":"","_ZF7782__MacBypass":0,"_ZF7782__supplicantType":"mac","_ZF7782__SpUsername":"","_ZF7782__SpPassword":"","_ZF7782_LLDPEnable":0,"_ZF7782_LLDPAdInterval":30,"_ZF7782_LLDPHoldTime":120,"_ZF7782_LLDPMgmtEnable":0,"_ZF7782N__lanPortCount":2,"_ZF7782N_poeOutPort":1,"_ZF7782N_ledStatus":1,"_ZF7782N_eth0State":1,"_ZF7782N_eth0Type":1,"_ZF7782N_eth0UntagId":1,"_ZF7782N_eth0VlanMembers":"1-4094","_ZF7782N_eth0Role":0,"_ZF7782N_eth1State":1,"_ZF7782N_eth1Type":1,"_ZF7782N_eth1UntagId":1,"_ZF7782N_eth1VlanMembers":"1-4094","_ZF7782N_eth1Role":0,"_ZF7782N__authId":"","_ZF7782N__acctId":"","_ZF7782N__MacBypass":0,"_ZF7782N__supplicantType":"mac","_ZF7782N__SpUsername":"","_ZF7782N__SpPassword":"","_ZF7782N_LLDPEnable":0,"_ZF7782N_LLDPAdInterval":30,"_ZF7782N_LLDPHoldTime":120,"_ZF7782N_LLDPMgmtEnable":0,"_ZF7782S__lanPortCount":2,"_ZF7782S_poeOutPort":1,"_ZF7782S_ledStatus":1,"_ZF7782S_eth0State":1,"_ZF7782S_eth0Type":1,"_ZF7782S_eth0UntagId":1,"_ZF7782S_eth0VlanMembers":"1-4094","_ZF7782S_eth0Role":0,"_ZF7782S_eth1State":1,"_ZF7782S_eth1Type":1,"_ZF7782S_eth1UntagId":1,"_ZF7782S_eth1VlanMembers":"1-4094","_ZF7782S_eth1Role":0,"_ZF7782S__authId":"","_ZF7782S__acctId":"","_ZF7782S__MacBypass":0,"_ZF7782S__supplicantType":"mac","_ZF7782S__SpUsername":"","_ZF7782S__SpPassword":"","_ZF7782S_LLDPEnable":0,"_ZF7782S_LLDPAdInterval":30,"_ZF7782S_LLDPHoldTime":120,"_ZF7782S_LLDPMgmtEnable":0,"_ZF7782E__lanPortCount":2,"_ZF7782E_poeOutPort":1,"_ZF7782E_ledStatus":1,"_ZF7782E_wifi0ExtAnt":1,"_ZF7782E_wifi0ExtAntGain":5,"_ZF7782E_wifi0ExtAntChainMask":7,"_ZF7782E_wifi1ExtAnt":1,"_ZF7782E_wifi1ExtAntGain":5,"_ZF7782E_wifi1ExtAntChainMask":7,"_ZF7782E_eth0State":1,"_ZF7782E_eth0Type":1,"_ZF7782E_eth0UntagId":1,"_ZF7782E_eth0VlanMembers":"1-4094","_ZF7782E_eth0Role":0,"_ZF7782E_eth1State":1,"_ZF7782E_eth1Type":1,"_ZF7782E_eth1UntagId":1,"_ZF7782E_eth1VlanMembers":"1-4094","_ZF7782E_eth1Role":0,"_ZF7782E__authId":"","_ZF7782E__acctId":"","_ZF7782E__MacBypass":0,"_ZF7782E__supplicantType":"mac","_ZF7782E__SpUsername":"","_ZF7782E__SpPassword":"","_ZF7782E_LLDPEnable":0,"_ZF7782E_LLDPAdInterval":30,"_ZF7782E_LLDPHoldTime":120,"_ZF7782E_LLDPMgmtEnable":0,"_ZF7781M__lanPortCount":1,"_ZF7781M_wifi0ExtAnt":1,"_ZF7781M_wifi0ExtAntGain":5,"_ZF7781M_wifi1ExtAnt":1,"_ZF7781M_wifi1ExtAntGain":5,"_ZF7781M_eth0State":1,"_ZF7781M_eth0Type":1,"_ZF7781M_eth0UntagId":1,"_ZF7781M_eth0VlanMembers":"1-4094","_ZF7781M_eth0Role":0,"_ZF7781M__authId":"","_ZF7781M__acctId":"","_ZF7781M__MacBypass":0,"_ZF7781M__supplicantType":"mac","_ZF7781M__SpUsername":"","_ZF7781M__SpPassword":"","_ZF7781M_LLDPEnable":0,"_ZF7781M_LLDPAdInterval":30,"_ZF7781M_LLDPHoldTime":120,"_ZF7781M_LLDPMgmtEnable":0,"_ZF7781CM_cmLedMode":7,"_ZF7781CM_internalHeater":1,"_ZF7781CM_poeOutPort":1,"_ZF7781CM_ledStatus":1,"_ZF7781CM__lanPortCount":2,"_ZF7781CM_eth0State":1,"_ZF7781CM_eth0Type":1,"_ZF7781CM_eth0UntagId":1,"_ZF7781CM_eth0VlanMembers":"1-4094","_ZF7781CM_eth0Role":0,"_ZF7781CM_eth1State":1,"_ZF7781CM_eth1Type":1,"_ZF7781CM_eth1UntagId":1,"_ZF7781CM_eth1VlanMembers":"1-4094","_ZF7781CM_eth1Role":0,"_ZF7781CM__authId":"","_ZF7781CM__acctId":"","_ZF7781CM__MacBypass":0,"_ZF7781CM__supplicantType":"mac","_ZF7781CM__SpUsername":"","_ZF7781CM__SpPassword":"","_ZF7781CM_LLDPEnable":0,"_ZF7781CM_LLDPAdInterval":30,"_ZF7781CM_LLDPHoldTime":120,"_ZF7781CM_LLDPMgmtEnable":0,"_ZF7781FN_poeOutPort":1,"_ZF7781FN_ledStatus":1,"_ZF7781FN_eth0State":1,"_ZF7781FN__lanPortCount":1,"_ZF7781FN_eth0Type":1,"_ZF7781FN_eth0UntagId":1,"_ZF7781FN_eth0VlanMembers":"1-4094","_ZF7781FN_eth0Role":0,"_ZF7781FN_eth1State":1,"_ZF7781FN_eth1Type":1,"_ZF7781FN_eth1UntagId":1,"_ZF7781FN_eth1VlanMembers":"1-4094","_ZF7781FN_eth1Role":0,"_ZF7781FN__authId":"","_ZF7781FN__acctId":"","_ZF7781FN__MacBypass":0,"_ZF7781FN__supplicantType":"mac","_ZF7781FN__SpUsername":"","_ZF7781FN__SpPassword":"","_ZF7781FN_LLDPEnable":0,"_ZF7781FN_LLDPAdInterval":30,"_ZF7781FN_LLDPHoldTime":120,"_ZF7781FN_LLDPMgmtEnable":0,"_ZF7781FNS_poeOutPort":1,"_ZF7781FNS_ledStatus":1,"_ZF7781FNS_eth0State":1,"_ZF7781FNS__lanPortCount":1,"_ZF7781FNS_eth0Type":1,"_ZF7781FNS_eth0UntagId":1,"_ZF7781FNS_eth0VlanMembers":"1-4094","_ZF7781FNS_eth0Role":0,"_ZF7781FNS_eth1State":1,"_ZF7781FNS_eth1Type":1,"_ZF7781FNS_eth1UntagId":1,"_ZF7781FNS_eth1VlanMembers":"1-4094","_ZF7781FNS_eth1Role":0,"_ZF7781FNS__authId":"","_ZF7781FNS__acctId":"","_ZF7781FNS__MacBypass":0,"_ZF7781FNS__supplicantType":"mac","_ZF7781FNS__SpUsername":"","_ZF7781FNS__SpPassword":"","_ZF7781FNS_LLDPEnable":0,"_ZF7781FNS_LLDPAdInterval":30,"_ZF7781FNS_LLDPHoldTime":120,"_ZF7781FNS_LLDPMgmtEnable":0,"_ZF7781FNE_poeOutPort":1,"_ZF7781FNE_ledStatus":1,"_ZF7781FNE_wifi0ExtAnt":1,"_ZF7781FNE_wifi0ExtAntGain":5,"_ZF7781FNE_wifi0ExtAntChainMask":7,"_ZF7781FNE_wifi1ExtAnt":1,"_ZF7781FNE_wifi1ExtAntGain":5,"_ZF7781FNE_wifi1ExtAntChainMask":7,"_ZF7781FNE_eth0State":1,"_ZF7781FNE__lanPortCount":1,"_ZF7781FNE_eth0Type":1,"_ZF7781FNE_eth0UntagId":1,"_ZF7781FNE_eth0VlanMembers":"1-4094","_ZF7781FNE_eth0Role":0,"_ZF7781FNE_eth1State":1,"_ZF7781FNE_eth1Type":1,"_ZF7781FNE_eth1UntagId":1,"_ZF7781FNE_eth1VlanMembers":"1-4094","_ZF7781FNE_eth1Role":0,"_ZF7781FNE__authId":"","_ZF7781FNE__acctId":"","_ZF7781FNE__MacBypass":0,"_ZF7781FNE__supplicantType":"mac","_ZF7781FNE__SpUsername":"","_ZF7781FNE__SpPassword":"","_ZF7781FNE_LLDPEnable":0,"_ZF7781FNE_LLDPAdInterval":30,"_ZF7781FNE_LLDPHoldTime":120,"_ZF7781FNE_LLDPMgmtEnable":0,"_ZF7352_eth0State":1,"_ZF7352__lanPortCount":2,"_ZF7352_eth0Type":1,"_ZF7352_eth0UntagId":1,"_ZF7352_eth0VlanMembers":"1-4094","_ZF7352_eth0Role":0,"_ZF7352_eth1State":1,"_ZF7352_eth1Type":1,"_ZF7352_eth1UntagId":1,"_ZF7352_eth1VlanMembers":"1-4094","_ZF7352_eth1Role":0,"_ZF7352__authId":"","_ZF7352__acctId":"","_ZF7352__MacBypass":0,"_ZF7352__supplicantType":"mac","_ZF7352__SpUsername":"","_ZF7352__SpPassword":"","_ZF7352_ledStatus":1,"_ZF7352_LLDPEnable":0,"_ZF7352_LLDPAdInterval":30,"_ZF7352_LLDPHoldTime":120,"_ZF7352_LLDPMgmtEnable":0,"_ZF7352U_eth0State":1,"_ZF7352U__lanPortCount":2,"_ZF7352U_eth0Type":1,"_ZF7352U_eth0UntagId":1,"_ZF7352U_eth0VlanMembers":"1-4094","_ZF7352U_eth0Role":0,"_ZF7352U_eth1State":1,"_ZF7352U_eth1Type":1,"_ZF7352U_eth1UntagId":1,"_ZF7352U_eth1VlanMembers":"1-4094","_ZF7352U_eth1Role":0,"_ZF7352U__authId":"","_ZF7352U__acctId":"","_ZF7352U__MacBypass":0,"_ZF7352U__supplicantType":"mac","_ZF7352U__SpUsername":"","_ZF7352U__SpPassword":"","_ZF7352U_ledStatus":1,"_ZF7352U_LLDPEnable":0,"_ZF7352U_LLDPAdInterval":30,"_ZF7352U_LLDPHoldTime":120,"_ZF7352U_LLDPMgmtEnable":0,"_ZF7372_eth0State":1,"_ZF7372__lanPortCount":2,"_ZF7372_eth0Type":1,"_ZF7372_eth0UntagId":1,"_ZF7372_eth0VlanMembers":"1-4094","_ZF7372_eth0Role":0,"_ZF7372_eth1State":1,"_ZF7372_eth1Type":1,"_ZF7372_eth1UntagId":1,"_ZF7372_eth1VlanMembers":"1-4094","_ZF7372_eth1Role":0,"_ZF7372__authId":"","_ZF7372__acctId":"","_ZF7372__MacBypass":0,"_ZF7372__supplicantType":"mac","_ZF7372__SpUsername":"","_ZF7372__SpPassword":"","_ZF7372_ledStatus":1,"_ZF7372_LLDPEnable":0,"_ZF7372_LLDPAdInterval":30,"_ZF7372_LLDPHoldTime":120,"_ZF7372_LLDPMgmtEnable":0,"_ZF7372U_eth0State":1,"_ZF7372U__lanPortCount":2,"_ZF7372U_eth0Type":1,"_ZF7372U_eth0UntagId":1,"_ZF7372U_eth0VlanMembers":"1-4094","_ZF7372U_eth0Role":0,"_ZF7372U_eth1State":1,"_ZF7372U_eth1Type":1,"_ZF7372U_eth1UntagId":1,"_ZF7372U_eth1VlanMembers":"1-4094","_ZF7372U_eth1Role":0,"_ZF7372U__authId":"","_ZF7372U__acctId":"","_ZF7372U__MacBypass":0,"_ZF7372U__supplicantType":"mac","_ZF7372U__SpUsername":"","_ZF7372U__SpPassword":"","_ZF7372U_ledStatus":1,"_ZF7372U_LLDPEnable":0,"_ZF7372U_LLDPAdInterval":30,"_ZF7372U_LLDPHoldTime":120,"_ZF7372U_LLDPMgmtEnable":0,"_ZF7372E_ledStatus":1,"_ZF7372E_wifi0ExtAnt":1,"_ZF7372E_wifi0ExtAntGain":2,"_ZF7372E_wifi1ExtAnt":1,"_ZF7372E_wifi1ExtAntGain":3,"_ZF7372E_eth0State":1,"_ZF7372E__lanPortCount":2,"_ZF7372E_eth0Type":1,"_ZF7372E_eth0UntagId":1,"_ZF7372E_eth0VlanMembers":"1-4094","_ZF7372E_eth0Role":0,"_ZF7372E_eth1State":1,"_ZF7372E_eth1Type":1,"_ZF7372E_eth1UntagId":1,"_ZF7372E_eth1VlanMembers":"1-4094","_ZF7372E_eth1Role":0,"_ZF7372E__authId":"","_ZF7372E__acctId":"","_ZF7372E__MacBypass":0,"_ZF7372E__supplicantType":"mac","_ZF7372E__SpUsername":"","_ZF7372E__SpPassword":"","_ZF7372E_LLDPEnable":0,"_ZF7372E_LLDPAdInterval":30,"_ZF7372E_LLDPHoldTime":120,"_ZF7372E_LLDPMgmtEnable":0,"_ZF7441_ledStatus":1,"_ZF7441_wifi0ExtAnt":1,"_ZF7441_wifi0ExtAntGain":5,"_ZF7441_eth0State":1,"_ZF7441__lanPortCount":1,"_ZF7441_eth0Type":1,"_ZF7441_eth0UntagId":1,"_ZF7441_eth0VlanMembers":"1-4094","_ZF7441_eth0Role":0,"_ZF7441__authId":"","_ZF7441__acctId":"","_ZF7441__MacBypass":0,"_ZF7441__supplicantType":"mac","_ZF7441__SpUsername":"","_ZF7441__SpPassword":"","_ZF7441_LLDPEnable":0,"_ZF7441_LLDPAdInterval":30,"_ZF7441_LLDPHoldTime":120,"_ZF7441_LLDPMgmtEnable":0,"_R300_ledStatus":1,"_R300__lanPortCount":1,"_R300_eth0State":1,"_R300_eth0Type":1,"_R300_eth0UntagId":1,"_R300_eth0VlanMembers":"1-4094","_R300_eth0Role":0,"_R300__authId":"","_R300__acctId":"","_R300__MacBypass":0,"_R300__supplicantType":"mac","_R300__SpUsername":"","_R300__SpPassword":"","_R300_LLDPEnable":0,"_R300_LLDPAdInterval":30,"_R300_LLDPHoldTime":120,"_R300_LLDPMgmtEnable":0}}
        return zone_data
    def get_zone_data_update(self):
        #zone_data = {"zoneDescription":None,"zoneName":None,"fwVersion":None,"tunnelType":None,"tunnelProfileUUID":None,"commonConfig":{"_allowIndoorChannel":None,"apLogin":None,"apPass":None,"countryCode":"US","wifi0BgScan":None,"wifi0Channel":None,"wifi0ChannelWidth":None,"wifi0TxPower":"max","wifi1BgScan":0,"wifi1Channel":0,"_wifi1Channel_indoor":0,"wifi1ChannelWidth":None,"wifi1TxPower":None,"syslogIp":None,"syslogPort":None,"syslogFacility":-1,"syslogRLevel":3,"wifi0RoamEnable":1,"wifi1RoamEnable":1,"smartRoamDisconnect":0,"smartMonEnable":0,"smartMonInterval":None,"smartMonThreshold":None,"wifi0WeakBypass":33,"wifi1WeakBypass":35,"wifi0HeadRoom":3,"wifi1HeadRoom":3},"zoneUUID":None,"tunnelConfig":{"_tunnelType":None,"tunnelEncryption":None},"modelConfig":{"_ZF2741__MacBypass":0,"_ZF2741__SpPassword":"","_ZF2741__SpUsername":"","_ZF2741__acctId":"","_ZF2741__authId":"","_ZF2741__lanPortCount":1,"_ZF2741__supplicantType":"mac","_ZF2741_eth0Role":0,"_ZF2741_eth0State":1,"_ZF2741_eth0Type":1,"_ZF2741_eth0UntagId":1,"_ZF2741_eth0VlanMembers":"1-4094","_ZF2741_wifi0ExtAnt":0,"_ZF2741_wifi0ExtAntGain":5,"_ZF2741_LLDPEnable":0,"_ZF2741_LLDPAdInterval":30,"_ZF2741_LLDPHoldTime":120,"_ZF2741_LLDPMgmtEnable":0,"_ZF2942__MacBypass":0,"_ZF2942__SpPassword":"","_ZF2942__SpUsername":"","_ZF2942__acctId":"","_ZF2942__authId":"","_ZF2942__lanPortCount":2,"_ZF2942__supplicantType":"mac","_ZF2942_eth0Role":0,"_ZF2942_eth0State":1,"_ZF2942_eth0Type":1,"_ZF2942_eth0UntagId":1,"_ZF2942_eth0VlanMembers":"1-4094","_ZF2942_eth1Role":0,"_ZF2942_eth1State":1,"_ZF2942_eth1Type":1,"_ZF2942_eth1UntagId":1,"_ZF2942_eth1VlanMembers":"1-4094","_ZF2942_wifi0ExtAnt":0,"_ZF2942_wifi0ExtAntGain":5,"_ZF2942_LLDPEnable":0,"_ZF2942_LLDPAdInterval":30,"_ZF2942_LLDPHoldTime":120,"_ZF2942_LLDPMgmtEnable":0,"_ZF7025__MacBypass":0,"_ZF7025__SpPassword":"","_ZF7025__SpUsername":"","_ZF7025__acctId":"","_ZF7025__authId":"","_ZF7025_ledStatus":1,"_ZF7025__lanPortCount":5,"_ZF7025__supplicantType":"mac","_ZF7025_eth0Role":0,"_ZF7025_eth0State":1,"_ZF7025_eth0Type":0,"_ZF7025_eth0UntagId":1,"_ZF7025_eth0VlanMembers":"1-4094","_ZF7025_eth1Role":0,"_ZF7025_eth1State":1,"_ZF7025_eth1Type":0,"_ZF7025_eth1UntagId":1,"_ZF7025_eth1VlanMembers":"1-4094","_ZF7025_eth2Role":0,"_ZF7025_eth2State":1,"_ZF7025_eth2Type":0,"_ZF7025_eth2UntagId":1,"_ZF7025_eth2VlanMembers":"1-4094","_ZF7025_eth3Role":0,"_ZF7025_eth3State":1,"_ZF7025_eth3Type":0,"_ZF7025_eth3UntagId":1,"_ZF7025_eth3VlanMembers":"1-4094","_ZF7025_eth4Role":0,"_ZF7025_eth4State":1,"_ZF7025_eth4Type":1,"_ZF7025_eth4UntagId":1,"_ZF7025_eth4VlanMembers":"1-4094","_ZF7025_LLDPEnable":0,"_ZF7025_LLDPAdInterval":30,"_ZF7025_LLDPHoldTime":120,"_ZF7025_LLDPMgmtEnable":0,"_ZF7055__MacBypass":0,"_ZF7055__SpPassword":"","_ZF7055__SpUsername":"","_ZF7055__acctId":"","_ZF7055__authId":"","_ZF7055_ledStatus":1,"_ZF7055__lanPortCount":5,"_ZF7055__supplicantType":"mac","_ZF7055_eth0Role":0,"_ZF7055_eth0State":1,"_ZF7055_eth0Type":0,"_ZF7055_eth0UntagId":1,"_ZF7055_eth0VlanMembers":"1-4094","_ZF7055_eth1Role":0,"_ZF7055_eth1State":1,"_ZF7055_eth1Type":0,"_ZF7055_eth1UntagId":1,"_ZF7055_eth1VlanMembers":"1-4094","_ZF7055_eth2Role":0,"_ZF7055_eth2State":1,"_ZF7055_eth2Type":0,"_ZF7055_eth2UntagId":1,"_ZF7055_eth2VlanMembers":"1-4094","_ZF7055_eth3Role":0,"_ZF7055_eth3State":1,"_ZF7055_eth3Type":0,"_ZF7055_eth3UntagId":1,"_ZF7055_eth3VlanMembers":"1-4094","_ZF7055_eth4Role":0,"_ZF7055_eth4State":1,"_ZF7055_eth4Type":1,"_ZF7055_eth4UntagId":1,"_ZF7055_eth4VlanMembers":"1-4094","_ZF7055_LLDPEnable":0,"_ZF7055_LLDPAdInterval":30,"_ZF7055_LLDPHoldTime":120,"_ZF7055_LLDPMgmtEnable":0,"_ZF7321__MacBypass":0,"_ZF7321__SpPassword":"","_ZF7321__SpUsername":"","_ZF7321__acctId":"","_ZF7321__authId":"","_ZF7321__lanPortCount":1,"_ZF7321__supplicantType":"mac","_ZF7321_eth0Role":0,"_ZF7321_eth0State":1,"_ZF7321_eth0Type":1,"_ZF7321_eth0UntagId":1,"_ZF7321_eth0VlanMembers":"1-4094","_ZF7321_LLDPEnable":0,"_ZF7321_LLDPAdInterval":30,"_ZF7321_LLDPHoldTime":120,"_ZF7321_LLDPMgmtEnable":0,"_ZF7321_ledStatus":1,"_ZF7321U__MacBypass":0,"_ZF7321U__SpPassword":"","_ZF7321U__SpUsername":"","_ZF7321U__acctId":"","_ZF7321U__authId":"","_ZF7321U__lanPortCount":1,"_ZF7321U__supplicantType":"mac","_ZF7321U_eth0Role":0,"_ZF7321U_eth0State":1,"_ZF7321U_eth0Type":1,"_ZF7321U_eth0UntagId":1,"_ZF7321U_eth0VlanMembers":"1-4094","_ZF7321U_LLDPEnable":0,"_ZF7321U_LLDPAdInterval":30,"_ZF7321U_LLDPHoldTime":120,"_ZF7321U_LLDPMgmtEnable":0,"_ZF7321U_ledStatus":1,"_ZF7341U__MacBypass":0,"_ZF7341U__SpPassword":"","_ZF7341U__SpUsername":"","_ZF7341U__acctId":"","_ZF7341U__authId":"","_ZF7341U__lanPortCount":1,"_ZF7341U_ledStatus":1,"_ZF7341U__supplicantType":"mac","_ZF7341U_eth0Role":0,"_ZF7341U_eth0State":1,"_ZF7341U_eth0Type":1,"_ZF7341U_eth0UntagId":1,"_ZF7341U_eth0VlanMembers":"1-4094","_ZF7341U_LLDPEnable":0,"_ZF7341U_LLDPAdInterval":30,"_ZF7341U_LLDPHoldTime":120,"_ZF7341U_LLDPMgmtEnable":0,"_ZF7341__MacBypass":0,"_ZF7341__SpPassword":"","_ZF7341__SpUsername":"","_ZF7341__acctId":"","_ZF7341__authId":"","_ZF7341__lanPortCount":1,"_ZF7341_ledStatus":1,"_ZF7341__supplicantType":"mac","_ZF7341_eth0Role":0,"_ZF7341_eth0State":1,"_ZF7341_eth0Type":1,"_ZF7341_eth0UntagId":1,"_ZF7341_eth0VlanMembers":"1-4094","_ZF7341_LLDPEnable":0,"_ZF7341_LLDPAdInterval":30,"_ZF7341_LLDPHoldTime":120,"_ZF7341_LLDPMgmtEnable":0,"_ZF7351__MacBypass":0,"_ZF7351__SpPassword":"","_ZF7351__SpUsername":"","_ZF7351__acctId":"","_ZF7351__authId":"","_ZF7351__lanPortCount":1,"_ZF7351_ledStatus":1,"_ZF7351__supplicantType":"mac","_ZF7351_eth0Role":0,"_ZF7351_eth0State":1,"_ZF7351_eth0Type":1,"_ZF7351_eth0UntagId":1,"_ZF7351_eth0VlanMembers":"1-4094","_ZF7351_LLDPEnable":0,"_ZF7351_LLDPAdInterval":30,"_ZF7351_LLDPHoldTime":120,"_ZF7351_LLDPMgmtEnable":0,"_ZF7351U__MacBypass":0,"_ZF7351U__SpPassword":"","_ZF7351U__SpUsername":"","_ZF7351U__acctId":"","_ZF7351U__authId":"","_ZF7351U__lanPortCount":1,"_ZF7351U_ledStatus":1,"_ZF7351U__supplicantType":"mac","_ZF7351U_eth0Role":0,"_ZF7351U_eth0State":1,"_ZF7351U_eth0Type":1,"_ZF7351U_eth0UntagId":1,"_ZF7351U_eth0VlanMembers":"1-4094","_ZF7351U_LLDPEnable":0,"_ZF7351U_LLDPAdInterval":30,"_ZF7351U_LLDPHoldTime":120,"_ZF7351U_LLDPMgmtEnable":0,"_ZF7343U__MacBypass":0,"_ZF7343U__SpPassword":"","_ZF7343U__SpUsername":"","_ZF7343U__acctId":"","_ZF7343U__authId":"","_ZF7343U__lanPortCount":3,"_ZF7343U_ledStatus":1,"_ZF7343U__supplicantType":"mac","_ZF7343U_eth0Role":0,"_ZF7343U_eth0State":1,"_ZF7343U_eth0Type":1,"_ZF7343U_eth0UntagId":1,"_ZF7343U_eth0VlanMembers":"1-4094","_ZF7343U_eth1Role":0,"_ZF7343U_eth1State":1,"_ZF7343U_eth1Type":1,"_ZF7343U_eth1UntagId":1,"_ZF7343U_eth1VlanMembers":"1-4094","_ZF7343U_eth2Role":0,"_ZF7343U_eth2State":1,"_ZF7343U_eth2Type":1,"_ZF7343U_eth2UntagId":1,"_ZF7343U_eth2VlanMembers":"1-4094","_ZF7343U_LLDPEnable":0,"_ZF7343U_LLDPAdInterval":30,"_ZF7343U_LLDPHoldTime":120,"_ZF7343U_LLDPMgmtEnable":0,"_ZF7343__MacBypass":0,"_ZF7343__SpPassword":"","_ZF7343__SpUsername":"","_ZF7343__acctId":"","_ZF7343__authId":"","_ZF7343__lanPortCount":3,"_ZF7343_ledStatus":1,"_ZF7343__supplicantType":"mac","_ZF7343_eth0Role":0,"_ZF7343_eth0State":1,"_ZF7343_eth0Type":1,"_ZF7343_eth0UntagId":1,"_ZF7343_eth0VlanMembers":"1-4094","_ZF7343_eth1Role":0,"_ZF7343_eth1State":1,"_ZF7343_eth1Type":1,"_ZF7343_eth1UntagId":1,"_ZF7343_eth1VlanMembers":"1-4094","_ZF7343_eth2Role":0,"_ZF7343_eth2State":1,"_ZF7343_eth2Type":1,"_ZF7343_eth2UntagId":1,"_ZF7343_eth2VlanMembers":"1-4094","_ZF7343_LLDPEnable":0,"_ZF7343_LLDPAdInterval":30,"_ZF7343_LLDPHoldTime":120,"_ZF7343_LLDPMgmtEnable":0,"_ZF7363U__MacBypass":0,"_ZF7363U__SpPassword":"","_ZF7363U__SpUsername":"","_ZF7363U__acctId":"","_ZF7363U__authId":"","_ZF7363U__lanPortCount":3,"_ZF7363U_ledStatus":1,"_ZF7363U__supplicantType":"mac","_ZF7363U_eth0Role":0,"_ZF7363U_eth0State":1,"_ZF7363U_eth0Type":1,"_ZF7363U_eth0UntagId":1,"_ZF7363U_eth0VlanMembers":"1-4094","_ZF7363U_eth1Role":0,"_ZF7363U_eth1State":1,"_ZF7363U_eth1Type":1,"_ZF7363U_eth1UntagId":1,"_ZF7363U_eth1VlanMembers":"1-4094","_ZF7363U_eth2Role":0,"_ZF7363U_eth2State":1,"_ZF7363U_eth2Type":1,"_ZF7363U_eth2UntagId":1,"_ZF7363U_eth2VlanMembers":"1-4094","_ZF7363U_LLDPEnable":0,"_ZF7363U_LLDPAdInterval":30,"_ZF7363U_LLDPHoldTime":120,"_ZF7363U_LLDPMgmtEnable":0,"_ZF7363__MacBypass":0,"_ZF7363__SpPassword":"","_ZF7363__SpUsername":"","_ZF7363__acctId":"","_ZF7363__authId":"","_ZF7363__lanPortCount":3,"_ZF7363_ledStatus":1,"_ZF7363__supplicantType":"mac","_ZF7363_eth0Role":0,"_ZF7363_eth0State":1,"_ZF7363_eth0Type":1,"_ZF7363_eth0UntagId":1,"_ZF7363_eth0VlanMembers":"1-4094","_ZF7363_eth1Role":0,"_ZF7363_eth1State":1,"_ZF7363_eth1Type":1,"_ZF7363_eth1UntagId":1,"_ZF7363_eth1VlanMembers":"1-4094","_ZF7363_eth2Role":0,"_ZF7363_eth2State":1,"_ZF7363_eth2Type":1,"_ZF7363_eth2UntagId":1,"_ZF7363_eth2VlanMembers":"1-4094","_ZF7363_LLDPEnable":0,"_ZF7363_LLDPAdInterval":30,"_ZF7363_LLDPHoldTime":120,"_ZF7363_LLDPMgmtEnable":0,"_ZF7761CM_wifi1ExtAnt":1,"_ZF7761CM_wifi1ExtAntGain":5,"_ZF7761CM__MacBypass":0,"_ZF7761CM__SpPassword":"","_ZF7761CM__SpUsername":"","_ZF7761CM__acctId":"","_ZF7761CM__authId":"","_ZF7761CM__lanPortCount":2,"_ZF7761CM_ledStatus":1,"_ZF7761CM__supplicantType":"mac","_ZF7761CM_eth0Role":0,"_ZF7761CM_eth0State":1,"_ZF7761CM_eth0Type":1,"_ZF7761CM_eth0UntagId":1,"_ZF7761CM_eth0VlanMembers":"1-4094","_ZF7761CM_eth1Role":0,"_ZF7761CM_eth1State":1,"_ZF7761CM_eth1Type":1,"_ZF7761CM_eth1UntagId":1,"_ZF7761CM_eth1VlanMembers":"1-4094","_ZF7761CM_internalHeater":1,"_ZF7761CM_poeOutPort":1,"_ZF7761CM_cmLedMode":7,"_ZF7761CM_LLDPEnable":0,"_ZF7761CM_LLDPAdInterval":30,"_ZF7761CM_LLDPHoldTime":120,"_ZF7761CM_LLDPMgmtEnable":0,"_ZF7781CM_wifi1ExtAnt":None,"_ZF7781CM_wifi1ExtAntGain":None,"_ZF7781CM__MacBypass":0,"_ZF7781CM__SpPassword":"","_ZF7781CM__SpUsername":"","_ZF7781CM__acctId":"","_ZF7781CM__authId":"","_ZF7781CM__lanPortCount":2,"_ZF7781CM_ledStatus":1,"_ZF7781CM__supplicantType":"mac","_ZF7781CM_eth0Role":0,"_ZF7781CM_eth0State":1,"_ZF7781CM_eth0Type":1,"_ZF7781CM_eth0UntagId":1,"_ZF7781CM_eth0VlanMembers":"1-4094","_ZF7781CM_eth1Role":0,"_ZF7781CM_eth1State":1,"_ZF7781CM_eth1Type":1,"_ZF7781CM_eth1UntagId":1,"_ZF7781CM_eth1VlanMembers":"1-4094","_ZF7781CM_poeOutPort":1,"_ZF7781CM_cmLedMode":7,"_ZF7781CM_LLDPEnable":0,"_ZF7781CM_LLDPAdInterval":30,"_ZF7781CM_LLDPHoldTime":120,"_ZF7781CM_LLDPMgmtEnable":0,"_ZF7781FN_wifi1ExtAnt":None,"_ZF7781FN_wifi1ExtAntGain":None,"_ZF7781FN__MacBypass":0,"_ZF7781FN__SpPassword":"","_ZF7781FN__SpUsername":"","_ZF7781FN__acctId":"","_ZF7781FN__authId":"","_ZF7781FN__lanPortCount":1,"_ZF7781FN_ledStatus":1,"_ZF7781FN__supplicantType":"mac","_ZF7781FN_eth0Role":0,"_ZF7781FN_eth0State":1,"_ZF7781FN_eth0Type":1,"_ZF7781FN_eth0UntagId":1,"_ZF7781FN_eth0VlanMembers":"1-4094","_ZF7781FN_internalHeater":None,"_ZF7781FN_poeOutPort":1,"_ZF7781FN_LLDPEnable":0,"_ZF7781FN_LLDPAdInterval":30,"_ZF7781FN_LLDPHoldTime":120,"_ZF7781FN_LLDPMgmtEnable":0,"_ZF7781FNS_wifi1ExtAnt":None,"_ZF7781FNS_wifi1ExtAntGain":None,"_ZF7781FNS__MacBypass":0,"_ZF7781FNS__SpPassword":"","_ZF7781FNS__SpUsername":"","_ZF7781FNS__acctId":"","_ZF7781FNS__authId":"","_ZF7781FNS__lanPortCount":1,"_ZF7781FNS_ledStatus":1,"_ZF7781FNS__supplicantType":"mac","_ZF7781FNS_eth0Role":0,"_ZF7781FNS_eth0State":1,"_ZF7781FNS_eth0Type":1,"_ZF7781FNS_eth0UntagId":1,"_ZF7781FNS_eth0VlanMembers":"1-4094","_ZF7781FNS_internalHeater":None,"_ZF7781FNS_poeOutPort":1,"_ZF7781FNS_LLDPEnable":0,"_ZF7781FNS_LLDPAdInterval":30,"_ZF7781FNS_LLDPHoldTime":120,"_ZF7781FNS_LLDPMgmtEnable":0,"_ZF7781FNE_wifi0ExtAnt":1,"_ZF7781FNE_wifi0ExtAntGain":5,"_ZF7781FNE_wifi0ExtAntChainMask":7,"_ZF7781FNE_wifi1ExtAnt":1,"_ZF7781FNE_wifi1ExtAntGain":5,"_ZF7781FNE_wifi1ExtAntChainMask":7,"_ZF7781FNE__MacBypass":0,"_ZF7781FNE__SpPassword":"","_ZF7781FNE__SpUsername":"","_ZF7781FNE__acctId":"","_ZF7781FNE__authId":"","_ZF7781FNE__lanPortCount":1,"_ZF7781FNE_ledStatus":1,"_ZF7781FNE__supplicantType":"mac","_ZF7781FNE_eth0Role":0,"_ZF7781FNE_eth0State":1,"_ZF7781FNE_eth0Type":1,"_ZF7781FNE_eth0UntagId":1,"_ZF7781FNE_eth0VlanMembers":"1-4094","_ZF7781FNE_internalHeater":None,"_ZF7781FNE_poeOutPort":1,"_ZF7781FNE_LLDPEnable":0,"_ZF7781FNE_LLDPAdInterval":30,"_ZF7781FNE_LLDPHoldTime":120,"_ZF7781FNE_LLDPMgmtEnable":0,"_ZF7762AC_wifi1ExtAnt":0,"_ZF7762AC_wifi1ExtAntGain":5,"_ZF7762AC__MacBypass":0,"_ZF7762AC__SpPassword":"","_ZF7762AC__SpUsername":"","_ZF7762AC__acctId":"","_ZF7762AC__authId":"","_ZF7762AC__lanPortCount":2,"_ZF7762AC_ledStatus":1,"_ZF7762AC__supplicantType":"mac","_ZF7762AC_eth0Role":0,"_ZF7762AC_eth0State":1,"_ZF7762AC_eth0Type":1,"_ZF7762AC_eth0UntagId":1,"_ZF7762AC_eth0VlanMembers":"1-4094","_ZF7762AC_eth1Role":0,"_ZF7762AC_eth1State":1,"_ZF7762AC_eth1Type":1,"_ZF7762AC_eth1UntagId":1,"_ZF7762AC_eth1VlanMembers":"1-4094","_ZF7762AC_internalHeater":0,"_ZF7762AC_poeOutPort":0,"_ZF7762AC_LLDPEnable":0,"_ZF7762AC_LLDPAdInterval":30,"_ZF7762AC_LLDPHoldTime":120,"_ZF7762AC_LLDPMgmtEnable":0,"_ZF7762SAC_wifi1ExtAnt":1,"_ZF7762SAC_wifi1ExtAntGain":5,"_ZF7762SAC__MacBypass":0,"_ZF7762SAC__SpPassword":"","_ZF7762SAC__SpUsername":"","_ZF7762SAC__acctId":"","_ZF7762SAC__authId":"","_ZF7762SAC__lanPortCount":2,"_ZF7762SAC_ledStatus":1,"_ZF7762SAC__supplicantType":"mac","_ZF7762SAC_eth0Role":0,"_ZF7762SAC_eth0State":1,"_ZF7762SAC_eth0Type":1,"_ZF7762SAC_eth0UntagId":1,"_ZF7762SAC_eth0VlanMembers":"1-4094","_ZF7762SAC_eth1Role":0,"_ZF7762SAC_eth1State":1,"_ZF7762SAC_eth1Type":1,"_ZF7762SAC_eth1UntagId":1,"_ZF7762SAC_eth1VlanMembers":"1-4094","_ZF7762SAC_internalHeater":0,"_ZF7762SAC_poeOutPort":0,"_ZF7762SAC_LLDPEnable":0,"_ZF7762SAC_LLDPAdInterval":30,"_ZF7762SAC_LLDPHoldTime":120,"_ZF7762SAC_LLDPMgmtEnable":0,"_ZF7762S_wifi1ExtAnt":1,"_ZF7762S_wifi1ExtAntGain":5,"_ZF7762S__MacBypass":0,"_ZF7762S__SpPassword":"","_ZF7762S__SpUsername":"","_ZF7762S__acctId":"","_ZF7762S__authId":"","_ZF7762S__lanPortCount":2,"_ZF7762S_ledStatus":1,"_ZF7762S__supplicantType":"mac","_ZF7762S_eth0Role":0,"_ZF7762S_eth0State":1,"_ZF7762S_eth0Type":1,"_ZF7762S_eth0UntagId":1,"_ZF7762S_eth0VlanMembers":"1-4094","_ZF7762S_eth1Role":0,"_ZF7762S_eth1State":1,"_ZF7762S_eth1Type":1,"_ZF7762S_eth1UntagId":1,"_ZF7762S_eth1VlanMembers":"1-4094","_ZF7762S_internalHeater":0,"_ZF7762S_poeOutPort":0,"_ZF7762S_LLDPEnable":0,"_ZF7762S_LLDPAdInterval":30,"_ZF7762S_LLDPHoldTime":120,"_ZF7762S_LLDPMgmtEnable":0,"_ZF7762T_wifi1ExtAnt":1,"_ZF7762T_wifi1ExtAntGain":5,"_ZF7762T__MacBypass":0,"_ZF7762T__SpPassword":"","_ZF7762T__SpUsername":"","_ZF7762T__acctId":"","_ZF7762T__authId":"","_ZF7762T__lanPortCount":2,"_ZF7762T_ledStatus":1,"_ZF7762T__supplicantType":"mac","_ZF7762T_eth0Role":0,"_ZF7762T_eth0State":1,"_ZF7762T_eth0Type":1,"_ZF7762T_eth0UntagId":1,"_ZF7762T_eth0VlanMembers":"1-4094","_ZF7762T_eth1Role":0,"_ZF7762T_eth1State":1,"_ZF7762T_eth1Type":1,"_ZF7762T_eth1UntagId":1,"_ZF7762T_eth1VlanMembers":"1-4094","_ZF7762T_internalHeater":0,"_ZF7762T_poeOutPort":0,"_ZF7762T_LLDPEnable":0,"_ZF7762T_LLDPAdInterval":30,"_ZF7762T_LLDPHoldTime":120,"_ZF7762T_LLDPMgmtEnable":0,"_ZF7762_wifi1ExtAnt":0,"_ZF7762_wifi1ExtAntGain":5,"_ZF7762__MacBypass":0,"_ZF7762__SpPassword":"","_ZF7762__SpUsername":"","_ZF7762__acctId":"","_ZF7762__authId":"","_ZF7762__lanPortCount":2,"_ZF7762_ledStatus":1,"_ZF7762__supplicantType":"mac","_ZF7762_eth0Role":0,"_ZF7762_eth0State":1,"_ZF7762_eth0Type":1,"_ZF7762_eth0UntagId":1,"_ZF7762_eth0VlanMembers":"1-4094","_ZF7762_eth1Role":0,"_ZF7762_eth1State":1,"_ZF7762_eth1Type":1,"_ZF7762_eth1UntagId":1,"_ZF7762_eth1VlanMembers":"1-4094","_ZF7762_internalHeater":0,"_ZF7762_poeOutPort":0,"_ZF7762_LLDPEnable":0,"_ZF7762_LLDPAdInterval":30,"_ZF7762_LLDPHoldTime":120,"_ZF7762_LLDPMgmtEnable":0,"_ZF7962__MacBypass":0,"_ZF7962__SpPassword":"","_ZF7962__SpUsername":"","_ZF7962__acctId":"","_ZF7962__authId":"","_ZF7962__lanPortCount":2,"_ZF7962__supplicantType":"mac","_ZF7962_eth0Role":0,"_ZF7962_eth0State":1,"_ZF7962_eth0Type":1,"_ZF7962_eth0UntagId":1,"_ZF7962_eth0VlanMembers":"1-4094","_ZF7962_eth1Role":0,"_ZF7962_eth1State":1,"_ZF7962_eth1Type":1,"_ZF7962_eth1UntagId":1,"_ZF7962_eth1VlanMembers":"1-4094","_ZF7962_LLDPEnable":0,"_ZF7962_LLDPAdInterval":30,"_ZF7962_LLDPHoldTime":120,"_ZF7962_LLDPMgmtEnable":0,"_ZF7982_ledStatus":1,"_ZF7982__MacBypass":0,"_ZF7982__SpPassword":"","_ZF7982__SpUsername":"","_ZF7982__acctId":"","_ZF7982__authId":"","_ZF7982__lanPortCount":2,"_ZF7982__supplicantType":"mac","_ZF7982_eth0Role":0,"_ZF7982_eth0State":1,"_ZF7982_eth0Type":1,"_ZF7982_eth0UntagId":1,"_ZF7982_eth0VlanMembers":"1-4094","_ZF7982_eth1Role":0,"_ZF7982_eth1State":1,"_ZF7982_eth1Type":1,"_ZF7982_eth1UntagId":1,"_ZF7982_eth1VlanMembers":"1-4094","_ZF7982_LLDPEnable":0,"_ZF7982_LLDPAdInterval":30,"_ZF7982_LLDPHoldTime":120,"_ZF7982_LLDPMgmtEnable":0,"_SC8800S_wifi0ExtAnt":0,"_SC8800S_wifi0ExtAntGain":6,"_SC8800S_wifi1ExtAnt":0,"_SC8800S_wifi1ExtAntGain":5,"_SC8800S_poeOutPort":1,"_SC8800S_ledStatus":1,"_SC8800S__MacBypass":0,"_SC8800S__SpPassword":"","_SC8800S__SpUsername":"","_SC8800S__acctId":"","_SC8800S__authId":"","_SC8800S__lanPortCount":2,"_SC8800S__supplicantType":"mac","_SC8800S_eth0Role":0,"_SC8800S_eth0State":1,"_SC8800S_eth0Type":1,"_SC8800S_eth0UntagId":1,"_SC8800S_eth0VlanMembers":"1-4094","_SC8800S_eth1Role":0,"_SC8800S_eth1State":1,"_SC8800S_eth1Type":1,"_SC8800S_eth1UntagId":1,"_SC8800S_eth1VlanMembers":"1-4094","_SC8800S_LLDPEnable":0,"_SC8800S_LLDPAdInterval":30,"_SC8800S_LLDPHoldTime":120,"_SC8800S_LLDPMgmtEnable":0,"_SC8800SAC_wifi1ExtAnt":0,"_SC8800SAC_wifi1ExtAntGain":5,"_SC8800SAC_poeOutPort":0,"_SC8800SAC_ledStatus":1,"_SC8800SAC__MacBypass":0,"_SC8800SAC__SpPassword":"","_SC8800SAC__SpUsername":"","_SC8800SAC__acctId":"","_SC8800SAC__authId":"","_SC8800SAC__lanPortCount":2,"_SC8800SAC__supplicantType":"mac","_SC8800SAC_eth0Role":0,"_SC8800SAC_eth0State":1,"_SC8800SAC_eth0Type":1,"_SC8800SAC_eth0UntagId":1,"_SC8800SAC_eth0VlanMembers":"1-4094","_SC8800SAC_eth1Role":0,"_SC8800SAC_eth1State":1,"_SC8800SAC_eth1Type":1,"_SC8800SAC_eth1UntagId":1,"_SC8800SAC_eth1VlanMembers":"1-4094","_SC8800SAC_LLDPEnable":0,"_SC8800SAC_LLDPAdInterval":30,"_SC8800SAC_LLDPHoldTime":120,"_SC8800SAC_LLDPMgmtEnable":0,"_ZF7782E_wifi0ExtAnt":1,"_ZF7782E_wifi0ExtAntGain":5,"_ZF7782E_wifi0ExtAntChainMask":7,"_ZF7782E_wifi1ExtAnt":1,"_ZF7782E_wifi1ExtAntGain":5,"_ZF7782E_wifi1ExtAntChainMask":7,"_ZF7782E_poeOutPort":1,"_ZF7782E_ledStatus":1,"_ZF7782E__MacBypass":0,"_ZF7782E__SpPassword":"","_ZF7782E__SpUsername":"","_ZF7782E__acctId":"","_ZF7782E__authId":"","_ZF7782E__lanPortCount":2,"_ZF7782E__supplicantType":"mac","_ZF7782E_eth0Role":0,"_ZF7782E_eth0State":1,"_ZF7782E_eth0Type":1,"_ZF7782E_eth0UntagId":1,"_ZF7782E_eth0VlanMembers":"1-4094","_ZF7782E_eth1Role":0,"_ZF7782E_eth1State":1,"_ZF7782E_eth1Type":1,"_ZF7782E_eth1UntagId":1,"_ZF7782E_eth1VlanMembers":"1-4094","_ZF7782E_LLDPEnable":0,"_ZF7782E_LLDPAdInterval":30,"_ZF7782E_LLDPHoldTime":120,"_ZF7782E_LLDPMgmtEnable":0,"_ZF7781M_wifi0ExtAnt":1,"_ZF7781M_wifi0ExtAntGain":5,"_ZF7781M_wifi1ExtAnt":1,"_ZF7781M_wifi1ExtAntGain":5,"_ZF7781M__MacBypass":0,"_ZF7781M__SpPassword":"","_ZF7781M__SpUsername":"","_ZF7781M__acctId":"","_ZF7781M__authId":"","_ZF7781M__lanPortCount":1,"_ZF7781M__supplicantType":"mac","_ZF7781M_eth0Role":0,"_ZF7781M_eth0State":1,"_ZF7781M_eth0Type":1,"_ZF7781M_eth0UntagId":1,"_ZF7781M_eth0VlanMembers":"1-4094","_ZF7781M_LLDPEnable":0,"_ZF7781M_LLDPAdInterval":30,"_ZF7781M_LLDPHoldTime":120,"_ZF7781M_LLDPMgmtEnable":0,"_ZF7782_poeOutPort":1,"_ZF7782_ledStatus":1,"_ZF7782__MacBypass":0,"_ZF7782__SpPassword":"","_ZF7782__SpUsername":"","_ZF7782__acctId":"","_ZF7782__authId":"","_ZF7782__lanPortCount":2,"_ZF7782__supplicantType":"mac","_ZF7782_eth0Role":0,"_ZF7782_eth0State":1,"_ZF7782_eth0Type":1,"_ZF7782_eth0UntagId":1,"_ZF7782_eth0VlanMembers":"1-4094","_ZF7782_eth1Role":0,"_ZF7782_eth1State":1,"_ZF7782_eth1Type":1,"_ZF7782_eth1UntagId":1,"_ZF7782_eth1VlanMembers":"1-4094","_ZF7782_LLDPEnable":0,"_ZF7782_LLDPAdInterval":30,"_ZF7782_LLDPHoldTime":120,"_ZF7782_LLDPMgmtEnable":0,"_ZF7782N_poeOutPort":1,"_ZF7782N_ledStatus":1,"_ZF7782N__MacBypass":0,"_ZF7782N__SpPassword":"","_ZF7782N__SpUsername":"","_ZF7782N__acctId":"","_ZF7782N__authId":"","_ZF7782N__lanPortCount":2,"_ZF7782N__supplicantType":"mac","_ZF7782N_eth0Role":0,"_ZF7782N_eth0State":1,"_ZF7782N_eth0Type":1,"_ZF7782N_eth0UntagId":1,"_ZF7782N_eth0VlanMembers":"1-4094","_ZF7782N_eth1Role":0,"_ZF7782N_eth1State":1,"_ZF7782N_eth1Type":1,"_ZF7782N_eth1UntagId":1,"_ZF7782N_eth1VlanMembers":"1-4094","_ZF7782N_LLDPEnable":0,"_ZF7782N_LLDPAdInterval":30,"_ZF7782N_LLDPHoldTime":120,"_ZF7782N_LLDPMgmtEnable":0,"_ZF7782S_poeOutPort":1,"_ZF7782S_ledStatus":1,"_ZF7782S__MacBypass":0,"_ZF7782S__SpPassword":"","_ZF7782S__SpUsername":"","_ZF7782S__acctId":"","_ZF7782S__authId":"","_ZF7782S__lanPortCount":2,"_ZF7782S__supplicantType":"mac","_ZF7782S_eth0Role":0,"_ZF7782S_eth0State":1,"_ZF7782S_eth0Type":1,"_ZF7782S_eth0UntagId":1,"_ZF7782S_eth0VlanMembers":"1-4094","_ZF7782S_eth1Role":0,"_ZF7782S_eth1State":1,"_ZF7782S_eth1Type":1,"_ZF7782S_eth1UntagId":1,"_ZF7782S_eth1VlanMembers":"1-4094","_ZF7782S_LLDPEnable":0,"_ZF7782S_LLDPAdInterval":30,"_ZF7782S_LLDPHoldTime":120,"_ZF7782S_LLDPMgmtEnable":0,"_ZF7352__MacBypass":0,"_ZF7352__SpPassword":"","_ZF7352__SpUsername":"","_ZF7352__acctId":"","_ZF7352__authId":"","_ZF7352__lanPortCount":2,"_ZF7352__supplicantType":"mac","_ZF7352_eth0Role":0,"_ZF7352_eth0State":1,"_ZF7352_eth0Type":1,"_ZF7352_eth0UntagId":1,"_ZF7352_eth0VlanMembers":"1-4094","_ZF7352_eth1Role":0,"_ZF7352_eth1State":1,"_ZF7352_eth1Type":1,"_ZF7352_eth1UntagId":1,"_ZF7352_eth1VlanMembers":"1-4094","_ZF7352_LLDPEnable":0,"_ZF7352_LLDPAdInterval":30,"_ZF7352_LLDPHoldTime":120,"_ZF7352_LLDPMgmtEnable":0,"_ZF7352_ledStatus":1,"_ZF7352U__MacBypass":0,"_ZF7352U__SpPassword":"","_ZF7352U__SpUsername":"","_ZF7352U__acctId":"","_ZF7352U__authId":"","_ZF7352U__lanPortCount":2,"_ZF7352U__supplicantType":"mac","_ZF7352U_eth0Role":0,"_ZF7352U_eth0State":1,"_ZF7352U_eth0Type":1,"_ZF7352U_eth0UntagId":1,"_ZF7352U_eth0VlanMembers":"1-4094","_ZF7352U_eth1Role":0,"_ZF7352U_eth1State":1,"_ZF7352U_eth1Type":1,"_ZF7352U_eth1UntagId":1,"_ZF7352U_eth1VlanMembers":"1-4094","_ZF7352U_LLDPEnable":0,"_ZF7352U_LLDPAdInterval":30,"_ZF7352U_LLDPHoldTime":120,"_ZF7352U_LLDPMgmtEnable":0,"_ZF7352U_ledStatus":1,"_ZF7372__MacBypass":0,"_ZF7372__SpPassword":"","_ZF7372__SpUsername":"","_ZF7372__acctId":"","_ZF7372__authId":"","_ZF7372__lanPortCount":2,"_ZF7372__supplicantType":"mac","_ZF7372_eth0Role":0,"_ZF7372_eth0State":1,"_ZF7372_eth0Type":1,"_ZF7372_eth0UntagId":1,"_ZF7372_eth0VlanMembers":"1-4094","_ZF7372_eth1Role":0,"_ZF7372_eth1State":1,"_ZF7372_eth1Type":1,"_ZF7372_eth1UntagId":1,"_ZF7372_eth1VlanMembers":"1-4094","_ZF7372_LLDPEnable":0,"_ZF7372_LLDPAdInterval":30,"_ZF7372_LLDPHoldTime":120,"_ZF7372_LLDPMgmtEnable":0,"_ZF7372_ledStatus":1,"_ZF7372U__MacBypass":0,"_ZF7372U__SpPassword":"","_ZF7372U__SpUsername":"","_ZF7372U__acctId":"","_ZF7372U__authId":"","_ZF7372U__lanPortCount":2,"_ZF7372U__supplicantType":"mac","_ZF7372U_eth0Role":0,"_ZF7372U_eth0State":1,"_ZF7372U_eth0Type":1,"_ZF7372U_eth0UntagId":1,"_ZF7372U_eth0VlanMembers":"1-4094","_ZF7372U_eth1Role":0,"_ZF7372U_eth1State":1,"_ZF7372U_eth1Type":1,"_ZF7372U_eth1UntagId":1,"_ZF7372U_eth1VlanMembers":"1-4094","_ZF7372U_LLDPEnable":0,"_ZF7372U_LLDPAdInterval":30,"_ZF7372U_LLDPHoldTime":120,"_ZF7372U_LLDPMgmtEnable":0,"_ZF7372U_ledStatus":1,"_ZF7372E__MacBypass":0,"_ZF7372E__SpPassword":"","_ZF7372E__SpUsername":"","_ZF7372E__acctId":"","_ZF7372E__authId":"","_ZF7372E__lanPortCount":2,"_ZF7372E__supplicantType":"mac","_ZF7372E_eth0Role":0,"_ZF7372E_eth0State":1,"_ZF7372E_eth0Type":1,"_ZF7372E_eth0UntagId":1,"_ZF7372E_eth0VlanMembers":"1-4094","_ZF7372E_eth1Role":0,"_ZF7372E_eth1State":1,"_ZF7372E_eth1Type":1,"_ZF7372E_eth1UntagId":1,"_ZF7372E_eth1VlanMembers":"1-4094","_ZF7372E_wifi0ExtAnt":1,"_ZF7372E_wifi0ExtAntGain":2,"_ZF7372E_wifi0ExtAntChainMask":None,"_ZF7372E_wifi1ExtAnt":1,"_ZF7372E_wifi1ExtAntGain":3,"_ZF7372E_wifi1ExtAntChainMask":None,"_ZF7372E_LLDPEnable":0,"_ZF7372E_LLDPAdInterval":30,"_ZF7372E_LLDPHoldTime":120,"_ZF7372E_LLDPMgmtEnable":0,"_ZF7372E_ledStatus":1,"_ZF7441__MacBypass":0,"_ZF7441__SpPassword":"","_ZF7441__SpUsername":"","_ZF7441__acctId":"","_ZF7441__authId":"","_ZF7441__lanPortCount":1,"_ZF7441__supplicantType":"mac","_ZF7441_ledStatus":1,"_ZF7441_eth0Role":0,"_ZF7441_eth0State":1,"_ZF7441_eth0Type":1,"_ZF7441_eth0UntagId":1,"_ZF7441_eth0VlanMembers":"1-4094","_ZF7441_wifi0ExtAnt":1,"_ZF7441_wifi0ExtAntGain":5,"_ZF7441_LLDPEnable":0,"_ZF7441_LLDPAdInterval":30,"_ZF7441_LLDPHoldTime":120,"_ZF7441_LLDPMgmtEnable":0,"_R300__MacBypass":0,"_R300__SpPassword":"","_R300__SpUsername":"","_R300__acctId":"","_R300__authId":"","_R300__lanPortCount":1,"_R300__supplicantType":"mac","_R300_ledStatus":1,"_R300_eth0Role":0,"_R300_eth0State":1,"_R300_eth0Type":1,"_R300_eth0UntagId":1,"_R300_eth0VlanMembers":"1-4094","_R300_LLDPEnable":0,"_R300_LLDPAdInterval":30,"_R300_LLDPHoldTime":120,"_R300_LLDPMgmtEnable":0}}
        zone_data = {"zoneDescription":None,"zoneName":None,"fwVersion":None,"tunnelType":None,"tunnelProfileUUID":"77a20d60-43bf-494c-a6ff-daae10aebce4","location":"","locationAdditionalInfo":"","gpsInfo":"","lbsEnable":0,"enableBandBalancing":True,"clientPercent24":25,"ipMode":"IPV4","commonConfig":{"_allowIndoorChannel":None,"apLogin":None,"apPass":None,"countryCode":"US","wifi0BgScan":None,"wifi0Channel":None,"wifi0ChannelWidth":None,"wifi0TxPower":"max","wifi1BgScan":0,"wifi1Channel":0,"_wifi1Channel_indoor":0,"wifi1ChannelWidth":None,"wifi1TxPower":None,"syslogIp":None,"syslogIpv6":"","syslogPort":None,"syslogFacility":-1,"syslogRLevel":3,"wifi0RoamEnable":1,"wifi1RoamEnable":1,"smartRoamDisconnect":0,"smartMonEnable":0,"smartMonInterval":None,"smartMonThreshold":None,"wifi0WeakBypass":33,"wifi1WeakBypass":35,"wifi0HeadRoom":3,"wifi1HeadRoom":3,"wifi0ChannelSelectMode":1,"wifi1ChannelSelectMode":1,"wifi0ChannelflyMtbc":480,"wifi1ChannelflyMtbc":480,"channelEvaluationInterval":600,"vlanOverlappingEnabled":False,"location":"","locationAdditionalInfo":"","apRogueEnabled":0,"apRogueReportAll":1,"apRogueReportSsidSpoofing":1,"apRogueReportSameNetwork":0,"apRogueReportMacSpoofing":0,"apRogueReportProtect":0,"gwLossTimeout":1800,"serverLossTimeout":7200,"apManagementVlanMode":"KEEP","wifi0ChannelRange":"1,2,3,4,5,6,7,8,9,10,11","_wifi1ChannelRangeIndoor":"36,40,44,48,149,153,157,161","wifi1ChannelRange":"149,153,157,161"},"zoneUUID":None,"tunnelConfig":{"_tunnelType":None,"tunnelEncryption":None},"clientAdmissionConfig":{"clientAdmEnable24":False,"clientAdmEnable50":False,"clientAdmMaxRadioLoad24":75,"clientAdmMaxRadioLoad50":75,"clientAdmMinClientCount24":10,"clientAdmMinClientCount50":20,"clientAdmMinClientThroughput24":0,"clientAdmMinClientThroughput50":0},"modelConfig":{"_ZF2741_wifi0ExtAnt":0,"_ZF2741_wifi0ExtAntGain":5,"_ZF2741__lanPortCount":1,"_ZF2741_eth0ProfileId":0,"_ZF2741_eth0OverwriteVlan":0,"_ZF2741_eth0State":1,"_ZF2741_eth0Type":1,"_ZF2741_eth0UntagId":1,"_ZF2741_eth0VlanMembers":"1-4094","_ZF2741_eth0Role":0,"_ZF2741__authId":"","_ZF2741__acctId":"","_ZF2741__MacBypass":0,"_ZF2741__supplicantType":"mac","_ZF2741__SpUsername":"","_ZF2741__SpPassword":"","_ZF2741_LLDPEnable":0,"_ZF2741_LLDPAdInterval":30,"_ZF2741_LLDPHoldTime":120,"_ZF2741_LLDPMgmtEnable":0,"_ZF2942_eth0State":1,"_ZF2942__lanPortCount":2,"_ZF2942_eth0ProfileId":0,"_ZF2942_eth0OverwriteVlan":0,"_ZF2942_eth0Type":1,"_ZF2942_eth0UntagId":1,"_ZF2942_eth0VlanMembers":"1-4094","_ZF2942_eth0Role":0,"_ZF2942_eth1ProfileId":0,"_ZF2942_eth1OverwriteVlan":0,"_ZF2942_eth1State":1,"_ZF2942_eth1Type":1,"_ZF2942_eth1UntagId":1,"_ZF2942_eth1VlanMembers":"1-4094","_ZF2942_eth1Role":0,"_ZF2942_wifi0ExtAnt":0,"_ZF2942_wifi0ExtAntGain":5,"_ZF2942__authId":"","_ZF2942__acctId":"","_ZF2942__MacBypass":0,"_ZF2942__supplicantType":"mac","_ZF2942__SpUsername":"","_ZF2942__SpPassword":"","_ZF2942_LLDPEnable":0,"_ZF2942_LLDPAdInterval":30,"_ZF2942_LLDPHoldTime":120,"_ZF2942_LLDPMgmtEnable":0,"_ZF7025_ledStatus":1,"_ZF7025__lanPortCount":5,"_ZF7025_eth0ProfileId":1,"_ZF7025_eth0OverwriteVlan":0,"_ZF7025_eth0State":1,"_ZF7025_eth0Type":0,"_ZF7025_eth0UntagId":1,"_ZF7025_eth0VlanMembers":"1","_ZF7025_eth0Role":0,"_ZF7025_eth1ProfileId":1,"_ZF7025_eth1OverwriteVlan":0,"_ZF7025_eth1State":1,"_ZF7025_eth1Type":0,"_ZF7025_eth1UntagId":1,"_ZF7025_eth1VlanMembers":"1","_ZF7025_eth1Role":0,"_ZF7025_eth2ProfileId":1,"_ZF7025_eth2OverwriteVlan":0,"_ZF7025_eth2State":1,"_ZF7025_eth2Type":0,"_ZF7025_eth2UntagId":1,"_ZF7025_eth2VlanMembers":"1","_ZF7025_eth2Role":0,"_ZF7025_eth3ProfileId":1,"_ZF7025_eth3OverwriteVlan":0,"_ZF7025_eth3State":1,"_ZF7025_eth3Type":0,"_ZF7025_eth3UntagId":1,"_ZF7025_eth3VlanMembers":"1","_ZF7025_eth3Role":0,"_ZF7025_eth4ProfileId":0,"_ZF7025_eth4OverwriteVlan":0,"_ZF7025_eth4State":1,"_ZF7025_eth4Type":1,"_ZF7025_eth4UntagId":1,"_ZF7025_eth4VlanMembers":"1-4094","_ZF7025_eth4Role":0,"_ZF7025__authId":"","_ZF7025__acctId":"","_ZF7025__MacBypass":0,"_ZF7025__supplicantType":"mac","_ZF7025__SpUsername":"","_ZF7025__SpPassword":"","_ZF7025_LLDPEnable":0,"_ZF7025_LLDPAdInterval":30,"_ZF7025_LLDPHoldTime":120,"_ZF7025_LLDPMgmtEnable":0,"_ZF7055_ledStatus":1,"_ZF7055__lanPortCount":5,"_ZF7055_eth0ProfileId":1,"_ZF7055_eth0OverwriteVlan":0,"_ZF7055_eth0State":1,"_ZF7055_eth0Type":0,"_ZF7055_eth0UntagId":1,"_ZF7055_eth0VlanMembers":"1","_ZF7055_eth0Role":0,"_ZF7055_eth1ProfileId":1,"_ZF7055_eth1OverwriteVlan":0,"_ZF7055_eth1State":1,"_ZF7055_eth1Type":0,"_ZF7055_eth1UntagId":1,"_ZF7055_eth1VlanMembers":"1","_ZF7055_eth1Role":0,"_ZF7055_eth2ProfileId":1,"_ZF7055_eth2OverwriteVlan":0,"_ZF7055_eth2State":1,"_ZF7055_eth2Type":0,"_ZF7055_eth2UntagId":1,"_ZF7055_eth2VlanMembers":"1","_ZF7055_eth2Role":0,"_ZF7055_eth3ProfileId":1,"_ZF7055_eth3OverwriteVlan":0,"_ZF7055_eth3State":1,"_ZF7055_eth3Type":0,"_ZF7055_eth3UntagId":1,"_ZF7055_eth3VlanMembers":"1","_ZF7055_eth3Role":0,"_ZF7055_eth4ProfileId":0,"_ZF7055_eth4OverwriteVlan":0,"_ZF7055_eth4State":1,"_ZF7055_eth4Type":1,"_ZF7055_eth4UntagId":1,"_ZF7055_eth4VlanMembers":"1-4094","_ZF7055_eth4Role":0,"_ZF7055__authId":"","_ZF7055__acctId":"","_ZF7055__MacBypass":0,"_ZF7055__supplicantType":"mac","_ZF7055__SpUsername":"","_ZF7055__SpPassword":"","_ZF7055_LLDPEnable":0,"_ZF7055_LLDPAdInterval":30,"_ZF7055_LLDPHoldTime":120,"_ZF7055_LLDPMgmtEnable":0,"_H500_ledStatus":1,"_H500_usbPowerEnable":1,"_H500__lanPortCount":5,"_H500_eth0ProfileId":1,"_H500_eth0OverwriteVlan":0,"_H500_eth0State":1,"_H500_eth0Type":0,"_H500_eth0UntagId":1,"_H500_eth0VlanMembers":"1","_H500_eth0Role":0,"_H500_eth1ProfileId":1,"_H500_eth1OverwriteVlan":0,"_H500_eth1State":1,"_H500_eth1Type":0,"_H500_eth1UntagId":1,"_H500_eth1VlanMembers":"1","_H500_eth1Role":0,"_H500_eth2ProfileId":1,"_H500_eth2OverwriteVlan":0,"_H500_eth2State":1,"_H500_eth2Type":0,"_H500_eth2UntagId":1,"_H500_eth2VlanMembers":"1","_H500_eth2Role":0,"_H500_eth3ProfileId":1,"_H500_eth3OverwriteVlan":0,"_H500_eth3State":1,"_H500_eth3Type":0,"_H500_eth3UntagId":1,"_H500_eth3VlanMembers":"1","_H500_eth3Role":0,"_H500_eth4ProfileId":0,"_H500_eth4OverwriteVlan":0,"_H500_eth4State":1,"_H500_eth4Type":1,"_H500_eth4UntagId":1,"_H500_eth4VlanMembers":"1-4094","_H500_eth4Role":0,"_H500__authId":"","_H500__acctId":"","_H500__MacBypass":0,"_H500__supplicantType":"mac","_H500__SpUsername":"","_H500__SpPassword":"","_H500_LLDPEnable":0,"_H500_LLDPAdInterval":30,"_H500_LLDPHoldTime":120,"_H500_LLDPMgmtEnable":0,"_ZF7321_eth0State":1,"_ZF7321_usbPowerEnable":1,"_ZF7321__lanPortCount":1,"_ZF7321_eth0ProfileId":0,"_ZF7321_eth0OverwriteVlan":0,"_ZF7321_eth0Type":1,"_ZF7321_eth0UntagId":1,"_ZF7321_eth0VlanMembers":"1-4094","_ZF7321_eth0Role":0,"_ZF7321__authId":"","_ZF7321__acctId":"","_ZF7321__MacBypass":0,"_ZF7321__supplicantType":"mac","_ZF7321__SpUsername":"","_ZF7321__SpPassword":"","_ZF7321_ledStatus":1,"_ZF7321_LLDPEnable":0,"_ZF7321_LLDPAdInterval":30,"_ZF7321_LLDPHoldTime":120,"_ZF7321_LLDPMgmtEnable":0,"_ZF7321_radioBand":"2.4","_ZF7321U_eth0State":1,"_ZF7321U__lanPortCount":1,"_ZF7321U_eth0ProfileId":0,"_ZF7321U_eth0OverwriteVlan":0,"_ZF7321U_eth0Type":1,"_ZF7321U_eth0UntagId":1,"_ZF7321U_eth0VlanMembers":"1-4094","_ZF7321U_eth0Role":0,"_ZF7321U__authId":"","_ZF7321U__acctId":"","_ZF7321U__MacBypass":0,"_ZF7321U__supplicantType":"mac","_ZF7321U__SpUsername":"","_ZF7321U__SpPassword":"","_ZF7321U_ledStatus":1,"_ZF7321U_LLDPEnable":0,"_ZF7321U_LLDPAdInterval":30,"_ZF7321U_LLDPHoldTime":120,"_ZF7321U_LLDPMgmtEnable":0,"_ZF7321U_radioBand":"2.4","_ZF7321U_apUsbSoftwarePackageId":"","_ZF7341_ledStatus":1,"_ZF7341_eth0State":1,"_ZF7341__lanPortCount":1,"_ZF7341_eth0ProfileId":0,"_ZF7341_eth0OverwriteVlan":0,"_ZF7341_eth0Type":1,"_ZF7341_eth0UntagId":1,"_ZF7341_eth0VlanMembers":"1-4094","_ZF7341_eth0Role":0,"_ZF7341__authId":"","_ZF7341__acctId":"","_ZF7341__MacBypass":0,"_ZF7341__supplicantType":"mac","_ZF7341__SpUsername":"","_ZF7341__SpPassword":"","_ZF7341_LLDPEnable":0,"_ZF7341_LLDPAdInterval":30,"_ZF7341_LLDPHoldTime":120,"_ZF7341_LLDPMgmtEnable":0,"_ZF7351U_ledStatus":1,"_ZF7351U_eth0State":1,"_ZF7351U__lanPortCount":1,"_ZF7351U_eth0ProfileId":0,"_ZF7351U_eth0OverwriteVlan":0,"_ZF7351U_eth0Type":1,"_ZF7351U_eth0UntagId":1,"_ZF7351U_eth0VlanMembers":"1-4094","_ZF7351U_eth0Role":0,"_ZF7351U__authId":"","_ZF7351U__acctId":"","_ZF7351U__MacBypass":0,"_ZF7351U__supplicantType":"mac","_ZF7351U__SpUsername":"","_ZF7351U__SpPassword":"","_ZF7351U_LLDPEnable":0,"_ZF7351U_LLDPAdInterval":30,"_ZF7351U_LLDPHoldTime":120,"_ZF7351U_LLDPMgmtEnable":0,"_ZF7351_ledStatus":1,"_ZF7351_eth0State":1,"_ZF7351__lanPortCount":1,"_ZF7351_eth0ProfileId":0,"_ZF7351_eth0OverwriteVlan":0,"_ZF7351_eth0Type":1,"_ZF7351_eth0UntagId":1,"_ZF7351_eth0VlanMembers":"1-4094","_ZF7351_eth0Role":0,"_ZF7351__authId":"","_ZF7351__acctId":"","_ZF7351__MacBypass":0,"_ZF7351__supplicantType":"mac","_ZF7351__SpUsername":"","_ZF7351__SpPassword":"","_ZF7351_LLDPEnable":0,"_ZF7351_LLDPAdInterval":30,"_ZF7351_LLDPHoldTime":120,"_ZF7351_LLDPMgmtEnable":0,"_ZF7343_ledStatus":1,"_ZF7343_eth0State":1,"_ZF7343__lanPortCount":3,"_ZF7343_eth0ProfileId":0,"_ZF7343_eth0OverwriteVlan":0,"_ZF7343_eth0Type":1,"_ZF7343_eth0UntagId":1,"_ZF7343_eth0VlanMembers":"1-4094","_ZF7343_eth0Role":0,"_ZF7343_eth1ProfileId":0,"_ZF7343_eth1OverwriteVlan":0,"_ZF7343_eth1State":1,"_ZF7343_eth1Type":1,"_ZF7343_eth1UntagId":1,"_ZF7343_eth1VlanMembers":"1-4094","_ZF7343_eth1Role":0,"_ZF7343_eth2ProfileId":0,"_ZF7343_eth2OverwriteVlan":0,"_ZF7343_eth2State":1,"_ZF7343_eth2Type":1,"_ZF7343_eth2UntagId":1,"_ZF7343_eth2VlanMembers":"1-4094","_ZF7343_eth2Role":0,"_ZF7343__authId":"","_ZF7343__acctId":"","_ZF7343__MacBypass":0,"_ZF7343__supplicantType":"mac","_ZF7343__SpUsername":"","_ZF7343__SpPassword":"","_ZF7343_LLDPEnable":0,"_ZF7343_LLDPAdInterval":30,"_ZF7343_LLDPHoldTime":120,"_ZF7343_LLDPMgmtEnable":0,"_ZF7363_ledStatus":1,"_ZF7363_eth0State":1,"_ZF7363__lanPortCount":3,"_ZF7363_eth0ProfileId":0,"_ZF7363_eth0OverwriteVlan":0,"_ZF7363_eth0Type":1,"_ZF7363_eth0UntagId":1,"_ZF7363_eth0VlanMembers":"1-4094","_ZF7363_eth0Role":0,"_ZF7363_eth1ProfileId":0,"_ZF7363_eth1OverwriteVlan":0,"_ZF7363_eth1State":1,"_ZF7363_eth1Type":1,"_ZF7363_eth1UntagId":1,"_ZF7363_eth1VlanMembers":"1-4094","_ZF7363_eth1Role":0,"_ZF7363_eth2ProfileId":0,"_ZF7363_eth2OverwriteVlan":0,"_ZF7363_eth2State":1,"_ZF7363_eth2Type":1,"_ZF7363_eth2UntagId":1,"_ZF7363_eth2VlanMembers":"1-4094","_ZF7363_eth2Role":0,"_ZF7363__authId":"","_ZF7363__acctId":"","_ZF7363__MacBypass":0,"_ZF7363__supplicantType":"mac","_ZF7363__SpUsername":"","_ZF7363__SpPassword":"","_ZF7363_LLDPEnable":0,"_ZF7363_LLDPAdInterval":30,"_ZF7363_LLDPHoldTime":120,"_ZF7363_LLDPMgmtEnable":0,"_ZF7762_internalHeater":0,"_ZF7762_poeOutPort":0,"_ZF7762_ledStatus":1,"_ZF7762_wifi1ExtAnt":0,"_ZF7762_wifi1ExtAntGain":5,"_ZF7762_eth0State":1,"_ZF7762__lanPortCount":2,"_ZF7762_eth0ProfileId":0,"_ZF7762_eth0OverwriteVlan":0,"_ZF7762_eth0Type":1,"_ZF7762_eth0UntagId":1,"_ZF7762_eth0VlanMembers":"1-4094","_ZF7762_eth0Role":0,"_ZF7762_eth1ProfileId":0,"_ZF7762_eth1OverwriteVlan":0,"_ZF7762_eth1State":1,"_ZF7762_eth1Type":1,"_ZF7762_eth1UntagId":1,"_ZF7762_eth1VlanMembers":"1-4094","_ZF7762_eth1Role":0,"_ZF7762__authId":"","_ZF7762__acctId":"","_ZF7762__MacBypass":0,"_ZF7762__supplicantType":"mac","_ZF7762__SpUsername":"","_ZF7762__SpPassword":"","_ZF7762_LLDPEnable":0,"_ZF7762_LLDPAdInterval":30,"_ZF7762_LLDPHoldTime":120,"_ZF7762_LLDPMgmtEnable":0,"_ZF7762S_internalHeater":0,"_ZF7762S_poeOutPort":0,"_ZF7762S_ledStatus":1,"_ZF7762S_wifi1ExtAnt":1,"_ZF7762S_wifi1ExtAntGain":5,"_ZF7762S_eth0State":1,"_ZF7762S__lanPortCount":2,"_ZF7762S_eth0ProfileId":0,"_ZF7762S_eth0OverwriteVlan":0,"_ZF7762S_eth0Type":1,"_ZF7762S_eth0UntagId":1,"_ZF7762S_eth0VlanMembers":"1-4094","_ZF7762S_eth0Role":0,"_ZF7762S_eth1ProfileId":0,"_ZF7762S_eth1OverwriteVlan":0,"_ZF7762S_eth1State":1,"_ZF7762S_eth1Type":1,"_ZF7762S_eth1UntagId":1,"_ZF7762S_eth1VlanMembers":"1-4094","_ZF7762S_eth1Role":0,"_ZF7762S__authId":"","_ZF7762S__acctId":"","_ZF7762S__MacBypass":0,"_ZF7762S__supplicantType":"mac","_ZF7762S__SpUsername":"","_ZF7762S__SpPassword":"","_ZF7762S_LLDPEnable":0,"_ZF7762S_LLDPAdInterval":30,"_ZF7762S_LLDPHoldTime":120,"_ZF7762S_LLDPMgmtEnable":0,"_ZF7762T_internalHeater":0,"_ZF7762T_poeOutPort":0,"_ZF7762T_ledStatus":1,"_ZF7762T_eth0State":1,"_ZF7762T__lanPortCount":2,"_ZF7762T_wifi1ExtAnt":1,"_ZF7762T_wifi1ExtAntGain":5,"_ZF7762T_eth0ProfileId":0,"_ZF7762T_eth0OverwriteVlan":0,"_ZF7762T_eth0Type":1,"_ZF7762T_eth0UntagId":1,"_ZF7762T_eth0VlanMembers":"1-4094","_ZF7762T_eth0Role":0,"_ZF7762T_eth1ProfileId":0,"_ZF7762T_eth1OverwriteVlan":0,"_ZF7762T_eth1State":1,"_ZF7762T_eth1Type":1,"_ZF7762T_eth1UntagId":1,"_ZF7762T_eth1VlanMembers":"1-4094","_ZF7762T_eth1Role":0,"_ZF7762T__authId":"","_ZF7762T__acctId":"","_ZF7762T__MacBypass":0,"_ZF7762T__supplicantType":"mac","_ZF7762T__SpUsername":"","_ZF7762T__SpPassword":"","_ZF7762T_LLDPEnable":0,"_ZF7762T_LLDPAdInterval":30,"_ZF7762T_LLDPHoldTime":120,"_ZF7762T_LLDPMgmtEnable":0,"_ZF7762AC_internalHeater":0,"_ZF7762AC_poeOutPort":0,"_ZF7762AC_ledStatus":1,"_ZF7762AC_wifi1ExtAnt":0,"_ZF7762AC_wifi1ExtAntGain":5,"_ZF7762AC_eth0State":1,"_ZF7762AC__lanPortCount":2,"_ZF7762AC_eth0ProfileId":0,"_ZF7762AC_eth0OverwriteVlan":0,"_ZF7762AC_eth0Type":1,"_ZF7762AC_eth0UntagId":1,"_ZF7762AC_eth0VlanMembers":"1-4094","_ZF7762AC_eth0Role":0,"_ZF7762AC_eth1ProfileId":0,"_ZF7762AC_eth1OverwriteVlan":0,"_ZF7762AC_eth1State":1,"_ZF7762AC_eth1Type":1,"_ZF7762AC_eth1UntagId":1,"_ZF7762AC_eth1VlanMembers":"1-4094","_ZF7762AC_eth1Role":0,"_ZF7762AC__authId":"","_ZF7762AC__acctId":"","_ZF7762AC__MacBypass":0,"_ZF7762AC__supplicantType":"mac","_ZF7762AC__SpUsername":"","_ZF7762AC__SpPassword":"","_ZF7762AC_LLDPEnable":0,"_ZF7762AC_LLDPAdInterval":30,"_ZF7762AC_LLDPHoldTime":120,"_ZF7762AC_LLDPMgmtEnable":0,"_ZF7762SAC_internalHeater":0,"_ZF7762SAC_poeOutPort":0,"_ZF7762SAC_ledStatus":1,"_ZF7762SAC_wifi1ExtAnt":1,"_ZF7762SAC_wifi1ExtAntGain":5,"_ZF7762SAC_eth0State":1,"_ZF7762SAC__lanPortCount":2,"_ZF7762SAC_eth0ProfileId":0,"_ZF7762SAC_eth0OverwriteVlan":0,"_ZF7762SAC_eth0Type":1,"_ZF7762SAC_eth0UntagId":1,"_ZF7762SAC_eth0VlanMembers":"1-4094","_ZF7762SAC_eth0Role":0,"_ZF7762SAC_eth1ProfileId":0,"_ZF7762SAC_eth1OverwriteVlan":0,"_ZF7762SAC_eth1State":1,"_ZF7762SAC_eth1Type":1,"_ZF7762SAC_eth1UntagId":1,"_ZF7762SAC_eth1VlanMembers":"1-4094","_ZF7762SAC_eth1Role":0,"_ZF7762SAC__authId":"","_ZF7762SAC__acctId":"","_ZF7762SAC__MacBypass":0,"_ZF7762SAC__supplicantType":"mac","_ZF7762SAC__SpUsername":"","_ZF7762SAC__SpPassword":"","_ZF7762SAC_LLDPEnable":0,"_ZF7762SAC_LLDPAdInterval":30,"_ZF7762SAC_LLDPHoldTime":120,"_ZF7762SAC_LLDPMgmtEnable":0,"_ZF7761CM_cmLedMode":7,"_ZF7761CM_internalHeater":1,"_ZF7761CM_poeOutPort":1,"_ZF7761CM_ledStatus":1,"_ZF7761CM_wifi1ExtAnt":1,"_ZF7761CM_wifi1ExtAntGain":5,"_ZF7761CM__lanPortCount":2,"_ZF7761CM_eth0ProfileId":0,"_ZF7761CM_eth0OverwriteVlan":0,"_ZF7761CM_eth0State":1,"_ZF7761CM_eth0Type":1,"_ZF7761CM_eth0UntagId":1,"_ZF7761CM_eth0VlanMembers":"1-4094","_ZF7761CM_eth0Role":0,"_ZF7761CM_eth1ProfileId":0,"_ZF7761CM_eth1OverwriteVlan":0,"_ZF7761CM_eth1State":1,"_ZF7761CM_eth1Type":1,"_ZF7761CM_eth1UntagId":1,"_ZF7761CM_eth1VlanMembers":"1-4094","_ZF7761CM_eth1Role":0,"_ZF7761CM__authId":"","_ZF7761CM__acctId":"","_ZF7761CM__MacBypass":0,"_ZF7761CM__supplicantType":"mac","_ZF7761CM__SpUsername":"","_ZF7761CM__SpPassword":"","_ZF7761CM_LLDPEnable":0,"_ZF7761CM_LLDPAdInterval":30,"_ZF7761CM_LLDPHoldTime":120,"_ZF7761CM_LLDPMgmtEnable":0,"_ZF7962_eth0State":1,"_ZF7962__lanPortCount":2,"_ZF7962_eth0ProfileId":0,"_ZF7962_eth0OverwriteVlan":0,"_ZF7962_eth0Type":1,"_ZF7962_eth0UntagId":1,"_ZF7962_eth0VlanMembers":"1-4094","_ZF7962_eth0Role":0,"_ZF7962_eth1ProfileId":0,"_ZF7962_eth1OverwriteVlan":0,"_ZF7962_eth1State":1,"_ZF7962_eth1Type":1,"_ZF7962_eth1UntagId":1,"_ZF7962_eth1VlanMembers":"1-4094","_ZF7962_eth1Role":0,"_ZF7962__authId":"","_ZF7962__acctId":"","_ZF7962__MacBypass":0,"_ZF7962__supplicantType":"mac","_ZF7962__SpUsername":"","_ZF7962__SpPassword":"","_ZF7962_LLDPEnable":0,"_ZF7962_LLDPAdInterval":30,"_ZF7962_LLDPHoldTime":120,"_ZF7962_LLDPMgmtEnable":0,"_ZF7982_ledStatus":1,"_ZF7982__lanPortCount":2,"_ZF7982_eth0ProfileId":0,"_ZF7982_eth0OverwriteVlan":0,"_ZF7982_eth0State":1,"_ZF7982_eth0Type":1,"_ZF7982_eth0UntagId":1,"_ZF7982_eth0VlanMembers":"1-4094","_ZF7982_eth0Role":0,"_ZF7982_eth1ProfileId":0,"_ZF7982_eth1OverwriteVlan":0,"_ZF7982_eth1State":1,"_ZF7982_eth1Type":1,"_ZF7982_eth1UntagId":1,"_ZF7982_eth1VlanMembers":"1-4094","_ZF7982_eth1Role":0,"_ZF7982__authId":"","_ZF7982__acctId":"","_ZF7982__MacBypass":0,"_ZF7982__supplicantType":"mac","_ZF7982__SpUsername":"","_ZF7982__SpPassword":"","_ZF7982_LLDPEnable":0,"_ZF7982_LLDPAdInterval":30,"_ZF7982_LLDPHoldTime":120,"_ZF7982_LLDPMgmtEnable":0,"_SC8800S__lanPortCount":2,"_SC8800S_poeOutPort":1,"_SC8800S_ledStatus":1,"_SC8800S_wifi0ExtAnt":0,"_SC8800S_wifi0ExtAntGain":6,"_SC8800S_wifi1ExtAnt":0,"_SC8800S_wifi1ExtAntGain":5,"_SC8800S_eth0ProfileId":0,"_SC8800S_eth0OverwriteVlan":0,"_SC8800S_eth0State":1,"_SC8800S_eth0Type":1,"_SC8800S_eth0UntagId":1,"_SC8800S_eth0VlanMembers":"1-4094","_SC8800S_eth0Role":0,"_SC8800S_eth1ProfileId":0,"_SC8800S_eth1OverwriteVlan":0,"_SC8800S_eth1State":1,"_SC8800S_eth1Type":1,"_SC8800S_eth1UntagId":1,"_SC8800S_eth1VlanMembers":"1-4094","_SC8800S_eth1Role":0,"_SC8800S__authId":"","_SC8800S__acctId":"","_SC8800S__MacBypass":0,"_SC8800S__supplicantType":"mac","_SC8800S__SpUsername":"","_SC8800S__SpPassword":"","_SC8800S_LLDPEnable":0,"_SC8800S_LLDPAdInterval":30,"_SC8800S_LLDPHoldTime":120,"_SC8800S_LLDPMgmtEnable":0,"_SC8800SAC__lanPortCount":2,"_SC8800SAC_poeOutPort":0,"_SC8800SAC_ledStatus":1,"_SC8800SAC_wifi1ExtAnt":0,"_SC8800SAC_wifi1ExtAntGain":5,"_SC8800SAC_eth0ProfileId":0,"_SC8800SAC_eth0OverwriteVlan":0,"_SC8800SAC_eth0State":1,"_SC8800SAC_eth0Type":1,"_SC8800SAC_eth0UntagId":1,"_SC8800SAC_eth0VlanMembers":"1-4094","_SC8800SAC_eth0Role":0,"_SC8800SAC_eth1ProfileId":0,"_SC8800SAC_eth1OverwriteVlan":0,"_SC8800SAC_eth1State":1,"_SC8800SAC_eth1Type":1,"_SC8800SAC_eth1UntagId":1,"_SC8800SAC_eth1VlanMembers":"1-4094","_SC8800SAC_eth1Role":0,"_SC8800SAC__authId":"","_SC8800SAC__acctId":"","_SC8800SAC__MacBypass":0,"_SC8800SAC__supplicantType":"mac","_SC8800SAC__SpUsername":"","_SC8800SAC__SpPassword":"","_SC8800SAC_LLDPEnable":0,"_SC8800SAC_LLDPAdInterval":30,"_SC8800SAC_LLDPHoldTime":120,"_SC8800SAC_LLDPMgmtEnable":0,"_ZF7782__lanPortCount":2,"_ZF7782_poeOutPort":1,"_ZF7782_ledStatus":1,"_ZF7782_eth0ProfileId":0,"_ZF7782_eth0OverwriteVlan":0,"_ZF7782_eth0State":1,"_ZF7782_eth0Type":1,"_ZF7782_eth0UntagId":1,"_ZF7782_eth0VlanMembers":"1-4094","_ZF7782_eth0Role":0,"_ZF7782_eth1ProfileId":0,"_ZF7782_eth1OverwriteVlan":0,"_ZF7782_eth1State":1,"_ZF7782_eth1Type":1,"_ZF7782_eth1UntagId":1,"_ZF7782_eth1VlanMembers":"1-4094","_ZF7782_eth1Role":0,"_ZF7782__authId":"","_ZF7782__acctId":"","_ZF7782__MacBypass":0,"_ZF7782__supplicantType":"mac","_ZF7782__SpUsername":"","_ZF7782__SpPassword":"","_ZF7782_LLDPEnable":0,"_ZF7782_LLDPAdInterval":30,"_ZF7782_LLDPHoldTime":120,"_ZF7782_LLDPMgmtEnable":0,"_ZF7782N__lanPortCount":2,"_ZF7782N_poeOutPort":1,"_ZF7782N_ledStatus":1,"_ZF7782N_eth0ProfileId":0,"_ZF7782N_eth0OverwriteVlan":0,"_ZF7782N_eth0State":1,"_ZF7782N_eth0Type":1,"_ZF7782N_eth0UntagId":1,"_ZF7782N_eth0VlanMembers":"1-4094","_ZF7782N_eth0Role":0,"_ZF7782N_eth1ProfileId":0,"_ZF7782N_eth1OverwriteVlan":0,"_ZF7782N_eth1State":1,"_ZF7782N_eth1Type":1,"_ZF7782N_eth1UntagId":1,"_ZF7782N_eth1VlanMembers":"1-4094","_ZF7782N_eth1Role":0,"_ZF7782N__authId":"","_ZF7782N__acctId":"","_ZF7782N__MacBypass":0,"_ZF7782N__supplicantType":"mac","_ZF7782N__SpUsername":"","_ZF7782N__SpPassword":"","_ZF7782N_LLDPEnable":0,"_ZF7782N_LLDPAdInterval":30,"_ZF7782N_LLDPHoldTime":120,"_ZF7782N_LLDPMgmtEnable":0,"_ZF7782S__lanPortCount":2,"_ZF7782S_poeOutPort":1,"_ZF7782S_ledStatus":1,"_ZF7782S_eth0ProfileId":0,"_ZF7782S_eth0OverwriteVlan":0,"_ZF7782S_eth0State":1,"_ZF7782S_eth0Type":1,"_ZF7782S_eth0UntagId":1,"_ZF7782S_eth0VlanMembers":"1-4094","_ZF7782S_eth0Role":0,"_ZF7782S_eth1ProfileId":0,"_ZF7782S_eth1OverwriteVlan":0,"_ZF7782S_eth1State":1,"_ZF7782S_eth1Type":1,"_ZF7782S_eth1UntagId":1,"_ZF7782S_eth1VlanMembers":"1-4094","_ZF7782S_eth1Role":0,"_ZF7782S__authId":"","_ZF7782S__acctId":"","_ZF7782S__MacBypass":0,"_ZF7782S__supplicantType":"mac","_ZF7782S__SpUsername":"","_ZF7782S__SpPassword":"","_ZF7782S_LLDPEnable":0,"_ZF7782S_LLDPAdInterval":30,"_ZF7782S_LLDPHoldTime":120,"_ZF7782S_LLDPMgmtEnable":0,"_ZF7782E__lanPortCount":2,"_ZF7782E_poeOutPort":1,"_ZF7782E_ledStatus":1,"_ZF7782E_wifi0ExtAnt":1,"_ZF7782E_wifi0ExtAntGain":5,"_ZF7782E_wifi0ExtAntChainMask":7,"_ZF7782E_wifi1ExtAnt":1,"_ZF7782E_wifi1ExtAntGain":5,"_ZF7782E_wifi1ExtAntChainMask":7,"_ZF7782E_eth0ProfileId":0,"_ZF7782E_eth0OverwriteVlan":0,"_ZF7782E_eth0State":1,"_ZF7782E_eth0Type":1,"_ZF7782E_eth0UntagId":1,"_ZF7782E_eth0VlanMembers":"1-4094","_ZF7782E_eth0Role":0,"_ZF7782E_eth1ProfileId":0,"_ZF7782E_eth1OverwriteVlan":0,"_ZF7782E_eth1State":1,"_ZF7782E_eth1Type":1,"_ZF7782E_eth1UntagId":1,"_ZF7782E_eth1VlanMembers":"1-4094","_ZF7782E_eth1Role":0,"_ZF7782E__authId":"","_ZF7782E__acctId":"","_ZF7782E__MacBypass":0,"_ZF7782E__supplicantType":"mac","_ZF7782E__SpUsername":"","_ZF7782E__SpPassword":"","_ZF7782E_LLDPEnable":0,"_ZF7782E_LLDPAdInterval":30,"_ZF7782E_LLDPHoldTime":120,"_ZF7782E_LLDPMgmtEnable":0,"_ZF7781CM_cmLedMode":7,"_ZF7781CM_internalHeater":1,"_ZF7781CM_poeOutPort":1,"_ZF7781CM_ledStatus":1,"_ZF7781CM__lanPortCount":2,"_ZF7781CM_eth0ProfileId":0,"_ZF7781CM_eth0OverwriteVlan":0,"_ZF7781CM_eth0State":1,"_ZF7781CM_eth0Type":1,"_ZF7781CM_eth0UntagId":1,"_ZF7781CM_eth0VlanMembers":"1-4094","_ZF7781CM_eth0Role":0,"_ZF7781CM_eth1ProfileId":0,"_ZF7781CM_eth1OverwriteVlan":0,"_ZF7781CM_eth1State":1,"_ZF7781CM_eth1Type":1,"_ZF7781CM_eth1UntagId":1,"_ZF7781CM_eth1VlanMembers":"1-4094","_ZF7781CM_eth1Role":0,"_ZF7781CM__authId":"","_ZF7781CM__acctId":"","_ZF7781CM__MacBypass":0,"_ZF7781CM__supplicantType":"mac","_ZF7781CM__SpUsername":"","_ZF7781CM__SpPassword":"","_ZF7781CM_LLDPEnable":0,"_ZF7781CM_LLDPAdInterval":30,"_ZF7781CM_LLDPHoldTime":120,"_ZF7781CM_LLDPMgmtEnable":0,"_ZF7352_eth0State":1,"_ZF7352__lanPortCount":2,"_ZF7352_eth0ProfileId":0,"_ZF7352_eth0OverwriteVlan":0,"_ZF7352_eth0Type":1,"_ZF7352_eth0UntagId":1,"_ZF7352_eth0VlanMembers":"1-4094","_ZF7352_eth0Role":0,"_ZF7352_eth1ProfileId":0,"_ZF7352_eth1OverwriteVlan":0,"_ZF7352_eth1State":1,"_ZF7352_eth1Type":1,"_ZF7352_eth1UntagId":1,"_ZF7352_eth1VlanMembers":"1-4094","_ZF7352_eth1Role":0,"_ZF7352__authId":"","_ZF7352__acctId":"","_ZF7352__MacBypass":0,"_ZF7352__supplicantType":"mac","_ZF7352__SpUsername":"","_ZF7352__SpPassword":"","_ZF7352_ledStatus":1,"_ZF7352_LLDPEnable":0,"_ZF7352_LLDPAdInterval":30,"_ZF7352_LLDPHoldTime":120,"_ZF7352_LLDPMgmtEnable":0,"_ZF7372_eth0State":1,"_ZF7372__lanPortCount":2,"_ZF7372_eth0ProfileId":0,"_ZF7372_eth0OverwriteVlan":0,"_ZF7372_eth0Type":1,"_ZF7372_eth0UntagId":1,"_ZF7372_eth0VlanMembers":"1-4094","_ZF7372_eth0Role":0,"_ZF7372_eth1ProfileId":0,"_ZF7372_eth1OverwriteVlan":0,"_ZF7372_eth1State":1,"_ZF7372_eth1Type":1,"_ZF7372_eth1UntagId":1,"_ZF7372_eth1VlanMembers":"1-4094","_ZF7372_eth1Role":0,"_ZF7372__authId":"","_ZF7372__acctId":"","_ZF7372__MacBypass":0,"_ZF7372__supplicantType":"mac","_ZF7372__SpUsername":"","_ZF7372__SpPassword":"","_ZF7372_ledStatus":1,"_ZF7372_LLDPEnable":0,"_ZF7372_LLDPAdInterval":30,"_ZF7372_LLDPHoldTime":120,"_ZF7372_LLDPMgmtEnable":0,"_ZF7372E_ledStatus":1,"_ZF7372E_wifi0ExtAnt":1,"_ZF7372E_wifi0ExtAntGain":2,"_ZF7372E_wifi1ExtAnt":1,"_ZF7372E_wifi1ExtAntGain":3,"_ZF7372E_eth0State":1,"_ZF7372E__lanPortCount":2,"_ZF7372E_eth0ProfileId":0,"_ZF7372E_eth0OverwriteVlan":0,"_ZF7372E_eth0Type":1,"_ZF7372E_eth0UntagId":1,"_ZF7372E_eth0VlanMembers":"1-4094","_ZF7372E_eth0Role":0,"_ZF7372E_eth1ProfileId":0,"_ZF7372E_eth1OverwriteVlan":0,"_ZF7372E_eth1State":1,"_ZF7372E_eth1Type":1,"_ZF7372E_eth1UntagId":1,"_ZF7372E_eth1VlanMembers":"1-4094","_ZF7372E_eth1Role":0,"_ZF7372E__authId":"","_ZF7372E__acctId":"","_ZF7372E__MacBypass":0,"_ZF7372E__supplicantType":"mac","_ZF7372E__SpUsername":"","_ZF7372E__SpPassword":"","_ZF7372E_LLDPEnable":0,"_ZF7372E_LLDPAdInterval":30,"_ZF7372E_LLDPHoldTime":120,"_ZF7372E_LLDPMgmtEnable":0,"_ZF7441_ledStatus":1,"_ZF7441_wifi0ExtAnt":1,"_ZF7441_wifi0ExtAntGain":5,"_ZF7441_eth0State":1,"_ZF7441__lanPortCount":1,"_ZF7441_eth0ProfileId":0,"_ZF7441_eth0OverwriteVlan":0,"_ZF7441_eth0Type":1,"_ZF7441_eth0UntagId":1,"_ZF7441_eth0VlanMembers":"1-4094","_ZF7441_eth0Role":0,"_ZF7441__authId":"","_ZF7441__acctId":"","_ZF7441__MacBypass":0,"_ZF7441__supplicantType":"mac","_ZF7441__SpUsername":"","_ZF7441__SpPassword":"","_ZF7441_LLDPEnable":0,"_ZF7441_LLDPAdInterval":30,"_ZF7441_LLDPHoldTime":120,"_ZF7441_LLDPMgmtEnable":0,"_ZF7441_radioBand":"2.4","_R300_ledStatus":1,"_R300__lanPortCount":1,"_R300_eth0ProfileId":0,"_R300_eth0OverwriteVlan":0,"_R300_eth0State":1,"_R300_eth0Type":1,"_R300_eth0UntagId":1,"_R300_eth0VlanMembers":"1-4094","_R300_eth0Role":0,"_R300__authId":"","_R300__acctId":"","_R300__MacBypass":0,"_R300__supplicantType":"mac","_R300__SpUsername":"","_R300__SpPassword":"","_R300_LLDPEnable":0,"_R300_LLDPAdInterval":30,"_R300_LLDPHoldTime":120,"_R300_LLDPMgmtEnable":0,"_R500_eth0State":1,"_R500_usbPowerEnable":1,"_R500__lanPortCount":2,"_R500_eth0ProfileId":0,"_R500_eth0OverwriteVlan":0,"_R500_eth0Type":1,"_R500_eth0UntagId":1,"_R500_eth0VlanMembers":"1-4094","_R500_eth0Role":0,"_R500_eth1ProfileId":0,"_R500_eth1OverwriteVlan":0,"_R500_eth1State":1,"_R500_eth1Type":1,"_R500_eth1UntagId":1,"_R500_eth1VlanMembers":"1-4094","_R500_eth1Role":0,"_R500__authId":"","_R500__acctId":"","_R500__MacBypass":0,"_R500__supplicantType":"mac","_R500__SpUsername":"","_R500__SpPassword":"","_R500_ledStatus":1,"_R500_LLDPEnable":0,"_R500_LLDPAdInterval":30,"_R500_LLDPHoldTime":120,"_R500_LLDPMgmtEnable":0,"_R600_eth0State":1,"_R600__lanPortCount":2,"_R600_eth0ProfileId":0,"_R600_eth0OverwriteVlan":0,"_R600_eth0Type":1,"_R600_eth0UntagId":1,"_R600_eth0VlanMembers":"1-4094","_R600_eth0Role":0,"_R600_eth1ProfileId":0,"_R600_eth1OverwriteVlan":0,"_R600_eth1State":1,"_R600_eth1Type":1,"_R600_eth1UntagId":1,"_R600_eth1VlanMembers":"1-4094","_R600_eth1Role":0,"_R600__authId":"","_R600__acctId":"","_R600__MacBypass":0,"_R600__supplicantType":"mac","_R600__SpUsername":"","_R600__SpPassword":"","_R600_ledStatus":1,"_R600_LLDPEnable":0,"_R600_LLDPAdInterval":30,"_R600_LLDPHoldTime":120,"_R600_LLDPMgmtEnable":0,"_R700_eth0State":1,"_R700__lanPortCount":2,"_R700_eth0ProfileId":0,"_R700_eth0OverwriteVlan":0,"_R700_eth0Type":1,"_R700_eth0UntagId":1,"_R700_eth0VlanMembers":"1-4094","_R700_eth0Role":0,"_R700_eth1ProfileId":0,"_R700_eth1OverwriteVlan":0,"_R700_eth1State":1,"_R700_eth1Type":1,"_R700_eth1UntagId":1,"_R700_eth1VlanMembers":"1-4094","_R700_eth1Role":0,"_R700__authId":"","_R700__acctId":"","_R700__MacBypass":0,"_R700__supplicantType":"mac","_R700__SpUsername":"","_R700__SpPassword":"","_R700_ledStatus":1,"_R700_LLDPEnable":0,"_R700_LLDPAdInterval":30,"_R700_LLDPHoldTime":120,"_R700_LLDPMgmtEnable":0,"_R710_usbPowerEnable":1,"_R710_eth0State":1,"_R710__lanPortCount":2,"_R710_eth0Type":1,"_R710_eth0ProfileId":0,"_R710_eth0OverwriteVlan":0,"_R710_eth0UntagId":1,"_R710_eth0VlanMembers":"1-4094","_R710_eth0Role":0,"_R710_eth1State":1,"_R710_eth1ProfileId":0,"_R710_eth1OverwriteVlan":0,"_R710_eth1Type":1,"_R710_eth1UntagId":1,"_R710_eth1VlanMembers":"1-4094","_R710_eth1Role":0,"_R710__authId":"","_R710__acctId":"","_R710__MacBypass":0,"_R710__supplicantType":"mac","_R710__SpUsername":"","_R710__SpPassword":"","_R710_ledStatus":1,"_R710_LLDPEnable":0,"_R710_LLDPAdInterval":30,"_R710_LLDPHoldTime":120,"_R710_LLDPMgmtEnable":0,"_T300__lanPortCount":1,"_T300_ledStatus":1,"_T300_eth0ProfileId":0,"_T300_eth0OverwriteVlan":0,"_T300_eth0State":1,"_T300_eth0Type":1,"_T300_eth0UntagId":1,"_T300_eth0VlanMembers":"1-4094","_T300_eth0Role":0,"_T300__authId":"","_T300__acctId":"","_T300__MacBypass":0,"_T300__supplicantType":"mac","_T300__SpUsername":"","_T300__SpPassword":"","_T300_LLDPEnable":0,"_T300_LLDPAdInterval":30,"_T300_LLDPHoldTime":120,"_T300_LLDPMgmtEnable":0,"_T301N__lanPortCount":1,"_T301N_ledStatus":1,"_T301N_eth0ProfileId":0,"_T301N_eth0OverwriteVlan":0,"_T301N_eth0State":1,"_T301N_eth0Type":1,"_T301N_eth0UntagId":1,"_T301N_eth0VlanMembers":"1-4094","_T301N_eth0Role":0,"_T301N__authId":"","_T301N__acctId":"","_T301N__MacBypass":0,"_T301N__supplicantType":"mac","_T301N__SpUsername":"","_T301N__SpPassword":"","_T301N_LLDPEnable":0,"_T301N_LLDPAdInterval":30,"_T301N_LLDPHoldTime":120,"_T301N_LLDPMgmtEnable":0,"_T301S__lanPortCount":1,"_T301S_ledStatus":1,"_T301S_eth0ProfileId":0,"_T301S_eth0OverwriteVlan":0,"_T301S_eth0State":1,"_T301S_eth0Type":1,"_T301S_eth0UntagId":1,"_T301S_eth0VlanMembers":"1-4094","_T301S_eth0Role":0,"_T301S__authId":"","_T301S__acctId":"","_T301S__MacBypass":0,"_T301S__supplicantType":"mac","_T301S__SpUsername":"","_T301S__SpPassword":"","_T301S_LLDPEnable":0,"_T301S_LLDPAdInterval":30,"_T301S_LLDPHoldTime":120,"_T301S_LLDPMgmtEnable":0,"_T300E__lanPortCount":1,"_T300E_wifi1ExtAnt":0,"_T300E_wifi1ExtAntGain":5,"_T300E_ledStatus":1,"_T300E_usbPowerEnable":1,"_T300E_eth0ProfileId":0,"_T300E_eth0OverwriteVlan":0,"_T300E_eth0State":1,"_T300E_eth0Type":1,"_T300E_eth0UntagId":1,"_T300E_eth0VlanMembers":"1-4094","_T300E_eth0Role":0,"_T300E__authId":"","_T300E__acctId":"","_T300E__MacBypass":0,"_T300E__supplicantType":"mac","_T300E__SpUsername":"","_T300E__SpPassword":"","_T300E_LLDPEnable":0,"_T300E_LLDPAdInterval":30,"_T300E_LLDPHoldTime":120,"_T300E_LLDPMgmtEnable":0,"_FZM300__lanPortCount":1,"_FZM300_ledStatus":1,"_FZM300_wifi0ExtAnt":1,"_FZM300_wifi0ExtAntGain":5,"_FZM300_wifi1ExtAnt":1,"_FZM300_wifi1ExtAntGain":5,"_FZM300_eth0ProfileId":0,"_FZM300_eth0OverwriteVlan":0,"_FZM300_eth0State":1,"_FZM300_eth0Type":1,"_FZM300_eth0UntagId":1,"_FZM300_eth0VlanMembers":"1-4094","_FZM300_eth0Role":0,"_FZM300__authId":"","_FZM300__acctId":"","_FZM300__MacBypass":0,"_FZM300__supplicantType":"mac","_FZM300__SpUsername":"","_FZM300__SpPassword":"","_FZM300_LLDPEnable":0,"_FZM300_LLDPAdInterval":30,"_FZM300_LLDPHoldTime":120,"_FZM300_LLDPMgmtEnable":0,"_FZP300__lanPortCount":1,"_FZP300_ledStatus":1,"_FZP300_eth0ProfileId":0,"_FZP300_eth0OverwriteVlan":0,"_FZP300_eth0State":1,"_FZP300_eth0Type":1,"_FZP300_eth0UntagId":1,"_FZP300_eth0VlanMembers":"1-4094","_FZP300_eth0Role":0,"_FZP300__authId":"","_FZP300__acctId":"","_FZP300__MacBypass":0,"_FZP300__supplicantType":"mac","_FZP300__SpUsername":"","_FZP300__SpPassword":"","_FZP300_LLDPEnable":0,"_FZP300_LLDPAdInterval":30,"_FZP300_LLDPHoldTime":120,"_FZP300_LLDPMgmtEnable":0,"_C500_ledStatus":1,"_C500__lanPortCount":2,"_C500_eth0State":1,"_C500_eth0Type":1,"_C500_eth0ProfileId":0,"_C500_eth0OverwriteVlan":0,"_C500_eth0UntagId":1,"_C500_eth0VlanMembers":"1-4094","_C500_eth0Role":0,"_C500_eth1State":1,"_C500_eth1Type":1,"_C500_eth1ProfileId":0,"_C500_eth1OverwriteVlan":0,"_C500_eth1UntagId":1,"_C500_eth1VlanMembers":"1-4094","_C500_eth1Role":0,"_C500__authId":"","_C500__acctId":"","_C500__MacBypass":0,"_C500__supplicantType":"mac","_C500__SpUsername":"","_C500__SpPassword":"","_C500_LLDPEnable":0,"_C500_LLDPAdInterval":30,"_C500_LLDPHoldTime":120,"_C500_LLDPMgmtEnable":0}}
        return zone_data

    def get_wlan_template_data(self):

        wlan_data = {"mobilityZoneUUID":"f0a0e5ee-a706-4ce4-808b-887009fa5fa3",
                    "key":"",
                    "zoneName":"",
                    "devicePolicyId": "",
                    "l2AccessControlId": "",
                    "dpskEnabled": False,
                    "enableBandBalancingShield": False,
                    "configContent":{"Availability":1,
                                     "_enableWlan":1,
                                     "hessid": "",
                                     "OperatorRealm":"",
                                     "_MFP": "disabled",
                                     "RoamEnable":0,
                                     "RoamFactor24G":1,
                                     "RoamFactor5G":1,
                                     "STAIssolation":1,
                                     "Priority":"high",
                                     "RatePerStaUplink":"0",
                                     "RatePerStaDnlink":"0",
                                     "VlanId":1,"ProxyARP":1,
                                     "DhcpOp82":1, "DVlanEnabled":1, "acctTTGSession":0,
                                     "AcctDelayTime":0,"BroadcastSSID":1,"80211d":0,"IgnoreUnauth":0,
                                     "STAInfoExtraction":0, "MacAuthBypass":0,"MacAuthPasswordType":0,"MacAuthPassword":"", 
                                     "MacAuthUsernameType":0,"_userTrafficProfileId":"",
                                      "_l2AccessControlId": "",
						            "_devicePolicyId": "",
						            "dscpProfileId":"",
						            "EnableType": 0,
						            "RFC5580SupportEnabled": 0,
						            "ClbEnable": 1,
						            "ForceClientDhcpEnable": 0,
						            "PMKEnable": 0,
						            "OKCEnable": 0,
						            "WlanSchedulerId": "",
						            "_QosMap": {}}}
        return wlan_data

    def get_wlan_template_data_update(self):
        wlan_data = {"mobilityZoneUUID":"",
                    "key":None,
                    "zoneName":"",
                   "devicePolicyId": "",
                   "l2AccessControlId": "",
                   "dpskEnabled": False,
                   "enableBandBalancingShield": False,
                        "configContent":{"Availability":1,
                                     "_enableWlan":1,
                                     "TunnelEnabled":0,
                                     "hessid": "",
                                     "OperatorRealm":"",
                                     "_MFP": "disabled",
                                     "coreNetworkType":"Bridge",
                                     "RoamEnable":0,
                                     "RoamFactor24G":1,
                                     "RoamFactor5G":1,
                                     "STAIssolation":1,
                                     "Priority":"high",
                                     #"RatePerStaUplink":"0",
                                     #"RatePerStaDnlink":"0",
                                     "VlanId":None,"ProxyARP":0,
                                     "DhcpOp82":0,
                                     "DVlanEnabled":0,
                                     "acctTTGSession":0,
                                     "AcctDelayTime":0,
                                     "BroadcastSSID":1,
                                     "80211d":0,
                                     "IgnoreUnauth":0,
                                     "STAInfoExtraction":None,
                                     "MacAuthBypass":0,
                                     "MacAuthPasswordType":0,
                                     "MacAuthPassword":"",
                                     "MacAuthUsernameType":0,
                                     "_userTrafficProfileId":"",
                                     "_l2AccessControlId": "",
						            "_devicePolicyId": "",
						            "dscpProfileId":"",
						            "EnableType": 0,
						            "RFC5580SupportEnabled": 0,
						            "ClbEnable": 1,
						            "ForceClientDhcpEnable": 1,
						            "PMKEnable": 0,
						            "OKCEnable": 0,
						            "WlanSchedulerId": "",
						            "_QosMap": {}}}
        return wlan_data

    def get_mvno_template_data(self):

        mvno_data = {"name":"",
                     "description":"",
                        "apZoneUUIDList":[],
                        "wlanUUIDList":[],
                        "superAdmin": {"userName": "",
                                       "realName": "",
                                       "title": "",
                                       "phone": "",
                                       "email": "",
                                       "passphrase": ""},
                        #"superAdminRole": {"capabilities": ["viewWLANConfiguration","editWLANConfiguration","viewWLANTemplate","createWLANTemplate","editWLANTemplate","deleteWLANTemplate","viewRADIUSServer","createRADIUSServer","editRADIUSServer","deleteRADIUSServer","viewDHCPServer","createDHCPServer","editDHCPServer","deleteDHCPServer","viewGGSNConfigurations","updateGGSNConfigurations","viewCGF","createCGF","editCGF","deleteCGF","viewftpService","editftpService","createftpService","deleteftpService","viewHLRMncNdc","editHLRMncNdc","viewHLR","createHLR","editHLR","deleteHLR","viewAuthenticationServiceProfile","createAuthenticationServiceProfile","editAuthenticationServiceProfile","deleteAuthenticationServiceProfile","viewAuthorizationServiceProfile","createAuthorizationServiceProfile","editAuthorizationServiceProfile","deleteAuthorizationServiceProfile","viewAccountingServiceProfile","createAccountingServiceProfile","editAccountingServiceProfile","deleteAccountingServiceProfile","viewForwardingServiceProfile","createForwardingServiceProfile","editForwardingServiceProfile","deleteForwardingServiceProfile","viewDiameterSystemWideSettings","updateDiameterSystemWideSettings","viewDiameterRemotePeerConfiguration","editDiameterRemotePeerConfiguration","createDiameterRemotePeerConfiguration","deleteDiameterRemotePeerConfiguration","viewPackages","createPackages","editPackages","deletePackages","viewManagementDomain","createManagementDomain","editManagementDomain","deleteManagementDomain","viewAdministratorAccount","createAdministratorAccount","editAdministratorAccount","deleteAdministratorAccount","viewAdministratorRole","createAdministratorRole","editAdministratorRole","deleteAdministratorRole","viewAdminAAAServer","createAdminAAAServer","editAdminAAAServer","deleteAdminAAAServer","viewZoneStatus","viewZoneMeshTopology","viewAPStatus","viewAPEvents","viewAPAlarms","viewClientStatus","viewClientEvents","viewAuditLog","viewReport","createReport","editReport","deleteReport","runReport","viewHistoricalClientStatistics","viewCoreNetworkTunnelStatistics","viewIdentityProfile","createIdentityProfile","editIdentityProfile","deleteIdentityProfile","guestPassService","guestPassManage","mvnoDiagnosticsStatistics"]},
                        "superAdminRole": {"capabilities": ["viewWLANConfiguration","editWLANConfiguration","viewWLANTemplate","createWLANTemplate","editWLANTemplate","deleteWLANTemplate","viewAuthService","createAuthService","editAuthService","deleteAuthService","viewAcctService","createAcctService","editAcctService","deleteAcctService","viewRADIUSServer","createRADIUSServer","editRADIUSServer","deleteRADIUSServer","viewDHCPServer","createDHCPServer","editDHCPServer","deleteDHCPServer","viewGGSNConfigurations","updateGGSNConfigurations","viewCGF","createCGF","editCGF","deleteCGF","viewftpService","createftpService","editftpService","deleteftpService","viewSmsServerConfigurations","updateSmsServerConfigurations","viewHLRMncNdc","editHLRMncNdc","viewHLR","createHLR","editHLR","deleteHLR","viewAuthenticationServiceProfile","createAuthenticationServiceProfile","editAuthenticationServiceProfile","deleteAuthenticationServiceProfile","viewAccountingServiceProfile","createAccountingServiceProfile","editAccountingServiceProfile","deleteAccountingServiceProfile","viewForwardingServiceProfile","createForwardingServiceProfile","editForwardingServiceProfile","deleteForwardingServiceProfile","viewManagementDomain","createManagementDomain","editManagementDomain","deleteManagementDomain","viewAdministratorAccount","createAdministratorAccount","editAdministratorAccount","deleteAdministratorAccount","viewAdministratorRole","createAdministratorRole","editAdministratorRole","deleteAdministratorRole","viewAdminAAAServer","createAdminAAAServer","editAdminAAAServer","deleteAdminAAAServer","viewZoneStatus","viewZoneMeshTopology","viewAPStatus","viewAPEvents","viewAPAlarms","viewClientStatus","viewClientEvents","viewAuditLog","viewReport","createReport","editReport","deleteReport","runReport","viewHistoricalClientStatistics","viewCoreNetworkTunnelStatistics","viewIdentityUsers","createIdentityUsers","editIdentityUsers","deleteIdentityUsers","guestPassService","guestPassManage","viewIdentityUserRole","createIdentityUserRole","editIdentityUserRole","deleteIdentityUserRole","viewPackages","createPackages","editPackages","deletePackages","mvnoDiagnosticsStatistics"]},

                        "aaaServers": []}

        return mvno_data


    def add_mvno_template_data(self):
        mvno_data = {"name":"",
                      "description":"",
                        "apZoneUUIDList":[],
                        "wlanUUIDList":[],
                        "superAdmin": {"userName": "",
                                       "realName": "",
                                       "title": "",
                                       "phone": "",
                                       "email": "",
                                       "passphrase": ""},
                        "superAdminRole":{"capabilities": []},
                        "aaaServers": []}

        return mvno_data

    def get_guest_access_template(self):
        guest_access = {"zoneUUID":"",
                        "name":"TEST",
                        "description":"",
                        "language":"en_US",
                        "key":"",
                        "bridgeMode":1,
                        "secondRedirect":"user",
                        "smsGatewayId":"",
                        "title":"",
                        "sessionTime":1440,
                        "gracePeriod":60,
                        "termsAndConditionsEnabled":False,
                        "zoneName":"Auto-1-hegde",
                        "logoFileName":"",
                        "startUrl":""}
        return guest_access

    def get_web_auth_template(self):
        web_auth_data = {"zoneUUID":"",
                "name":"TEST",
                "description":"",
                "language":"en_US",
                "key":"",
                "bridgeMode":1,
                "secondRedirect":"user",
                "sessionTime":1440,
                "gracePeriod":60,
                "zoneName":"",
                "startUrl":""}
        return web_auth_data


