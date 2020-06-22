'''
NOTE:::: #######################Fetch the corresponding id of the device below and give the id as the input to "dev_details"b variable in PublicApiVariables.py####################################################
	48 -> MacBookPro
	49 -> MacBoookAir
	50 -> MacBookProNew
	51 -> iMac
	52 -> MacPro
	53 -> Macmini
'''
mac_details_dict = {
################################################# Mac Device list ######################################################
		48 : [{'serialid':'NA'},{'name':'MacBookPro'},{'mac':'24:f0:94:e5:db:f4'},{'alias':'mac1'},{'ports':"4802"},{'ios_devicename':None},{'MAC_IP':'11.1.5.41'},{'WIN_IP':'NA'},{'WIN_USR':'NA'},{'WIN_PWD':'NA'},{'ios_version':'NA'}],  
		49 : [{'name':'MacBookAir'},{'mac':'5c:f9:38:9d:1a:ea'},{'alias':'mac2'},{'ports':"4803"},{'MAC_IP':'11.1.5.85'},{'username':'aricentwifi'},{'password':'Password1'}],
		50 : [{'name':'MacBookProNew'},{'mac':'f4:0f:24:2b:b8:85'},{'alias':'mac3'},{'ports':"4804"},{'MAC_IP':'11.1.5.45'},{'username':'it'},{'password':'Password1'}],
		51 : [{'name':'iMac'},{'mac':'88:63:df:a7:11:01'},{'alias':'mac4'},{'ports':"4805"},{'MAC_IP':'11.1.5.113'},{'username':'administrator'},{'password':'Password1'}],
		52 : [{'name':'MacPro'},{'mac':'60:f4:45:ea:70:c8'},{'alias':'mac5'},{'ports':"4806"},{'MAC_IP':'11.1.5.83'},{'username':'aricentwifi'},{'password':'Password1'}],
		53 : [{'name':'Macmini'},{'mac':'bc:54:36:cd:a9:ee'},{'alias':'mac6'},{'ports':"4807"},{'MAC_IP':'11.1.5.44'},{'username':'macmini'},{'password':'Password1'}],
		61 : [{'name':'MacBookAirNew'},{'mac':'30:35:ad:a8:9c:66'},{'alias':'mac7'},{'ports':"4808"},{'MAC_IP':'50.1.1.18'},{'username':'aricentwifi'},{'password':'Password1'}]
}
