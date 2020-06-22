from qattg.coreapi.common.ScgJsonLogin import ScgJsonLogin
import qa.ttgcommon.coreapi.common.json_interface as ji

import traceback

class ScgStatistics():
    """
    Class contains APIs used to get the Statistics of SCG and Filtering of data 

    """
    def __init__(self, scg_mgmt_ip='127.0.0.1', scg_port='8443'):
        """
        Initializing parameters
        """
        self.req_api_hlr_stat = '/wsg/api/scg/diagnostics/stats/hlr?'
        self.req_api_sctp_assc = '/wsg/api/scg/diagnostics/stats/hlr/sctpAssociation?'
        self.req_api_cgf_trans = '/wsg/api/scg/diagnostics/stats/cgf/transaction?'
        self.req_cgf_connect = '/wsg/api/scg/diagnostics/stats/cgf/connectivity?'
        self.req_api_dhcp_server = '/wsg/api/scg/diagnostics/stats/dhcp/cp?' 
        self.req_api_dhcp_relaty = '/wsg/api/scg/diagnostics/stats/dhcp/dp?'
        self.req_api_ggsn_conn = ' /wsg/api/scg/diagnostics/stats/ggsn/connection?'
        self.req_api_ggsn_pgw = '/wsg/api/scg/diagnostics/stats/ggsn/gtpc?'
        self.req_api_radius_server = '/wsg/api/scg/diagnostics/stats/radius/server?'
        self.req_api_radius_proxy = '/wsg/api/scg/diagnostics/stats/radius/proxy?'
        self.req_api_lma_signal = '/wsg/api/scg/diagnostics/stats/lma/signaling?'
        self.req_api_lma_conn = '/wsg/api/scg/diagnostics/stats/lma/connectivity?'
        self.jsessionid = ''
        self.scg_mgmt_ip = scg_mgmt_ip
        self.scg_port = scg_port

    def _login(self, username='admin', password='ruckus', **kwargs):

        l = ScgJsonLogin()
        result, self.jsessionid = l.login(scg_mgmt_ip=self.scg_mgmt_ip, scg_port=self.scg_port,
                username=username, password=password)
        print "SCG Login: jsessionid: %s" % self.jsessionid
        return result

    def set_jsessionid(self, jsessionid):
        self.jsessionid = jsessionid

    def get_jsessionid(self):
        return self.jsessionid

    def get_hlr_statistics(self):
        """
        API used to get HLR Statistics

        URI: GET /wsg/api/scg/diagnostics/stats/hlr?
        """

        try:
            url = ji.get_url(self.req_api_hlr_stat, self.scg_mgmt_ip, self.scg_port)
            rcvd_data = ji.get_json_data(url, self.jsessionid)

            if not rcvd_data:
                raise Exception("get_hlr_statistics(): No recieved data")
                return False

            return rcvd_data

        except Exception, e:
            print traceback.format_exc()
            return False

    def get_hlr_statistics_by_mvno_name(self, mvno_name=None):
        """
        API used to Filter HLR statastics by mvno name
        """

        is_entry = False
        rcvd_data = self.get_hlr_statistics()

        li = []
        if mvno_name:
            for i in range(0, len(rcvd_data['data']['list'])):
                if rcvd_data['data']['list'][i]['mvnoName'] == mvno_name:
                    is_entry = True
                    li.append(rcvd_data['data']['list'][i])

            if not is_entry:
                print "get_hlr_statistics_by_mvno_name(): Mvno name %s not found" % (mvno_name)
                return False

            return li

        else:
            return rcvd_data

    def get_hlr_statistics_by_cblade_name(self, mvno_name=None, cblade_name=None):

        is_entry = False
        rcvd_data = self.get_hlr_statistics_by_mvno_name(mvno_name)

        li = []
        if cblade_name:
            for i in range(0, len(rcvd_data)):
                if rcvd_data[i]['cBladeName'] == cblade_name:
                    is_entry = True
                    li.append(rcvd_data[i])

            if not is_entry:
                print "get_hlr_statistics_by_cblade_name(): cblade_name %s not found" % cblade_name
                return False

            return li

        else:
            return rcvd_data


    def get_hlr_statistics_by_hlr_name(self, mvno_name=None, cblade_name=None, hlr_service_name=None):

        is_entry = False
        rcvd_data = self.get_hlr_statistics_by_cblade_name(mvno_name, cblade_name)

        li = []
        if hlr_service_name:
            for i in range(0, len(rcvd_data)):
                if rcvd_data[i]["hlrSrvcName"] == hlr_service_name:
                    is_entry = True
                    li.append(rcvd_data[i])

            if not is_entry:
                print "get_hlr_statistics_by_hlr_name(): hlr_service_name %s not found" % hlr_service_name
                return False

            return li

        else:
            return rcvd_data


    def get_hlr_statistics_by_create_time(self, hlr_service_name=None, mvno_name=None, cblade_name=None, create_time=None):

        is_entry = False

        rcvd_data = self.get_hlr_statistics_by_hlr_name(hlr_service_name=hlr_service_name,mvno_name=mvno_name, 
                cblade_name=cblade_name)

        li = []
        if create_time:
            _crt_time = int(create_time) * 1000
            for i in range(0, len(rcvd_data)):
                if rcvd_data[i]['recCrtTime'] == _crt_time:
                    is_entry = True
                    li.append(rcvd_data[i])

            if not is_entry:
                print "get_hlr_statistics_by_create_time(): create_time %s not found" % create_time
                return False

            return li

        else:
            return rcvd_data

    def get_hlr_statistics_by_modified_time(self, hlr_service_name=None, mvno_name=None, cblade_name=None,
                                                   create_time=None, modified_time=None):

        is_entry = False
        rcvd_data = self.get_hlr_statistics_by_create_time(hlr_service_name=hlr_service_name, mvno_name=mvno_name,
                cblade_name=cblade_name, create_time=create_time)

        li = []
        if modified_time:
            _mod_time = int(modified_time) * 1000
            for i in range(0, len(rcvd_data)):
                if rcvd_data[i]['recUpdTime'] == _mod_time:
                    is_entry = True
                    li.append(rcvd_data[i])

            if not is_entry:
                print "get_hlr_statistics_by_create_time(): create_time %s not found" % create_time
                return False

            print "hello method_modified time", li
            return li

        else:
            return rcvd_data



    def get_sctp_associations(self):
        """
        API used to get SCTP Association Statistics

        URI: GET /wsg/api/scg/diagnostics/stats/hlr/sctpAssociation?
        """
        try:
            url = ji.get_url(self.req_api_sctp_assc, self.scg_mgmt_ip, self.scg_port)
            rcvd_data = ji.get_json_data(url, self.jsessionid)
            return rcvd_data

        except Exception, e:
            print traceback.format_exc()
            return False

    def get_cgf_transactions(self):
        """
        API used to get CGF Transaction Statistics

        URI: GET /wsg/api/scg/diagnostics/stats/cgf/transaction?
        """

        try:
            url = ji.get_url(self.req_api_cgf_trans, self.scg_mgmt_ip, self.scg_port)
            rcvd_data = ji.get_json_data(url, self.jsessionid)
            return rcvd_data

        except Exception, e:
            print traceback.format_exc()
            return False

    def get_cgf_connectivity(self):
        """
        API used to get CGF Connectivity Statistics

        URI: GET /wsg/api/scg/diagnostics/stats/cgf/connectivity?
        """
        try:
            url = ji.get_url(self.req_api_cgf_connect, self.scg_mgmt_ip, self.scg_port)
            rcvd_data = ji.get_json_data(url, self.jsessionid)
            return rcvd_data

        except Exception, e:
            print traceback.format_exc()
            return False

    def get_dhcp_server_stat(self):
        """
        API used to get DHCP Server Statistics

        URI: GET /wsg/api/scg/diagnostics/stats/dhcp/cp?
        """
        try:
            url = ji.get_url(self.req_api_dhcp_server, self.scg_mgmt_ip, self.scg_port)
            rcvd_data = ji.get_json_data(url, self.jsessionid)
            return rcvd_data

        except Exception, e:
            print traceback.format_exc()
            return False

    def get_dhcp_relay_stat(self):
        """
        API used to get DHCP Realy Statistics

        URI: GET /wsg/api/scg/diagnostics/stats/dhcp/dp?
        """
        try:
            url = ji.get_url(self.req_api_dhcp_relay, self.scg_mgmt_ip, self.scg_port)
            rcvd_data = ji.get_json_data(url, self.jsessionid)
            return rcvd_data

        except Exception, e:
            print traceback.format_exc()
            return False

    def get_ggsn_connection(self):
        """
        API used to get GGSN Connection Statistics

        URI: GET /wsg/api/scg/diagnostics/stats/ggsn/connection?
        """
        try:
            url = ji.get_url(self.req_api_ggsn_conn, self.scg_mgmt_ip, self.scg_port)
            rcvd_data = ji.get_json_data(url, self.jsessionid)
            return rcvd_data

        except Exception, e:
            print traceback.format_exc()
            return False

    def get_ggsn_pgw_gtpc_session(self):
        """
        API used to get GGSN/PGW GTP-C session

        URI: GET /wsg/api/scg/diagnostics/stats/ggsn/gtpc?
        """
        try:
            url = ji.get_url(self.req_api_ggsn_pgw, self.scg_mgmt_ip, self.scg_port)
            rcvd_data = ji.get_json_data(url, self.jsessionid)
            return rcvd_data

        except Exception, e:
            print traceback.format_exc()
            return False

    def get_radius_server(self):
        """
        API used to get RADIUS server Statistics

        URI: GET /wsg/api/scg/diagnostics/stats/radius/server?
        """
        try:
            url = ji.get_url(self.req_api_radius_server, self.scg_mgmt_ip, self.scg_port)
            rcvd_data = ji.get_json_data(url, self.jsessionid)
            return rcvd_data

        except Exception, e:
            print traceback.format_exc()
            return False


    def get_radius_proxy(self):
        """
        API used to get RADIUS proxy Statistics

        URI: GET /wsg/api/scg/diagnostics/stats/radius/proxy?

        """
        try:
            url = ji.get_url(self.req_api_radius_proxy, self.scg_mgmt_ip, self.scg_port)
            rcvd_data = ji.get_json_data(url, self.jsessionid)
            return rcvd_data

        except Exception, e:
            print traceback.format_exc()
            return False

    def get_lma_signaling(self):
        """
        API used to get LMA Signaling Statistics

        URI: GET /wsg/api/scg/diagnostics/stats/lma/signaling? 

        """
        try:
            url = ji.get_url(self.req_api_lma_signal, self.scg_mgmt_ip, self.scg_port)
            rcvd_data = ji.get_json_data(url, self.jsessionid)
            return rcvd_data

        except Exception, e:
            print traceback.format_exc()
            return False

    def get_lma_connectivity(self):
        """
        API used to get LMA Connectivity Statistics

        URI: GET /wsg/api/scg/diagnostics/stats/lma/connectivity?

        """
        try:
            url = ji.get_url(self.req_api_lma_conn, self.scg_mgmt_ip, self.scg_port)
            rcvd_data = ji.get_json_data(url, self.jsessionid)
            return rcvd_data

        except Exception, e:
            print traceback.format_exc()
            return False
 


    def _get_hlr_statistics_by_hlr_nam(self, rcvd_data=None, hlr_service_name=None):

        is_entry = False
        for i in range(0, len(rcvd_data['data']['list'])):
            if rcvd_data['data']['list'][i]["hlrSrvcName"] == hlr_service_name:
                is_entry = True
                print rcvd_data['data']['list'][i]

        if not is_entry:
            print "not found"
            return False

        return True

    def _get_hlr_statistics_by_cblade_name(self, rcvd_data=None, cblade_name=None):

        is_entry = False
        for i in range(0, len(rcvd_data['data']['list'])):
            if rcvd_data['data']['list'][i]["cBladeName"] == cblade_name:
                is_entry = True
                print rcvd_data['data']['list'][i]

        if not is_entry:
            print "not found"
            return False

        return True

    def _get_hlr_statistics_by_mvno_name(self, rcvd_data=None, mvno_name=None):

        is_entry = False
        for i in range(0, len(rcvd_data['data']['list'])):
            if rcvd_data['data']['list'][i]["mvnoName"] == mvno_name:
                is_entry = True
                print rcvd_data['data']['list'][i]

        if not is_entry:
            print "not found"
            return False

        return True
            

