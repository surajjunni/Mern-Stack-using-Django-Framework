import urllib
import sys
import traceback
import qa.ttgcommon.coreapi.common.json_interface as ji
from ScgJsonLogin import ScgJsonLogin

class ScgJsonAdminAppStatus():
    def __init__(self, scg_mgmt_ip="127.0.0.2", scg_port="8443"):

        self.scg_mgmt_ip = scg_mgmt_ip
        self.scg_port = scg_port
        self.jsessionid = ''
        self.req_api_control_blade_uuid = '/wsg/api/scg/planes/control/ids'
        self.req_api_diagnostics_app_status = '/wsg/api/scg/diagnostics/applications/%s'
        self.req_api_control_plane_summary = '/wsg/api/scg/planes/control'
        self.req_api_data_plane_summary = '/wsg/api/scg/planes/data'
        self.req_api_download_all_logs = '/wsg/api/scg/diagnostics/applications/download?%s'

    def _login(self, username='admin', password='ruckus', **kwargs):

        l = ScgJsonLogin()
        result, self.jsessionid = l.login(scg_mgmt_ip=self.scg_mgmt_ip, scg_port=self.scg_port,
                username=username, password=password)
            
        return result

    def set_jsessionid(self, jsessionid):
        self.jsessionid = jsessionid

    def get_control_blade_uuid(self, cblade_label='mylabel'):

        is_entry_found = False
        uuid = None

        try:
            url = ji.get_url(self.req_api_control_blade_uuid, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.get_json_data(url, self.jsessionid)

            if len(recvd_data['data']['list']) >= 1:
                for data in recvd_data['data']['list']:
                    if data['label'] == cblade_label:
                        uuid = data['bladeUUID']
                        is_entry_found = True
                        break
            else:
                print "get_control_blade_uuid(): No data.list recvd"
                return uuid

            if not is_entry_found:
                print "get_control_blade_uuid(): cblade_label: %s not found" % cblade_label
                return uuid

        except Exception, e:
            print traceback.format_exc()
            return uuid

        return uuid

    def get_app_status(self, cblade_label='mylabel'):

        try:
            blade_uuid = self.get_control_blade_uuid(cblade_label=cblade_label)
            if not blade_uuid:
                print "get_app_status(): blade_uuid not found for cblade_label: %s" % cblade_label
                return None

            url = ji.get_url(self.req_api_diagnostics_app_status % blade_uuid, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.get_json_data(url, self.jsessionid)

            return recvd_data['data']['list']

        except Exception, e:
            print traceback.format_exc()
            return None

    def get_control_plane_summary(self):

        try:
            url = ji._get_url(self.req_api_control_plane_summary, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji._get_json_data(url, self.jsessionid)

            return recvd_data['data']['list']

        except Exception, e:
            print traceback.format_exc()
            return None

    def get_control_plane_names(self):

        try:
            cp_info_list = self.get_control_plane_summary()
            cp_names = []
            for item in cp_info_list:
                cp_names.append(item['name'])
            return cp_names

        except Exception, e:
            print traceback.format_exc()
            return None

    def get_control_plane_mac(self, cblade_label='mylabel'):

        try:
            mac = None
            cp_info_list = self.get_control_plane_summary()
            for item in cp_info_list:
                if item['name'] == cblade_label:
                    mac = item['mac']
                    break
            return mac

        except Exception, e:
            print traceback.format_exc()
            return None

    def get_data_plane_summary(self):

        try:
            url = ji._get_url(self.req_api_data_plane_summary, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji._get_json_data(url, self.jsessionid)

            return recvd_data['data']['list']

        except Exception, e:
            print traceback.format_exc()
            return None

    def get_data_plane_mac(self, dblade_label='mylabel'):

        try:
            mac = None
            dp_info_list = self.get_data_plane_summary()
            for item in dp_info_list:
                if item['name'] == dblade_label:
                    mac = item['latestConfig']['dpMac']
                    break
            return mac

        except Exception, e:
            print traceback.format_exc()
            return None

    def download_all_logs(self, cblade_label='mylabel', local_path='/tmp/'):

        try:
            cblade_uuid = self.get_control_blade_uuid(cblade_label=cblade_label)
            if not cblade_uuid:
                print "download_all_logs(): get_control_blade_uuid() failed. cblade_label: %s" % (
                        cblade_label)
                return None

            _query = {
                        'bladeUUID' : cblade_uuid,
                        'bladeName' : cblade_label,
                        'appName' : '',
                        'logFileName' : '',
                     }

            url = ji._get_url(self.req_api_download_all_logs % (
                urllib.urlencode(_query)), self.scg_mgmt_ip, self.scg_port)
            resp = ji._get_octetstream_data(url, self.jsessionid)
            if not resp:
                print "download_all_logs(): _get_octetstream_data() failed. cblade_label: %s" % cblade_label
                return None

            meta_data = resp.info()

            content_disp = meta_data.getheaders('Content-Disposition')[0]

            print "download_all_logs(): Http Resp Header: Content-Disposition: %s"% (
                    content_disp)
            file_size = int(meta_data.getheaders('Content-Length')[0])

            display_filename = self._parse_content_disposition(content_disp)

            if not display_filename:
                print "download_all_logs(): Could not parse filename in Content-Disposition of resp header"
                return None

            local_filename = local_path + '/' + display_filename

            if not self._download_log_file(resp, file_name=local_filename, file_size=file_size):
                print "download_log_file(): _download_log_file: %s failed" % local_filename
                return None
            else:
                return local_filename

        except Exception, e:
            print traceback.format_exc()
            return None

    def _parse_content_disposition(self, content_disp):

        filename = None
        _cd_list = content_disp.split(';')
        if (len(_cd_list) >= 2) and (_cd_list[0] == 'attachment'):
            _tmp = _cd_list[1].split('=')
            if (len(_tmp) == 2) and (_tmp[0] == 'filename'):
                filename = _tmp[1]

        return filename

    def _download_log_file(self, resp, file_name='/tmp/tmp.txt', file_size=8192, block_sz=8192):
        try:
            file_size_dl = 0
            print "download_log_file(): Downloading file: %s   Bytes: %s" % (
                    file_name, file_size)
            f = open(file_name, 'wb')
            while True:
                buf = resp.read(int(block_sz))
                if not buf:
                    break

                file_size_dl += len(buf)
                f.write(buf)
                status = r"%10d  [%3.2f%%]" % (file_size_dl, file_size_dl * 100. / int(file_size))
                sys.stdout.write('\r')
                sys.stdout.write(status)
                sys.stdout.flush()

            sys.stdout.write('\n')
            f.close()
            return file_size_dl

        except Exception, e:
            print traceback.format_exc()
            return None



if __name__ == '__main__':

    sjc = ScgJsonAdminAppStatus(scg_mgmt_ip='172.19.16.150', scg_port='8443')

    if not sjc._login(username='admin', password='ruckus1!'):
        print "user login() failed"
        sys.exit(1)
    else:
        print "scg login success"

    cp_names = sjc.get_control_plane_names()
    if not cp_names:
        print "get_control_plane_names() failed"
        sys.exit(1)
    else:
        print "get_control_plane_names() success. cp_names: %s" % cp_names

    bladename = None
    for cblade_label in cp_names:
        app_status = sjc.get_app_status(cblade_label=cblade_label)
        if not app_status:
            print "get_app_status failed"
            sys.exit(1)
        else:
            print "get_app_status: success[cblade_label: %s  total_apps: %d]. data: %s" % (
                    cblade_label, len(app_status), app_status)
            print "Downloading logs..."
            file_downloaded = sjc.download_all_logs(cblade_label=cblade_label, local_path='/tmp/')
            if not file_downloaded:
                print "download_all_logs() failed"
                sys.exit(1)
            else:
                print "download_all_logs() success. file_downloaded: %s" % file_downloaded


