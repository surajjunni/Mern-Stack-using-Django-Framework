import json
import urllib
import sys
import traceback

import qa.ttgcommon.coreapi.common.json_interface as ji
from qattg.coreapi.common.ScgJsonLogin import ScgJsonLogin
from qattg.coreapi.common.ScgJsonConfigApZone import ScgJsonConfigApZone
from qattg.coreapi.common.ScgJsonAdminAppStatus import ScgJsonAdminAppStatus
from ScgJsonReportTemplate import ScgJsonReportTemplate


class ScgJsonReport():
    def __init__(self, scg_mgmt_ip="127.0.0.2", scg_port="8443"):

        self.scg_mgmt_ip = scg_mgmt_ip
        self.scg_port = scg_port
        self.jsessionid = ''
        self.req_api_reports = '/wsg/api/scg/reports'
        self.req_api_get_report_results = '/wsg/api/scg/reports/%s/result'
        self.req_api_download_report_result = '/wsg/api/scg/reports/downLoadReport?%s'
        self.req_api_report_generate = '/wsg/api/scg/reports/%s/run'
        self.req_api_report_delete = '/wsg/api/scg/reports/%s'
        self.SJT = ScgJsonReportTemplate()
        self.apzone_api = None
        self.admin_api = None

    def _login(self, username='admin', password='ruckus', **kwargs):

        l = ScgJsonLogin()
        result, self.jsessionid = l.login(scg_mgmt_ip=self.scg_mgmt_ip, scg_port=self.scg_port,
                username=username, password=password)
            
        return result

    def get_jsessionid(self):
        return self.jsessionid

    def set_jsessionid(self, jsessionid):
        self.jsessionid = jsessionid

    def _create_apzone_info_api(self, jsessionid=None):
        self.apzone_api = ScgJsonConfigApZone(scg_mgmt_ip=self.scg_mgmt_ip,
                scg_port=self.scg_port)
        self.apzone_api.set_jsessionid(jsessionid)

    def _get_apzone_uuid(self, domain_label=None, ap_zone=None):
        return self.apzone_api.get_apzone_uuid(domain_label=domain_label, apzone_name=ap_zone)

    def _get_domain_uuid(self, domain_label=None):
        return self.apzone_api.get_domain_uuid(domain_label=domain_label)

    def _get_ap_info(self, domain_label=None, ap_ip=None):
        return self.apzone_api.get_ap_info(domain_label=domain_label, ap_ip=ap_ip)

    def _create_admin_api(self, jsessionid=None):
        self.admin_api = ScgJsonAdminAppStatus(scg_mgmt_ip=self.scg_mgmt_ip,
                scg_port=self.scg_port)
        self.admin_api.set_jsessionid(jsessionid)

    def _get_control_blade_uuid(self, cblade_label=None):
        return self.admin_api.get_control_blade_uuid(cblade_label=cblade_label)

    def find_report_title(self, report_title='myreport'):

        """
        API is used to Find REport Title

        URI GET: '/wsg/api/scg/reports'

        :param str report_title: Report Title
        :return: dictionary containing report entry if Report Title Found else None
        :rtype: dictionary

        """

        try:
            url = ji.get_url(self.req_api_reports, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.get_json_data(url, self.jsessionid)

            for report_entry in recvd_data['data']['list']:
                if report_entry['title'] == report_title:
                    return report_entry

            return None

        except Exception, e:
            print traceback.format_exc()
            return None

    def create_report(self, report_title='myreport', 
            report_type='Client Number',
            output_format='csv',
            time_filter_interval='FIFTEEN_MIN',
            time_filter_value=8, time_filter_units='HOURS',
            is_device_filter=True,
            device_category='Management Domains',
            domain_label='Administration Domain',
            ap_zone=None,
            ap_label=None,
            ap_ip=None,
            cblade_label=None,
            is_ssid_filter=False,
            ssid=None,
            is_radio_filter=False,
            radio=None,
            enable_schedules=True,
            schedule_interval='DAILY',
            schedule_day=8,
            schedule_week='MONDAY',
            schedule_hour=0,
            schedule_min=0,
            enable_email_notifications=False,
            email_id='laxmi.narayana@ruckuswireless.com',
            enable_export_results=False,
            ftp_host='1.2.3.4',
            ftp_port='21',
            ftp_username='user1',
            ftp_password='pswd1',
            ftp_remote_dir=None):


        """
        API is used to Create Report

        URI POST: '/wsg/api/scg/reports'

        :Param str report_title: Report Title
        :Param str report_type: Report Type Client Number | Client Number Vs Air Time | Active TTG Sessions | Continuously Disconnected APs 
        :Param str output_format: Output Format  csv | pdf  
        :Param str time_filter_interval: FIFTEEN_MIN | DAILY | HOURLY | MONTHLY
        :Param str time_filter_value: from 1 to 48
        :Param str time_filter_units: HOURS | DAYS |  MONTHS
        :Param str is_device_filter: Resource Filter - True
        :Param str device_category: Management Domains | APZONE | Access Point
        :Param str domain_label: Domain Label Name
        :Param str ap_zone: Ap Zone Name
        :Param str ap_label: Ap Zone Name
        :Param str ap_ip: Access Point IP
        :Param str cblade_label: Cblade Label Name
        :Param str is_ssid_filter: True | False
        :Param str ssid: SSID
        :Param str is_radio_filter: True | False
        :Param str radio: 2.5G | 5G
        :Param str enable_schedules:  True | False
        :Param str schedule_interval : DAILY | MONTHLY | WEEKLY | HOURLY
        :Param str schedule_day: schedule Day
        :Param str schedule_week: schedule Week
        :Param str schedule_hour: from 0 to 23
        :Param str schedule_min: from 0 to 59 
        :Param str enable_email_notifications: True | False
        :Param str email_id: Email ID
        :Param str enable_export_results: True | False
        :Param str ftp_host: FTP Host IP Address
        :Param str ftp_port: FTP Port Address
        :Param str ftp_username: FTP User Name
        :Param str ftp_password: FTP Password
        :Param str ftp_remote_dir: FTP Remote Directory
        :return: Trur if Report is created else False
        :rtype: boolean

        """
        try:
            domain_uuid = None
            apzone_uuid = None
            ap_info = None
            ap_mac = None

            report_data = self.SJT.get_report_template_data()

            report_data['title'] = report_title
            report_data['reportType'] = report_type
            if output_format == 'csv':
                report_data['csvFormat'] = True
            elif output_format == 'pdf':
                report_data['pdfFormat'] = True
            else:
                print "create_report(): Invalid output_format: %s" % output_format
                return False
            report_data['timeFilter']['interval'] = time_filter_interval
            report_data['timeFilter']['timeSpan'] = int(time_filter_value)
            report_data['timeFilter']['timeUtil'] = time_filter_units

            self._create_apzone_info_api(jsessionid=self.jsessionid)

            if is_device_filter or is_ssid_filter or is_radio_filter:
                domain_uuid = self._get_domain_uuid(domain_label=domain_label)
                if not domain_uuid:
                    print "create_report(): _get_domain_uuid() failed. domain_label: %s" % (
                            domain_label)
                    return False

                report_data['domainUUID'] = domain_uuid
            else:
                print "create_report(): atleast one resource_filter_criteria shall be enabled by user"
                return False

            if is_device_filter:
                device_filter = self.SJT.get_filter_template_data()

                if device_category == 'Management Domains':
                    device_filter['resourceType'] = 'DOMAIN'
                    device_filter['resourceEntity'][0]['label'] = domain_label
                    device_filter['resourceEntity'][0]['value'] = domain_uuid
                elif device_category == 'AP Zone':
                    apzone_uuid = self._get_apzone_uuid(domain_label=domain_label,
                            ap_zone=ap_zone)
                    if not apzone_uuid:
                        print "create_report(): _get_apzone_uuid() failed. ap_zone: %s" % ap_zone
                        return False
                    device_filter['resourceType'] = 'APZONE'
                    device_filter['resourceEntity'][0]['label'] = ap_zone
                    device_filter['resourceEntity'][0]['value'] = apzone_uuid
                elif device_category == 'Access Point':
                    ap_info = self._get_ap_info(domain_label=domain_label,
                            ap_ip=ap_ip)
                    if not ap_info:
                        print "create_report(): _get_ap_info() failed. ap_ip: %s" % ap_ip
                        return False
                    ap_mac = ap_info['apMac']
                    device_filter['resourceType'] = 'AP'
                    device_filter['resourceEntity'][0]['label'] = ap_label
                    device_filter['resourceEntity'][0]['value'] = ap_mac
                elif device_category == 'PLANE':
                    self._create_admin_api(jsessionid=self.jsessionid)
                    cblade_uuid = self._get_control_blade_uuid(cblade_label=cblade_label)
                    if not cblade_uuid:
                        print "create_report(): _get_control_blade_uuid() failed. cblade_label: %s" % cblade_label
                        return False
                    device_filter['resourceType'] = 'PLANE'
                    device_filter['resourceEntity'][0]['label'] = cblade_label
                    device_filter['resourceEntity'][0]['value'] = cblade_uuid
                else:
                    print "create_report(): Invalid device_category: %s" % device_category
                    return False

                report_data['deviceFilter'] = device_filter

            if is_ssid_filter:
                ssid_filter = self.SJT.get_filter_template_data()
                device_filter['resourceType'] = 'SSID'
                device_filter['resourceEntity'][0]['label'] = ssid
                device_filter['resourceEntity'][0]['value'] = ssid

                report_data['ssidFilter'] = ssid_filter

            if is_radio_filter:
                radio_filter = self.SJT.get_filter_template_data()
                device_filter['resourceType'] = 'RADIO'
                device_filter['resourceEntity'][0]['label'] = "1" if radio == '5G' else "0"
                device_filter['resourceEntity'][0]['value'] = "1" if radio == '5G' else "0"

                report_data['radioFilter'] = radio_filter

            if enable_schedules:
                report_data['scheduleEnable'] = True
                report_data['schedules'][0]['interval'] = schedule_interval
                report_data['schedules'][0]['dateOfMonth'] = int(schedule_day)
                report_data['schedules'][0]['dayOfWeek'] = schedule_week
                report_data['schedules'][0]['hour'] = int(schedule_hour)
                report_data['schedules'][0]['minute'] = int(schedule_min)

            if enable_email_notifications:
                report_data['notificationEnable'] = True
                report_data['notifiedMailList'].append(email_id)

            if enable_export_results:
                report_data['ftpEnable'] = "true"
                report_data["ftpServer"] = {
                        "ftpHost" : ftp_host,
                        "ftpPort" : ftp_port,
                        "ftpUserName" : ftp_username,
                        "ftpPassword" : ftp_password,
                        "key":"",
                        "ftpRemoteDirectory": ftp_remote_dir if ftp_remote_dir else "",
                        }

            data_json = json.dumps(report_data)

            url = ji.get_url(self.req_api_reports, self.scg_mgmt_ip, self.scg_port)
            result = ji.post_json_data(url, self.jsessionid, data_json)

            return result

        except Exception, e:
            print traceback.format_exc()
            return False

    def _get_report_uuid(self, report_title='myreport'):

        """
        API used to get Report UUID

        :param str report_title: Report Title
        :return: True if _get_report_uuid success else False
        :rtype: Dictionary


        """
        try:
            report_entry =  self.find_report_title(report_title=report_title)
            if not report_entry:
                print "get_report_uuid(): find_report_title() failed. report_title: %s" % report_title
                return None

            report_uuid = report_entry['reportUUID']

            return report_uuid

        except Exception, e:
            print traceback.format_exc()
            return None

    def generate_report(self, report_title='myreport'):

        """

        API used to Generate Report

        URI GET: '/wsg/api/scg/reports/<report_uuid>/run'

        :param str report_title: Report Title
        :return: True if Report Generated else False
        :rtype: boolean

        """
        try:
            report_uuid = self._get_report_uuid(report_title=report_title)
            if not report_uuid:
                print "generate_report(): _get_report_uuid() failed. report_title: %s" % (
                        report_title)
                return False

            url = ji.get_url(self.req_api_report_generate % report_uuid, 
                    self.scg_mgmt_ip, self.scg_port)
            data_json = None
            result = ji.put_json_data(url, self.jsessionid, data_json)

            return result

        except Exception, e:
            print traceback.format_exc()
            return False

    def delete_report(self, report_title='myreport'):

        """
        API used to Delete Report

        URI DELETE: '/wsg/api/scg/reports/<report_uuid>'

        :param str report_title: Report Title
        :return: True if Report Deleted else False
        :rtype: boolean

        """
        try:
            report_uuid = self._get_report_uuid(report_title=report_title)
            if not report_uuid:
                print "delete_report(): _get_report_uuid() failed. report_title: %s" % (
                        report_title)
                return False

            url = ji.get_url(self.req_api_report_delete % report_uuid, 
                    self.scg_mgmt_ip, self.scg_port)
            data_json = None
            result = ji.delete_scg_data(url, self.jsessionid, data_json)

            return result

        except Exception, e:
            print traceback.format_exc()
            return False

    def get_report_results(self, report_title='myreport'):

        """
        API used to Get Report Results

        URI GET: '/wsg/api/scg/reports/<report_uuid>/result'

        :param str report_title: Report Title
        :return: list of results if success else False
        :rtype: list

        """
        try:
            report_uuid = self._get_report_uuid(report_title=report_title)
            if not report_uuid:
                print "get_report_results(): _get_report_uuid() failed. report_title: %s" % (
                        report_title)
                return None

            report_results_url = ji.get_url(self.req_api_get_report_results % report_uuid, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.get_json_data(report_results_url, self.jsessionid)

            return recvd_data['data']['list']

        except Exception, e:
            print traceback.format_exc()
            return None

    def download_report_result(self, report_title='myreport', local_path='/tmp/'):

        """
        API used to Download Report Results

        :param str report_title: Report Title
        :param str local_path: Path Required to store Downloaded Reports 
        :return: local copied filename if success else None
        :rtype: str

        """
        try:
            csv_file = None
            pdf_file = None
            report_id = None
            report_fileid = None
            local_filename = None

            report_results = self.get_report_results(report_title=report_title)
            if not report_results:
                print "download_report_result(): get_report_results() failed. report_title: %s" % report_title
                return None

            for report_result in report_results:
                csv_file = report_result['csvFilename']
                pdf_file = report_result['pdfFilename']
                report_id = report_fileid = report_result['uuid']
                #only the latest report is considered for downloading as of now
                break

            if not csv_file and not pdf_file:
                print "download_report_result(): Could not find report result. report_title: %s" % report_title
                return None

            report_download_query = {
                        'reportfileid' : report_fileid,
                        'reportid' : report_id,
                        'isAchive' : 'N',
                        'fileNames' : csv_file if csv_file is not None else pdf_file
                    }

            download_report_url = ji.get_url(self.req_api_download_report_result % (
                urllib.urlencode(report_download_query)), self.scg_mgmt_ip, self.scg_port)
            resp = ji.get_octetstream_data(download_report_url, self.jsessionid)
            if not resp:
                print "download_report_result(): get_octetstream_data() failed. report_title: %s" % report_title
                return None

            meta_data = resp.info()

            content_disp = meta_data.getheaders('Content-Disposition')[0]
            print "download_report_result(): Http Resp Header: Content-Disposition: %s"% (
                    content_disp)
            file_size = int(meta_data.getheaders('Content-Length')[0])

            display_filename = self._parse_content_disposition(content_disp)

            if not display_filename:
                print "download_report_result(): Could not parse filename in Content-Disposition of resp header"
                return None

            local_filename = local_path + '/' + display_filename

            if not self._download_report_file(resp, file_name=local_filename, file_size=file_size):
                print "download_report_result(): _download_report_file: %s failed" % local_filename
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

    def _download_report_file(self, resp, file_name='/tmp/tmp.txt', file_size=8192, block_sz=8192):
        try:
            file_size_dl = 0
            print "download_report_file(): Downloading file: %s   Bytes: %s" % (
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
"""
if __name__ == '__main__':

    sjc = ScgJsonReport(scg_mgmt_ip='172.19.16.150', scg_port='8443')

    if not sjc._login(username='admin', password='ruckus1!'):
        print "user login() failed"
        sys.exit(1)
    else:
        print "scg login success"

    report_title = 'myreport'

    if sjc.find_report_title(report_title=report_title):
        print "find_report_title(): report_title: %s already exists" % report_title
    else:
        if not sjc.create_report(report_title=report_title):
            print "create_report(): failed. report_title: %s" % report_title
            sys.exit(1)
        else:
            print "create_report(): success. report_title: %s" % report_title


    if not sjc.generate_report(report_title=report_title):
        print "generate_report() failed. report_title: %s" % report_title
        sys.exit(1)
    else:
        print "generate_report() success. report_title: %s" % report_title

    file_downloaded = sjc.download_report_result(report_title=report_title, local_path='/tmp/')
    if not file_downloaded:
        print "download_report_result() failed"
        sys.exit(1)
    else:
        print "download_report_result() success. file_downloaded: %s" % file_downloaded

    if not sjc.delete_report(report_title=report_title):
        print "delete_report() failed. report_title: %s" % report_title
        sys.exit(1)
    else:
        print "delete_report() success. report_title: %s" % report_title

"""
