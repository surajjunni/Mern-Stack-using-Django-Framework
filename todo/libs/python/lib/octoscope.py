import re
import json
import requests
import time
import logging
from requests.packages.urllib3.exceptions import InsecureRequestWarning

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

def atten_control_incr(ip_addr='127.0.0.1', max_threshold=75, step_incr=1, wait_time=1, reset=False):
    max_threshold_range = max_threshold + 1
    url="http://%s/api/quadAtten" %(ip_addr)
    for i in range(1, max_threshold_range, step_incr):
        gmtime = time.gmtime()
        localtime = time.localtime()
        gmtOffsetMinutes = (localtime.tm_min - gmtime.tm_min) + (localtime.tm_hour - gmtime.tm_hour) * 60
        _gmtOffset = '%+02d%02d' % (gmtOffsetMinutes / 60, gmtOffsetMinutes % 60)
        _timezoneOffset = -gmtOffsetMinutes
        headers = {
            'Content-Type':'application/json',
            'GMTOffset':'%s' % _gmtOffset,
            'TimezoneOffset':'%d' % _timezoneOffset
        }
        a1 = float(i)
        a2 = float(max_threshold - i)
        request_body = {
            'atten1' : a1,
            'atten2' : a1,
            'atten3' : a2,
            'atten4' : a2
        }
        logging.info('calling : '+url)
        logging.info('Making a request...')
        logging.info('body'+json.dumps(request_body,indent=2,sort_keys=True))
        try:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            response = requests.post(url,headers=headers,json=request_body,verify=False)
            if response.status_code != 200:
                logging.error('Response status :' + str(response.status_code))
                logging.error(response.text)
                raise Exception("Unable to change the octoscope data")
            else:
                logging.info('Response status :' + str(response.status_code))
        except Exception as e:
            logging.error(str(e))
            return
        logging.info("Waiting for %d seconds in specific dB",wait_time)
        time.sleep(wait_time)
    if reset:
        a1 = a2 = 0.0
        request_body = {
            'atten1' : a1,
            'atten2' : a1,
            'atten3' : a2,
            'atten4' : a2
        }
        logging.info('calling : '+url)
        logging.info('Making a request...')
        logging.info('body'+json.dumps(request_body,indent=2,sort_keys=True))
        response = requests.post(url,headers=headers,json=request_body,verify=False)
        if not response.status_code == 200:
            logging.error('Response status :' + str(response.status_code))
            logging.error(response.text)
            raise Exception("Unable to change the octoscope data")
        else:
            logging.info('Response status :' + str(response.status_code))

def atten_control(ip_addr='127.0.0.1', ap1_value=75, ap2_value=75, wait_time=1, reset=False):
    url="http://%s/api/quadAtten" %(ip_addr)
    gmtime = time.gmtime()
    localtime = time.localtime()
    gmtOffsetMinutes = (localtime.tm_min - gmtime.tm_min) + (localtime.tm_hour - gmtime.tm_hour) * 60
    _gmtOffset = '%+02d%02d' % (gmtOffsetMinutes / 60, gmtOffsetMinutes % 60)
    _timezoneOffset = -gmtOffsetMinutes
    headers = {
        'Content-Type':'application/json',
        'GMTOffset':'%s' % _gmtOffset,
        'TimezoneOffset':'%d' % _timezoneOffset
    }
    a1 = float(channel1)
    a2 = float(channel2)
    request_body = {
        'atten1' : a1,
        'atten2' : a1,
        'atten3' : a2,
        'atten4' : a2
    }
    logging.info('calling : '+url)
    logging.info('Making a request...')
    logging.info('body'+json.dumps(request_body,indent=2,sort_keys=True))
    try:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.post(url,headers=headers,json=request_body,verify=False)
        if response.status_code != 200:
            logging.error('Response status :' + str(response.status_code))
            logging.error(response.text)
            raise Exception("Unable to change the octoscope data")
        else:
            logging.info('Response status :' + str(response.status_code))
    except Exception as e:
        logging.error(str(e))
        return
    logging.info("Waiting for %d seconds in specific dB",wait_time)
    time.sleep(wait_time)
    if reset:
        a1 = a2 = 0.0
        request_body = {
            'atten1' : a1,
            'atten2' : a1,
            'atten3' : a2,
            'atten4' : a2
        }
        logging.info('calling : '+url)
        logging.info('Making a request...')
        logging.info('body'+json.dumps(request_body,indent=2,sort_keys=True))
        response = requests.post(url,headers=headers,json=request_body,verify=False)
        if not response.status_code == 200:
            logging.error('Response status :' + str(response.status_code))
            logging.error(response.text)
            raise Exception("Unable to change the octoscope data")
        else:
            logging.info('Response status :' + str(response.status_code))

