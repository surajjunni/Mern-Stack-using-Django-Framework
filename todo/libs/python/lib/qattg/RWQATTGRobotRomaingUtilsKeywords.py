from qattg.coreapi.components import Roaming_Utils as RU
from qattg.coreapi.common.ScgJsonLogin import ScgJsonLogin

class RWQATTGRobotRomaingUtilsKeywords():

    def __init__(self):
        self.ru = None

    def login_to_scg_roaming(self, scg_mgmt_ip='127.0.0.2', scg_port='8443',
                            username='admin', password='ruckus',
                            ):
        """
        API used to login to SCG.

        :param str scg_mgmt_ip: SCG Management IP

        :param str scg_port: SCG https port

        :param str username: username (admin or mvno user)

        :param str password: password (admin or mvno password)

        :return: jsessionid if login is successful else Exception

        :rtype: string

        Example:
        | Login to SCG | scg_mgmt_ip=172.19.18.150 | username=admin | password=ruckus |


        """

        sjl = ScgJsonLogin()
        res, jsessionid = sjl.login(scg_mgmt_ip=scg_mgmt_ip, scg_port=scg_port,
                username=username, password=password)

        if not res:
            raise AssertionError("Failed to Login to SCG")

        self.set_scg_session(scg_mgmt_ip=scg_mgmt_ip, scg_port=scg_port, jsessionid=jsessionid)

        return jsessionid


    def set_scg_session(self, scg_mgmt_ip='127.0.0.2', scg_port='8443',
            jsessionid=None):
        """
        Creates an instance of scg json config for SCG IP and https port.
        This keyword shall be used if login is not done from this class instance
        and user knows the jsessionid. This API is helpful if the JSON API is available across
        multiple library files.

        :param str scg_mgmt_ip: SCG Management IP

        :param str scg_port: SCG https port

        :param str jsessionid: jsessionid returned by a successful login to SCG

        :return: None

        :rtype: None

        Example:
        | Set SCG Session | scg_mgmt_ip=172.19.18.150 | jsessionid=${JSESSIONID} |

        """

        if not jsessionid:
            raise AssertionError("Invalid jsessionid: %s" % jsessionid)

        self.ru = RU.Roaming_Utils(scg_mgmt_ip=scg_mgmt_ip, scg_port=scg_port)

        self.ru.set_jsessionid(jsessionid)

    def set_roaming_params(self, **kwargs):

        res = self.ru.set_roaming_params(**kwargs)
 
    def current_ap_dblade_reboot_using_ap_ip(self):
        """
        API used to Reboot the D-blade using AP ip
        """
        res = self.ru.current_ap_dblade_reboot()
       
    def reboot_ap(self,**kwargs):
        """
        API used to Reboot the AP
        """
        res = self.ru.reboot_ap(**kwargs)
            
    def free_dblade_ip(self, **kwargs):
        res = self.ru.free_dblade_ip(**kwargs)
        if not res:
            raise AssertionError("free_dblade_ip(): Failed")

    def get_ap_to_dblade_tunnel_status(self, **kwargs):
        """
        API used to get the ap tunnel status

        :param str dblade: D-Blade IP

        :param str status: Enabled | Disabled

        :return: True if status is Enabled else Exception

        :rtype: boolean
        """
        res = self.ru.get_ap_to_dblade_tunnel_status(**kwargs)
        if not res:
            raise AssertionError("get_ap_to_dblade_tunnel_status(): Failed")

    def configure_ap_tunnel_to_dblade(self, **kwargs):
        """
        API used to Configure ap to Particular Dblade

        :param str dblade: D-Blade ip

        :param str reset: True | False

        :return: True if dblade ip configure else exception

        :rtype: boolean

        """
        res = self.ru.configure_ap_tunnel_to_dblade(**kwargs)
        if not res:
            raise AssertionError("configure_ap_tunnel_to_dblade(): Failed")

    def configure_ap_tunnel_to_cblade(self, **kwargs):
        """
        API used to Configure ap to Particular CBlade

        :param str scg_ip: SCG Control IP

        :return: True if cblade ip configure else exception

        :rtype: boolean

        """
        res = self.ru.set_ap_scg_ip(**kwargs)
        if not res:
            raise AssertionError("configure_ap_tunnel_to_cblade(): Failed")

    def set_pmk_enable_disable(self, **kwargs):
        """
        API used to Configure pmk value of wlan to enable or disable

        :param str wlan_name: wlan name

        :return: True if setting pmk to wlan is success

        :rtype: boolean

        """
        res = self.ru.set_pmk_enable_disable(**kwargs)
        if not res:
            raise AssertionError("set_pmk_enable_disable(): Failed")

    def set_latitude_longitude(self, **kwargs):
        """
        API used to Configure latitude and longitude value for AP

        :param str latitude: latitude co-ordinates
        :param str longitude: longitude co-ordinates

        :return: True if setting latitude and longitude to AP is success

        :rtype: boolean

        """
        res = self.ru.set_latitude_longitude(**kwargs)
        if not res:
            raise AssertionError("set_latitude_longitude(): Failed")
                
    def set_okc_enable_disable(self, **kwargs):
        """
        API used to Configure okc value of wlan to enable or disable

        :param str wlan_name: wlan name

        :return: True if setting okc to wlan is success

        :rtype: boolean

        """
        res = self.ru.set_okc_enable_disable(**kwargs)
        if not res:
            raise AssertionError("set_okc_enable_disable(): Failed") 