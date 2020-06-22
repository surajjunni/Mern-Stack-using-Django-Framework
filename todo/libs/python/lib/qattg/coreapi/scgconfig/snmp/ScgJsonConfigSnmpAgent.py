import json
import sys
import traceback
import copy
from ScgJsonConfigSnmpAgentTemplate import ScgJsonConfigSnmpAgentTemplate
from qattg.coreapi.common.ScgJsonLogin import ScgJsonLogin
import qa.ttgcommon.coreapi.common.json_interface as ji

class ScgJsonConfigSnmpAgent():
    def __init__(self, scg_mgmt_ip="127.0.0.2", scg_port="8443"):

        self.scg_mgmt_ip = scg_mgmt_ip
        self.scg_port = scg_port
        self.jsessionid = ''
        self.req_api_snmp_agent = '/wsg/api/scg/globalSettings/mvno/snmp'
        self.SJT = ScgJsonConfigSnmpAgentTemplate()

    def _login(self, username='admin', password='ruckus', **kwargs):

        l = ScgJsonLogin()
        result, self.jsessionid = l.login(scg_mgmt_ip=self.scg_mgmt_ip, scg_port=self.scg_port,
                username=username, password=password)

        return result

    def set_jsessionid(self, jsessionid=''):
        self.jsessionid = jsessionid

    def create_snmpv2_agent(self, community='public', 
            read_privilege=True, write_privilege=True, trap_privilege=False,
            trap_target_ip=None, trap_target_port='162'):

        result = False
        snmp_agent_data = {}
        try:
            if self.get_snmpv2_agent(community=community):
                print "create_snmpv2_agent(): community: %s already exists" % community
                return False

            url = ji.get_url(self.req_api_snmp_agent, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.get_json_data(url, self.jsessionid)

            snmp_agent_data = self.SJT.get_snmpv2_agent_template_data()
            snmp_agent_data['communityName'] = community
            snmp_agent_data['readPrivilege'] = read_privilege
            snmp_agent_data['writePrivilege'] = write_privilege
            snmp_agent_data['trapPrivilege'] = trap_privilege

            snmp_agent_data['communities'] = copy.deepcopy(recvd_data['data']['communities'])
            snmp_agent_data['users'] = copy.deepcopy(recvd_data['data']['users'])

            community_dict = { 'communityName' : community,
                    'readPrivilege' : read_privilege,
                    'writePrivilege' : write_privilege,
                    'trapPrivilege' : trap_privilege,
                    'traps': [] if trap_target_ip is None else [{'targetAddress' : trap_target_ip, 'targetPort' : trap_target_port}]
                    }

            snmp_agent_data['communities'].append(community_dict)

            data_json = json.dumps(snmp_agent_data)

            result = ji.put_json_data(url, self.jsessionid, data_json)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def create_snmpv3_agent(self, user='user1', 
            auth_protocol='', 
            auth_passphrase='',
            privacy_protocol='',
            privacy_passphrase='',
            read_privilege=True, write_privilege=True, trap_privilege=False,
            trap_target_ip=None, trap_target_port='162'):

        result = False
        snmp_agent_data = {}

        try:
            if self.get_snmpv3_agent(user=user):
                print "create_snmpv3_agent(): user: %s already exists" % user
                return False

            url = ji.get_url(self.req_api_snmp_agent, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.get_json_data(url, self.jsessionid)

            snmp_agent_data = self.SJT.get_snmpv3_agent_template_data()
            snmp_agent_data['readPrivilege'] = read_privilege
            snmp_agent_data['writePrivilege'] = write_privilege
            snmp_agent_data['trapPrivilege'] = trap_privilege
            snmp_agent_data['userName'] = user
            snmp_agent_data['authProtocol'] = auth_protocol
            snmp_agent_data['authPassword'] = auth_passphrase
            snmp_agent_data['privProtocol'] = privacy_protocol
            snmp_agent_data['privPassword'] = privacy_passphrase


            snmp_agent_data['communities'] = copy.deepcopy(recvd_data['data']['communities'])
            snmp_agent_data['users'] = copy.deepcopy(recvd_data['data']['users'])

            user_dict = { 

                    'userName' : user,
                    'authProtocol' : auth_protocol,
                    'authPassword' : auth_passphrase,
                    'privProtocol' : privacy_protocol,
                    'privPassword' : privacy_passphrase,
                    'readPrivilege' : read_privilege,
                    'writePrivilege' : write_privilege,
                    'trapPrivilege' : trap_privilege,
                    'traps': [] if trap_target_ip is None else [{'targetAddress' : trap_target_ip, 'targetPort' : trap_target_port}]
                    }

            snmp_agent_data['users'].append(user_dict)

            data_json = json.dumps(snmp_agent_data)

            result = ji.put_json_data(url, self.jsessionid, data_json)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def update_snmpv2_agent(self, current_community='public', 
            new_community='public_new',
            read_privilege=None, write_privilege=None, trap_privilege=None,
            trap_target_ip=None, trap_target_port='162'):

        result = False
        is_entry_found = False
        snmp_agent_data = {}
        update_index = -1

        try:
            url = ji.get_url(self.req_api_snmp_agent, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.get_json_data(url, self.jsessionid)

            new_data = copy.deepcopy(recvd_data)

            for i in range(len(new_data['data']['communities'])):
                if new_data['data']['communities'][i]['communityName'] == current_community:
                    update_index = i
                    is_entry_found = True
                    break

            if not is_entry_found:
                print 'update_snmpv2_agent(): community: %s does not exist' % current_community
                return False
            else:
                community_dict = { 'communityName' : new_community,
                    'readPrivilege' : read_privilege if read_privilege is not None else recvd_data['data']['communities'][update_index]['readPrivilege'],
                    'writePrivilege' : write_privilege if write_privilege is not None else recvd_data['data']['communities'][update_index]['writePrivilege'],
                    'trapPrivilege' : trap_privilege if trap_privilege is not None else recvd_data['data']['communities'][update_index]['trapPrivilege'],
                    'traps':  [{'targetAddress' : trap_target_ip, 'targetPort' : trap_target_port}] if trap_target_ip is not None \
                            else copy.deepcopy(recvd_data['data']['communities'][update_index]['traps']),
                    }
                new_data['data']['communities'][update_index] = community_dict

            snmp_agent_data = new_data['data']

            data_json = json.dumps(snmp_agent_data)

            result = ji.put_json_data(url, self.jsessionid, data_json)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def update_snmpv3_agent(self, current_user='user1', 
            new_user='user2',
            auth_protocol=None, 
            auth_passphrase=None,
            privacy_protocol=None,
            privacy_passphrase=None,
            read_privilege=None, write_privilege=None, trap_privilege=None,
            trap_target_ip=None, trap_target_port='162'):

        result = False
        is_entry_found = False
        snmp_agent_data = {}
        update_index = -1

        try:
            url = ji.get_url(self.req_api_snmp_agent, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.get_json_data(url, self.jsessionid)

            new_data = copy.deepcopy(recvd_data)

            for i in range(len(new_data['data']['users'])):
                if new_data['data']['users'][i]['userName'] == current_user:
                    update_index = i
                    is_entry_found = True
                    break

            if not is_entry_found:
                print 'update_snmpv3_agent(): user: %s does not exist' % current_user
                return False
            else:
                user_dict = { 
                    'userName' : new_user,
                    'authProtocol' : auth_protocol if auth_protocol is not None else recvd_data['data']['users'][update_index]['authProtocol'],
                    'authPassword' : auth_passphrase if auth_passphrase is not None else recvd_data['data']['users'][update_index]['authPassword'],
                    'privProtocol' : privacy_protocol if privacy_protocol is not None else recvd_data['data']['users'][update_index]['privProtocol'],
                    'privPassword' : privacy_passphrase if privacy_passphrase is not None else recvd_data['data']['users'][update_index]['privPassword'],
                    'readPrivilege' : read_privilege if read_privilege is not None else recvd_data['data']['users'][update_index]['readPrivilege'],
                    'writePrivilege' : write_privilege if write_privilege is not None else recvd_data['data']['users'][update_index]['writePrivilege'],
                    'trapPrivilege' : trap_privilege if trap_privilege is not None else recvd_data['data']['users'][update_index]['trapPrivilege'],
                    'traps': [] [{'targetAddress' : trap_target_ip, 'targetPort' : trap_target_port}] if trap_target_ip is not None \
                                                else copy.deepcopy(recvd_data['data']['users'][update_index]['traps'])
                    }

                new_data['data']['users'][update_index] = user_dict

            snmp_agent_data = new_data['data']

            data_json = json.dumps(snmp_agent_data)

            result = ji.put_json_data(url, self.jsessionid, data_json)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def snmpv2_add_trap_target(self, current_community='public', 
            trap_target_ip='1.2.3.4', trap_target_port='162'):

        result = False
        is_entry_found = False
        snmp_agent_data = {}
        update_index = -1

        try:
            url = ji.get_url(self.req_api_snmp_agent, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.get_json_data(url, self.jsessionid)

            new_data = copy.deepcopy(recvd_data)

            for i in range(len(new_data['data']['communities'])):
                if new_data['data']['communities'][i]['communityName'] == current_community:
                    update_index = i
                    is_entry_found = True
                    break

            if not is_entry_found:
                print 'snmpv2_add_trap_target(): community: %s does not exist' % current_community
                return False
            else:
                new_data['data']['communities'][update_index]['traps'].append({'targetAddress' : trap_target_ip, 'targetPort' : trap_target_port})

            snmp_agent_data = new_data['data']

            data_json = json.dumps(snmp_agent_data)

            result = ji.put_json_data(url, self.jsessionid, data_json)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def snmpv3_add_trap_target(self, current_user='user1', 
            trap_target_ip='1.2.3.4', trap_target_port='162'):

        result = False
        is_entry_found = False
        snmp_agent_data = {}
        update_index = -1

        try:
            url = ji.get_url(self.req_api_snmp_agent, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.get_json_data(url, self.jsessionid)

            new_data = copy.deepcopy(recvd_data)

            for i in range(len(new_data['data']['users'])):
                if new_data['data']['users'][i]['userName'] == current_user:
                    update_index = i
                    is_entry_found = True
                    break

            if not is_entry_found:
                print 'snmpv3_add_trap_target(): user: %s does not exist' % current_user
                return False
            else:
                new_data['data']['users'][update_index]['traps'].append({'targetAddress' : trap_target_ip, 'targetPort' : trap_target_port})

            snmp_agent_data = new_data['data']

            data_json = json.dumps(snmp_agent_data)

            result = ji.put_json_data(url, self.jsessionid, data_json)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def delete_snmpv2_agent(self, community='public'):

        result = False
        is_entry_found = False
        snmp_agent_data = {}
        delete_index = -1

        try:
            url = ji.get_url(self.req_api_snmp_agent, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.get_json_data(url, self.jsessionid)

            new_data = copy.deepcopy(recvd_data)

            for i in range(len(new_data['data']['communities'])):
                if new_data['data']['communities'][i]['communityName'] == community:
                    delete_index = i
                    is_entry_found = True
                    break

            if not is_entry_found:
                print 'delete_snmpv2_agent(): community: %s does not exist' % community
                return False
            else:
                del new_data['data']['communities'][delete_index]

            snmp_agent_data = new_data['data']

            data_json = json.dumps(snmp_agent_data)

            result = ji.put_json_data(url, self.jsessionid, data_json)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def delete_snmpv3_agent(self, user='user1'):

        result = False
        is_entry_found = False
        snmp_agent_data = {}
        delete_index = -1

        try:
            url = ji.get_url(self.req_api_snmp_agent, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.get_json_data(url, self.jsessionid)

            new_data = copy.deepcopy(recvd_data)

            for i in range(len(new_data['data']['users'])):
                if new_data['data']['users'][i]['userName'] == user:
                    delete_index = i
                    is_entry_found = True
                    break

            if not is_entry_found:
                print 'delete_snmpv3_agent(): user: %s does not exist' % user
                return False
            else:
                del new_data['data']['users'][delete_index]

            snmp_agent_data = new_data['data']

            data_json = json.dumps(snmp_agent_data)

            result = ji.put_json_data(url, self.jsessionid, data_json)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def disable_global_snmp_trap(self):

        result = False
        snmp_agent_data = {}

        try:
            url = ji.get_url(self.req_api_snmp_agent, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.get_json_data(url, self.jsessionid)

            snmp_agent_data = copy.deepcopy(recvd_data['data'])

            snmp_agent_data['enabled'] = False

            data_json = json.dumps(snmp_agent_data)

            result = ji.put_json_data(url, self.jsessionid, data_json)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def enable_global_snmp_trap(self):

        result = False
        snmp_agent_data = {}

        try:
            url = ji.get_url(self.req_api_snmp_agent, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.get_json_data(url, self.jsessionid)

            snmp_agent_data = copy.deepcopy(recvd_data['data'])

            snmp_agent_data['enabled'] = True

            data_json = json.dumps(snmp_agent_data)

            result = ji.put_json_data(url, self.jsessionid, data_json)

        except Exception, e:
            print traceback.format_exc()
            return False

        return result

    def get_snmpv2_agent(self, community='public'):

        result = None
        is_entry_found = False
        get_index = -1

        try:
            url = ji.get_url(self.req_api_snmp_agent, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.get_json_data(url, self.jsessionid)

            new_data = copy.deepcopy(recvd_data)

            for i in range(len(new_data['data']['communities'])):
                if new_data['data']['communities'][i]['communityName'] == community:
                    get_index = i
                    is_entry_found = True
                    break

            if not is_entry_found:
                #print 'get_snmpv2_agent(): community: %s does not exist' % community
                return None
            else:
                result = new_data['data']['communities'][get_index]

        except Exception, e:
            print traceback.format_exc()
            return None

        return result

    def get_snmpv3_agent(self, user='user1'):

        result = None
        is_entry_found = False
        get_index = -1

        try:
            url = ji.get_url(self.req_api_snmp_agent, self.scg_mgmt_ip, self.scg_port)
            recvd_data = ji.get_json_data(url, self.jsessionid)

            new_data = copy.deepcopy(recvd_data)

            for i in range(len(new_data['data']['users'])):
                if new_data['data']['users'][i]['userName'] == user:
                    get_index = i
                    is_entry_found = True
                    break

            if not is_entry_found:
                #print 'get_snmpv3_agent(): user: %s does not exist' % user
                return None
            else:
                result = new_data['data']['users'][get_index]

        except Exception, e:
            print traceback.format_exc()
            return None

        return result





if __name__ == '__main__':

    sjc = ScgJsonConfigSnmpAgent(scg_mgmt_ip='172.19.16.150', scg_port='8443')
    if not sjc._login(username='admin', password='ruckus1!'):
        print "user _login() failed"
        sys.exit(1)
    else:
        print "scg login success"

    if not sjc.get_snmpv2_agent(community='xyz123'):
        if not sjc.create_snmpv2_agent(community='xyz123'):
            print "create_snmpv2_agent() failed"
            sys.exit(1)
        else:
            print "create_snmpv2_agent() success"
    else:
        print "Warn: community already exists"

    if not sjc.get_snmpv3_agent(user='ln3333'):
        if not sjc.create_snmpv3_agent(user='ln3333', 
                auth_protocol='MD5',
                auth_passphrase='ruckus1!',
                privacy_protocol='AES',
                privacy_passphrase='ruckus1!'
        ):
            print "create_snmpv3_agent() failed"
            sys.exit(1)
        else:
            print "create_snmpv3_agent() success"
    else:
        print "Warn: user already exists"

    """
    if not sjc.delete_snmpv2_agent(community='spyder'):
        print "delete_snmpv2_agent() failed"
        sys.exit(1)
    else:
        print "delete_snmpv2_agent() success"

    if not sjc.delete_snmpv3_agent(user='user1'):
        print "delete_snmpv3_agent() failed"
        sys.exit(1)
    else:
        print "delete_snmpv3_agent() success"

    if not sjc.disable_global_snmp_trap():
        print "disable_global_snmp_trap() failed"
        sys.exit(1)
    else:
        print "disable_global_snmp_trap() success"

    if not sjc.enable_global_snmp_trap():
        print "enable_global_snmp_trap() failed"
        sys.exit(1)
    else:
        print "enable_global_snmp_trap() success"

    if not sjc.update_snmpv2_agent(current_community='hello234',
            new_community='zreddy',
            read_privilege=True,
            write_privilege=True):
        print "update_snmpv2_agent() failed"
        sys.exit(1)
    else:
        print "update_snmpv2_agent() success"

    if not sjc.update_snmpv3_agent(current_user='user1',
            new_user='user2',
            read_privilege=True,
            write_privilege=True,
            auth_protocol='MD5',
            auth_passphrase='ruckus1!'):
        print "update_snmpv3_agent() failed"
        sys.exit(1)
    else:
        print "update_snmpv3_agent() success"

    if not sjc.snmpv3_add_trap_target(current_user='user2',
            trap_target_ip='172.20.1.2'
            ):
        print "snmpv3_add_trap_target() failed"
        sys.exit(1)
    else:
        print "snmpv3_add_trap_target() success"
    """



