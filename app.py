from flask import Flask, render_template, request, redirect, url_for, flash   
import json
import os
from netmiko import ConnectHandler
import paramiko

app = Flask(__name__, template_folder='templates')

app.secret_key = 'Supawitadmin123_'

json_file_path = 'cisco_device.json'
cisco_devices = []

if os.path.exists(json_file_path):
    with open(json_file_path, 'r') as f:
        try:
            cisco_devices = json.load(f)
        except json.JSONDecodeError:
            cisco_devices = []

@app.route('/')
def login_frist():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if username == 'admin' and password == 'admin':
        return redirect(url_for('index'))
    else:
        return '<script>alert("Incorrect username or password!!"); window.location.href="/";</script>'

@app.route('/logout', methods=['POST'])
def logout():
    return redirect(url_for('login_frist'))

@app.route('/index', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        name = request.form.get('name')
        ip_address = request.form.get('ip_address')
        ssh_username = request.form.get('ssh_username')
        ssh_password = request.form.get('ssh_password')
        secret_password = request.form.get('secret_password')

        for device in cisco_devices:
            if device['name'] == name or device['device_info']['ip'] == ip_address:
                return '<script>alert("Duplicate name or IP address found. Please try again!"); window.location.href="/index";</script>'

        cisco_device = {
            'name': name,
            'device_info': {
                'device_type': 'cisco_ios',
                'ip': ip_address,
                'username': ssh_username,
                'password': ssh_password,
                'secret': secret_password,
                'session_log': 'output.log',
            }
        }

        cisco_devices.append(cisco_device)
        with open(json_file_path, 'w') as f:
            json.dump(cisco_devices, f, indent=4)

    return render_template('index.html', cisco_devices=cisco_devices)

@app.route('/devices', methods=['GET', 'POST'])
def devices():
    return render_template('devices.html', cisco_devices=cisco_devices)

@app.route('/delete', methods=['POST'])
def delete_device():
    if request.method == 'POST':
        device_index = int(request.form.get('device_index'))
        if 0 <= device_index < len(cisco_devices):
            del cisco_devices[device_index]

            with open(json_file_path, 'w') as f:
                json.dump(cisco_devices, f, indent=4)

    return redirect(url_for('devices'))

@app.route('/basicedit', methods=['POST', 'GET'])
def basic_edit():
    return render_template('basicedit.html', cisco_devices=cisco_devices)

@app.route('/configure', methods=['POST'])
def configure():
    if request.method == 'POST':
        device_name = request.form.get('device_name')
        many_hostname = request.form.get('many_hostname')
        hostname = request.form.get('hostname')
        secret_password = request.form.get('secret_password')
        new_username = request.form.get('new_username')
        new_password = request.form.get('new_password')
        level_privilege = request.form.get('level_pri')
        service_password_encryption = request.form.get('password_encryption')
        enable_snmp = request.form.get('enable_snmp')
        save_config = request.form.get('save_config')
        default_gateway = request.form.get('default_gateway')
        enable_cdp = request.form.get('enable_cdp')
        raw_interfaces = request.form.get('interface').strip()
        ip_addresses = request.form.get('ip_address')
        active_interfaces = request.form.get('activate')
        deactivate_interfaces = request.form.get('deactivate')
        raw_vlan_id = request.form.get('vlan_id')
        vlan_name = request.form.get('vlan_name')
        raw_vlan_id_del = request.form.get('vlan_id_del')
        active_vlan = request.form.get('activate_vlan')
        deactive_vlan = request.form.get('deactivate_vlan')
        console_login_method = request.form.get('console_login_method')
        console_password = request.form.get('console_password')
        console_timeout = request.form.get('console_timeout')
        enable_loggin_syn_con = request.form.get('enable_loggin_syn_con')
        vty_login_method = request.form.get('vty_login_method')
        vty_password = request.form.get('vty_password')
        vty_timeout = request.form.get('vty_timeout')
        vty_transport = request.form.get('vty_transport')
        vty_range = request.form.get('vty_range')
        enable_loggin_syn_vty = request.form.get('enable_loggin_syn_vty')
        ntp_server = request.form.get('ntp_server')
        ntp_authentication = request.form.get('ntp_authentication')
        ntp_source_interface = request.form.get('ntp_source_interface')
        clock_timezone = request.form.get('clock_timezone')
        snmp_server = request.form.get('snmp_server')
        snmp_trap_level = request.form.get('snmp_trap_level')


        def parse_vlan_range(raw):
            ranges = raw.split(',')
            result = []
            for r in ranges:
                if r.strip():  # Check if the string is not empty or only contains whitespace
                    if '-' in r:
                        start, end = map(int, r.split('-'))
                        result.extend(range(start, end + 1))
                    else:
                        try:
                            result.append(int(r))
                        except ValueError:
                            pass
            return result

        
        vlan_id_list = parse_vlan_range(raw_vlan_id)
        vlan_id_del_list = parse_vlan_range(raw_vlan_id_del)

        def cidr_to_subnet_mask(cidr):
            try:
                cidr = int(cidr)
                if cidr < 0 or cidr > 32:
                    return None  # Invalid CIDR notation

                subnet_mask = (0xffffffff << (32 - cidr)) & 0xffffffff
                return ".".join([str((subnet_mask >> 24) & 0xff),
                                 str((subnet_mask >> 16) & 0xff),
                                 str((subnet_mask >> 8) & 0xff),
                                 str(subnet_mask & 0xff)])
            except ValueError:
                return None  # Invalid input
        
        ip_and_subnet_list = ip_addresses.split(',')
        interface_list = raw_interfaces.split(',')
        ip_list = []
        subnet_mask_list = []

        for item in ip_and_subnet_list:
            parts = item.split('/')
            if len(parts) == 2:
                ip, cidr = parts
                subnet_mask = cidr_to_subnet_mask(cidr)
                if subnet_mask:
                    ip_list.append(ip)
                    subnet_mask_list.append(subnet_mask)

        def configuration(device_info, device):

            if hostname:
                net_connect = ConnectHandler(**device_info)
                net_connect.enable()
                output = net_connect.send_config_set(['hostname ' + hostname])
                print(output)
                net_connect.disconnect()
                device['name'] = hostname

            if secret_password:
                net_connect = ConnectHandler(**device_info)
                net_connect.enable()
                output = net_connect.send_config_set(['enable secret ' + secret_password])
                print(output)
                net_connect.disconnect()

                device['device_info']['secret'] = secret_password
            
            if interface_list and ip_list and subnet_mask_list:
                try:
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    config_commands = []

                    for interface, ip, subnet_mask in zip(interface_list, ip_list, subnet_mask_list):
                        if active_interfaces == "enable":
                            config_commands.append('interface ' + interface)
                            config_commands.append('ip address ' + ip + ' ' + subnet_mask)
                            config_commands.append('no shutdown')
                        elif deactivate_interfaces == "enable":
                            config_commands.append('interface ' + interface)
                            config_commands.append('no ip address ' + ip + ' ' + subnet_mask)
                            config_commands.append('shutdown')

                    output = net_connect.send_config_set(config_commands)
                    print(output)
                    net_connect.disconnect()
                except Exception as e:
                    print("An error occurred:", str(e))
            else:
                print("One or more required lists are empty (raw_interfaces, ip_list, subnet_mask_list).")
            
            if interface_list and active_interfaces == "enable" or deactivate_interfaces == "enable":
                for interface in interface_list:
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    config_commands = []
                    if active_interfaces == "enable":
                        config_commands.append('interface range ' + interface)
                        config_commands.append('no shutdown')
                    elif deactivate_interfaces == "enable":
                        config_commands.append('interface range ' + interface)
                        config_commands.append('shutdown')
                    output = net_connect.send_config_set(config_commands)
                    print(output)
                    net_connect.disconnect()

            if vlan_id_list :
                for vlan_id in vlan_id_list:
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    config_commands = []
                    config_commands.append('vlan ' + str(vlan_id))
                    if vlan_name:
                        config_commands.append('name ' + vlan_name + '_' + str(vlan_id))
                    if active_vlan == "enable":
                        config_commands.append('no shutdown')
                    elif deactive_vlan == "enable":
                        config_commands.append('shutdown')
                    else:
                        pass
                    output = net_connect.send_config_set(config_commands)
                    print(output)
                    net_connect.disconnect()
            
            if vlan_id_del_list:
                for vlan_id_del in vlan_id_del_list:
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    config_commands = []
                    config_commands.append('no vlan ' + str(vlan_id_del))
                    output = net_connect.send_config_set(config_commands)
                    print(output)
                    net_connect.disconnect()

            if default_gateway:
                net_connect = ConnectHandler(**device_info)
                net_connect.enable()
                output = net_connect.send_config_set(['ip default-gateway ' + default_gateway])
                print(output)
                net_connect.disconnect()

            if new_username and new_password and level_privilege:
                net_connect = ConnectHandler(**device_info)
                net_connect.enable()
                output = net_connect.send_config_set(
                    ['username ' + new_username + ' privilege ' + level_privilege + ' secret ' + new_password])
                print(output)
                net_connect.disconnect()
            
            if console_login_method != 'none':
                if console_login_method == 'login':
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    commands = ['line console 0', 'login']
                    output = net_connect.send_config_set(commands)
                    print(output)
                    net_connect.disconnect()
                elif console_login_method == 'login_local':
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    commands = ['line console 0', 'login local']
                    output = net_connect.send_config_set(commands)
                    print(output)
                    net_connect.disconnect()
                elif console_login_method == 'no_login':
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    commands = ['line console 0', 'no login']
                    output = net_connect.send_config_set(commands)
                    print(output)
                    net_connect.disconnect()
            
            if console_password:
                net_connect = ConnectHandler(**device_info)
                net_connect.enable()
                output = net_connect.send_config_set(['line console 0', 'password ' + console_password])
                print(output)
                net_connect.disconnect()
            
            if console_timeout:
                net_connect = ConnectHandler(**device_info)
                net_connect.enable()
                output = net_connect.send_config_set(['line console 0', 'exec-timeout ' + console_timeout + ' 0'])
                print(output)
                net_connect.disconnect()
            
            if enable_loggin_syn_con == 'enable':
                net_connect = ConnectHandler(**device_info)
                net_connect.enable()
                output = net_connect.send_config_set(['line console 0', 'logging synchronous'])
                print(output)
                net_connect.disconnect()

            if vty_login_method != 'none':
                if vty_login_method == 'login':
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    commands = []
                    if vty_range:
                        commands.append('line vty ' + vty_range)
                        commands.append('login')
                    else:
                        commands.append('line vty 0 4')
                        commands.append('login')
                    output = net_connect.send_config_set(commands)
                    print(output)
                    net_connect.disconnect()
                elif vty_login_method == 'login_local':
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    commands = []
                    if vty_range:
                        commands.append('line vty ' + vty_range)
                        commands.append('login local')
                    else:
                        commands.append('line vty 0 4')
                        commands.append('login local')
                    output = net_connect.send_config_set(commands)
                    print(output)
                    net_connect.disconnect()
                elif vty_login_method == 'no_login':
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    commands = []
                    if vty_range:
                        commands.append('line vty ' + vty_range)
                        commands.append('no login')
                    else:
                        commands.append('line vty 0 4')
                        commands.append('no login')
                    output = net_connect.send_config_set(commands)
                    print(output)
                    net_connect.disconnect()

            if vty_password:
                if vty_range:
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    output = net_connect.send_config_set(['line vty ' + vty_range, 'password ' + vty_password])
                    print(output)
                    net_connect.disconnect()
                else:
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    output = net_connect.send_config_set(['line vty 0 4', 'password ' + vty_password])
                    print(output)
                    net_connect.disconnect()
            
            if vty_timeout:
                if vty_range:
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    output = net_connect.send_config_set(['line vty ' + vty_range, 'exec-timeout ' + vty_timeout + ' 0'])
                    print(output)
                    net_connect.disconnect()
                else:
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    output = net_connect.send_config_set(['line vty 0 4', 'exec-timeout ' + vty_timeout + ' 0'])
                    print(output)
                    net_connect.disconnect()
            
            if vty_transport != 'none':
                if vty_range:
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    output = net_connect.send_config_set(['line vty ' + vty_range, 'transport input' + vty_transport])
                    print(output)
                    net_connect.disconnect()
                else:
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    output = net_connect.send_config_set(['line vty 0 4', 'transport input ' + vty_transport])
                    print(output)
                    net_connect.disconnect()
            
            if enable_loggin_syn_vty == 'enable':
                if vty_range:
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    output = net_connect.send_config_set(['line vty ' + vty_range, 'logging synchronous'])
                    print(output)
                    net_connect.disconnect()
                else:
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    output = net_connect.send_config_set(['line vty 0 4', 'logging synchronous'])
                    print(output)
                    net_connect.disconnect()

            if ntp_server:
                config_commands = []
                config_commands.append(f'ntp server {ntp_server}')
                if ntp_authentication:
                    config_commands.append(f'ntp authentication-key 1 md5 {ntp_authentication}')
                    config_commands.append('ntp trusted-key 1')
                    config_commands.append('ntp update-calendar')
                if ntp_source_interface:
                    config_commands.append(f'ntp source {ntp_source_interface}')

                if config_commands:
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    output = net_connect.send_config_set(config_commands)
                    print(output)
                    net_connect.disconnect()

            if clock_timezone:
                net_connect = ConnectHandler(**device_info)
                net_connect.enable()
                output = net_connect.send_config_set(['clock timezone ' + clock_timezone])
                print(output)
                net_connect.disconnect()

            if snmp_server:
                config_commands = []
                snmp_trap_level = request.form.get('snmp_trap_level')
                
                if not snmp_trap_level:
                    snmp_trap_level = 'warning'  # Default to "warning" if not specified
                config_commands.append(f'logging trap {snmp_trap_level}')
                config_commands.append(f'logging {snmp_server}')
                
                if config_commands:
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    output = net_connect.send_config_set(config_commands)
                    print(output)
                    net_connect.disconnect()

            if service_password_encryption == "enable":
                net_connect = ConnectHandler(**device_info)
                net_connect.enable()
                output = net_connect.send_config_set(['service password-encryption'])
                print(output)
                net_connect.disconnect()

            if enable_snmp == "enable":
                net_connect = ConnectHandler(**device_info)
                net_connect.enable()
                output = net_connect.send_config_set(['snmp-server community public RO'])
                print(output)
                net_connect.disconnect()

            if enable_cdp == "enable":
                net_connect = ConnectHandler(**device_info)
                net_connect.enable()
                output = net_connect.send_config_set(['cdp run'])
                print(output)
                net_connect.disconnect()

            if save_config == "enable":
                net_connect = ConnectHandler(**device_info)
                net_connect.enable()
                output = net_connect.send_command_timing('write')
                print(output)
                net_connect.disconnect()

        # many hostname
        if many_hostname:
            many_names = [name.strip() for name in many_hostname.split(',')]
            print(many_names)
            try:
                for name in many_names:
                    print(name)
                    try:
                        for device in cisco_devices:
                            if device['name'] == name:
                                device_info = device['device_info']
                                ip = device_info['ip']

                                if not is_ssh_reachable(ip, device_info['username'], device_info['password']):
                                    return '<script>alert("SSH connection failed. Make sure SSH is enabled and credentials are correct."); window.location.href="/basicedit";</script>'
                                
                                configuration(device_info, device)

                        with open(json_file_path, 'w') as f:
                            json.dump(cisco_devices, f, indent=4)

                    except Exception as e:
                        print(e)
                        if str(e).startswith('Failed to enter enable mode.'):
                            return '<script>alert("Failed to enter enable mode. Please ensure you set secret in device"); window.location.href="/basicedit";</script>'
                        return '<script>alert("Something went wrong. Please try again!"); window.location.href="/basicedit";</script>'
                return '<script>alert("Configuration successful!"); window.location.href="/basicedit";</script>'
            except Exception as e:
                print(e)

        # single hostname
        try:
            for device in cisco_devices:
                if device['name'] == device_name:
                    device_info = device['device_info']
                    ip = device_info['ip']

                    if not is_ssh_reachable(ip, device_info['username'], device_info['password']):
                        return '<script>alert("SSH connection failed. Make sure SSH is enabled and credentials are correct."); window.location.href="/basicedit";</script>'

                    configuration(device_info, device)

            with open(json_file_path, 'w') as f:
                json.dump(cisco_devices, f, indent=4)

            return '<script>alert("Configuration successful!"); window.location.href="/basicedit";</script>'
        except Exception as e:
            print(e)
            if str(e).startswith('Failed to enter enable mode.'):
                return '<script>alert("Failed to enter enable mode. Please ensure you set secret in device"); window.location.href="/basicedit";</script>'
            return '<script>alert("Something went wrong. Please try again!"); window.location.href="/basicedit";</script>'

@app.route('/routing', methods=['POST', 'GET'])
def routing():
    return render_template('routing.html', cisco_devices=cisco_devices)

@app.route('/routing-config', methods=['POST', 'GET'])
def config_routing():
    if request.method == 'POST':
        device_name = request.form.get('device_name')
        default_route = request.form.get('default_route')
        delete_route = request.form.get('delete_route')
        process_id = request.form.get('process_id')
        router_id = request.form.get('router_id')
        network_ospf_remove = request.form.get('network_ospf_remove')
        wildcard_ospf_remove = request.form.get('wildcard_ospf_remove')
        area_ospf_remove = request.form.get('area_ospf_remove')
        remove_process_id = request.form.get('remove_process_id')
    
    for device in cisco_devices:
        if device['name'] == device_name:
            device_info = device['device_info']
            try:
                ip = device_info['ip']
                if not is_ssh_reachable(ip, device_info['username'], device_info['password']):
                    return '<script>alert("SSH connection failed. Make sure SSH is enabled and credentials are correct."); window.location.href="/basicedit";</script>'

                def cidr_to_subnet_mask(cidr):
                    try:
                        cidr = int(cidr)
                        if cidr < 0 or cidr > 32:
                            return None  # Invalid CIDR notation

                        subnet_mask = (0xffffffff << (32 - cidr)) & 0xffffffff
                        return ".".join([str((subnet_mask >> 24) & 0xff),
                                        str((subnet_mask >> 16) & 0xff),
                                        str((subnet_mask >> 8) & 0xff),
                                        str(subnet_mask & 0xff)])
                    except ValueError:
                        return None  
                    
                if default_route:
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    default_route_commands = default_route.split(',')
                    for route in default_route_commands:
                        command = f'ip route 0.0.0.0 0.0.0.0 {route.strip()}'
                        output = net_connect.send_config_set(command)
                        print(output)
                    net_connect.disconnect()

                for i in range(1, 5): 
                    network_static = request.form.get(f'network_static_{i}')
                    exit_static = request.form.get(f'exit_static_{i}')
                    
                    if network_static and exit_static:
                        network, cidr = network_static.split('/')
                        subnet_mask = cidr_to_subnet_mask(int(cidr))
                        
                        if subnet_mask:
                            route_command = f'ip route {network} {subnet_mask} {exit_static}'
                            net_connect = ConnectHandler(**device_info)
                            net_connect.enable()
                            output = net_connect.send_config_set(route_command)
                            print(output)
                            net_connect.disconnect()
                
                if delete_route:
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    command = f'no ip route'
                    network, cidr = delete_route.split('/')
                    subnet_mask = cidr_to_subnet_mask(int(cidr))
                    if subnet_mask:
                        command += f' {network} {subnet_mask}'
                    output = net_connect.send_config_set(command)
                    print(output)
                    net_connect.disconnect()
                
                if process_id:
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    commands = ['router ospf ' + process_id]
                    if router_id:
                        commands.append('router-id ' + router_id)
                    for i in range(1,4):
                        network_ospf = request.form.get(f'network_ospf_{i}')
                        wildcard_ospf = request.form.get(f'wildcard_ospf_{i}')
                        area_ospf = request.form.get(f'area_ospf_{i}')
                        if network_ospf and wildcard_ospf and area_ospf:
                            commands.append(f'network {network_ospf} {wildcard_ospf} area {area_ospf}')
                    output = net_connect.send_config_set(commands)
                    print(output)
                    net_connect.disconnect()
                
                if network_ospf_remove and wildcard_ospf_remove and area_ospf_remove and process_id:
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    command = ['router ospf ' + process_id]
                    command.append(f'no network {network_ospf_remove} {wildcard_ospf_remove} area {area_ospf_remove}')
                    output = net_connect.send_config_set(command)
                    print(output)
                    net_connect.disconnect()
                
                if remove_process_id:
                    net_connect = ConnectHandler(**device_info)
                    net_connect.enable()
                    command = f'no router ospf {remove_process_id}'
                    output = net_connect.send_config_set(command)
                    print(output)
                    net_connect.disconnect()

                

            

                    





                return '<script>alert("Configuration successful!"); window.location.href="/routing";</script>'
            except Exception as e:
                print(e)
                if str(e).startswith('Failed to enter enable mode.'):
                    return '<script>alert("Failed to enter enable mode. Please ensure you set secret in device"); window.location.href="/routing";</script>'
                return '<script>alert("Something went wrong. Please try again!"); window.location.href="/routing";</script>'
            
@app.route('/eraseconfig', methods=['POST', 'GET'])
def eraseconfig():
    return render_template('eraseconfig.html', cisco_devices=cisco_devices)

@app.route('/erase', methods=['POST'])
def erase_device():
    if request.method == 'POST':
        device_index = int(request.form.get('device_index'))
        if 0 <= device_index < len(cisco_devices):
            device = cisco_devices[device_index]
            device_info = device['device_info']

            try:
                net_connect = ConnectHandler(**device_info)
                net_connect.enable()

                output = net_connect.send_command_timing('erase startup-config')
                if 'confirm' in output:
                    output += net_connect.send_command_timing('')
                output += net_connect.send_command_timing('reload')
                if 'confirm' in output:
                    output += net_connect.send_command_timing('no')
                if 'confirm' in output:
                    output += net_connect.send_command_timing('')
                
                net_connect.disconnect()
                del cisco_devices[device_index]
                with open(json_file_path, 'w') as f:
                    json.dump(cisco_devices, f, indent=4)

                return '<script>alert("Configuration erased successfully! Device will reload."); window.location.href="/eraseconfig";</script>'
            except Exception as e:
                print(e)
                return '<script>alert("Failed to erase configuration. Please try again."); window.location.href="/eraseconfig";</script>'

    return redirect(url_for('eraseconfig'))

@app.route('/showconfig', methods=['POST', 'GET'])
def showconfig():
    return render_template('showconfig.html', cisco_devices=cisco_devices)

@app.route('/show-config', methods=['POST', 'GET'])
def show_config():
    if request.method == 'POST':
        device_name = request.form.get('device_name')
        selected_commands = request.form.getlist('selected_commands')  # Get all selected commands as a list

        for device in cisco_devices:
            if device['name'] == device_name:
                device_info = device['device_info']
                try:
                    config_data = ""

                    if "show_running_config" in selected_commands:
                        net_connect = ConnectHandler(**device_info)
                        net_connect.enable()
                        output = net_connect.send_command('show running-config')
                        net_connect.disconnect()
                        config_data += "===== show running config =====\n" + output + "\n"

                    if "show_version" in selected_commands:
                        net_connect = ConnectHandler(**device_info)
                        net_connect.enable()
                        output = net_connect.send_command('show version')
                        net_connect.disconnect()
                        config_data += "===== show version =====\n" + output + "\n"

                    if "show_interfaces" in selected_commands:
                        net_connect = ConnectHandler(**device_info)
                        net_connect.enable()
                        output = net_connect.send_command('show interfaces')
                        net_connect.disconnect()
                        config_data += "===== show interfaces =====\n" + output + "\n"
                    
                    if "show_ip_interface_brief" in selected_commands:
                        net_connect = ConnectHandler(**device_info)
                        net_connect.enable()
                        output = net_connect.send_command('show ip interface brief')
                        net_connect.disconnect()
                        config_data += "===== show ip interface brief =====\n" + output + "\n"

                    if "show_ip_route" in selected_commands:
                        net_connect = ConnectHandler(**device_info)
                        net_connect.enable()
                        output = net_connect.send_command('show ip route')
                        net_connect.disconnect()
                        config_data += "===== show ip route =====\n" + output + "\n"

                    if "show_vlan" in selected_commands:
                        net_connect = ConnectHandler(**device_info)
                        net_connect.enable()
                        output = net_connect.send_command('show vlan')
                        net_connect.disconnect()
                        config_data += "===== show vlan =====\n" + output + "\n"

                    if "show_cdp_neighbors" in selected_commands:
                        net_connect = ConnectHandler(**device_info)
                        net_connect.enable()
                        output = net_connect.send_command('show cdp neighbors')
                        net_connect.disconnect()
                        config_data += "===== show cdp neighbors =====\n" + output + "\n" 

                    if "show_ip_protocols" in selected_commands:
                        net_connect = ConnectHandler(**device_info)
                        net_connect.enable()
                        output = net_connect.send_command('show ip protocols')
                        net_connect.disconnect()
                        config_data += "===== show ip protocols =====\n" + output + "\n"             

                    return render_template('showconfig.html', cisco_devices=cisco_devices, config_data=config_data)

                except Exception as e:
                    print(e)
                    error_message = "Failed to retrieve configuration. Please try again."
                    return render_template('showconfig.html', cisco_devices=cisco_devices, error_message=error_message)

    return render_template('showconfig.html', cisco_devices=cisco_devices)


def is_ssh_reachable(ip, username, password):
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(ip, username=username, password=password, timeout=5)
        ssh_client.close()
        return True
    except Exception as e:
        print(e)
        return False



if __name__ == '__main__':
    app.run(debug=True)

