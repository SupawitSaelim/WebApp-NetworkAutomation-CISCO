from flask import Flask, render_template, request, redirect, url_for
import json
import os
from netmiko import ConnectHandler

app = Flask(__name__, template_folder='templates')

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
        hostname = request.form.get('hostname')
        if hostname != '':
            net_connect = ConnectHandler(**cisco_devices[device_name]['device_info'])
            net_connect.enable()
            output = net_connect.send_config_set(['hostname ' + hostname])
            print(output)
            net_connect.disconnect()

        return redirect(url_for('basic_edit'))





    
if __name__ == '__main__':
    app.run(debug=True)
