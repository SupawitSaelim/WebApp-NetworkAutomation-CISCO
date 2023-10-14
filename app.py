from flask import Flask, render_template, request, redirect, url_for
from netmiko import ConnectHandler

app = Flask(__name__)

cisco_device = {
    'device_type': 'cisco_ios',
    'ip': '10.4.15.29',
    'username': 'admin',
    'password': 'admin',
    'session_log': 'output.log',  # Specify a log file
}


@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if username == 'admin' and password == 'admin':
        return redirect(url_for('ssh'))
    else:
        return '<script>alert("Incorrect username or password!!"); window.location.href="/";</script>'

@app.route('/ssh', methods=['GET', 'POST'])
def ssh():
    if request.method == 'POST':
        ip_address = request.form.get('ip_address')
        ssh_username = request.form.get('ssh_username')
        ssh_password = request.form.get('ssh_password')
        hostname = request.form.get('hostname')

        # Update the cisco_device dictionary with the form input
        cisco_device['ip'] = ip_address
        cisco_device['username'] = ssh_username
        cisco_device['password'] = ssh_password

        try:
            # Connect to the Cisco device
            net_connect = ConnectHandler(**cisco_device)
            net_connect.enable()

            if hostname != '':
                # Execute configuration commands
                config_commands = [
                    'enable',
                    'admin',
                    'configure terminal',
                    f'hostname {hostname}',
                    'end',
                ]
                output = net_connect.send_config_set(config_commands)
                print(output)
            
            net_connect.disconnect()

            return render_template('ssh.html', output=f'Successfully connected to {ip_address}')

        except Exception as e:
            return render_template('ssh.html', alert=str(e))
    
    return render_template('ssh.html', output=None)


if __name__ == '__main__':
    app.run(debug=True)
