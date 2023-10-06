from flask import Flask, render_template, request, redirect, url_for
import paramiko
import time 

app = Flask(__name__)

# Create an SSH client
ssh_client = paramiko.SSHClient()
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

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
        
        try:
            # Establish SSH connection
            ssh_client.connect(ip_address, port=22, username=ssh_username, password=ssh_password, allow_agent=False, look_for_keys=False)
            print("Successfully connected to " + ip_address)


            if hostname != '':
                # Execute command
                stdin, stdout, stderr = ssh_client.exec_command('enable')
                stdin, stdout, stderr = ssh_client.exec_command('admin')
                stdin, stdout, stderr = ssh_client.exec_command('conf t')
                stdin, stdout, stderr = ssh_client.exec_command('hostname ' + hostname)
                stdin, stdout, stderr = ssh_client.exec_command('end')
                output = stdout.readlines()
                print(output)
                time.sleep(.5)
            
            ssh_client.close()

            return render_template('ssh.html', output='Successfully connected to ' + ip_address)

        except Exception as e:
            return render_template('ssh.html', alert=str(e))
    
    return render_template('ssh.html', output=None)

if __name__ == '__main__':
    app.run(debug=True)
