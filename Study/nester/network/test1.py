import paramiko, base64
key = paramiko.RSAKey(data=base64.decodestring('AAA...'))
client = paramiko.SSHClient()
client.get_host_keys().add('ssh.example.com', 'ssh-rsa', key)
client.connect('ssh.example.com', username='strongbad', password='thecheat')
stdin, stdout, stderr = client.exec_command('ls')
for line in stdout:
    print ('... ' + line.strip('\n'))
client.close()