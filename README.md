

Create a CA
```
mkdir pki
python3 ca.py -c
```

Create a server cert/key
```
python3 ca.py -s its23vpn.westeurope.cloudapp.azure.com
```

Deploy via ansible
```
ansible-playbook -i its23vpn.westeurope.cloudapp.azure.com, -u sba --ask-pass play.yml

or locally

ansible-playbook --connection=local --inventory=127.0.0.1, play.yml 
```

ssh-keygen -t ed25519 -C "student"

user experience
```
ssh -v -i id_ed25519 student@localhost
sudo -g vpn-self-service ca.py -u
sudo openvpn client.ovpn
```
sudo ansible-playbook --connection=local --inventory=127.0.0.1, play.yml
