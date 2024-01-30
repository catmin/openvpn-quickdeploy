
Prepare
```
ssh-keygen -t ed25519 -C "student"
pip install -r requirements.txt
```

Installation on a remote host
```
ansible-playbook -i its23vpn.westeurope.cloudapp.azure.com, -u sba --ask-pass play.yml
```

Local installation

ansible-playbook --connection=local --inventory=127.0.0.1, play.yml 

```

Create a CA
```
python3 ca.py -c
```

Create a server cert/key
```
python3 ca.py -s its23vpn.westeurope.cloudapp.azure.com
```

user experience: use the ID file to connect to the VPN server and create configuation. Run openvpn with the created client configuration. 
```
ssh -v -i id_ed25519 student@localhost sudo -g vpn-self-service ca.py -u > client.ovpn
sudo openvpn client.ovpn
```
Openvpn connects to the VPN server using a udp/1194 connection and authenticates using certificates.
The VPN-IP is allocated dynamically and openvpn pushes the necessary routes.

