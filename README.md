

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
```

Deploy via ansible
```
python3 ca.py -u >client.ovpn
sudo openvpn client.ovpn
```
