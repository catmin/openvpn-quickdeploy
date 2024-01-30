#!/usr/bin/env python3

import sys, getopt
import random, string
from OpenSSL import crypto, SSL
import os 

class FileStore:

    ca_cert_path = "ca.crt"
    ca_key_path = "ca.key"
    server_cert_path = "server.crt"
    server_key_path = "server.key"


    def __init__(self, target_dir=None):
        self.target_dir = target_dir

    def get_abs_path(self, rel_path):
        return os.path.join(self.target_dir, rel_path)

    @staticmethod
    def get_cert_pem(x509_cert):
        return crypto.dump_certificate(crypto.FILETYPE_PEM, x509_cert)

    @staticmethod
    def get_key_pem(x509_key):
        return crypto.dump_privatekey(crypto.FILETYPE_PEM, x509_key)

    def store_serial(self, serial):
        open(self.get_abs_path("serial"), 'w').write(serial)
        return

    def get_serial(self):
        serial = int(open(self.get_abs_path("serial"), 'r').read())
        return serial

    def set_serial(self, serial):
        open(self.get_abs_path("aerial"), 'w').write(str(serial))


    def store_ca(self, cert, key):
        cacert_path = self.get_abs_path(self.ca_cert_path) 
        cakey_path = self.get_abs_path(self.ca_key_path) 
        with open(cacert_path, 'wb') as certificate:
            certificate.write(self.get_cert_pem(cert))
        with open(cakey_path, 'wb') as privatekey:
            privatekey.write(self.get_key_pem(key))
        return cert, key

    def get_ca(self):
        cert_path = self.get_abs_path(self.ca_cert_path) 
        key_path = self.get_abs_path(self.ca_key_path) 
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(cert_path).read())
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(key_path).read())
        return cert, key

    def store_server_cert(self, cert, key):
        cert_path = self.get_abs_path(self.server_cert_path.format(cert.get_serial_number())) 
        key_path = self.get_abs_path(self.server_key_path.format(cert.get_serial_number())) 
        with open(cert_path, 'wb') as certificate:
            certificate.write(self.get_cert_pem(cert))
        with open(key_path, 'wb') as privatekey:
            privatekey.write(self.get_key_pem(key))
        return cert, key

    def store_client_cert(self, cert, key):
        ca_cert, ca_key = self.get_ca()
        subj = cert.get_subject()
        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
        ca_cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert)
        ovpn_template = """
dev tun
cipher AES-256-CBC
client
remote its23vpn.westeurope.cloudapp.azure.com 1194 udp4
comp-lzo
route 10.6.0.0 255.255.255.0
verb 4
<ca>
{0}
</ca>
<cert>
{1}
</cert>
<key>
{2}
</key>
    """.format(ca_cert_pem.decode("utf-8"), cert_pem.decode("utf-8"), key_pem.decode("utf-8"))
        print(ovpn_template)
        #with open("x", "w") as f:
        #    f.write(ovpn_template)


class OpenVpnCa:
    """ creates certificates and stores them locally into the filesystem """

    # ca cert expiration time 
    CA_VALID = 6*30*24*60*60 # 6 month
    # client / server cert expiration time
    CERT_VALID = 3*30*24*60*60 # 3 month
    # ca bit length
    CA_BITS = 4096
    # server cert bit length
    SERVER_BITS = 4096
    # client cert bit length 
    NERF_BITS = 4096
    # default signing algorithm
    SIGN_ALGO = "sha256"
    # initial serial
    # INIT_SERIAL = 1000

    def __init__(self, create_new=False):
        store = FileStore("/opt/pki/")
        self.store = store 
        if create_new:

            #self.serial = self.INIT_SERIAL
            self.create_ca_cert()
        else:
            self.load_ca_from_store(store)
        return

    def load_ca_from_store(self, store):
        # get ca cert from store
        cert, key = store.get_ca()
        #serial = store.get_serial()
        # assign to object
        self.ca_cert = cert
        self.ca_key = key
        #self.serial = serial
        return cert, key 

    def get_next_serial_nr(self):
        #print("serial is {0}".format(self.serial))
        #self.serial += 1 
        #TODO save serial?
        #self.store.set_serial(self.serial)
        #return self.serial
        return random.getrandbits(48) 
        
    def gen_key(self, bits_len):
        """
        create a RSA key with defined bit length
        """
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, bits_len)
        return key

    def create_ca_cert(self):
        """ create ca certificate and key and store it """
        key = self.gen_key(self.CA_BITS)

        cert = crypto.X509()
        cert.set_version(0x2) # version 3
        cert.get_subject().O = "ITS23"
        cert.get_subject().CN = "CA"
        # initial serial is used for ca cert
        cert.set_serial_number(self.get_next_serial_nr())
        # start today
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(self.CA_VALID)
        # self sign
        cert.set_issuer(cert.get_subject())
        ca_constraints = ([
            crypto.X509Extension(b"keyUsage", True, b"keyCertSign"),
            crypto.X509Extension(b"basicConstraints", False, b"CA:TRUE"),
            #crypto.X509Extension("extendedKeyUsage",False,"serverAuth"), for client auth
        ])
        x509_extensions = ca_constraints
        cert.add_extensions(x509_extensions)
        cert.set_pubkey(key)
        cert.sign(key, self.SIGN_ALGO)

        # store
        self.store.store_ca(cert, key)    

        # for future use of the object
        self.ca_cert = cert
        self.ca_key = key

        return self.ca_cert, self.ca_key
    
    def get_ca_cert(self):
        return self.store.get_ca()    

    def create_server_cert(self, fqdn):
        """ vpn endpoint cert """
        cert = crypto.X509()
        cert.set_version(0x2) # version 3
        cert.get_subject().O = "ITS"
        cert.get_subject().CN = fqdn
        cert.set_serial_number(self.get_next_serial_nr())
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(self.CERT_VALID)
        cert.set_issuer(self.ca_cert.get_subject())
        san_list = str.encode("DNS:{0}".format(fqdn))
        server_extensions = ([
            crypto.X509Extension(b"keyUsage", False, b"Digital Signature, Non Repudiation, Key Encipherment"),
            crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
            crypto.X509Extension(b"subjectAltName", False, san_list)
            #crypto.X509Extension("extendedKeyUsage",False,"serverAuth"), for client auth
        ])
        cert.add_extensions(server_extensions)
        key = self.gen_key(self.SERVER_BITS)
        cert.set_pubkey(key)
        cert.sign(self.ca_key, self.SIGN_ALGO)

        # store to database
        self.store.store_server_cert(cert, key)

        return cert, key

    def create_client_cert(self, cn):
        """ vpn endpoint cert """
        cert = crypto.X509()
        cert.set_version(0x2) # version 3
            cert.get_subject().O = "ITS"
        cert.get_subject().CN = cn
        cert.set_serial_number(self.get_next_serial_nr())
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(self.CERT_VALID)
        cert.set_issuer(self.ca_cert.get_subject())
        base_constraints = ([
            crypto.X509Extension(b"keyUsage", False, b"Digital Signature, Non Repudiation, Key Encipherment"),
            crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
            #crypto.X509Extension("extendedKeyUsage",False,"serverAuth"), for client auth
        ])
        x509_extensions = base_constraints
        cert.add_extensions(x509_extensions)
        key = self.gen_key(self.SERVER_BITS)
        cert.set_pubkey(key)
        cert.sign(self.ca_key, self.SIGN_ALGO)

        # store to database
        self.store.store_client_cert(cert, key)

        return cert, key



def create_new_ca():
    ca = OpenVpnCa(create_new=True)

def create_server_cert(fqdn):
    ca = OpenVpnCa()
    ca.create_server_cert(fqdn)

def create_client_cert(outfile):
    ca = OpenVpnCa()
    ca_cert, ca_key = ca.get_ca_cert()
    cn = ''.join(random.choice(string.ascii_letters) for i in range(20))
    ca.create_client_cert(cn)


def usage():
    print ('ca.py -c create new CA')
    print ('ca.py -s <fqdn> create new server cert and key')
    print ('ca.py -u create user cert')

def main(argv):
    inputfile = ''
    outputfile = ''
    try:
        opts, args = getopt.getopt(argv,"hcus:",[])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            usage()
            sys.exit()
        elif opt == '-c':
            create_new_ca()
        elif opt == '-s':
            fqdn = arg
            create_server_cert(fqdn)
        elif opt == '-u':
            cn = arg
            create_client_cert(cn)
        #elif opt in ("-o", "--outfile"):
            #outputfile = arg


if __name__ == "__main__":
    main(sys.argv[1:])

