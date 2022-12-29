from cryptography.hazmat.primitives import serialization    # For key serialization
from cryptography.hazmat.primitives.asymmetric import rsa   # Generate our key
from cryptography.x509.oid import NameOID               # For certificate builder
from datetime import datetime
import datetime
from cryptography.hazmat.primitives import hashes
import os
from cryptography.hazmat.primitives.asymmetric import padding       # For padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF            # For Hkdf function
from cryptography import x509

def generate_key(user):
    ''' This function generates different length keys for CA, Alice and Bob as per the requirement and stores them '''

    if user == "CA":
        ca_pvt_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)  # Write ca key to disk for safe keeping
        with open("ca_pvt_key.pem", "wb") as f:
            f.write(ca_pvt_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase")))
        print("-----CA key generated------")

    elif user == "alice":
        alice_pvt_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # Write alice key to disk for safe keeping
        with open("alice_pvt_key.pem", "wb") as g:
            g.write(alice_pvt_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase")))
        print("-----Alice key generated------")

    else:
        bob_pvt_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # Write bob key to disk for safe keeping
        with open("bob_pvt_key.pem", "wb") as h:
            h.write(bob_pvt_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase")))
        print("------Bob key generated------")

def ca_cert():
    ''' Creating self signed certificate for CA '''

    with open("ca_pvt_key.pem", "rb") as key_file:
        ca_pvt_key = serialization.load_pem_private_key(key_file.read(), password=b"passphrase")

    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"cz"), x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"olympia"),x509.NameAttribute(NameOID.LOCALITY_NAME, u"brno"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My newcompany"), x509.NameAttribute(NameOID.COMMON_NAME, u"myest.com")])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(ca_pvt_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)).add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]), critical=False, ).sign(ca_pvt_key, hashes.SHA256())

    with open("ca_certificate.pem", "wb") as f:     # Write ca certificate out to disk.
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print("-----CA cert generated-----")

def csr_alice():
    '''  Creating CSR for Alice '''

    with open("alice_pvt_key.pem", "rb") as key_file:        # Loading the Alice private key
        alice_pvt_key = serialization.load_pem_private_key(key_file.read(), password=b"passphrase")
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([ x509.NameAttribute(NameOID.COUNTRY_NAME, u"us"),x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"jersey"), x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My work"), x509.NameAttribute(NameOID.COMMON_NAME, u"forsite.com"),])).add_extension(x509.SubjectAlternativeName([x509.DNSName(u"forsite.com"),x509.DNSName(u"www.forsite.com"), x509.DNSName(u"subdomain.forsite.com"),]), critical=False,).sign(alice_pvt_key, hashes.SHA256())          # Sign the CSR with alice private key.
    with open("alice_csr.pem", "wb") as f:          # storing Alice CSR
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    print("------CSR for alice generated-----")

def csr_bob():
    '''  Creating CSR for Bob '''

    with open("bob_pvt_key.pem", "rb") as key_file:         # Loading Bob private key
        bob_pvt_key = serialization.load_pem_private_key(key_file.read(), password=b"passphrase")
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"cn"),x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"alberta"), x509.NameAttribute(NameOID.LOCALITY_NAME, u"Bowden"),x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My job"),x509.NameAttribute(NameOID.COMMON_NAME, u"onlysite.com"),])).add_extension(x509.SubjectAlternativeName([x509.DNSName(u"onlysite.com"),x509.DNSName(u"www.onlysite.com"),x509.DNSName(u"subdomain.onlysite.com"),]),critical=False,).sign(bob_pvt_key, hashes.SHA256())             # Sign the CSR bob private key.
    with open("bob_csr.pem", "wb") as f:               # storing Bob CSR
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    print("------CSR for bob generated-----")


def sign_cert(user):
    ''' This function signs the certificate for Alice/ Bob depending upon the passed argument '''

    if user == "alice":
        with open("alice_pvt_key.pem", "rb") as key_file:       # Loading Alice private key and CSR for certificate generation
            user_pvt_key = serialization.load_pem_private_key(key_file.read(), password=b"passphrase")
        with open("alice_csr.pem", "rb") as f:
            user_csr = x509.load_pem_x509_csr(f.read())


    else:
        with open("bob_pvt_key.pem", "rb") as key_file:         # Loading Bob private key and CSR for certificate generation
            user_pvt_key = serialization.load_pem_private_key(key_file.read(), password=b"passphrase")
        with open("bob_csr.pem", "rb") as f:
            user_csr = x509.load_pem_x509_csr(f.read())

    with open("ca_pvt_key.pem", "rb") as key_f:                 # Loading CA details for certificate signing
        ca_pvt_key = serialization.load_pem_private_key(key_f.read(), password=b"passphrase")
    with open("ca_certificate.pem", "rb") as m:
        ca_cert = x509.load_pem_x509_certificate(m.read())

    crt = x509.CertificateBuilder().subject_name(user_csr.subject).issuer_name(ca_cert.issuer).public_key(user_pvt_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)).add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]), critical=False, ).sign(ca_pvt_key, hashes.SHA256())

    if user == "alice":
        with open("alice_certificate.pem", "wb") as f:
            f.write(crt.public_bytes(serialization.Encoding.PEM))
        print("------Alice certificate signed by CA-----")

    else:
        with open("bob_certificate.pem", "wb") as g:
            g.write(crt.public_bytes(serialization.Encoding.PEM))
        print("------Bob certificate signed by CA-----")



def main():
    input("Press enter to generate CA 4096 bit key")
    generate_key("CA")         # generating key for CA
    input("Press enter to generate key for alice")
    generate_key("alice")
    input("Press enter to generate key for bob")
    generate_key("bob")

    input("Press enter to generate ca self signed cert")
    ca_cert()                 # generating CA cert - self signed
    input("Press enter to generate certificate signing request for alice and bob ")
    csr_alice()
    csr_bob()
    input("Press enter for Generating certificates for alice and bob with CA private key ")
    sign_cert("alice")
    sign_cert("bob")

   
if __name__ == "__main__":
    main()

