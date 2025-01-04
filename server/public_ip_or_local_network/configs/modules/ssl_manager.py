# configs/modules/ssl_manager.py

import os
import ssl
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

class SSLManager:
    def __init__(self):
        self.CERTS_DIR = "certs"
        self.CA_CERT = os.path.join(self.CERTS_DIR, "ca.crt")
        self.CA_KEY = os.path.join(self.CERTS_DIR, "ca.key")
        self.SERVER_CERT = os.path.join(self.CERTS_DIR, "server.crt")
        self.SERVER_KEY = os.path.join(self.CERTS_DIR, "server.key")
        self.CLIENT_CERT = os.path.join(self.CERTS_DIR, "client.crt")
        self.CLIENT_KEY = os.path.join(self.CERTS_DIR, "client.key")

    def ensure_certs(self):
        """Garante que todos os certificados necessários existam."""
        if not os.path.exists(self.CERTS_DIR):
            os.makedirs(self.CERTS_DIR)

        # Gerar CA se não existir
        if not os.path.exists(self.CA_CERT) or not os.path.exists(self.CA_KEY):
            self._generate_ca()

        # Gerar certificado do servidor se não existir
        if not os.path.exists(self.SERVER_CERT) or not os.path.exists(self.SERVER_KEY):
            self._generate_server_cert()

        # Gerar certificado do cliente se não existir
        if not os.path.exists(self.CLIENT_CERT) or not os.path.exists(self.CLIENT_KEY):
            self._generate_client_cert()

    def _generate_ca(self):
        """Gera o certificado da Autoridade Certificadora (CA)."""
        print("Gerando certificado CA...")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        with open(self.CA_KEY, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"São Paulo"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"São Paulo"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MinhaEmpresa"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"MinhaEmpresa CA"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(key, hashes.SHA256())

        with open(self.CA_CERT, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print("Certificado CA gerado.")

    def _generate_server_cert(self):
        """Gera o certificado do servidor."""
        print("Gerando certificado do servidor...")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        with open(self.SERVER_KEY, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        with open(self.CA_KEY, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)

        with open(self.CA_CERT, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"São Paulo"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"São Paulo"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MinhaEmpresa"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).sign(ca_key, hashes.SHA256())

        with open(self.SERVER_CERT, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print("Certificado do servidor gerado.")

    def _generate_client_cert(self):
        """Gera o certificado do cliente."""
        print("Gerando certificado do cliente...")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        with open(self.CLIENT_KEY, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        with open(self.CA_KEY, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)

        with open(self.CA_CERT, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"São Paulo"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"São Paulo"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MinhaEmpresa"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"cliente"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        ).sign(ca_key, hashes.SHA256())

        with open(self.CLIENT_CERT, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print("Certificado do cliente gerado.")

    def get_ssl_context(self):
        """Retorna o contexto SSL configurado para o servidor."""
        self.ensure_certs()
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=self.SERVER_CERT, keyfile=self.SERVER_KEY)
        ssl_context.load_verify_locations(cafile=self.CA_CERT)
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        return ssl_context