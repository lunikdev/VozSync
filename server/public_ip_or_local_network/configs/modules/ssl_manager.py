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
        """
        A ideia aqui é:
          - Manter certificados autoassinados em 'certs/' (como backup ou fallback).
          - Manter certificados reais (Let's Encrypt) em 'certs/letsencrypt/'.
        """
        self.CERTS_DIR = "certs"

        # Caminhos para CA e certificados autoassinados (fallback)
        self.CA_CERT = os.path.join(self.CERTS_DIR, "ca.crt")
        self.CA_KEY = os.path.join(self.CERTS_DIR, "ca.key")
        self.AUTO_SERVER_CERT = os.path.join(self.CERTS_DIR, "server.crt")
        self.AUTO_SERVER_KEY = os.path.join(self.CERTS_DIR, "server.key")
        self.CLIENT_CERT = os.path.join(self.CERTS_DIR, "client.crt")
        self.CLIENT_KEY = os.path.join(self.CERTS_DIR, "client.key")

        # Caminho para os certificados Let's Encrypt
        # Caso não existam, vamos usar os autoassinados.
        self.LETS_ENCRYPT_DIR = os.path.join(self.CERTS_DIR, "letsencrypt")
        os.makedirs(self.LETS_ENCRYPT_DIR, exist_ok=True)
        self.LE_SERVER_CERT = os.path.join(self.LETS_ENCRYPT_DIR, "server.crt")
        self.LE_SERVER_KEY = os.path.join(self.LETS_ENCRYPT_DIR, "server.key")

        # Inicialmente, vamos apontar o 'server.crt' e 'server.key' para os autoassinados
        self.SERVER_CERT = self.AUTO_SERVER_CERT
        self.SERVER_KEY = self.AUTO_SERVER_KEY

    def ensure_certs(self):
        """
        Garante que os certificados existam:
          1) Se houver server.crt e server.key em 'certs/letsencrypt/', usamos estes (Let's Encrypt).
          2) Caso contrário, criamos/garantimos a CA e o server.crt autoassinado em 'certs/'.
          3) Garantimos também o client.crt (se for usado para algo).
        """
        if not os.path.exists(self.CERTS_DIR):
            os.makedirs(self.CERTS_DIR)

        # 1) Verifica se há certificados do Let's Encrypt
        if os.path.exists(self.LE_SERVER_CERT) and os.path.exists(self.LE_SERVER_KEY):
            print("[SSLManager] Detectados certificados Let's Encrypt em 'certs/letsencrypt/'.")
            self.SERVER_CERT = self.LE_SERVER_CERT
            self.SERVER_KEY = self.LE_SERVER_KEY
        else:
            print("[SSLManager] Não foram encontrados certificados em 'certs/letsencrypt/'. Usando autoassinados.")
            # 2) Gera a CA e os certificados autoassinados, se necessário
            if not os.path.exists(self.CA_CERT) or not os.path.exists(self.CA_KEY):
                self._generate_ca()

            if not os.path.exists(self.AUTO_SERVER_CERT) or not os.path.exists(self.AUTO_SERVER_KEY):
                self._generate_server_cert()

        # 3) Garantir a existência do certificado de cliente (apenas se for necessário)
        #    Se você realmente usa cliente->servidor mutuo, gere-o; caso não use, pode omitir.
        if not os.path.exists(self.CLIENT_CERT) or not os.path.exists(self.CLIENT_KEY):
            self._generate_client_cert()

    def _generate_ca(self):
        """Gera o certificado da Autoridade Certificadora (CA) para assinar certificados autoassinados."""
        print("[SSLManager] Gerando certificado CA...")
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
            # Válido por 10 anos
            datetime.utcnow() + timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(key, hashes.SHA256())

        with open(self.CA_CERT, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print("[SSLManager] Certificado CA gerado.")

    def _generate_server_cert(self):
        """Gera um certificado de servidor autoassinado, usando a CA acima."""
        print("[SSLManager] Gerando certificado do servidor autoassinado...")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        with open(self.AUTO_SERVER_KEY, "wb") as f:
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
            # Podemos adicionar mais domínios se quiser, ex: DNSName(u"meusite.com")
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).sign(ca_key, hashes.SHA256())

        with open(self.AUTO_SERVER_CERT, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print("[SSLManager] Certificado do servidor autoassinado gerado.")

    def _generate_client_cert(self):
        """Gera um certificado de cliente autoassinado (caso seja necessário para uso)."""
        print("[SSLManager] Gerando certificado do cliente...")
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
        print("[SSLManager] Certificado do cliente gerado.")

    def get_ssl_context(self):
        """
        Retorna o contexto SSL configurado para o servidor.
        """
        self.ensure_certs()

        # Cria contexto para servidor
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        # Define o nível mínimo de segurança
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Carrega o certificado de servidor + chave
        ssl_context.load_cert_chain(certfile=self.SERVER_CERT, keyfile=self.SERVER_KEY)

        # Verifica se está usando certificados autoassinados ou Let's Encrypt
        if self.SERVER_CERT == self.AUTO_SERVER_CERT:  # Usando certificados autoassinados
            if os.path.exists(self.CA_CERT):
                ssl_context.load_verify_locations(cafile=self.CA_CERT)
                ssl_context.verify_mode = ssl.CERT_NONE  # Não requer certificados de cliente em desenvolvimento
                print("[SSLManager] Usando certificados autoassinados - Modo desenvolvimento.")
            else:
                raise RuntimeError("[SSLManager] CA não encontrada.")
        else:  # Usando Let's Encrypt
            ssl_context.verify_mode = ssl.CERT_NONE
            print("[SSLManager] Usando Let's Encrypt - Certificados de cliente não requeridos.")

        return ssl_context