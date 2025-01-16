# configs/modules/letsencrypt_manager.py

import os
import sys
import platform
import shutil
import subprocess
from pathlib import Path

class LetsEncryptManager:
    def __init__(self):
        self.CERTS_DIR = "certs"
        self.LETS_ENCRYPT_DIR = os.path.join(self.CERTS_DIR, "letsencrypt")
        os.makedirs(self.LETS_ENCRYPT_DIR, exist_ok=True)

    def setup_letsencrypt(self):
        domain = input("Digite seu subdomínio/domínio para Let's Encrypt (ex: sub.dominio.com): ").strip()
        if not domain:
            print("Nenhum domínio informado. Abortando criação de certificados Let's Encrypt.")
            return False

        if self._install_certbot():
            if self._request_certificate(domain):
                if self._copy_certificates_windows(domain) if platform.system().lower() == "windows" else self._copy_certificates_linux(domain):
                    return True
        
        print("Não foi possível gerar certificados Let's Encrypt.")
        return False

    def _install_certbot(self):
        system_name = platform.system().lower()
        if "windows" in system_name:
            print("\n[LEManager] Instalando Certbot no Windows via pip...")
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], check=True)
                subprocess.run([sys.executable, "-m", "pip", "install", "certbot"], check=True)
                return True
            except subprocess.CalledProcessError as e:
                print(f"[LEManager] Erro ao instalar Certbot: {e}")
                return False
        else:
            print("\n[LEManager] Verificando instalação do Certbot em Linux...")
            try:
                if shutil.which("apt-get"):
                    subprocess.run(["sudo", "apt-get", "update"], check=True)
                    subprocess.run(["sudo", "apt-get", "install", "-y", "certbot"], check=True)
                elif shutil.which("dnf"):
                    subprocess.run(["sudo", "dnf", "install", "-y", "certbot"], check=True)
                elif shutil.which("yum"):
                    subprocess.run(["sudo", "yum", "install", "-y", "certbot"], check=True)
                return True
            except Exception as e:
                print(f"[LEManager] Erro ao instalar Certbot: {e}")
                return False

    def _request_certificate(self, domain):
        system_name = platform.system().lower()
        print(f"[LEManager] Gerando certificado para domínio {domain} em modo standalone...")

        if "windows" in system_name:
            certbot_base = os.path.expanduser(os.path.join("~", "certbot-win", "config"))
            os.makedirs(certbot_base, exist_ok=True)

            cmd = [
                "certbot",
                "certonly",
                "--standalone",
                "-d", domain,
                "--agree-tos",
                "--non-interactive",
                "-m", "seu-email@exemplo.com",
                "--cert-name", domain,
                "--config-dir", certbot_base,
                "--key-type", "rsa",
                "--rsa-key-size", "2048",
                "--no-eff-email"
            ]
        else:
            cmd = [
                "sudo",
                "certbot",
                "certonly",
                "--standalone",
                "-d", domain,
                "--agree-tos",
                "--non-interactive",
                "-m", "seu-email@exemplo.com"
            ]

        try:
            # Executa o Certbot e captura stdout + stderr
            result = subprocess.run(cmd, capture_output=True, text=True)

            # Se o retorno não for zero, houve algum erro
            if result.returncode != 0:
                # Verifica se tem algo relacionado a CertStorageError OU link simbólico
                if ("CertStorageError" in result.stderr or
                    "target" in result.stderr and "symlink" in result.stderr):
                    print("[LEManager] Aviso: ocorreu erro de link simbólico no Certbot, mas vamos ignorar.")
                    print("[LEManager] Copiaremos os arquivos diretamente da pasta 'archive'.")
                    # Ignoramos o erro e retornamos True para seguir o fluxo
                    return True
                else:
                    print("[LEManager] Falha ao executar certbot.")
                    print("[LEManager] Saída de erro:\n", result.stderr)
                    return False

            # Se result.returncode == 0, então deu tudo certo
            print("[LEManager] Certificado gerado com sucesso!")
            return True

        except Exception as e:
            print("[LEManager] Falha ao executar certbot:", e)
            return False


    def _copy_certificates_windows(self, domain):
        """Copia certificados diretamente do diretório archive no Windows"""
        try:
            # No Windows, vamos direto no diretório archive onde estão os arquivos
            archive_dir = os.path.expanduser(os.path.join("~", "certbot-win", "config", "archive", domain))
            
            print(f"[LEManager] Procurando certificados em: {archive_dir}")

            # Os arquivos no archive têm número no final (ex: cert1.pem)
            required_files = {
                "privkey1.pem": "server.key",
                "fullchain1.pem": "server.crt"
            }

            # Verificar existência dos arquivos
            if not os.path.exists(archive_dir):
                print(f"[LEManager] Diretório não encontrado: {archive_dir}")
                return False

            for src_file in required_files:
                src_path = os.path.join(archive_dir, src_file)
                if not os.path.exists(src_path):
                    print(f"[LEManager] Arquivo não encontrado: {src_path}")
                    return False

            # Copiar os arquivos
            for src_file, dst_file in required_files.items():
                src_path = os.path.join(archive_dir, src_file)
                dst_path = os.path.join(self.LETS_ENCRYPT_DIR, dst_file)
                shutil.copy2(src_path, dst_path)
                print(f"[LEManager] Copiado: {src_path} -> {dst_path}")

            print("[LEManager] Certificados Let's Encrypt copiados com sucesso!")
            return True

        except Exception as e:
            print(f"[LEManager] Erro ao copiar certificados: {e}")
            print(f"[LEManager] Detalhes do erro: {str(e)}")
            return False

    def _copy_certificates_linux(self, domain):
        try:
            src_dir = f"/etc/letsencrypt/live/{domain}"
            required_files = {
                "privkey.pem": "server.key",
                "fullchain.pem": "server.crt"
            }

            # Verificar existência dos arquivos
            for src_file in required_files:
                src_path = os.path.join(src_dir, src_file)
                if not os.path.exists(src_path):
                    print(f"[LEManager] Arquivo não encontrado: {src_path}")
                    return False

            # Copiar os arquivos
            for src_file, dst_file in required_files.items():
                src_path = os.path.join(src_dir, src_file)
                dst_path = os.path.join(self.LETS_ENCRYPT_DIR, dst_file)
                shutil.copy2(src_path, dst_path)
                os.chmod(dst_path, 0o600)

            print("[LEManager] Certificados Let's Encrypt copiados com sucesso!")
            return True

        except Exception as e:
            print(f"[LEManager] Erro ao copiar certificados: {e}")
            return False

    def check_certificates(self):
        """Verifica se os certificados Let's Encrypt existem localmente"""
        cert_path = os.path.join(self.LETS_ENCRYPT_DIR, "server.crt")
        key_path = os.path.join(self.LETS_ENCRYPT_DIR, "server.key")
        return os.path.exists(cert_path) and os.path.exists(key_path)