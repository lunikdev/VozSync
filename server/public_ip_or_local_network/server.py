# server.py

import asyncio
import websockets
import ssl
import os
import json
import base64
import collections
import threading
import time
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import pyaudio
import wave
import keyboard
import io
import numpy as np
import noisereduce as nr  # Biblioteca de redução de ruído
from dotenv import load_dotenv, find_dotenv
from urllib.parse import urlparse, parse_qs  # Para análise de URLs
# Imports necessários para IPv6
import socket
import json

CONFIGS_DIR = "configs"
SERVER_CONFIG_FILE = os.path.join(CONFIGS_DIR, "server_config.json")
SELECTED_CLIENT_FILE = os.path.join(CONFIGS_DIR, "selected_client.json")

# Adicione esta função para gerenciar as configurações
def load_or_create_configs():
    """Carrega ou cria as configurações do servidor."""
    # Criar diretório de configs se não existir
    if not os.path.exists(CONFIGS_DIR):
        os.makedirs(CONFIGS_DIR)
    
    # Configuração padrão do servidor
    default_config = {
        "redundancy_level": 1,
        "auto_select_first": True,
        "use_ipv6": False,
        "use_ssl": False
    }
    
    # Carregar ou criar arquivo de configuração do servidor
    if os.path.exists(SERVER_CONFIG_FILE):
        with open(SERVER_CONFIG_FILE, 'r') as f:
            config = json.load(f)
    else:
        config = default_config
        with open(SERVER_CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)  # Corrigido
    
    return config

# Adicione esta função para salvar o cliente selecionado
def save_selected_client(client_ip):
    """Salva o cliente selecionado em um arquivo JSON."""
    data = {"selected_client_ip": client_ip}
    with open(SELECTED_CLIENT_FILE, 'w') as f:
        json.dump(data, f, indent=4)

# Adicione esta função para carregar o cliente selecionado
def load_selected_client():
    """Carrega o cliente selecionado do arquivo JSON."""
    if os.path.exists(SELECTED_CLIENT_FILE):
        with open(SELECTED_CLIENT_FILE, 'r') as f:
            data = json.load(f)
            return data.get("selected_client_ip")
    return None

# Carregar variáveis de ambiente do arquivo .env
load_dotenv(find_dotenv())

# Obter o token de autenticação do arquivo .env
AUTH_TOKEN = os.getenv("AUTH_TOKEN")
if not AUTH_TOKEN:
    raise EnvironmentError("AUTH_TOKEN não está definido no arquivo .env")

# Adicione este print para verificar se o token foi carregado corretamente
print(f"[{datetime.now().strftime('%H:%M:%S')}] AUTH_TOKEN carregado: '{AUTH_TOKEN}'")

# Diretório e arquivos de certificados
CERTS_DIR = "certs"
CA_CERT = os.path.join(CERTS_DIR, "ca.crt")
CA_KEY = os.path.join(CERTS_DIR, "ca.key")
SERVER_CERT = os.path.join(CERTS_DIR, "server.crt")
SERVER_KEY = os.path.join(CERTS_DIR, "server.key")
CLIENT_CERT = os.path.join(CERTS_DIR, "client.crt")
CLIENT_KEY = os.path.join(CERTS_DIR, "client.key")


def ensure_certs():
    if not os.path.exists(CERTS_DIR):
        os.makedirs(CERTS_DIR)

    # Gerar CA se não existir
    if not os.path.exists(CA_CERT) or not os.path.exists(CA_KEY):
        print("Gerando certificado CA...")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(CA_KEY, "wb") as f:
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

        with open(CA_CERT, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print("Certificado CA gerado.")

    # Gerar certificado do servidor se não existir
    if not os.path.exists(SERVER_CERT) or not os.path.exists(SERVER_KEY):
        print("Gerando certificado do servidor...")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(SERVER_KEY, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        with open(CA_KEY, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)

        with open(CA_CERT, "rb") as f:
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

        with open(SERVER_CERT, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print("Certificado do servidor gerado.")

    # Gerar certificado do cliente se não existir
    if not os.path.exists(CLIENT_CERT) or not os.path.exists(CLIENT_KEY):
        print("Gerando certificado do cliente...")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(CLIENT_KEY, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        with open(CA_KEY, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)

        with open(CA_CERT, "rb") as f:
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

        with open(CLIENT_CERT, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print("Certificado do cliente gerado.")


class AudioServer:
    def __init__(self, host="0.0.0.0", port=9024, use_ssl=False, use_ipv6=False):
        # Carregar configurações
        config = load_or_create_configs()
        
        self.host = "::" if config["use_ipv6"] else host
        self.port = port
        self.use_ssl = config["use_ssl"]
        self.use_ipv6 = config["use_ipv6"]
        self.ssl_context = None
        self.clients = {}
        self.running = True
        self.muted = False
        self.audio_buffer = collections.deque(maxlen=int((16000 / 1024) * 0.5))
        self.long_term_noise_level = 0.0
        self.current_noise_level = 0.0
        self.ambient_noise_level = 0.0
        self.voice_activity_detected = False
        self.frames = []
        self.executor = ThreadPoolExecutor(max_workers=2)
        self.force_send_event = threading.Event()
        self.AUTH_TOKEN = os.getenv("AUTH_TOKEN")
        # Configurações de redundância
        self.redundancy_level = config["redundancy_level"]
        self.auto_select_first = config["auto_select_first"]
        self.selected_client = load_selected_client()
        self.menu_active = False
        self.next_client_id = 1
        if not self.AUTH_TOKEN:
            raise EnvironmentError("AUTH_TOKEN não está definido no arquivo .env")
        self.setup_audio()
        if self.use_ssl:
            self.setup_ssl()

    def setup_ssl(self):
        ensure_certs()
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
        self.ssl_context.load_verify_locations(cafile=CA_CERT)
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        print("Contexto SSL configurado para o servidor.")

    def setup_audio(self):
        try:
            self.audio = pyaudio.PyAudio()
            self.chunk_size = 1024
            self.format = pyaudio.paInt16
            self.channels = 1
            self.rate = 16000  # Taxa de amostragem (Hz)
            self.record_seconds = 1  # Tempo de gravação por chunk

            print(f"[{self.get_timestamp()}] Configuração de Áudio:")
            print(f"Taxa de Amostragem: {self.rate} Hz")
            print(f"Canais: {self.channels}")
            print(f"Formato: PCM 16-bit")
        except Exception as e:
            print(f"[{self.get_timestamp()}] Erro ao configurar áudio: {e}")

    def get_timestamp(self):
        return datetime.now().strftime("%H:%M:%S")

    async def handle_client_disconnect(self, client_info):
        """Gerencia a desconexão de um cliente."""
        try:
            if client_info in self.clients:
                was_selected = (client_info == self.selected_client)
                client_id = self.clients[client_info]['client_id']
                del self.clients[client_info]
                print(f"[{self.get_timestamp()}] Cliente {client_info} removido da lista de conexões")
                
                if was_selected and self.clients:
                    saved_client = load_selected_client()
                    if saved_client and saved_client in self.clients:
                        # Se o cliente salvo está disponível, seleciona ele
                        self.selected_client = saved_client
                        print(f"[{self.get_timestamp()}] Cliente prioritário #{self.clients[saved_client]['client_id']} selecionado automaticamente")
                    else:
                        # Caso contrário, seleciona o próximo disponível
                        next_client_info = next(iter(self.clients))
                        self.selected_client = next_client_info
                        print(f"[{self.get_timestamp()}] Cliente #{self.clients[next_client_info]['client_id']} selecionado automaticamente")
                elif was_selected:
                    print(f"[{self.get_timestamp()}] Cliente selecionado desconectou e não há outros clientes disponíveis.")
                    self.selected_client = None
        except Exception as e:
            print(f"[{self.get_timestamp()}] Erro ao desconectar cliente {client_info}: {e}")

    @staticmethod
    def extract_ip(websocket):
        """Extrai apenas o IP do endereço do websocket."""
        return websocket.remote_address[0]

    async def register(self, websocket):
        client_ip = self.extract_ip(websocket)
        
        try:
            request_headers = getattr(websocket, 'request', None)
            if request_headers:
                auth_header = request_headers.headers.get('Authorization', '')
            else:
                auth_header = ''
            
            if not auth_header or not auth_header.startswith('Bearer '):
                print(f"[{self.get_timestamp()}] Token ausente ou formato inválido de {client_ip}")
                await websocket.close(1002, reason='Token ausente ou formato inválido')
                return
                
            token = auth_header.split('Bearer ')[1].strip()
            
            print(f"[{self.get_timestamp()}] Token recebido de {client_ip}")

            if token != self.AUTH_TOKEN:
                print(f"[{self.get_timestamp()}] Token inválido de {client_ip}")
                await websocket.close(1002, reason='Token inválido')
                return

            print(f"[{self.get_timestamp()}] Nova conexão de {client_ip} autenticada com sucesso.")
            
            # Se o IP já está conectado, atualizar o websocket
            if client_ip in self.clients:
                old_client_id = self.clients[client_ip]['client_id']
                self.clients[client_ip] = {
                    'websocket': websocket,
                    'last_ping': time.time(),
                    'client_id': old_client_id  # Mantém o mesmo ID
                }
                print(f"[{self.get_timestamp()}] Reconexão detectada para {client_ip}")

                # Se este é o cliente prioritário e não está selecionado, selecioná-lo
                saved_client = load_selected_client()
                if saved_client == client_ip and self.selected_client != client_ip:
                    self.selected_client = client_ip
                    print(f"[{self.get_timestamp()}] Cliente prioritário {client_ip} reconectado e selecionado automaticamente")
            else:
                # Novo cliente
                new_client_id = self.next_client_id
                self.next_client_id += 1
                
                # Se estiver no nível 1 com auto-seleção ativada
                if self.redundancy_level == 1 and self.auto_select_first:
                    saved_client = load_selected_client()
                    
                    # Se este é o cliente prioritário ou não há cliente selecionado
                    if saved_client == client_ip:
                        self.selected_client = client_ip
                        print(f"[{self.get_timestamp()}] Cliente prioritário {client_ip} conectado e selecionado automaticamente")
                    elif not self.selected_client:
                        self.selected_client = client_ip
                        print(f"[{self.get_timestamp()}] Cliente {client_ip} selecionado automaticamente")
                
                self.clients[client_ip] = {
                    'websocket': websocket,
                    'last_ping': time.time(),
                    'client_id': new_client_id
                }

            # Se este é o cliente prioritário, sempre salvar a seleção
            saved_client = load_selected_client()
            if saved_client == client_ip:
                save_selected_client(client_ip)

            welcome_message = {
                "type": "welcome",
                "client_id": self.clients[client_ip]['client_id'],
                "message": f"Conectado como Cliente #{self.clients[client_ip]['client_id']}"
            }
            await websocket.send(json.dumps(welcome_message))

            try:
                async for message in websocket:
                    await self.handle_message(message, client_ip)
            except websockets.exceptions.ConnectionClosed as e:
                print(f"[{self.get_timestamp()}] Cliente {client_ip} desconectado: {e}")
            except Exception as e:
                print(f"[{self.get_timestamp()}] Erro com cliente {client_ip}: {e}")
            finally:
                # Só desconecta se o websocket atual for o mesmo que está registrado
                if client_ip in self.clients and self.clients[client_ip]['websocket'] == websocket:
                    await self.handle_client_disconnect(client_ip)
                
        except Exception as e:
            print(f"[{self.get_timestamp()}] Erro na autenticação de {client_ip}: {e}")
            await websocket.close(1002, reason='Erro na autenticação')
            return

    def set_redundancy_level(self, level):
        """Define o nível de redundância do servidor."""
        if level in [1, 2]:
            self.redundancy_level = level
            # Atualizar configuração
            with open(SERVER_CONFIG_FILE, 'r') as f:
                config = json.load(f)
            config["redundancy_level"] = level
            with open(SERVER_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)  # Corrigido
            
            print(f"[{self.get_timestamp()}] Nível de redundância alterado para {level}")
            if level == 1:
                self.selected_client = None
                if os.path.exists(SELECTED_CLIENT_FILE):
                    os.remove(SELECTED_CLIENT_FILE)
            return True
        return False

    def select_client(self, client_id):
        """Seleciona um cliente específico para processamento (apenas para nível 1)."""
        if self.redundancy_level != 1:
            print(f"[{self.get_timestamp()}] Seleção de cliente só está disponível no nível 1 de redundância")
            return False

        for client_ip, client_data in self.clients.items():
            if client_data['client_id'] == client_id:
                self.selected_client = client_ip
                # Salvar o cliente selecionado
                save_selected_client(client_ip)
                print(f"[{self.get_timestamp()}] Cliente #{client_id} (IP: {client_ip}) selecionado para processamento")
                return True
        
        print(f"[{self.get_timestamp()}] Cliente #{client_id} não encontrado")
        return False
    
    def show_menu(self):
        """Exibe o menu de controle de redundância."""
        print("\n=== Menu de Controle de Redundância ===")
        print(f"Nível atual: {self.redundancy_level}")
        print(f"Auto-seleção: {'Ativada' if self.auto_select_first else 'Desativada'}")
        print("\nOpções:")
        print("1. Alterar para Nível 1 (Cliente Único)")
        print("2. Alterar para Nível 2 (Redundância Total)")
        print("3. Selecionar Cliente Específico")
        print("4. Listar Clientes Conectados")
        print("5. Alternar Auto-seleção")
        print("0. Sair do Menu")
        print("\nEscolha uma opção: ")

    def handle_menu(self):
        """Processa as escolhas do menu."""
        while self.menu_active:
            self.show_menu()
            try:
                choice = input().strip()
                
                if choice == "0":
                    self.menu_active = False
                    print("Saindo do menu...")
                
                elif choice == "1":
                    self.set_redundancy_level(1)
                    if self.auto_select_first:
                        self.select_first_available_client()
                
                elif choice == "2":
                    self.set_redundancy_level(2)
                
                elif choice == "3":
                    if self.redundancy_level == 1:
                        self.list_clients()
                        try:
                            client_id = int(input("\nDigite o ID do cliente para selecionar: "))
                            self.select_client(client_id)
                        except ValueError:
                            print("ID inválido")
                    else:
                        print("Seleção de cliente só está disponível no nível 1")
                
                elif choice == "4":
                    self.list_clients()
                    input("\nPressione Enter para continuar...")
                
                elif choice == "5":
                    self.auto_select_first = not self.auto_select_first
                    status = "ativada" if self.auto_select_first else "desativada"
                    print(f"Auto-seleção {status}")
                    if self.auto_select_first and self.redundancy_level == 1:
                        self.select_first_available_client()
                
                else:
                    print("Opção inválida!")
                
            except Exception as e:
                print(f"Erro ao processar opção: {e}")

    def select_first_available_client(self):
        """Seleciona automaticamente o primeiro cliente disponível, priorizando o cliente salvo."""
        if not self.clients:
            print("Nenhum cliente disponível para seleção")
            return False

        saved_client = load_selected_client()
        
        # Se existe um cliente salvo e ele está conectado, seleciona ele
        if saved_client and saved_client in self.clients:
            self.selected_client = saved_client
            print(f"[{self.get_timestamp()}] Cliente prioritário #{self.clients[saved_client]['client_id']} selecionado automaticamente")
            return True
        
        # Caso contrário, seleciona o primeiro disponível
        first_client = list(self.clients.values())[0]
        self.selected_client = list(self.clients.keys())[0]
        print(f"[{self.get_timestamp()}] Cliente #{first_client['client_id']} selecionado automaticamente")
        return True

    def list_clients(self):
        """Lista todos os clientes conectados com seus IDs."""
        print(f"\n[{self.get_timestamp()}] Clientes conectados:")
        for client_ip, client_data in self.clients.items():
            selected = " (Selecionado)" if client_ip == self.selected_client else ""
            print(f"Cliente #{client_data['client_id']} - IP: {client_ip}{selected}")

    def get_levels(self, data):
        """Calcula o nível de volume do áudio."""
        pegel = np.abs(np.frombuffer(data, dtype=np.int16)).mean()
        self.long_term_noise_level = self.long_term_noise_level * 0.995 + pegel * (1.0 - 0.995)
        self.current_noise_level = self.current_noise_level * 0.920 + pegel * (1.0 - 0.920)
        return pegel

    async def handle_message(self, message, client_info):
        """Processa mensagens recebidas dos clientes."""
        try:
            data = json.loads(message)
            message_type = data.get("type", "unknown")
            if message_type == "transcription":
                transcription = data.get("text", "")
                timestamp = data.get("timestamp", self.get_timestamp())
                print(f"[{timestamp}] Transcrição recebida de {client_info}: {transcription}")
            else:
                print(f"[{self.get_timestamp()}] Tipo de mensagem desconhecido de {client_info}: {message_type}")
        except json.JSONDecodeError as e:
            print(f"[{self.get_timestamp()}] Erro ao decodificar mensagem de {client_info}: {e}")
        except Exception as e:
            print(f"[{self.get_timestamp()}] Erro ao processar mensagem de {client_info}: {e}")

    async def broadcast_audio(self):
        """Transmite áudio para os clientes com base na detecção de atividade vocal."""
        try:
            stream = self.audio.open(
                format=self.format,
                channels=self.channels,
                rate=self.rate,
                input=True,
                frames_per_buffer=self.chunk_size
            )
            print(f"[{self.get_timestamp()}] Iniciando captura de áudio...")

            loop = asyncio.get_event_loop()

            while self.running:
                if not self.muted:
                    try:
                        # Ler dados de áudio de forma não bloqueante
                        data = await loop.run_in_executor(
                            self.executor,
                            lambda: stream.read(self.chunk_size, exception_on_overflow=False)
                        )
                        if not data:
                            continue

                        pegel = self.get_levels(data)
                        self.audio_buffer.append(data)

                        # Definir limiar para detecção de atividade vocal
                        voice_threshold = self.long_term_noise_level + 300  # Ajuste conforme necessário

                        if self.voice_activity_detected:
                            self.frames.append(data)
                            if self.current_noise_level < self.ambient_noise_level + 100:
                                # Fim da atividade vocal
                                audio_bytes = b''.join(self.frames)
                                if len(audio_bytes) > 0:
                                    print(f"[{self.get_timestamp()}] Segmento de fala finalizado, enviando para os clientes.")
                                    # Aplicar redução de ruído e normalização antes de enviar
                                    processed_audio = self.process_audio(audio_bytes)
                                    await self.send_audio_to_clients(processed_audio)
                                self.frames = []
                                self.voice_activity_detected = False
                        else:
                            if self.current_noise_level > voice_threshold:
                                print(f"[{self.get_timestamp()}] Voz detectada!")
                                self.voice_activity_detected = True
                                self.ambient_noise_level = self.long_term_noise_level
                                self.frames = list(self.audio_buffer)

                    except Exception as e:
                        print(f"[{self.get_timestamp()}] Erro ao capturar áudio: {e}")
                        break
                else:
                    # Quando está mutado, não captura novos dados
                    await asyncio.sleep(0.1)

                # Verificar se o evento de força de envio foi sinalizado
                if self.force_send_event.is_set():
                    if self.frames:
                        audio_bytes = b''.join(self.frames)
                        if len(audio_bytes) > 0:
                            print(f"[{self.get_timestamp()}] Forçando envio do áudio devido ao mute.")
                            # Aplicar redução de ruído e normalização antes de enviar
                            processed_audio = self.process_audio(audio_bytes)
                            await self.send_audio_to_clients(processed_audio)
                        self.frames = []
                        self.voice_activity_detected = False
                    self.force_send_event.clear()  # Resetar o evento

        except Exception as e:
            print(f"[{self.get_timestamp()}] Erro em broadcast_audio: {e}")
        finally:
            try:
                stream.stop_stream()
                stream.close()
            except Exception as e:
                print(f"[{self.get_timestamp()}] Erro ao fechar stream: {e}")
            print(f"[{self.get_timestamp()}] Captura de áudio parada.")
            await self.send_complete_audio()

    def reset_audio_state(self):
        """Reseta os buffers e estados de áudio para evitar envio de áudio residual."""
        self.frames = []
        self.audio_buffer.clear()
        self.voice_activity_detected = False
        self.ambient_noise_level = 0.0
        self.long_term_noise_level = 0.0
        self.current_noise_level = 0.0
        print(f"[{self.get_timestamp()}] Estado de áudio resetado.")

    def process_audio(self, audio_bytes):
        """Aplica redução de ruído e normalização no áudio."""
        try:
            # Converter bytes para array numpy
            audio_np = np.frombuffer(audio_bytes, dtype=np.int16).astype(np.float32)

            # Aplicar redução de ruído
            reduced_noise = nr.reduce_noise(y=audio_np, sr=self.rate)

            # Normalizar áudio para prevenir clipping
            if np.max(np.abs(reduced_noise)) == 0:
                normalized_audio = reduced_noise
            else:
                normalized_audio = reduced_noise / np.max(np.abs(reduced_noise)) * 32767

            # Converter de volta para bytes
            normalized_audio = np.int16(normalized_audio)
            processed_bytes = normalized_audio.tobytes()

            return processed_bytes
        except Exception as e:
            print(f"[{self.get_timestamp()}] Erro ao processar áudio: {e}")
            return audio_bytes  # Retorna o original se falhar

    async def send_audio_to_clients(self, audio_bytes):
        """Envia dados de áudio para os clientes com base no nível de redundância."""
        wav_data = self.create_wav_from_bytes(audio_bytes)
        if not wav_data:
            return

        message = {
            "type": "complete_audio",
            "timestamp": self.get_timestamp(),
            "audio_data": base64.b64encode(wav_data).decode('utf-8'),
            "format": "wav",
            "duration": len(audio_bytes) / (self.rate * self.channels * 2)
        }

        disconnected_clients = []

        if self.redundancy_level == 2:
            # Redundância total - enviar para todos os clientes
            for client_info, client_data in self.clients.items():
                try:
                    await client_data['websocket'].send(json.dumps(message))
                    print(f"[{self.get_timestamp()}] Áudio enviado para Cliente #{client_data['client_id']}")
                except Exception as e:
                    print(f"[{self.get_timestamp()}] Erro ao enviar para Cliente #{client_data['client_id']}: {e}")
                    disconnected_clients.append(client_info)

        elif self.redundancy_level == 1:
            # Redundância seletiva - enviar apenas para o cliente selecionado
            if self.selected_client and self.selected_client in self.clients:
                try:
                    await self.clients[self.selected_client]['websocket'].send(json.dumps(message))
                    print(f"[{self.get_timestamp()}] Áudio enviado para Cliente #{self.clients[self.selected_client]['client_id']}")
                except Exception as e:
                    print(f"[{self.get_timestamp()}] Erro ao enviar para Cliente #{self.clients[self.selected_client]['client_id']}: {e}")
                    disconnected_clients.append(self.selected_client)
            else:
                print(f"[{self.get_timestamp()}] Nenhum cliente selecionado para processamento")

        # Remover clientes desconectados
        for client_info in disconnected_clients:
            del self.clients[client_info]

    def create_wav_from_bytes(self, audio_bytes):
        """Cria um arquivo WAV a partir de bytes de áudio."""
        try:
            wav_buffer = io.BytesIO()
            with wave.open(wav_buffer, 'wb') as wf:
                wf.setnchannels(self.channels)
                wf.setsampwidth(self.audio.get_sample_size(self.format))
                wf.setframerate(self.rate)
                wf.writeframes(audio_bytes)
            return wav_buffer.getvalue()
        except Exception as e:
            print(f"[{self.get_timestamp()}] Erro ao criar WAV: {e}")
            return None

    async def send_complete_audio(self):
        """Envia qualquer áudio restante no buffer durante o desligamento."""
        if self.frames:
            audio_bytes = b''.join(self.frames)
            if len(audio_bytes) > 0:
                print(f"[{self.get_timestamp()}] Enviando segmento final de áudio.")
                # Aplicar redução de ruído e normalização antes de enviar
                processed_audio = self.process_audio(audio_bytes)
                await self.send_audio_to_clients(processed_audio)

    def handle_keys(self):
        """Gerencia entradas de teclado para controle do servidor."""
        def check_keys():
            last_toggle_time = 0
            toggle_cooldown = 0.5

            while self.running:
                if keyboard.is_pressed('q'):
                    print(f"[{self.get_timestamp()}] Desligando servidor...")
                    self.running = False
                    break
                elif keyboard.is_pressed('k'):
                    current_time = time.time()
                    if current_time - last_toggle_time > toggle_cooldown:
                        self.muted = not self.muted
                        status = "Mutado" if self.muted else "Ativo"
                        print(f"[{self.get_timestamp()}] Estado de mute alterado para: {status}")
                        if self.muted:
                            self.force_send_event.set()
                        else:
                            self.reset_audio_state()
                        last_toggle_time = current_time
                elif keyboard.is_pressed('m'):
                    # Ativar menu de controle
                    current_time = time.time()
                    if current_time - last_toggle_time > toggle_cooldown:
                        if not self.menu_active:
                            print("\nAbrindo menu de controle...")
                            self.menu_active = True
                            # Criar uma nova thread para o menu para não bloquear o servidor
                            menu_thread = threading.Thread(target=self.handle_menu)
                            menu_thread.daemon = True
                            menu_thread.start()
                        last_toggle_time = current_time
                time.sleep(0.1)

        keyboard_thread = threading.Thread(target=check_keys)
        keyboard_thread.daemon = True
        keyboard_thread.start()

    def cleanup(self):
        if hasattr(self, 'audio') and self.audio:
            self.audio.terminate()
        print(f"[{self.get_timestamp()}] Desligamento do servidor completo.")

    async def start_server(self):
        self.handle_keys()

        try:
            if self.use_ipv6:
                # Configurações específicas para IPv6
                socket_kwargs = {
                    'family': socket.AF_INET6,
                    'host': self.host,
                    'port': self.port,
                    'ssl': self.ssl_context if self.use_ssl else None,
                    'ping_interval': None,
                    'max_size': 20 * 1024 * 1024,
                    'process_request': None,
                    'compression': None
                }
            else:
                # Configurações para IPv4
                socket_kwargs = {
                    'host': self.host,
                    'port': self.port,
                    'ssl': self.ssl_context if self.use_ssl else None,
                    'ping_interval': None,
                    'max_size': 20 * 1024 * 1024,
                    'process_request': None,
                    'compression': None
                }

            async with websockets.serve(self.register, **socket_kwargs) as server:
                protocolo = 'wss' if self.use_ssl else 'ws'
                ip_version = 'IPv6' if self.use_ipv6 else 'IPv4'
                print(f"[{self.get_timestamp()}] Servidor {ip_version} iniciado em {protocolo}://{self.host}:{self.port}")
                print(f"[{self.get_timestamp()}] Pressione 'q' para desligar o servidor.")
                print(f"[{self.get_timestamp()}] Pressione 'k' para alternar o mute do microfone.")

                broadcast_task = asyncio.create_task(self.broadcast_audio())
                await asyncio.gather(server.wait_closed(), broadcast_task)

        except Exception as e:
            print(f"[{self.get_timestamp()}] Erro em start_server: {e}")
        finally:
            self.cleanup()

if __name__ == "__main__":
    # Carregar configurações existentes
    config = load_or_create_configs()
    
    # Criar o servidor com as configurações carregadas
    server = AudioServer(use_ssl=config["use_ssl"], use_ipv6=config["use_ipv6"])
    
    try:
        asyncio.run(server.start_server())
    except KeyboardInterrupt:
        print("\nDesligando servidor...")
    except Exception as e:
        print(f"Erro inesperado: {e}")
    finally:
        server.running = False
        server.cleanup()