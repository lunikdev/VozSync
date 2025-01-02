# client.py

import asyncio
import websockets
import ssl
import os
import json
import base64
import numpy as np
import whisper
import torch
from datetime import datetime
import time
import wave
import io
import sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from dotenv import load_dotenv, find_dotenv  # Para carregar variáveis de ambiente
# Imports necessários para IPv6
import socket

# Diretório e arquivos de certificados
CERTS_DIR = "certs"
CA_CERT = os.path.join(CERTS_DIR, "ca.crt")
CLIENT_CERT = os.path.join(CERTS_DIR, "client.crt")
CLIENT_KEY = os.path.join(CERTS_DIR, "client.key")


def ensure_certs_client():
    """
    Garante que os certificados necessários existam.
    Se não existirem, instrui o usuário a copiá-los do servidor.
    """
    if not os.path.exists(CERTS_DIR):
        os.makedirs(CERTS_DIR)

    # Verifica se o certificado CA existe
    if not os.path.exists(CA_CERT):
        print(f"Erro: Certificado CA não encontrado em '{CA_CERT}'.")
        print("Por favor, copie 'ca.crt' do servidor para o diretório 'certs/'.")
        sys.exit(1)

    # Verifica se o certificado do cliente e a chave existem
    if not os.path.exists(CLIENT_CERT) or not os.path.exists(CLIENT_KEY):
        print(f"Erro: Certificado do cliente ou chave privada não encontrados em '{CLIENT_CERT}' ou '{CLIENT_KEY}'.")
        print("Por favor, copie 'client.crt' e 'client.key' do servidor para o diretório 'certs/'.")
        sys.exit(1)


class AudioClient:
    def __init__(self, server_url, port, model, language, device, use_ssl=False, auth_token=None, use_ipv6=False):
        self.server_url = server_url
        self.port = port
        self.use_ssl = use_ssl
        self.use_ipv6 = use_ipv6
        self.ssl_context = None
        self.model = model
        self.language = language
        self.device = device
        self.files_processed = 0
        self.running = True
        self.connected = False
        self.reconnect_delay = 1
        self.max_reconnect_delay = 30
        self.last_activity = time.time()
        self.connection_timeout = 60
        self.audio_buffer = []
        self.websocket = None
        self.auth_token = auth_token

        if self.use_ssl:
            self.setup_ssl()

    def setup_ssl(self):
        """
        Configura o contexto SSL para comunicação segura com autenticação mútua.
        """
        ensure_certs_client()
        self.ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
        self.ssl_context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        print("Contexto SSL configurado para o cliente.")

    def update_status(self, message, status_type='info'):
        """Atualiza o status no console"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        status_messages = {
            'info': f"[{timestamp}] INFO: {message}",
            'success': f"[{timestamp}] SUCCESS: {message}",
            'warning': f"[{timestamp}] WARNING: {message}",
            'error': f"[{timestamp}] ERROR: {message}"
        }
        print(status_messages.get(status_type, f"[{timestamp}] INFO: {message}"))

    def validate_audio_format(self, wf):
        """Valida o formato do áudio"""
        if wf.getnchannels() != 1 or wf.getframerate() != 16000:
            self.update_status(
                f"Formato de áudio inválido - Canais: {wf.getnchannels()}, " +
                f"Taxa de Amostragem: {wf.getframerate()} Hz",
                'warning'
            )
            return False
        return True

    async def transcribe_audio(self, audio_float):
        """Realiza a transcrição do áudio"""
        try:
            result = self.model.transcribe(
                audio=audio_float,
                language=None if self.language == "automatic" else self.language,
                task="transcribe",
                fp16=(self.device.type == "cuda")
            )

            transcription = result["text"].strip()
            if transcription:
                self.files_processed += 1
                self.update_status(
                    f"Transcrição {self.files_processed}: {transcription}",
                    'success'
                )
                await self.send_transcription(transcription)
                return transcription
        except Exception as e:
            self.update_status(f"Erro durante a transcrição: {str(e)}", 'error')
            return None

    async def send_transcription(self, transcription):
        """Envia a transcrição de volta para o servidor via WebSocket"""
        if self.websocket and self.connected:
            message = {
                "type": "transcription",
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "text": transcription
            }
            try:
                await self.websocket.send(json.dumps(message))
                self.update_status(f"Transcrição enviada para o servidor: {transcription}", 'info')
            except Exception as e:
                self.update_status(f"Erro ao enviar transcrição: {str(e)}", 'error')

    async def process_audio_data(self, audio_data_b64, message_info):
        """Processa os dados de áudio recebidos"""
        try:
            # Decodifica o áudio
            audio_data = base64.b64decode(audio_data_b64)
            message_type = message_info.get('type', 'chunk')

            # Se for um chunk de áudio contínuo
            if message_type == "chunk":
                self.update_status(
                    f"Recebendo áudio... ({len(audio_data)/1024:.1f}KB)",
                    'info'
                )
                return

            # Se for áudio completo para transcrição
            elif message_type == "complete_audio":
                wav_io = io.BytesIO(audio_data)
                duration = message_info.get('duration', 0)

                with wave.open(wav_io, 'rb') as wf:
                    # Valida o formato
                    if not self.validate_audio_format(wf):
                        return

                    # Converte para array numpy
                    audio_data = np.frombuffer(wf.readframes(wf.getnframes()), dtype=np.int16)
                    audio_float = audio_data.astype(np.float32) / 32768.0

                    # Verifica dados inválidos
                    if not np.all(np.isfinite(audio_float)):
                        self.update_status("Dados de áudio inválidos detectados", 'error')
                        return

                    # Log do início da transcrição
                    file_size = len(audio_data) / 1024
                    self.update_status(
                        f"Iniciando transcrição - Tamanho: {file_size:.1f}KB, " +
                        f"Duração: {duration:.1f}s",
                        'info'
                    )

                    # Realiza a transcrição
                    await self.transcribe_audio(audio_float)

        except Exception as e:
            self.update_status(f"Erro ao processar áudio: {str(e)}", 'error')

    async def connect_to_server(self):
        """Gerencia a conexão com o servidor com suporte a IPv6"""
        while self.running:
            try:
                self.update_status("Tentando conectar ao servidor...", 'info')
                
                # Criar a URL com o formato apropriado para IPv6 ou IPv4
                protocolo = 'wss' if self.use_ssl else 'ws'
                if self.use_ipv6:
                    # Para IPv6, envolvemos o endereço em colchetes
                    if ':' in self.server_url:  # Verifica se é um endereço IPv6
                        server_url = f"{protocolo}://[{self.server_url}]:{self.port}"
                    else:
                        server_url = f"{protocolo}://{self.server_url}:{self.port}"
                else:
                    server_url = f"{protocolo}://{self.server_url}:{self.port}"

                # Configurar as opções de conexão específicas para IPv6 se necessário
                connection_kwargs = {
                    'uri': server_url,
                    'ssl': self.ssl_context if self.use_ssl else None,
                    'ping_interval': 20,
                    'ping_timeout': 10,
                    'max_size': 20 * 1024 * 1024,
                    'compression': None,
                    'additional_headers': {
                        'Authorization': f'Bearer {self.auth_token}'
                    }
                }

                if self.use_ipv6:
                    # Adicionar configurações específicas para IPv6
                    connection_kwargs['family'] = socket.AF_INET6

                async with websockets.connect(**connection_kwargs) as websocket:
                    self.websocket = websocket
                    self.connected = True
                    self.update_status(f"Conectado ao servidor via {'IPv6' if self.use_ipv6 else 'IPv4'}!", 'success')

                    while True:
                        try:
                            message = await asyncio.wait_for(
                                websocket.recv(),
                                timeout=self.connection_timeout
                            )

                            self.reconnect_delay = 1
                            self.last_activity = time.time()

                            try:
                                data = json.loads(message)
                                await self.process_audio_data(
                                    data.get('audio_data', ''),
                                    {
                                        'type': data.get('type', 'chunk'),
                                        'timestamp': data.get('timestamp'),
                                        'duration': data.get('duration', 0)
                                    }
                                )
                            except json.JSONDecodeError as e:
                                self.update_status(f"Erro ao decodificar mensagem: {str(e)}", 'error')
                                continue

                        except asyncio.TimeoutError:
                            if time.time() - self.last_activity > self.connection_timeout:
                                self.update_status("Timeout da conexão. Reconectando...", 'warning')
                                break
                        except websockets.exceptions.ConnectionClosed:
                            self.update_status("Conexão fechada pelo servidor. Reconectando...", 'warning')
                            break
                        except Exception as e:
                            self.update_status(f"Erro inesperado: {str(e)}", 'error')
                            continue

            except Exception as e:
                self.connected = False
                self.update_status(
                    f"Erro de conexão: {str(e)}\nTentando reconectar em {self.reconnect_delay} segundos...",
                    'error'
                )
                await asyncio.sleep(self.reconnect_delay)
                self.reconnect_delay = min(self.reconnect_delay * 2, self.max_reconnect_delay)

    async def handle_incoming_messages(self):
        """Opcional: Lida com mensagens recebidas do servidor, se necessário"""
        pass

def get_server_ip(use_ipv6):
    """Solicita ao usuário que insira o IP do servidor com suporte a IPv6."""
    while True:
        if use_ipv6:
            print("Digite o endereço IPv6 do servidor (exemplo: 2001:db8::1)")
            print("Ou deixe em branco para usar 'localhost' (::1)")
        else:
            print("Digite o endereço IPv4 do servidor (exemplo: 192.168.1.1)")
            print("Ou deixe em branco para usar 'localhost' (127.0.0.1)")
            
        server_ip = input("Endereço do servidor: ").strip()
        
        if not server_ip:
            return "::1" if use_ipv6 else "127.0.0.1"
        
        # Validação básica do formato do endereço
        if use_ipv6:
            if ':' in server_ip:  # Verificação simples para IPv6
                return server_ip
            print("Formato de IPv6 inválido. Tente novamente.")
        else:
            if '.' in server_ip:  # Verificação simples para IPv4
                return server_ip
            print("Formato de IPv4 inválido. Tente novamente.")

def get_use_cuda():
    """Pergunta ao usuário se deseja usar CUDA (GPU) ou CPU."""
    while True:
        choice = input("Deseja usar CUDA (GPU)? (y/n): ").strip().lower()
        if choice in ['y', 'yes']:
            return True
        elif choice in ['n', 'no']:
            return False
        else:
            print("Entrada inválida. Responda com 'y' ou 'n'.")


def get_language():
    """Pergunta ao usuário se deseja detecção automática de idioma ou especificar um idioma."""
    while True:
        choice = input("Deseja que o idioma seja detectado automaticamente? (y/n): ").strip().lower()
        if choice in ['y', 'yes']:
            return "automatic"
        elif choice in ['n', 'no']:
            lang = input("Especifique o código do idioma (exemplo: 'pt' para Português): ").strip().lower()
            if lang:
                return lang
            else:
                print("Código de idioma inválido. Por favor, tente novamente.")
        else:
            print("Entrada inválida. Responda com 'y' ou 'n'.")


def get_device(use_cuda):
    """Determina o dispositivo a ser usado com base na disponibilidade de CUDA."""
    if use_cuda and torch.cuda.is_available():
        device = torch.device("cuda")
        cuda_device_name = torch.cuda.get_device_name(0)
        print(f"Usando dispositivo CUDA: {cuda_device_name}")
    elif use_cuda and not torch.cuda.is_available():
        device = torch.device("cpu")
        print("CUDA não está disponível. Usando CPU em vez disso.")
    else:
        device = torch.device("cpu")
        print("Usando CPU.")
    return device


async def main():
    """Função principal com suporte a IPv6"""
    # Primeiro, perguntar sobre a versão do IP
    ip_version = input("Qual versão do IP deseja usar? (4/6) [4]: ").strip() or "4"
    use_ipv6 = ip_version == "6"

    use_ssl_input = input("Deseja usar comunicação segura (SSL/TLS)? (y/n): ").strip().lower()
    use_ssl = use_ssl_input in ['y', 'yes']

    # Coleta das configurações do usuário com suporte a IPv6
    SERVER_IP = get_server_ip(use_ipv6)
    SERVER_PORT = 9024

    USE_CUDA = get_use_cuda()
    LANGUAGE = get_language()

    # Carregar variáveis de ambiente
    load_dotenv(find_dotenv())
    AUTH_TOKEN = os.getenv("AUTH_TOKEN")
    if not AUTH_TOKEN:
        AUTH_TOKEN = input("Digite o token de autenticação: ").strip()

    # Log das configurações
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Configurações:")
    print(f"Versão IP: {'IPv6' if use_ipv6 else 'IPv4'}")
    print(f"Endereço do servidor: {SERVER_IP}")
    print(f"Token de autenticação configurado")

    # Configuração do dispositivo e modelo
    device = get_device(USE_CUDA)

    print("\n=== Informações do Sistema ===")
    print(f"PyTorch versão: {torch.__version__}")
    print(f"CUDA disponível: {torch.cuda.is_available()}")
    if torch.cuda.is_available():
        print(f"Versão do CUDA: {torch.version.cuda}")
        print(f"GPUs disponíveis: {torch.cuda.device_count()}")
        print(f"GPU: {torch.cuda.get_device_name(0)}")
    print("===========================\n")

    print("Carregando o modelo Whisper...")
    try:
        model = whisper.load_model("medium")
        model.to(device)
    except Exception as e:
        print(f"Erro ao carregar o modelo Whisper: {e}")
        sys.exit(1)
    print(f"Modelo carregado no dispositivo: {device}")
    print(f"Idioma: {LANGUAGE if LANGUAGE != 'automatic' else 'Automático'}\n")

    client = AudioClient(
        server_url=SERVER_IP,
        port=SERVER_PORT,
        model=model,
        language=LANGUAGE,
        device=device,
        use_ssl=use_ssl,
        auth_token=AUTH_TOKEN,
        use_ipv6=use_ipv6
    )

    try:
        await client.connect_to_server()
    except KeyboardInterrupt:
        print("\nFechando conexão...")
    finally:
        client.running = False

# Executa o cliente
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nFechando conexão...")
        sys.exit()