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
    def __init__(self, server_url, model, language, device, use_ssl=False):
        self.server_url = server_url
        self.use_ssl = use_ssl
        self.ssl_context = None
        self.model = model  # Armazena o modelo Whisper
        self.language = language
        self.device = device
        self.files_processed = 0
        self.running = True
        self.connected = False
        self.reconnect_delay = 1
        self.max_reconnect_delay = 30
        self.last_activity = time.time()
        self.connection_timeout = 60
        self.audio_buffer = []  # Buffer para chunks de áudio
        self.websocket = None  # Referência ao WebSocket

        if self.use_ssl:
            self.setup_ssl()

    def setup_ssl(self):
        """
        Configura o contexto SSL para comunicação segura com autenticação mútua.
        """
        ensure_certs_client()
        self.ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
        self.ssl_context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
        self.ssl_context.check_hostname = False  # Defina como True se o hostname do servidor for válido e corresponder ao certificado
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
                f"Invalid audio format - Channels: {wf.getnchannels()}, " +
                f"Sample Rate: {wf.getframerate()} Hz",
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
                fp16=(self.device == "cuda")  # Use fp16 se estiver na GPU
            )

            transcription = result["text"].strip()
            if transcription:
                self.files_processed += 1
                self.update_status(
                    f"Transcription {self.files_processed}: {transcription}",
                    'success'
                )
                # Envia a transcrição de volta para o servidor
                await self.send_transcription(transcription)
                return transcription
        except Exception as e:
            self.update_status(f"Error during transcription: {str(e)}", 'error')
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
                self.update_status(f"Transcription sent to server: {transcription}", 'info')
            except Exception as e:
                self.update_status(f"Error sending transcription: {str(e)}", 'error')

    async def process_audio_data(self, audio_data_b64, message_info):
        """Processa os dados de áudio recebidos"""
        try:
            # Decodifica o áudio
            audio_data = base64.b64decode(audio_data_b64)
            message_type = message_info.get('type', 'chunk')

            # Se for um chunk de áudio contínuo
            if message_type == "chunk":
                # Log opcional para recepção
                self.update_status(
                    f"Receiving audio... ({len(audio_data)/1024:.1f}KB)",
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
                        self.update_status("Invalid audio data detected", 'error')
                        return

                    # Log do início da transcrição
                    file_size = len(audio_data) / 1024
                    self.update_status(
                        f"Starting transcription - Size: {file_size:.1f}KB, " +
                        f"Duration: {duration:.1f}s",
                        'info'
                    )

                    # Realiza a transcrição
                    await self.transcribe_audio(audio_float)

        except Exception as e:
            self.update_status(f"Error processing audio: {str(e)}", 'error')

    async def connect_to_server(self):
        """Gerencia a conexão com o servidor"""
        while self.running:
            try:
                self.update_status("Attempting to connect to the server...", 'info')
                async with websockets.connect(
                    self.server_url,
                    ssl=self.ssl_context if self.use_ssl else None,
                    ping_interval=20,       # Envia um ping a cada 20 segundos
                    ping_timeout=10,        # Tempo limite para resposta do ping
                    max_size=20 * 1024 * 1024,
                    close_timeout=5
                ) as websocket:
                    self.websocket = websocket  # Armazena a referência do WebSocket
                    self.connected = True
                    self.update_status("Connected to the server!", 'success')

                    while True:
                        try:
                            # Espera por uma mensagem com timeout
                            message = await asyncio.wait_for(
                                websocket.recv(),
                                timeout=self.connection_timeout
                            )

                            # Reseta o delay de reconexão após sucesso
                            self.reconnect_delay = 1
                            self.last_activity = time.time()

                            # Processa a mensagem
                            try:
                                data = json.loads(message)
                                self.update_status(f"Received message: {data}", 'info')
                                await self.process_audio_data(
                                    data.get('audio_data', ''),
                                    {
                                        'type': data.get('type', 'chunk'),
                                        'timestamp': data.get('timestamp'),
                                        'duration': data.get('duration', 0)
                                    }
                                )
                            except json.JSONDecodeError as e:
                                self.update_status(f"Error decoding message: {str(e)}", 'error')
                                continue

                        except asyncio.TimeoutError:
                            if time.time() - self.last_activity > self.connection_timeout:
                                self.update_status("Connection timeout. Reconnecting...", 'warning')
                                break
                        except websockets.exceptions.ConnectionClosed:
                            self.update_status("Connection closed by server. Reconnecting...", 'warning')
                            break
                        except Exception as e:
                            self.update_status(f"Unexpected error: {str(e)}", 'error')
                            continue

            except Exception as e:
                self.connected = False
                self.update_status(
                    f"Connection error: {str(e)}\nAttempting to reconnect in {self.reconnect_delay} seconds...",
                    'error'
                )
                await asyncio.sleep(self.reconnect_delay)
                self.reconnect_delay = min(self.reconnect_delay * 2, self.max_reconnect_delay)

    async def handle_incoming_messages(self):
        """Opcional: Lida com mensagens recebidas do servidor, se necessário"""
        # Se precisar lidar com mensagens específicas do servidor, implemente aqui
        pass

async def main():
    """Função principal"""
    use_ssl_input = input("Deseja usar comunicação segura (SSL/TLS)? (y/n): ").strip().lower()
    use_ssl = use_ssl_input in ['y', 'yes']

    # Coleta das configurações do usuário
    SERVER_IP = get_server_ip()
    SERVER_PORT = 9024  # Você também pode tornar isso configurável, se desejar

    USE_CUDA = get_use_cuda()

    LANGUAGE = get_language()

    # Determina o dispositivo com base em USE_CUDA e disponibilidade de CUDA
    if USE_CUDA and torch.cuda.is_available():
        device = "cuda"
    else:
        device = "cpu"
        if USE_CUDA:
            print("CUDA não está disponível. Usando CPU em vez disso.")

    print("Loading Whisper model...")
    try:
        model = whisper.load_model("medium", device=device)
    except Exception as e:
        print(f"Erro ao carregar o modelo Whisper: {e}")
        sys.exit(1)
    print(f"Model loaded on device: {device}")
    print(f"Language set to: {LANGUAGE if LANGUAGE != 'automatic' else 'Automatic'}")

    # Cria a URL do servidor com base na escolha de SSL
    protocolo = 'wss' if use_ssl else 'ws'
    server_url = f"{protocolo}://{SERVER_IP}:{SERVER_PORT}"

    client = AudioClient(server_url, model, LANGUAGE, device, use_ssl=use_ssl)
    try:
        await client.connect_to_server()
    except KeyboardInterrupt:
        print("\nClosing connection...")
    finally:
        client.running = False

def get_server_ip():
    """Prompts the user to enter the server's public IP."""
    while True:
        server_ip = input("Enter the server's public IP (example: 192.168.1.1): ").strip()
        if server_ip:
            return server_ip
        else:
            print("Invalid IP. Please try again.")

def get_use_cuda():
    """Asks the user whether to use CUDA (GPU) or CPU."""
    while True:
        choice = input("Do you want to use CUDA (GPU)? (y/n): ").strip().lower()
        if choice in ['y', 'yes']:
            return True
        elif choice in ['n', 'no']:
            return False
        else:
            print("Invalid input. Please respond with 'y' or 'n'.")

def get_language():
    """Asks the user whether to use automatic language detection or specify a language."""
    while True:
        choice = input("Do you want the language to be detected automatically? (y/n): ").strip().lower()
        if choice in ['y', 'yes']:
            return "automatic"
        elif choice in ['n', 'no']:
            lang = input("Specify the language code (example: 'pt' for Portuguese): ").strip().lower()
            if lang:
                return lang
            else:
                print("Invalid language code. Please try again.")
        else:
            print("Invalid input. Please respond with 'y' or 'n'.")

# Executa o cliente
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nClosing connection...")
        sys.exit()
