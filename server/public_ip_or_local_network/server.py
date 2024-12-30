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
    def __init__(self, host="0.0.0.0", port=9024, use_ssl=False):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
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
        self.AUTH_TOKEN = os.getenv("AUTH_TOKEN")  # Armazenar o token como atributo da classe
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

    async def register(self, websocket):
        """
        Gerencia o registro de novos clientes.
        Versão atualizada para websockets 14.1
        """
        client_info = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
        
        try:
            # Na versão 14.1 do websockets, os headers estão em websocket.request.headers
            request_headers = getattr(websocket, 'request', None)
            if request_headers:
                auth_header = request_headers.headers.get('Authorization', '')
            else:
                # Fallback para a forma antiga de obter os headers
                auth_header = ''
            
            if not auth_header or not auth_header.startswith('Bearer '):
                print(f"[{self.get_timestamp()}] Token ausente ou formato inválido de {client_info}")
                await websocket.close(1002, reason='Token ausente ou formato inválido')
                return
                
            token = auth_header.split('Bearer ')[1].strip()
            
            # Log do token recebido (apenas para debug)
            print(f"[{self.get_timestamp()}] Token recebido de {client_info}")

            if token != self.AUTH_TOKEN:
                print(f"[{self.get_timestamp()}] Token inválido de {client_info}")
                await websocket.close(1002, reason='Token inválido')
                return

            print(f"[{self.get_timestamp()}] Nova conexão de {client_info} autenticada com sucesso.")
            
            self.clients[client_info] = {
                'websocket': websocket,
                'last_ping': time.time()
            }

            try:
                async for message in websocket:
                    await self.handle_message(message, client_info)
            except websockets.exceptions.ConnectionClosed as e:
                print(f"[{self.get_timestamp()}] Cliente {client_info} desconectado: {e}")
            except Exception as e:
                print(f"[{self.get_timestamp()}] Erro com cliente {client_info}: {e}")
            finally:
                if client_info in self.clients:
                    del self.clients[client_info]
                print(f"[{self.get_timestamp()}] Cliente {client_info} removido da lista de conexões")
                
        except Exception as e:
            print(f"[{self.get_timestamp()}] Erro na autenticação de {client_info}: {e}")
            await websocket.close(1002, reason='Erro na autenticação')
            return

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
        """Envia dados de áudio para todos os clientes conectados."""
        wav_data = self.create_wav_from_bytes(audio_bytes)
        if wav_data:
            message = {
                "type": "complete_audio",
                "timestamp": self.get_timestamp(),
                "audio_data": base64.b64encode(wav_data).decode('utf-8'),
                "format": "wav",
                "duration": len(audio_bytes) / (self.rate * self.channels * 2)  # Duração aproximada
            }

            disconnected_clients = []
            for client_info, client_data in list(self.clients.items()):
                try:
                    await client_data['websocket'].send(json.dumps(message))
                    print(f"[{self.get_timestamp()}] Áudio enviado para {client_info}")
                except Exception as e:
                    print(f"[{self.get_timestamp()}] Erro ao enviar para {client_info}: {e}")
                    disconnected_clients.append(client_info)

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
        """Gerencia entradas de teclado para desligar o servidor e alternar o mute."""
        def check_keys():
            last_toggle_time = 0
            toggle_cooldown = 0.5  # Segundos para prevenir alternâncias rápidas

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
                            self.force_send_event.set()  # Sinaliza para enviar áudio imediatamente
                        else:
                            self.reset_audio_state()  # Reseta o estado de áudio ao desmutar
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
            async with websockets.serve(
                self.register,
                self.host,
                self.port,
                ssl=self.ssl_context if self.use_ssl else None,
                ping_interval=None,
                max_size=20 * 1024 * 1024,
                process_request=None,
                compression=None
            ) as server:
                protocolo = 'wss' if self.use_ssl else 'ws'
                print(f"[{self.get_timestamp()}] Servidor iniciado em {protocolo}://{self.host}:{self.port}")
                print(f"[{self.get_timestamp()}] Pressione 'q' para desligar o servidor.")
                print(f"[{self.get_timestamp()}] Pressione 'k' para alternar o mute do microfone.")

                # Iniciar a tarefa de transmissão de áudio
                broadcast_task = asyncio.create_task(self.broadcast_audio())

                # Aguardar até que o servidor esteja em execução e a transmissão seja concluída
                await asyncio.gather(server.wait_closed(), broadcast_task)
        except Exception as e:
            print(f"[{self.get_timestamp()}] Erro em start_server: {e}")
        finally:
            self.cleanup()


if __name__ == "__main__":
    use_ssl_input = input("Deseja usar comunicação segura (SSL/TLS)? (y/n): ").strip().lower()
    use_ssl = use_ssl_input in ['y', 'yes']

    server = AudioServer(use_ssl=use_ssl)

    try:
        asyncio.run(server.start_server())
    except KeyboardInterrupt:
        print("\nDesligando servidor...")
    except Exception as e:
        print(f"Erro inesperado: {e}")
    finally:
        server.running = False
        server.cleanup()