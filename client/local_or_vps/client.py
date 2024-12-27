import asyncio
import websockets
import json
import base64
import numpy as np
import whisper
import torch  # Importing the torch module
from datetime import datetime
import time
import wave
import io
import sys

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
        print("CUDA is not available. Using CPU instead.")

print("Loading Whisper model...")
model = whisper.load_model("medium", device=device)
print(f"Model loaded on device: {device}")
print(f"Language set to: {LANGUAGE if LANGUAGE != 'automatic' else 'Automatic'}")

class AudioClient:
    def __init__(self, server_url):
        self.server_url = server_url
        self.files_processed = 0
        self.running = True
        self.connected = False
        self.reconnect_delay = 1
        self.max_reconnect_delay = 30
        self.last_activity = time.time()
        self.connection_timeout = 60
        self.audio_buffer = []  # Buffer para chunks de áudio
        self.websocket = None  # Referência ao WebSocket

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
            result = model.transcribe(
                audio=audio_float,
                language=None if LANGUAGE == "automatic" else LANGUAGE,
                task="transcribe",
                fp16=(device == "cuda")  # Use fp16 se estiver na GPU
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
                async with websockets.connect(
                    self.server_url,
                    ping_interval=None,
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
                                await self.process_audio_data(
                                    data['audio_data'],
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
                            self.update_status("Connection lost. Reconnecting...", 'warning')
                            break
                        except Exception as e:
                            self.update_status(f"Error: {str(e)}", 'error')
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
    client = AudioClient(f"ws://{SERVER_IP}:{SERVER_PORT}")
    try:
        await client.connect_to_server()
    except KeyboardInterrupt:
        print("\nClosing connection...")
    finally:
        client.running = False

# Executa o cliente
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nClosing connection...")
        sys.exit()
