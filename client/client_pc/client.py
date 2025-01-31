#client.py cliente final que envia o audio e tem que receber a transcrição

import asyncio
import websockets
import pyaudio
import wave
import json
import base64
import os
import io
from datetime import datetime
import keyboard
from dotenv import load_dotenv

class AudioClient:
    def __init__(self):
        # Carrega variáveis de ambiente
        load_dotenv()
        self.AUTH_TOKEN = os.getenv("AUTH_TOKEN")
        if not self.AUTH_TOKEN:
            raise ValueError("AUTH_TOKEN não encontrado no arquivo .env")
        
        # Configurações iniciais
        self.setup_connection()
        
        # Configurações de áudio
        self.chunk_size = 1024
        self.format = pyaudio.paInt16
        self.channels = 1
        self.rate = 16000
        self.audio = pyaudio.PyAudio()
        
        # Estado do cliente
        self.running = True
        self.recording = False
        self.frames = []
        
        # Fila para áudio e loop de eventos
        self.audio_queue = None
        self.event_loop = None
        
    def setup_connection(self):
        """Configura a conexão com base nas preferências do usuário."""
        print("\n=== Configuração de Conexão ===")
        
        # Pergunta sobre SSL
        use_ssl = input("Deseja usar HTTPS? (S/N): ").strip().lower() in ['s', 'sim', 'y', 'yes']
        self.use_ssl = use_ssl
        
        if use_ssl:
            # Pergunta sobre Let's Encrypt
            use_le = input("Usar Let's Encrypt? (S/N): ").strip().lower() in ['s', 'sim', 'y', 'yes']
            
            if use_le:
                # Para Let's Encrypt, precisamos de um domínio válido
                self.host = input("Digite o domínio (ex: exemplo.com): ").strip()
            else:
                # Para SSL autoassinado, pode ser IP ou domínio
                self.host = input("Digite o IP ou domínio (ex: 192.168.1.100 ou exemplo.local): ").strip()
        else:
            # Para HTTP, pode ser IP ou domínio
            self.host = input("Digite o IP ou domínio (ex: 192.168.1.100 ou exemplo.local): ").strip()
        
        # Configuração da porta
        while True:
            try:
                port_input = input("Digite a porta (padrão: 9024): ").strip()
                self.port = int(port_input) if port_input else 9024
                break
            except ValueError:
                print("Porta inválida! Digite um número.")
        
        # Configura a URI final
        self.protocol = "wss" if use_ssl else "ws"
        self.uri = f"{self.protocol}://{self.host}:{self.port}"
        
        print(f"\nConexão configurada: {self.uri}")
        
    def get_timestamp(self):
        """Retorna timestamp formatado."""
        return datetime.now().strftime("%H:%M:%S")
        
    async def connect(self):
        """Estabelece conexão WebSocket com o servidor."""
        self.audio_queue = asyncio.Queue()
        self.event_loop = asyncio.get_event_loop()
        
        headers = {
            "Authorization": f"Bearer {self.AUTH_TOKEN}",
            "Client-Type": "final"  # Identifica como cliente final
        }
        
        try:
            async with websockets.connect(
                self.uri,
                additional_headers=headers,
                ssl=None if not self.use_ssl else True
            ) as websocket:
                print(f"[{self.get_timestamp()}] Conectado ao servidor em {self.uri}")
                
                # Inicia thread para monitorar teclas
                self.start_key_monitor()
                
                # Inicia tarefa para processar a fila de áudio
                audio_task = asyncio.create_task(self.process_audio_queue(websocket))
                
                # Processa mensagens recebidas
                try:
                    while self.running:
                        message = await websocket.recv()
                        await self.handle_message(message)
                except websockets.exceptions.ConnectionClosed:
                    print(f"[{self.get_timestamp()}] Conexão perdida. Tentando reconectar...")
                finally:
                    audio_task.cancel()
                        
        except Exception as e:
            print(f"[{self.get_timestamp()}] Erro de conexão: {e}")
            
    async def process_audio_queue(self, websocket):
        """Processa a fila de áudio assincronamente."""
        while True:
            try:
                wav_data = await self.audio_queue.get()
                message = {
                    "type": "audio",
                    "timestamp": self.get_timestamp(),
                    "audio_data": base64.b64encode(wav_data).decode('utf-8'),
                    "format": "wav"
                }
                await websocket.send(json.dumps(message))
                print(f"[{self.get_timestamp()}] Áudio enviado para o servidor")
            except Exception as e:
                print(f"[{self.get_timestamp()}] Erro ao enviar áudio: {e}")
            
    def start_key_monitor(self):
        """Inicia monitoramento de teclas em uma thread separada."""
        import threading
        
        def check_keys():
            print("\nControles:")
            print("Mantenha 'R' pressionado para gravar")
            print("Pressione 'Q' para sair")
            
            while self.running:
                if keyboard.is_pressed('r'):
                    if not self.recording:
                        self.start_recording()
                elif self.recording:
                    self.stop_recording()
                    
                if keyboard.is_pressed('q'):
                    self.running = False
                    break
                    
        key_thread = threading.Thread(target=check_keys)
        key_thread.daemon = True
        key_thread.start()
        
    def start_recording(self):
        """Inicia gravação de áudio."""
        self.recording = True
        self.frames = []
        print(f"\n[{self.get_timestamp()}] Gravando... (solte R para parar)")
        
        self.stream = self.audio.open(
            format=self.format,
            channels=self.channels,
            rate=self.rate,
            input=True,
            frames_per_buffer=self.chunk_size
        )
        
        # Inicia captura de áudio em uma thread separada
        def capture_audio():
            while self.recording:
                try:
                    data = self.stream.read(self.chunk_size, exception_on_overflow=False)
                    self.frames.append(data)
                except Exception as e:
                    print(f"[{self.get_timestamp()}] Erro na captura de áudio: {e}")
                    break
        
        import threading
        audio_thread = threading.Thread(target=capture_audio)
        audio_thread.daemon = True
        audio_thread.start()
        
    def stop_recording(self):
        """Para gravação e processa o áudio."""
        if not self.recording:
            return
            
        self.recording = False
        self.stream.stop_stream()
        self.stream.close()
        
        print(f"[{self.get_timestamp()}] Gravação finalizada")
        
        if not self.frames:
            print(f"[{self.get_timestamp()}] Nenhum áudio capturado")
            return
            
        # Cria arquivo WAV em memória
        wav_buffer = io.BytesIO()
        with wave.open(wav_buffer, 'wb') as wf:
            wf.setnchannels(self.channels)
            wf.setsampwidth(self.audio.get_sample_size(self.format))
            wf.setframerate(self.rate)
            wf.writeframes(b''.join(self.frames))
        
        # Coloca o áudio na fila para processamento assíncrono
        if self.event_loop and self.audio_queue:
            self.event_loop.call_soon_threadsafe(
                lambda: asyncio.create_task(
                    self.audio_queue.put(wav_buffer.getvalue())
                )
            )
            
    async def handle_message(self, message):
        try:
            data = json.loads(message)
            message_type = data.get("type", "unknown")
            
            if message_type == "welcome":
                print(f"[{self.get_timestamp()}] {data['message']}")
            elif message_type == "transcription":
                transcription = data.get("text", "")
                audio_uuid = data.get("audio_uuid", "")
                if transcription:
                    print(f"[{self.get_timestamp()}] Transcrição recebida (UUID: {audio_uuid}): {transcription}")
                else:
                    print(f"[{self.get_timestamp()}] Transcrição vazia recebida para UUID: {audio_uuid}")
            else:
                print(f"[{self.get_timestamp()}] Mensagem desconhecida recebida: {message_type}")
        except json.JSONDecodeError:
            print(f"[{self.get_timestamp()}] Erro ao decodificar mensagem")
        except Exception as e:
            print(f"[{self.get_timestamp()}] Erro ao processar mensagem: {e}")
            
    def cleanup(self):
        """Limpa recursos do cliente."""
        if hasattr(self, 'stream'):
            try:
                self.stream.stop_stream()
                self.stream.close()
            except:
                pass
        if self.audio:
            self.audio.terminate()
        print(f"[{self.get_timestamp()}] Cliente finalizado")

if __name__ == "__main__":
    client = AudioClient()
    
    try:
        asyncio.run(client.connect())
    except KeyboardInterrupt:
        print("\nEncerrando cliente...")
    except Exception as e:
        print(f"Erro: {e}")
    finally:
        client.cleanup()