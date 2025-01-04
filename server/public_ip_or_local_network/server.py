# server.py
import asyncio
import websockets
import os
import json
import base64
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import keyboard
import socket
from configs.modules.ssl_manager import SSLManager
from configs.modules.config_manager import ConfigManager
from configs.modules.audio_processor import AudioProcessor
from configs.modules.client_manager import ClientManager

class AudioServer:
    def __init__(self, host="0.0.0.0", port=9024, use_ssl=False, use_ipv6=False):
        # Inicializar gerenciadores
        self.config_manager = ConfigManager()
        config = self.config_manager.load_or_create_configs()
        
        # Configurações básicas
        self.host = "::" if config["use_ipv6"] else host
        self.port = port
        self.use_ssl = config["use_ssl"]
        self.use_ipv6 = config["use_ipv6"]
        self.ssl_context = None
        
        # Inicializar gerenciadores
        self.client_manager = ClientManager(self.config_manager)
        self.audio_processor = AudioProcessor()
        
        # Estado do servidor
        self.running = True
        self.muted = False
        self.menu_active = False
        self.force_send_event = threading.Event()
        self.executor = ThreadPoolExecutor(max_workers=2)
        
        # Inicializar SSL se necessário
        if self.use_ssl:
            self.ssl_manager = SSLManager()
            self.ssl_context = self.ssl_manager.get_ssl_context()
            print("Contexto SSL configurado para o servidor.")
        
        self.AUTH_TOKEN = self.config_manager.get_auth_token()

    def get_timestamp(self):
        return datetime.now().strftime("%H:%M:%S")

    async def register(self, websocket):
        client_ip = self.client_manager.extract_ip(websocket)
        
        try:
            # Verificar autenticação
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
            
            if token != self.AUTH_TOKEN:
                print(f"[{self.get_timestamp()}] Token inválido de {client_ip}")
                await websocket.close(1002, reason='Token inválido')
                return

            print(f"[{self.get_timestamp()}] Nova conexão de {client_ip} autenticada com sucesso.")
            
            # Registrar cliente
            await self.client_manager.add_client(websocket, client_ip)

            try:
                async for message in websocket:
                    await self.handle_message(message, client_ip)
            except websockets.exceptions.ConnectionClosed as e:
                print(f"[{self.get_timestamp()}] Cliente {client_ip} desconectado: {e}")
            except Exception as e:
                print(f"[{self.get_timestamp()}] Erro com cliente {client_ip}: {e}")
            finally:
                await self.client_manager.handle_client_disconnect(client_ip)
                
        except Exception as e:
            print(f"[{self.get_timestamp()}] Erro na autenticação de {client_ip}: {e}")
            await websocket.close(1002, reason='Erro na autenticação')
            return

    async def handle_message(self, message, client_info):
        """Processa mensagens recebidas dos clientes."""
        try:
            data = json.loads(message)
            message_type = data.get("type", "unknown")

            if message_type == "transcription":
                transcription = data.get("text", "")
                timestamp = data.get("timestamp", self.get_timestamp())
                client_id = self.client_manager.get_client_id(client_info)
                print(f"[{timestamp}] Transcrição recebida de Cliente #{client_id}: {transcription}")

                if self.client_manager.redundancy_level == 3:
                    print(f"[{self.get_timestamp()}] Processamento balanceado - Cliente #{client_id}")
            else:
                print(f"[{self.get_timestamp()}] Tipo de mensagem desconhecido de {client_info}: {message_type}")

        except json.JSONDecodeError as e:
            print(f"[{self.get_timestamp()}] Erro ao decodificar mensagem de {client_info}: {e}")
        except Exception as e:
            print(f"[{self.get_timestamp()}] Erro ao processar mensagem de {client_info}: {e}")

    async def broadcast_audio(self):
        """Transmite áudio para os clientes."""
        try:
            stream = self.audio_processor.get_audio_stream()
            print(f"[{self.get_timestamp()}] Iniciando captura de áudio...")

            loop = asyncio.get_event_loop()

            while self.running:
                if not self.muted:
                    try:
                        data = await loop.run_in_executor(
                            self.executor,
                            lambda: stream.read(self.audio_processor.chunk_size, exception_on_overflow=False)
                        )
                        if not data:
                            continue

                        pegel = self.audio_processor.get_levels(data)
                        self.audio_processor.add_to_buffer(data)

                        voice_threshold = self.audio_processor.long_term_noise_level + 300

                        if self.audio_processor.voice_activity_detected:
                            self.audio_processor.append_frame(data)
                            if self.audio_processor.current_noise_level < self.audio_processor.ambient_noise_level + 100:
                                audio_bytes = self.audio_processor.get_frames_as_bytes()
                                if len(audio_bytes) > 0:
                                    print(f"[{self.get_timestamp()}] Segmento de fala finalizado, enviando para os clientes.")
                                    processed_audio = self.audio_processor.process_audio(audio_bytes)
                                    await self.send_audio_to_clients(processed_audio)
                                    
                                self.audio_processor.reset_audio_state()
                        else:
                            if self.audio_processor.current_noise_level > voice_threshold:
                                print(f"[{self.get_timestamp()}] Voz detectada!")
                                self.audio_processor.voice_activity_detected = True
                                self.audio_processor.ambient_noise_level = self.audio_processor.long_term_noise_level
                                self.audio_processor.frames = self.audio_processor.get_buffer_as_list()

                    except Exception as e:
                        print(f"[{self.get_timestamp()}] Erro ao capturar áudio: {e}")
                        break
                else:
                    await asyncio.sleep(0.1)

                if self.force_send_event.is_set():
                    audio_bytes = self.audio_processor.get_frames_as_bytes()
                    if audio_bytes:
                        print(f"[{self.get_timestamp()}] Forçando envio do áudio devido ao mute.")
                        processed_audio = self.audio_processor.process_audio(audio_bytes)
                        await self.send_audio_to_clients(processed_audio)

                    self.audio_processor.reset_audio_state()
                    self.force_send_event.clear()

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

    async def send_audio_to_clients(self, audio_bytes):
        """Envia dados de áudio para os clientes."""
        wav_data = self.audio_processor.create_wav_from_bytes(audio_bytes)
        if not wav_data:
            return

        message = {
            "type": "complete_audio",
            "timestamp": self.get_timestamp(),
            "audio_data": base64.b64encode(wav_data).decode('utf-8'),
            "format": "wav",
            "duration": len(audio_bytes) / (self.audio_processor.rate * self.audio_processor.channels * 2)
        }

        message_str = json.dumps(message)

        if self.client_manager.redundancy_level == 3:
            next_client = self.client_manager.get_next_round_robin_client()
            if next_client:
                client_info, client_data = next_client
                if not await self.client_manager.send_to_client(client_info, message_str):
                    await self.client_manager.handle_client_disconnect(client_info)
        
        elif self.client_manager.redundancy_level == 2:
            for client_ip in list(self.client_manager.clients.keys()):
                if not await self.client_manager.send_to_client(client_ip, message_str):
                    await self.client_manager.handle_client_disconnect(client_ip)
        
        elif self.client_manager.redundancy_level == 1:
            if self.client_manager.selected_client:
                if not await self.client_manager.send_to_client(self.client_manager.selected_client, message_str):
                    await self.client_manager.handle_client_disconnect(self.client_manager.selected_client)

    async def send_complete_audio(self):
        """Envia qualquer áudio restante no buffer."""
        if self.audio_processor.frames:
            audio_bytes = self.audio_processor.get_frames_as_bytes()
            if len(audio_bytes) > 0:
                print(f"[{self.get_timestamp()}] Enviando segmento final de áudio.")
                processed_audio = self.audio_processor.process_audio(audio_bytes)
                await self.send_audio_to_clients(processed_audio)

    def show_menu(self):
        """Exibe o menu de controle."""
        print("\n=== Menu de Controle de Redundância ===")
        print(f"Nível atual: {self.client_manager.redundancy_level}")
        print(f"Auto-seleção: {'Ativada' if self.client_manager.auto_select_first else 'Desativada'}")
        print("\nOpções:")
        print("1. Alterar para Nível 1 (Cliente Único)")
        print("2. Alterar para Nível 2 (Redundância Total)")
        print("3. Alterar para Nível 3 (Redundância + Balanceamento)")
        print("4. Selecionar Cliente Específico (somente nível 1)")
        print("5. Listar Clientes Conectados")
        print("6. Alternar Auto-seleção")
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
                    self.client_manager.update_redundancy_level(1)
                    if self.client_manager.auto_select_first:
                        self.client_manager.select_first_available_client()
                elif choice == "2":
                    self.client_manager.update_redundancy_level(2)
                elif choice == "3":
                    self.client_manager.update_redundancy_level(3)
                elif choice == "4":
                    if self.client_manager.redundancy_level == 1:
                        self.client_manager.list_clients()
                        try:
                            client_id = int(input("\nDigite o ID do cliente para selecionar: "))
                            self.client_manager.select_client(client_id)
                        except ValueError:
                            print("ID inválido")
                    else:
                        print("Seleção de cliente só está disponível no nível 1")
                elif choice == "5":
                    self.client_manager.list_clients()
                    input("\nPressione Enter para continuar...")
                elif choice == "6":
                    auto_select = not self.client_manager.auto_select_first
                    self.client_manager.set_auto_select_first(auto_select)
                    if auto_select and self.client_manager.redundancy_level == 1:
                        self.client_manager.select_first_available_client()
                else:
                    print("Opção inválida!")

            except Exception as e:
                print(f"Erro ao processar opção: {e}")

    def handle_keys(self):
        """Gerencia entradas de teclado."""
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
                            self.audio_processor.reset_audio_state()
                        last_toggle_time = current_time
                elif keyboard.is_pressed('m'):
                    current_time = time.time()
                    if current_time - last_toggle_time > toggle_cooldown:
                        if not self.menu_active:
                            print("\nAbrindo menu de controle...")
                            self.menu_active = True
                            menu_thread = threading.Thread(target=self.handle_menu)
                            menu_thread.daemon = True
                            menu_thread.start()
                        last_toggle_time = current_time
                time.sleep(0.1)

        keyboard_thread = threading.Thread(target=check_keys)
        keyboard_thread.daemon = True
        keyboard_thread.start()

    def cleanup(self):
        """Limpa recursos do servidor."""
        self.audio_processor.cleanup()
        print(f"[{self.get_timestamp()}] Desligamento do servidor completo.")

    async def start_server(self):
        """Inicia o servidor."""
        self.handle_keys()

        try:
            if self.use_ipv6:
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
    config_manager = ConfigManager()
    config = config_manager.load_or_create_configs()
    
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