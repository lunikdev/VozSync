#server.py

import asyncio
import websockets
import os
import json
import base64
import threading
import time
from datetime import datetime
import uuid
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
            """Registra um novo cliente ou reconecta um cliente existente."""
            client_ip = self.client_manager.extract_ip(websocket)
            
            try:
                # Verificar autenticação
                request_headers = getattr(websocket, 'request', None)
                if request_headers:
                    auth_header = request_headers.headers.get('Authorization', '')
                    client_type = request_headers.headers.get('Client-Type', 'processing')
                else:
                    auth_header = ''
                    client_type = 'processing'
                
                if not auth_header or not auth_header.startswith('Bearer '):
                    print(f"[{self.get_timestamp()}] Token ausente ou formato inválido de {client_ip}")
                    await websocket.close(1002, reason='Token ausente ou formato inválido')
                    return
                    
                token = auth_header.split('Bearer ')[1].strip()
                
                if token != self.AUTH_TOKEN:
                    print(f"[{self.get_timestamp()}] Token inválido de {client_ip}")
                    await websocket.close(1002, reason='Token inválido')
                    return

                # Registrar cliente com seu tipo
                await self.client_manager.add_client(websocket, client_ip, client_type)

                if client_type == 'final':
                    # Para clientes finais
                    async for message in websocket:
                        try:
                            data = json.loads(message)
                            if data.get('type') == 'audio':
                                audio_uuid = str(uuid.uuid4())
                                print(f"[{self.get_timestamp()}] Novo áudio recebido do cliente final. UUID: {audio_uuid}")
                                await self.send_audio_to_clients(base64.b64decode(data['audio_data']), audio_uuid)
                        except json.JSONDecodeError:
                            print(f"[{self.get_timestamp()}] Erro ao decodificar mensagem do cliente final")
                        except Exception as e:
                            print(f"[{self.get_timestamp()}] Erro ao processar mensagem do cliente final: {str(e)}")
                else:
                    # Para clientes de processamento
                    async for message in websocket:
                        await self.handle_message(message, client_ip)

            except websockets.exceptions.ConnectionClosed:
                print(f"[{self.get_timestamp()}] Cliente {client_ip} desconectou")
                await self.client_manager.handle_client_disconnect(client_ip)
            except Exception as e:
                print(f"[{self.get_timestamp()}] Erro na conexão de {client_ip}: {e}")
                await self.client_manager.handle_client_disconnect(client_ip)

    async def handle_message(self, message, client_info):
        """Processa mensagens recebidas dos clientes."""
        try:
            data = json.loads(message)
            message_type = data.get("type", "unknown")

            if message_type == "transcription":
                transcription = data.get("text", "")
                audio_uuid = data.get("audio_uuid")
                timestamp = data.get("timestamp", self.get_timestamp())
                client_id = self.client_manager.get_client_id(client_info)
                
                print(f"[{timestamp}] Transcrição recebida de Cliente #{client_id}")
                print(f"UUID: {audio_uuid}")
                print(f"Texto: {transcription}")

                if audio_uuid:
                    await self.send_transcription_to_final_client(audio_uuid, transcription)
                else:
                    print(f"[{timestamp}] AVISO: Transcrição recebida sem UUID")
            else:
                print(f"[{self.get_timestamp()}] Tipo de mensagem desconhecido de {client_info}: {message_type}")

        except json.JSONDecodeError as e:
            print(f"[{self.get_timestamp()}] Erro ao decodificar mensagem de {client_info}: {e}")
        except Exception as e:
            print(f"[{self.get_timestamp()}] Erro ao processar mensagem de {client_info}: {e}")

    async def send_audio_to_clients(self, audio_bytes, audio_uuid):
            """Envia dados de áudio para os clientes de processamento."""
            if not audio_uuid:
                print(f"[{self.get_timestamp()}] ERRO: Tentativa de envio de áudio sem UUID")
                return

            wav_data = self.audio_processor.create_wav_from_bytes(audio_bytes)
            if not wav_data:
                print(f"[{self.get_timestamp()}] Erro: Dados WAV inválidos para UUID {audio_uuid}")
                return

            message = {
                "type": "complete_audio",
                "timestamp": self.get_timestamp(),
                "audio_data": base64.b64encode(wav_data).decode('utf-8'),
                "audio_uuid": audio_uuid,
                "format": "wav",
                "duration": len(audio_bytes) / (self.audio_processor.rate * self.audio_processor.channels * 2)
            }

            message_str = json.dumps(message)
            sent_successfully = False

            # Filtra apenas os clientes de processamento
            processing_slots = {k: v for k, v in self.client_manager.processing_slots.items()}

            if not processing_slots:
                print(f"[{self.get_timestamp()}] Não há clientes de processamento disponíveis para UUID {audio_uuid}")
                return

            if self.client_manager.redundancy_level == 3:
                next_client = self.client_manager.get_next_round_robin_client()
                if next_client:
                    slot_key, client_data = next_client
                    if await self.client_manager.send_to_client(slot_key, message_str):
                        sent_successfully = True
                        print(f"[{self.get_timestamp()}] Áudio UUID {audio_uuid} enviado para cliente #{client_data['client_id']}")
                    else:
                        await self.client_manager.handle_client_disconnect(client_data['ip'])
            
            elif self.client_manager.redundancy_level == 2:
                for slot_key, client_data in processing_slots.items():
                    if await self.client_manager.send_to_client(slot_key, message_str):
                        sent_successfully = True
                        print(f"[{self.get_timestamp()}] Áudio UUID {audio_uuid} enviado para cliente #{client_data['client_id']}")
                    else:
                        await self.client_manager.handle_client_disconnect(client_data['ip'])
            
            elif self.client_manager.redundancy_level == 1:
                if self.client_manager.selected_client:
                    slot_key = self.client_manager.selected_client
                    if slot_key in processing_slots:
                        client_data = processing_slots[slot_key]
                        if await self.client_manager.send_to_client(slot_key, message_str):
                            sent_successfully = True
                            print(f"[{self.get_timestamp()}] Áudio UUID {audio_uuid} enviado para cliente #{client_data['client_id']}")
                        else:
                            await self.client_manager.handle_client_disconnect(client_data['ip'])

            if not sent_successfully:
                print(f"[{self.get_timestamp()}] Não foi possível enviar o áudio UUID {audio_uuid} para processamento")

    async def send_transcription_to_final_client(self, audio_uuid, transcription):
            """Envia a transcrição de volta para o cliente final com o UUID."""
            final_clients = {k: v for k, v in self.client_manager.clients.items() if '_final' in k}
            
            if not final_clients:
                print(f"[{self.get_timestamp()}] Nenhum cliente final encontrado para receber a transcrição")
                return

            message = {
                "type": "transcription",
                "timestamp": self.get_timestamp(),
                "text": transcription,
                "audio_uuid": audio_uuid
            }
            message_str = json.dumps(message)

            for client_key, client_data in final_clients.items():
                try:
                    success = await self.client_manager.send_to_client(client_key, message_str)
                    if success:
                        print(f"[{self.get_timestamp()}] Transcrição enviada para o cliente final #{client_data['client_id']}")
                        print(f"UUID: {audio_uuid}")
                        print(f"Texto: {transcription}")
                    else:
                        print(f"[{self.get_timestamp()}] Falha ao enviar transcrição para o cliente final #{client_data['client_id']}")
                except Exception as e:
                    print(f"[{self.get_timestamp()}] Erro ao enviar para cliente final #{client_data['client_id']}: {e}")

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

                        self.audio_processor.add_to_buffer(data)
                        voice_threshold = self.audio_processor.long_term_noise_level + 300

                        if self.audio_processor.voice_activity_detected:
                            self.audio_processor.append_frame(data)
                            if self.audio_processor.current_noise_level < self.audio_processor.ambient_noise_level + 100:
                                audio_bytes = self.audio_processor.get_frames_as_bytes()
                                if len(audio_bytes) > 0:
                                    print(f"[{self.get_timestamp()}] Segmento de fala finalizado")
                                    audio_uuid = str(uuid.uuid4())
                                    processed_audio = self.audio_processor.process_audio(audio_bytes)
                                    await self.send_audio_to_clients(processed_audio, audio_uuid)
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
                        print(f"[{self.get_timestamp()}] Forçando envio do áudio devido ao mute")
                        processed_audio = self.audio_processor.process_audio(audio_bytes)
                        audio_uuid = str(uuid.uuid4())
                        await self.send_audio_to_clients(processed_audio, audio_uuid)
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
            print(f"[{self.get_timestamp()}] Captura de áudio parada")

    def show_menu(self):
        """Exibe o menu de controle de redundância."""
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
        """Gerencia entradas de teclado (para desligar, mutar, etc.)."""
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
                elif keyboard.is_pressed('x'):
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
        """Limpa recursos do servidor antes de sair."""
        self.audio_processor.cleanup()
        print(f"[{self.get_timestamp()}] Desligamento do servidor completo.")

    async def start_server(self):
        """Inicia o servidor WebSocket."""
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
                print(f"[{self.get_timestamp()}] Pressione 'm' para abrir o menu de controle.")

                broadcast_task = asyncio.create_task(self.broadcast_audio())
                await asyncio.gather(server.wait_closed(), broadcast_task)

        except Exception as e:
            print(f"[{self.get_timestamp()}] Erro em start_server: {e}")
        finally:
            self.cleanup()

if __name__ == "__main__":
    from configs.modules.letsencrypt_manager import LetsEncryptManager

    config_manager = ConfigManager()
    config = config_manager.load_or_create_configs()

    if config["use_ssl"]:
        if config.get("use_lets_encrypt", False):
            print("[MAIN] Modo HTTPS (produção) com Let's Encrypt habilitado.")

            # Verifica se já existem server.crt / server.key em 'certs/letsencrypt/'
            le_server_crt = os.path.join("certs", "letsencrypt", "server.crt")
            le_server_key = os.path.join("certs", "letsencrypt", "server.key")

            if not (os.path.exists(le_server_crt) and os.path.exists(le_server_key)):
                # Se não existir, pergunta ao usuário se deseja gerar agora
                choice_generate = input("Certificados LE não encontrados. Deseja gerar agora? (S/N): ").strip().lower()
                if choice_generate in ['s', 'sim', 'y', 'yes']:
                    lem = LetsEncryptManager()
                    success = lem.setup_letsencrypt()
                    if not success:
                        print("[MAIN] Falha na criação de certificados Let's Encrypt. Voltando para autoassinado.")
                        config["use_lets_encrypt"] = False
                        config_manager.update_config("use_lets_encrypt", False)
                else:
                    print("[MAIN] O usuário optou por não gerar LE. Voltando para autoassinado.")
                    config["use_lets_encrypt"] = False
                    config_manager.update_config("use_lets_encrypt", False)
            else:
                print("[MAIN] Certificados Let's Encrypt já existem na pasta certs/letsencrypt/.")
        else:
            print("[MAIN] Modo HTTPS (desenvolvimento) com certificados autoassinados.")
    else:
        print("[MAIN] Modo HTTP (sem SSL).")

    # Agora instancia o servidor com base no config atualizado
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