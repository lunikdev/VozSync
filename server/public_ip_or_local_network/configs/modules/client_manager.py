# configs/modules/client_manager.py

import time
import json
from datetime import datetime
import websockets
import uuid
import hashlib

class ClientManager:
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.clients = {}  # Para clientes finais
        self.processing_slots = {}  # Para clientes de processamento
        self.next_client_id = 1
        self.redundancy_level = config_manager.load_or_create_configs()["redundancy_level"]
        self.auto_select_first = config_manager.load_or_create_configs()["auto_select_first"]
        self.selected_client = config_manager.load_selected_client()
        self.round_robin_index = 0
        self.client_fingerprints = {}  # Mapeia fingerprints para slots
        
    def get_timestamp(self):
        return datetime.now().strftime("%H:%M:%S")

    @staticmethod
    def extract_ip(websocket):
        """Extrai apenas o IP do endereço do websocket."""
        return websocket.remote_address[0]

    def generate_fingerprint(self, websocket, client_type):
        """Gera um fingerprint único para o cliente baseado em headers e outros dados."""
        request_headers = getattr(websocket, 'request', None)
        if request_headers and request_headers.headers:
            # Pega headers que podem ajudar a identificar o cliente
            user_agent = request_headers.headers.get('User-Agent', '')
            host = request_headers.headers.get('Host', '')
            client_ip = self.extract_ip(websocket)
            
            # Cria uma string única com essas informações
            unique_string = f"{client_ip}:{user_agent}:{host}:{client_type}"
            
            # Gera um hash dessa string
            return hashlib.md5(unique_string.encode()).hexdigest()
        return str(uuid.uuid4())  # Fallback se não houver headers

    def get_slot_by_fingerprint(self, fingerprint):
        """Retorna o slot associado ao fingerprint ou None."""
        return self.client_fingerprints.get(fingerprint)

    async def add_client(self, websocket, client_ip, client_type='processing'):
            """Registra um novo cliente ou reconecta um cliente existente."""
            if client_type == 'processing':
                # Gera fingerprint único para o cliente de processamento
                fingerprint = self.generate_fingerprint(websocket, client_type)
                
                # Procura por um slot existente com este fingerprint
                existing_slot = None
                for slot_key, data in self.processing_slots.items():
                    if data.get('fingerprint') == fingerprint:
                        existing_slot = slot_key
                        break
                
                if existing_slot:
                    # Reconexão - atualiza o slot existente
                    client_id = self.processing_slots[existing_slot]['client_id']
                    self.processing_slots[existing_slot].update({
                        'websocket': websocket,
                        'last_ping': time.time(),
                        'ip': client_ip
                    })
                    print(f"[{self.get_timestamp()}] Reconexão detectada no slot {existing_slot}")
                    print(f"IP: {client_ip} | ID: {client_id} | Fingerprint: {fingerprint[:8]}")
                else:
                    # Novo cliente - cria novo slot
                    client_id = self.next_client_id
                    self.next_client_id += 1
                    new_slot = f"slot_{len(self.processing_slots) + 1}"
                    
                    self.processing_slots[new_slot] = {
                        'websocket': websocket,
                        'last_ping': time.time(),
                        'client_id': client_id,
                        'type': client_type,
                        'ip': client_ip,
                        'fingerprint': fingerprint
                    }
                    
                    if self.redundancy_level == 1 and self.auto_select_first and not self.selected_client:
                        self.selected_client = new_slot
                        print(f"[{self.get_timestamp()}] Novo cliente de processamento selecionado")
                        print(f"Slot: {new_slot} | IP: {client_ip} | ID: {client_id} | Fingerprint: {fingerprint[:8]}")
                    else:
                        print(f"[{self.get_timestamp()}] Novo cliente de processamento conectado")
                        print(f"Slot: {new_slot} | IP: {client_ip} | ID: {client_id} | Fingerprint: {fingerprint[:8]}")
            else:
                # Cliente final - usa uma chave simples com IP + tipo
                client_key = f"{client_ip}_{client_type}"
                
                if client_key in self.clients:
                    # Reconexão
                    old_client_id = self.clients[client_key]['client_id']
                    self.clients[client_key].update({
                        'websocket': websocket,
                        'last_ping': time.time()
                    })
                    print(f"[{self.get_timestamp()}] Reconexão de cliente final")
                    print(f"IP: {client_ip} | ID: {old_client_id}")
                    client_id = old_client_id
                else:
                    # Novo cliente
                    client_id = self.next_client_id
                    self.next_client_id += 1
                    
                    self.clients[client_key] = {
                        'websocket': websocket,
                        'last_ping': time.time(),
                        'client_id': client_id,
                        'type': client_type
                    }
                    print(f"[{self.get_timestamp()}] Novo cliente final conectado")
                    print(f"IP: {client_ip} | ID: {client_id}")

            welcome_message = {
                "type": "welcome",
                "client_id": client_id,
                "client_type": client_type,
                "message": f"Conectado como Cliente #{client_id}"
            }
            await websocket.send(json.dumps(welcome_message))

    async def handle_client_disconnect(self, client_info):
        """Gerencia a desconexão de um cliente."""
        try:
            # Procura em clientes de processamento
            slots_to_remove = []
            for slot_key, data in self.processing_slots.items():
                if data['ip'] == client_info:
                    slots_to_remove.append((slot_key, data))
            
            for slot_key, data in slots_to_remove:
                was_selected = (slot_key == self.selected_client)
                print(f"[{self.get_timestamp()}] Cliente de processamento desconectado")
                print(f"Slot: {slot_key} | IP: {data['ip']} | ID: {data['client_id']} | Fingerprint: {data['fingerprint'][:8]}")
                
                if was_selected:
                    self._select_new_processing_client()
            
            # Procura em clientes finais
            client_key = f"{client_info}:final"
            if client_key in self.clients:
                client_id = self.clients[client_key]['client_id']
                del self.clients[client_key]
                print(f"[{self.get_timestamp()}] Cliente final desconectado")
                print(f"IP: {client_info} | ID: {client_id}")
                    
        except Exception as e:
            print(f"[{self.get_timestamp()}] Erro ao desconectar cliente {client_info}: {e}")

    def _select_new_processing_client(self):
        """Seleciona um novo cliente de processamento após desconexão."""
        if self.processing_slots:
            next_slot = next(iter(self.processing_slots.keys()))
            self.selected_client = next_slot
            data = self.processing_slots[next_slot]
            print(f"[{self.get_timestamp()}] Novo cliente de processamento selecionado automaticamente")
            print(f"Slot: {next_slot} | IP: {data['ip']} | ID: {data['client_id']} | Fingerprint: {data['fingerprint'][:8]}")
        else:
            self.selected_client = None
            print(f"[{self.get_timestamp()}] Nenhum cliente de processamento disponível")

    def list_clients(self):
        """Lista todos os clientes conectados."""
        print(f"\n[{self.get_timestamp()}] Clientes conectados:")
        print("\nClientes de Processamento:")
        for slot_key, data in self.processing_slots.items():
            selected = " (Selecionado)" if slot_key == self.selected_client else ""
            print(f"Slot: {slot_key} | IP: {data['ip']} | ID: {data['client_id']} | Fingerprint: {data['fingerprint'][:8]}{selected}")
        
        print("\nClientes Finais:")
        for client_key, data in self.clients.items():
            ip = client_key.split(':')[0]
            print(f"IP: {ip} | ID: {data['client_id']}")

    async def send_to_client(self, client_key, message):
            """Envia uma mensagem para um cliente específico."""
            try:
                if client_key.startswith('slot_'):
                    # Cliente de processamento
                    if client_key not in self.processing_slots:
                        return False
                    await self.processing_slots[client_key]['websocket'].send(message)
                else:
                    # Cliente final
                    if client_key not in self.clients:
                        return False
                    await self.clients[client_key]['websocket'].send(message)
                return True
            except Exception as e:
                client_id = (self.processing_slots[client_key]['client_id'] if client_key.startswith('slot_') 
                            else self.clients[client_key]['client_id'])
                print(f"[{self.get_timestamp()}] Erro ao enviar para Cliente #{client_id}: {e}")
                return False

    def get_client_id(self, client_ip):
        """Retorna o ID do cliente."""
        # Procura em clientes de processamento
        for data in self.processing_slots.values():
            if data['ip'] == client_ip:
                return data['client_id']
        
        # Procura em clientes finais
        client_key = f"{client_ip}:final"
        if client_key in self.clients:
            return self.clients[client_key]['client_id']
        return None

    def update_redundancy_level(self, level):
        """Atualiza o nível de redundância."""
        self.redundancy_level = level

    def set_auto_select_first(self, value):
        """Define se deve selecionar automaticamente o primeiro cliente."""
        self.auto_select_first = value

    def get_next_round_robin_client(self):
        """Retorna o próximo cliente de processamento na ordem round-robin."""
        processing_slots = list(self.processing_slots.items())
        
        if len(processing_slots) >= 2:
            client = processing_slots[self.round_robin_index]
            self.round_robin_index = (self.round_robin_index + 1) % len(processing_slots)
            return client
        elif len(processing_slots) == 1:
            return processing_slots[0]
        return None