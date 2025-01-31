# configs/modules/client_manager.py

import time
import json
from datetime import datetime
import websockets

class ClientManager:
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.clients = {}
        self.next_client_id = 1
        self.redundancy_level = config_manager.load_or_create_configs()["redundancy_level"]
        self.auto_select_first = config_manager.load_or_create_configs()["auto_select_first"]
        self.selected_client = config_manager.load_selected_client()
        self.round_robin_index = 0

    def get_timestamp(self):
        return datetime.now().strftime("%H:%M:%S")

    @staticmethod
    def extract_ip(websocket):
        """Extrai apenas o IP do endereço do websocket."""
        return websocket.remote_address[0]

    async def handle_client_disconnect(self, client_info):
        """Gerencia a desconexão de um cliente."""
        try:
            if client_info in self.clients:
                was_selected = (client_info == self.selected_client)
                client_id = self.clients[client_info]['client_id']
                del self.clients[client_info]
                print(f"[{self.get_timestamp()}] Cliente {client_info} removido da lista de conexões")
                
                if was_selected and self.clients:
                    saved_client = self.config_manager.load_selected_client()
                    if saved_client and saved_client in self.clients:
                        self.selected_client = saved_client
                        print(f"[{self.get_timestamp()}] Cliente prioritário #{self.clients[saved_client]['client_id']} selecionado automaticamente")
                    else:
                        next_client_info = next(iter(self.clients))
                        self.selected_client = next_client_info
                        print(f"[{self.get_timestamp()}] Cliente #{self.clients[next_client_info]['client_id']} selecionado automaticamente")
                elif was_selected:
                    print(f"[{self.get_timestamp()}] Cliente selecionado desconectou e não há outros clientes disponíveis.")
                    self.selected_client = None
        except Exception as e:
            print(f"[{self.get_timestamp()}] Erro ao desconectar cliente {client_info}: {e}")


    async def add_client(self, websocket, client_ip, client_type='processing'):
        if client_ip in self.clients:
            old_client_id = self.clients[client_ip]['client_id']
            self.clients[client_ip] = {
                'websocket': websocket,
                'last_ping': time.time(),
                'client_id': old_client_id,
                'type': client_type
            }
            print(f"[{self.get_timestamp()}] Reconexão detectada para {client_ip} ({client_type})")
        else:
            new_client_id = self.next_client_id
            self.next_client_id += 1
            
            if client_type == 'processing' and self.redundancy_level == 1 and self.auto_select_first:
                saved_client = self.config_manager.load_selected_client()
                
                if saved_client == client_ip:
                    self.selected_client = client_ip
                    print(f"[{self.get_timestamp()}] Cliente prioritário {client_ip} conectado e selecionado automaticamente")
                elif not self.selected_client:
                    self.selected_client = client_ip
                    print(f"[{self.get_timestamp()}] Cliente {client_ip} selecionado automaticamente")
            
            self.clients[client_ip] = {
                'websocket': websocket,
                'last_ping': time.time(),
                'client_id': new_client_id,
                'type': client_type
            }

        welcome_message = {
            "type": "welcome",
            "client_id": self.clients[client_ip]['client_id'],
            "client_type": client_type,
            "message": f"Conectado como Cliente #{self.clients[client_ip]['client_id']}"
        }
        await websocket.send(json.dumps(welcome_message))

    def select_client(self, client_id):
        """Seleciona um cliente específico para processamento."""
        if self.redundancy_level != 1:
            print(f"[{self.get_timestamp()}] Seleção de cliente só está disponível no nível 1 de redundância")
            return False

        for client_ip, client_data in self.clients.items():
            if client_data['client_id'] == client_id:
                self.selected_client = client_ip
                self.config_manager.save_selected_client(client_ip)
                print(f"[{self.get_timestamp()}] Cliente #{client_id} (IP: {client_ip}) selecionado para processamento")
                return True
        
        print(f"[{self.get_timestamp()}] Cliente #{client_id} não encontrado")
        return False

    def select_first_available_client(self):
        """Seleciona automaticamente o primeiro cliente disponível."""
        if not self.clients:
            print("Nenhum cliente disponível para seleção")
            return False

        saved_client = self.config_manager.load_selected_client()
        
        if saved_client and saved_client in self.clients:
            self.selected_client = saved_client
            print(f"[{self.get_timestamp()}] Cliente prioritário #{self.clients[saved_client]['client_id']} selecionado automaticamente")
            return True
        
        first_client = list(self.clients.values())[0]
        self.selected_client = list(self.clients.keys())[0]
        print(f"[{self.get_timestamp()}] Cliente #{first_client['client_id']} selecionado automaticamente")
        return True

    def list_clients(self):
        """Lista todos os clientes conectados."""
        print(f"\n[{self.get_timestamp()}] Clientes conectados:")
        for client_ip, client_data in self.clients.items():
            selected = " (Selecionado)" if client_ip == self.selected_client else ""
            print(f"Cliente #{client_data['client_id']} - IP: {client_ip}{selected}")

    async def send_to_client(self, client_ip, message):
        """Envia uma mensagem para um cliente específico."""
        try:
            await self.clients[client_ip]['websocket'].send(message)
            return True
        except Exception as e:
            print(f"[{self.get_timestamp()}] Erro ao enviar para Cliente #{self.clients[client_ip]['client_id']}: {e}")
            return False

    def get_client_id(self, client_ip):
        """Retorna o ID do cliente."""
        return self.clients[client_ip]['client_id'] if client_ip in self.clients else None

    def update_redundancy_level(self, level):
        """Atualiza o nível de redundância."""
        self.redundancy_level = level

    def set_auto_select_first(self, value):
        """Define se deve selecionar automaticamente o primeiro cliente."""
        self.auto_select_first = value

    def get_next_round_robin_client(self):
        """Retorna o próximo cliente na ordem round-robin."""
        if len(self.clients) >= 2:
            clients_list = list(self.clients.items())
            client = clients_list[self.round_robin_index]
            self.round_robin_index = (self.round_robin_index + 1) % len(clients_list)
            return client
        elif len(self.clients) == 1:
            return next(iter(self.clients.items()))
        return None