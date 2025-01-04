# configs/modules/config_manager.py

import os
import json
from datetime import datetime
from dotenv import load_dotenv, find_dotenv

class ConfigManager:
    def __init__(self):
        self.CONFIGS_DIR = "configs"
        self.SERVER_CONFIG_FILE = os.path.join(self.CONFIGS_DIR, "server_config.json")
        self.SELECTED_CLIENT_FILE = os.path.join(self.CONFIGS_DIR, "selected_client.json")
        
        # Carregar variáveis de ambiente
        load_dotenv(find_dotenv())
        self.AUTH_TOKEN = os.getenv("AUTH_TOKEN")
        
        if not self.AUTH_TOKEN:
            raise EnvironmentError("AUTH_TOKEN não está definido no arquivo .env")
        
        print(f"[{self.get_timestamp()}] AUTH_TOKEN carregado: '{self.AUTH_TOKEN}'")

    def get_timestamp(self):
        """Retorna timestamp formatado."""
        return datetime.now().strftime("%H:%M:%S")

    def load_or_create_configs(self):
        """Carrega ou cria as configurações do servidor."""
        if not os.path.exists(self.CONFIGS_DIR):
            os.makedirs(self.CONFIGS_DIR)
        
        default_config = {
            "redundancy_level": 1,
            "auto_select_first": True,
            "use_ipv6": False,
            "use_ssl": False
        }
        
        if os.path.exists(self.SERVER_CONFIG_FILE):
            with open(self.SERVER_CONFIG_FILE, 'r') as f:
                config = json.load(f)
        else:
            config = default_config
            with open(self.SERVER_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
        
        return config

    def save_selected_client(self, client_ip):
        """Salva o cliente selecionado em um arquivo JSON."""
        data = {"selected_client_ip": client_ip}
        with open(self.SELECTED_CLIENT_FILE, 'w') as f:
            json.dump(data, f, indent=4)

    def load_selected_client(self):
        """Carrega o cliente selecionado do arquivo JSON."""
        if os.path.exists(self.SELECTED_CLIENT_FILE):
            with open(self.SELECTED_CLIENT_FILE, 'r') as f:
                data = json.load(f)
                return data.get("selected_client_ip")
        return None

    def update_config(self, key, value):
        """Atualiza uma configuração específica no arquivo."""
        config = self.load_or_create_configs()
        config[key] = value
        with open(self.SERVER_CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        return config

    def get_auth_token(self):
        """Retorna o token de autenticação."""
        return self.AUTH_TOKEN