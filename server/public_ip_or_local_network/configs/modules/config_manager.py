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
        
        # Carrega variáveis de ambiente do .env
        load_dotenv(find_dotenv())
        self.AUTH_TOKEN = os.getenv("AUTH_TOKEN")
        
        if not self.AUTH_TOKEN:
            raise EnvironmentError("AUTH_TOKEN não está definido no arquivo .env")
        
        print(f"[{self.get_timestamp()}] AUTH_TOKEN carregado: '{self.AUTH_TOKEN}'")

    def get_timestamp(self):
        """Retorna timestamp formatado (HH:MM:SS)."""
        return datetime.now().strftime("%H:%M:%S")

    def load_or_create_configs(self):
        """
        Carrega ou cria as configurações do servidor (server_config.json).
        Se não existir, pergunta interativamente ao usuário o tipo de conexão (HTTP/HTTPS),
        se for HTTPS, se é Let's Encrypt ou autoassinado, e se deseja usar IPv6.
        """
        if not os.path.exists(self.CONFIGS_DIR):
            os.makedirs(self.CONFIGS_DIR)
        
        default_config = {
            "redundancy_level": 1,
            "auto_select_first": True,
            "use_ipv6": False,
            "use_ssl": False,          # Por padrão: HTTP
            "use_lets_encrypt": False  # Por padrão: não usa Let's Encrypt
        }
        
        if os.path.exists(self.SERVER_CONFIG_FILE):
            # Se já existe, apenas carrega
            with open(self.SERVER_CONFIG_FILE, 'r') as f:
                config = json.load(f)
        else:
            # Se não existe, perguntar ao usuário
            print("\nNão foi encontrado 'server_config.json'. Vamos criar agora...")

            # Pergunta sobre IPv6
            choice_ipv6 = input("Deseja usar IPv6 (S/N)? ").strip().lower()
            if choice_ipv6 in ['s', 'sim', 'y', 'yes']:
                default_config["use_ipv6"] = True
                print("Você escolheu IPv6.")
            else:
                default_config["use_ipv6"] = False
                print("Você escolheu IPv4 (padrão).")

            # Pergunta se deseja usar HTTPS
            choice_https = input("Deseja usar HTTPS (S/N)? ").strip().lower()
            if choice_https in ['s', 'sim', 'y', 'yes']:
                default_config["use_ssl"] = True

                # Se escolher HTTPS, pergunta se quer Let’s Encrypt ou autoassinado
                choice_le = input(
                    "Deseja usar Let's Encrypt (produção) ou autoassinado (desenvolvimento)?\n"
                    "Digite 'LE' ou 'auto': "
                ).strip().lower()
                
                if choice_le.startswith('l'):
                    # Vamos assumir que 'l', 'le' => Let's Encrypt
                    default_config["use_lets_encrypt"] = True
                    print("Você escolheu HTTPS com Let's Encrypt (produção).")
                else:
                    # Qualquer coisa fora de 'l' tratamos como autoassinado
                    default_config["use_lets_encrypt"] = False
                    print("Você escolheu HTTPS autoassinado (desenvolvimento).")
            else:
                # HTTP
                default_config["use_ssl"] = False
                default_config["use_lets_encrypt"] = False
                print("Você escolheu HTTP (sem SSL).")

            # Salva o arquivo JSON com as escolhas feitas
            with open(self.SERVER_CONFIG_FILE, 'w') as f:
                json.dump(default_config, f, indent=4)
            
            config = default_config

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
        """Atualiza uma configuração específica no arquivo server_config.json."""
        config = self.load_or_create_configs()
        config[key] = value
        with open(self.SERVER_CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        return config

    def get_auth_token(self):
        """Retorna o token de autenticação carregado do .env."""
        return self.AUTH_TOKEN
