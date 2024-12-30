import os
import secrets
from dotenv import load_dotenv, set_key, find_dotenv

def generate_token(length=32):
    """Gera um token seguro usando o módulo secrets."""
    return secrets.token_urlsafe(length)

def update_env(token, env_path):
    """
    Atualiza ou adiciona a variável AUTH_TOKEN no arquivo .env.

    Args:
        token (str): O token de autenticação a ser inserido no .env.
        env_path (str): O caminho para o arquivo .env.
    """
    # Carrega as variáveis de ambiente existentes
    load_dotenv(dotenv_path=env_path)

    # Define ou atualiza a variável AUTH_TOKEN
    set_key(env_path, "AUTH_TOKEN", token)
    print(f"AUTH_TOKEN atualizado com sucesso no arquivo {env_path}.")

def main():
    # Encontra o caminho do arquivo .env
    env_path = find_dotenv()

    # Se o .env não existir, cria um novo
    if not env_path:
        env_path = '.env'
        with open(env_path, 'w') as f:
            f.write("# Arquivo de variáveis de ambiente\n")
        print(f"Arquivo .env criado em {os.path.abspath(env_path)}.")
    else:
        print(f"Arquivo .env encontrado em {os.path.abspath(env_path)}.")

    # Gera um novo token
    token = generate_token()
    print(f"Token gerado: {token}")

    # Atualiza o arquivo .env com o novo token
    update_env(token, env_path)

if __name__ == "__main__":
    main()
