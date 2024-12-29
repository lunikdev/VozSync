import subprocess
import sys
import platform
import os
import re

def get_pytorch_cuda_version():
    try:
        import torch
        cuda_available = torch.cuda.is_available()
        pytorch_cuda_version = torch.version.cuda
        cuda_device_count = torch.cuda.device_count()
        cuda_device_names = [torch.cuda.get_device_name(i) for i in range(cuda_device_count)] if cuda_available else []
        return {
            "cuda_available": cuda_available,
            "pytorch_cuda_version": pytorch_cuda_version,
            "cuda_device_count": cuda_device_count,
            "cuda_device_names": cuda_device_names
        }
    except ImportError:
        return {
            "error": "PyTorch não está instalado no ambiente."
        }

def get_nvcc_version():
    try:
        result = subprocess.run(['nvcc', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            output = result.stdout
            # Buscar a versão na saída
            match = re.search(r'release\s+(\d+\.\d+)', output)
            if match:
                return match.group(1)
            else:
                return "Não foi possível determinar a versão do nvcc."
        else:
            return "nvcc não está instalado ou não está no PATH."
    except FileNotFoundError:
        return "nvcc não está instalado ou não está no PATH."

def get_nvidia_smi_version():
    try:
        result = subprocess.run(['nvidia-smi'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            output = result.stdout
            # Buscar a versão do CUDA na saída
            match = re.search(r'CUDA Version:\s*(\d+\.\d+)', output)
            if match:
                return match.group(1)
            else:
                return "Não foi possível determinar a versão do CUDA através do nvidia-smi."
        else:
            return "nvidia-smi não está disponível."
    except FileNotFoundError:
        return "nvidia-smi não está instalado ou não está no PATH."

def get_system_cuda_version():
    system = platform.system()
    if system == "Windows":
        return get_cuda_version_windows()
    elif system == "Linux":
        return get_cuda_version_linux()
    else:
        return "Sistema operacional não suportado."

def get_cuda_version_linux():
    cuda_version = "Não encontrado"
    # Verificar o diretório padrão do CUDA
    cuda_path = "/usr/local/cuda/version.txt"
    if os.path.exists(cuda_path):
        try:
            with open(cuda_path, 'r') as f:
                content = f.read()
                match = re.search(r'CUDA Version (\d+\.\d+)', content)
                if match:
                    cuda_version = match.group(1)
        except Exception as e:
            cuda_version = f"Erro ao ler {cuda_path}: {e}"
    else:
        # Tentar outras formas, como consultar o link simbólico
        try:
            result = subprocess.run(['nvcc', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0:
                output = result.stdout
                match = re.search(r'release\s+(\d+\.\d+)', output)
                if match:
                    cuda_version = match.group(1)
        except:
            pass
    return cuda_version

def get_cuda_version_windows():
    cuda_version = "Não encontrado"
    # Verificar as variáveis de ambiente
    cuda_path = os.environ.get('CUDA_PATH', '')
    if cuda_path:
        version_txt = os.path.join(cuda_path, 'version.txt')
        if os.path.exists(version_txt):
            try:
                with open(version_txt, 'r') as f:
                    content = f.read()
                    match = re.search(r'CUDA Version (\d+\.\d+)', content)
                    if match:
                        cuda_version = match.group(1)
            except Exception as e:
                cuda_version = f"Erro ao ler {version_txt}: {e}"
    else:
        # Verificar programas instalados no Windows (pode ser complexo; alternativa: verificar diretórios padrão)
        default_paths = [
            "C:\\Program Files\\NVIDIA GPU Computing Toolkit\\CUDA\\v11.7\\version.txt",
            "C:\\Program Files\\NVIDIA GPU Computing Toolkit\\CUDA\\v11.8\\version.txt",
            "C:\\Program Files\\NVIDIA GPU Computing Toolkit\\CUDA\\v11.6\\version.txt",
            # Adicione mais versões conforme necessário
        ]
        for path in default_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        content = f.read()
                        match = re.search(r'CUDA Version (\d+\.\d+)', content)
                        if match:
                            cuda_version = match.group(1)
                            break
                except Exception as e:
                    cuda_version = f"Erro ao ler {path}: {e}"
    return cuda_version

def main():
    print("=== Verificação de Versão do CUDA ===\n")

    print("1. Verificando a versão do CUDA através do PyTorch...")
    pytorch_info = get_pytorch_cuda_version()
    if 'error' in pytorch_info:
        print(f"Erro: {pytorch_info['error']}")
    else:
        print(f"CUDA disponível no PyTorch: {pytorch_info['cuda_available']}")
        if pytorch_info['cuda_available']:
            print(f"Versão do CUDA utilizada pelo PyTorch: {pytorch_info['pytorch_cuda_version']}")
            print(f"Número de GPUs disponíveis: {pytorch_info['cuda_device_count']}")
            for idx, name in enumerate(pytorch_info['cuda_device_names']):
                print(f"  GPU {idx}: {name}")
        print()

    print("2. Verificando a versão do nvcc...")
    nvcc_version = get_nvcc_version()
    print(f"Versão do nvcc: {nvcc_version}\n")

    print("3. Verificando a versão do CUDA através do nvidia-smi...")
    nvidia_smi_cuda_version = get_nvidia_smi_version()
    print(f"Versão do CUDA via nvidia-smi: {nvidia_smi_cuda_version}\n")

    print("4. Verificando a versão do CUDA instalada no sistema...")
    system_cuda_version = get_system_cuda_version()
    print(f"Versão do CUDA instalada no sistema: {system_cuda_version}\n")

    print("=== Fim da Verificação ===")

if __name__ == "__main__":
    main()
