# VozSync

This project is divided into two parts: one running on the user's machine and the other that can run in the cloud or locally. The user can send audio from their microphone to the cloud-based machine, which transcribes the audio and returns the transcribed text.

---

## Installation

To install the project, follow these steps:

1. **Create and activate a virtual environment**:
```bash
python -m venv venv
```

2. **Activate the virtual environment**:
```bash
.\venv\Scripts\activate
```
or on Linux/Mac:
```bash
source venv/bin/activate
```

3. **Install required packages**:
```bash
pip install -r requirements.txt
```

**Note**: Installing dependencies without a virtual environment is not recommended.

---

## Token System

To ensure secure communication between the client and server, the project uses a token-based authentication system. The token is stored in the `.env` file and is validated on both the server and client sides.

### Generating and Updating the Token

A Python script (`generate_token.py`) is available to generate and update the token directly in the `.env` file. Run the following command:

```bash
python generate_token.py
```

This will generate a new token and automatically update it in the `.env` file.

### Verifying the Token

The server and client validate the token during the connection. Ensure that the token in the `.env` file is the same on both sides.

---

## CUDA Support

CPU support is native and requires no additional installation. However, if you want to accelerate processing using CUDA cores, you need to install the compatible version of PyTorch with CUDA. You can find the appropriate version for your system on the [PyTorch Get Started page](https://pytorch.org/get-started/locally/).

### Installation Commands

**Windows**:
```bash
pip3 install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124
```

**Linux**:
```bash
pip3 install torch torchvision torchaudio
```

### Checking CUDA Version

Before installing PyTorch, you can verify your current CUDA version using the provided `check_cuda_version.py` script. Run the following command:

```bash
python check_cuda_version.py
```

This will help you determine the correct CUDA version to install from the PyTorch website.

---

## Easy Setup (In Development)

We are developing an `easy setup` system to simplify project configuration for end users. This system will automate dependency installation, token configuration, and environment setup. Stay tuned for updates!

---

### Usage Example

#### Server
To start the server, run:
```bash
python server.py
```

#### Client
To start the client, run:
```bash
python client.py
```

#### Client on Google Colab
To run the client on Google Colab, use the `Whisper.ipynb` script and follow the instructions in the notebook.

---

## Dependencies

This project uses Whisper from OpenAI, licensed under the MIT License.

---

## License

This project is licensed under the MIT License.

---

## Contact

Developed by Leandro Gonçalves. For more information:

* Email: contato@znix.com.br
* GitHub: github.com/lunikdev

---

This project is constantly evolving. Contributions and suggestions are welcome! 🚀

---
