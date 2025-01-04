# configs/modules/audio_processor.py

import pyaudio
import wave
import io
import numpy as np
import noisereduce as nr
import collections
from datetime import datetime

class AudioProcessor:
    def __init__(self):
        self.audio = None
        self.chunk_size = 1024
        self.format = pyaudio.paInt16
        self.channels = 1
        self.rate = 16000  # Taxa de amostragem (Hz)
        self.record_seconds = 1  # Tempo de gravação por chunk
        
        # Buffers e estados de áudio
        self.audio_buffer = collections.deque(maxlen=int((16000 / 1024) * 0.5))
        self.long_term_noise_level = 0.0
        self.current_noise_level = 0.0
        self.ambient_noise_level = 0.0
        self.voice_activity_detected = False
        self.frames = []
        
        self.setup_audio()

    def get_timestamp(self):
        return datetime.now().strftime("%H:%M:%S")

    def setup_audio(self):
        """Configura o sistema de áudio."""
        try:
            self.audio = pyaudio.PyAudio()
            print(f"[{self.get_timestamp()}] Configuração de Áudio:")
            print(f"Taxa de Amostragem: {self.rate} Hz")
            print(f"Canais: {self.channels}")
            print(f"Formato: PCM 16-bit")
        except Exception as e:
            print(f"[{self.get_timestamp()}] Erro ao configurar áudio: {e}")

    def get_audio_stream(self):
        """Retorna um novo stream de áudio configurado."""
        return self.audio.open(
            format=self.format,
            channels=self.channels,
            rate=self.rate,
            input=True,
            frames_per_buffer=self.chunk_size
        )

    def get_levels(self, data):
        """Calcula o nível de volume do áudio."""
        pegel = np.abs(np.frombuffer(data, dtype=np.int16)).mean()
        self.long_term_noise_level = self.long_term_noise_level * 0.995 + pegel * (1.0 - 0.995)
        self.current_noise_level = self.current_noise_level * 0.920 + pegel * (1.0 - 0.920)
        return pegel

    def process_audio(self, audio_bytes):
        """Aplica redução de ruído e normalização no áudio."""
        try:
            audio_np = np.frombuffer(audio_bytes, dtype=np.int16).astype(np.float32)
            reduced_noise = nr.reduce_noise(y=audio_np, sr=self.rate)

            if np.max(np.abs(reduced_noise)) == 0:
                normalized_audio = reduced_noise
            else:
                normalized_audio = reduced_noise / np.max(np.abs(reduced_noise)) * 32767

            normalized_audio = np.int16(normalized_audio)
            processed_bytes = normalized_audio.tobytes()

            return processed_bytes
        except Exception as e:
            print(f"[{self.get_timestamp()}] Erro ao processar áudio: {e}")
            return audio_bytes

    def create_wav_from_bytes(self, audio_bytes):
        """Cria um arquivo WAV a partir de bytes de áudio."""
        try:
            wav_buffer = io.BytesIO()
            with wave.open(wav_buffer, 'wb') as wf:
                wf.setnchannels(self.channels)
                wf.setsampwidth(self.audio.get_sample_size(self.format))
                wf.setframerate(self.rate)
                wf.writeframes(audio_bytes)
            return wav_buffer.getvalue()
        except Exception as e:
            print(f"[{self.get_timestamp()}] Erro ao criar WAV: {e}")
            return None

    def reset_audio_state(self):
        """Reseta os buffers e estados de áudio."""
        self.frames = []
        self.audio_buffer.clear()
        self.voice_activity_detected = False
        self.ambient_noise_level = 0.0
        self.long_term_noise_level = 0.0
        self.current_noise_level = 0.0
        print(f"[{self.get_timestamp()}] Estado de áudio resetado.")

    def add_to_buffer(self, data):
        """Adiciona dados ao buffer de áudio."""
        self.audio_buffer.append(data)

    def append_frame(self, data):
        """Adiciona um frame aos frames de áudio."""
        self.frames.append(data)

    def get_frames_as_bytes(self):
        """Retorna os frames combinados como bytes."""
        return b''.join(self.frames)

    def get_buffer_as_list(self):
        """Retorna o buffer como uma lista."""
        return list(self.audio_buffer)

    def cleanup(self):
        """Limpa os recursos de áudio."""
        if self.audio:
            self.audio.terminate()
        print(f"[{self.get_timestamp()}] Recursos de áudio liberados.")