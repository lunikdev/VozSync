import asyncio
import websockets
import pyaudio
import wave
import json
import base64
import keyboard
import threading
import time
from datetime import datetime
import io
import numpy as np
import collections
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv, find_dotenv
import noisereduce as nr  # Importing noise reduction library
from pydub import AudioSegment  # Importing audio processing library

class AudioServer:
    def __init__(self, host="0.0.0.0", port=9024):
        self.host = host
        self.port = port
        self.clients = {}
        self.running = True
        self.muted = False  # Mute state
        # Buffer for 0.5 seconds of audio
        self.audio_buffer = collections.deque(maxlen=int((16000 // 1024) * 0.5))
        self.long_term_noise_level = 0.0
        self.current_noise_level = 0.0
        self.ambient_noise_level = 0.0
        self.voice_activity_detected = False
        self.frames = []
        self.executor = ThreadPoolExecutor(max_workers=2)  # Executor for blocking operations
        self.setup_audio()

    def setup_audio(self):
        try:
            self.audio = pyaudio.PyAudio()
            self.chunk_size = 1024
            self.format = pyaudio.paInt16
            self.channels = 1
            self.rate = 16000  # Sample rate (Hz)
            self.record_seconds = 1  # Recording time per chunk

            print(f"[{self.get_timestamp()}] Audio Configuration:")
            print(f"Sample Rate: {self.rate} Hz")
            print(f"Channels: {self.channels}")
            print(f"Format: 16-bit PCM")
        except Exception as e:
            print(f"[{self.get_timestamp()}] Error setting up audio: {e}")

    def get_timestamp(self):
        return datetime.now().strftime("%H:%M:%S")

    def get_levels(self, data):
        """Calculates the volume level of the audio."""
        pegel = np.abs(np.frombuffer(data, dtype=np.int16)).mean()
        self.long_term_noise_level = self.long_term_noise_level * 0.995 + pegel * (1.0 - 0.995)
        self.current_noise_level = self.current_noise_level * 0.920 + pegel * (1.0 - 0.920)
        return pegel

    async def register(self, websocket, path=None):
        client_info = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
        print(f"[{self.get_timestamp()}] New connection from {client_info}")

        self.clients[client_info] = {
            'websocket': websocket,
            'last_ping': time.time()
        }

        try:
            async for message in websocket:
                await self.handle_message(message, client_info)
        except websockets.exceptions.ConnectionClosed as e:
            print(f"[{self.get_timestamp()}] Client {client_info} disconnected: {e}")
        except Exception as e:
            print(f"[{self.get_timestamp()}] Error with client {client_info}: {e}")
        finally:
            if client_info in self.clients:
                del self.clients[client_info]
            print(f"[{self.get_timestamp()}] Client {client_info} removed from connection list")

    async def handle_message(self, message, client_info):
        """Processes messages received from clients."""
        try:
            data = json.loads(message)
            message_type = data.get("type", "unknown")
            if message_type == "transcription":
                transcription = data.get("text", "")
                timestamp = data.get("timestamp", self.get_timestamp())
                print(f"[{timestamp}] Transcription received from {client_info}: {transcription}")
                # Here you can add logic to process the transcription, like saving to a file, etc.
            else:
                print(f"[{self.get_timestamp()}] Unknown message type from {client_info}: {message_type}")
        except json.JSONDecodeError as e:
            print(f"[{self.get_timestamp()}] Error decoding message from {client_info}: {e}")
        except Exception as e:
            print(f"[{self.get_timestamp()}] Error processing message from {client_info}: {e}")

    async def broadcast_audio(self):
        """Broadcasts audio to clients based on voice activity detection."""
        try:
            stream = self.audio.open(
                format=self.format,
                channels=self.channels,
                rate=self.rate,
                input=True,
                frames_per_buffer=self.chunk_size
            )
            print(f"[{self.get_timestamp()}] Starting audio capture...")

            loop = asyncio.get_event_loop()

            while self.running:
                if self.muted:
                    await asyncio.sleep(0.1)  # Brief pause when muted
                    continue

                try:
                    # Read audio data in a non-blocking way
                    data = await loop.run_in_executor(
                        self.executor,
                        lambda: stream.read(self.chunk_size, exception_on_overflow=False)
                    )
                    if not data:
                        continue

                    pegel = self.get_levels(data)
                    self.audio_buffer.append(data)

                    # Define threshold for voice activity detection
                    voice_threshold = self.long_term_noise_level + 300  # Adjust as needed

                    if self.voice_activity_detected:
                        self.frames.append(data)
                        if self.current_noise_level < self.ambient_noise_level + 100:
                            # End of voice activity
                            audio_bytes = b''.join(self.frames)
                            if len(audio_bytes) > 0:
                                print(f"[{self.get_timestamp()}] Speech segment ended, sending to clients.")
                                # Apply noise reduction and normalization before sending
                                processed_audio = self.process_audio(audio_bytes)
                                await self.send_audio_to_clients(processed_audio)
                            self.frames = []
                            self.voice_activity_detected = False
                    else:
                        if self.current_noise_level > voice_threshold:
                            print(f"[{self.get_timestamp()}] Voice detected!")
                            self.voice_activity_detected = True
                            self.ambient_noise_level = self.long_term_noise_level
                            self.frames = list(self.audio_buffer)

                except Exception as e:
                    print(f"[{self.get_timestamp()}] Error capturing audio: {e}")
                    break

        except Exception as e:
            print(f"[{self.get_timestamp()}] Error in broadcast_audio: {e}")
        finally:
            try:
                stream.stop_stream()
                stream.close()
            except Exception as e:
                print(f"[{self.get_timestamp()}] Error closing stream: {e}")
            print(f"[{self.get_timestamp()}] Audio capture stopped.")
            await self.send_complete_audio()

    def process_audio(self, audio_bytes):
        """Applies noise reduction and normalization to the audio."""
        try:
            # Convert bytes to numpy array
            audio_np = np.frombuffer(audio_bytes, dtype=np.int16).astype(np.float32)

            # Apply noise reduction
            reduced_noise = nr.reduce_noise(y=audio_np, sr=self.rate)

            # Normalize audio to prevent clipping
            normalized_audio = np.int16(reduced_noise / np.max(np.abs(reduced_noise)) * 32767)

            # Convert back to bytes
            processed_bytes = normalized_audio.tobytes()

            return processed_bytes
        except Exception as e:
            print(f"[{self.get_timestamp()}] Error processing audio: {e}")
            return audio_bytes  # Return original if processing fails

    async def send_audio_to_clients(self, audio_bytes):
        """Sends audio data to all connected clients."""
        wav_data = self.create_wav_from_bytes(audio_bytes)
        if wav_data:
            message = {
                "type": "complete_audio",
                "timestamp": self.get_timestamp(),
                "audio_data": base64.b64encode(wav_data).decode('utf-8'),
                "format": "wav",
                "duration": len(audio_bytes) / (self.rate * self.channels * 2)  # Approximate duration
            }

            disconnected_clients = []
            for client_info, client_data in list(self.clients.items()):
                try:
                    await client_data['websocket'].send(json.dumps(message))
                    print(f"[{self.get_timestamp()}] Audio sent to {client_info}")
                except Exception as e:
                    print(f"[{self.get_timestamp()}] Error sending to {client_info}: {e}")
                    disconnected_clients.append(client_info)

            # Remove disconnected clients
            for client_info in disconnected_clients:
                del self.clients[client_info]

    def create_wav_from_bytes(self, audio_bytes):
        """Creates a WAV file from audio bytes."""
        try:
            wav_buffer = io.BytesIO()
            with wave.open(wav_buffer, 'wb') as wf:
                wf.setnchannels(self.channels)
                wf.setsampwidth(self.audio.get_sample_size(self.format))
                wf.setframerate(self.rate)
                wf.writeframes(audio_bytes)
            return wav_buffer.getvalue()
        except Exception as e:
            print(f"[{self.get_timestamp()}] Error creating WAV: {e}")
            return None

    async def send_complete_audio(self):
        """Sends any remaining audio in the buffer upon shutdown."""
        if self.frames:
            audio_bytes = b''.join(self.frames)
            if len(audio_bytes) > 0:
                print(f"[{self.get_timestamp()}] Sending final audio segment.")
                # Apply noise reduction and normalization before sending
                processed_audio = self.process_audio(audio_bytes)
                await self.send_audio_to_clients(processed_audio)

    def handle_keyboard(self):
        """Manages keyboard inputs to shut down the server and toggle mute."""
        def check_keys():
            last_toggle_time = 0
            toggle_cooldown = 0.5  # Seconds to prevent rapid toggles

            while self.running:
                if keyboard.is_pressed('q'):
                    print(f"[{self.get_timestamp()}] Shutting down server...")
                    self.running = False
                    break
                elif keyboard.is_pressed('k'):
                    current_time = time.time()
                    if current_time - last_toggle_time > toggle_cooldown:
                        self.muted = not self.muted
                        status = "Muted" if self.muted else "Active"
                        print(f"[{self.get_timestamp()}] Mute state changed to: {status}")
                        last_toggle_time = current_time
                time.sleep(0.1)

        keyboard_thread = threading.Thread(target=check_keys)
        keyboard_thread.daemon = True
        keyboard_thread.start()

    def cleanup(self):
        if self.audio:
            self.audio.terminate()
        print(f"[{self.get_timestamp()}] Server shutdown complete.")

    async def start_server(self):
        self.handle_keyboard()

        try:
            async with websockets.serve(
                self.register,
                self.host,
                self.port,
                ping_interval=None,
                max_size=20 * 1024 * 1024
            ) as server:
                print(f"[{self.get_timestamp()}] Server started at ws://{self.host}:{self.port}")
                print(f"[{self.get_timestamp()}] Press 'q' to shut down the server.")
                print(f"[{self.get_timestamp()}] Press 'k' to toggle microphone mute.")

                # Start the audio broadcast task
                broadcast_task = asyncio.create_task(self.broadcast_audio())

                # Wait until the server is running and the broadcast is complete
                await asyncio.gather(server.wait_closed(), broadcast_task)
        except Exception as e:
            print(f"[{self.get_timestamp()}] Error in start_server: {e}")
        finally:
            self.cleanup()

if __name__ == "__main__":
    server = AudioServer()

    try:
        asyncio.run(server.start_server())
    except KeyboardInterrupt:
        print("\nShutting down server...")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        server.running = False
        server.cleanup()
