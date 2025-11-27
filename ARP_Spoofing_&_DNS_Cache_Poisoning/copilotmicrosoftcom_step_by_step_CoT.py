import RPi.GPIO as GPIO
import time
from datetime import datetime
import socket

# Konfiguracja GPIO
GPIO.setmode(GPIO.BCM)
PIR_PIN = 18  # GPIO 1 to BCM 18
GPIO.setup(PIR_PIN, GPIO.IN)

# Konfiguracja sieci
TARGET_IP = "192.168.1.106"
TARGET_PORT = 5005  # Możesz zmienić na dowolny otwarty port

def send_message(message):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message.encode(), (TARGET_IP, TARGET_PORT))
    except Exception as e:
        print(f"Błąd wysyłania: {e}")

try:
    print("Monitoring ruchu rozpoczęty...")
    while True:
        motion = GPIO.input(PIR_PIN)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if motion:
            msg = f"{timestamp} - Wykryto ruch!"
        else:
            msg = f"{timestamp} - Brak ruchu"
        print(msg)
        send_message(msg)
        time.sleep(0.5)

except KeyboardInterrupt:
    print("Zatrzymano program.")

finally:
    GPIO.cleanup()
