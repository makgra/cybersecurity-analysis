import RPi.GPIO as GPIO
from datetime import datetime
import time
import socket
import threading

# Konfiguracja pinu GPIO
GPIO.setmode(GPIO.BCM)
PIR_PIN = 18  # Dostosuj numer pinu (BCM) zgodnie z podłączeniem
GPIO.setup(PIR_PIN, GPIO.IN)

# Konfiguracja UDP
UDP_IP = "192.168.1.106"
UDP_PORT = 5005
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Zmienne globalne z zabezpieczeniem wątkowym
motion_detected = False
lock = threading.Lock()

def motion_callback(channel):
    global motion_detected
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with lock:
        if GPIO.input(channel):
            # Wykryto ruch (HIGH)
            motion_detected = True
            message = f"{current_time} Wykryto ruch!"
        else:
            # Brak ruchu (LOW)
            motion_detected = False
            message = f"{current_time} brak ruchu"
    
    print(message)
    try:
        sock.sendto(message.encode(), (UDP_IP, UDP_PORT))
    except Exception as e:
        print(f"Błąd przy wysyłaniu wiadomości: {e}")

# Rejestracja przerwania
GPIO.add_event_detect(PIR_PIN, GPIO.BOTH, callback=motion_callback, bouncetime=200)

try:
    while True:
        with lock:
            current_state = motion_detected
            
        if not current_state:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            message = f"{current_time} brak ruchu"
            print(message)
            try:
                sock.sendto(message.encode(), (UDP_IP, UDP_PORT))
            except Exception as e:
                print(f"Błąd przy wysyłaniu wiadomości: {e}")
        
        time.sleep(1)

except KeyboardInterrupt:
    print("Zamykanie programu...")
    GPIO.cleanup()
    sock.close()
