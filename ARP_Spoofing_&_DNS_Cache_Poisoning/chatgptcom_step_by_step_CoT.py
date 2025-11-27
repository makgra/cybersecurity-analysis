import RPi.GPIO as GPIO
import time
import socket
from datetime import datetime

# Ustawienia GPIO
GPIO.setmode(GPIO.BCM)  # Używamy numeracji pinów GPIO
GPIO.setup(1, GPIO.IN)  # Ustawiamy pin GPIO 1 jako wejście

# Ustawienia dla socketu
server_ip = '192.168.1.106'
server_port = 12345  # Możemy ustalić port (np. 12345)

def send_message(message):
    """Funkcja do wysyłania komunikatów na adres IP serwera"""
    try:
        # Tworzymy gniazdo (socket)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_ip, server_port))
            s.sendall(message.encode())  # Wysyłamy wiadomość
    except Exception as e:
        print(f"Nie udało się wysłać komunikatu: {e}")

def display_message(message):
    """Funkcja do wyświetlania komunikatu na ekranie z datą i godziną"""
    # Pobieramy bieżącą datę i godzinę
    now = datetime.now()
    current_time = now.strftime("%Y-%m-%d %H:%M:%S")
    
    # Wyświetlamy komunikat z datą i godziną
    print(f"{current_time} - {message}")

try:
    while True:
        # Odczytujemy stan czujnika
        motion_detected = GPIO.input(1)

        # Sprawdzamy, czy wykryto ruch
        if motion_detected:
            message = "Wykryto ruch!"
        else:
            message = "Brak ruchu"

        # Wyświetlamy komunikat na ekranie
        display_message(message)

        # Wysyłamy komunikat do serwera
        send_message(message)

        # Czekamy chwilę, aby nie przeciążyć CPU
        time.sleep(1)

except KeyboardInterrupt:
    print("Program zakończony.")
finally:
    GPIO.cleanup()  # Zwalniamy zasoby GPIO po zakończeniu programu
