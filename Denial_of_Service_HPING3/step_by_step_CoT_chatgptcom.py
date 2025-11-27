import time
import subprocess
import threading

# Zmienna do śledzenia statusu ataku
attack_detected = False
attack_start_time = None
attack_end_time = None
packet_count = 0

# Funkcja do monitorowania pakietów
def monitor_packets():
    global attack_detected, attack_start_time, attack_end_time, packet_count
    
    # Uruchomienie tcpdump do monitorowania pakietów SYN
    process = subprocess.Popen(
        ['sudo', 'tcpdump', '-i', 'eth0', 'tcp[tcpflags] & tcp-syn != 0', '-l'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    while True:
        line = process.stdout.readline()
        if line:
            packet_count += 1
            if not attack_detected:
                attack_detected = True
                attack_start_time = time.time()
                print("Wykryto atak!")
        time.sleep(1)

# Funkcja do monitorowania ciągłości ataku
def check_attack_continuity():
    global attack_detected, attack_end_time, attack_start_time, packet_count
    
    while True:
        if attack_detected:
            # Monitorowanie końca ataku (np. brak pakietów przez 30 sekund)
            time.sleep(30)
            if packet_count == 0:
                attack_end_time = time.time()
                print(f"Atak zakończony. Czas rozpoczęcia: {attack_start_time}, Czas zakończenia: {attack_end_time}, Liczba pakietów: {packet_count}")
                attack_detected = False
                packet_count = 0
        else:
            print("Monitoruje...")
        time.sleep(1)

# Uruchomienie monitorowania pakietów w oddzielnym wątku
monitor_thread = threading.Thread(target=monitor_packets)
monitor_thread.daemon = True
monitor_thread.start()

# Uruchomienie funkcji sprawdzania ciągłości ataku w oddzielnym wątku
continuity_thread = threading.Thread(target=check_attack_continuity)
continuity_thread.daemon = True
continuity_thread.start()

# Utrzymywanie programu w działaniu
while True:
    time.sleep(1)
