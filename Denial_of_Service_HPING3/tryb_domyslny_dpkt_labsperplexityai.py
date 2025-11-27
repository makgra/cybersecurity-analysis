#!/usr/bin/env python3
import time
import threading
import argparse
import socket
import fcntl
import struct
import dpkt
from collections import defaultdict
import select

# Konfiguracja
THRESHOLD = 100  # Próg wykrywania ataku (liczba pakietów/sekundę z jednego źródła)
MONITOR_INTERVAL = 1  # Interwał sprawdzania (sekundy)

def get_interface_ip(interface):
    """Pobiera adres IP przypisany do interfejsu sieciowego."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', interface[:15].encode())
        )[20:24])
        return ip
    except Exception as e:
        print(f"Błąd: Nie można pobrać adresu IP dla interfejsu {interface}: {e}")
        exit(1)

def packet_listener(interface, our_ip, counts, attack_lock, in_attack, total_packets_attack, running):
    """Odbiera i przetwarza pakiety w pętli przy użyciu DPKT."""
    # Utwórz surowe gniazdo do przechwytywania pakietów
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind((interface, 0x0003))
    
    while running[0]:
        # Użyj select do sprawdzenia dostępności danych z timeoutem (100ms)
        r, _, _ = select.select([sock], [], [], 0.1)
        if not r:
            continue
            
        data, _ = sock.recvfrom(65536)
        
        try:
            eth = dpkt.ethernet.Ethernet(data)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                dst_ip = socket.inet_ntoa(ip.dst)
                if dst_ip == our_ip and isinstance(ip.data, dpkt.tcp.TCP):
                    src_ip = socket.inet_ntoa(ip.src)
                    
                    # Aktualizuj licznik dla źródłowego IP
                    counts[src_ip] += 1
                    
                    # Aktualizuj licznik pakietów podczas ataku
                    with attack_lock:
                        if in_attack[0]:
                            total_packets_attack[0] += 1
        except Exception:
            continue

def main():
    parser = argparse.ArgumentParser(description='Detektor ataków hping3 na Raspberry Pi')
    parser.add_argument('--interface', required=True, help='Interfejs sieciowy (np. eth0)')
    args = parser.parse_args()
    
    # Pobierz adres IP interfejsu
    our_ip = get_interface_ip(args.interface)
    print(f"Monitorowanie interfejsu: {args.interface} (adres IP: {our_ip})")
    
    # Współdzielone zmienne
    counts = defaultdict(int)
    in_attack = [False]
    attack_start_time = [0]
    total_packets_attack = [0]
    attack_lock = threading.Lock()
    running = [True]  # Flaga kontrolująca działanie wątku
    
    # Uruchom wątek nasłuchujący pakiety
    listener_thread = threading.Thread(
        target=packet_listener,
        args=(args.interface, our_ip, counts, attack_lock, in_attack, total_packets_attack, running),
        daemon=True
    )
    listener_thread.start()
    
    print("Rozpoczęto monitorowanie...")
    try:
        while True:
            time.sleep(MONITOR_INTERVAL)
            current_counts = counts.copy()
            counts.clear()  # Resetuj licznik dla nowej sekundy
            
            max_packets = max(current_counts.values()) if current_counts else 0
            
            with attack_lock:
                if in_attack[0]:
                    if max_packets < THRESHOLD:
                        # Koniec ataku
                        attack_end_time = time.time()
                        duration = attack_end_time - attack_start_time[0]
                        print("\nAtak zakończony!")
                        print(f"Czas rozpoczęcia: {time.ctime(attack_start_time[0])}")
                        print(f"Czas zakończenia: {time.ctime(attack_end_time)}")
                        print(f"Łączna liczba pakietów: {total_packets_attack[0]}")
                        in_attack[0] = False
                else:
                    if max_packets >= THRESHOLD:
                        # Rozpoczęcie ataku
                        in_attack[0] = True
                        attack_start_time[0] = time.time()
                        total_packets_attack[0] = sum(current_counts.values())
                        print("\nWykryto atak!")
                    else:
                        print("Monitoruje...", end='\r', flush=True)
    except KeyboardInterrupt:
        running[0] = False  # Zatrzymaj wątek nasłuchujący
        listener_thread.join(timeout=2.0)
        print("\nZatrzymano monitorowanie.")

if __name__ == "__main__":
    main()
