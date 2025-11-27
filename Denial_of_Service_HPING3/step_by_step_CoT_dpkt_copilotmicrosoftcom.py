#!/usr/bin/env python3
import socket
import select
import time
import argparse
import fcntl
import struct
from datetime import datetime
from collections import defaultdict

import dpkt  # pip install dpkt

# Konfiguracja progów i stabilizacji
THRESHOLD_START = 800         # pakiety/sekunda, próg rozpoczęcia
THRESHOLD_END = 500           # pakiety/sekunda, próg zakończenia (niższy)
START_CONSECUTIVE = 3         # ile kolejnych sekund >= THRESHOLD_START aby uznać start
END_CONSECUTIVE = 3           # ile kolejnych sekund < THRESHOLD_END aby uznać koniec

# Interwały
POLL_TIMEOUT = 0.1            # select timeout w sekundach (100ms)
WINDOW_SECONDS = 1.0          # długość okna agregacji (sekundy)

def get_interface_ip(interface: str) -> str:
    """Pobiera adres IPv4 przypisany do interfejsu sieciowego."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ip = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(), 0x8915,  # SIOCGIFADDR
            struct.pack('256s', interface[:15].encode())
        )[20:24])
        return ip
    finally:
        s.close()

def create_raw_socket(interface: str) -> socket.socket:
    """Tworzy surowe gniazdo do przechwytywania wszystkich ramek na interfejsie."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind((interface, 0))
    return sock

class IpAttackState:
    """Stan detekcji ataku dla jednego źródłowego IP."""
    __slots__ = (
        "attack_active", "start_dt", "total_packets",
        "consec_high", "consec_low",
        "current_window_count"
    )
    def __init__(self):
        self.attack_active = False
        self.start_dt = None
        self.total_packets = 0
        self.consec_high = 0
        self.consec_low = 0
        self.current_window_count = 0

def process_frame(frame: bytes):
    """
    Dekoduje ramkę Ethernet -> IP przy użyciu DPKT.
    Zwraca (src_ip_str, dst_ip_str) dla IPv4; inaczej None.
    """
    try:
        eth = dpkt.ethernet.Ethernet(frame)
        ip = eth.data
        if isinstance(ip, dpkt.ip.IP):
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            return src_ip, dst_ip
    except Exception:
        return None
    return None

def main():
    parser = argparse.ArgumentParser(description="Detekcja hping3 per-IP (DPKT + histereza)")
    parser.add_argument("--interface", required=True, help="Interfejs sieciowy (np. eth0, wlan0)")
    args = parser.parse_args()

    try:
        our_ip = get_interface_ip(args.interface)
    except Exception as e:
        print(f"Błąd pobierania IP interfejsu {args.interface}: {e}")
        return

    try:
        sock = create_raw_socket(args.interface)
    except Exception as e:
        print(f"Błąd tworzenia RAW socket: {e}")
        return

    print(f"Monitorowanie interfejsu: {args.interface} (IP: {our_ip})")
    ip_states = defaultdict(IpAttackState)

    last_window_ts = time.time()

    try:
        while True:
            # Odbiór ramek z select (nieblokująco z timeoutem)
            rlist, _, _ = select.select([sock], [], [], POLL_TIMEOUT)
            if rlist:
                try:
                    frame, _ = sock.recvfrom(65536)
                except Exception:
                    frame = None
                if frame:
                    addrs = process_frame(frame)
                    if addrs:
                        src_ip, dst_ip = addrs
                        # Zliczaj tylko pakiety do naszego IP
                        if dst_ip == our_ip:
                            state = ip_states[src_ip]
                            state.current_window_count += 1

            # Co sekundę: przetwarzanie okna i aktualizacja stanu dla każdego IP
            now = time.time()
            if now - last_window_ts >= WINDOW_SECONDS:
                last_window_ts = now

                any_attack_active = False

                for src_ip, state in list(ip_states.items()):
                    pps = state.current_window_count  # pakiety/sek dla tego IP
                    state.current_window_count = 0

                    # Histereza: aktualizacja liczników stabilizacji
                    if pps >= THRESHOLD_START:
                        state.consec_high += 1
                        state.consec_low = 0
                    elif pps < THRESHOLD_END:
                        state.consec_low += 1
                        state.consec_high = 0
                    else:
                        # Strefa przejściowa – nie zwiększamy liczników, utrzymujemy dotychczasowe
                        pass

                    # Start/koniec ataku
                    if not state.attack_active:
                        if state.consec_high >= START_CONSECUTIVE:
                            state.attack_active = True
                            state.start_dt = datetime.now()
                            state.total_packets = 0
                            state.consec_high = 0
                            print(f"Wykryto atak! Źródło: {src_ip}")
                        # brak else – czekamy na spełnienie warunku startu
                    else:
                        # Atak trwa – sumuj pakiety
                        state.total_packets += pps

                        if state.consec_low >= END_CONSECUTIVE:
                            end_dt = datetime.now()
                            print("Atak zakończony.")
                            print(f"Źródło: {src_ip}")
                            print(f"Czas rozpoczęcia: {state.start_dt.strftime('%Y-%m-%d %H:%M:%S')}")
                            print(f"Czas zakończenia:  {end_dt.strftime('%Y-%m-%d %H:%M:%S')}")
                            print(f"Łączna liczba pakietów: {state.total_packets}")
                            # Reset stanu dla tego IP
                            state.attack_active = False
                            state.start_dt = None
                            state.total_packets = 0
                            state.consec_low = 0

                    if state.attack_active:
                        any_attack_active = True

                if not any_attack_active:
                    print("Monitoruje...")

    except KeyboardInterrupt:
        print("\nZatrzymano monitoring.")
    finally:
        try:
            sock.close()
        except Exception:
            pass

if __name__ == "__main__":
    main()
