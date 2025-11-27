#!/usr/bin/env python3
import socket
import select
import time
import argparse
import fcntl
import struct
from datetime import datetime
from collections import defaultdict

# Konfiguracja progów i stabilizacji
THRESHOLD_START = 800         # pakiety/sekunda, próg rozpoczęcia
THRESHOLD_END = 500           # pakiety/sekunda, próg zakończenia (niższy)
START_CONSECUTIVE = 3         # ile kolejnych sekund >= THRESHOLD_START aby uznać start
END_CONSECUTIVE = 3           # ile kolejnych sekund < THRESHOLD_END aby uznać koniec

# Interwały
POLL_TIMEOUT = 0.1            # select timeout w sekundach (100ms)
WINDOW_SECONDS = 1.0          # długość okna agregacji

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

def decode_ipv4_addresses(frame: bytes):
    """Zwraca (src_ip_str, dst_ip_str) dla ramek IPv4; inaczej None."""
    # Nagłówek Ethernet: 14 bajtów: [dst_mac(6)] [src_mac(6)] [ethertype(2)]
    if len(frame) < 14:
        return None
    ethertype = int.from_bytes(frame[12:14], "big")
    if ethertype != 0x0800:  # IPv4
        return None

    # Nagłówek IP: co najmniej 20 bajtów
    ip_offset = 14
    if len(frame) < ip_offset + 20:
        return None

    # Wersja/IHL
    ver_ihl = frame[ip_offset]
    version = ver_ihl >> 4
    if version != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if len(frame) < ip_offset + ihl:
        return None

    # Pobierz adresy źródłowy i docelowy (bajty 12–15, 16–19 względem nagłówka IP)
    src = frame[ip_offset + 12: ip_offset + 16]
    dst = frame[ip_offset + 16: ip_offset + 20]
    src_ip = socket.inet_ntoa(src)
    dst_ip = socket.inet_ntoa(dst)
    return src_ip, dst_ip

def main():
    parser = argparse.ArgumentParser(description="Detekcja hping3 per-IP z histerezą (Raspberry Pi)")
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
                    addrs = decode_ipv4_addresses(frame)
                    if addrs:
                        src_ip, dst_ip = addrs
                        # Zliczaj tylko pakiety do naszego IP
                        if dst_ip == our_ip:
                            state = ip_states[src_ip]
                            state.current_window_count += 1

            # Czy minęło okno sekundowe?
            now = time.time()
            if now - last_window_ts >= WINDOW_SECONDS:
                last_window_ts = now

                any_attack_active = False

                # Przetwarzanie okna dla każdego IP
                for src_ip, state in list(ip_states.items()):
                    pps = state.current_window_count  # pakiety/sek dla tego IP
                    # Reset dla kolejnego okna
                    state.current_window_count = 0

                    # Aktualizacja liczników histerezy
                    if pps >= THRESHOLD_START:
                        state.consec_high += 1
                        state.consec_low = 0
                    elif pps < THRESHOLD_END:
                        state.consec_low += 1
                        state.consec_high = 0
                    else:
                        # Strefa przejściowa nie zwiększa liczników
                        # (utrzymuje bieżące wartości, co dodatkowo stabilizuje stan)
                        pass

                    # Logika start/koniec ataku dla tego IP
                    if not state.attack_active:
                        if state.consec_high >= START_CONSECUTIVE:
                            state.attack_active = True
                            state.start_dt = datetime.now()
                            state.total_packets = 0
                            state.consec_high = 0
                            print(f"Wykryto atak! Źródło: {src_ip}")
                        else:
                            # brak ataku dla tego IP – nic nie wypisujemy tutaj, globalny status poniżej
                            pass
                    else:
                        # Atak trwa: sumuj pakiety z każdej sekundy
                        state.total_packets += pps

                        if state.consec_low >= END_CONSECUTIVE:
                            end_dt = datetime.now()
                            print("Atak zakończony.")
                            print(f"Źródło: {src_ip}")
                            print(f"Czas rozpoczęcia: {state.start_dt.strftime('%Y-%m-%d %H:%M:%S')}")
                            print(f"Czas zakończenia:  {end_dt.strftime('%Y-%m-%d %H:%M:%S')}")
                            print(f"Łączna liczba pakietów: {state.total_packets}")
                            # Reset stanu
                            state.attack_active = False
                            state.start_dt = None
                            state.total_packets = 0
                            state.consec_low = 0

                    # Sprawdzenie globalnego statusu (czy jakikolwiek atak jest aktywny)
                    if state.attack_active:
                        any_attack_active = True

                # Globalne „Monitoruje…” gdy żaden IP nie jest w stanie ataku
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
