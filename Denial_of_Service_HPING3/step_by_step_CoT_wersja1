import time
from datetime import datetime

# Ścieżka do statystyk interfejsu sieciowego
INTERFACE = "eth0"  # lub wlan0, jeśli używasz Wi-Fi
THRESHOLD = 1000    # próg pakietów na sekundę uznany za atak

def get_rx_packets():
    with open("/proc/net/dev", "r") as f:
        for line in f:
            if INTERFACE in line:
                data = line.split(f"{INTERFACE}:")[1].split()
                return int(data[1])  # liczba bajtów odebranych
    return 0

def main():
    print("Rozpoczynam monitoring...")
    prev_packets = get_rx_packets()
    attack = False
    attack_start = None
    total_packets = 0

    while True:
        time.sleep(1)
        current_packets = get_rx_packets()
        delta = current_packets - prev_packets
        prev_packets = current_packets

        if delta > THRESHOLD:
            if not attack:
                attack = True
                attack_start = datetime.now()
                total_packets = 0
                print("⚠️ Wykryto atak!")
            total_packets += delta
        else:
            if attack:
                attack_end = datetime.now()
                duration = (attack_end - attack_start).total_seconds()
                print("✅ Atak zakończony.")
                print(f"⏱️ Czas trwania: {attack_start.strftime('%H:%M:%S')} – {attack_end.strftime('%H:%M:%S')}")
                print(f"📦 Odebrano pakietów: {total_packets}")
                attack = False
            else:
                print("Monitoruje...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nZatrzymano monitoring.")
