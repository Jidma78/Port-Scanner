import socket
import threading
import ipaddress
import datetime


open_ports = []
lock = threading.Lock()

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def scan_port(ip, port, verbose=False):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as scan:
            scan.settimeout(0.5)
            result = scan.connect_ex((ip, port))
            if result == 0:
                with lock:
                    open_ports.append((ip, port))
                    if verbose:
                        print(f"[+] Port ouvert {port} sur {ip}")
            elif verbose:
                print(f"[-] Port fermé {port} sur {ip}")
    except Exception:
        pass

def save_results(filename="result.log"):
    with open(filename, "a") as f:
        f.write(f"\n=== Résultats du scan : {datetime.datetime.now()} ===\n")
        for ip, port in sorted(open_ports):
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "Service inconnu"
            f.write(f"{ip}:{port} -> {service}\n")
        f.write("=== Fin du scan ===\n\n")

def scan_ip(ip, start_port, end_port, verbose):
    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(ip, port, verbose))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

def main():
    print("=== Scanner de Ports Multi-IP ===\n")
    mode = input("Scanner une seule IP ou un fichier d'IPs ? (ip/fichier) > ").strip().lower()

    ip_list = []
    if mode == "ip":
        ip = input("Quelle IP voulez-vous scanner ? > ").strip()
        while not is_valid_ip(ip):
            print("Adresse IP invalide. Réessayez.")
            ip = input("> ").strip()
        ip_list.append(ip)
    elif mode == "fichier":
        file_path = input("Entrez le nom du fichier (ex: ips.txt) > ").strip()
        try:
            with open(file_path, "r") as f:
                for line in f:
                    ip = line.strip()
                    if is_valid_ip(ip):
                        ip_list.append(ip)
        except FileNotFoundError:
            print(f"Fichier introuvable : {file_path}")
            return
    else:
        print("Option invalide.")
        return

    try:
        port_range = input("Entrez la plage de ports (ex: 1-1000): > ")
        start_port, end_port = map(int, port_range.strip().split("-"))
        if start_port < 0 or end_port > 65535 or start_port > end_port:
            raise ValueError
    except ValueError:
        print("Plage invalide. Utilisez le format 'début-fin'.")
        return

    verbose = input("Mode verbose ? (y/n) > ").strip().lower() == "y"

    for ip in ip_list:
        print(f"\n--- Scan de {ip} ---")
        scan_ip(ip, start_port, end_port, verbose)

    if open_ports:
        print("\nPorts ouverts trouvés :")
        for ip, port in sorted(open_ports):
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "Service inconnu"
            print(f"{ip}:{port} -> {service}")
    else:
        print( "Aucun port ouvert trouvé.")

    save_results()
    print("\nRésultats sauvegardés dans 'result.log'.")

if __name__ == "__main__":
    main()
