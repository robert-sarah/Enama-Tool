# Levi Kali WiFi Tool

![Levi Kali WiFi Tool](https://img.shields.io/badge/Tool-Kali_WiFi-green)

**Auteur :** Enama Eyenoah  
**Version :** 1.0  
**Description :**  
Outil terminal puissant pour le pentesting WiFi sous Kali Linux, utilisant `rich` pour une interface en couleurs claire et organisée.  
Permet de scanner interfaces WiFi, passer en mode moniteur, détecter réseaux et clients, lancer des attaques Deauth, Fake Auth, ARP Spoof, et envoyer des fichiers sur un client distant.

---

## Fonctionnalités principales

- Scan automatique des interfaces WiFi disponibles
- Passage automatique ou manuel en mode moniteur (airmon-ng)
- Scan des réseaux WiFi proches (avec détails BSSID, SSID, canal, signal)
- Scan des clients connectés (via arp-scan)
- Attaques Deauth, Fake Auth et ARP Spoof paramétrables
- Envoi de fichiers via TCP sur port 9000 (nécessite client écouteur sur poste cible)
- Logs détaillés horodatés dans `levi_wifi_tool.log`
- Interface terminal élégante avec couleurs et tableaux via `rich`
- Nom de l’auteur bien visible dans le menu principal
- Message de redirection vers GitHub `robert-sarah`

---

## Prérequis

- Système : Kali Linux ou distribution Linux compatible  
- Python 3.8+  
- Droits root (sudo) pour les opérations réseau et injection WiFi  
- Outils Kali installés :  
  - aircrack-ng  
  - arp-scan  
- Modules Python :  
  - rich

---

## Installation

1. Cloner le dépôt :  
```bash
git clone https://github.com/ton_nom_utilisateur/levi-kali-wifi-tool.git
cd levi-kali-wifi-tool
