import csv
import json
import socket
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import urllib.request
import webbrowser

# Importation pour les notifications système
from plyer import notification

# Importations ciblées Scapy
from scapy.config import conf
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import send, srp

OUI_DICTIONNAIRE = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "00:1E:C6": "ASUSTeK Computer",
    "04:D4:C4": "Intel Corporation",
    "3C:D9:2B": "Hewlett Packard",
    "50:65:F3": "Apple, Inc.",
    "AC:BC:B5": "Apple, Inc.",
    "F4:D4:88": "Apple, Inc.",
    "DC:BF:E9": "TP-Link Corporation",
    "50:C7:BF": "TP-Link Corporation",
    "CC:32:E5": "Samsung Electronics",
    "84:25:DB": "Samsung Electronics",
    "C8:D7:B0": "Xiaomi Communications",
    "70:85:C2": "Huawei Technologies",
    "00:11:32": "Synology Inc."
}


class NetworkMonitorApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("NetGuard Pro - Gestionnaire & Analyseur Réseau")
        self.root.geometry("1100x650")
        self.root.minsize(950, 500)

        # État interne, caches et automatisation
        self.is_scanning = False
        self.devices = []
        self.oui_cache = {}
        self.auto_scan_active = False
        self.auto_scan_job = None
        self.auto_scan_interval_ms = 0

        # Gestion des blocages réseau (ARP Spoofing)
        self.blocked_threads = {}  # {ip: {"active": bool, "thread": Thread}}

        # Suivi des adresses MAC connues pour les notifications
        self.known_macs = set()
        self.first_scan_done = False

        # Style & IHM
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.setup_styles()
        self.create_widgets()

        self.router_ip = self.obtenir_ip_passerelle()

    def setup_styles(self):
        self.style.configure("TFrame", background="#2b2b2b")
        self.style.configure("Header.TFrame", background="#1e1e1e")
        self.style.configure("TLabel", background="#2b2b2b", foreground="#ffffff", font=("Helvetica", 10))
        self.style.configure("Header.TLabel", background="#1e1e1e", foreground="#00e676",
                             font=("Helvetica", 15, "bold"))
        self.style.configure("Status.TLabel", background="#1e1e1e", foreground="#b0bec5", font=("Helvetica", 9))
        self.style.configure("TButton", font=("Helvetica", 10, "bold"), padding=6)

        self.style.configure(
            "Treeview",
            background="#333333",
            foreground="#ffffff",
            fieldbackground="#333333",
            rowheight=28,
            font=("Consolas", 10)
        )
        self.style.configure(
            "Treeview.Heading",
            background="#1e1e1e",
            foreground="#ffffff",
            font=("Helvetica", 10, "bold")
        )
        self.style.map("Treeview", background=[('selected', '#00e676')], foreground=[('selected', '#000000')])

    def create_widgets(self):
        header_frame = ttk.Frame(self.root, style="Header.TFrame", padding=12)
        header_frame.pack(fill="x", side="top")

        title_label = ttk.Label(header_frame, text="📡 NetGuard Pro - Network Monitor & Defender", style="Header.TLabel")
        title_label.pack(side="left")

        toolbar_frame = ttk.Frame(self.root, padding=10)
        toolbar_frame.pack(fill="x", side="top")

        self.btn_scan = ttk.Button(toolbar_frame, text="🔍 Lancer le Scan", command=self.demarrer_scan_thread)
        self.btn_scan.pack(side="left", padx=5)

        # Bouton pour bloquer/débloquer l'appareil sélectionné
        self.btn_block = ttk.Button(toolbar_frame, text="🚫 Bloquer / Débloquer", command=self.basculer_blocage_appareil)
        self.btn_block.pack(side="left", padx=5)

        self.btn_export = ttk.Button(toolbar_frame, text="💾 Exporter (CSV)", command=self.exporter_csv)
        self.btn_export.pack(side="left", padx=5)

        ttk.Label(toolbar_frame, text="⏱️ Scan auto :").pack(side="left", padx=(15, 2))
        self.combo_interval = ttk.Combobox(
            toolbar_frame,
            values=["Désactivé", "1 minute", "5 minutes", "10 minutes"],
            state="readonly",
            width=12
        )
        self.combo_interval.current(0)
        self.combo_interval.pack(side="left", padx=5)
        self.combo_interval.bind("<<ComboboxSelected>>", self.gerer_auto_scan)

        self.btn_router = ttk.Button(toolbar_frame, text="🛡️ Admin Routeur", command=self.ouvrir_admin_routeur)
        self.btn_router.pack(side="right", padx=5)

        table_frame = ttk.Frame(self.root, padding=10)
        table_frame.pack(fill="both", expand=True)

        columns = ("ip", "nom", "mac", "constructeur", "statut")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("ip", text="Adresse IP")
        self.tree.heading("nom", text="Nom d'appareil (DNS)")
        self.tree.heading("mac", text="Adresse MAC")
        self.tree.heading("constructeur", text="Constructeur (OUI)")
        self.tree.heading("statut", text="État / Connexion")

        self.tree.column("ip", width=130, anchor="center")
        self.tree.column("nom", width=220, anchor="w")
        self.tree.column("mac", width=160, anchor="center")
        self.tree.column("constructeur", width=200, anchor="w")
        self.tree.column("statut", width=180, anchor="center")

        # Tags de couleur pour l'état des appareils
        self.tree.tag_configure("even", background="#383838")
        self.tree.tag_configure("odd", background="#2e2e2e")
        self.tree.tag_configure("router", foreground="#00e676", font=("Consolas", 10, "bold"))
        self.tree.tag_configure("blocked", foreground="#ff5252", font=("Consolas", 10, "bold"))

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.status_frame = ttk.Frame(self.root, style="Header.TFrame", padding=6)
        self.status_frame.pack(fill="x", side="bottom")

        self.lbl_status = ttk.Label(self.status_frame, text="Prêt à scanner le réseau local.", style="Status.TLabel")
        self.lbl_status.pack(side="left", padx=10)

        self.progress = ttk.Progressbar(self.status_frame, mode="indeterminate", length=150)

    def basculer_blocage_appareil(self):
        """Active ou désactive le blocage Internet de l'appareil sélectionné."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Sélection requise", "Veuillez sélectionner un appareil dans le tableau.")
            return

        item = self.tree.item(selection[0])
        vals = item["values"]
        target_ip = str(vals[0])
        target_mac = str(vals[2])
        statut = str(vals[4])

        if "Passerelle" in statut:
            messagebox.showerror("Action impossible", "Vous ne pouvez pas bloquer le routeur lui-même !")
            return

        # Si l'appareil est déjà en cours de blocage -> On le débloque
        if target_ip in self.blocked_threads and self.blocked_threads[target_ip]["active"]:
            self.blocked_threads[target_ip]["active"] = False
            del self.blocked_threads[target_ip]

            # Mise à jour visuelle
            self.tree.item(selection[0], values=(vals[0], vals[1], vals[2], vals[3], "Connecté"), tags=("even",))
            messagebox.showinfo("Débloqué", f"Le blocage a été levé pour {target_ip}.\nL'accès Internet est rétabli.")
            self.lbl_status.config(text=f"Accès rétabli pour {target_ip}.")
        else:
            # Sinon -> On le bloque
            confirmation = messagebox.askyesno(
                "Confirmation de blocage",
                f"Voulez-vous couper l'accès Internet de cet appareil ?\n\n"
                f"• IP : {target_ip}\n"
                f"• MAC : {target_mac}\n"
                f"• Nom : {vals[1]}"
            )
            if confirmation:
                self.demarrer_blocage(target_ip, target_mac)
                self.tree.item(selection[0], values=(vals[0], vals[1], vals[2], vals[3], "🚫 BLOQUÉ (ARP)"),
                               tags=("blocked",))
                messagebox.showinfo("Blocage Actif", f"L'appareil {target_ip} est désormais bloqué du réseau.")
                self.lbl_status.config(text=f"Blocage ARP actif sur {target_ip}.")

    def demarrer_blocage(self, target_ip: str, target_mac: str):
        """Lance la boucle d'empoisonnement ARP dans un thread séparé."""
        self.blocked_threads[target_ip] = {"active": True}

        t = threading.Thread(
            target=self.boucle_arp_spoofing,
            args=(target_ip, target_mac),
            daemon=True
        )
        self.blocked_threads[target_ip]["thread"] = t
        t.start()

    def boucle_arp_spoofing(self, target_ip: str, target_mac: str):
        """Envoie en continu de faux paquets ARP pour couper la connexion de la cible."""
        conf.verb = 0

        # Paquet 1: Fait croire à la cible que notre PC est le routeur
        pkt_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=self.router_ip)
        # Paquet 2: Fait croire au routeur que notre PC est la cible
        pkt_router = ARP(op=2, pdst=self.router_ip, psrc=target_ip)

        while target_ip in self.blocked_threads and self.blocked_threads[target_ip]["active"]:
            try:
                send(pkt_target, verbose=False)
                send(pkt_router, verbose=False)
            except Exception:
                pass
            time.sleep(1.5)  # Envoi toutes les 1.5 secondes pour maintenir le blocage

    def gerer_auto_scan(self, event=None):
        if self.auto_scan_job:
            self.root.after_cancel(self.auto_scan_job)
            self.auto_scan_job = None

        choix = self.combo_interval.get()
        if choix == "Désactivé":
            self.auto_scan_active = False
            self.lbl_status.config(text="Scan automatique désactivé.")
        else:
            self.auto_scan_active = True
            minutes = int(choix.split()[0])
            self.auto_scan_interval_ms = minutes * 60 * 1000
            self.lbl_status.config(text=f"Scan automatique activé (toutes les {minutes} min).")
            self.programmer_prochain_scan()

    def programmer_prochain_scan(self):
        if not self.auto_scan_active:
            return

        def boucle():
            if self.auto_scan_active:
                if not self.is_scanning:
                    self.demarrer_scan_thread()
                self.auto_scan_job = self.root.after(self.auto_scan_interval_ms, boucle)

        self.auto_scan_job = self.root.after(self.auto_scan_interval_ms, boucle)

    def obtenir_ip_passerelle(self) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip_locale = s.getsockname()[0]
            return ".".join(ip_locale.split(".")[:-1]) + ".1"
        except Exception:
            return "192.168.1.1"
        finally:
            s.close()

    def obtenir_nom_hote(self, ip: str) -> str:
        try:
            socket.setdefaulttimeout(0.3)
            nom, _, _ = socket.gethostbyaddr(ip)
            return nom
        except Exception:
            return "Inconnu / Non renseigné"

    def obtenir_constructeur(self, mac: str) -> str:
        mac_upper = mac.upper()
        prefixe = mac_upper[:8]

        if prefixe in self.oui_cache:
            return self.oui_cache[prefixe]

        if prefixe in OUI_DICTIONNAIRE:
            self.oui_cache[prefixe] = OUI_DICTIONNAIRE[prefixe]
            return OUI_DICTIONNAIRE[prefixe]

        try:
            mac_clean = mac_upper.replace(":", "").replace("-", "")[:6]
            url = f"https://api.maclookup.app/v2/macs/{mac_clean}"
            req = urllib.request.Request(url, headers={'User-Agent': 'NetGuard/1.0'})

            with urllib.request.urlopen(req, timeout=0.8) as response:
                data = json.loads(response.read().decode('utf-8'))
                if data.get("success") and data.get("company"):
                    nom_compagnie = data["company"] if data["company"] else "Générique"
                    self.oui_cache[prefixe] = nom_compagnie
                    return nom_compagnie
        except Exception:
            pass

        self.oui_cache[prefixe] = "Inconnu"
        return "Inconnu"

    def envoyer_notification_nouveau_dispositif(self, nouveaux_appareils: list):
        nb = len(nouveaux_appareils)
        if nb == 1:
            dev = nouveaux_appareils[0]
            titre = "⚠️ Nouveau périphérique détecté !"
            message = f"IP: {dev[0]}\nNom: {dev[1]}\nConstructeur: {dev[3]}"
        else:
            titre = f"⚠️ {nb} nouveaux périphériques détectés !"
            message = f"Dernier connecté : {nouveaux_appareils[-1][0]} ({nouveaux_appareils[-1][3]})"

        try:
            notification.notify(
                title=titre,
                message=message,
                app_name="NetGuard Pro",
                timeout=6
            )
        except Exception:
            pass

    def demarrer_scan_thread(self):
        if not self.is_scanning:
            self.is_scanning = True
            self.btn_scan.config(state="disabled")
            self.progress.pack(side="right", padx=10)
            self.progress.start(10)
            self.lbl_status.config(text="Analyse du réseau ARP et identification en cours...")

            for item in self.tree.get_children():
                self.tree.delete(item)

            threading.Thread(target=self.executer_scan_reseau, daemon=True).start()

    def executer_scan_reseau(self):
        try:
            conf.verb = 0
            ip_passerelle = self.obtenir_ip_passerelle()
            ip_range = ".".join(ip_passerelle.split(".")[:-1]) + ".0/24"

            requete_arp = ARP()
            requete_arp.pdst = ip_range

            broadcast = Ether()
            broadcast.dst = "ff:ff:ff:ff:ff:ff"

            paquet = broadcast / requete_arp

            reponses, _ = srp(paquet, timeout=2, verbose=False)

            self.devices = []
            nouveaux_appareils = []

            for _, recu in reponses:
                ip = recu.psrc
                mac = recu.hwsrc

                nom = self.obtenir_nom_hote(ip)
                constructeur = self.obtenir_constructeur(mac)

                # Conserver le statut 'BLOQUÉ' si le blocage est déjà actif sur cette IP
                if ip == ip_passerelle:
                    statut = "Passerelle (Routeur)"
                elif ip in self.blocked_threads and self.blocked_threads[ip]["active"]:
                    statut = "🚫 BLOQUÉ (ARP)"
                else:
                    statut = "Connecté"

                device_tuple = (ip, nom, mac, constructeur, statut)
                self.devices.append(device_tuple)

                if self.first_scan_done and mac not in self.known_macs:
                    nouveaux_appareils.append(device_tuple)

                self.known_macs.add(mac)

            if nouveaux_appareils:
                self.envoyer_notification_nouveau_dispositif(nouveaux_appareils)

            self.first_scan_done = True
            self.root.after(0, self.mettre_a_jour_tableau)

        except PermissionError:
            self.root.after(0, lambda: messagebox.showerror(
                "Privilèges Insuffisants",
                "Droits Administrateur requis !\n\nFermez l'application puis réouvrez en tant qu'administrateur."
            ))
            self.root.after(0, self.fin_scan)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Erreur de Scan", f"Erreur lors du scan : {e}"))
            self.root.after(0, self.fin_scan)

    def mettre_a_jour_tableau(self):
        for i, device in enumerate(self.devices):
            if device[4] == "Passerelle (Routeur)":
                tag = "router"
            elif "BLOQUÉ" in device[4]:
                tag = "blocked"
            else:
                tag = "even" if i % 2 == 0 else "odd"

            self.tree.insert("", "end", values=device, tags=(tag,))

        count = len(self.devices)
        self.lbl_status.config(text=f"Scan terminé. {count} appareil(s) détecté(s).")
        self.fin_scan()

    def fin_scan(self):
        self.is_scanning = False
        self.progress.stop()
        self.progress.pack_forget()
        self.btn_scan.config(state="normal")

    def exporter_csv(self):
        if not self.devices:
            messagebox.showwarning("Attention", "Aucun appareil à exporter. Lancez d'abord un scan.")
            return

        fichier = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("Fichiers CSV", "*.csv")])
        if fichier:
            try:
                with open(fichier, mode="w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Adresse IP", "Nom d'appareil", "Adresse MAC", "Constructeur", "Statut"])
                    writer.writerows(self.devices)
                messagebox.showinfo("Succès", "Rapport CSV généré avec succès.")
            except Exception as e:
                messagebox.showerror("Erreur", f"Échec de l'exportation : {e}")

    def ouvrir_admin_routeur(self):
        webbrowser.open(f"http://{self.router_ip}")


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitorApp(root)
    root.mainloop()# 📡 NetGuard Pro - Network Monitor & Analyzer

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows)
![License](https://img.shields.io/badge/License-MIT-green)
![Release](https://img.shields.io/badge/Version-1.0.0-orange)

**NetGuard Pro** est une application de bureau légère et intuitive conçue pour analyser, surveiller et sécuriser votre réseau local (LAN/Wi-Fi). Elle permet de détecter en temps réel l'ensemble des équipements connectés, de recevoir des alerte système automatiques à chaque nouvel appareil détecté et de générer des rapports détaillés.

---

## 📸 Aperçu de l'interface

> *Une interface sombre (Dark Mode) moderne, épurée et pensée pour une lisibilité maximale.*
