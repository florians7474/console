#!/bin/bash
#
# Fennec - Installation complète sur Raspberry Pi OS (64-bit, Bookworm/Trixie).
# Installe Fennec, Pwnagotchi (fork jayofelony), bettercap et pwngrid,
# et met en place les services systemd pilotés par le lanceur.
#
# Usage :  cd ~/console && ./install.sh
#
set -e

# --- Repères ---
REPO="$(cd "$(dirname "$0")" && pwd)"      # dossier du dépôt (où est ce script)
SYS="$REPO/system"                         # fichiers système modèles
USER_NAME="$(whoami)"
USER_HOME="$HOME"
VENV="$USER_HOME/pwnagotchi-venv"

echo "==> Fennec : installation pour l'utilisateur '$USER_NAME'"

# --- 1. Paquets système ---
echo "==> Installation des paquets apt..."
sudo apt update
sudo apt install -y \
    git python3-venv python3-flask aircrack-ng bettercap golang \
    libpcap-dev libdbus-1-dev libglib2.0-dev pkg-config build-essential \
    liblgpio-dev swig libcap-dev iw \
    john hcxtools qtbase5-dev qt5-qmake libssl-dev
    
# --- 2. Environnement Python (venv) + Pwnagotchi ---
if [ ! -d "$VENV" ]; then
    echo "==> Création du venv Python..."
    python3 -m venv "$VENV"
fi

if [ ! -d "$USER_HOME/pwnagotchi-src" ]; then
    echo "==> Clonage de Pwnagotchi (fork jayofelony)..."
    git clone https://github.com/jayofelony/pwnagotchi.git "$USER_HOME/pwnagotchi-src"
fi

echo "==> Installation de Pwnagotchi dans le venv (long)..."
"$VENV/bin/pip" install --prefer-binary "$USER_HOME/pwnagotchi-src"
"$VENV/bin/pip" install python-prctl

# --- 3. Compilation de pwngrid ---
if [ ! -f /usr/local/bin/pwngrid ]; then
    echo "==> Compilation de pwngrid..."
    if [ ! -d "$USER_HOME/pwngrid-src" ]; then
        git clone https://github.com/jayofelony/pwngrid.git "$USER_HOME/pwngrid-src"
    fi
    ( cd "$USER_HOME/pwngrid-src" && make )
    sudo cp "$USER_HOME/pwngrid-src/build/pwngrid" /usr/local/bin/
fi

# --- 4. Mot de passe bettercap généré ---
BC_PASS="$(openssl rand -hex 12)"
echo "==> Mot de passe bettercap généré."

# --- 5. Config Pwnagotchi + caplet ---
echo "==> Mise en place de la config Pwnagotchi..."
sudo mkdir -p /etc/pwnagotchi
sudo sed "s/__BETTERCAP_PASS__/$BC_PASS/" "$SYS/config.toml" \
    | sudo tee /etc/pwnagotchi/config.toml > /dev/null
sudo sed "s/__BETTERCAP_PASS__/$BC_PASS/" "$SYS/pwnagotchi-auto.cap" \
    | sudo tee /etc/pwnagotchi/pwnagotchi-auto.cap > /dev/null

# --- 6. Scripts de lancement ---
echo "==> Installation des scripts de lancement..."
sudo cp "$SYS/fennec-bettercap" /usr/local/bin/fennec-bettercap
sudo cp "$SYS/fennec-pwngrid"   /usr/local/bin/fennec-pwngrid
sudo chmod +x /usr/local/bin/fennec-bettercap /usr/local/bin/fennec-pwngrid

# --- 7. Services systemd (avec substitution du venv) ---
echo "==> Installation des services systemd..."
for svc in bettercap pwngrid-peer pwnagotchi; do
    sudo sed "s#__VENV__#$VENV#g" "$SYS/$svc.service" \
        | sudo tee "/etc/systemd/system/$svc.service" > /dev/null
done
sudo systemctl daemon-reload

# --- 8. Règle sudoers (avec substitution de l'utilisateur) ---
echo "==> Mise en place des droits sudo pour Fennec..."
sudo sed "s/__USER__/$USER_NAME/" "$SYS/fennec.sudoers" \
    | sudo tee /etc/sudoers.d/fennec > /dev/null
sudo chmod 440 /etc/sudoers.d/fennec

# --- 9. Raton : moteur de cassage WPA (routerkeygen + wordlists) ---
echo "==> Mise en place de Raton (cassage WPA)..."

# routerkeygen-cli (cles d'usine) : pas dans apt, compile depuis les sources
if [ ! -f /usr/local/bin/routerkeygen-cli ]; then
    echo "==> Compilation de routerkeygen-cli..."
    if [ ! -d "$USER_HOME/routerkeygen-src" ]; then
        git clone https://github.com/routerkeygen/routerkeygenPC.git "$USER_HOME/routerkeygen-src"
    fi
    ( cd "$USER_HOME/routerkeygen-src/cli" && qmake && make )
    sudo cp "$USER_HOME/routerkeygen-src/cli/routerkeygen-cli" /usr/local/bin/
fi

# Wordlists (dans /usr/share/wordlists)
sudo mkdir -p /usr/share/wordlists

# rockyou (téléchargé depuis SecLists, extrait dans /usr/share/wordlists)
if [ ! -f /usr/share/wordlists/rockyou.txt ]; then
    sudo wget -O /tmp/rockyou.txt.tar.gz \
        https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz
    sudo tar -xzf /tmp/rockyou.txt.tar.gz -C /usr/share/wordlists/
    sudo rm -f /tmp/rockyou.txt.tar.gz
    sudo chown root:root /usr/share/wordlists/rockyou.txt
    sudo chmod 644 /usr/share/wordlists/rockyou.txt
fi

# 10k mots de passe courants (SecLists)
if [ ! -f /usr/share/wordlists/10k-common.txt ]; then
    sudo wget -O /usr/share/wordlists/10k-common.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt
fi

# vraies cles WPA cassees (SecLists)
if [ ! -f /usr/share/wordlists/probable-wpa-top4800.txt ]; then
    sudo wget -O /usr/share/wordlists/probable-wpa-top4800.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt
fi

echo ""
echo "==> Installation terminée."
echo "    Lance Fennec avec :  python3 $REPO/app.py"
echo "    Puis ouvre :         http://<IP-du-Pi>:5000/"
