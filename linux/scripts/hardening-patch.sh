#!/usr/bin/env bash
#
# hardening-patch.sh - Script de durcissement système (Niveau Production)
# Auteur : Kadohack12
#
# Ce script doit être exécuté avec les privilèges root.
# Options disponibles :
#   --dry-run : Simule les modifications sans impacter le système.
#

set -euo pipefail

# Configuration des variables globales
LOG_FILE="/var/log/system_hardening.log"
BACKUP_DIR="/var/backup/hardening_$(date +%F_%H%M%S)"
DRY_RUN=false

# Journalisation
log() {
    local msg="$1"
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $msg" | tee -a "$LOG_FILE"
}

# Gestion des arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            log "[DÉMARRAGE] Mode simulation (DRY-RUN) activé. Aucune modification ne sera appliquée."
            ;;
        *)
            echo "Option inconnue : $1. Options disponibles : --dry-run"
            exit 1
            ;;
    esac
    shift
done

# Vérification des privilèges
if [ "$EUID" -ne 0 ]; then
    echo "Erreur : Ce script doit être exécuté en tant que root (sudo)." >&2
    exit 1
fi

# Fonction de sauvegarde des fichiers
backup_file() {
    local target_file="$1"
    if [ -f "$target_file" ]; then
        if [ "$DRY_RUN" = false ]; then
            mkdir -p "$BACKUP_DIR"
            cp -p "$target_file" "$BACKUP_DIR/$(basename "$target_file").bak"
            log "[Sauvegarde] Fichier original sauvegardé : $target_file"
        else
            log "[DRY-RUN] Devrait sauvegarder $target_file dans $BACKUP_DIR"
        fi
    fi
}

# Fonction pour modifier proprement la configuration SSH (Idempotent)
set_ssh_config() {
    local key="$1"
    local value="$2"
    local config_file="/etc/ssh/sshd_config"

    if [ "$DRY_RUN" = true ]; then
        log "[DRY-RUN] Devrait configurer SSH : $key -> $value"
        return
    fi

    backup_file "$config_file"

    # Vérifie si la clé est déjà configurée (qu'elle soit commentée ou non)
    if grep -qE "^[#[:space:]]*$key[[:space:]]" "$config_file"; then
        # Remplace la ligne existante
        sed -i -E "s|^[#[:space:]]*($key[[:space:]]+).*|\1$value|" "$config_file"
    else
        # Ajoute la configuration si elle n'existe pas du tout
        echo "$key $value" >> "$config_file"
    fi
    log "[SSH] Paramètre configuré : $key -> $value"
}

# ==========================================
# 1. DURCISSEMENT RÉSEAU (SYSCTL)
# ==========================================
apply_sysctl_hardening() {
    local sysctl_conf="/etc/sysctl.d/99-hardening.conf"
    log "[Étape 1] Application des règles sysctl (protection réseau)..."

    if [ "$DRY_RUN" = false ]; then
        backup_file "$sysctl_conf"
        cat << 'EOF' > "$sysctl_conf"
# Configuration de sécurité sysctl générée automatiquement
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
fs.suid_dumpable = 0
kernel.randomize_va_space = 2
EOF
        sysctl -p "$sysctl_conf" >/dev/null
        log "[SYSCTL] Configuration appliquée avec succès."
    else
        log "[DRY-RUN] Devrait écrire les règles réseau dans $sysctl_conf"
    fi
}

# ==========================================
# 2. SÉCURISATION DU SERVICE SSH (SSHD)
# ==========================================
apply_ssh_hardening() {
    log "[Étape 2] Sécurisation de la configuration SSH..."

    # La directive "Protocol 2" a été supprimée d'OpenSSH depuis la version 7.6 :
    # la laisser dans sshd_config fait échouer "sshd -t" et bloque le redémarrage.
    # Le protocole 2 est de toute façon le seul supporté désormais.
    set_ssh_config "PermitRootLogin" "prohibit-password" # Utilisation des clés SSH uniquement pour root
    set_ssh_config "MaxAuthTries" "4"
    set_ssh_config "X11Forwarding" "no"
    set_ssh_config "ClientAliveInterval" "300"
    set_ssh_config "ClientAliveCountMax" "2"
    set_ssh_config "IgnoreRhosts" "yes"
    set_ssh_config "PermitEmptyPasswords" "no"

    if [ "$DRY_RUN" = false ]; then
        # Valider la syntaxe avant tout redémarrage : si elle est invalide on
        # restaure immédiatement pour ne jamais laisser un sshd cassé.
        if ! sshd -t; then
            log "[ERREUR] La configuration SSH générée contient des erreurs. Restauration du fichier d'origine..."
            cp -pf "$BACKUP_DIR/sshd_config.bak" "/etc/ssh/sshd_config"
            exit 1
        fi

        # Debian/Ubuntu nomment l'unité "ssh", RHEL/CentOS "sshd" : cibler celle
        # qui existe, sinon le redémarrage échoue silencieusement.
        if systemctl list-unit-files --type=service 2>/dev/null | grep -q '^ssh\.service'; then
            ssh_unit="ssh"
        else
            ssh_unit="sshd"
        fi
        systemctl restart "$ssh_unit"
        log "[SSH] Configuration validée et service $ssh_unit redémarré avec succès."
    else
        log "[DRY-RUN] Devrait valider la syntaxe et redémarrer sshd."
    fi
}

# ==========================================
# 3. UMASK PAR DÉFAUT (PROTECTION DES FICHIERS)
# ==========================================
apply_umask_hardening() {
    log "[Étape 3] Configuration du masque par défaut (Umask 027)..."
    local login_defs="/etc/login.defs"

    if [ "$DRY_RUN" = false ]; then
        backup_file "$login_defs"
        if grep -qE "^UMASK" "$login_defs"; then
            sed -i "s/^UMASK.*/UMASK           027/" "$login_defs"
        else
            echo "UMASK           027" >> "$login_defs"
        fi
        log "[UMASK] Umask configuré à 027 dans $login_defs"
    else
        log "[DRY-RUN] Devrait modifier l'UMASK dans $login_defs"
    fi
}

# ==========================================
# EXÉCUTION DU SCRIPT
# ==========================================
main() {
    log "[DÉBUT] Lancement du patch de durcissement système..."
    
    apply_sysctl_hardening
    apply_ssh_hardening
    apply_umask_hardening
    
    if [ "$DRY_RUN" = false ]; then
        log "[FIN] Processus terminé avec succès. Sauvegardes stockées dans : $BACKUP_DIR"
    else
        log "[FIN] Simulation terminée. Aucune modification n'a été enregistrée."
    fi
}

main
