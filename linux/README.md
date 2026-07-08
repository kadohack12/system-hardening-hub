# Sécurisation & Durcissement Linux

Ce répertoire contient les ressources de durcissement et de sécurisation pour les systèmes Linux.

## Contenu

- [scripts/](scripts/) : Scripts de durcissement système.
- [ansible/](ansible/) : Playbooks et rôles Ansible pour automatiser le déploiement du durcissement.

## Utilisation du Script de Durcissement

Le script principal de durcissement est [hardening-patch.sh](scripts/hardening-patch.sh). Il permet d'appliquer les règles de sécurité réseau, de configurer SSH de manière sécurisée et de configurer l'UMASK par défaut.

### Prérequis
- Droits `root` (sudo) sur la machine cible.
- Un système Linux compatible (Debian/Ubuntu/CentOS/RHEL).

### Lancement du script

#### 1. Simulation (Dry-run)
Avant d'appliquer des modifications réelles sur votre système de production, il est fortement recommandé de simuler le comportement du script :
```bash
sudo ./scripts/hardening-patch.sh --dry-run
```

#### 2. Application réelle
Pour appliquer le durcissement sur le système :
```bash
sudo ./scripts/hardening-patch.sh
```

Les modifications seront journalisées dans `/var/log/system_hardening.log` et les fichiers originaux sauvegardés sous `/var/backup/`.
