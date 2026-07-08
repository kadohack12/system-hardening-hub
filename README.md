# System Hardening Hub

Ce dépôt centralise les scripts, politiques de sécurité et configurations de durcissement (hardening) pour différents systèmes d'exploitation (Windows et Linux).

## Structure du projet

Le projet est organisé de la manière suivante :

```text
system-hardening-hub/
├── .github/                  # Configuration GitHub (Ex. modèles d'issues)
├── windows/                  # Ressources pour l'écosystème Windows
│   ├── scripts/              # Scripts PowerShell de durcissement
│   ├── gpo/                  # Objets de stratégie de groupe (GPO)
│   └── README.md             # Documentation spécifique à Windows
├── linux/                    # Ressources pour l'écosystème Linux
│   ├── ansible/              # Playbooks et configurations Ansible
│   ├── scripts/              # Scripts Bash de durcissement
│   │   └── hardening-patch.sh
│   └── README.md             # Documentation et instructions pour Linux
├── LICENSE                   # Licence du projet (MIT)
├── README.md                 # Ce fichier
└── CONTRIBUTING.md           # Instructions pour contribuer au projet
```

## Premiers pas

Pour commencer à appliquer ou simuler des patches de durcissement :
- Pour **Linux**, consultez le document [linux/README.md](linux/README.md).
- Pour **Windows**, consultez le document [windows/README.md](windows/README.md).

## Contribution

Toutes les contributions sont les bienvenues. Veuillez consulter le guide [CONTRIBUTING.md](CONTRIBUTING.md) pour plus d'informations.
