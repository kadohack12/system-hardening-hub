# Contribution au projet System Hardening Hub

Merci de l'intérêt que vous portez à ce projet ! Les contributions de la communauté nous permettent d'améliorer continuellement le niveau de sécurité proposé.

## Comment contribuer ?

1. **Signaler des anomalies ou proposer des fonctionnalités** via les issues GitHub.
2. **Proposer des modifications (Pull Requests)** :
   - Créez une branche dédiée à votre modification.
   - Assurez-vous que vos scripts sont documentés et testés (notamment avec le mode simulation/dry-run).
   - Soumettez votre Pull Request pour revue.

## Règles de développement

- Tous les nouveaux scripts PowerShell doivent être placés dans `windows/scripts/`.
- Tous les nouveaux scripts Bash/Linux doivent être placés dans `linux/scripts/`.
- Assurez-vous d'implémenter un mode simulation (`--dry-run`) autant que possible afin de valider les modifications sans impacter directement les machines cibles.
- Mettez à jour les fichiers `README.md` concernés si vous ajoutez des fonctionnalités ou modifiez des prérequis.
