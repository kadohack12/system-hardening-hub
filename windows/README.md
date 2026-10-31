# Durcissement Windows — Scripts et GPO

## Contenu

- [scripts/hardening-patch.ps1](scripts/hardening-patch.ps1) : script PowerShell de durcissement local (idempotent, journalisé).
- [gpo/local-security-policy.inf](gpo/local-security-policy.inf) : modèle de sécurité (format GPO/`secedit`) pour la politique locale ou l'import en GPO de domaine.

## Script PowerShell

À exécuter dans une **console élevée** (administrateur).

```powershell
# Simulation : n'applique rien, affiche les changements prévus
.\scripts\hardening-patch.ps1 -DryRun

# Application réelle
.\scripts\hardening-patch.ps1
```

Le script applique notamment :

| Domaine | Réglage |
|---|---|
| SMB | SMBv1 désactivé, signature SMB obligatoire |
| Résolution de noms | LLMNR désactivé, NetBIOS over TCP/IP désactivé |
| Identifiants | WDigest désactivé, protection LSA (`RunAsPPL`), cache de logon à 0 |
| PowerShell | Moteur v2 désactivé (vecteur de contournement) |
| RDP | NLA obligatoire, chiffrement élevé |
| Médias amovibles | Autorun désactivé |
| Réseau | Pare-feu activé (profils Domain/Private/Public) |

Journal : `%ProgramData%\Hardening\hardening.log`.

> ⚠️ Le réglage du cache de logon à `0` et le renommage du compte administrateur
> peuvent gêner la connexion hors-ligne / les outils de gestion. Testez d'abord en
> `-DryRun` sur un poste pilote.

## Modèle de sécurité GPO

`gpo/local-security-policy.inf` applique la politique de mot de passe, de
verrouillage de compte, l'audit, plusieurs réglages de registre (SMB, LLMNR,
WDigest, LSA, Autorun) et les droits d'accès réseau.

Application locale (machine non jointe à un domaine) :

```cmd
secedit /configure /db %TEMP%\hardening.sdb /cfg gpo\local-security-policy.inf /areas SECURITYPOLICY
```

Import en GPO de domaine : via la console GPMC (*Configuration ordinateur >
Paramètres Windows > Paramètres de sécurité > Importer la stratégie*) ou avec
`Import-GPO` / `secedit /export`.
