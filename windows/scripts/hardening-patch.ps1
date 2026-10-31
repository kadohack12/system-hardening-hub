<#
.SYNOPSIS
    Durcissement Windows (poste de travail et serveur).

.DESCRIPTION
    Applique un ensemble de réglages de sécurité courants et réversibles :
    désactivation de SMBv1, signature SMB, LLMNR/NetBIOS, mise en cache des
    identifiants, protection LSA, désactivation de PowerShell v2, pare-feu,
    RDP avec NLA, etc. Chaque modification est journalisée.

    Le script est idempotent : le relancer ne casse rien.

.PARAMETER DryRun
    Affiche ce qui serait modifié sans rien appliquer.

.PARAMETER LogPath
    Chemin du journal. Par défaut : %ProgramData%\Hardening\hardening.log

.EXAMPLE
    .\hardening-patch.ps1 -DryRun
    .\hardening-patch.ps1
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [string]$LogPath = (Join-Path $env:ProgramData 'Hardening\hardening.log')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Changed = 0

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    try {
        $dir = Split-Path -Parent $LogPath
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -Path $LogPath -Value $line -Encoding UTF8
    } catch {
        Write-Warning "Journalisation impossible : $($_.Exception.Message)"
    }
}

# Vérifie les privilèges administrateur.
function Assert-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Ce script doit être exécuté en tant qu'administrateur (Console élevée)."
    }
}

# Écrit une valeur de registre de façon idempotente.
function Set-RegValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [ValidateSet('DWord', 'String', 'QWord', 'ExpandString', 'MultiString')][string]$Type = 'DWord'
    )

    if ($DryRun) {
        Write-Log "[DRY-RUN] Registre : $Path\$Name = $Value ($Type)"
        return
    }

    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($current -eq $Value) { return }

    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    $script:Changed++
    Write-Log "Registre : $Path\$Name = $Value"
}

# --- 1. SMB ---------------------------------------------------------------
function Set-SmbHardening {
    Write-Log "Étape 1 : durcissement SMB (désactivation SMBv1, signature obligatoire)..."

    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($null -eq $smb1) {
        Write-Log "SMB1Protocol introuvable sur cette édition ; ignoré." 'WARN'
    } elseif ($smb1.State -eq 'Enabled') {
        if ($DryRun) {
            Write-Log "[DRY-RUN] Désactiverait la fonctionnalité SMB1Protocol."
        } else {
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
            $script:Changed++
            Write-Log "Fonctionnalité SMB1Protocol désactivée."
        }
    } else {
        Write-Log "SMB1Protocol déjà désactivé."
    }

    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
        -Name 'SMB1' -Value 0
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
        -Name 'RequireSecuritySignature' -Value 1
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' `
        -Name 'RequireSecuritySignature' -Value 1
}

# --- 2. Résolution de noms (LLMNR / NetBIOS) ------------------------------
function Set-NameResolutionHardening {
    Write-Log "Étape 2 : désactivation LLMNR et NetBIOS over TCP/IP..."

    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
        -Name 'EnableMulticast' -Value 0

    if ($DryRun) {
        Write-Log "[DRY-RUN] Désactiverait NetBIOS sur toutes les interfaces."
        return
    }

    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue |
        ForEach-Object {
            New-ItemProperty -Path $_.PSPath -Name 'NetbiosOptions' -Value 2 `
                -PropertyType DWord -Force | Out-Null
        }
    $script:Changed++
    Write-Log "NetBIOS over TCP/IP désactivé sur toutes les interfaces."
}

# --- 3. Protection des identifiants ---------------------------------------
function Set-CredentialHardening {
    Write-Log "Étape 3 : protection des identifiants (WDigest, LSA, cache)..."
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
        -Name 'UseLogonCredential' -Value 0
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name 'RunAsPPL' -Value 1
    Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' `
        -Name 'CachedLogonsCount' -Value '0' -Type String
}

# --- 4. PowerShell v2 (vecteur de contournement) --------------------------
function Set-PowerShellV2Hardening {
    Write-Log "Étape 4 : désactivation du moteur PowerShell v2..."
    $feature = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 `
        -ErrorAction SilentlyContinue
    if ($null -eq $feature -or $feature.State -eq 'Disabled') {
        Write-Log "PowerShell v2 déjà désactivé ou absent."
        return
    }
    if ($DryRun) {
        Write-Log "[DRY-RUN] Désactiverait MicrosoftWindowsPowerShellV2."
        return
    }
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart | Out-Null
    $script:Changed++
    Write-Log "PowerShell v2 désactivé."
}

# --- 5. RDP avec authentification au niveau réseau ------------------------
function Set-RdpHardening {
    Write-Log "Étape 5 : RDP avec NLA et niveau de chiffrement élevé..."
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
        -Name 'UserAuthentication' -Value 1
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
        -Name 'MinEncryptionLevel' -Value 3
}

# --- 6. Autorun / médias amovibles ----------------------------------------
function Set-AutorunHardening {
    Write-Log "Étape 6 : désactivation de l'exécution automatique..."
    Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
        -Name 'NoAutorun' -Value 1
    Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
        -Name 'NoDriveTypeAutoRun' -Value 255
}

# --- 7. Pare-feu ----------------------------------------------------------
function Set-FirewallHardening {
    Write-Log "Étape 7 : activation du pare-feu sur tous les profils..."
    if ($DryRun) {
        Write-Log "[DRY-RUN] Activerait le pare-feu pour Domain/Private/Public."
        return
    }
    Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True
    $script:Changed++
    Write-Log "Pare-feu activé sur les trois profils."
}

function Invoke-Hardening {
    Write-Log "=== Début du durcissement Windows $(if ($DryRun) { '(DRY-RUN)' }) ==="
    Set-SmbHardening
    Set-NameResolutionHardening
    Set-CredentialHardening
    Set-PowerShellV2Hardening
    Set-RdpHardening
    Set-AutorunHardening
    Set-FirewallHardening
    if ($DryRun) {
        Write-Log "=== DRY-RUN terminé : aucune modification appliquée. ==="
    } else {
        Write-Log "=== Durcissement terminé : $script:Changed modification(s). Redémarrage recommandé. ==="
    }
}

Assert-Administrator
Invoke-Hardening
