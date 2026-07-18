#Requires -Version 5.1
<#
    OptiWin GUI - Utilitaire de mise a jour et d'optimisation Windows (interface graphique)
    Auteur : Dona By
    Usage : lancer via Lancer-OptiWin-GUI.bat
#>

# ------------------------- Elevation automatique -------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# ------------------------- Utilitaires -------------------------
function Set-RegValue($chemin, $nom, $valeur, $type = 'DWord') {
    if (-not (Test-Path $chemin)) { New-Item -Path $chemin -Force | Out-Null }
    New-ItemProperty -Path $chemin -Name $nom -Value $valeur -PropertyType $type -Force | Out-Null
}

# Affiche un recapitulatif des actions cochees et demande confirmation
function Confirm-Actions($titre, $actions) {
    if ($actions.Count -eq 0) { return $false }
    $texte = "Les actions suivantes seront appliquées :`r`n`r`n" + (($actions | ForEach-Object { " -  $_" }) -join "`r`n")
    $r = [System.Windows.Forms.MessageBox]::Show($texte, "$titre - Confirmation",
         [System.Windows.Forms.MessageBoxButtons]::OKCancel,
         [System.Windows.Forms.MessageBoxIcon]::Question)
    return ($r -eq [System.Windows.Forms.DialogResult]::OK)
}

# Localise le vrai winget.exe (l'alias du Store ne fonctionne pas toujours en mode administrateur)
function Resolve-WingetPath {
    # 1. Executable reel dans WindowsApps (fonctionne en admin)
    $cand = @(Get-ChildItem "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue |
              Sort-Object FullName -Descending)
    if ($cand.Count -eq 0) {
        $cand = @(Get-ChildItem "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue |
                  Sort-Object FullName -Descending)
    }
    if ($cand.Count -gt 0) { return $cand[0].FullName }
    # 2. Alias classique
    $c = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    return $null
}
$script:Winget = Resolve-WingetPath

# Analyse la sortie de 'winget upgrade' et renvoie la liste des applications
function Get-WingetUpdates {
    $raw = & $script:Winget upgrade --include-unknown --accept-source-agreements 2>$null
    if (-not $raw) { return @() }
    $lines = @($raw | ForEach-Object { "$_" -replace "`r", "" })

    # Ligne d'en-tete (Nom/Name ... Id ... Version ... Disponible/Available)
    $hIndex = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^(Nom|Name)\s' -and $lines[$i] -match '\bId\b') { $hIndex = $i; break }
    }
    if ($hIndex -lt 0) { return @() }

    $header   = $lines[$hIndex]
    $idxId    = [regex]::Match($header, '\bId\b').Index
    $idxVer   = [regex]::Match($header, '\bVersion\b').Index
    $mDispo   = [regex]::Match($header, 'Disponible|Available')
    $idxDispo = $mDispo.Index
    $mSrc     = [regex]::Match($header, '\bSource\b')
    $idxSrc   = if ($mSrc.Success) { $mSrc.Index } else { 9999 }

    $apps = @()
    for ($i = $hIndex + 2; $i -lt $lines.Count; $i++) {
        $l = $lines[$i]
        if ($l -match '^\s*$') { break }
        if ($l -match '^\d+\s') { break }
        if ($l.Length -le $idxVer) { continue }

        $fin1 = [Math]::Min($idxVer, $l.Length)
        $id = $l.Substring($idxId, $fin1 - $idxId).Trim()
        if (-not $id) { continue }

        $fin2 = [Math]::Min($idxDispo, $l.Length)
        $fin3 = [Math]::Min($idxSrc, $l.Length)
        $ver   = if ($idxVer   -lt $l.Length) { $l.Substring($idxVer, $fin2 - $idxVer).Trim() } else { "" }
        $dispo = if ($idxDispo -lt $l.Length) { $l.Substring($idxDispo, $fin3 - $idxDispo).Trim() } else { "" }

        $apps += [pscustomobject]@{
            Nom     = $l.Substring(0, [Math]::Min($idxId, $l.Length)).Trim()
            Id      = $id
            Version = $ver
            Dispo   = $dispo
        }
    }
    return $apps
}

# Execute des commandes dans une console visible (via script temporaire)
function Start-ConsoleScript($contenu) {
    $tmp = Join-Path $env:TEMP ("OptiWin_" + [guid]::NewGuid().ToString("N") + ".ps1")
    $fin = "`r`nWrite-Host ''; Write-Host 'Terminé. Appuyez sur une touche pour fermer.' -ForegroundColor Green; [void][Console]::ReadKey(`$true)"
    Set-Content -Path $tmp -Value ($contenu + $fin) -Encoding UTF8
    Start-Process powershell.exe -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$tmp`""
}

# ------------------------- Fenetre principale -------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = "OptiWin - Utilitaire Windows  |  Auteur : Dona By"
$form.Size = New-Object System.Drawing.Size(720, 600)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Location = New-Object System.Drawing.Point(10, 10)
$tabs.Size = New-Object System.Drawing.Size(688, 340)
$form.Controls.Add($tabs)

# Journal (log)
$log = New-Object System.Windows.Forms.RichTextBox
$log.Location = New-Object System.Drawing.Point(10, 360)
$log.Size = New-Object System.Drawing.Size(688, 190)
$log.ReadOnly = $true
$log.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$log.ForeColor = [System.Drawing.Color]::LightGreen
$log.Font = New-Object System.Drawing.Font("Consolas", 9)
$form.Controls.Add($log)

function Log($texte) {
    $log.AppendText("[$(Get-Date -Format 'HH:mm:ss')] $texte`r`n")
    $log.ScrollToCaret()
    [System.Windows.Forms.Application]::DoEvents()
}

function New-Tab($titre) {
    $t = New-Object System.Windows.Forms.TabPage
    $t.Text = $titre
    $t.BackColor = [System.Drawing.Color]::White
    $tabs.TabPages.Add($t)
    return $t
}

function New-Check($parent, $texte, $x, $y, $coche = $true, $largeur = 630) {
    $c = New-Object System.Windows.Forms.CheckBox
    $c.Text = $texte
    $c.Location = New-Object System.Drawing.Point($x, $y)
    $c.Size = New-Object System.Drawing.Size($largeur, 24)
    $c.Checked = $coche
    $parent.Controls.Add($c)
    return $c
}

function New-Bouton($parent, $texte, $x, $y, $largeur = 220) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $texte
    $b.Location = New-Object System.Drawing.Point($x, $y)
    $b.Size = New-Object System.Drawing.Size($largeur, 34)
    $b.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
    $b.ForeColor = [System.Drawing.Color]::White
    $b.FlatStyle = "Flat"
    $parent.Controls.Add($b)
    return $b
}

# ========================= Onglet 1 : Mises a jour =========================
$tabMaj = New-Tab "Mises à jour"
$script:updates = @()

$lbl = New-Object System.Windows.Forms.Label
$lbl.Text = "Cliquez sur 'Rechercher' pour voir les applications à mettre à jour, puis cochez celles à installer."
$lbl.Location = New-Object System.Drawing.Point(15, 12)
$lbl.Size = New-Object System.Drawing.Size(650, 20)
$tabMaj.Controls.Add($lbl)

$listApps = New-Object System.Windows.Forms.CheckedListBox
$listApps.Location = New-Object System.Drawing.Point(15, 82)
$listApps.Size = New-Object System.Drawing.Size(650, 150)
$listApps.CheckOnClick = $true
$listApps.Font = New-Object System.Drawing.Font("Consolas", 9)
$tabMaj.Controls.Add($listApps)

$btnScan = New-Bouton $tabMaj "Rechercher les mises à jour" 15 38 240
$btnScan.Add_Click({
    if (-not $script:Winget) { $script:Winget = Resolve-WingetPath }
    if (-not $script:Winget) {
        Log "ERREUR : winget introuvable. Installez 'App Installer' depuis le Microsoft Store."
        return
    }
    Log "winget : $script:Winget"
    Log "Recherche des mises à jour d'applications (winget)... patientez."
    $listApps.Items.Clear()
    $script:updates = @(Get-WingetUpdates)
    if ($script:updates.Count -eq 0) {
        Log "Aucune mise à jour trouvée (ou sortie winget non reconnue)."
        return
    }
    foreach ($u in $script:updates) {
        [void]$listApps.Items.Add(("{0,-38} {1,14} -> {2}" -f $u.Nom, $u.Version, $u.Dispo), $true)
    }
    Log "$($script:updates.Count) mise(s) à jour disponible(s). Décochez celles à ignorer."
})

$btnMajSel = New-Bouton $tabMaj "Mettre à jour la sélection" 15 245 240
$btnMajSel.Add_Click({
    $sel = @()
    foreach ($i in $listApps.CheckedIndices) { $sel += $script:updates[$i] }
    if ($sel.Count -eq 0) { Log "Aucune application cochée. Lancez d'abord une recherche."; return }
    $noms = @($sel | ForEach-Object { "$($_.Nom)  ($($_.Version) -> $($_.Dispo))" })
    if (-not (Confirm-Actions "Mises à jour" $noms)) { Log "Mise à jour annulée."; return }
    Log "Mise à jour de $($sel.Count) application(s) dans une console séparée..."
    $cmds = ($sel | ForEach-Object { "& `"$($script:Winget)`" upgrade --id `"$($_.Id)`" --include-unknown --accept-source-agreements --accept-package-agreements" }) -join "`r`n"
    Start-ConsoleScript $cmds
})

$btnMajAll = New-Bouton $tabMaj "Tout mettre à jour" 275 245 190
$btnMajAll.Add_Click({
    if (-not $script:Winget) { $script:Winget = Resolve-WingetPath }
    if (-not $script:Winget) {
        Log "ERREUR : winget introuvable. Installez 'App Installer' depuis le Microsoft Store."
        return
    }
    Log "Mise à jour de toutes les applications (console séparée)..."
    Start-ConsoleScript "& `"$($script:Winget)`" upgrade --all --include-unknown --accept-source-agreements --accept-package-agreements"
})

$btnMajWin = New-Bouton $tabMaj "Mettre à jour Windows" 275 38 190
$btnMajWin.Add_Click({
    Log "Recherche des mises à jour Windows (console séparée)..."
    $cmd = @'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Write-Host "Installation du module PSWindowsUpdate..."
    try {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null
        Install-Module PSWindowsUpdate -Force -Scope CurrentUser -ErrorAction Stop
    } catch {
        Write-Host "Echec, ouverture des paramètres Windows Update..." -ForegroundColor Red
        Start-Process "ms-settings:windowsupdate"; Start-Sleep 3; exit
    }
}
Import-Module PSWindowsUpdate
Write-Host "Recherche des mises à jour Windows..." -ForegroundColor Cyan
$maj = Get-WindowsUpdate
if (-not $maj) { Write-Host "Windows est à jour." -ForegroundColor Green }
else {
    Write-Host ""
    Write-Host "Mises à jour Windows qui seront installées :" -ForegroundColor Yellow
    $maj | Format-Table -AutoSize
    $r = Read-Host "Installer ces mises à jour ? (O/N)"
    if ($r -match '^[oOyY]') {
        Get-WindowsUpdate -AcceptAll -Install -IgnoreReboot
        Write-Host "Installation terminée. Un redémarrage peut être nécessaire." -ForegroundColor Green
    }
}
Write-Host ''
Write-Host 'Appuyez sur une touche pour fermer.'
[void][Console]::ReadKey($true)
'@
    $tmp = Join-Path $env:TEMP ("OptiWin_WU_" + [guid]::NewGuid().ToString("N") + ".ps1")
    Set-Content -Path $tmp -Value $cmd -Encoding UTF8
    Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$tmp`""
    Log "Fenêtre Windows Update ouverte : la liste s'affiche avant l'installation."
})

$btnMajSettings = New-Bouton $tabMaj "Paramètres Windows Update" 475 38 190
$btnMajSettings.Add_Click({ Start-Process "ms-settings:windowsupdate"; Log "Paramètres Windows Update ouverts." })

# ========================= Onglet 2 : Nettoyage =========================
$tabNet = New-Tab "Nettoyage"
$chkTempUser = New-Check $tabNet "Fichiers temporaires utilisateur (%TEMP%)" 15 15
$chkTempWin  = New-Check $tabNet "Fichiers temporaires Windows (C:\Windows\Temp)" 15 45
$chkWU       = New-Check $tabNet "Cache Windows Update (SoftwareDistribution\Download)" 15 75
$chkCorbeille= New-Check $tabNet "Vider la corbeille" 15 105
$chkDNS      = New-Check $tabNet "Vider le cache DNS" 15 135
$chkDISM     = New-Check $tabNet "Nettoyage des composants Windows (DISM - lent)" 15 165 $false

$btnNettoyer = New-Bouton $tabNet "Lancer le nettoyage" 15 230
$btnNettoyer.Add_Click({
    $actions = @()
    if ($chkTempUser.Checked)  { $actions += "Supprimer les fichiers temporaires utilisateur (%TEMP%)" }
    if ($chkTempWin.Checked)   { $actions += "Supprimer les fichiers temporaires Windows (C:\Windows\Temp)" }
    if ($chkWU.Checked)        { $actions += "Vider le cache Windows Update" }
    if ($chkCorbeille.Checked) { $actions += "Vider la corbeille" }
    if ($chkDNS.Checked)       { $actions += "Vider le cache DNS" }
    if ($chkDISM.Checked)      { $actions += "Nettoyage des composants Windows (DISM)" }
    if ($actions.Count -eq 0)  { Log "Aucune option cochée."; return }
    if (-not (Confirm-Actions "Nettoyage" $actions)) { Log "Nettoyage annulé."; return }

    $avant = (Get-PSDrive C).Free
    if ($chkTempUser.Checked) { Log "Nettoyage %TEMP%..."; Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue }
    if ($chkTempWin.Checked)  { Log "Nettoyage C:\Windows\Temp..."; Remove-Item "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue }
    if ($chkWU.Checked) {
        Log "Nettoyage du cache Windows Update..."
        Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
        Start-Service wuauserv -ErrorAction SilentlyContinue
    }
    if ($chkCorbeille.Checked) { Log "Vidage de la corbeille..."; Clear-RecycleBin -Force -ErrorAction SilentlyContinue }
    if ($chkDNS.Checked) { Log "Vidage du cache DNS..."; ipconfig /flushdns | Out-Null }
    if ($chkDISM.Checked) {
        Log "Nettoyage DISM en cours (patientez, cela peut prendre plusieurs minutes)..."
        Start-Process Dism.exe -ArgumentList "/Online","/Cleanup-Image","/StartComponentCleanup" -Wait -NoNewWindow
    }
    $libere = [math]::Round((((Get-PSDrive C).Free) - $avant) / 1MB, 0)
    if ($libere -lt 0) { $libere = 0 }
    Log "Nettoyage terminé. Espace libéré : environ $libere Mo."
})

# ========================= Onglet 3 : Performance =========================
$tabPerf = New-Tab "Performance"
$chkPlan   = New-Check $tabPerf "Activer le plan d'alimentation 'Performances élevées'" 15 15
$chkVisuel = New-Check $tabPerf "Effets visuels : 'Meilleures performances' (effet après reconnexion)" 15 45

$btnPerf = New-Bouton $tabPerf "Appliquer" 15 90
$btnPerf.Add_Click({
    $actions = @()
    if ($chkPlan.Checked)   { $actions += "Activer le plan d'alimentation 'Performances élevées'" }
    if ($chkVisuel.Checked) { $actions += "Effets visuels sur 'Meilleures performances'" }
    if ($actions.Count -eq 0) { Log "Aucune option cochée."; return }
    if (-not (Confirm-Actions "Performance" $actions)) { Log "Opération annulée."; return }

    if ($chkPlan.Checked) {
        powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>$null
        Log "Plan 'Performances élevées' activé."
    }
    if ($chkVisuel.Checked) {
        Set-RegValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting" 2
        Log "Effets visuels réglés sur 'Meilleures performances'."
    }
    Log "Optimisations de performance appliquées."
})

$btnStartup = New-Bouton $tabPerf "Gérer les applications au démarrage" 15 140 300
$btnStartup.Add_Click({
    Start-Process taskmgr -ArgumentList "/0 /startup" -ErrorAction SilentlyContinue
    Log "Gestionnaire des tâches ouvert (onglet Démarrage)."
})

# ========================= Onglet 4 : Confidentialite =========================
$tabPriv = New-Tab "Confidentialité"
$chkTelem = New-Check $tabPriv "Réduire la télémétrie au minimum + désactiver le service DiagTrack" 15 15
$chkPub   = New-Check $tabPriv "Désactiver l'identifiant publicitaire" 15 45
$chkSugg  = New-Check $tabPriv "Désactiver les suggestions / pubs (menu Démarrer, écran de verrouillage)" 15 75
$chkTailo = New-Check $tabPriv "Désactiver les expériences personnalisées" 15 105

$btnPriv = New-Bouton $tabPriv "Appliquer" 15 150
$btnPriv.Add_Click({
    $actions = @()
    if ($chkTelem.Checked) { $actions += "Télémétrie au minimum + service DiagTrack désactivé" }
    if ($chkPub.Checked)   { $actions += "Identifiant publicitaire désactivé" }
    if ($chkSugg.Checked)  { $actions += "Suggestions / pubs désactivées" }
    if ($chkTailo.Checked) { $actions += "Expériences personnalisées désactivées" }
    if ($actions.Count -eq 0) { Log "Aucune option cochée."; return }
    if (-not (Confirm-Actions "Confidentialité" $actions)) { Log "Opération annulée."; return }

    if ($chkTelem.Checked) {
        Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0
        Stop-Service DiagTrack -Force -ErrorAction SilentlyContinue
        Set-Service DiagTrack -StartupType Disabled -ErrorAction SilentlyContinue
        Log "Télémétrie réduite, service DiagTrack désactivé."
    }
    if ($chkPub.Checked) {
        Set-RegValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
        Log "Identifiant publicitaire désactivé."
    }
    if ($chkSugg.Checked) {
        $cdm = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
        foreach ($n in "SubscribedContent-338387Enabled","SubscribedContent-338388Enabled",
                       "SubscribedContent-338389Enabled","SubscribedContent-353694Enabled",
                       "SubscribedContent-353696Enabled","SystemPaneSuggestionsEnabled",
                       "SilentInstalledAppsEnabled","SoftLandingEnabled") {
            Set-RegValue $cdm $n 0
        }
        Log "Suggestions et publicités désactivées."
    }
    if ($chkTailo.Checked) {
        Set-RegValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" "TailoredExperiencesWithDiagnosticDataEnabled" 0
        Log "Expériences personnalisées désactivées."
    }
    Log "Réglages de confidentialité appliqués."
})

# ========================= Onglet 5 : Interface =========================
$tabUI = New-Tab "Interface"
$chkExt    = New-Check $tabUI "Afficher les extensions de fichiers" 15 15
$chkCaches = New-Check $tabUI "Afficher les fichiers cachés" 15 45 $false
$chkGauche = New-Check $tabUI "Aligner la barre des tâches à gauche (Windows 11)" 15 75 $false
$chkWidget = New-Check $tabUI "Masquer les widgets de la barre des tâches (Windows 11)" 15 105 $false
$chkSearch = New-Check $tabUI "Réduire la zone de recherche à une simple icône" 15 135 $false
$chkCePC   = New-Check $tabUI "Ouvrir l'Explorateur sur 'Ce PC' au lieu de l'Accueil" 15 165 $false

$btnUI = New-Bouton $tabUI "Appliquer + redémarrer l'Explorateur" 15 210 300
$btnUI.Add_Click({
    $actions = @()
    if ($chkExt.Checked)    { $actions += "Afficher les extensions de fichiers" }
    if ($chkCaches.Checked) { $actions += "Afficher les fichiers cachés" }
    if ($chkGauche.Checked) { $actions += "Barre des tâches à gauche" }
    if ($chkWidget.Checked) { $actions += "Masquer les widgets" }
    if ($chkSearch.Checked) { $actions += "Recherche réduite à une icône" }
    if ($chkCePC.Checked)   { $actions += "Explorateur ouvre 'Ce PC'" }
    if ($actions.Count -eq 0) { Log "Aucune option cochée."; return }
    $actions += "Redémarrage de l'Explorateur"
    if (-not (Confirm-Actions "Interface" $actions)) { Log "Opération annulée."; return }

    $adv = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    if ($chkExt.Checked)    { Set-RegValue $adv "HideFileExt" 0; Log "Extensions de fichiers visibles." }
    if ($chkCaches.Checked) { Set-RegValue $adv "Hidden" 1; Log "Fichiers cachés visibles." }
    if ($chkGauche.Checked) { Set-RegValue $adv "TaskbarAl" 0; Log "Barre des tâches alignée à gauche." }
    if ($chkWidget.Checked) { Set-RegValue $adv "TaskbarDa" 0; Log "Widgets masqués." }
    if ($chkSearch.Checked) { Set-RegValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" "SearchboxTaskbarMode" 1; Log "Recherche réduite à une icône." }
    if ($chkCePC.Checked)   { Set-RegValue $adv "LaunchTo" 1; Log "Explorateur ouvrira 'Ce PC'." }
    Stop-Process -Name explorer -Force
    Log "Explorateur redémarré. Tweaks d'interface appliqués."
})

# ------------------------- Lancement -------------------------
Log "OptiWin prêt - par Dona By. Sélectionnez un onglet puis appliquez les actions souhaitées."
[void]$form.ShowDialog()
