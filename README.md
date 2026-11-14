# Attack Surface Watch

Plateforme de cartographie automatisée de la surface d'attaque et de veille
sur les vulnérabilités. Structure plate (tout dans un seul dossier), en PHP
vanilla, pensée pour XAMPP.

## ⚠️ Légal / éthique

N'utilise cet outil QUE sur des domaines pour lesquels tu as une autorisation
explicite (ta propre infra, un scope de bug bounty signé, ou un mandat de
pentest).

## Structure

```
attack-surface/
├── config.php              # Toute la config (DB, NVD, SMTP, nmap) — à éditer
├── db.php                   # Connexion PDO
├── auth.php                  # Fonctions de session/login
├── subdomain_enum.php        # Découverte sous-domaines (crt.sh + DNS bruteforce)
├── port_scanner.php          # Scan de ports via Nmap
├── tech_detector.php         # Détection technologies web
├── cve_matcher.php           # Matching CVE via API NVD
├── alert_notifier.php        # Alertes email/webhook
├── scan_orchestrator.php     # Orchestre le pipeline complet
├── index.php                 # Redirige vers login ou dashboard
├── login.php / logout.php
├── dashboard.php             # Liste des organisations suivies
├── organization.php          # Détail : actifs, vulnérabilités, graphe
├── run_scan.php               # Déclenche un scan (appelé en POST)
├── schema.sql                # Schéma SQL complet
├── seed.php                   # Crée un admin + une org de démo
├── subdomains_wordlist.txt
├── css/style.css
└── js/graph.js
```

1. Ouvre un terminal dans le dossier du projet, lance :
   ```
   C:\xampp\php\php.exe seed.php
   ```
2. Ouvre `http://localhost/attack-surface/login.php`
   - Email : `admin@securinets.local`
   - Mot de passe : `ChangeMe123!`

Identifiants DB par défaut dans `config.php` (déjà réglés pour XAMPP :
`root` / mot de passe vide). Si t'as mis un mot de passe root MySQL,
modifie `DB_PASS` dans `config.php`.

## Nmap (pour le scan de ports)

Nmap ne vient pas avec XAMPP. Installe-le séparément :
https://nmap.org/download.html

Puis dans `config.php`, vérifie que `NMAP_PATH` pointe vers le bon exécutable,
ex : `C:\\Program Files (x86)\\Nmap\\nmap.exe`

## Scan planifié (veille automatique)

Avec le Planificateur de tâches Windows, ou via cron sous Linux/Mac :
```
0 2 * * * php /chemin/vers/attack-surface/run_scan_cli.php
```
(si tu veux un scan automatique de toutes les organisations, dis-le-moi et
je crée `run_scan_cli.php` — pour l'instant `run_scan.php` est fait pour
être appelé depuis le dashboard via un bouton).

## Notes techniques

- Toutes les requêtes SQL passent par PDO en prepared statements
- `port_scanner.php` utilise `escapeshellarg`/`escapeshellcmd` avant tout `exec()`
- CSS et JS sont dans des fichiers séparés (`css/style.css`, `js/graph.js`),
  chargés via des chemins **relatifs** (`css/style.css`, pas `/css/style.css`)
  pour éviter les soucis de path si tu déplaces le dossier
- Testé en local (PHP 8.3 + MariaDB) : login → dashboard → détail
  organisation → CSS/JS, tout fonctionne de bout en bout
