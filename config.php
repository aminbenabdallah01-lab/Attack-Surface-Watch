<?php
/**
 * Configuration centrale de la plateforme.
 * Modifie directement les valeurs ci-dessous selon ton environnement XAMPP.
 */

// --- Base de données ---
define('DB_HOST', 'localhost');
define('DB_NAME', 'attack_surface_platform');
define('DB_USER', 'root');
define('DB_PASS', ''); // XAMPP par défaut : pas de mot de passe

// --- Application ---
define('APP_NAME', 'Attack Surface Watch');
define('APP_DEBUG', true); // mets à false en production
date_default_timezone_set('Africa/Tunis');

// Chemin vers l'exécutable PHP CLI (nécessaire pour lancer les scans en
// arrière-plan et pouvoir les annuler). Sur XAMPP, c'est C:\xampp\php\php.exe
// — PAS le même binaire que celui qui exécute ce site web (Apache utilise
// souvent un mode différent, php-cgi ou le module intégré).
define('PHP_CLI_PATH', 'C:\\xampp\\php\\php.exe');

// --- API NVD (CVE matching) ---
// Clé recommandée : https://nvd.nist.gov/developers/request-an-api-key
define('NVD_API_KEY', '');
define('NVD_BASE_URL', 'https://services.nvd.nist.gov/rest/json/cves/2.0');

// --- SMTP (alertes email, ex: Gmail App Password comme pour SecuriNets) ---
define('SMTP_HOST', 'smtp.gmail.com');
define('SMTP_PORT', 587);
define('SMTP_USER', '');
define('SMTP_PASS', '');
define('SMTP_FROM_EMAIL', 'alerts@example.com');
define('SMTP_FROM_NAME', 'Attack Surface Watch');

// --- Outils système ---
define('NMAP_PATH', 'C:\\Program Files (x86)\\Nmap\\nmap.exe'); // adapte selon ton install Windows/Linux
// IMPORTANT : --top-ports N se base sur des statistiques de fréquence Internet
// et NE COUVRE PAS les ports de dev/app courants (ex: 3000 = Juice Shop par
// défaut, 5173 = Vite, 8080/8081, etc.). On utilise donc une liste explicite
// combinant les ports "infra" classiques + les ports "app/dev" courants,
// pour ne rater aucun service réel lors d'un scan.
define(
    'NMAP_FLAGS',
    '-sV --version-light -T4 -Pn --max-retries 1 --host-timeout 120s -p 21,22,23,25,53,80,81,110,111,135,139,143,443,445,465,587,631,993,995,1433,1521,1723,2049,3000,3001,3128,3306,3389,4200,4443,5000,5001,5432,5601,5900,5984,6379,7000,7001,7474,8000,8008,8080,8081,8082,8443,8888,9000,9042,9090,9200,9300,9999,11211,27017,27018,50000'
);
// --- Brute-force DNS (découverte active de sous-domaines) ---
define('DNS_BRUTEFORCE_ENABLED', true);
define('DNS_WORDLIST_PATH', __DIR__ . '/subdomains_wordlist.txt');

if (APP_DEBUG) {
    error_reporting(E_ALL);
    ini_set('display_errors', '1');
} else {
    error_reporting(0);
    ini_set('display_errors', '0');
}
