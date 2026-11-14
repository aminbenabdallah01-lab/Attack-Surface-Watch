<?php
require_once __DIR__ . '/config.php';

/**
 * Découverte des actifs pour un domaine cible :
 *   0) Le domaine racine lui-même est TOUJOURS inclus en premier — c'est
 *      l'actif principal demandé par l'utilisateur, il doit toujours être
 *      analysé même si crt.sh/bruteforce ne trouvent rien (cas fréquent
 *      pour un domaine local/interne comme juiceshop.local).
 *   1) Passive -> Certificate Transparency logs (crt.sh) — utile seulement
 *      pour les domaines publics, ignoré silencieusement si le domaine
 *      n'est pas résolvable publiquement.
 *   2) Active  -> Brute-force DNS avec wordlist
 *
 * @return array [['hostname'=>'juiceshop.local','source'=>'root'], ...]
 */
function enumerate_subdomains(string $rootDomain): array
{
    $results = [];

    // 0) Le domaine cible lui-même, toujours en premier.
    $results[$rootDomain] = ['hostname' => $rootDomain, 'source' => 'root'];

    // 1) Passif (crt.sh) — n'a de sens que pour un domaine public avec
    // certificats TLS publics. Échoue silencieusement pour .local/interne.
    foreach (passive_crtsh($rootDomain) as $host) {
        if (!isset($results[$host])) {
            $results[$host] = ['hostname' => $host, 'source' => 'crtsh'];
        }
    }

    // 2) Actif (bruteforce DNS)
    if (DNS_BRUTEFORCE_ENABLED) {
        foreach (active_dns_bruteforce($rootDomain) as $host) {
            if (!isset($results[$host])) {
                $results[$host] = ['hostname' => $host, 'source' => 'dns_bruteforce'];
            }
        }
    }

    return array_values($results);
}

function passive_crtsh(string $rootDomain): array
{
    $url = 'https://crt.sh/?q=%25.' . urlencode($rootDomain) . '&output=json';

    $context = stream_context_create([
        'http' => ['timeout' => 8, 'header' => "User-Agent: AttackSurfacePlatform/1.0\r\n"],
        'ssl'  => ['verify_peer' => true, 'verify_peer_name' => true],
    ]);

    $raw = @file_get_contents($url, false, $context);
    if ($raw === false) {
        // Normal pour un domaine local/interne : pas de certificat TLS public.
        return [];
    }

    $data = json_decode($raw, true);
    if (!is_array($data)) {
        return [];
    }

    $hostnames = [];
    foreach ($data as $entry) {
        $names = explode("\n", $entry['name_value'] ?? '');
        foreach ($names as $name) {
            $name = strtolower(trim($name));
            if ($name === '' || str_starts_with($name, '*.')) {
                continue;
            }
            if (str_ends_with($name, $rootDomain)) {
                $hostnames[$name] = true;
            }
        }
    }

    return array_keys($hostnames);
}

function active_dns_bruteforce(string $rootDomain): array
{
    if (!file_exists(DNS_WORDLIST_PATH)) {
        error_log("[subdomain_enum] Wordlist introuvable : " . DNS_WORDLIST_PATH);
        return [];
    }

    $words = file(DNS_WORDLIST_PATH, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $found = [];

    foreach ($words as $word) {
        $word = trim($word);
        if ($word === '') {
            continue;
        }
        $candidate = $word . '.' . $rootDomain;

        if (host_resolves($candidate)) {
            $found[] = $candidate;
        }
    }

    return $found;
}

/**
 * Résout un hostname en IP(s). Combine deux méthodes pour couvrir à la fois :
 *   - les domaines publics (dns_get_record : requêtes DNS classiques)
 *   - les domaines locaux/internes résolus via /etc/hosts ou un DNS local
 *     (gethostbyname : utilise le résolveur du système d'exploitation, qui
 *     lit /etc/hosts ou C:\Windows\System32\drivers\etc\hosts en premier)
 * C'est ce deuxième mécanisme qui manquait pour scanner correctement un
 * domaine comme "juiceshop.local" ajouté manuellement au fichier hosts.
 */
function resolve_ips(string $hostname): array
{
    $ips = [];

    $aRecords = @dns_get_record($hostname, DNS_A);
    foreach ($aRecords ?: [] as $r) {
        if (!empty($r['ip'])) {
            $ips[] = $r['ip'];
        }
    }

    $aaaaRecords = @dns_get_record($hostname, DNS_AAAA);
    foreach ($aaaaRecords ?: [] as $r) {
        if (!empty($r['ipv6'])) {
            $ips[] = $r['ipv6'];
        }
    }

    // Fallback résolveur système (couvre /etc/hosts, DNS local, .local, etc.)
    if (empty($ips)) {
        $resolved = @gethostbyname($hostname);
        // gethostbyname renvoie le hostname tel quel s'il n'a pas pu résoudre
        if ($resolved !== $hostname && filter_var($resolved, FILTER_VALIDATE_IP)) {
            $ips[] = $resolved;
        }
    }

    return array_unique($ips);
}

/**
 * Vérifie si un hostname résout (DNS public OU résolveur système/hosts).
 * Utilisé par le bruteforce pour ne garder que les sous-domaines réels.
 */
function host_resolves(string $hostname): bool
{
    if (checkdnsrr($hostname, 'A') || checkdnsrr($hostname, 'AAAA')) {
        return true;
    }
    $resolved = @gethostbyname($hostname);
    return $resolved !== $hostname && filter_var($resolved, FILTER_VALIDATE_IP);
}
