
<?php

require_once __DIR__ . '/config.php';

/**
 * Découverte des actifs pour un domaine cible.
 *
 * 0) Le domaine racine est toujours inclus.
 * 1) Passive discovery via crt.sh (domaines publics uniquement).
 * 2) Active DNS brute-force avec wordlist.
 *
 * @return array
 */
function enumerate_subdomains(string $rootDomain): array
{
    $rootDomain = strtolower(trim($rootDomain));

    if (!is_valid_hostname($rootDomain)) {
        return [];
    }

    $results = [];

    // 0) Always include the root domain.
    $results[$rootDomain] = [
        'hostname' => $rootDomain,
        'source' => 'root'
    ];

    // 1) Passive discovery via crt.sh.
    foreach (passive_crtsh($rootDomain) as $host) {
        if (!isset($results[$host])) {
            $results[$host] = [
                'hostname' => $host,
                'source' => 'crtsh'
            ];
        }
    }

    // 2) Active DNS brute-force.
    if (DNS_BRUTEFORCE_ENABLED) {
        foreach (active_dns_bruteforce($rootDomain) as $host) {
            if (!isset($results[$host])) {
                $results[$host] = [
                    'hostname' => $host,
                    'source' => 'dns_bruteforce'
                ];
            }
        }
    }

    return array_values($results);
}

/**
 * Validate hostname syntax.
 */
function is_valid_hostname(string $hostname): bool
{
    $hostname = strtolower(trim($hostname));

    if (
        $hostname === '' ||
        strlen($hostname) > 253 ||
        str_contains($hostname, '@') ||
        str_contains($hostname, ' ') ||
        str_contains($hostname, "\n") ||
        str_contains($hostname, "\r")
    ) {
        return false;
    }

    // Reject IP addresses.
    if (filter_var($hostname, FILTER_VALIDATE_IP)) {
        return false;
    }

    // Reject wildcard hostnames.
    if (str_contains($hostname, '*')) {
        return false;
    }

    $labels = explode('.', $hostname);

    foreach ($labels as $label) {
        if (
            $label === '' ||
            strlen($label) > 63 ||
            !preg_match(
                '/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/',
                $label
            )
        ) {
            return false;
        }
    }

    return true;
}

/**
 * Check whether a hostname belongs to the target domain.
 */
function is_subdomain_of(string $hostname, string $rootDomain): bool
{
    $hostname = strtolower(trim($hostname));
    $rootDomain = strtolower(trim($rootDomain));

    return (
        $hostname === $rootDomain ||
        str_ends_with($hostname, '.' . $rootDomain)
    );
}

/**
 * Passive discovery using Certificate Transparency logs.
 * Disabled for local and private domains.
 */
function passive_crtsh(string $rootDomain): array
{
    $rootDomain = strtolower(trim($rootDomain));

    if (
        !is_valid_hostname($rootDomain) ||
        $rootDomain === 'localhost' ||
        !str_contains($rootDomain, '.') ||
        str_ends_with($rootDomain, '.local') ||
        str_ends_with($rootDomain, '.localhost')
    ) {
        return [];
    }

    // Correct crt.sh query.
    $url = 'https://crt.sh/?q=%25.' .
        urlencode($rootDomain) .
        '&output=json';

    $context = stream_context_create([
        'http' => [
            'timeout' => 8,
            'header' => "User-Agent: AttackSurfacePlatform/1.0\r\n"
        ],
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true
        ],
    ]);

    $raw = @file_get_contents($url, false, $context);

    if ($raw === false) {
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

            // Ignore empty and wildcard entries.
            if ($name === '' || str_starts_with($name, '*.')) {
                continue;
            }

            // Validate hostname syntax.
            if (!is_valid_hostname($name)) {
                continue;
            }

            // Keep only the root domain and its real subdomains.
            if (!is_subdomain_of($name, $rootDomain)) {
                continue;
            }

            $hostnames[$name] = true;
        }
    }

    return array_keys($hostnames);
}

/**
 * Active DNS brute-force using the configured wordlist.
 */
function active_dns_bruteforce(string $rootDomain): array
{
    if (!is_valid_hostname($rootDomain)) {
        return [];
    }

    if (!file_exists(DNS_WORDLIST_PATH)) {
        error_log(
            "[subdomain_enum] Wordlist introuvable : " .
            DNS_WORDLIST_PATH
        );

        return [];
    }

    $words = file(
        DNS_WORDLIST_PATH,
        FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES
    );

    if (!is_array($words)) {
        return [];
    }

    $found = [];

    foreach ($words as $word) {
        $word = strtolower(trim($word));

        // Wordlist entries must be single DNS labels.
        if (
            $word === '' ||
            str_contains($word, '.') ||
            !preg_match(
                '/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/',
                $word
            )
        ) {
            continue;
        }

        $candidate = $word . '.' . $rootDomain;

        if (
            is_valid_hostname($candidate) &&
            host_resolves($candidate)
        ) {
            $found[$candidate] = true;
        }
    }

    return array_keys($found);
}

/**
 * Resolve a hostname into IPv4 and IPv6 addresses.
 *
 * Supports:
 * - Public DNS
 * - Local DNS
 * - Windows hosts file
 * - Linux /etc/hosts
 */
function resolve_ips(string $hostname): array
{
    $hostname = strtolower(trim($hostname));

    if (!is_valid_hostname($hostname)) {
        return [];
    }

    $ips = [];

    // IPv4 records.
    $aRecords = @dns_get_record($hostname, DNS_A);

    foreach ($aRecords ?: [] as $record) {
        if (
            !empty($record['ip']) &&
            filter_var($record['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
        ) {
            $ips[] = $record['ip'];
        }
    }

    // IPv6 records.
    $aaaaRecords = @dns_get_record($hostname, DNS_AAAA);

    foreach ($aaaaRecords ?: [] as $record) {
        if (
            !empty($record['ipv6']) &&
            filter_var($record['ipv6'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)
        ) {
            $ips[] = $record['ipv6'];
        }
    }

    // System resolver fallback.
    if (empty($ips)) {
        $resolved = @gethostbyname($hostname);

        if (
            $resolved !== $hostname &&
            filter_var($resolved, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
        ) {
            $ips[] = $resolved;
        }
    }

    return array_values(array_unique($ips));
}

/**
 * Check whether a hostname resolves.
 */
function host_resolves(string $hostname): bool
{
    $hostname = strtolower(trim($hostname));

    if (!is_valid_hostname($hostname)) {
        return false;
    }

    return !empty(resolve_ips($hostname));
}
