<?php

require_once __DIR__ . '/config.php';

/**
 * CVE Matcher
 *
 * Pipeline:
 * Product + Version
 *       ↓
 * NVD API 2.0
 *       ↓
 * CPE structured data
 *       ↓
 * Version validation
 *       ↓
 * CVE results
 *
 * Compatible with scan_orchestrator.php
 *
 * find_vulnerabilities() returns:
 *
 * [
 *     'status'  => 'ok' | 'no_version' | 'no_match' | 'error',
 *     'results' => [...]
 * ]
 */


/**
 * Mini-dictionnaire CPE pour les produits les plus courants détectés par
 * le scanner (nmap fingerprinting + tech_detector.php). Permet d'utiliser
 * virtualMatchString (matching exact côté serveur NVD) au lieu de
 * keywordSearch (texte libre, peu fiable) quand le produit est reconnu.
 *
 * Clé = normalize_product_name() du produit détecté
 * Valeur = ['vendor' => ..., 'product' => ...] tels qu'utilisés dans les
 * CPE officiels NVD (cpe:2.3:a:VENDOR:PRODUCT:VERSION:...)
 */
function get_known_cpe_map(): array
{
    return [
        'http server'  => ['vendor' => 'apache', 'product' => 'http_server'],
        'nginx'        => ['vendor' => 'nginx', 'product' => 'nginx'],
        'mysql'        => ['vendor' => 'mysql', 'product' => 'mysql'],
        'mariadb'      => ['vendor' => 'mariadb', 'product' => 'mariadb'],
        'php'          => ['vendor' => 'php', 'product' => 'php'],
        'openssh'      => ['vendor' => 'openbsd', 'product' => 'openssh'],
        'wordpress'    => ['vendor' => 'wordpress', 'product' => 'wordpress'],
        'nodejs'       => ['vendor' => 'nodejs', 'product' => 'node.js'],
        'express'      => ['vendor' => 'expressjs', 'product' => 'express'],
        'postgresql'   => ['vendor' => 'postgresql', 'product' => 'postgresql'],
        'mongodb'      => ['vendor' => 'mongodb', 'product' => 'mongodb'],
        'redis'        => ['vendor' => 'redis', 'product' => 'redis'],
        'tomcat'       => ['vendor' => 'apache', 'product' => 'tomcat'],
        'jquery'       => ['vendor' => 'jquery', 'product' => 'jquery'],
        'drupal'       => ['vendor' => 'drupal', 'product' => 'drupal'],
        'joomla'       => ['vendor' => 'joomla', 'product' => 'joomla'],
        'proftpd'      => ['vendor' => 'proftpd', 'product' => 'proftpd'],
        'vsftpd'       => ['vendor' => 'vsftpd', 'product' => 'vsftpd'],
        'samba'        => ['vendor' => 'samba', 'product' => 'samba'],
    ];
}

/**
 * Cherche le CPE officiel connu pour un produit détecté. Retourne null si
 * inconnu (dans ce cas find_vulnerabilities() retombe sur keywordSearch).
 */
function lookup_known_cpe(string $product): ?array
{
    $normalized = normalize_product_name($product);
    $map = get_known_cpe_map();
    return $map[$normalized] ?? null;
}


/**
 * Recherche les vulnérabilités NVD correspondant à un produit/version.
 */
function find_vulnerabilities(string $product, ?string $version): array
{
    $product = trim($product);
    $version = $version !== null ? trim($version) : null;

    if ($product === '') {
        return [
            'status' => 'error',
            'results' => []
        ];
    }

    if ($version === null || $version === '' || $version === 'unknown') {
        return [
            'status' => 'no_version',
            'results' => []
        ];
    }

    /*
     * IMPORTANT :
     * NVD keywordSearch (recherche texte libre) est peu fiable : elle exige
     * que TOUS les mots apparaissent littéralement dans la description du
     * CVE. "Apache httpd 2.4.58" échoue souvent car NVD écrit "Apache HTTP
     * Server" dans ses descriptions, pas "httpd" — résultat : 0 CVE trouvée
     * alors que le produit/version est réellement vulnérable.
     *
     * Solution : quand on connaît le CPE officiel (vendor:product) du
     * produit détecté, on utilise virtualMatchString — NVD fait alors le
     * matching CPE + plage de versions côté serveur, de façon exacte et
     * fiable. On ne retombe sur keywordSearch qu'en dernier recours pour
     * les produits qu'on ne reconnaît pas.
     */
    $cpeInfo = lookup_known_cpe($product);
    $keyword = $product . ' ' . $version; // utilisé pour les logs d'erreur quelle que soit la stratégie

    if ($cpeInfo !== null) {
        $virtualMatchString = "cpe:2.3:a:{$cpeInfo['vendor']}:{$cpeInfo['product']}:{$version}:*:*:*:*:*:*:*";
        $query = http_build_query([
            'virtualMatchString' => $virtualMatchString,
            'resultsPerPage' => 50
        ]);
    } else {
        $query = http_build_query([
            'keywordSearch' => $keyword,
            'resultsPerPage' => 50
        ]);
    }

    $url = NVD_BASE_URL . '?' . $query;

    $headers = [
        'User-Agent: AttackSurfaceWatch/1.0'
    ];

    if (defined('NVD_API_KEY') && NVD_API_KEY !== '') {
        $headers[] = 'apiKey: ' . NVD_API_KEY;
    }

    $ch = curl_init($url);

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);

    $raw = curl_exec($ch);

    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);

    curl_close($ch);

    if ($raw === false) {
        error_log("[cve_matcher] NVD request failed for '{$keyword}': {$curlError}");
        return [
            'status' => 'error',
            'results' => []
        ];
    }

    if ($httpCode < 200 || $httpCode >= 300) {
        error_log("[cve_matcher] NVD HTTP {$httpCode} for '{$keyword}'");
        return [
            'status' => 'error',
            'results' => []
        ];
    }

    $data = json_decode($raw, true);

    if (!is_array($data)) {
        error_log("[cve_matcher] Invalid JSON returned by NVD for '{$keyword}'");
        return [
            'status' => 'error',
            'results' => []
        ];
    }

    if (
        !isset($data['vulnerabilities']) ||
        !is_array($data['vulnerabilities'])
    ) {
        return [
            'status' => 'no_match',
            'results' => []
        ];
    }

    $results = [];

    foreach ($data['vulnerabilities'] as $item) {

        if (!isset($item['cve']) || !is_array($item['cve'])) {
            continue;
        }

        $cve = $item['cve'];
        $cveId = $cve['id'] ?? null;

        if (!$cveId) {
            continue;
        }

        $match = cve_matches_product_and_version($cve, $product, $version);

        if (!$match['matched']) {
            continue;
        }

        $score = extract_cvss_score($cve);
        $description = extract_cve_description($cve);

        $publishedAt = null;
        if (!empty($cve['published'])) {
            $publishedAt = substr($cve['published'], 0, 10);
        }

        $results[] = [
            'cve_id' => $cveId,
            'cvss_score' => $score,
            'severity' => score_to_severity($score),
            'description' => $description,
            'published_at' => $publishedAt,
            'confidence' => 'high',
            'match_reason' => $match['reason'],
        ];
    }

    if (empty($results)) {
        return [
            'status' => 'no_match',
            'results' => []
        ];
    }

    $unique = [];
    foreach ($results as $result) {
        $unique[$result['cve_id']] = $result;
    }

    return [
        'status' => 'ok',
        'results' => array_values($unique)
    ];
}


/**
 * Vérifie le produit ET la version dans les CPE structurés NVD.
 * Exemple CPE: cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*
 */
function cve_matches_product_and_version(array $cve, string $product, string $detectedVersion): array
{
    $configurations = $cve['configurations'] ?? [];

    if (!is_array($configurations)) {
        return ['matched' => false, 'reason' => ''];
    }

    $productNormalized = normalize_product_name($product);

    foreach ($configurations as $configuration) {
        foreach ($configuration['nodes'] ?? [] as $node) {
            foreach ($node['cpeMatch'] ?? [] as $cpeMatch) {

                $criteria = $cpeMatch['criteria'] ?? '';
                if ($criteria === '') {
                    continue;
                }

                $cpeData = parse_cpe_23($criteria);
                if ($cpeData === null) {
                    continue;
                }

                $cpeProduct = normalize_product_name($cpeData['product']);
                $cpeVersion = $cpeData['version'];

                if (!products_match($productNormalized, $cpeProduct)) {
                    continue;
                }

                $versionMatch = version_matches_cpe($detectedVersion, $cpeVersion, $cpeMatch);
                if (!$versionMatch) {
                    continue;
                }

                return [
                    'matched' => true,
                    'reason' => "CPE NVD confirme {$product} {$detectedVersion}"
                ];
            }
        }
    }

    return ['matched' => false, 'reason' => ''];
}


/**
 * Parse un CPE 2.3.
 * Exemple: cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*
 */
function parse_cpe_23(string $cpe): ?array
{
    if (!str_starts_with($cpe, 'cpe:2.3:')) {
        return null;
    }

    $parts = explode(':', $cpe);

    if (count($parts) < 6) {
        return null;
    }

    return [
        'part' => $parts[2] ?? '',
        'vendor' => $parts[3] ?? '',
        'product' => $parts[4] ?? '',
        'version' => $parts[5] ?? '',
    ];
}


/**
 * Normalisation des noms de produits.
 */
function normalize_product_name(string $product): string
{
    $product = strtolower(trim($product));

    $product = str_replace(['\\', '_', '-', '.'], ' ', $product);

    $aliases = [
        'apache httpd' => 'http server',
        'apache http server' => 'http server',
        'apache2' => 'http server',
        'node js' => 'nodejs',
        'node.js' => 'nodejs',
        'mariadb server' => 'mariadb',
        'mysql server' => 'mysql',
    ];

    foreach ($aliases as $from => $to) {
        if ($product === $from) {
            $product = $to;
        }
    }

    $product = preg_replace('/\s+/', ' ', $product);

    return trim($product);
}


/**
 * Compare deux noms de produits.
 */
function products_match(string $detectedProduct, string $cpeProduct): bool
{
    if ($detectedProduct === '' || $cpeProduct === '') {
        return false;
    }

    if ($detectedProduct === $cpeProduct) {
        return true;
    }

    $detectedTokens = preg_split('/\s+/', $detectedProduct);
    $cpeTokens = preg_split('/\s+/', $cpeProduct);

    $detectedTokens = array_filter($detectedTokens, fn($token) => strlen($token) >= 3);
    $cpeTokens = array_filter($cpeTokens, fn($token) => strlen($token) >= 3);

    if (empty($detectedTokens) || empty($cpeTokens)) {
        return false;
    }

    $matches = 0;

    foreach ($cpeTokens as $token) {
        foreach ($detectedTokens as $detectedToken) {
            if (
                $token === $detectedToken ||
                str_contains($detectedToken, $token) ||
                str_contains($token, $detectedToken)
            ) {
                $matches++;
                break;
            }
        }
    }

    return $matches === count($cpeTokens);
}


/**
 * Vérifie si la version détectée correspond à la version affectée par le CPE.
 */
function version_matches_cpe(string $detectedVersion, string $cpeVersion, array $cpeMatch): bool
{
    $detectedVersion = trim($detectedVersion);
    $cpeVersion = trim($cpeVersion);

    if ($detectedVersion === '') {
        return false;
    }

    if ($cpeVersion === '*' || $cpeVersion === '-') {
        return version_is_in_range($detectedVersion, $cpeMatch);
    }

    if (normalize_version($detectedVersion) === normalize_version($cpeVersion)) {
        return true;
    }

    if (version_compare_safe($detectedVersion, $cpeVersion) === 0) {
        return true;
    }

    return false;
}


/**
 * Vérifie une plage de versions CPE.
 * NVD peut fournir: versionStartIncluding / versionStartExcluding /
 * versionEndIncluding / versionEndExcluding
 */
function version_is_in_range(string $version, array $cpeMatch): bool
{
    $startIncluding = $cpeMatch['versionStartIncluding'] ?? null;
    $startExcluding = $cpeMatch['versionStartExcluding'] ?? null;
    $endIncluding = $cpeMatch['versionEndIncluding'] ?? null;
    $endExcluding = $cpeMatch['versionEndExcluding'] ?? null;

    if (
        $startIncluding === null &&
        $startExcluding === null &&
        $endIncluding === null &&
        $endExcluding === null
    ) {
        return true;
    }

    if ($startIncluding !== null && version_compare_safe($version, $startIncluding) < 0) {
        return false;
    }

    if ($startExcluding !== null && version_compare_safe($version, $startExcluding) <= 0) {
        return false;
    }

    if ($endIncluding !== null && version_compare_safe($version, $endIncluding) > 0) {
        return false;
    }

    if ($endExcluding !== null && version_compare_safe($version, $endExcluding) >= 0) {
        return false;
    }

    return true;
}


/**
 * Normalise une version.
 */
function normalize_version(string $version): string
{
    $version = strtolower(trim($version));
    $version = preg_replace('/^(version|ver|v)\s*/i', '', $version);
    return trim($version);
}


/**
 * Compare deux versions de manière sécurisée.
 */
function version_compare_safe(string $versionA, string $versionB): int
{
    $a = normalize_version($versionA);
    $b = normalize_version($versionB);

    if ($a === $b) {
        return 0;
    }

    return version_compare($a, $b);
}


/**
 * Extrait le score CVSS.
 */
function extract_cvss_score(array $cve): ?float
{
    $metrics = $cve['metrics'] ?? [];

    foreach (['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV40', 'cvssMetricV2'] as $metricVersion) {
        if (!empty($metrics[$metricVersion]) && is_array($metrics[$metricVersion])) {
            foreach ($metrics[$metricVersion] as $metric) {
                if (isset($metric['cvssData']['baseScore'])) {
                    return (float) $metric['cvssData']['baseScore'];
                }
            }
        }
    }

    return null;
}


/**
 * Convertit un score CVSS en niveau de sévérité.
 */
function score_to_severity(?float $score): string
{
    if ($score === null) {
        return 'medium';
    }
    if ($score >= 9.0) {
        return 'critical';
    }
    if ($score >= 7.0) {
        return 'high';
    }
    if ($score >= 4.0) {
        return 'medium';
    }
    return 'low';
}


/**
 * Extrait la description anglaise d'une CVE.
 */
function extract_cve_description(array $cve): ?string
{
    foreach ($cve['descriptions'] ?? [] as $description) {
        if (($description['lang'] ?? '') === 'en') {
            return $description['value'] ?? null;
        }
    }

    foreach ($cve['descriptions'] ?? [] as $description) {
        if (!empty($description['value'])) {
            return $description['value'];
        }
    }

    return null;
}


/**
 * Délai entre deux requêtes NVD.
 * Sans API key: ~6.5s. Avec API key: ~0.6s.
 */
function cve_throttle_delay_microseconds(): int
{
    if (defined('NVD_API_KEY') && NVD_API_KEY !== '') {
        return 600000;
    }
    return 6500000;
}
