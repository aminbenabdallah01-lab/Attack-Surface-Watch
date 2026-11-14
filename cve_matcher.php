
<?php

require_once __DIR__ . '/config.php';

/**
 * CVE Matcher - Attack Surface Watch
 *
 * Compatible with scan_orchestrator.php
 *
 * Return structure:
 * [
 *     'status'  => 'ok' | 'no_version' | 'no_match' | 'error',
 *     'results' => [...]
 * ]
 */


/* =========================================================
   1. KNOWN CPE PRODUCTS
========================================================= */

function get_known_cpe_map(): array
{
    return [
        'http server' => [
            'vendor' => 'apache',
            'product' => 'http_server'
        ],
        'nginx' => [
            'vendor' => 'nginx',
            'product' => 'nginx'
        ],
        'mysql' => [
            'vendor' => 'mysql',
            'product' => 'mysql'
        ],
        'mariadb' => [
            'vendor' => 'mariadb',
            'product' => 'mariadb'
        ],
        'php' => [
            'vendor' => 'php',
            'product' => 'php'
        ],
        'openssh' => [
            'vendor' => 'openbsd',
            'product' => 'openssh'
        ],
        'wordpress' => [
            'vendor' => 'wordpress',
            'product' => 'wordpress'
        ],
        'nodejs' => [
            'vendor' => 'nodejs',
            'product' => 'node.js'
        ],
        'express' => [
            'vendor' => 'expressjs',
            'product' => 'express'
        ],
        'postgresql' => [
            'vendor' => 'postgresql',
            'product' => 'postgresql'
        ],
        'mongodb' => [
            'vendor' => 'mongodb',
            'product' => 'mongodb'
        ],
        'redis' => [
            'vendor' => 'redis',
            'product' => 'redis'
        ],
        'tomcat' => [
            'vendor' => 'apache',
            'product' => 'tomcat'
        ],
        'jquery' => [
            'vendor' => 'jquery',
            'product' => 'jquery'
        ],
        'drupal' => [
            'vendor' => 'drupal',
            'product' => 'drupal'
        ],
        'joomla' => [
            'vendor' => 'joomla',
            'product' => 'joomla'
        ],
        'proftpd' => [
            'vendor' => 'proftpd',
            'product' => 'proftpd'
        ],
        'vsftpd' => [
            'vendor' => 'vsftpd',
            'product' => 'vsftpd'
        ],
        'samba' => [
            'vendor' => 'samba',
            'product' => 'samba'
        ],
    ];
}


function lookup_known_cpe(string $product): ?array
{
    $map = get_known_cpe_map();

    return $map[normalize_product_name($product)] ?? null;
}


/* =========================================================
   2. PRODUCT NORMALIZATION
========================================================= */

function normalize_product_name(string $product): string
{
    $product = strtolower(trim($product));

    $product = str_replace(
        ['\\', '_', '-', '.'],
        ' ',
        $product
    );

    $product = preg_replace('/\s+/', ' ', $product);

    $aliases = [
        'apache httpd' => 'http server',
        'apache http server' => 'http server',
        'apache2' => 'http server',
        'httpd' => 'http server',

        'node js' => 'nodejs',
        'node.js' => 'nodejs',

        'mariadb server' => 'mariadb',
        'mysql server' => 'mysql',

        'postgres' => 'postgresql',
    ];

    return trim($aliases[$product] ?? $product);
}


/**
 * Product-specific version normalization.
 *
 * Add a rule only when the product's version format
 * is known and verified.
 */
function normalize_detected_version(
    string $product,
    string $version
): string {

    $product = normalize_product_name($product);
    $version = trim($version);

    $versionRules = [
        'mariadb' => [
            'pattern' => '/^5\.5\.5-(\d+(?:\.\d+)+)(?:[-+].*)?$/i',
            'replacement' => '$1',
        ],
    ];

    if (isset($versionRules[$product])) {

        $rule = $versionRules[$product];

        $normalized = preg_replace(
            $rule['pattern'],
            $rule['replacement'],
            $version
        );

        if ($normalized !== null) {
            $version = $normalized;
        }
    }

    return normalize_version($version);
}


/* =========================================================
   3. MAIN CVE SEARCH
========================================================= */

function find_vulnerabilities(
    string $product,
    ?string $version
): array {

    $product = trim($product);

    if ($product === '') {
        return [
            'status' => 'error',
            'results' => []
        ];
    }

    if (
        $version === null ||
        trim($version) === '' ||
        strtolower(trim($version)) === 'unknown'
    ) {
        return [
            'status' => 'no_version',
            'results' => []
        ];
    }

    $version = normalize_detected_version(
        $product,
        $version
    );

    $cpeInfo = lookup_known_cpe($product);

    $keyword = $product . ' ' . $version;

    if ($cpeInfo !== null) {

        $virtualMatchString =
            "cpe:2.3:a:" .
            $cpeInfo['vendor'] . ":" .
            $cpeInfo['product'] . ":" .
            $version .
            ":*:*:*:*:*:*:*";

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

    if (
        defined('NVD_API_KEY') &&
        NVD_API_KEY !== ''
    ) {
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

    $httpCode = curl_getinfo(
        $ch,
        CURLINFO_HTTP_CODE
    );

    $curlError = curl_error($ch);

    curl_close($ch);

    if ($raw === false) {

        error_log(
            "[cve_matcher] NVD request failed for '{$keyword}': {$curlError}"
        );

        return [
            'status' => 'error',
            'results' => []
        ];
    }

    if ($httpCode < 200 || $httpCode >= 300) {

        error_log(
            "[cve_matcher] NVD HTTP {$httpCode} for '{$keyword}'"
        );

        return [
            'status' => 'error',
            'results' => []
        ];
    }

    $data = json_decode($raw, true);

    if (!is_array($data)) {

        error_log(
            "[cve_matcher] Invalid JSON returned by NVD"
        );

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

        if (
            !isset($item['cve']) ||
            !is_array($item['cve'])
        ) {
            continue;
        }

        $cve = $item['cve'];

        $cveId = $cve['id'] ?? null;

        if (!$cveId) {
            continue;
        }

        $match = cve_matches_product_and_version(
            $cve,
            $product,
            $version
        );

        if (!$match['matched']) {
            continue;
        }

        $score = extract_cvss_score($cve);

        $description = extract_cve_description($cve);

        $publishedAt = null;

        if (!empty($cve['published'])) {
            $publishedAt = substr(
                $cve['published'],
                0,
                10
            );
        }

        $results[] = [
            'cve_id' => $cveId,
            'cvss_score' => $score,
            'severity' => score_to_severity($score),
            'description' => $description,
            'published_at' => $publishedAt,

            // A version match is not proof of exploitability.
            'confidence' => 'medium',

            'match_reason' => $match['reason'],
        ];
    }

    if (empty($results)) {
        return [
            'status' => 'no_match',
            'results' => []
        ];
    }

    // Remove duplicate CVE IDs.
    $unique = [];

    foreach ($results as $result) {
        $unique[$result['cve_id']] = $result;
    }

    return [
        'status' => 'ok',
        'results' => array_values($unique)
    ];
}


/* =========================================================
   4. CPE PARSING
========================================================= */

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


/* =========================================================
   5. PRODUCT / CPE IDENTITY
========================================================= */

function products_match(
    string $detectedProduct,
    string $cpeProduct
): bool {

    if (
        $detectedProduct === '' ||
        $cpeProduct === ''
    ) {
        return false;
    }

    return normalize_product_name($detectedProduct)
        === normalize_product_name($cpeProduct);
}


function cpe_identity_matches(
    string $detectedProduct,
    array $cpeData
): bool {

    // This scanner maps software/application CPEs.
    if (($cpeData['part'] ?? '') !== 'a') {
        return false;
    }

    $known = lookup_known_cpe($detectedProduct);

    if ($known !== null) {

        return (
            strtolower($cpeData['vendor']) === strtolower($known['vendor']) &&
            strtolower($cpeData['product']) === strtolower($known['product'])
        );
    }

    return products_match(
        normalize_product_name($detectedProduct),
        normalize_product_name($cpeData['product'] ?? '')
    );
}


/* =========================================================
   6. VERSION MATCHING
========================================================= */

function normalize_version(string $version): string
{
    $version = strtolower(trim($version));

    $version = preg_replace(
        '/^(version|ver|v)\s*/i',
        '',
        $version
    );

    return trim($version);
}


function version_compare_safe(
    string $versionA,
    string $versionB
): int {

    $a = normalize_version($versionA);
    $b = normalize_version($versionB);

    if ($a === $b) {
        return 0;
    }

    return version_compare($a, $b);
}


function version_matches_cpe(
    string $detectedVersion,
    string $cpeVersion,
    array $cpeMatch
): bool {

    $detectedVersion = normalize_version(
        $detectedVersion
    );

    $cpeVersion = trim($cpeVersion);

    if (
        $detectedVersion === '' ||
        $cpeVersion === '-'
    ) {
        return false;
    }

    // Exact CPE version.
    if ($cpeVersion !== '*') {

        if (
            version_compare_safe(
                $detectedVersion,
                $cpeVersion
            ) !== 0
        ) {
            return false;
        }
    }

    // Check NVD version boundaries as well.
    return version_is_in_range(
        $detectedVersion,
        $cpeMatch
    );
}


function version_is_in_range(
    string $version,
    array $cpeMatch
): bool {

    $startIncluding =
        $cpeMatch['versionStartIncluding'] ?? null;

    $startExcluding =
        $cpeMatch['versionStartExcluding'] ?? null;

    $endIncluding =
        $cpeMatch['versionEndIncluding'] ?? null;

    $endExcluding =
        $cpeMatch['versionEndExcluding'] ?? null;

    if (
        $startIncluding === null &&
        $startExcluding === null &&
        $endIncluding === null &&
        $endExcluding === null
    ) {
        return true;
    }

    if (
        $startIncluding !== null &&
        version_compare_safe($version, $startIncluding) < 0
    ) {
        return false;
    }

    if (
        $startExcluding !== null &&
        version_compare_safe($version, $startExcluding) <= 0
    ) {
        return false;
    }

    if (
        $endIncluding !== null &&
        version_compare_safe($version, $endIncluding) > 0
    ) {
        return false;
    }

    if (
        $endExcluding !== null &&
        version_compare_safe($version, $endExcluding) >= 0
    ) {
        return false;
    }

    return true;
}


/* =========================================================
   7. NVD CONFIGURATION EVALUATION
========================================================= */

/**
 * Evaluate a CPE node recursively.
 *
 * AND is evaluated conservatively:
 * every condition must match the detected product.
 *
 * This avoids treating one matching CPE as sufficient
 * when the NVD node requires additional conditions.
 */
function evaluate_cpe_node(
    array $node,
    string $product,
    string $version
): bool {

    $operator = strtoupper(
        $node['operator'] ?? 'OR'
    );

    $conditions = [];

    foreach ($node['cpeMatch'] ?? [] as $cpeMatch) {

        $criteria = $cpeMatch['criteria'] ?? '';

        if ($criteria === '') {
            $conditions[] = false;
            continue;
        }

        $cpeData = parse_cpe_23($criteria);

        $matched = false;

        if (
            $cpeData !== null &&
            ($cpeMatch['vulnerable'] ?? true) === true &&
            cpe_identity_matches($product, $cpeData)
        ) {

            $matched = version_matches_cpe(
                $version,
                $cpeData['version'],
                $cpeMatch
            );
        }

        $conditions[] = $matched;
    }

    foreach ($node['children'] ?? [] as $child) {

        $conditions[] = evaluate_cpe_node(
            $child,
            $product,
            $version
        );
    }

    if (empty($conditions)) {
        return false;
    }

    if ($operator === 'AND') {

        $result = !in_array(
            false,
            $conditions,
            true
        );

    } else {

        $result = in_array(
            true,
            $conditions,
            true
        );
    }

    if (!empty($node['negate'])) {
        $result = !$result;
    }

    return $result;
}


/**
 * Checks whether the detected product/version
 * matches an NVD vulnerability configuration.
 */
function cve_matches_product_and_version(
    array $cve,
    string $product,
    string $detectedVersion
): array {

    $configurations = $cve['configurations'] ?? [];

    if (!is_array($configurations)) {
        return [
            'matched' => false,
            'reason' => ''
        ];
    }

    foreach ($configurations as $configuration) {

        foreach ($configuration['nodes'] ?? [] as $node) {

            if (
                evaluate_cpe_node(
                    $node,
                    $product,
                    $detectedVersion
                )
            ) {

                return [
                    'matched' => true,
                    'reason' =>
                        "CPE NVD compatible avec {$product} {$detectedVersion}"
                ];
            }
        }
    }

    return [
        'matched' => false,
        'reason' => ''
    ];
}


/* =========================================================
   8. CVSS SCORE
========================================================= */

function extract_cvss_score(array $cve): ?float
{
    $metrics = $cve['metrics'] ?? [];

    foreach (
        [
            'cvssMetricV40',
            'cvssMetricV31',
            'cvssMetricV30',
            'cvssMetricV2'
        ] as $metricVersion
    ) {

        if (
            !empty($metrics[$metricVersion]) &&
            is_array($metrics[$metricVersion])
        ) {

            foreach ($metrics[$metricVersion] as $metric) {

                if (
                    isset($metric['cvssData']['baseScore'])
                ) {
                    return (float) $metric['cvssData']['baseScore'];
                }
            }
        }
    }

    return null;
}


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


/* =========================================================
   9. CVE DESCRIPTION
========================================================= */

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


/* =========================================================
   10. NVD REQUEST THROTTLING
========================================================= */

function cve_throttle_delay_microseconds(): int
{
    if (
        defined('NVD_API_KEY') &&
        NVD_API_KEY !== ''
    ) {
        return 600000;
    }

    return 6500000;
}
