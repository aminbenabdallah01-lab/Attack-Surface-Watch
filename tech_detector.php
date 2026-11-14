<?php

/**
 * Détection de technologies web (type Wappalyzer simplifié) via headers
 * HTTP + contenu HTML, sans dépendance externe.
 *
 * Chaque signature définit :
 *   - 'headers' : règles sur les headers HTTP
 *   - 'html'    : règle sur le corps HTML
 *   - 'version_regex' : regex AVEC un groupe de capture (...) pour extraire la version.
 *                       Si absente ou non matchée, la version reste inconnue (null)
 *                       et sera traitée en confiance faible dans cve_matcher (pas de
 *                       matching CVE automatique sans version confirmée).
 *   - 'category'
 */
function get_tech_signatures(): array
{
    return [
        'WordPress' => [
            'html'          => '/wp-content|wp-includes/i',
            'version_regex' => '/content="WordPress\s+([0-9.]+)"/i',
            'category'      => 'CMS',
        ],
        'Joomla' => [
            'html'          => '/Joomla!/i',
            'version_regex' => '/Joomla!\s+([0-9.]+)/i',
            'category'      => 'CMS',
        ],
        'Drupal' => [
            'headers'       => ['x-generator' => '/Drupal/i'],
            'html'          => '/Drupal.settings/i',
            'version_regex' => '/Drupal\s+([0-9.]+)/i',
            'category'      => 'CMS',
        ],
        'Laravel' => [
            'headers'  => ['set-cookie' => '/laravel_session/i'],
            'category' => 'Framework',
        ],
        'nginx' => [
            'headers'       => ['server' => '/nginx/i'],
            'version_regex' => '/nginx\/([0-9.]+)/i',
            'category'      => 'Web Server',
        ],
        'Apache' => [
            'headers'       => ['server' => '/apache/i'],
            'version_regex' => '/Apache\/([0-9.]+)/i',
            'category'      => 'Web Server',
        ],
        'PHP' => [
            'headers'       => ['x-powered-by' => '/php/i'],
            'version_regex' => '/PHP\/([0-9.]+)/i',
            'category'      => 'Language',
        ],
        'Express' => [
            'headers'  => ['x-powered-by' => '/express/i'],
            'category' => 'Framework',
        ],
        'Node.js' => [
            'headers'  => ['x-powered-by' => '/node\.?js/i'],
            'category' => 'Runtime',
        ],
        'React' => [
            'html'     => '/__REACT_DEVTOOLS|react-dom|data-reactroot/i',
            'category' => 'JS Framework',
        ],
        'jQuery' => [
            'html'          => '/jquery[-.]([0-9.]+)(?:\.min)?\.js/i',
            'version_regex' => '/jquery[-.]([0-9.]+)(?:\.min)?\.js/i',
            'category'      => 'JS Library',
        ],
        'Angular' => [
            'html'          => '/ng-version="([0-9.]+)"|angular\.js|ng-app/i',
            'version_regex' => '/ng-version="([0-9.]+)"/i',
            'category'      => 'JS Framework',
        ],
    ];
}

/**
 * @return array [['tech_name'=>'nginx','tech_version'=>'1.18.0'|null,'category'=>'Web Server','evidence'=>'...'], ...]
 *
 * IMPORTANT : ne retourne QUE des technologies pour lesquelles une preuve
 * concrète (regex matchée sur une vraie réponse HTTP du bien scanné) a été
 * trouvée. Aucune valeur par défaut / fallback n'est injectée ici.
 */
function detect_technologies(string $url): array
{
    $context = stream_context_create([
        'http' => [
            'timeout'       => 10,
            'header'        => "User-Agent: AttackSurfacePlatform/1.0\r\n",
            'ignore_errors' => true,
        ],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
    ]);

    $body = @file_get_contents($url, false, $context);
    $headers = parse_response_headers($http_response_header ?? []);

    // Aucune réponse du tout -> aucune technologie ne peut être affirmée.
    if ($body === false && empty($headers)) {
        error_log("[tech_detector] Aucune réponse de {$url}");
        return [];
    }
    $body = $body === false ? '' : $body;

    $detected = [];

    foreach (get_tech_signatures() as $techName => $rules) {
        $matched = false;
        $evidence = null;

        if (isset($rules['headers'])) {
            foreach ($rules['headers'] as $headerName => $regex) {
                if (isset($headers[$headerName]) && preg_match($regex, $headers[$headerName])) {
                    $matched = true;
                    $evidence = "header {$headerName}: {$headers[$headerName]}";
                    break;
                }
            }
        }

        if (!$matched && isset($rules['html']) && preg_match($rules['html'], $body, $htmlMatch)) {
            $matched = true;
            $evidence = "motif HTML trouvé (« " . substr($htmlMatch[0], 0, 60) . " »)";
        }

        if (!$matched) {
            continue;
        }

        // Tentative d'extraction de version à partir d'une preuve réelle uniquement
        $version = null;
        if (!empty($rules['version_regex'])) {
            if (isset($headers['server']) && preg_match($rules['version_regex'], $headers['server'], $vm)) {
                $version = $vm[1];
                $evidence = "header Server: {$headers['server']}";
            } elseif (isset($headers['x-powered-by']) && preg_match($rules['version_regex'], $headers['x-powered-by'], $vm)) {
                $version = $vm[1];
                $evidence = "header X-Powered-By: {$headers['x-powered-by']}";
            } elseif (preg_match($rules['version_regex'], $body, $vm)) {
                $version = $vm[1];
                $evidence = "version trouvée dans le HTML (« " . substr($vm[0], 0, 60) . " »)";
            }
        }

        $detected[] = [
            'tech_name'    => $techName,
            'tech_version' => $version, // reste null si aucune preuve -> confiance faible dans cve_matcher
            'category'     => $rules['category'],
            'evidence'     => $evidence,
        ];
    }

    return $detected;
}

function parse_response_headers(array $rawHeaders): array
{
    $headers = [];
    foreach ($rawHeaders as $line) {
        if (strpos($line, ':') !== false) {
            [$key, $value] = explode(':', $line, 2);
            $headers[strtolower(trim($key))] = trim($value);
        }
    }
    return $headers;
}
