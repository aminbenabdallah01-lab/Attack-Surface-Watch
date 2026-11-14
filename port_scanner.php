<?php
require_once __DIR__ . '/config.php';

/**
 * Wrapper autour de Nmap.
 * Nécessite que le binaire soit installé et accessible
 * au chemin défini dans config.php.
 */
function scan_ports(string $ip): array
{
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        error_log("[port_scanner] IP invalide ignorée : {$ip}");
        return [];
    }

    $outputFile = tempnam(sys_get_temp_dir(), 'nmap_') . '.xml';

    $cmd = sprintf(
        '"%s" %s -oX %s %s 2>&1',
        NMAP_PATH,
        NMAP_FLAGS,
        escapeshellarg($outputFile),
        escapeshellarg($ip)
    );

    // 150s : doit rester supérieur à --host-timeout dans NMAP_FLAGS (config.php),
    // sinon PHP tue le script avant que nmap n'ait fini sur une cible distante lente.
    set_time_limit(150);

    $out = [];
    $exitCode = -1;

    exec($cmd, $out, $exitCode);

    error_log("[port_scanner] CMD: " . $cmd);
    error_log("[port_scanner] EXIT: " . $exitCode);
    error_log("[port_scanner] OUTPUT FILE: " . $outputFile);
    error_log(
        "[port_scanner] FILE EXISTS: " .
        (file_exists($outputFile) ? 'YES' : 'NO')
    );
    error_log(
        "[port_scanner] OUTPUT: " .
        implode(" | ", $out)
    );

    if ($exitCode !== 0 || !file_exists($outputFile)) {
        error_log(
            "[port_scanner] Échec scan nmap pour {$ip} " .
            "(exit code {$exitCode})"
        );

        @unlink($outputFile);
        return [];
    }

    $services = parse_nmap_xml($outputFile);

    error_log(
        "[port_scanner] PARSED SERVICES COUNT: " .
        count($services)
    );

    error_log(
        "[port_scanner] PARSED SERVICES: " .
        print_r($services, true)
    );

    @unlink($outputFile);

    return $services;
}


/**
 * Parse le XML généré par Nmap.
 */
function parse_nmap_xml(string $xmlPath): array
{
    $services = [];

    if (!file_exists($xmlPath)) {
        error_log(
            "[port_scanner] Fichier XML introuvable : {$xmlPath}"
        );
        return [];
    }

    libxml_use_internal_errors(true);

    $xml = simplexml_load_file($xmlPath);

    if ($xml === false) {
        error_log(
            "[port_scanner] Échec du parsing XML nmap pour {$xmlPath}"
        );

        foreach (libxml_get_errors() as $error) {
            error_log(
                "[port_scanner] Erreur XML : " .
                trim($error->message)
            );
        }

        libxml_clear_errors();

        return [];
    }

    foreach ($xml->host as $host) {

        if (!isset($host->ports->port)) {
            continue;
        }

        foreach ($host->ports->port as $port) {

            $state = (string)($port->state['state'] ?? '');

            if ($state !== 'open') {
                continue;
            }

            $service = $port->service;

            $services[] = [
                'port' => (int)$port['portid'],

                'protocol' => (string)$port['protocol'],

                'service_name' => (string)(
                    $service['name'] ?? ''
                ),

                'product' => (string)(
                    $service['product'] ?? ''
                ),

                'version' => (string)(
                    $service['version'] ?? ''
                ),

                'banner' => trim(
                    (string)($service['product'] ?? '') . ' ' .
                    (string)($service['version'] ?? '') . ' ' .
                    (string)($service['extrainfo'] ?? '')
                ),
            ];
        }
    }

    return $services;
}