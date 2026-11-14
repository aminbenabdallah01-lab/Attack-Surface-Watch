<?php
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/subdomain_enum.php';
require_once __DIR__ . '/port_scanner.php';
require_once __DIR__ . '/tech_detector.php';
require_once __DIR__ . '/cve_matcher.php';
require_once __DIR__ . '/alert_notifier.php';

/**
 * Exécute le pipeline complet pour une organisation :
 * domaine -> sous-domaines -> IPs -> ports/services -> technologies -> CVE -> alertes.
 *
 * Toutes les données créées/mises à jour sont strictement rattachées à
 * organization_id = $organizationId. Aucune donnée d'une autre organisation
 * n'est jamais lue ni modifiée (chaque requête filtre explicitement dessus).
 *
 * Veille (diff détection) : ce scan compare ses résultats à l'état "actif"
 * précédent de l'organisation pour détecter :
 *   - nouveaux actifs (sous-domaines)
 *   - actifs disparus (is_active=0 + alerte)
 *   - nouveaux ports/services (+ alerte)
 *   - ports/services disparus (is_active=0 + alerte)
 *   - nouvelles technologies (+ alerte)
 *   - nouvelles vulnérabilités confirmées (+ alerte)
 * Les alertes ne sont générées QUE pour de vrais changements, jamais pour
 * un actif déjà connu et inchangé.
 */
function run_scan(int $organizationId, ?int $existingScanId = null): int
{
    $db = get_db();

    $org = get_organization($db, $organizationId);
    if (!$org) {
        throw new RuntimeException("Organisation {$organizationId} introuvable");
    }

    // Réutilise un scan déjà créé (cas du worker en arrière-plan, où la ligne
    // 'pending' est créée par run_scan.php AVANT de lancer le process, pour
    // pouvoir stocker le PID immédiatement) sinon en crée un nouveau
    // (cas du cron, appelé directement sans passer par le web).
    $scanId = $existingScanId ?? create_scan($db, $organizationId);
    $newAssetsCount = 0;
    $seenSubdomainIds = [];

    try {
        mark_scan_status($db, $scanId, 'running', ['started_at' => date('Y-m-d H:i:s')]);

        $discovered = enumerate_subdomains($org['root_domain']);

        foreach ($discovered as $item) {
            // Vérifie à chaque sous-domaine si l'utilisateur a annulé le scan
            // (cancel_scan.php met status='cancelled' immédiatement en base).
            // Filet de sécurité en plus du kill du process : si le kill échoue
            // ou est en retard, le scan s'arrête proprement ici au prochain tour.
            if (scan_is_cancelled($db, $scanId)) {
                break;
            }

            [$subdomainId, $isNew] = upsert_subdomain($db, $organizationId, $item['hostname'], $item['source']);
            $seenSubdomainIds[] = $subdomainId;

            if ($isNew) {
                $newAssetsCount++;
                record_alert($db, $organizationId, 'new_asset', "Nouveau sous-domaine découvert : {$item['hostname']}");
            }

            $seenIpIds = [];
            $seenTechIds = [];
            $ips = resolve_ips($item['hostname']);

            foreach ($ips as $ip) {
                $ipId = upsert_ip($db, $subdomainId, $ip);
                $seenIpIds[] = $ipId;

                // --- Ports / services (upsert, jamais de doublon) ---
                $services = scan_ports($ip);
                $seenServiceIds = [];

                foreach ($services as $svc) {
                    [$serviceId, $isNewService] = upsert_service($db, $ipId, $svc);
                    $seenServiceIds[] = $serviceId;

                    if ($isNewService) {
                        record_alert(
                            $db, $organizationId, 'new_asset',
                            "Nouveau port ouvert : {$item['hostname']} — port {$svc['port']}/{$svc['protocol']}" .
                            ($svc['product'] ? " ({$svc['product']} {$svc['version']})" : '')
                        );
                    }

                    process_cve_matching_for_service($db, $organizationId, $item['hostname'], $svc['port'], $serviceId, $svc['product'] ?: null, $svc['version'] ?: null);
                }

                // Ports vus précédemment mais absents de ce scan -> fermés
                mark_removed_services($db, $ipId, $seenServiceIds, $organizationId, $item['hostname']);

                // --- Technologies : on interroge chaque port WEB réellement
                // ouvert (pas seulement 80/443 par défaut). C'est ce qui
                // permet de détecter correctement une appli comme Juice Shop
                // qui tourne sur un port applicatif (3000, 8080, ...).
                $webPorts = array_filter($services, fn($s) => is_web_service($s));

                if (empty($webPorts)) {
                    // Aucun port web détecté par nmap -> on tente quand même
                    // 80/443 par défaut (nmap peut être absent/mal configuré).
                    $webPorts = [['port' => 443, 'protocol' => 'tcp'], ['port' => 80, 'protocol' => 'tcp']];
                }

                foreach ($webPorts as $svc) {
                    $scheme = ($svc['port'] == 443 || $svc['port'] == 8443) ? 'https://' : 'http://';
                    $portSuffix = in_array($svc['port'], [80, 443]) ? '' : ':' . $svc['port'];
                    $target = $scheme . $item['hostname'] . $portSuffix . '/';

                    $techs = detect_technologies($target);
                    foreach ($techs as $tech) {
                        [$techId, $isNewTech] = upsert_technology($db, $subdomainId, $tech);
                        $seenTechIds[] = $techId;

                        if ($isNewTech) {
                            record_alert(
                                $db, $organizationId, 'new_asset',
                                "Nouvelle technologie détectée sur {$item['hostname']}{$portSuffix} : {$tech['tech_name']}" .
                                ($tech['tech_version'] ? " {$tech['tech_version']}" : ' (version inconnue)')
                            );
                        }

                        process_cve_matching_for_technology($db, $organizationId, $item['hostname'], $techId, $tech['tech_name'], $tech['tech_version']);
                    }
                }
            }

            mark_removed_technologies($db, $subdomainId, $seenTechIds, $organizationId, $item['hostname']);
        }

        if (scan_is_cancelled($db, $scanId)) {
            // Arrêt demandé par l'utilisateur en cours de route : on ne marque
            // PAS les actifs restants comme "disparus" (on ne les a pas tous
            // revisités, ce serait un faux diff), et on laisse le statut
            // 'cancelled' déjà posé par cancel_scan.php tel quel.
            return $scanId;
        }

        // Sous-domaines connus avant ce scan mais non retrouvés -> disparus
        mark_removed_subdomains($db, $organizationId, $seenSubdomainIds);

        mark_scan_status($db, $scanId, 'completed', [
            'finished_at'      => date('Y-m-d H:i:s'),
            'new_assets_count' => $newAssetsCount,
        ]);
    } catch (Throwable $e) {
        error_log('[scan_orchestrator] Erreur : ' . $e->getMessage());
        if (!scan_is_cancelled($db, $scanId)) {
            mark_scan_status($db, $scanId, 'failed', ['finished_at' => date('Y-m-d H:i:s')]);
        }
        throw $e;
    }

    return $scanId;
}

/**
 * Vérifie si l'utilisateur a demandé l'annulation du scan (cancel_scan.php
 * met à jour le statut immédiatement en base dès le clic). Appelée entre
 * chaque sous-domaine pour un arrêt propre et rapide.
 */
function scan_is_cancelled(PDO $db, int $scanId): bool
{
    $stmt = $db->prepare('SELECT status FROM scans WHERE id = ?');
    $stmt->execute([$scanId]);
    $row = $stmt->fetch();
    return $row && $row['status'] === 'cancelled';
}

/**
 * Lance un scan en arrière-plan (process PHP CLI séparé) et retourne
 * immédiatement l'id du scan créé, sans attendre qu'il termine. Permet à
 * l'utilisateur de continuer à naviguer et d'annuler le scan à tout moment
 * via cancel_scan.php (qui tue le process via son PID).
 */
function launch_background_scan(int $orgId): int
{
    $db = get_db();

    // La ligne 'pending' est créée ICI (avant de lancer le process) pour
    // pouvoir stocker le PID dessus dès qu'on l'a, et pour que l'utilisateur
    // voie immédiatement "scan en cours" sans attendre le démarrage du worker.
    $scanId = create_scan($db, $orgId);

    $workerScript = __DIR__ . '/scan_worker.php';
    $cmd = escapeshellarg(PHP_CLI_PATH) . ' ' . escapeshellarg($workerScript) . ' ' . (int) $orgId . ' ' . (int) $scanId;

    $logDir = sys_get_temp_dir();
    $descriptorSpec = [
        0 => ['pipe', 'r'],
        1 => ['file', $logDir . "/attack_surface_scan_{$scanId}_out.log", 'a'],
        2 => ['file', $logDir . "/attack_surface_scan_{$scanId}_err.log", 'a'],
    ];

    $options = [];
    if (stripos(PHP_OS, 'WIN') !== false) {
        // Sans ceci, Windows lance le process dans un wrapper cmd.exe et le
        // PID récupéré est celui de cmd.exe, pas de php.exe -> taskkill sur
        // ce PID ne tue pas le vrai scan. bypass_shell donne le PID exact.
        $options['bypass_shell'] = true;
    }

    $process = proc_open($cmd, $descriptorSpec, $pipes, __DIR__, null, $options);

    if (!is_resource($process)) {
        mark_scan_status($db, $scanId, 'failed', ['finished_at' => date('Y-m-d H:i:s')]);
        throw new RuntimeException('Impossible de lancer le worker de scan en arrière-plan (vérifie PHP_CLI_PATH dans config.php).');
    }

    $status = proc_get_status($process);
    if (!empty($status['pid'])) {
        $update = $db->prepare('UPDATE scans SET pid = ? WHERE id = ?');
        $update->execute([$status['pid'], $scanId]);
    }

    // On NE ferme PAS les pipes de façon bloquante et on n'appelle PAS
    // proc_close() : ça attendrait la fin du process. On le laisse tourner
    // détaché et on retourne immédiatement.

    return $scanId;
}

/**
 * Matching CVE pour un service (port ouvert) détecté, avec gestion explicite
 * du cas "version inconnue" : dans ce cas on n'insère AUCUNE vulnérabilité,
 * on se contente de logger — conformément à la règle "pas de CVE sans preuve".
 */
function process_cve_matching_for_service(PDO $db, int $orgId, string $hostname, int $port, int $serviceId, ?string $product, ?string $version): void
{
    if (empty($product)) {
        return; // aucun produit identifié par nmap -> rien à vérifier
    }

    $match = find_vulnerabilities($product, $version);

    if ($match['status'] === 'no_version') {
        error_log("[cve_matcher] {$hostname}:{$port} — {$product} détecté sans version confirmée, CVE non vérifiées (évite les faux positifs).");
        return;
    }

    foreach ($match['results'] as $vuln) {
        $isNewVuln = insert_vulnerability($db, $serviceId, null, $vuln);
        if ($isNewVuln) {
            record_alert(
                $db, $orgId, 'new_vulnerability',
                "Nouvelle CVE {$vuln['severity']} ({$vuln['confidence']}) : {$vuln['cve_id']} sur {$hostname}:{$port} ({$product} {$version})"
            );
        }
    }

    usleep(cve_throttle_delay_microseconds());
}

function process_cve_matching_for_technology(PDO $db, int $orgId, string $hostname, int $techId, string $techName, ?string $techVersion): void
{
    $match = find_vulnerabilities($techName, $techVersion);

    if ($match['status'] === 'no_version') {
        error_log("[cve_matcher] {$hostname} — {$techName} détecté sans version confirmée, CVE non vérifiées (évite les faux positifs).");
        return;
    }

    foreach ($match['results'] as $vuln) {
        $isNewVuln = insert_vulnerability($db, null, $techId, $vuln);
        if ($isNewVuln) {
            record_alert(
                $db, $orgId, 'new_vulnerability',
                "Nouvelle CVE {$vuln['severity']} ({$vuln['confidence']}) : {$vuln['cve_id']} sur {$hostname} ({$techName} {$techVersion})"
            );
        }
    }

    usleep(cve_throttle_delay_microseconds());
}

/**
 * Détermine si un service ouvert détecté par nmap est probablement un
 * service web (HTTP/HTTPS), pour savoir sur quel(s) port(s) lancer la
 * détection de technologies. Se base sur :
 *   - le nom de service identifié par nmap (http, https, http-proxy...)
 *   - une liste de ports applicatifs/dev courants (3000, 8080, 8443...)
 *     car nmap peut fingerprinter un service HTTP sous un nom générique
 *     (ex: "ppp") sur un port non standard.
 */
function is_web_service(array $svc): bool
{
    $name = strtolower($svc['service_name'] ?? '');
    if (str_contains($name, 'http')) {
        return true;
    }

    $commonWebPorts = [80, 443, 3000, 3001, 4200, 5000, 5173, 8000, 8008, 8080, 8081, 8082, 8443, 8888, 9000];
    return in_array((int) $svc['port'], $commonWebPorts, true);
}

// ------------------------------------------------------------------
// Helpers DB (requêtes préparées uniquement, toujours filtrées par organization_id)
// ------------------------------------------------------------------

function get_organization(PDO $db, int $id): ?array
{
    $stmt = $db->prepare('SELECT * FROM organizations WHERE id = ?');
    $stmt->execute([$id]);
    $row = $stmt->fetch();
    return $row ?: null;
}

function create_scan(PDO $db, int $orgId): int
{
    $stmt = $db->prepare('INSERT INTO scans (organization_id, status, triggered_by) VALUES (?, "pending", "manual")');
    $stmt->execute([$orgId]);
    return (int) $db->lastInsertId();
}

function mark_scan_status(PDO $db, int $scanId, string $status, array $extra = []): void
{
    $fields = ['status = ?'];
    $params = [$status];
    foreach ($extra as $col => $val) {
        $fields[] = "{$col} = ?";
        $params[] = $val;
    }
    $params[] = $scanId;
    $stmt = $db->prepare('UPDATE scans SET ' . implode(', ', $fields) . ' WHERE id = ?');
    $stmt->execute($params);
}

/** @return array{0:int,1:bool} [subdomainId, isNewlyCreated] */
function upsert_subdomain(PDO $db, int $orgId, string $hostname, string $source): array
{
    $stmt = $db->prepare('SELECT id FROM subdomains WHERE organization_id = ? AND hostname = ?');
    $stmt->execute([$orgId, $hostname]);
    $existing = $stmt->fetch();

    if ($existing) {
        $update = $db->prepare('UPDATE subdomains SET last_seen = NOW(), is_active = 1 WHERE id = ?');
        $update->execute([$existing['id']]);
        return [(int) $existing['id'], false];
    }

    $insert = $db->prepare('INSERT INTO subdomains (organization_id, hostname, source) VALUES (?, ?, ?)');
    $insert->execute([$orgId, $hostname, $source]);
    return [(int) $db->lastInsertId(), true];
}

/**
 * Marque comme inactifs (retirés) les sous-domaines de l'organisation qui
 * étaient actifs mais n'ont pas été revus dans ce scan. Génère une alerte
 * pour chaque disparition réelle.
 */
function mark_removed_subdomains(PDO $db, int $orgId, array $seenIds): void
{
    if (empty($seenIds)) {
        $seenIds = [0]; // évite un IN () vide invalide en SQL
    }
    $placeholders = implode(',', array_fill(0, count($seenIds), '?'));

    $stmt = $db->prepare(
        "SELECT id, hostname FROM subdomains
         WHERE organization_id = ? AND is_active = 1 AND id NOT IN ({$placeholders})"
    );
    $stmt->execute(array_merge([$orgId], $seenIds));
    $removed = $stmt->fetchAll();

    foreach ($removed as $row) {
        $update = $db->prepare('UPDATE subdomains SET is_active = 0 WHERE id = ?');
        $update->execute([$row['id']]);
        record_alert($db, $orgId, 'asset_removed', "Sous-domaine disparu (non retrouvé lors du dernier scan) : {$row['hostname']}");
    }
}

function upsert_ip(PDO $db, int $subdomainId, string $ip): int
{
    $stmt = $db->prepare('SELECT id FROM ip_addresses WHERE subdomain_id = ? AND ip_address = ?');
    $stmt->execute([$subdomainId, $ip]);
    $existing = $stmt->fetch();
    if ($existing) {
        return (int) $existing['id'];
    }

    $insert = $db->prepare('INSERT INTO ip_addresses (subdomain_id, ip_address) VALUES (?, ?)');
    $insert->execute([$subdomainId, $ip]);
    return (int) $db->lastInsertId();
}

/** @return array{0:int,1:bool} [serviceId, isNewlyCreated] */
function upsert_service(PDO $db, int $ipId, array $svc): array
{
    $stmt = $db->prepare('SELECT id FROM services WHERE ip_address_id = ? AND port = ? AND protocol = ?');
    $stmt->execute([$ipId, $svc['port'], $svc['protocol']]);
    $existing = $stmt->fetch();

    if ($existing) {
        $update = $db->prepare(
            'UPDATE services SET service_name = ?, product = ?, version = ?, banner = ?, last_seen = NOW(), is_active = 1 WHERE id = ?'
        );
        $update->execute([$svc['service_name'], $svc['product'], $svc['version'], $svc['banner'], $existing['id']]);
        return [(int) $existing['id'], false];
    }

    $insert = $db->prepare(
        'INSERT INTO services (ip_address_id, port, protocol, service_name, product, version, banner)
         VALUES (?, ?, ?, ?, ?, ?, ?)'
    );
    $insert->execute([
        $ipId, $svc['port'], $svc['protocol'], $svc['service_name'],
        $svc['product'], $svc['version'], $svc['banner'],
    ]);
    return [(int) $db->lastInsertId(), true];
}

function mark_removed_services(PDO $db, int $ipId, array $seenServiceIds, int $orgId, string $hostname): void
{
    if (empty($seenServiceIds)) {
        $seenServiceIds = [0];
    }
    $placeholders = implode(',', array_fill(0, count($seenServiceIds), '?'));

    $stmt = $db->prepare(
        "SELECT id, port, protocol FROM services
         WHERE ip_address_id = ? AND is_active = 1 AND id NOT IN ({$placeholders})"
    );
    $stmt->execute(array_merge([$ipId], $seenServiceIds));
    $removed = $stmt->fetchAll();

    foreach ($removed as $row) {
        $update = $db->prepare('UPDATE services SET is_active = 0 WHERE id = ?');
        $update->execute([$row['id']]);
        record_alert($db, $orgId, 'port_closed', "Port fermé (non retrouvé lors du dernier scan) : {$hostname} — {$row['port']}/{$row['protocol']}");
    }
}

/** @return array{0:int,1:bool} [technologyId, isNewlyCreated] */
function upsert_technology(PDO $db, int $subdomainId, array $tech): array
{
    $stmt = $db->prepare('SELECT id FROM technologies WHERE subdomain_id = ? AND tech_name = ?');
    $stmt->execute([$subdomainId, $tech['tech_name']]);
    $existing = $stmt->fetch();

    if ($existing) {
        $update = $db->prepare(
            'UPDATE technologies SET tech_version = ?, evidence = ?, last_seen = NOW(), is_active = 1 WHERE id = ?'
        );
        $update->execute([$tech['tech_version'], $tech['evidence'] ?? null, $existing['id']]);
        return [(int) $existing['id'], false];
    }

    $insert = $db->prepare(
        'INSERT INTO technologies (subdomain_id, tech_name, tech_version, category, evidence) VALUES (?, ?, ?, ?, ?)'
    );
    $insert->execute([$subdomainId, $tech['tech_name'], $tech['tech_version'], $tech['category'], $tech['evidence'] ?? null]);
    return [(int) $db->lastInsertId(), true];
}

function mark_removed_technologies(PDO $db, int $subdomainId, array $seenTechIds, int $orgId, string $hostname): void
{
    if (empty($seenTechIds)) {
        $seenTechIds = [0];
    }
    $placeholders = implode(',', array_fill(0, count($seenTechIds), '?'));

    $stmt = $db->prepare(
        "SELECT id, tech_name FROM technologies
         WHERE subdomain_id = ? AND is_active = 1 AND id NOT IN ({$placeholders})"
    );
    $stmt->execute(array_merge([$subdomainId], $seenTechIds));
    $removed = $stmt->fetchAll();

    foreach ($removed as $row) {
        $update = $db->prepare('UPDATE technologies SET is_active = 0 WHERE id = ?');
        $update->execute([$row['id']]);
        record_alert($db, $orgId, 'technology_removed', "Technologie non retrouvée sur {$hostname} : {$row['tech_name']}");
    }
}

function insert_vulnerability(PDO $db, ?int $serviceId, ?int $technologyId, array $vuln): bool
{
    if (empty($vuln['cve_id'])) {
        return false;
    }

    $check = $db->prepare(
        'SELECT id FROM vulnerabilities WHERE cve_id = ? AND service_id <=> ? AND technology_id <=> ?'
    );
    $check->execute([$vuln['cve_id'], $serviceId, $technologyId]);
    if ($check->fetch()) {
        return false; // déjà connue, pas une nouveauté
    }

    $insert = $db->prepare(
        'INSERT INTO vulnerabilities (service_id, technology_id, cve_id, cvss_score, severity, confidence, description, match_reason, published_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    );
    $insert->execute([
        $serviceId, $technologyId, $vuln['cve_id'], $vuln['cvss_score'],
        $vuln['severity'], $vuln['confidence'] ?? 'medium', $vuln['description'],
        $vuln['match_reason'] ?? null, $vuln['published_at'],
    ]);
    return true;
}

function record_alert(PDO $db, int $orgId, string $type, string $message): void
{
    $stmt = $db->prepare('INSERT INTO alerts (organization_id, type, message, channel) VALUES (?, ?, ?, "email")');
    $stmt->execute([$orgId, $type, $message]);
}
