<?php
require_once __DIR__ . '/auth.php';
start_session();
require_login();

$db = get_db();
$orgId = (int) ($_GET['id'] ?? 0);

// Vérifie que l'utilisateur a bien accès à cette organisation
$stmt = $db->prepare(
    'SELECT o.* FROM organizations o
     JOIN organization_user ou ON ou.organization_id = o.id
     WHERE o.id = ? AND ou.user_id = ?'
);
$stmt->execute([$orgId, current_user_id()]);
$org = $stmt->fetch();

if (!$org) {
    http_response_code(404);
    die('Organisation introuvable ou accès non autorisé. <a href="dashboard.php" style="color:#4fd1c5;">Retour au dashboard</a>');
}

$subdomainsStmt = $db->prepare(
    'SELECT s.*,
        (SELECT COUNT(*) FROM ip_addresses ip WHERE ip.subdomain_id = s.id) AS ip_count
     FROM subdomains s WHERE s.organization_id = ? AND s.is_active = 1 ORDER BY s.hostname'
);
$subdomainsStmt->execute([$orgId]);
$subdomains = $subdomainsStmt->fetchAll();

$vulnStmt = $db->prepare(
    'SELECT v.*, sd.hostname, sv.port, sv.service_name, sv.product AS service_product, sv.version AS service_version,
            t.tech_name, t.tech_version
     FROM vulnerabilities v
     LEFT JOIN services sv ON v.service_id = sv.id
     LEFT JOIN ip_addresses ip ON sv.ip_address_id = ip.id
     LEFT JOIN technologies t ON v.technology_id = t.id
     LEFT JOIN subdomains sd ON sd.id = COALESCE(ip.subdomain_id, t.subdomain_id)
     WHERE sd.organization_id = ? AND v.status = "open" AND v.is_active = 1
     ORDER BY FIELD(v.severity, "critical","high","medium","low"), v.detected_at DESC'
);
$vulnStmt->execute([$orgId]);
$vulnerabilities = $vulnStmt->fetchAll();

$techStmt = $db->prepare(
    'SELECT t.*, sd.hostname FROM technologies t
     JOIN subdomains sd ON sd.id = t.subdomain_id
     WHERE sd.organization_id = ? AND t.is_active = 1
     ORDER BY sd.hostname, t.tech_name'
);
$techStmt->execute([$orgId]);
$technologies = $techStmt->fetchAll();

$servicesStmt = $db->prepare(
    'SELECT sv.*, ipa.ip_address, sd.hostname FROM services sv
     JOIN ip_addresses ipa ON ipa.id = sv.ip_address_id
     JOIN subdomains sd ON sd.id = ipa.subdomain_id
     WHERE sd.organization_id = ? AND sv.is_active = 1
     ORDER BY sd.hostname, sv.port'
);
$servicesStmt->execute([$orgId]);
$services = $servicesStmt->fetchAll();

$scansStmt = $db->prepare('SELECT * FROM scans WHERE organization_id = ? ORDER BY created_at DESC LIMIT 10');
$scansStmt->execute([$orgId]);
$scans = $scansStmt->fetchAll();

// Scan actuellement en cours (pending ou running) pour cette organisation,
// s'il y en a un — détermine si on affiche "Lancer" ou "Annuler".
$activeScan = null;
foreach ($scans as $sc) {
    if (in_array($sc['status'], ['pending', 'running'], true)) {
        $activeScan = $sc;
        break;
    }
}

$alertsStmt = $db->prepare('SELECT * FROM alerts WHERE organization_id = ? ORDER BY created_at DESC LIMIT 20');
$alertsStmt->execute([$orgId]);
$alerts = $alertsStmt->fetchAll();

$flashSuccess = $_SESSION['flash_success'] ?? null;
$flashError   = $_SESSION['flash_error'] ?? null;
unset($_SESSION['flash_success'], $_SESSION['flash_error']);
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title><?= htmlspecialchars($org['name']) ?> — Attack Surface Watch</title>
<?php if ($activeScan): ?>
<meta http-equiv="refresh" content="5">
<?php endif; ?>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="css/style.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
</head>
<body>
    <header>
        <div>
            <a class="back" href="dashboard.php">← Retour au dashboard</a>
        </div>
        <span style="font-size:13px; color:#94a3b8;">
            <a href="account.php" style="color:#94a3b8; margin-right:12px;">Mon compte</a><?= htmlspecialchars($_SESSION['user_name'] ?? '') ?>
        </span>
    </header>
    <main>
        <div style="display:flex; justify-content:space-between; align-items:flex-start;">
            <div>
                <h1 style="font-size:22px; color:#4fd1c5;"><?= htmlspecialchars($org['name']) ?></h1>
                <div class="subtitle"><?= htmlspecialchars($org['root_domain']) ?></div>
            </div>
            <?php if (!$activeScan): ?>
            <form method="POST" action="delete_organization.php"
                  onsubmit="return confirm('Supprimer « <?= htmlspecialchars(addslashes($org['name'])) ?> » et TOUTES ses données (scans, vulnérabilités, historique) ? Cette action est irréversible.');">
                <input type="hidden" name="organization_id" value="<?= (int)$org['id'] ?>">
                <button type="submit" style="background:transparent; color:#f87171; border:1px solid #7f1d1d; font-size:12px; padding:6px 12px;">🗑 Supprimer cette organisation</button>
            </form>
            <?php endif; ?>
        </div>

        <?php if ($flashSuccess): ?>
            <div class="flash success"><?= htmlspecialchars($flashSuccess) ?></div>
        <?php endif; ?>
        <?php if ($flashError): ?>
            <div class="flash error"><?= htmlspecialchars($flashError) ?></div>
        <?php endif; ?>

        <div class="toolbar">
            <div style="font-size:13px; color:#94a3b8;">
                <?= count($subdomains) ?> actifs actifs · <?= count($vulnerabilities) ?> vulnérabilités ouvertes
                <?php if ($activeScan): ?>
                    <span style="color:#4fd1c5;"> · Scan #<?= (int)$activeScan['id'] ?> en cours…</span>
                <?php endif; ?>
            </div>
            <?php if ($activeScan): ?>
                <form method="POST" action="cancel_scan.php"
                      onsubmit="return confirm('Annuler le scan en cours ? Les résultats déjà trouvés restent enregistrés.');">
                    <input type="hidden" name="organization_id" value="<?= (int)$org['id'] ?>">
                    <input type="hidden" name="scan_id" value="<?= (int)$activeScan['id'] ?>">
                    <button type="submit" style="background:#f87171;">✕ Annuler le scan</button>
                </form>
            <?php else: ?>
                <form method="POST" action="run_scan.php">
                    <input type="hidden" name="organization_id" value="<?= (int)$org['id'] ?>">
                    <button type="submit">▶ Lancer un scan</button>
                </form>
            <?php endif; ?>
        </div>

        <div class="section">
            <h2>Cartographie de la surface d'attaque</h2>
            <div id="graph"></div>
        </div>

        <div class="section">
            <h2>Vulnérabilités ouvertes</h2>
            <table>
                <thead>
                    <tr><th>CVE</th><th>Sévérité</th><th>Confiance</th><th>CVSS</th><th>Actif</th><th>Contexte</th><th>Preuve du match</th></tr>
                </thead>
                <tbody>
                <?php if (empty($vulnerabilities)): ?>
                    <tr><td colspan="7" style="color:#94a3b8;">Aucune vulnérabilité confirmée pour le moment. (Les technologies détectées sans version confirmée ne génèrent pas de CVE — voir section Technologies ci-dessous.)</td></tr>
                <?php endif; ?>
                <?php foreach ($vulnerabilities as $v): ?>
                    <tr>
                        <td><code><?= htmlspecialchars($v['cve_id']) ?></code></td>
                        <td><span class="badge <?= htmlspecialchars($v['severity']) ?>"><?= htmlspecialchars($v['severity']) ?></span></td>
                        <td><span class="badge status"><?= htmlspecialchars($v['confidence'] ?? 'medium') ?></span></td>
                        <td><?= $v['cvss_score'] !== null ? htmlspecialchars($v['cvss_score']) : '—' ?></td>
                        <td><?= htmlspecialchars($v['hostname'] ?? '—') ?></td>
                        <td><?= $v['port'] ? 'port ' . (int)$v['port'] . ' — ' . htmlspecialchars($v['service_product'] ?? $v['service_name'] ?? '') . ' ' . htmlspecialchars($v['service_version'] ?? '') : htmlspecialchars(($v['tech_name'] ?? '') . ' ' . ($v['tech_version'] ?? '')) ?></td>
                        <td style="color:#94a3b8; font-size:12px;"><?= htmlspecialchars($v['match_reason'] ?? '—') ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Ports & services ouverts</h2>
            <table>
                <thead><tr><th>Hostname</th><th>IP</th><th>Port</th><th>Service</th><th>Produit / Version</th></tr></thead>
                <tbody>
                <?php if (empty($services)): ?>
                    <tr><td colspan="5" style="color:#94a3b8;">Aucun port ouvert détecté (Nmap non installé/configuré, ou aucun port ouvert sur la cible).</td></tr>
                <?php endif; ?>
                <?php foreach ($services as $s): ?>
                    <tr>
                        <td><?= htmlspecialchars($s['hostname']) ?></td>
                        <td><?= htmlspecialchars($s['ip_address']) ?></td>
                        <td><?= (int)$s['port'] ?>/<?= htmlspecialchars($s['protocol']) ?></td>
                        <td><?= htmlspecialchars($s['service_name'] ?? '—') ?></td>
                        <td><?= htmlspecialchars(trim(($s['product'] ?? '') . ' ' . ($s['version'] ?? '')) ?: '—') ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Technologies détectées</h2>
            <table>
                <thead><tr><th>Hostname</th><th>Technologie</th><th>Version</th><th>Preuve</th></tr></thead>
                <tbody>
                <?php if (empty($technologies)): ?>
                    <tr><td colspan="4" style="color:#94a3b8;">Aucune technologie détectée pour le moment.</td></tr>
                <?php endif; ?>
                <?php foreach ($technologies as $t): ?>
                    <tr>
                        <td><?= htmlspecialchars($t['hostname']) ?></td>
                        <td><?= htmlspecialchars($t['tech_name']) ?> <span style="color:#64748b;">(<?= htmlspecialchars($t['category']) ?>)</span></td>
                        <td><?= $t['tech_version'] ? htmlspecialchars($t['tech_version']) : '<span style="color:#94a3b8;">inconnue — CVE non vérifiées</span>' ?></td>
                        <td style="color:#94a3b8; font-size:12px;"><?= htmlspecialchars($t['evidence'] ?? '—') ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Sous-domaines découverts</h2>
            <table>
                <thead><tr><th>Hostname</th><th>Source</th><th>IPs résolues</th><th>Première détection</th></tr></thead>
                <tbody>
                <?php if (empty($subdomains)): ?>
                    <tr><td colspan="4" style="color:#94a3b8;">Aucun sous-domaine découvert pour le moment. Lance un scan.</td></tr>
                <?php endif; ?>
                <?php foreach ($subdomains as $s): ?>
                    <tr>
                        <td><?= htmlspecialchars($s['hostname']) ?></td>
                        <td><?= htmlspecialchars($s['source']) ?></td>
                        <td><?= (int)$s['ip_count'] ?></td>
                        <td><?= htmlspecialchars($s['first_seen']) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Alertes de veille (changements détectés entre scans)</h2>
            <table>
                <thead><tr><th>Type</th><th>Message</th><th>Date</th></tr></thead>
                <tbody>
                <?php if (empty($alerts)): ?>
                    <tr><td colspan="3" style="color:#94a3b8;">Aucune alerte pour le moment. Les alertes n'apparaissent que pour de vrais changements (nouvel actif, port fermé, nouvelle CVE...).</td></tr>
                <?php endif; ?>
                <?php foreach ($alerts as $a): ?>
                    <tr>
                        <td><span class="badge status"><?= htmlspecialchars($a['type']) ?></span></td>
                        <td><?= htmlspecialchars($a['message']) ?></td>
                        <td><?= htmlspecialchars($a['created_at']) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Historique des scans</h2>
            <table>
                <thead><tr><th>#</th><th>Statut</th><th>Nouveaux actifs</th><th>Démarré</th><th>Terminé</th></tr></thead>
                <tbody>
                <?php if (empty($scans)): ?>
                    <tr><td colspan="5" style="color:#94a3b8;">Aucun scan effectué pour le moment.</td></tr>
                <?php endif; ?>
                <?php foreach ($scans as $sc): ?>
                    <tr>
                        <td><?= (int)$sc['id'] ?></td>
                        <td><span class="badge status"><?= htmlspecialchars($sc['status']) ?></span></td>
                        <td><?= (int)$sc['new_assets_count'] ?></td>
                        <td><?= htmlspecialchars($sc['started_at'] ?? '—') ?></td>
                        <td><?= htmlspecialchars($sc['finished_at'] ?? '—') ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </main>

    <script>
        window.ROOT_DOMAIN = <?= json_encode($org['root_domain']) ?>;
        window.SUBDOMAINS = <?= json_encode(array_column($subdomains, 'hostname')) ?>;
    </script>
    <script src="js/graph.js"></script>
</body>
</html>
