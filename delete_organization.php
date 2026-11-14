<?php
require_once __DIR__ . '/auth.php';
start_session();
require_login();

$orgId = (int) ($_POST['organization_id'] ?? 0);

if ($orgId <= 0) {
    header('Location: dashboard.php');
    exit;
}

$db = get_db();

// Vérifie que l'organisation appartient bien à l'utilisateur connecté
$check = $db->prepare(
    'SELECT o.name FROM organizations o
     JOIN organization_user ou ON ou.organization_id = o.id
     WHERE o.id = ? AND ou.user_id = ?'
);
$check->execute([$orgId, current_user_id()]);
$org = $check->fetch();

if (!$org) {
    http_response_code(403);
    die('Accès non autorisé à cette organisation.');
}

// Empêche de supprimer une organisation dont le scan est en cours (on tuerait
// le worker en plein travail sans passer par cancel_scan.php proprement)
$running = $db->prepare(
    "SELECT id FROM scans WHERE organization_id = ? AND status IN ('pending','running') LIMIT 1"
);
$running->execute([$orgId]);

if ($running->fetch()) {
    $_SESSION['flash_error'] = "Un scan est en cours pour cette organisation. Annule-le d'abord avant de la supprimer.";
    header('Location: organization.php?id=' . $orgId);
    exit;
}

// ON DELETE CASCADE (schema.sql) nettoie automatiquement : subdomains,
// ip_addresses, services, technologies, vulnerabilities, scans, alerts,
// organization_user — tout ce qui est rattaché à cette organisation.
$delete = $db->prepare('DELETE FROM organizations WHERE id = ?');
$delete->execute([$orgId]);

$_SESSION['flash_success'] = "Organisation « {$org['name']} » supprimée avec toutes ses données.";
header('Location: dashboard.php');
exit;
