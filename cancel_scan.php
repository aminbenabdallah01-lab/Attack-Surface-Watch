<?php
require_once __DIR__ . '/auth.php';
start_session();
require_login();

$scanId = (int) ($_POST['scan_id'] ?? 0);
$orgId  = (int) ($_POST['organization_id'] ?? 0);

if ($scanId <= 0 || $orgId <= 0) {
    header('Location: dashboard.php');
    exit;
}

$db = get_db();

// Vérifie l'accès de l'utilisateur à cette organisation
$check = $db->prepare('SELECT 1 FROM organization_user WHERE organization_id = ? AND user_id = ?');
$check->execute([$orgId, current_user_id()]);

if (!$check->fetch()) {
    http_response_code(403);
    die('Accès non autorisé à cette organisation.');
}

// Vérifie que le scan appartient bien à CETTE organisation (jamais annuler
// un scan d'une autre organisation en devinant son id)
$stmt = $db->prepare('SELECT * FROM scans WHERE id = ? AND organization_id = ?');
$stmt->execute([$scanId, $orgId]);
$scan = $stmt->fetch();

if (!$scan) {
    http_response_code(404);
    die('Scan introuvable.');
}

if (!in_array($scan['status'], ['pending', 'running'], true)) {
    $_SESSION['flash_error'] = "Ce scan n'est plus en cours (statut actuel : {$scan['status']}), rien à annuler.";
    header('Location: organization.php?id=' . $orgId);
    exit;
}

// 1) On marque 'cancelled' en base TOUT DE SUITE — c'est ce que le worker
//    vérifie entre chaque sous-domaine (scan_is_cancelled() dans
//    scan_orchestrator.php), et c'est ce que l'utilisateur voit immédiatement
//    dans l'interface, même si le kill du process ci-dessous échoue ou tarde.
$update = $db->prepare('UPDATE scans SET status = "cancelled", finished_at = NOW() WHERE id = ?');
$update->execute([$scanId]);

// 2) On tue le process en arrière-plan pour arrêter tout de suite le scan
//    (nmap en cours, requêtes NVD, etc.) plutôt que d'attendre qu'il arrive
//    au prochain point de vérification.
if (!empty($scan['pid'])) {
    $pid = (int) $scan['pid'];
    if (stripos(PHP_OS, 'WIN') !== false) {
        exec('taskkill /F /T /PID ' . $pid . ' 2>&1', $out, $code);
    } else {
        exec('kill -9 ' . $pid . ' 2>&1', $out, $code);
    }
}

$_SESSION['flash_success'] = "Scan #{$scanId} annulé.";
header('Location: organization.php?id=' . $orgId);
exit;
