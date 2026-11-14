<?php
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/scan_orchestrator.php';
start_session();
require_login();

$orgId = (int) ($_POST['organization_id'] ?? 0);

if ($orgId <= 0) {
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

// Empêche de lancer deux scans en parallèle sur la même organisation
$running = $db->prepare(
    "SELECT id FROM scans WHERE organization_id = ? AND status IN ('pending','running') ORDER BY id DESC LIMIT 1"
);
$running->execute([$orgId]);

if ($running->fetch()) {
    $_SESSION['flash_error'] = "Un scan est déjà en cours pour cette organisation. Annule-le d'abord si tu veux en relancer un autre.";
    header('Location: organization.php?id=' . $orgId);
    exit;
}

// Lance le scan en arrière-plan (process séparé) — la page se recharge tout
// de suite, pas besoin d'attendre la fin. L'utilisateur peut l'annuler tant
// qu'il tourne (bouton "Annuler le scan" sur organization.php).
try {
    $scanId = launch_background_scan($orgId);
    $_SESSION['flash_success'] = "Scan #{$scanId} lancé en arrière-plan. Tu peux quitter la page ou l'annuler à tout moment pendant qu'il tourne.";
} catch (Throwable $e) {
    error_log('[run_scan.php] ' . $e->getMessage());
    $_SESSION['flash_error'] = "Impossible de lancer le scan : " . $e->getMessage();
}

header('Location: organization.php?id=' . $orgId);
exit;
