<?php
/**
 * Worker exécuté en arrière-plan par launch_background_scan() (lui-même
 * appelé depuis run_scan.php). NE PAS ouvrir cette page dans le navigateur —
 * c'est un script CLI uniquement, lancé via `php scan_worker.php <org_id> <scan_id>`.
 *
 * C'est ce process séparé qui peut être annulé (tué) par cancel_scan.php
 * pendant qu'un scan est en cours, sans bloquer le navigateur de l'utilisateur.
 */

require_once __DIR__ . '/scan_orchestrator.php';

$orgId  = (int) ($argv[1] ?? 0);
$scanId = (int) ($argv[2] ?? 0);

if ($orgId <= 0 || $scanId <= 0) {
    fwrite(STDERR, "Usage: php scan_worker.php <organization_id> <scan_id>\n");
    exit(1);
}

try {
    run_scan($orgId, $scanId);
    exit(0);
} catch (Throwable $e) {
    fwrite(STDERR, '[scan_worker] ' . $e->getMessage() . "\n");
    exit(1);
}
