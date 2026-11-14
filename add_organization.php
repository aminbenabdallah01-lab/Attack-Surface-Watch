<?php
require_once __DIR__ . '/auth.php';
start_session();
require_login();

$name = trim($_POST['name'] ?? '');
$rootDomain = trim($_POST['root_domain'] ?? '');

// Nettoyage basique : si l'utilisateur colle une URL complète, on garde juste le host
$rootDomain = preg_replace('#^https?://#i', '', $rootDomain);
$rootDomain = rtrim($rootDomain, '/');
$rootDomain = explode('/', $rootDomain)[0]; // enlève un éventuel /chemin
$rootDomain = strtolower($rootDomain);

if ($rootDomain === '') {
    $_SESSION['flash_error'] = "Merci d'indiquer un domaine (ex: juiceshop.local ou mondomaine.tn).";
    header('Location: dashboard.php');
    exit;
}

if ($name === '') {
    $name = $rootDomain; // nom par défaut = le domaine lui-même
}

// Validation basique du format domaine (lettres, chiffres, points, tirets)
if (!preg_match('/^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$/', $rootDomain)) {
    $_SESSION['flash_error'] = "Format de domaine invalide : {$rootDomain}";
    header('Location: dashboard.php');
    exit;
}

$db = get_db();

// Évite les doublons pour cet utilisateur (même domaine déjà suivi)
$check = $db->prepare(
    'SELECT o.id FROM organizations o
     JOIN organization_user ou ON ou.organization_id = o.id
     WHERE ou.user_id = ? AND o.root_domain = ?'
);
$check->execute([current_user_id(), $rootDomain]);
$existing = $check->fetch();

if ($existing) {
    // Déjà suivi -> on redirige direct dessus, pas de doublon créé
    header('Location: organization.php?id=' . (int) $existing['id']);
    exit;
}

$insert = $db->prepare('INSERT INTO organizations (name, root_domain, created_by) VALUES (?, ?, ?)');
$insert->execute([$name, $rootDomain, current_user_id()]);
$orgId = (int) $db->lastInsertId();

$link = $db->prepare('INSERT INTO organization_user (organization_id, user_id) VALUES (?, ?)');
$link->execute([$orgId, current_user_id()]);

$_SESSION['flash_success'] = "Organisation « {$name} » ajoutée. Lance un scan pour découvrir ses actifs.";
header('Location: organization.php?id=' . $orgId);
exit;
