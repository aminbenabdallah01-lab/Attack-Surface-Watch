<?php
/**
 * Exécuter une seule fois après avoir importé schema.sql :
 *   php seed.php
 */
require_once __DIR__ . '/db.php';

$db = get_db();

$adminEmail    = 'admin@securinets.local';
$adminPassword = 'ChangeMe123!'; // À CHANGER après la première connexion

$hash = password_hash($adminPassword, PASSWORD_DEFAULT);

$stmt = $db->prepare(
    'INSERT INTO users (full_name, email, password_hash, role) VALUES (?, ?, ?, "admin")
     ON DUPLICATE KEY UPDATE full_name = VALUES(full_name)'
);
$stmt->execute(['Administrateur', $adminEmail, $hash]);
$adminId = $db->lastInsertId() ?: $db->query("SELECT id FROM users WHERE email = '{$adminEmail}'")->fetchColumn();

$stmt = $db->prepare('INSERT INTO organizations (name, root_domain, created_by) VALUES (?, ?, ?)');
$stmt->execute(['Organisation Démo', 'example.com', $adminId]);
$orgId = $db->lastInsertId();

$stmt = $db->prepare('INSERT INTO organization_user (organization_id, user_id) VALUES (?, ?)');
$stmt->execute([$orgId, $adminId]);

echo "Seed terminé.\n";
echo "Connexion : {$adminEmail} / {$adminPassword}\n";
