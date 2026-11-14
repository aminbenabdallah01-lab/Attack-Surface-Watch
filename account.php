<?php
require_once __DIR__ . '/auth.php';
start_session();
require_login();

$db = get_db();
$userId = current_user_id();

$error = null;
$success = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $currentPassword = $_POST['current_password'] ?? '';
    $newPassword     = $_POST['new_password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';

    $stmt = $db->prepare('SELECT * FROM users WHERE id = ?');
    $stmt->execute([$userId]);
    $user = $stmt->fetch();

    if (!$user || !password_verify($currentPassword, $user['password_hash'])) {
        $error = 'Mot de passe actuel incorrect.';
    } elseif (strlen($newPassword) < 8) {
        $error = 'Le nouveau mot de passe doit contenir au moins 8 caractères.';
    } elseif ($newPassword !== $confirmPassword) {
        $error = 'Les mots de passe ne correspondent pas.';
    } else {
        $newHash = password_hash($newPassword, PASSWORD_DEFAULT);
        $update = $db->prepare('UPDATE users SET password_hash = ? WHERE id = ?');
        $update->execute([$newHash, $userId]);
        $success = 'Mot de passe mis à jour avec succès.';
    }
}

$stmt = $db->prepare('SELECT full_name, email, role, created_at FROM users WHERE id = ?');
$stmt->execute([$userId]);
$user = $stmt->fetch();
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Mon compte — Attack Surface Watch</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="css/style.css">
</head>
<body>
    <header>
        <div>
            <a class="back" href="dashboard.php">← Retour au dashboard</a>
        </div>
        <span style="font-size:13px; color:#94a3b8;"><?= htmlspecialchars($_SESSION['user_name'] ?? '') ?></span>
    </header>
    <main style="max-width:500px;">
        <h1 style="font-size:22px; color:#4fd1c5; margin-bottom:20px;">Mon compte</h1>

        <div class="section">
            <h2>Informations</h2>
            <p style="font-size:13px; color:#cbd5e1; margin-bottom:6px;">Nom : <?= htmlspecialchars($user['full_name']) ?></p>
            <p style="font-size:13px; color:#cbd5e1; margin-bottom:6px;">Email : <?= htmlspecialchars($user['email']) ?></p>
            <p style="font-size:13px; color:#cbd5e1;">Rôle : <?= htmlspecialchars($user['role']) ?></p>
        </div>

        <div class="section">
            <h2>Changer le mot de passe</h2>

            <?php if ($error): ?>
                <div class="error"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            <?php if ($success): ?>
                <div class="flash success"><?= htmlspecialchars($success) ?></div>
            <?php endif; ?>

            <form method="POST" action="account.php">
                <label for="current_password">Mot de passe actuel</label>
                <input type="password" id="current_password" name="current_password" required>

                <label for="new_password">Nouveau mot de passe</label>
                <input type="password" id="new_password" name="new_password" required minlength="8">

                <label for="confirm_password">Confirmer le nouveau mot de passe</label>
                <input type="password" id="confirm_password" name="confirm_password" required minlength="8">

                <button type="submit">Mettre à jour le mot de passe</button>
            </form>
        </div>
    </main>
</body>
</html>
