<?php
require_once __DIR__ . '/auth.php';
start_session();

if (is_logged_in()) {
    header('Location: dashboard.php');
    exit;
}

$error = null;
$fullName = '';
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $fullName = trim($_POST['full_name'] ?? '');
    $email    = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm  = $_POST['confirm_password'] ?? '';

    if ($fullName === '' || $email === '' || $password === '') {
        $error = 'Merci de remplir tous les champs.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Adresse email invalide.';
    } elseif (strlen($password) < 8) {
        $error = 'Le mot de passe doit contenir au moins 8 caractères.';
    } elseif ($password !== $confirm) {
        $error = 'Les mots de passe ne correspondent pas.';
    } else {
        $db = get_db();

        $check = $db->prepare('SELECT id FROM users WHERE email = ?');
        $check->execute([$email]);

        if ($check->fetch()) {
            $error = 'Un compte existe déjà avec cet email.';
        } else {
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $insert = $db->prepare(
                'INSERT INTO users (full_name, email, password_hash, role) VALUES (?, ?, ?, "analyst")'
            );
            $insert->execute([$fullName, $email, $hash]);
            $userId = (int) $db->lastInsertId();

            // Connecte directement le nouvel utilisateur
            session_regenerate_id(true);
            $_SESSION['user_id']   = $userId;
            $_SESSION['user_role'] = 'analyst';
            $_SESSION['user_name'] = $fullName;

            header('Location: dashboard.php');
            exit;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Créer un compte — Attack Surface Watch</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="css/style.css">
</head>
<body>
<div class="login-wrapper">
    <div class="login-box">
        <h1>🛡 Attack Surface Watch</h1>
        <p class="subtitle">Créer un compte</p>

        <?php if ($error): ?>
            <div class="error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <form method="POST" action="register.php">
            <label for="full_name">Nom complet</label>
            <input type="text" id="full_name" name="full_name" value="<?= htmlspecialchars($fullName) ?>" required autofocus>

            <label for="email">Email</label>
            <input type="email" id="email" name="email" value="<?= htmlspecialchars($email) ?>" required>

            <label for="password">Mot de passe</label>
            <input type="password" id="password" name="password" required minlength="8">

            <label for="confirm_password">Confirmer le mot de passe</label>
            <input type="password" id="confirm_password" name="confirm_password" required minlength="8">

            <button type="submit" style="width:100%;">Créer mon compte</button>
        </form>

        <p style="margin-top:16px; font-size:13px; color:#94a3b8; text-align:center;">
            Déjà un compte ? <a href="login.php" style="color:#4fd1c5;">Se connecter</a>
        </p>
    </div>
</div>
</body>
</html>
