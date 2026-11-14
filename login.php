<?php
require_once __DIR__ . '/auth.php';
start_session();

if (is_logged_in()) {
    header('Location: dashboard.php');
    exit;
}

$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email    = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if (attempt_login($email, $password)) {
        header('Location: dashboard.php');
        exit;
    }
    $error = 'Email ou mot de passe incorrect.';
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Connexion — Attack Surface Watch</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="css/style.css">
</head>
<body>
<div class="login-wrapper">
    <div class="login-box">
        <h1>🛡 Attack Surface Watch</h1>
        <p class="subtitle">Cartographie & veille de vulnérabilités</p>

        <?php if ($error): ?>
            <div class="error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <form method="POST" action="login.php">
            <label for="email">Email</label>
            <input type="email" id="email" name="email" required autofocus>

            <label for="password">Mot de passe</label>
            <input type="password" id="password" name="password" required>

            <button type="submit" style="width:100%;">Se connecter</button>
        </form>

        <p style="margin-top:16px; font-size:13px; color:#94a3b8; text-align:center;">
            Pas encore de compte ? <a href="register.php" style="color:#4fd1c5;">Créer un compte</a>
        </p>
    </div>
</div>
</body>
</html>
