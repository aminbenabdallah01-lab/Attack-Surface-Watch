<?php
require_once __DIR__ . '/auth.php';
start_session();
require_login();

$db = get_db();

$stmt = $db->prepare(
    'SELECT o.*,
        (SELECT COUNT(*) FROM subdomains s WHERE s.organization_id = o.id AND s.is_active = 1) AS asset_count,
        (
            (SELECT COUNT(*) FROM vulnerabilities v
                JOIN services sv ON v.service_id = sv.id
                JOIN ip_addresses ip ON sv.ip_address_id = ip.id
                JOIN subdomains sd ON ip.subdomain_id = sd.id
                WHERE sd.organization_id = o.id AND v.status = "open" AND v.is_active = 1 AND v.severity IN ("high","critical")
            ) +
            (SELECT COUNT(*) FROM vulnerabilities v
                JOIN technologies t ON v.technology_id = t.id
                JOIN subdomains sd ON t.subdomain_id = sd.id
                WHERE sd.organization_id = o.id AND v.status = "open" AND v.is_active = 1 AND v.severity IN ("high","critical")
            )
        ) AS critical_vuln_count
     FROM organizations o
     JOIN organization_user ou ON ou.organization_id = o.id
     WHERE ou.user_id = ?
     ORDER BY o.name'
);
$stmt->execute([current_user_id()]);
$organizations = $stmt->fetchAll();

$flashSuccess = $_SESSION['flash_success'] ?? null;
$flashError   = $_SESSION['flash_error'] ?? null;
unset($_SESSION['flash_success'], $_SESSION['flash_error']);
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Dashboard — Attack Surface Watch</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="css/style.css">
</head>
<body>
    <header>
        <h1>🛡 Attack Surface Watch</h1>
        <div>
            <span style="font-size:13px; color:#94a3b8; margin-right:16px;"><?= htmlspecialchars($_SESSION['user_name'] ?? '') ?></span>
            <a href="account.php" style="margin-right:16px;">Mon compte</a>
            <a href="logout.php">Déconnexion</a>
        </div>
    </header>
    <main>
        <?php if ($flashSuccess): ?>
            <div class="flash success"><?= htmlspecialchars($flashSuccess) ?></div>
        <?php endif; ?>
        <?php if ($flashError): ?>
            <div class="flash error"><?= htmlspecialchars($flashError) ?></div>
        <?php endif; ?>

        <div class="section">
            <h2>Tester un nouveau domaine</h2>
            <form method="POST" action="add_organization.php" style="display:flex; gap:12px; align-items:flex-end; flex-wrap:wrap;">
                <div style="flex:1; min-width:220px;">
                    <label for="root_domain">Domaine à analyser</label>
                    <input type="text" id="root_domain" name="root_domain" placeholder="ex: example.com" required style="margin-bottom:0;">
                </div>
                <div style="flex:1; min-width:220px;">
                    <label for="name">Nom (optionnel)</label>
                    <input type="text" id="name" name="name" placeholder="ex: Example Company - Test Environment" style="margin-bottom:0;">
                </div>
                <button type="submit">+ Ajouter & analyser</button>
            </form>
            <p style="font-size:12px; color:#64748b; margin-top:10px;">
                N'entre que des domaines pour lesquels tu as une autorisation explicite de scan (ta propre infra, un lab local comme Juice Shop, ou un scope autorisé).
            </p>
        </div>

        <h2 style="font-size:20px;">Domaines déjà suivis</h2>

        <?php if (empty($organizations)): ?>
            <p class="empty">Aucune organisation suivie pour le moment.</p>
        <?php else: ?>
        <div class="grid">
            <?php foreach ($organizations as $org): ?>
                <div class="card" style="position:relative;">
                    <form method="POST" action="delete_organization.php"
                          style="position:absolute; top:14px; right:14px; margin:0;"
                          onsubmit="return confirm('Supprimer « <?= htmlspecialchars(addslashes($org['name'])) ?> » et TOUTES ses données (scans, vulnérabilités, historique) ? Cette action est irréversible.');">
                        <input type="hidden" name="organization_id" value="<?= (int)$org['id'] ?>">
                        <button type="submit" title="Supprimer" style="background:transparent; color:#64748b; padding:4px 8px; font-size:16px; line-height:1;">✕</button>
                    </form>
                    <a href="organization.php?id=<?= (int)$org['id'] ?>" style="text-decoration:none; color:inherit; display:block;">
                        <h2 style="padding-right:24px;"><?= htmlspecialchars($org['name']) ?></h2>
                        <div class="domain"><?= htmlspecialchars($org['root_domain']) ?></div>
                        <div class="stats">
                            <div class="stat assets">
                                <span class="num"><?= (int)$org['asset_count'] ?></span>
                                actifs
                            </div>
                            <div class="stat critical">
                                <span class="num"><?= (int)$org['critical_vuln_count'] ?></span>
                                vuln. critiques/hautes
                            </div>
                        </div>
                    </a>
                </div>
            <?php endforeach; ?>
        </div>
        <p style="font-size:12px; color:#64748b; margin-top:16px;">Clique sur ✕ pour supprimer une organisation et toutes ses données associées.</p>
        <?php endif; ?>
    </main>
</body>
</html>
