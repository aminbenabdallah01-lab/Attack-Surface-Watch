<?php
require_once __DIR__ . '/config.php';

/**
 * Envoi d'alertes email. Remplace le corps de send_email() par une
 * vraie intégration PHPMailer (comme fait pour SecuriNets FSG) si tu
 * veux passer par Gmail SMTP plutôt que mail() natif.
 */
function send_new_vulnerability_alert(string $toEmail, string $orgName, array $vulnerability): bool
{
    $subject = "[ALERTE] Nouvelle vulnérabilité {$vulnerability['severity']} détectée - {$orgName}";

    $body = "Une nouvelle vulnérabilité a été détectée sur votre surface d'attaque :\n\n"
          . "Organisation : {$orgName}\n"
          . "CVE          : {$vulnerability['cve_id']}\n"
          . "Sévérité     : {$vulnerability['severity']}\n"
          . "Score CVSS   : {$vulnerability['cvss_score']}\n"
          . "Description  : {$vulnerability['description']}\n\n"
          . "Connectez-vous au dashboard pour plus de détails.";

    return send_email($toEmail, $subject, $body);
}

function send_new_asset_alert(string $toEmail, string $orgName, string $hostname): bool
{
    $subject = "[INFO] Nouvel actif découvert - {$orgName}";
    $body = "Un nouveau sous-domaine a été découvert lors du dernier scan :\n\n"
          . "Organisation : {$orgName}\n"
          . "Hostname     : {$hostname}\n\n"
          . "Vérifiez qu'il s'agit bien d'un actif légitime et autorisé.";

    return send_email($toEmail, $subject, $body);
}

function send_email(string $toEmail, string $subject, string $body): bool
{
    if (empty(SMTP_USER) || empty(SMTP_PASS)) {
        error_log("[alert_notifier] SMTP non configuré, alerte non envoyée : {$subject}");
        return false;
    }

    // Placeholder simple avec mail() natif. Remplace par PHPMailer pour un envoi
    // fiable via Gmail SMTP (comme sur SecuriNets) :
    //   require 'PHPMailer/PHPMailerAutoload.php';
    //   $mail = new PHPMailer(true);
    //   $mail->isSMTP(); $mail->Host = SMTP_HOST; $mail->SMTPAuth = true;
    //   $mail->Username = SMTP_USER; $mail->Password = SMTP_PASS;
    //   $mail->SMTPSecure = 'tls'; $mail->Port = SMTP_PORT;
    //   $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
    //   $mail->addAddress($toEmail); $mail->Subject = $subject; $mail->Body = $body;
    //   return $mail->send();
    $headers = "From: " . SMTP_FROM_NAME . " <" . SMTP_FROM_EMAIL . ">\r\n";
    return @mail($toEmail, $subject, $body, $headers);
}

function send_webhook_alert(string $webhookUrl, string $message): bool
{
    $payload = json_encode(['text' => $message]);

    $context = stream_context_create([
        'http' => [
            'method'  => 'POST',
            'header'  => "Content-Type: application/json\r\n",
            'content' => $payload,
            'timeout' => 10,
        ],
    ]);

    $result = @file_get_contents($webhookUrl, false, $context);
    return $result !== false;
}
