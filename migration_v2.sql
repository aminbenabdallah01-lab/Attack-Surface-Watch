-- =====================================================================
-- Migration v2 : fiabilité du matching CVE + veille (diff détection)
-- À exécuter UNE FOIS sur la base existante (phpMyAdmin > SQL > coller > Go)
-- Ne supprime aucune donnée existante, ajoute seulement des colonnes/valeurs.
-- =====================================================================

USE attack_surface_platform;

-- ---------------------------------------------------------------------
-- 1) Vulnérabilités : traçabilité de la confiance du match
-- ---------------------------------------------------------------------
ALTER TABLE vulnerabilities
    ADD COLUMN confidence ENUM('high','medium','low') NOT NULL DEFAULT 'medium' AFTER severity,
    ADD COLUMN match_reason VARCHAR(255) NULL AFTER description,
    ADD COLUMN is_active TINYINT(1) NOT NULL DEFAULT 1 AFTER status;

-- ---------------------------------------------------------------------
-- 2) Services : éviter les doublons à chaque scan + détection de
--    ports/services retirés entre deux scans
-- ---------------------------------------------------------------------
ALTER TABLE services
    ADD COLUMN last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER detected_at,
    ADD COLUMN is_active TINYINT(1) NOT NULL DEFAULT 1 AFTER last_seen,
    ADD UNIQUE KEY uniq_service (ip_address_id, port, protocol);

-- ---------------------------------------------------------------------
-- 3) Technologies : idem, éviter les doublons + preuve de détection
-- ---------------------------------------------------------------------
ALTER TABLE technologies
    ADD COLUMN evidence VARCHAR(255) NULL AFTER category,
    ADD COLUMN last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER evidence,
    ADD COLUMN is_active TINYINT(1) NOT NULL DEFAULT 1 AFTER last_seen,
    ADD UNIQUE KEY uniq_technology (subdomain_id, tech_name);

-- ---------------------------------------------------------------------
-- 4) Alertes : nouveaux types pour la veille (actif retiré, port fermé,
--    techno changée)
-- ---------------------------------------------------------------------
ALTER TABLE alerts
    MODIFY COLUMN type ENUM(
        'new_asset','new_vulnerability','asset_changed',
        'asset_removed','port_closed','technology_removed'
    ) NOT NULL;

-- ---------------------------------------------------------------------
-- 5) Nettoyage optionnel : purger les données de démo (example.com)
--    pour repartir propre. Décommente si tu veux l'exécuter.
-- ---------------------------------------------------------------------
-- DELETE FROM organizations WHERE root_domain = 'example.com';
-- (les suppressions en cascade nettoient subdomains/services/technologies/vulnerabilities/scans/alerts liés)
