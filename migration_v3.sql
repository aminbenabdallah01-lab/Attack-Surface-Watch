-- =====================================================================
-- Migration v3 : annulation de scan (scan en arrière-plan + PID + statut
-- "cancelled")
-- À exécuter dans phpMyAdmin > onglet SQL > coller > Go
-- Ne supprime aucune donnée existante.
-- =====================================================================

USE attack_surface_platform;

ALTER TABLE scans
    ADD COLUMN pid INT NULL AFTER triggered_by,
    MODIFY COLUMN status ENUM('pending','running','completed','failed','cancelled') NOT NULL DEFAULT 'pending';
