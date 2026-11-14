-- =====================================================================
-- Attack Surface Mapping & Vulnerability Watch Platform
-- Schéma de base de données (MySQL / MariaDB)
-- =====================================================================

CREATE DATABASE IF NOT EXISTS attack_surface_platform
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE attack_surface_platform;

-- ---------------------------------------------------------------------
-- Utilisateurs & rôles (admin / analyste)
-- ---------------------------------------------------------------------
CREATE TABLE users (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    full_name       VARCHAR(150) NOT NULL,
    email           VARCHAR(150) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    role            ENUM('admin','analyst') NOT NULL DEFAULT 'analyst',
    is_active       TINYINT(1) NOT NULL DEFAULT 1,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Organisations / cibles suivies (multi-tenant léger)
-- ---------------------------------------------------------------------
CREATE TABLE organizations (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(150) NOT NULL,
    root_domain     VARCHAR(255) NOT NULL,
    created_by      INT NOT NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Association users <-> organizations (un analyste peut suivre plusieurs cibles)
CREATE TABLE organization_user (
    organization_id INT NOT NULL,
    user_id          INT NOT NULL,
    PRIMARY KEY (organization_id, user_id),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Scans (chaque exécution du pipeline de découverte)
-- ---------------------------------------------------------------------
CREATE TABLE scans (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    organization_id INT NOT NULL,
    status          ENUM('pending','running','completed','failed','cancelled') NOT NULL DEFAULT 'pending',
    started_at      DATETIME NULL,
    finished_at     DATETIME NULL,
    triggered_by    ENUM('manual','scheduled') NOT NULL DEFAULT 'manual',
    pid             INT NULL,                   -- PID du process worker en arrière-plan (pour pouvoir l'annuler)
    new_assets_count INT NOT NULL DEFAULT 0,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Sous-domaines découverts
-- ---------------------------------------------------------------------
CREATE TABLE subdomains (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    organization_id INT NOT NULL,
    hostname        VARCHAR(255) NOT NULL,
    source          VARCHAR(50) NOT NULL,       -- crtsh | dns_bruteforce | manual
    first_seen      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active       TINYINT(1) NOT NULL DEFAULT 1,
    UNIQUE KEY uniq_subdomain (organization_id, hostname),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Adresses IP résolues pour chaque sous-domaine
-- ---------------------------------------------------------------------
CREATE TABLE ip_addresses (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    subdomain_id    INT NOT NULL,
    ip_address      VARCHAR(45) NOT NULL,       -- IPv4 ou IPv6
    resolved_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (subdomain_id) REFERENCES subdomains(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Ports & services détectés
-- ---------------------------------------------------------------------
CREATE TABLE services (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    ip_address_id   INT NOT NULL,
    port            INT NOT NULL,
    protocol        ENUM('tcp','udp') NOT NULL DEFAULT 'tcp',
    service_name    VARCHAR(100) NULL,          -- http, ssh, mysql...
    product         VARCHAR(150) NULL,          -- ex: Apache httpd
    version         VARCHAR(100) NULL,          -- ex: 2.4.41
    banner          TEXT NULL,
    detected_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active       TINYINT(1) NOT NULL DEFAULT 1,
    UNIQUE KEY uniq_service (ip_address_id, port, protocol),
    FOREIGN KEY (ip_address_id) REFERENCES ip_addresses(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Technologies détectées (type Wappalyzer) sur une cible web
-- ---------------------------------------------------------------------
CREATE TABLE technologies (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    subdomain_id    INT NOT NULL,
    tech_name       VARCHAR(150) NOT NULL,      -- ex: WordPress, PHP, nginx
    tech_version    VARCHAR(100) NULL,
    category        VARCHAR(100) NULL,          -- CMS, framework, web-server...
    evidence        VARCHAR(255) NULL,          -- preuve concrète de la détection (header/motif HTML)
    detected_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active       TINYINT(1) NOT NULL DEFAULT 1,
    UNIQUE KEY uniq_technology (subdomain_id, tech_name),
    FOREIGN KEY (subdomain_id) REFERENCES subdomains(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Vulnérabilités (CVE) liées à un service ou une techno détectée
-- ---------------------------------------------------------------------
CREATE TABLE vulnerabilities (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    service_id      INT NULL,
    technology_id   INT NULL,
    cve_id          VARCHAR(30) NOT NULL,       -- ex: CVE-2023-12345
    cvss_score      DECIMAL(3,1) NULL,
    severity        ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
    confidence      ENUM('high','medium','low') NOT NULL DEFAULT 'medium', -- fiabilité du match CVE
    description     TEXT NULL,
    match_reason    VARCHAR(255) NULL,          -- pourquoi ce CVE a été retenu (traçabilité anti faux-positif)
    published_at    DATE NULL,
    status          ENUM('open','acknowledged','resolved','false_positive') NOT NULL DEFAULT 'open',
    is_active       TINYINT(1) NOT NULL DEFAULT 1,
    detected_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
    FOREIGN KEY (technology_id) REFERENCES technologies(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Alertes envoyées (historique)
-- ---------------------------------------------------------------------
CREATE TABLE alerts (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    organization_id INT NOT NULL,
    vulnerability_id INT NULL,
    type            ENUM('new_asset','new_vulnerability','asset_changed','asset_removed','port_closed','technology_removed') NOT NULL,
    message         TEXT NOT NULL,
    channel         ENUM('email','webhook') NOT NULL DEFAULT 'email',
    sent_at         DATETIME NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Index utiles pour les recherches / dashboard
-- ---------------------------------------------------------------------
CREATE INDEX idx_vuln_severity ON vulnerabilities(severity, status);
CREATE INDEX idx_services_port ON services(port);
CREATE INDEX idx_subdomains_org ON subdomains(organization_id, is_active);
