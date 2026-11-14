<?php
// Test isolé de résolution DNS pour fsg.rnu.tn — à supprimer après diagnostic.
// Ouvre http://localhost/attack-surface/test_dns.php

$domain = 'fsg.rnu.tn';

echo '<pre>';
echo "=== Test 1 : dns_get_record (A) ===\n";
$a = @dns_get_record($domain, DNS_A);
var_dump($a);

echo "\n=== Test 2 : dns_get_record (AAAA) ===\n";
$aaaa = @dns_get_record($domain, DNS_AAAA);
var_dump($aaaa);

echo "\n=== Test 3 : gethostbyname ===\n";
$ip = @gethostbyname($domain);
echo "Résultat : {$ip}\n";
echo "Résolu avec succès : " . ($ip !== $domain ? 'OUI' : 'NON (renvoie le hostname tel quel = échec)') . "\n";

echo "\n=== Test 4 : gethostbynamel (toutes les IPs) ===\n";
$ips = @gethostbynamel($domain);
var_dump($ips);

echo "\n=== Test 5 : checkdnsrr ===\n";
var_dump(checkdnsrr($domain, 'A'));

echo "\n=== Test 6 : fonction resolve_ips() de l'app ===\n";
require_once __DIR__ . '/subdomain_enum.php';
$result = resolve_ips($domain);
var_dump($result);

echo "\n=== Test 7 : enumerate_subdomains() complet (racine + crt.sh + bruteforce) ===\n";
$discovered = enumerate_subdomains($domain);
var_dump($discovered);

echo '</pre>';
