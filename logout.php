<?php
require_once __DIR__ . '/auth.php';
start_session();
logout();
header('Location: login.php');
exit;
