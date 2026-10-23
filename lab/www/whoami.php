<?php
// ============================================================================
//  PHP2Shell Lab - endpoint de identidad del worker
//
//  Propósito de la demo: hacer visible el reemplazo del worker tras el
//  segfault. El master de Apache re-crea el hijo que muere, así que el PID
//  que atiende cada request cambia cuando el worker vulnerable muere
//  limpiando el estado corrupto (CVE-2026-109618).
//
//  GET /whoami.php -> "worker=<pid> php=<version> memory_limit=<limit>"
// ============================================================================
header('Content-Type: text/plain');
echo "worker=" . getmypid()
   . " php=" . PHP_VERSION
   . " memory_limit=" . ini_get('memory_limit')
   . "\n";
