<?php
// ============================================================================
//  PHP2Shell Lab - pagina objetivo minima
//
//  Punto clave del CVE-2026-109618: el fallo ocurre durante la INICIALIZACION
//  del request (parseo del POST), ANTES de que se ejecute ninguna linea de
//  esta aplicacion. Ni autenticacion ni validacion a nivel de aplicacion
//  pueden impedirlo. Por eso el objetivo es intencionadamente trivial.
// ============================================================================
echo "PHP2Shell Lab :: PHP " . PHP_VERSION . " :: objetivo minimo\n";
