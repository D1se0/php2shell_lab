<?php
declare(strict_types=1);

header('Content-Type: text/plain');
$mode = $_GET['mode'] ?? 'ping';

if ($mode === 'warm') {
    // Raise glibc's mmap threshold in the dedicated worker so the large
    // allocation remains in the process heap, matching the proven lab.
    $warm = str_repeat('W', 12 * 1024 * 1024);
    unset($warm);
    echo "warmed pid=", getmypid(), "\n";
    exit;
}

echo json_encode([
    'marker' => 'PHP_RFC1867_RCE_TARGET_V1',
    'pid' => getmypid(),
    'version' => PHP_VERSION,
    'mem_real' => memory_get_usage(true),
], JSON_UNESCAPED_SLASHES), "\n";
