<?php
declare(strict_types=1);

header('Content-Type: application/json');
echo json_encode([
    'marker' => 'PHP_RFC1867_RCE_LAB_V1',
    'pid' => getmypid(),
    'version' => PHP_VERSION,
    'sapi' => PHP_SAPI,
    'memory_limit' => ini_get('memory_limit'),
    'post_max_size' => ini_get('post_max_size'),
    'upload_progress' => ini_get('session.upload_progress.enabled'),
    'use_zend_alloc' => getenv('USE_ZEND_ALLOC'),
    'use_tracked_alloc' => getenv('USE_TRACKED_ALLOC'),
], JSON_UNESCAPED_SLASHES), "\n";
