<?php
require_once __DIR__ . '/config_cobrador.php';

// Registrar logout en log
if (!empty($_SESSION['cobrador_portal_id'])) {
    registrarLogCobrador((int)$_SESSION['cobrador_portal_id'], 'logout');
}

// Destruir solo variables del portal cobrador
$keysToDestroy = [
    'cobrador_portal_id',
    'cobrador_portal_nombre',
    'cobrador_portal_codigo',
    'cobrador_portal_uid',
    'cobrador_portal_rol',
    'csrf_token_cobrador',
    'cobrador_redirect_after_login',
];
foreach ($keysToDestroy as $key) {
    unset($_SESSION[$key]);
}

// Si no quedan más datos de sesión, destruir completamente
if (empty($_SESSION)) {
    session_destroy();
}

header('Location: index.php?logout=1');
exit();