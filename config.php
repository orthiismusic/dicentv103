<?php
// config.php
define('DB_HOST', 'localhost');
define('DB_USER', 'xygfyvca_disen101');
define('DB_PASS', '*Camil7172*');
define('DB_NAME', 'xygfyvca_disen101');

// Configurar parámetros de sesión antes de iniciarla
ini_set('session.cookie_httponly', 1);
ini_set('session.use_only_cookies', 1);
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => true,
    'httponly' => true
]);

// Iniciar sesión en todas las páginas
session_start();

try {
    $conn = new PDO("mysql:host=".DB_HOST.";dbname=".DB_NAME, DB_USER, DB_PASS);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    error_log("Error de conexión: " . $e->getMessage());
    die("Error de conexión con la base de datos");
}


function verificarSesion() {
    // Verificar si existe la sesión
    if (!isset($_SESSION['usuario_id'])) {
        // Si estamos en una petición AJAX, enviar código de error específico
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
            strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
            header('HTTP/1.1 401 Unauthorized');
            exit('Sesion_expirada');
        }
        
        // Para peticiones normales, redirigir al login
        header('Location: login.php?mensaje=sesion_expirada');
        exit();
    }
    
    // Verificar si la sesión ha expirado
    if (isset($_SESSION['ultima_actividad']) && (time() - $_SESSION['ultima_actividad'] > 3600)) {
        // Destruir la sesión
        session_unset();
        session_destroy();
        
        // Si es una petición AJAX
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
            strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
            header('HTTP/1.1 401 Unauthorized');
            exit('Sesion_expirada');
        }
        
        // Para peticiones normales
        header('Location: login.php?mensaje=sesion_expirada');
        exit();
    }
    
    // Actualizar el tiempo de última actividad
    $_SESSION['ultima_actividad'] = time();
}
?>