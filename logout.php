<?php
require_once 'config.php';

// Registrar la hora de salida
if (isset($_SESSION['usuario_id'])) {
    try {
        $stmt = $conn->prepare("
            INSERT INTO logs_sistema (
                usuario_id, 
                accion, 
                detalles, 
                ip_address
            ) VALUES (?, 'logout', 'Cierre de sesión exitoso', ?)
        ");
        $stmt->execute([
            $_SESSION['usuario_id'],
            $_SERVER['REMOTE_ADDR']
        ]);

        // Actualizar último acceso del usuario
        $stmt = $conn->prepare("
            UPDATE usuarios 
            SET ultimo_acceso = NOW() 
            WHERE id = ?
        ");
        $stmt->execute([$_SESSION['usuario_id']]);
    } catch(PDOException $e) {
        // Continuar con el logout incluso si hay error en el log
        error_log("Error al registrar logout: " . $e->getMessage());
    }
}

// Destruir todas las variables de sesión
$_SESSION = array();

// Destruir la cookie de sesión si existe
if (isset($_COOKIE[session_name()])) {
    setcookie(session_name(), '', time()-42000, '/');
}

// Destruir la sesión
session_destroy();

// Redirigir al login con mensaje de éxito
header('Location: login.php?mensaje=logout_exitoso');
exit();
?>