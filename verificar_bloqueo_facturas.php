<?php
require_once 'config.php';
verificarSesion();

header('Content-Type: application/json');

try {
    // Limpieza de bloqueos antiguos
    $stmt = $conn->prepare("
        UPDATE generacion_facturas_lock 
        SET estado = 'inactivo' 
        WHERE timestamp < DATE_SUB(NOW(), INTERVAL 5 MINUTE)
        AND estado = 'activo'
    ");
    $stmt->execute();

    // Verificar si hay un bloqueo activo
    $stmt = $conn->prepare("
        SELECT fl.*, u.nombre as usuario_nombre 
        FROM generacion_facturas_lock fl
        JOIN usuarios u ON fl.usuario_id = u.id 
        WHERE fl.estado = 'activo' 
        AND fl.timestamp >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)
    ");
    $stmt->execute();
    $bloqueo = $stmt->fetch();

    if ($bloqueo) {
        // Si existe un bloqueo y no es del usuario actual
        if ($bloqueo['usuario_id'] != $_SESSION['usuario_id']) {
            echo json_encode([
                'bloqueo' => true,
                'mensaje' => "El usuario {$bloqueo['usuario_nombre']} está generando facturas actualmente."
            ]);
            exit;
        }
    }

    // No hay bloqueo o el bloqueo es del usuario actual
    echo json_encode([
        'bloqueo' => false,
        'mensaje' => ''
    ]);

} catch(PDOException $e) {
    http_response_code(500);
    echo json_encode([
        'error' => true,
        'mensaje' => "Error en el servidor: " . $e->getMessage()
    ]);
}
?>