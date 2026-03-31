<?php
require_once 'config.php';

try {
    $stmt = $conn->prepare("
        SELECT usuario_id 
        FROM generacion_lote_lock 
        WHERE estado = 'activo' 
        AND timestamp >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)
    ");
    $stmt->execute();
    $bloqueo = $stmt->fetch();

    echo json_encode([
        'bloqueado' => $bloqueo !== false,
        'usuario_id' => $bloqueo ? $bloqueo['usuario_id'] : null
    ]);
} catch(PDOException $e) {
    echo json_encode(['error' => $e->getMessage()]);
}
?>