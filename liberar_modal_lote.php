<?php
require_once 'config.php';

try {
    $stmt = $conn->prepare("
        UPDATE generacion_lote_lock 
        SET estado = 'inactivo' 
        WHERE usuario_id = ? 
        AND estado = 'activo'
    ");
    $stmt->execute([$_SESSION['usuario_id']]);
    
    echo json_encode(['success' => true]);
} catch(PDOException $e) {
    echo json_encode([
        'success' => false, 
        'error' => $e->getMessage()
    ]);
}
?>