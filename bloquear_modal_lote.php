<?php
require_once 'config.php';

try {
    $stmt = $conn->prepare("
        INSERT INTO generacion_lote_lock (usuario_id, timestamp, estado)
        VALUES (?, NOW(), 'activo')
    ");
    $stmt->execute([$_SESSION['usuario_id']]);
    
    echo json_encode(['success' => true]);
} catch(PDOException $e) {
    echo json_encode(['error' => $e->getMessage()]);
}
?>