<?php
require_once 'config.php';

if ($_SESSION['rol'] !== 'admin') {
    echo json_encode(['error' => 'Acceso no autorizado']);
    exit;
}

try {
    $data = json_decode(file_get_contents('php://input'), true);
    $id = $data['id'];
    
    $stmt = $conn->prepare("
        UPDATE generacion_lote_lock 
        SET estado = 'inactivo' 
        WHERE id = ? AND estado = 'activo'
    ");
    
    $stmt->execute([$id]);
    
    if ($stmt->rowCount() > 0) {
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['error' => 'El registro ya no está activo']);
    }
} catch(PDOException $e) {
    echo json_encode(['error' => $e->getMessage()]);
}
?>