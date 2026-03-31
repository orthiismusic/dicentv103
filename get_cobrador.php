<?php
require_once 'config.php';
verificarSesion();

header('Content-Type: application/json');

try {
    if (!isset($_GET['id'])) {
        throw new Exception('ID no proporcionado');
    }

    $stmt = $conn->prepare("
        SELECT c.*, 
               (SELECT COUNT(*) FROM clientes WHERE cobrador_id = c.id) as total_clientes
        FROM cobradores c 
        WHERE c.id = ?
    ");
    
    $stmt->execute([$_GET['id']]);
    $cobrador = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$cobrador) {
        throw new Exception('Cobrador no encontrado');
    }

    echo json_encode([
        'success' => true,
        'data' => $cobrador
    ]);

} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
}
?>