<?php
require_once 'config.php';
verificarSesion();

header('Content-Type: application/json');

try {
    if (!isset($_GET['id'])) {
        throw new Exception('ID no proporcionado');
    }

    $stmt = $conn->prepare("
        SELECT v.*, 
               (SELECT COUNT(*) FROM clientes WHERE vendedor_id = v.id) as total_clientes
        FROM vendedores v 
        WHERE v.id = ?
    ");
    
    $stmt->execute([$_GET['id']]);
    $vendedor = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$vendedor) {
        throw new Exception('Vendedor no encontrado');
    }

    echo json_encode([
        'success' => true,
        'data' => $vendedor
    ]);

} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
}
?>