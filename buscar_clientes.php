<?php
require_once 'config.php';
verificarSesion();

header('Content-Type: application/json');

try {
    if (!isset($_GET['termino'])) {
        throw new Exception('Término de búsqueda no proporcionado');
    }

    $termino = $_GET['termino'];
    
    // Modificada la consulta para buscar solo por nombre/apellidos y cédula
    $sql = "SELECT id, codigo, nombre, apellidos, cedula 
            FROM clientes 
            WHERE estado = 'activo' 
            AND (
                CONCAT(nombre, ' ', apellidos) LIKE ? OR 
                cedula LIKE ?
            )
            ORDER BY nombre, apellidos
            LIMIT 10";
    
    $stmt = $conn->prepare($sql);
    
    $termino = "%$termino%";
    $stmt->execute([$termino, $termino]);
    
    $clientes = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode([
        'success' => true,
        'clientes' => $clientes
    ]);

} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
}