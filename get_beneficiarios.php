<?php
require_once 'config.php';
verificarSesion();

header('Content-Type: application/json');

try {
    if (!isset($_GET['contrato_id'])) {
        throw new Exception('ID de contrato no proporcionado');
    }

    $stmt = $conn->prepare("
        SELECT id, contrato_id, nombre, apellidos, parentesco, 
               porcentaje, fecha_nacimiento
        FROM beneficiarios 
        WHERE contrato_id = ?
        ORDER BY nombre, apellidos
    ");
    
    $stmt->execute([$_GET['contrato_id']]);
    $beneficiarios = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Formatear fechas
    foreach ($beneficiarios as &$beneficiario) {
    if ($beneficiario['fecha_nacimiento']) {
        // Asegurarse de que la fecha esté en formato Y-m-d
        $beneficiario['fecha_nacimiento'] = date('Y-m-d', strtotime($beneficiario['fecha_nacimiento']));
    }
}

    echo json_encode([
        'success' => true,
        'beneficiarios' => $beneficiarios
    ]);

} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
}