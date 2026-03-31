<?php
require_once 'config.php';
verificarSesion();

header('Content-Type: application/json');

try {
    $data = json_decode(file_get_contents('php://input'), true);
    
    if (!isset($data['beneficiario_id'])) {
        throw new Exception('ID de beneficiario no proporcionado');
    }

    $stmt = $conn->prepare("DELETE FROM beneficiarios WHERE id = ?");
    $stmt->execute([$data['beneficiario_id']]);

    if ($stmt->rowCount() > 0) {
        echo json_encode([
            'success' => true,
            'message' => 'Beneficiario eliminado correctamente'
        ]);
    } else {
        throw new Exception('No se encontró el beneficiario');
    }

} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
}