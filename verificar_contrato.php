<?php
require_once 'config.php';

try {
    $numero_contrato = $_GET['contrato_id'] ?? '';
    
    // Agregar log
    error_log("Verificando contrato número: " . $numero_contrato);
    
    if (empty($numero_contrato)) {
        echo json_encode(['error' => 'Número de contrato no proporcionado']);
        exit;
    }
    
    $stmt = $conn->prepare("
        SELECT c.*, cl.nombre, cl.apellidos 
        FROM contratos c
        JOIN clientes cl ON c.cliente_id = cl.id
        WHERE c.numero_contrato = ? AND c.estado = 'activo'
    ");
    
    $stmt->execute([$numero_contrato]);
    $contrato = $stmt->fetch(PDO::FETCH_ASSOC);
    
    // Agregar log del resultado
    error_log("Resultado de la consulta: " . json_encode($contrato));
    
    if (!$contrato) {
        echo json_encode(['error' => 'Contrato no encontrado o inactivo']);
        exit;
    }
    
    $response = [
        'success' => true,
        'cliente' => [
            'nombre' => $contrato['nombre'],
            'apellidos' => $contrato['apellidos']
        ],
        'contrato' => [
            'id' => $contrato['id'],
            'numero_contrato' => $contrato['numero_contrato'],
            'monto_mensual' => $contrato['monto_mensual']
        ]
    ];
    
    // Agregar log de la respuesta
    error_log("Enviando respuesta: " . json_encode($response));
    
    echo json_encode($response);
} catch(PDOException $e) {
    error_log("Error PDO en verificar_contrato.php: " . $e->getMessage());
    echo json_encode(['error' => 'Error al verificar el contrato: ' . $e->getMessage()]);
} catch(Exception $e) {
    error_log("Error general en verificar_contrato.php: " . $e->getMessage());
    echo json_encode(['error' => 'Error general: ' . $e->getMessage()]);
}
?>