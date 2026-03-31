<?php
require_once 'config.php';
verificarSesion();

header('Content-Type: application/json');

try {
    if (!isset($_GET['id'])) {
        throw new Exception('ID del dependiente no proporcionado');
    }

    $dependienteId = (int)$_GET['id'];

    // Verificar que el dependiente existe
    $stmt = $conn->prepare("
        SELECT id FROM dependientes WHERE id = ?
    ");
    $stmt->execute([$dependienteId]);
    if (!$stmt->fetch()) {
        throw new Exception('Dependiente no encontrado');
    }

    // Obtener historial de cambios de plan
    $stmt = $conn->prepare("
        SELECT 
            h.*,
            p1.nombre as plan_anterior_nombre,
            p1.precio_base as plan_anterior_precio,
            p2.nombre as plan_nuevo_nombre,
            p2.precio_base as plan_nuevo_precio,
            u.nombre as usuario_nombre
        FROM historial_cambios_plan_dependientes h
        JOIN planes p1 ON h.plan_anterior_id = p1.id
        JOIN planes p2 ON h.plan_nuevo_id = p2.id
        JOIN usuarios u ON h.usuario_id = u.id
        WHERE h.dependiente_id = ?
        ORDER BY h.fecha_cambio DESC
    ");
    
    $stmt->execute([$dependienteId]);
    $historial = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Formatear fechas y datos adicionales
    foreach ($historial as &$cambio) {
        // Formatear fecha
        $cambio['fecha_cambio'] = date('Y-m-d H:i:s', strtotime($cambio['fecha_cambio']));
        
        // Calcular diferencia de precio
        $cambio['diferencia_precio'] = $cambio['plan_nuevo_precio'] - $cambio['plan_anterior_precio'];
        
        // Agregar indicador si el cambio fue a plan geriátrico
        $cambio['es_cambio_geriatrico'] = false;
        if ($cambio['plan_nuevo_id'] == 5) { // ID del plan geriátrico
            $cambio['es_cambio_geriatrico'] = true;
        }

        // Formatear motivo si está vacío
        if (empty($cambio['motivo'])) {
            $cambio['motivo'] = 'No especificado';
        }
        
        // Limpiar datos sensibles o innecesarios
        unset($cambio['usuario_id']);
        unset($cambio['plan_anterior_id']);
        unset($cambio['plan_nuevo_id']);
    }

    echo json_encode([
        'success' => true,
        'data' => $historial
    ]);

} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
}
?>