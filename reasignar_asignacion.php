<?php
require_once 'config.php';
header('Content-Type: application/json; charset=utf-8');

$data = json_decode(file_get_contents('php://input'), true);

if (!isset($data['asignacion_id'], $data['nuevo_cobrador_id'], $data['nueva_fecha'])) {
    echo json_encode(['success' => false, 'message' => 'Datos incompletos.']);
    exit;
}

try {
    $conn->beginTransaction();

    /* Obtener asignación actual */
    $stmt = $conn->prepare("
        SELECT id, cobrador_id, fecha_asignacion, factura_id
        FROM asignaciones_facturas
        WHERE id = ? AND estado = 'activa'
    ");
    $stmt->execute([$data['asignacion_id']]);
    $asig = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$asig) {
        $conn->rollBack();
        echo json_encode(['success' => false, 'message' => 'La asignación no existe o no está activa.']);
        exit;
    }

    /* Registrar en historial */
    $conn->prepare("
        INSERT INTO historial_reasignaciones
            (asignacion_id, cobrador_anterior_id, fecha_anterior, cobrador_nuevo_id, fecha_nueva)
        VALUES (?, ?, ?, ?, ?)
    ")->execute([
        $asig['id'], $asig['cobrador_id'], $asig['fecha_asignacion'],
        $data['nuevo_cobrador_id'], $data['nueva_fecha']
    ]);

    /* Eliminar historial referenciado y asignación original */
    $conn->prepare("DELETE FROM historial_reasignaciones WHERE asignacion_id = ?")
         ->execute([$asig['id']]);
    $conn->prepare("DELETE FROM asignaciones_facturas WHERE id = ?")
         ->execute([$asig['id']]);

    /* Crear nueva asignación */
    $conn->prepare("
        INSERT INTO asignaciones_facturas (factura_id, cobrador_id, fecha_asignacion, estado)
        VALUES (?, ?, ?, 'activa')
    ")->execute([$asig['factura_id'], $data['nuevo_cobrador_id'], $data['nueva_fecha']]);

    $conn->commit();
    echo json_encode(['success' => true, 'message' => 'Asignación reasignada exitosamente.']);

} catch (Exception $e) {
    $conn->rollBack();
    error_log("Error en reasignar_asignacion: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Error al reasignar: ' . $e->getMessage()]);
}
?>