<?php
require_once 'config.php';
header('Content-Type: application/json; charset=utf-8');

$data = json_decode(file_get_contents('php://input'), true);

if (!isset($data['asignaciones_ids'], $data['nuevo_cobrador_id'], $data['nueva_fecha'])) {
    echo json_encode(['success' => false, 'message' => 'Datos incompletos.']);
    exit;
}

$ids          = $data['asignaciones_ids'];
$nuevoCobr    = $data['nuevo_cobrador_id'];
$nuevaFecha   = $data['nueva_fecha'];

try {
    $conn->beginTransaction();
    $contador = 0;

    foreach ($ids as $id) {
        $id = (int)trim($id);
        if ($id <= 0) continue;

        /* Obtener asignación activa */
        $stmt = $conn->prepare("
            SELECT id, cobrador_id, fecha_asignacion, factura_id
            FROM asignaciones_facturas
            WHERE id = ? AND estado = 'activa'
        ");
        $stmt->execute([$id]);
        $asig = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$asig) continue;

        /* Registrar historial */
        $conn->prepare("
            INSERT INTO historial_reasignaciones
                (asignacion_id, cobrador_anterior_id, fecha_anterior, cobrador_nuevo_id, fecha_nueva)
            VALUES (?, ?, ?, ?, ?)
        ")->execute([$id, $asig['cobrador_id'], $asig['fecha_asignacion'], $nuevoCobr, $nuevaFecha]);

        /* Limpiar historial referenciado */
        $conn->prepare("DELETE FROM historial_reasignaciones WHERE asignacion_id = ?")
             ->execute([$id]);

        /* Eliminar asignación original */
        $conn->prepare("DELETE FROM asignaciones_facturas WHERE id = ?")
             ->execute([$id]);

        /* Crear nueva asignación */
        $conn->prepare("
            INSERT INTO asignaciones_facturas (factura_id, cobrador_id, fecha_asignacion, estado)
            VALUES (?, ?, ?, 'activa')
        ")->execute([$asig['factura_id'], $nuevoCobr, $nuevaFecha]);

        $contador++;
    }

    if ($contador === 0) {
        throw new Exception('No se procesó ninguna asignación válida.');
    }

    $conn->commit();
    echo json_encode([
        'success'              => true,
        'message'              => 'Asignaciones reasignadas exitosamente.',
        'registros_procesados' => $contador
    ]);

} catch (Exception $e) {
    $conn->rollBack();
    error_log("Error en reasignar_asignaciones_grupo: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Error: ' . $e->getMessage()]);
}
?>