<?php
require_once 'config.php';
header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Método no permitido.']);
    exit;
}

$data = json_decode(file_get_contents('php://input'), true);

if (!$data || !isset($data['cobrador_id'], $data['fecha_asignacion'], $data['facturas'])) {
    echo json_encode(['success' => false, 'message' => 'Datos incompletos.']);
    exit;
}

if (empty($data['facturas'])) {
    echo json_encode(['success' => false, 'message' => 'Debe incluir al menos una factura.']);
    exit;
}

try {
    $conn->beginTransaction();

    foreach ($data['facturas'] as $factura_id) {
        $factura_id = (int)$factura_id;
        if ($factura_id <= 0) continue;

        /* Si ya existe asignación activa, marcarla como reasignada */
        $stmt = $conn->prepare("
            SELECT id, cobrador_id, fecha_asignacion
            FROM asignaciones_facturas
            WHERE factura_id = ? AND estado = 'activa'
        ");
        $stmt->execute([$factura_id]);
        $existente = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($existente) {
            /* Registrar en historial */
            $conn->prepare("
                INSERT INTO historial_reasignaciones
                    (asignacion_id, cobrador_anterior_id, fecha_anterior, cobrador_nuevo_id, fecha_nueva)
                VALUES (?, ?, ?, ?, ?)
            ")->execute([
                $existente['id'],
                $existente['cobrador_id'],
                $existente['fecha_asignacion'],
                $data['cobrador_id'],
                $data['fecha_asignacion']
            ]);

            /* Marcar anterior como reasignada */
            $conn->prepare("
                UPDATE asignaciones_facturas SET estado = 'reasignada' WHERE id = ?
            ")->execute([$existente['id']]);
        }

        /* Crear nueva asignación */
        $conn->prepare("
            INSERT INTO asignaciones_facturas (factura_id, cobrador_id, fecha_asignacion, estado)
            VALUES (?, ?, ?, 'activa')
        ")->execute([$factura_id, $data['cobrador_id'], $data['fecha_asignacion']]);
    }

    $conn->commit();
    echo json_encode(['success' => true, 'message' => 'Facturas asignadas correctamente.']);

} catch (PDOException $e) {
    $conn->rollBack();
    error_log("Error en guardar_asignacion: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Error al guardar la asignación.']);
}
?>