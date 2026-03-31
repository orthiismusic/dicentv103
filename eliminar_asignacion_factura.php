<?php
require_once 'config.php';
header('Content-Type: application/json; charset=utf-8');

$data = json_decode(file_get_contents('php://input'), true);

if (!isset($data['factura_id'])) {
    echo json_encode(['success' => false, 'message' => 'ID de factura no proporcionado.']);
    exit;
}

try {
    $conn->beginTransaction();

    /* Obtener asignaci¨®n activa */
    $stmt = $conn->prepare("
        SELECT id FROM asignaciones_facturas
        WHERE factura_id = ? AND estado = 'activa'
    ");
    $stmt->execute([$data['factura_id']]);
    $asig = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($asig) {
        $conn->prepare("DELETE FROM historial_reasignaciones WHERE asignacion_id = ?")
             ->execute([$asig['id']]);

        $conn->prepare("DELETE FROM asignaciones_facturas WHERE id = ?")
             ->execute([$asig['id']]);
    }

    $conn->commit();
    echo json_encode(['success' => true, 'message' => 'Asignaci¨®n anterior liberada correctamente.']);

} catch (PDOException $e) {
    $conn->rollBack();
    error_log("Error en eliminar_asignacion_factura: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Error al liberar la asignaci¨®n.']);
}
?>