<?php
require_once 'config.php';
header('Content-Type: application/json; charset=utf-8');

$data = json_decode(file_get_contents('php://input'), true);

if (!isset($data['asignacion_id'])) {
    echo json_encode(['success' => false, 'message' => 'ID de asignación no proporcionado.']);
    exit;
}

try {
    $conn->beginTransaction();

    /* Eliminar historial relacionado primero */
    $conn->prepare("DELETE FROM historial_reasignaciones WHERE asignacion_id = ?")
         ->execute([$data['asignacion_id']]);

    /* Eliminar asignación */
    $stmt = $conn->prepare("DELETE FROM asignaciones_facturas WHERE id = ?");
    $stmt->execute([$data['asignacion_id']]);

    if ($stmt->rowCount() === 0) {
        $conn->rollBack();
        echo json_encode(['success' => false, 'message' => 'La asignación no fue encontrada.']);
        exit;
    }

    $conn->commit();
    echo json_encode(['success' => true, 'message' => 'Asignación eliminada exitosamente.']);

} catch (PDOException $e) {
    $conn->rollBack();
    error_log("Error en eliminar_asignacion: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Error al eliminar la asignación.']);
}
?>