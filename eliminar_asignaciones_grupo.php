<?php
require_once 'config.php';
header('Content-Type: application/json; charset=utf-8');

$data = json_decode(file_get_contents('php://input'), true);

if (!isset($data['asignaciones_ids']) || empty($data['asignaciones_ids'])) {
    echo json_encode(['success' => false, 'message' => 'No se proporcionaron IDs.']);
    exit;
}

try {
    $conn->beginTransaction();
    $contador = 0;

    foreach ($data['asignaciones_ids'] as $id) {
        $id = (int)trim($id);
        if ($id <= 0) continue;

        $conn->prepare("DELETE FROM historial_reasignaciones WHERE asignacion_id = ?")
             ->execute([$id]);

        $stmt = $conn->prepare("DELETE FROM asignaciones_facturas WHERE id = ?");
        $stmt->execute([$id]);
        $contador += $stmt->rowCount();
    }

    if ($contador === 0) {
        throw new Exception('No se procesó ningún ID válido.');
    }

    $conn->commit();
    echo json_encode([
        'success'             => true,
        'message'             => 'Asignaciones eliminadas exitosamente.',
        'registros_eliminados'=> $contador
    ]);

} catch (Exception $e) {
    $conn->rollBack();
    error_log("Error en eliminar_asignaciones_grupo: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Error al eliminar: ' . $e->getMessage()]);
}
?>