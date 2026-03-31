<?php
ob_start();
if (!defined('DB_HOST')) require_once __DIR__ . '/../../config.php';
ob_clean();

require_once __DIR__ . '/../config_cobrador.php';
verificarSesionCobradorAjax();

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Método no permitido.']);
    exit;
}

$data       = json_decode(file_get_contents('php://input'), true);
$cobradorId = (int)$_SESSION['cobrador_portal_id'];
$fecha      = date('Y-m-d');
$orden      = $data['orden'] ?? [];

if (!is_array($orden) || empty($orden)) {
    echo json_encode(['success' => false, 'message' => 'Sin datos de orden.']);
    exit;
}

try {
    $conn->beginTransaction();

    $conn->prepare("DELETE FROM cobrador_rutas WHERE cobrador_id = ? AND fecha = ?")
         ->execute([$cobradorId, $fecha]);

    $stmt = $conn->prepare("
        INSERT INTO cobrador_rutas (cobrador_id, cliente_id, orden, fecha)
        VALUES (?, ?, ?, ?)
    ");

    foreach ($orden as $item) {
        $stmt->execute([
            $cobradorId,
            (int)$item['cliente_id'],
            (int)$item['orden'],
            $fecha,
        ]);
    }

    $conn->commit();
    echo json_encode(['success' => true, 'message' => 'Ruta guardada correctamente.']);

} catch (PDOException $e) {
    if ($conn->inTransaction()) $conn->rollBack();
    error_log('guardar_ruta: ' . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Error al guardar ruta.']);
}