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

$data      = json_decode(file_get_contents('php://input'), true);
$mensajeId = (int)($data['mensaje_id'] ?? 0);
$cobrId    = (int)$_SESSION['cobrador_portal_id'];

if (!$mensajeId) {
    echo json_encode(['success' => false, 'message' => 'ID requerido.']);
    exit;
}

try {
    $stmt = $conn->prepare("
        UPDATE cobrador_mensajes
        SET leido = 1, fecha_leido = NOW()
        WHERE id = ? AND cobrador_id = ? AND leido = 0
    ");
    $stmt->execute([$mensajeId, $cobrId]);
    echo json_encode(['success' => true, 'updated' => $stmt->rowCount()]);
} catch (PDOException $e) {
    error_log('marcar_leido: ' . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Error al actualizar.']);
}