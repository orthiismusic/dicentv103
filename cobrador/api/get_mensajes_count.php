<?php
ob_start();
if (!defined('DB_HOST')) require_once __DIR__ . '/../../config.php';
ob_clean();

require_once __DIR__ . '/../config_cobrador.php';
verificarSesionCobradorAjax();

header('Content-Type: application/json; charset=utf-8');

try {
    $stmt = $conn->prepare("
        SELECT COUNT(*) FROM cobrador_mensajes
        WHERE cobrador_id = ? AND leido = 0
    ");
    $stmt->execute([(int)$_SESSION['cobrador_portal_id']]);
    echo json_encode(['success' => true, 'count' => (int)$stmt->fetchColumn()]);
} catch (PDOException $e) {
    echo json_encode(['success' => true, 'count' => 0]);
}