<?php
ob_start();
if (!defined('DB_HOST')) require_once __DIR__ . '/../../config.php';
ob_clean();

require_once __DIR__ . '/../config_cobrador.php';
verificarSesionCobradorAjax();

header('Content-Type: application/json; charset=utf-8');

$id     = (int)($_GET['id'] ?? 0);
$cobrId = (int)$_SESSION['cobrador_portal_id'];

if (!$id) {
    echo json_encode(['success' => false, 'message' => 'ID requerido.']);
    exit;
}

try {
    $stmt = $conn->prepare("
        SELECT m.*,
               u.nombre AS remitente_nombre,
               u.rol    AS remitente_rol,
               cl.nombre      AS cliente_visita_nombre,
               cl.apellidos   AS cliente_visita_apellidos,
               cl.direccion   AS cliente_visita_dir,
               cl.telefono1   AS cliente_visita_tel
        FROM cobrador_mensajes m
        JOIN usuarios u ON m.usuario_id = u.id
        LEFT JOIN clientes cl ON cl.id = m.cliente_visita_id
        WHERE m.id = ? AND m.cobrador_id = ?
        LIMIT 1
    ");
    $stmt->execute([$id, $cobrId]);
    $m = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$m) {
        echo json_encode(['success' => false, 'message' => 'Mensaje no encontrado.']);
        exit;
    }

    $diff = time() - strtotime($m['fecha_envio']);
    $m['tiempo_relativo'] = $diff < 60
        ? 'Ahora mismo'
        : ($diff < 3600 ? 'hace ' . floor($diff / 60) . ' min'
        : ($diff < 86400 ? 'hace ' . floor($diff / 3600) . ' h'
        : date('d/m/Y', strtotime($m['fecha_envio']))));

    $m['fecha_envio_formateada']  = date('d/m/Y H:i', strtotime($m['fecha_envio']));
    $m['fecha_leido_formateada']  = $m['fecha_leido']
        ? date('d/m/Y H:i', strtotime($m['fecha_leido'])) : null;

    echo json_encode(['success' => true, 'mensaje' => $m], JSON_UNESCAPED_UNICODE);

} catch (PDOException $e) {
    error_log('get_mensaje: ' . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Error interno.']);
}