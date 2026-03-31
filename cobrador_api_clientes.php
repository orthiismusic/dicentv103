<?php
/* ============================================================
   cobrador_api_clientes.php
   API auxiliar para obtener clientes de un cobrador
   Usado por mensajecobrador.php para el selector de visitas
   ============================================================ */
require_once 'config.php';
verificarSesion();

header('Content-Type: application/json; charset=utf-8');

// Solo admin y supervisor
if (!in_array($_SESSION['rol'], ['admin','supervisor'])) {
    http_response_code(403);
    echo json_encode(['success'=>false,'message'=>'Sin permiso.']);
    exit;
}

$cobradorId = (int)($_GET['cobrador_id'] ?? 0);

if (!$cobradorId) {
    echo json_encode(['success'=>false,'clientes'=>[]]);
    exit;
}

try {
    $stmt = $conn->prepare("
        SELECT id, nombre, apellidos, direccion, telefono1
        FROM clientes
        WHERE cobrador_id = ? AND estado = 'activo'
        ORDER BY nombre ASC, apellidos ASC
    ");
    $stmt->execute([$cobradorId]);
    $clientes = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode([
        'success'  => true,
        'clientes' => $clientes,
    ], JSON_UNESCAPED_UNICODE);

} catch (PDOException $e) {
    error_log('cobrador_api_clientes: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success'=>false,'clientes'=>[],'message'=>$e->getMessage()]);
}