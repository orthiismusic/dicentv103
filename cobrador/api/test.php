<?php
ob_start();
if (!defined('DB_HOST')) require_once __DIR__ . '/../../config.php';
$warnings = ob_get_clean();

header('Content-Type: application/json; charset=utf-8');

$cobradorId = (int)($_SESSION['cobrador_portal_id'] ?? 0);

$resultado = [
    'sesion_activa'  => $cobradorId > 0,
    'cobrador_id'    => $cobradorId,
    'warnings_config'=> !empty($warnings),
    'warnings_texto' => strip_tags($warnings),
    'tests'          => []
];

if ($cobradorId > 0) {
    // Test 1: clientes
    try {
        $s = $conn->prepare("SELECT COUNT(*) FROM clientes WHERE cobrador_id = ?");
        $s->execute([$cobradorId]);
        $resultado['tests']['clientes_total'] = (int)$s->fetchColumn();
    } catch (PDOException $e) {
        $resultado['tests']['clientes_error'] = $e->getMessage();
    }

    // Test 2: facturas asignadas
    try {
        $s = $conn->prepare("
            SELECT COUNT(*) FROM asignaciones_facturas af
            JOIN facturas f ON af.factura_id = f.id
            WHERE af.cobrador_id = ? AND af.estado = 'activa'
              AND f.estado IN ('pendiente','vencida','incompleta')
        ");
        $s->execute([$cobradorId]);
        $resultado['tests']['facturas_asignadas'] = (int)$s->fetchColumn();
    } catch (PDOException $e) {
        $resultado['tests']['facturas_error'] = $e->getMessage();
    }
}

echo json_encode($resultado, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);