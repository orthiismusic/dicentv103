<?php
/* ============================================================
   verificar_facturas.php
   Verifica si un contrato tiene facturas anteriores con saldo
   pendiente antes de permitir el pago de una factura posterior.
   Retorna JSON con detalle completo de cada factura pendiente.
   ============================================================ */
require_once 'config.php';
header('Content-Type: application/json; charset=utf-8');

$contrato_id = intval($_GET['contrato_id'] ?? 0);
$factura_id  = intval($_GET['factura_id']  ?? 0);

if (!$contrato_id || !$factura_id) {
    echo json_encode([
        'tiene_pendientes'  => false,
        'tiene_incompletas' => false,
        'facturas'          => []
    ]);
    exit;
}

try {
    $stmt = $conn->prepare("
        SELECT
            f.id,
            f.numero_factura,
            f.mes_factura,
            f.monto,
            f.estado,
            COALESCE(
                (SELECT SUM(p.monto)
                 FROM pagos p
                 WHERE p.factura_id = f.id
                   AND p.estado = 'procesado'),
                0
            ) AS total_pagado
        FROM facturas f
        WHERE f.contrato_id = ?
          AND f.id          < ?
          AND f.estado      NOT IN ('pagada', 'anulada')
        ORDER BY f.id ASC
    ");
    $stmt->execute([$contrato_id, $factura_id]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $facturas_pendientes = [];
    foreach ($rows as $row) {
        $pendiente = round((float)$row['monto'] - (float)$row['total_pagado'], 2);
        if ($pendiente > 0.00) {
            $facturas_pendientes[] = [
                'id'              => (int)$row['id'],
                'numero_factura'  => $row['numero_factura'],
                'mes_factura'     => $row['mes_factura'],
                'monto'           => number_format((float)$row['monto'],        2, '.', ''),
                'total_pagado'    => number_format((float)$row['total_pagado'],  2, '.', ''),
                'monto_pendiente' => number_format($pendiente,                   2, '.', ''),
                'estado'          => $row['estado'],
            ];
        }
    }

    $tiene = count($facturas_pendientes) > 0;
    echo json_encode([
        'tiene_pendientes'  => $tiene,
        'tiene_incompletas' => $tiene,
        'facturas'          => $facturas_pendientes,
    ]);
} catch (PDOException $e) {
    error_log("Error en verificar_facturas.php: " . $e->getMessage());
    echo json_encode([
        'tiene_pendientes'  => false,
        'tiene_incompletas' => false,
        'facturas'          => []
    ]);
}
