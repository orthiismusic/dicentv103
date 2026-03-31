<?php
/* ============================================================
   ajax_facturas_vigencia.php
   Retorna JSON con facturas pendientes de un contrato
   para el modal de vigencia.php
   ============================================================ */
require_once 'config.php';
verificarSesion();
header('Content-Type: application/json; charset=utf-8');

$contrato_id = intval($_GET['contrato_id'] ?? 0);
if (!$contrato_id) {
    echo json_encode(['facturas' => [], 'error' => 'ID de contrato requerido']);
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
            f.fecha_vencimiento,
            COALESCE(
                (SELECT SUM(p.monto)
                 FROM pagos p
                 WHERE p.factura_id = f.id
                   AND p.estado = 'procesado'),
                0
            ) AS total_abonado,
            (f.monto - COALESCE(
                (SELECT SUM(p.monto)
                 FROM pagos p
                 WHERE p.factura_id = f.id
                   AND p.estado = 'procesado'),
                0
            )) AS monto_pendiente
        FROM facturas f
        WHERE f.contrato_id = ?
          AND f.estado IN ('pendiente', 'incompleta', 'vencida')
        HAVING monto_pendiente > 0
        ORDER BY f.id ASC
    ");
    $stmt->execute([$contrato_id]);
    $facturas = $stmt->fetchAll(PDO::FETCH_ASSOC);

    /* Convertir a float para el JSON */
    foreach ($facturas as &$f) {
        $f['monto']          = (float)$f['monto'];
        $f['total_abonado']  = (float)$f['total_abonado'];
        $f['monto_pendiente']= (float)$f['monto_pendiente'];
    }

    echo json_encode(['facturas' => $facturas]);

} catch (PDOException $e) {
    error_log("Error en ajax_facturas_vigencia.php: " . $e->getMessage());
    echo json_encode(['facturas' => [], 'error' => 'Error al cargar facturas']);
}