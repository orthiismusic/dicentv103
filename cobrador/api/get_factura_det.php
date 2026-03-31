<?php
/* ============================================================
   cobrador/api/get_factura_det.php — VERSIÓN CORREGIDA
   ============================================================ */

ob_start();
if (!defined('DB_HOST')) {
    require_once __DIR__ . '/../../config.php';
}
ob_clean();

require_once __DIR__ . '/../config_cobrador.php';
verificarSesionCobradorAjax();

header('Content-Type: application/json; charset=utf-8');

$facturaId  = (int)($_GET['id'] ?? 0);
$cobradorId = (int)$_SESSION['cobrador_portal_id'];

if (!$facturaId) {
    echo json_encode(['success' => false, 'message' => 'ID de factura requerido.']);
    exit;
}

if (!verificarAccesoFactura($facturaId, $cobradorId)) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'No tienes permiso para ver esta factura.']);
    exit;
}

try {
    $stmt = $conn->prepare("
        SELECT
            f.id, f.numero_factura, f.mes_factura, f.cuota,
            f.monto, f.fecha_emision, f.fecha_vencimiento,
            f.estado, f.notas,
            c.numero_contrato, c.dia_cobro, c.monto_mensual,
            cl.nombre, cl.apellidos,
            cl.telefono1, cl.telefono2, cl.telefono3,
            cl.direccion,
            p.nombre AS plan_nombre,
            COALESCE(
                (SELECT SUM(pg.monto) FROM pagos pg
                 WHERE pg.factura_id = f.id AND pg.estado = 'procesado'),
                0
            ) AS total_abonado
        FROM facturas f
        JOIN contratos c ON f.contrato_id = c.id
        JOIN clientes cl ON c.cliente_id  = cl.id
        JOIN planes   p  ON c.plan_id     = p.id
        WHERE f.id = ?
        LIMIT 1
    ");
    $stmt->execute([$facturaId]);
    $factura = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$factura) {
        echo json_encode(['success' => false, 'message' => 'Factura no encontrada.']);
        exit;
    }

    $factura['monto_pendiente'] = max(
        0,
        (float)$factura['monto'] - (float)$factura['total_abonado']
    );

    // Abonos registrados
    $stmtPagos = $conn->prepare("
        SELECT p.monto, p.fecha_pago, p.metodo_pago, p.tipo_pago
        FROM pagos p
        WHERE p.factura_id = ? AND p.estado = 'procesado'
        ORDER BY p.fecha_pago ASC
    ");
    $stmtPagos->execute([$facturaId]);
    $pagos = $stmtPagos->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode([
        'success' => true,
        'factura' => $factura,
        'pagos'   => $pagos,
    ]);

} catch (PDOException $e) {
    error_log('get_factura_det cobrador: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'Error al cargar la factura.',
    ]);
}