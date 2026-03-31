<?php
/* ============================================================
   ajax_ver_cliente.php
   Devuelve JSON con todos los datos del cliente para el modal
   ============================================================ */
require_once 'config.php';
verificarSesion();
header('Content-Type: application/json; charset=utf-8');

$id = intval($_GET['id'] ?? 0);
if (!$id) {
    echo json_encode(['error' => 'ID requerido']);
    exit;
}

/* ── Datos principales del cliente ── */
$stmt = $conn->prepare("
    SELECT c.*,
           cb.nombre_completo AS cobrador_nombre,
           vd.nombre_completo AS vendedor_nombre,
           (SELECT COUNT(DISTINCT ct.id)
            FROM contratos ct WHERE ct.cliente_id = c.id)                          AS total_contratos,
           (SELECT COUNT(DISTINCT d.id)
            FROM contratos ct
            JOIN dependientes d ON d.contrato_id = ct.id
            WHERE ct.cliente_id = c.id AND d.estado = 'activo')                    AS total_dependientes,
           COALESCE((
               SELECT SUM(f.monto)
               FROM contratos ct
               JOIN facturas f ON ct.id = f.contrato_id
               WHERE ct.cliente_id = c.id
                 AND f.estado IN ('pendiente','vencida','incompleta')
           ), 0)                                                                    AS total_pendiente,
           COALESCE((
               SELECT SUM(pg.monto)
               FROM contratos ct
               JOIN facturas f  ON ct.id = f.contrato_id
               JOIN pagos    pg ON f.id  = pg.factura_id
               WHERE ct.cliente_id = c.id
                 AND pg.estado     = 'procesado'
                 AND pg.tipo_pago  = 'abono'
           ), 0)                                                                    AS total_abonado
    FROM clientes c
    LEFT JOIN cobradores cb ON c.cobrador_id = cb.id
    LEFT JOIN vendedores  vd ON c.vendedor_id = vd.id
    WHERE c.id = ?
");
$stmt->execute([$id]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$row) {
    echo json_encode(['error' => 'Cliente no encontrado']);
    exit;
}

/* ── Contratos ── */
$stmt = $conn->prepare("
    SELECT ct.id, ct.numero_contrato, ct.fecha_inicio, ct.fecha_fin,
           ct.monto_mensual, ct.estado,
           p.nombre AS plan_nombre,
           (SELECT COUNT(*) FROM facturas f
            WHERE f.contrato_id = ct.id
              AND f.estado IN ('pendiente','vencida','incompleta')) AS facturas_pendientes
    FROM contratos ct
    JOIN planes p ON ct.plan_id = p.id
    WHERE ct.cliente_id = ?
    ORDER BY ct.fecha_inicio DESC
");
$stmt->execute([$id]);
$row['contratos'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

/* ── Dependientes (todos los contratos) ── */
$stmt = $conn->prepare("
    SELECT d.*, p.nombre AS plan_nombre, ct.numero_contrato
    FROM contratos ct
    JOIN dependientes d ON d.contrato_id = ct.id
    JOIN planes       p ON d.plan_id     = p.id
    WHERE ct.cliente_id = ?
      AND d.estado = 'activo'
    ORDER BY d.nombre, d.apellidos
");
$stmt->execute([$id]);
$row['dependientes'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

/* ── Últimas 12 facturas ── */
$stmt = $conn->prepare("
    SELECT f.numero_factura, f.fecha_emision, f.monto, f.estado,
           ct.numero_contrato
    FROM facturas f
    JOIN contratos ct ON f.contrato_id = ct.id
    WHERE ct.cliente_id = ?
    ORDER BY f.fecha_emision DESC
    LIMIT 12
");
$stmt->execute([$id]);
$row['facturas'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

/* ── Últimos 10 pagos ── */
$stmt = $conn->prepare("
    SELECT pg.fecha_pago, pg.monto, pg.tipo_pago, pg.estado,
           f.numero_factura,
           ct.numero_contrato
    FROM pagos pg
    JOIN facturas  f  ON pg.factura_id   = f.id
    JOIN contratos ct ON f.contrato_id   = ct.id
    WHERE ct.cliente_id = ?
      AND pg.estado     = 'procesado'
    ORDER BY pg.fecha_pago DESC
    LIMIT 10
");
$stmt->execute([$id]);
$row['pagos'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

echo json_encode($row, JSON_UNESCAPED_UNICODE);