<?php
/* ============================================================
   ajax_ver_contrato.php
   Devuelve JSON con todos los datos del contrato para el modal
   ============================================================ */
require_once 'config.php';
verificarSesion();
header('Content-Type: application/json; charset=utf-8');

$id = intval($_GET['id'] ?? 0);
if (!$id) {
    echo json_encode(['error' => 'ID requerido']);
    exit;
}

/* ── Contrato + cliente + plan + vendedor ── */
$stmt = $conn->prepare("
    SELECT c.*,
           cl.codigo          AS cliente_codigo,
           cl.nombre          AS cliente_nombre,
           cl.apellidos       AS cliente_apellidos,
           cl.direccion       AS cliente_direccion,
           cl.telefono1       AS cliente_telefono1,
           cl.telefono2       AS cliente_telefono2,
           cl.email           AS cliente_email,
           p.nombre           AS plan_nombre,
           p.descripcion      AS plan_descripcion,
           p.cobertura_maxima,
           v.nombre_completo  AS vendedor_nombre,
           (SELECT COUNT(*) FROM dependientes d
            WHERE d.contrato_id = c.id AND d.estado = 'activo')   AS total_dependientes,
           (SELECT COUNT(*) FROM facturas f
            WHERE f.contrato_id = c.id AND f.estado = 'incompleta') AS facturas_incompletas,
           (SELECT COALESCE(SUM(pg.monto),0)
            FROM facturas f2
            JOIN pagos pg ON f2.id = pg.factura_id
            WHERE f2.contrato_id = c.id
              AND pg.tipo_pago = 'abono'
              AND pg.estado    = 'procesado')                      AS total_abonado,
           (SELECT COALESCE(SUM(f3.monto),0)
            FROM facturas f3
            WHERE f3.contrato_id = c.id
              AND f3.estado IN ('pendiente','incompleta','vencida')) AS total_pendiente
    FROM contratos c
    JOIN clientes cl ON c.cliente_id = cl.id
    JOIN planes   p  ON c.plan_id    = p.id
    LEFT JOIN vendedores v ON c.vendedor_id = v.id
    WHERE c.id = ?
");
$stmt->execute([$id]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$row) {
    echo json_encode(['error' => 'Contrato no encontrado']);
    exit;
}

/* nombre completo unificado para el modal */
$row['cliente_nombre'] = $row['cliente_nombre'] . ' ' . $row['cliente_apellidos'];

/* ── Beneficiarios ── */
$stmt = $conn->prepare("
    SELECT * FROM beneficiarios
    WHERE contrato_id = ?
    ORDER BY nombre, apellidos
");
$stmt->execute([$id]);
$row['beneficiarios'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

/* ── Dependientes ── */
$stmt = $conn->prepare("
    SELECT d.*, p.nombre AS plan_nombre
    FROM dependientes d
    JOIN planes p ON d.plan_id = p.id
    WHERE d.contrato_id = ?
    ORDER BY d.nombre, d.apellidos
");
$stmt->execute([$id]);
$row['dependientes'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

/* ── Últimos 10 pagos ── */
$stmt = $conn->prepare("
    SELECT pg.*, f.numero_factura
    FROM pagos pg
    JOIN facturas f ON pg.factura_id = f.id
    WHERE f.contrato_id = ?
    ORDER BY pg.fecha_pago DESC
    LIMIT 10
");
$stmt->execute([$id]);
$row['pagos'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

echo json_encode($row, JSON_UNESCAPED_UNICODE);