<?php
/* ============================================================
   cobrador/api/get_facturas.php
   FIX: manejo seguro cuando cobrador_facturas_autorizadas
   no existe + LIMIT/OFFSET como int directo
   ============================================================ */
ob_start();
if (!defined('DB_HOST')) require_once __DIR__ . '/../../config.php';
ob_clean();

require_once __DIR__ . '/../config_cobrador.php';
verificarSesionCobradorAjax();

header('Content-Type: application/json; charset=utf-8');

$cobradorId = (int)$_SESSION['cobrador_portal_id'];
$q          = trim($_GET['q']           ?? '');
$estado     = trim($_GET['estado']      ?? '');
$offset     = max(0, (int)($_GET['offset']    ?? 0));
$clienteId  = (int)($_GET['cliente_id'] ?? 0);
$porPagina  = 25;

$estadosValidos = ['pendiente', 'vencida', 'incompleta'];

try {
    /* ©¤©¤ Condiciones ©¤©¤ */
    $cond   = "cl.cobrador_id = ?";
    $params = [$cobradorId];

    if (in_array($estado, $estadosValidos, true)) {
        $cond    .= " AND f.estado = ?";
        $params[] = $estado;
    } else {
        $cond .= " AND f.estado IN ('pendiente','vencida','incompleta')";
    }

    if ($clienteId > 0) {
        $cond    .= " AND cl.id = ?";
        $params[] = $clienteId;
    }

    if ($q !== '') {
        $like     = "%$q%";
        $cond    .= " AND (
            cl.nombre LIKE ? OR cl.apellidos LIKE ?
            OR CONCAT(cl.nombre,' ',cl.apellidos) LIKE ?
            OR c.numero_contrato LIKE ? OR f.numero_factura LIKE ?
        )";
        $params[] = $like; $params[] = $like; $params[] = $like;
        $params[] = $like; $params[] = $like;
    }

    $sqlBase = "
        FROM facturas f
        JOIN contratos c  ON f.contrato_id = c.id
        JOIN clientes  cl ON c.cliente_id  = cl.id
        JOIN planes    p  ON c.plan_id     = p.id
        WHERE $cond
    ";

    /* ©¤©¤ Total ©¤©¤ */
    $stmtT = $conn->prepare("SELECT COUNT(*) $sqlBase");
    $stmtT->execute($params);
    $total = (int)$stmtT->fetchColumn();

    /* ©¤©¤ Listado con LIMIT/OFFSET directo como int ©¤©¤ */
    $lim = (int)$porPagina;
    $off = (int)$offset;

    $stmtL = $conn->prepare("
        SELECT f.id, f.numero_factura, f.mes_factura, f.cuota,
               f.monto, f.fecha_vencimiento, f.estado, f.notas,
               c.numero_contrato, c.dia_cobro,
               cl.id AS cliente_id, cl.nombre, cl.apellidos,
               cl.direccion, cl.telefono1, cl.telefono2,
               p.nombre AS plan_nombre
        $sqlBase
        ORDER BY
            FIELD(f.estado,'vencida','incompleta','pendiente'),
            f.fecha_vencimiento ASC
        LIMIT $lim OFFSET $off
    ");
    $stmtL->execute($params);
    $facturas = $stmtL->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode([
        'success'  => true,
        'facturas' => $facturas,
        'total'    => $total,
        'offset'   => $offset,
    ], JSON_UNESCAPED_UNICODE);

} catch (PDOException $e) {
    error_log('get_facturas cobrador: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'success'  => false,
        'message'  => 'Error: ' . $e->getMessage(),
        'facturas' => [], 'total' => 0,
    ]);
}