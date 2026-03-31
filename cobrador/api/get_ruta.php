<?php
/* ============================================================
   cobrador/api/get_ruta.php
   FIX: tabla cobrador_rutas puede no existir aún
   ============================================================ */
ob_start();
if (!defined('DB_HOST')) require_once __DIR__ . '/../../config.php';
ob_clean();

require_once __DIR__ . '/../config_cobrador.php';
verificarSesionCobradorAjax();

header('Content-Type: application/json; charset=utf-8');

$cobradorId = (int)$_SESSION['cobrador_portal_id'];
$fecha      = date('Y-m-d');

try {
    /* ── Clientes con facturas pendientes ── */
    $stmt = $conn->prepare("
        SELECT DISTINCT
            cl.id, cl.nombre, cl.apellidos,
            cl.direccion, cl.telefono1
        FROM clientes cl
        JOIN contratos c   ON c.cliente_id = cl.id AND c.estado = 'activo'
        JOIN facturas  f   ON f.contrato_id = c.id
                          AND f.estado IN ('pendiente','vencida','incompleta')
        WHERE cl.cobrador_id = ?
        ORDER BY cl.nombre ASC, cl.apellidos ASC
    ");
    $stmt->execute([$cobradorId]);
    $clientes = $stmt->fetchAll(PDO::FETCH_ASSOC);

    if (empty($clientes)) {
        echo json_encode(['success' => true, 'clientes' => [], 'fecha' => $fecha]);
        exit;
    }

    /* ── Monto pendiente por cliente ── */
    $stmtM = $conn->prepare("
        SELECT COALESCE(SUM(f.monto), 0) AS monto_pendiente,
               COUNT(f.id)               AS total_facturas
        FROM facturas f
        JOIN contratos c ON f.contrato_id = c.id AND c.cliente_id = ?
        WHERE f.estado IN ('pendiente','vencida','incompleta')
    ");

    /* ── Orden de ruta guardado (si la tabla existe) ── */
    $ordenRuta = [];
    try {
        $stmtO = $conn->prepare("
            SELECT cliente_id, orden FROM cobrador_rutas
            WHERE cobrador_id = ? AND fecha = ?
        ");
        $stmtO->execute([$cobradorId, $fecha]);
        foreach ($stmtO->fetchAll(PDO::FETCH_ASSOC) as $r) {
            $ordenRuta[$r['cliente_id']] = (int)$r['orden'];
        }
    } catch (PDOException $e) {
        /* tabla no existe aún — ignorar */
    }

    foreach ($clientes as &$cl) {
        $stmtM->execute([$cl['id']]);
        $row = $stmtM->fetch(PDO::FETCH_ASSOC);
        $cl['monto_pendiente']   = number_format((float)($row['monto_pendiente'] ?? 0), 2, '.', '');
        $cl['total_facturas']    = (int)($row['total_facturas'] ?? 0);
        $cl['orden_ruta']        = $ordenRuta[$cl['id']] ?? 999;
        $cl['lat']               = null;
        $cl['lng']               = null;
    }
    unset($cl);

    usort($clientes, function($a, $b) {
        if ($a['orden_ruta'] !== $b['orden_ruta'])
            return $a['orden_ruta'] <=> $b['orden_ruta'];
        return strcmp($a['nombre'], $b['nombre']);
    });

    echo json_encode([
        'success'  => true,
        'clientes' => $clientes,
        'total'    => count($clientes),
        'fecha'    => $fecha,
    ], JSON_UNESCAPED_UNICODE);

} catch (PDOException $e) {
    error_log('get_ruta: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'success'  => false,
        'message'  => 'Error: ' . $e->getMessage(),
        'clientes' => [],
    ]);
}