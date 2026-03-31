<?php
/* ============================================================
   facturacion.php — Gestión de Facturación
   Sistema ORTHIIS — Seguros de Vida
   ============================================================ */
require_once 'config.php';
verificarSesion();

/* ── Helpers ──────────────────────────────────────────────── */
function verificarBloqueoFacturas($conn) {
    $stmt = $conn->prepare("
        SELECT gfl.*, u.nombre AS usuario_nombre
        FROM generacion_facturas_lock gfl
        JOIN usuarios u ON gfl.usuario_id = u.id
        WHERE gfl.estado = 'activo'
        ORDER BY gfl.timestamp DESC
        LIMIT 1
    ");
    $stmt->execute();
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

function actualizarFechaFinContrato($conn, $contrato_id) {
    try {
        $stmt = $conn->prepare("
            SELECT fecha_vencimiento
            FROM facturas
            WHERE contrato_id = ?
              AND estado = 'pagada'
            ORDER BY fecha_vencimiento DESC
            LIMIT 1
        ");
        $stmt->execute([$contrato_id]);
        $resultado = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($resultado) {
            $conn->prepare("
                UPDATE contratos SET fecha_fin=?, updated_at=CURRENT_TIMESTAMP WHERE id=?
            ")->execute([$resultado['fecha_vencimiento'], $contrato_id]);
            return true;
        }
        return false;
    } catch (PDOException $e) {
        error_log("Error en actualizarFechaFinContrato: " . $e->getMessage());
        return false;
    }
}

function formatearFecha($fecha) {
    $fecha_obj = DateTime::createFromFormat('Y-m-d', $fecha);
    $meses = [
        '01'=>'Ene','02'=>'Feb','03'=>'Mar','04'=>'Abr',
        '05'=>'May','06'=>'Jun','07'=>'Jul','08'=>'Ago',
        '09'=>'Sep','10'=>'Oct','11'=>'Nov','12'=>'Dic'
    ];
    return $fecha_obj->format('d') . '/' .
           $meses[$fecha_obj->format('m')] . '/' .
           $fecha_obj->format('Y');
}

$mensaje      = '';
$tipo_mensaje = '';

/* ============================================================
   PROCESAR POST — Generar Facturas
   ============================================================ */
if ($_SERVER['REQUEST_METHOD'] === 'POST' &&
    isset($_POST['action']) && $_POST['action'] === 'generar_facturas') {
    try {
        $bloqueo = verificarBloqueoFacturas($conn);
        if ($bloqueo && $bloqueo['usuario_id'] != $_SESSION['usuario_id']) {
            throw new Exception("El usuario {$bloqueo['usuario_nombre']} está generando facturas actualmente.");
        }

        $conn->beginTransaction();

        $conn->prepare("
            INSERT INTO generacion_facturas_lock (usuario_id, timestamp, estado)
            VALUES (?, NOW(), 'activo')
        ")->execute([$_SESSION['usuario_id']]);

        $stmt = $conn->prepare("
            SELECT c.*
            FROM contratos c
            WHERE c.estado = 'activo'
              AND (
                  NOT EXISTS (SELECT 1 FROM facturas f WHERE f.contrato_id = c.id)
                  OR (
                      NOT EXISTS (
                          SELECT 1 FROM facturas f
                          WHERE f.contrato_id = c.id
                            AND f.estado IN ('pendiente','incompleta','vencida')
                      )
                      AND EXISTS (
                          SELECT 1 FROM facturas f
                          WHERE f.contrato_id = c.id AND f.estado = 'pagada'
                      )
                  )
              )
        ");
        $stmt->execute();
        $contratos       = $stmt->fetchAll();
        $facturasGeneradas = 0;

        foreach ($contratos as $contrato) {
            $stmtUlt = $conn->prepare("
                SELECT cuota, fecha_emision, mes_factura
                FROM facturas WHERE contrato_id=?
                ORDER BY cuota DESC LIMIT 1
            ");
            $stmtUlt->execute([$contrato['id']]);
            $ultima = $stmtUlt->fetch(PDO::FETCH_ASSOC);

            if ($ultima) {
                $nuevaCuota    = $ultima['cuota'] + 1;
                $fechaEmision  = date('Y-m-d', strtotime($ultima['fecha_emision'] . ' +1 month'));
                list($m, $y)   = explode('/', $ultima['mes_factura']);
                $nextDate      = new DateTime("$y-$m-01");
                $nextDate->modify('+1 month');
                $nuevoMes      = $nextDate->format('m') . '/' . $nextDate->format('Y');
            } else {
                $nuevaCuota   = 1;
                $fechaEmision = date('Y-m-d');
                $nuevoMes     = date('m/Y');
            }

            $diaVenc = $contrato['dia_cobro'];
            list($ye, $me, $de) = explode('-', $fechaEmision);
            $maxDia  = cal_days_in_month(CAL_GREGORIAN, (int)$me, (int)$ye);
            $diaReal = min($diaVenc, $maxDia);
            $fechaVencimiento = "$ye-$me-" . str_pad($diaReal, 2, '0', STR_PAD_LEFT);

            $stmtMax = $conn->prepare(
                "SELECT MAX(CAST(numero_factura AS UNSIGNED)) AS ult FROM facturas"
            );
            $stmtMax->execute();
            $maxNum         = $stmtMax->fetch()['ult'] ?? 0;
            $numeroFactura  = str_pad($maxNum + 1, 7, '0', STR_PAD_LEFT);

            $conn->prepare("
                INSERT INTO facturas
                    (numero_factura, contrato_id, cuota, fecha_emision, fecha_vencimiento,
                     mes_factura, monto, estado, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'pendiente', NOW())
            ")->execute([
                $numeroFactura,
                $contrato['id'],
                $nuevaCuota,
                $fechaEmision,
                $fechaVencimiento,
                $nuevoMes,
                $contrato['monto_total'],
            ]);

            $facturasGeneradas++;
        }

        $conn->prepare("
            UPDATE generacion_facturas_lock SET estado='inactivo'
            WHERE usuario_id=? AND estado='activo'
        ")->execute([$_SESSION['usuario_id']]);

        $conn->commit();
        $mensaje      = "Se generaron <strong>$facturasGeneradas</strong> facturas exitosamente.";
        $tipo_mensaje = 'success';

    } catch (PDOException $e) {
        if ($conn->inTransaction()) $conn->rollBack();
        $conn->prepare("
            UPDATE generacion_facturas_lock SET estado='inactivo'
            WHERE usuario_id=? AND estado='activo'
        ")->execute([$_SESSION['usuario_id']]);
        $mensaje      = "Error al generar facturas: " . $e->getMessage();
        $tipo_mensaje = 'danger';
    } catch (Exception $e) {
        if ($conn->inTransaction()) $conn->rollBack();
        $mensaje      = "Error: " . $e->getMessage();
        $tipo_mensaje = 'danger';
    }
}

/* ── Auto-actualizar facturas vencidas al cargar la página ── */
try {
    $conn->exec("
        UPDATE facturas
        SET estado = 'vencida', updated_at = CURRENT_TIMESTAMP
        WHERE estado = 'pendiente'
          AND fecha_vencimiento < CURDATE()
    ");
} catch (PDOException $e) {
    error_log('Auto-vencidas error: ' . $e->getMessage());
}

/* ── Filtros ──────────────────────────────────────────────── */
$where  = "1=1";
$params = [];

if (!empty($_GET['estado'])) {
    $where   .= " AND f.estado = ?";
    $params[] = $_GET['estado'];
}
/* Búsqueda unificada: número de factura exacto, número de contrato exacto o LIKE en ambos */
if (!empty($_GET['buscar'])) {
    $buscar_val = trim($_GET['buscar']);
    $t = '%' . $buscar_val . '%';
    $where .= " AND (f.numero_factura LIKE ? OR c.numero_contrato LIKE ?)";
    array_push($params, $t, $t);
}
/* Filtro exclusivo por factura desde filtros avanzados (si se usa por separado) */
if (!empty($_GET['numero_factura']) && empty($_GET['buscar'])) {
    $where .= " AND f.numero_factura = ?";
    $params[] = $_GET['numero_factura'];
}
/* Filtro exclusivo por contrato desde filtros avanzados (si se usa por separado) */
if (!empty($_GET['numero_contrato']) && empty($_GET['buscar'])) {
    $where .= " AND c.numero_contrato = ?";
    $params[] = $_GET['numero_contrato'];
}
if (!empty($_GET['mes_desde'])) {
    $mes_desde_dt = date('Y-m-01', strtotime($_GET['mes_desde']));
    $where    .= " AND STR_TO_DATE(CONCAT('01/', f.mes_factura), '%d/%m/%Y') >= ?";
    $params[]  = $mes_desde_dt;
}
if (!empty($_GET['mes_hasta'])) {
    $mes_hasta_dt = date('Y-m-01', strtotime($_GET['mes_hasta']));
    $where    .= " AND STR_TO_DATE(CONCAT('01/', f.mes_factura), '%d/%m/%Y') <= ?";
    $params[]  = $mes_hasta_dt;
}

/* ── Paginación ───────────────────────────────────────────── */
$por_pagina   = isset($_COOKIE['facturas_por_pagina']) ? (int)$_COOKIE['facturas_por_pagina'] : 50;
$pagina_actual = max(1, intval($_GET['pagina'] ?? 1));
$offset        = ($pagina_actual - 1) * $por_pagina;

/* total */
$stmtCnt = $conn->prepare("
    SELECT COUNT(*) AS total
    FROM facturas f
    JOIN contratos c  ON f.contrato_id = c.id
    JOIN clientes  cl ON c.cliente_id  = cl.id
    JOIN planes    p  ON c.plan_id     = p.id
    WHERE $where
");
$stmtCnt->execute($params);
$total_registros = (int)$stmtCnt->fetchColumn();
$total_paginas   = max(1, ceil($total_registros / $por_pagina));

/* listado */
$sql = "
    SELECT f.*,
           c.numero_contrato,
           cl.codigo   AS cliente_codigo,
           cl.nombre   AS cliente_nombre,
           cl.apellidos AS cliente_apellidos,
           p.nombre    AS plan_nombre,
           (SELECT COALESCE(SUM(pg.monto),0) FROM pagos pg
            WHERE pg.factura_id = f.id
              AND pg.estado     = 'procesado') AS total_abonado,
           (SELECT COUNT(*) FROM asignaciones_facturas af
            WHERE af.factura_id = f.id
              AND af.estado     = 'activa')  AS esta_asignada
    FROM facturas f
    JOIN contratos c  ON f.contrato_id = c.id
    JOIN clientes  cl ON c.cliente_id  = cl.id
    JOIN planes    p  ON c.plan_id     = p.id
    WHERE $where
    ORDER BY CAST(f.numero_factura AS UNSIGNED) DESC
    LIMIT ? OFFSET ?
";
$stmtList = $conn->prepare($sql);
$allP = array_merge($params, [$por_pagina, $offset]);
foreach ($allP as $i => $v) {
    $stmtList->bindValue($i + 1, $v, is_int($v) ? PDO::PARAM_INT : PDO::PARAM_STR);
}
$stmtList->execute();
$facturas = $stmtList->fetchAll();

/* totales KPI */
$stmtTot = $conn->prepare("
    SELECT
        COUNT(*) AS total_facturas,
        SUM(CASE WHEN f.estado='pendiente'  THEN 1 ELSE 0 END) AS facturas_pendientes,
        SUM(CASE WHEN f.estado='incompleta' THEN 1 ELSE 0 END) AS facturas_incompletas,
        SUM(CASE WHEN f.estado='vencida'    THEN 1 ELSE 0 END) AS facturas_vencidas,
        COUNT(DISTINCT f.contrato_id) AS total_clientes
    FROM facturas f
    JOIN contratos c  ON f.contrato_id = c.id
    JOIN clientes  cl ON c.cliente_id  = cl.id
    JOIN planes    p  ON c.plan_id     = p.id
    WHERE $where
");
$stmtTot->execute($params);
$totales = $stmtTot->fetch();

/* URL helper paginador */
$params_url_arr = [];
foreach (['estado','numero_contrato','numero_factura','mes_desde','mes_hasta'] as $k) {
    if (!empty($_GET[$k])) $params_url_arr[$k] = $_GET[$k];
}
$params_url = http_build_query($params_url_arr);

function buildFacturaUrl(int $p, string $qs): string {
    return 'facturacion.php?pagina=' . $p . ($qs ? '&' . $qs : '');
}

require_once 'header.php';
?>
<!-- ============================================================
     ESTILOS ESPECÍFICOS DE FACTURACIÓN
     ============================================================ -->
<style>
/* ── KPI CARDS ── */
.kpi-facturas {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 18px;
    margin-bottom: 24px;
}
@media(max-width:1100px){ .kpi-facturas { grid-template-columns: repeat(2,1fr); } }
@media(max-width:600px)  { .kpi-facturas { grid-template-columns: 1fr; } }

.kpi-facturas .kpi-card {
    border-radius: var(--radius);
    padding: 22px 22px 18px;
    position: relative;
    overflow: hidden;
    box-shadow: var(--shadow);
    transition: var(--transition);
    color: white;
    cursor: default;
}
.kpi-facturas .kpi-card:hover { transform: translateY(-3px); box-shadow: var(--shadow-md); }
.kpi-facturas .kpi-card::before {
    content:''; position:absolute; top:0; right:0;
    width:80px; height:80px;
    border-radius:0 var(--radius) 0 100%;
    opacity:.15; background:white;
}
.kpi-facturas .kpi-card.blue   { background: linear-gradient(135deg,#1565C0,#1976D2); }
.kpi-facturas .kpi-card.green  { background: linear-gradient(135deg,#1B5E20,#2E7D32); }
.kpi-facturas .kpi-card.amber  { background: linear-gradient(135deg,#E65100,#F57F17); }
.kpi-facturas .kpi-card.red    { background: linear-gradient(135deg,#B71C1C,#C62828); }

.kpi-facturas .kpi-label {
    font-size:11px; font-weight:600; color:rgba(255,255,255,.80);
    text-transform:uppercase; letter-spacing:.8px; margin-bottom:10px;
}
.kpi-facturas .kpi-top {
    display:flex; align-items:flex-start; justify-content:space-between; margin-bottom:6px;
}
.kpi-facturas .kpi-value {
    font-size:30px; font-weight:800; color:white; line-height:1; margin-bottom:4px;
}
.kpi-facturas .kpi-sub  { font-size:11px; color:rgba(255,255,255,.70); font-weight:500; }
.kpi-facturas .kpi-icon {
    width:48px; height:48px;
    background:rgba(255,255,255,.18); border-radius:var(--radius-sm);
    display:flex; align-items:center; justify-content:center;
    font-size:20px; color:white; flex-shrink:0;
}
.kpi-facturas .kpi-footer {
    margin-top:14px; padding-top:12px;
    border-top:1px solid rgba(255,255,255,.15);
    font-size:11.5px; color:rgba(255,255,255,.80); font-weight:600;
    display:flex; align-items:center; gap:6px;
}

/* ── Botones de acción superiores ── */
.action-bar {
    background: var(--white);
    border: 1px solid var(--gray-200);
    border-radius: var(--radius);
    padding: 14px 18px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 10px;
    margin-bottom: 16px;
    box-shadow: var(--shadow-sm);
}
.action-bar-left, .action-bar-right {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
}

/* ── Barra de filtros ── */
.filter-bar {
    background: var(--white);
    border: 1px solid var(--gray-200);
    border-radius: var(--radius);
    padding: 14px 18px;
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 20px;
    box-shadow: var(--shadow-sm);
}
.filter-bar .search-wrap {
    position: relative;
    flex: 1;
    min-width: 200px;
}
.filter-bar .search-wrap input {
    width: 100%;
    padding: 9px 12px 9px 36px;
    border: 1px solid var(--gray-200);
    border-radius: var(--radius-sm);
    font-size: 13.5px;
    font-family: var(--font);
    color: var(--gray-800);
    background: var(--gray-50);
    transition: var(--transition);
}
.filter-bar .search-wrap input:focus {
    outline: none;
    border-color: var(--accent);
    background: white;
    box-shadow: 0 0 0 3px rgba(33,150,243,.10);
}
.filter-bar .search-wrap .si {
    position: absolute;
    left: 11px; top: 50%;
    transform: translateY(-50%);
    color: var(--gray-400);
    font-size: 13px;
    pointer-events: none;
}
.filter-bar .filter-select {
    padding: 9px 10px;
    min-width: 155px;
    border: 1px solid var(--gray-200);
    border-radius: var(--radius-sm);
    font-size: 13px;
    font-family: var(--font);
    color: var(--gray-700);
    background: var(--gray-50);
    cursor: pointer;
    transition: var(--transition);
}
.filter-bar .filter-select:focus { outline: none; border-color: var(--accent); }

/* Filtros avanzados */
.advanced-filters {
    background: var(--gray-50);
    border: 1px solid var(--gray-200);
    border-radius: var(--radius-sm);
    padding: 16px 18px;
    margin-bottom: 16px;
}
.advanced-filters .filter-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: 12px;
}

/* ── Tabla ── */
.factura-num    { font-family:monospace; font-size:12.5px; font-weight:700; color:var(--accent); }
.client-name    { font-weight:600; color:var(--gray-800); font-size:12.5px; }
.client-subtext { font-size:10.5px; color:var(--gray-400); font-family:monospace; }
.td-muted       { color:var(--gray-400); font-size:12px; }
.td-amount      { font-weight:700; color:var(--gray-800); font-size:13px; }
.td-pend        { font-weight:700; color:#DC2626; font-size:12.5px; }

/* Badges estado factura */
.badge {
    display:inline-flex; align-items:center;
    padding:4px 11px; border-radius:20px;
    font-size:11px; font-weight:700; white-space:nowrap;
}
.badge-pendiente  { background:#FEF3C7; color:#B45309; }
.badge-pagada     { background:#DCFCE7; color:#15803D; }
.badge-incompleta { background:#EDE9FE; color:#7C3AED; }
.badge-vencida    { background:#FEE2E2; color:#DC2626; }

/* Badge asignada */
.badge-asig-si  { background:#DCFCE7; color:#15803D; font-weight:700; font-size:10.5px; padding:2px 8px; border-radius:10px; }
.badge-asig-no  { background:var(--gray-100); color:var(--gray-500); font-size:10.5px; padding:2px 8px; border-radius:10px; }

/* ── Botones de acción en tabla ── */
.tbl-actions { display:flex; align-items:center; justify-content:center; gap:4px; }
.btn-tbl {
    width:30px; height:30px; border-radius:var(--radius-sm); border:none;
    display:inline-flex; align-items:center; justify-content:center;
    font-size:12px; cursor:pointer; transition:var(--transition); text-decoration:none;
}
.btn-tbl:hover { transform:translateY(-2px); box-shadow:var(--shadow); }
.btn-tbl.view   { background:#EFF6FF; color:#1565C0; }
.btn-tbl.pay    { background:#F0FDF4; color:#15803D; }
.btn-tbl.print  { background:#F5F3FF; color:#7C3AED; }
.btn-tbl.view:hover   { background:#1565C0; color:white; }
.btn-tbl.pay:hover    { background:#15803D; color:white; }
.btn-tbl.print:hover  { background:#7C3AED; color:white; }

/* ── Paginador ── */
.paginador-wrap {
    display:flex; align-items:center; justify-content:space-between;
    padding:14px 20px; border-top:1px solid var(--gray-100);
    background:var(--gray-50); border-radius:0 0 var(--radius) var(--radius);
    flex-wrap:wrap; gap:10px;
}
.paginador-info { font-size:12.5px; color:var(--gray-500); }
.paginador-info strong { color:var(--gray-700); }
.paginador-pages { display:flex; align-items:center; gap:4px; }
.pag-btn {
    width:34px; height:34px; display:inline-flex; align-items:center; justify-content:center;
    border-radius:var(--radius-sm); border:1px solid var(--gray-200);
    background:var(--white); color:var(--gray-600); font-size:13px; font-weight:600;
    text-decoration:none; transition:var(--transition);
}
.pag-btn:hover:not(.disabled) { background:var(--accent); color:white; border-color:var(--accent); }
.pag-btn.active { background:var(--accent); color:white; border-color:var(--accent); }
.pag-btn.disabled { opacity:.4; pointer-events:none; }
.paginador-rpp { display:flex; align-items:center; gap:8px; font-size:12.5px; color:var(--gray-500); }
.paginador-rpp select {
    padding:5px 8px; border:1px solid var(--gray-200);
    border-radius:var(--radius-sm); font-size:12.5px;
    font-family:var(--font); background:var(--white); cursor:pointer;
}

/* ── Modales — overlay system ── */
.modal-overlay {
    display: none;
    position: fixed; inset: 0; z-index: 900;
    background: rgba(15,23,42,.55);
    backdrop-filter: blur(4px);
    align-items: center; justify-content: center;
    padding: 20px;
}
.modal-overlay.open { display: flex; }

/* Compat: el código existente usa .show para modales */
.modal-overlay.show { display: flex; }

.modal-box {
    background: var(--white); border-radius: var(--radius-lg);
    box-shadow: var(--shadow-lg); display: flex; flex-direction: column;
    width: 100%; max-height: 92vh; overflow: hidden;
}
.modal-box.sm  { max-width: 480px; }
.modal-box.md  { max-width: 580px; }
.modal-box.lg  { max-width: 760px; }
.modal-box.xl  { max-width: 960px; }

.mhdr {
    padding: 18px 22px; border-bottom: 1px solid var(--gray-100);
    display: flex; align-items: flex-start; justify-content: space-between;
    flex-shrink: 0; background: var(--white);
    border-radius: var(--radius-lg) var(--radius-lg) 0 0;
}
.mhdr-title {
    display: flex; align-items: center; gap: 10px;
    font-size: 16px; font-weight: 700; color: var(--gray-800);
}
.mhdr-sub { font-size: 12px; color: var(--gray-400); margin-top: 3px; }
.modal-close-btn {
    width: 32px; height: 32px; border: none; background: var(--gray-100);
    border-radius: var(--radius-sm); cursor: pointer; color: var(--gray-500);
    display: flex; align-items: center; justify-content: center;
    font-size: 14px; transition: var(--transition); flex-shrink: 0;
}
.modal-close-btn:hover { background: var(--gray-200); color: var(--gray-700); }
.mbody  { padding: 22px; overflow-y: auto; flex: 1; }
.mfooter {
    padding: 14px 22px; border-top: 1px solid var(--gray-100);
    display: flex; justify-content: flex-end; align-items: center; gap: 10px;
    flex-shrink: 0; background: var(--gray-50);
    border-radius: 0 0 var(--radius-lg) var(--radius-lg);
}

/* ── Formularios en modales ── */
.fsec-title {
    font-size: 11px; font-weight: 700; color: var(--gray-400);
    text-transform: uppercase; letter-spacing: .8px;
    margin: 18px 0 12px; padding-bottom: 8px;
    border-bottom: 1px solid var(--gray-100);
    display: flex; align-items: center; gap: 6px;
}
.fsec-title:first-child { margin-top: 0; }
.form-grid { display: grid; gap: 14px; }
.form-grid.cols-2 { grid-template-columns: repeat(2,1fr); }
.form-grid.cols-3 { grid-template-columns: repeat(3,1fr); }
.form-grid.cols-4 { grid-template-columns: repeat(4,1fr); }
@media(max-width:640px){
    .form-grid.cols-2,.form-grid.cols-3,.form-grid.cols-4 { grid-template-columns:1fr; }
}
.form-group { display: flex; flex-direction: column; gap: 5px; }
.form-label { font-size: 12.5px; font-weight: 600; color: var(--gray-600); }
.form-label.required::after { content: ' *'; color: var(--red-light); }
.form-control {
    padding: 9px 12px; border: 1px solid var(--gray-200);
    border-radius: var(--radius-sm); font-size: 13.5px;
    font-family: var(--font); color: var(--gray-800);
    background: var(--white); transition: var(--transition); width: 100%;
}
.form-control:focus {
    outline: none; border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(33,150,243,.10);
}

/* ── Tabla dentro de modal ── */
.mini-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.mini-table th {
    padding: 10px 12px; background: var(--gray-50);
    font-size: 10.5px; font-weight: 700; color: var(--gray-400);
    text-transform: uppercase; letter-spacing: .5px;
    border-bottom: 1px solid var(--gray-100); white-space: nowrap;
}
.mini-table td {
    padding: 10px 12px; border-bottom: 1px solid var(--gray-100);
    color: var(--gray-700); vertical-align: middle;
}
.mini-table tr:last-child td { border-bottom: none; }
.mini-table tr:hover td { background: var(--gray-50); }

/* ── Contador modal ── */
.contador-box {
    background: var(--gray-50); border: 1px solid var(--gray-200);
    border-radius: var(--radius-sm); padding: 14px 16px;
    text-align: center; font-size: 13.5px; color: var(--gray-600);
    margin-top: 14px;
}
.contador-box .cnt-num {
    font-size: 28px; font-weight: 800; color: var(--accent); display: block;
}

/* ── Progress bar ── */
.progress-wrap {
    background: var(--gray-200); border-radius: 20px;
    overflow: hidden; height: 10px; margin: 10px 0;
}
.progress-bar-inner {
    height: 100%; background: linear-gradient(90deg, var(--accent), #42A5F5);
    border-radius: 20px; transition: width .4s ease;
    animation: stripes 1s linear infinite;
    background-size: 30px 30px;
}

/* ── Selección facturas ── */
.facturas-counter {
    font-size: 12.5px; font-weight: 600; color: var(--accent);
    padding: 5px 12px; background: #EFF6FF;
    border-radius: 20px; border: 1px solid #BFDBFE;
}

/* ── Alerts ── */
.alert-global {
    padding: 12px 18px; border-radius: var(--radius-sm); margin-bottom: 20px;
    display: flex; align-items: center; gap: 10px;
    font-size: 13.5px; font-weight: 500; animation: slideDown .3s ease;
}
.alert-global.success { background: #F0FDF4; color: #15803D; border: 1px solid #BBF7D0; }
.alert-global.danger  { background: #FEF2F2; color: #DC2626; border: 1px solid #FCA5A5; }
.alert-global.warning { background: #FEF3C7; color: #92400E; border: 1px solid #FDE68A; }
@keyframes slideDown { from{opacity:0;transform:translateY(-10px)} to{opacity:1;transform:translateY(0)} }

/* ── Spinner ── */
.spinner {
    width: 36px; height: 36px; border: 3px solid var(--gray-200);
    border-top-color: var(--accent); border-radius: 50%;
    animation: spin .7s linear infinite; margin: 40px auto;
}
@keyframes spin { to { transform: rotate(360deg); } }

/* ── Botones ── */
.btn {
    display: inline-flex; align-items: center; gap: 7px;
    padding: 9px 16px; border-radius: var(--radius-sm); border: none;
    font-size: 13px; font-weight: 600; font-family: var(--font);
    cursor: pointer; transition: var(--transition); text-decoration: none; white-space: nowrap;
}
.btn-primary   { background: var(--accent);   color: white; }
.btn-primary:hover   { background: #1565C0; color: white; }
.btn-secondary { background: var(--gray-200); color: var(--gray-700); }
.btn-secondary:hover { background: var(--gray-300); }
.btn-success   { background: #DCFCE7; color: #15803D; }
.btn-success:hover   { background: #15803D; color: white; }
.btn-danger    { background: #FEE2E2; color: #DC2626; }
.btn-danger:hover    { background: #DC2626; color: white; }
.btn-warning   { background: #FEF3C7; color: #92400E; }
.btn-warning:hover   { background: #D97706; color: white; }
.btn-purple    { background: #F5F3FF; color: #7C3AED; }
.btn-purple:hover    { background: #7C3AED; color: white; }
.btn-info      { background: #E0F2FE; color: #0369A1; }
.btn-info:hover      { background: #0284C7; color: white; }
.btn-sm { padding: 7px 13px; font-size: 12px; }

/* ── Fade in ── */
.fade-in { animation: fadeIn .4s ease both; }
.delay-1 { animation-delay: .10s; }
.delay-2 { animation-delay: .20s; }
@keyframes fadeIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }

/* ── Info cliente en modal ── */
.info-cliente-modal {
    background: #EFF6FF; border: 1px solid #BFDBFE;
    border-radius: var(--radius-sm); padding: 12px 16px;
    margin-bottom: 14px; font-size: 13px; color: #1E40AF;
}
.info-cliente-modal strong { color: #1565C0; }
</style>

<!-- ============================================================
     PAGE HEADER
     ============================================================ -->
<div class="page-header fade-in">
    <div>
        <div class="page-title">Gestión de Facturación</div>
        <div class="page-subtitle">
            <?php echo number_format($total_registros); ?> factura<?php echo $total_registros !== 1 ? 's' : ''; ?>
            <?php echo (!empty($_GET['estado']) || !empty($_GET['numero_contrato']) || !empty($_GET['numero_factura'])) ? 'con filtros aplicados' : 'registradas en el sistema'; ?>
        </div>
    </div>
</div>

<?php if ($mensaje): ?>
<div class="alert-global <?php echo $tipo_mensaje; ?>" id="alertaGlobal">
    <i class="fas fa-<?php echo $tipo_mensaje === 'success' ? 'check-circle' : 'exclamation-circle'; ?>"></i>
    <?php echo $mensaje; ?>
</div>
<?php endif; ?>

<!-- ============================================================
     KPI CARDS
     ============================================================ -->
<div class="kpi-facturas fade-in delay-1">
    <div class="kpi-card blue">
        <div class="kpi-label">Clientes Atendidos</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo number_format($totales['total_clientes'] ?? 0); ?></div>
                <div class="kpi-sub">Total registrados</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-users"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-database"></i> En el filtro actual</div>
    </div>

    <div class="kpi-card green">
        <div class="kpi-label">Facturas Mostradas</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo number_format($totales['total_facturas'] ?? 0); ?></div>
                <div class="kpi-sub">Total facturas</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-file-invoice"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-list"></i> Según filtros aplicados</div>
    </div>

    <div class="kpi-card amber">
        <div class="kpi-label">Facturas Pendientes</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo number_format($totales['facturas_pendientes'] ?? 0); ?></div>
                <div class="kpi-sub">Por cobrar</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-clock"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-hourglass-half"></i> Pendientes de pago</div>
    </div>

    <div class="kpi-card red">
        <div class="kpi-label">Facturas Incompletas</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo number_format($totales['facturas_incompletas'] ?? 0); ?></div>
                <div class="kpi-sub">Con abonos parciales</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-exclamation-circle"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-circle-half-stroke"></i> Abonadas parcialmente</div>
    </div>
</div>

<!-- ============================================================
     BARRA DE ACCIONES
     ============================================================ -->
<div class="action-bar fade-in delay-2">
    <div class="action-bar-left">
        <button class="btn btn-primary" onclick="mostrarModalImpresion()">
            <i class="fas fa-print"></i> Imprimir Facturas
        </button>
        <button class="btn btn-info" onclick="mostrarModalImpresionLote()">
            <i class="fas fa-print"></i> Imprimir por Lote
        </button>
        <button class="btn btn-secondary" onclick="exportarFacturas()">
            <i class="fas fa-download"></i> Exportar
        </button>
    </div>
    <div class="action-bar-right">
        <button class="btn btn-danger" onclick="verificarYGenerarFacturas()">
            <i class="fas fa-file-invoice"></i> Generar Facturas
        </button>
        <button class="btn btn-warning" onclick="mostrarModalGeneracionLote()">
            <i class="fas fa-layer-group"></i> Generar Por Lote
        </button>
    </div>
</div>

<!-- ============================================================
     BARRA DE FILTROS
     ============================================================ -->
<div class="filter-bar-h fade-in delay-2">
    <form method="GET" action="facturacion.php" id="formFiltrosFacturacion">
        <div class="filter-row-fields">
            <!-- Búsqueda general -->
            <div class="filter-field field-search">
                <label for="buscarFactura"><i class="fas fa-search"></i> Buscar</label>
                <div class="search-wrap-h">
                    <i class="fas fa-search search-icon-h"></i>
                    <input type="text"
                           id="buscarFactura"
                           name="buscar"
                           class="filter-input"
                           placeholder="No. factura o No. contrato…"
                           value="<?php echo htmlspecialchars($_GET['buscar'] ?? $_GET['numero_factura'] ?? $_GET['numero_contrato'] ?? ''); ?>"
                           autocomplete="off">
                </div>
            </div>
            <!-- Estado -->
            <div class="filter-field field-select">
                <label for="estadoFactura"><i class="fas fa-circle-half-stroke"></i> Estado</label>
                <select id="estadoFactura" name="estado" class="filter-select-h" onchange="this.form.submit()">
                    <option value="">Todos</option>
                    <option value="pendiente"  <?php echo ($_GET['estado'] ?? '') === 'pendiente'  ? 'selected' : ''; ?>>Pendiente</option>
                    <option value="pagada"     <?php echo ($_GET['estado'] ?? '') === 'pagada'     ? 'selected' : ''; ?>>Pagada</option>
                    <option value="incompleta" <?php echo ($_GET['estado'] ?? '') === 'incompleta' ? 'selected' : ''; ?>>Incompleta</option>
                    <option value="vencida"    <?php echo ($_GET['estado'] ?? '') === 'vencida'    ? 'selected' : ''; ?>>Vencida</option>
                </select>
            </div>
            <!-- Mes desde -->
            <div class="filter-field field-date">
                <label for="mesDesde"><i class="fas fa-calendar-days"></i> Mes Desde</label>
                <input type="month"
                       id="mesDesde"
                       name="mes_desde"
                       class="filter-select-h"
                       value="<?php echo htmlspecialchars($_GET['mes_desde'] ?? ''); ?>">
            </div>
            <!-- Mes hasta -->
            <div class="filter-field field-date">
                <label for="mesHasta"><i class="fas fa-calendar-check"></i> Mes Hasta</label>
                <input type="month"
                       id="mesHasta"
                       name="mes_hasta"
                       class="filter-select-h"
                       value="<?php echo htmlspecialchars($_GET['mes_hasta'] ?? ''); ?>">
            </div>
        </div>
        <div class="filter-row-btns">
            <button type="submit" class="btn btn-primary btn-sm">
                <i class="fas fa-search"></i> Buscar
            </button>
            <?php if (!empty($_GET['buscar']) || !empty($_GET['estado']) || !empty($_GET['mes_desde']) || !empty($_GET['mes_hasta']) || !empty($_GET['numero_contrato'])): ?>
                <a href="facturacion.php" class="btn btn-secondary btn-sm">
                    <i class="fas fa-times"></i> Limpiar
                </a>
            <?php endif; ?>
            <div class="filter-results-info">
                <?php echo number_format($total_registros); ?> factura<?php echo $total_registros !== 1 ? 's' : ''; ?>
            </div>
        </div>
    </form>
</div>

<!-- ============================================================
     TABLA DE FACTURAS
     ============================================================ -->
<div class="card fade-in">
    <div class="card-header">
        <div>
            <div class="card-title">Lista de Facturas</div>
            <div class="card-subtitle">
                Mostrando
                <?php echo $total_registros > 0 ? min($offset+1, $total_registros) : 0; ?>–<?php echo min($offset+$por_pagina, $total_registros); ?>
                de <?php echo number_format($total_registros); ?> facturas
            </div>
        </div>
    </div>

    <div style="overflow-x:auto;">
        <table class="data-table" id="tablaFacturas">
            <thead>
                <tr>
                    <th><input type="checkbox" id="selectAll" style="width:16px;height:16px;"></th>
                    <th>No. Factura</th>
                    <th>Asignada</th>
                    <th>Cliente</th>
                    <th>Contrato</th>
                    <th>Mes</th>
                    <th>Emisión</th>
                    <th>Vencimiento</th>
                    <th>Monto</th>
                    <th>Pendiente</th>
                    <th>Estado</th>
                    <th style="text-align:center;">Acciones</th>
                </tr>
            </thead>
            <tbody>
            <?php if (!empty($facturas)): ?>
                <?php foreach ($facturas as $f):
                    $montoPendiente = $f['monto'] - ($f['total_abonado'] ?? 0);
                    $badgeCls = match($f['estado']) {
                        'pagada'     => 'badge-pagada',
                        'incompleta' => 'badge-incompleta',
                        'vencida'    => 'badge-vencida',
                        default      => 'badge-pendiente',
                    };
                    $puedesPagar = in_array($f['estado'], ['pendiente','vencida','incompleta']);
                ?>
                <tr>
                    <td><input type="checkbox" class="factura-checkbox" value="<?php echo $f['id']; ?>"></td>
                    <td><span class="factura-num"><?php echo htmlspecialchars($f['numero_factura']); ?></span></td>
                    <td>
                        <?php if ($f['esta_asignada'] > 0): ?>
                            <span class="badge-asig-si">SÍ</span>
                        <?php else: ?>
                            <span class="badge-asig-no">NO</span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <div class="client-name">
                            <?php echo htmlspecialchars($f['cliente_nombre'].' '.$f['cliente_apellidos']); ?>
                        </div>
                        <div class="client-subtext">
                            Cód. <?php echo htmlspecialchars($f['cliente_codigo']); ?>
                        </div>
                    </td>
                    <td>
                        <span style="font-family:monospace;font-size:12px;font-weight:700;color:var(--accent);">
                            <?php echo htmlspecialchars($f['numero_contrato']); ?>
                        </span>
                    </td>
                    <td><span class="td-muted"><?php echo htmlspecialchars($f['mes_factura']); ?></span></td>
                    <td><span class="td-muted"><?php echo date('d/m/Y', strtotime($f['fecha_emision'])); ?></span></td>
                    <td><span class="td-muted"><?php echo date('d/m/Y', strtotime($f['fecha_vencimiento'])); ?></span></td>
                    <td><span class="td-amount">RD$<?php echo number_format($f['monto'], 2); ?></span></td>
                    <td>
                        <?php if ($montoPendiente > 0 && $f['estado'] !== 'pagada'): ?>
                            <span class="td-pend">RD$<?php echo number_format($montoPendiente, 2); ?></span>
                        <?php else: ?>
                            <span class="td-muted">—</span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <span class="badge <?php echo $badgeCls; ?>">
                            <?php echo ucfirst($f['estado']); ?>
                        </span>
                    </td>
                    <td>
                        <div class="tbl-actions">
                            <a href="ver_factura.php?id=<?php echo $f['id']; ?>"
                               class="btn-tbl view" title="Ver factura">
                                <i class="fas fa-eye"></i>
                            </a>
                            <button class="btn-tbl print" title="Imprimir factura"
                                    onclick="imprimirFactura(<?php echo $f['id']; ?>)">
                                <i class="fas fa-print"></i>
                            </button>
                            <?php if ($puedesPagar): ?>
                            <a href="registrar_pago.php?factura_id=<?php echo $f['id']; ?>"
                               class="btn-tbl pay" title="Registrar pago"
                               onclick="return handlePagoClick(event, this, <?php echo (int)$f['contrato_id']; ?>, <?php echo (int)$f['id']; ?>)">
                                <i class="fas fa-dollar-sign"></i>
                            </a>
                            <?php endif; ?>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr>
                    <td colspan="12" style="text-align:center;padding:40px;color:var(--gray-400);">
                        <i class="fas fa-file-invoice" style="font-size:32px;display:block;margin-bottom:10px;opacity:.4;"></i>
                        No se encontraron facturas con los criterios de búsqueda.
                    </td>
                </tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>

    <!-- Paginador -->
    <?php if ($total_paginas > 1): ?>
    <div class="paginador-wrap">
        <div class="paginador-info">
            Mostrando <strong><?php echo min($offset+1,$total_registros); ?>–<?php echo min($offset+$por_pagina,$total_registros); ?></strong>
            de <strong><?php echo number_format($total_registros); ?></strong> facturas
        </div>

        <div class="paginador-pages">
            <a class="pag-btn <?php echo $pagina_actual<=1?'disabled':''; ?>"
               href="<?php echo buildFacturaUrl(1,$params_url); ?>" title="Primera">
                <i class="fas fa-angles-left" style="font-size:10px;"></i>
            </a>
            <a class="pag-btn <?php echo $pagina_actual<=1?'disabled':''; ?>"
               href="<?php echo buildFacturaUrl($pagina_actual-1,$params_url); ?>" title="Anterior">
                <i class="fas fa-angle-left" style="font-size:11px;"></i>
            </a>

            <?php for ($p=max(1,$pagina_actual-2); $p<=min($total_paginas,$pagina_actual+2); $p++): ?>
                <a class="pag-btn <?php echo $p===$pagina_actual?'active':''; ?>"
                   href="<?php echo buildFacturaUrl($p,$params_url); ?>">
                    <?php echo $p; ?>
                </a>
            <?php endfor; ?>

            <a class="pag-btn <?php echo $pagina_actual>=$total_paginas?'disabled':''; ?>"
               href="<?php echo buildFacturaUrl($pagina_actual+1,$params_url); ?>" title="Siguiente">
                <i class="fas fa-angle-right" style="font-size:11px;"></i>
            </a>
            <a class="pag-btn <?php echo $pagina_actual>=$total_paginas?'disabled':''; ?>"
               href="<?php echo buildFacturaUrl($total_paginas,$params_url); ?>" title="Última">
                <i class="fas fa-angles-right" style="font-size:10px;"></i>
            </a>
        </div>

        <div class="paginador-rpp">
            <span>Mostrar:</span>
            <select onchange="cambiarRPP(this.value)">
                <?php foreach ([25,50,100,200] as $rpp): ?>
                    <option value="<?php echo $rpp; ?>" <?php echo $por_pagina===$rpp?'selected':''; ?>>
                        <?php echo $rpp; ?>
                    </option>
                <?php endforeach; ?>
            </select>
            <span>por página</span>
        </div>
    </div>
    <?php endif; ?>
</div>


<!-- ==============================================================
     MODAL: CONFIRMAR GENERACIÓN DE FACTURAS
     ============================================================== -->
<div class="modal-overlay" id="confirmacionModal">
    <div class="modal-box sm">
        <div class="mhdr">
            <div class="mhdr-title" style="color:#DC2626;">
                <i class="fas fa-exclamation-triangle"></i>
                Generación de Facturas en Proceso
            </div>
            <button class="modal-close-btn" onclick="cerrarModal()">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="mbody">
            <p id="mensajeBloqueo" style="font-size:13.5px;color:var(--gray-700);margin-bottom:10px;"></p>
            <div style="background:#FEF3C7;border:1px solid #FDE68A;border-radius:var(--radius-sm);
                        padding:12px 14px;color:#92400E;font-size:13.5px;margin-bottom:14px;">
                <i class="fas fa-triangle-exclamation" style="margin-right:6px;"></i>
                ¿Desea continuar con la generación de facturas?
            </div>
            <div class="contador-box">
                El botón se habilitará en: <span class="cnt-num" id="contador">10</span> segundos
            </div>
        </div>
        <div class="mfooter">
            <button class="btn btn-secondary" onclick="cerrarModal()">
                <i class="fas fa-times"></i> Cancelar
            </button>
            <button class="btn btn-danger" id="btnGenerarFacturas" disabled onclick="generarFacturas()">
                <i class="fas fa-file-invoice"></i> Sí, Generar
            </button>
        </div>
    </div>
</div>


<!-- ==============================================================
     MODAL: IMPRESIÓN DE FACTURAS POR DÍAS
     ============================================================== -->
<div class="modal-overlay" id="impresionModal">
    <div class="modal-box xl">
        <div class="mhdr">
            <div class="mhdr-title">
                <i class="fas fa-print" style="color:var(--accent);"></i>
                Impresión de Facturas por Días
            </div>
            <button class="modal-close-btn" onclick="cerrarModalImpresion()">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="mbody">
            <form id="formImpresion">
                <div class="fsec-title"><i class="fas fa-filter"></i> Filtros de Búsqueda</div>
                <div class="form-grid cols-3">
                    <div class="form-group">
                        <label class="form-label">Estado Factura</label>
                        <select class="form-control" id="estado_factura" name="estado">
                            <option value="">Todos</option>
                            <option value="pendiente" selected>Pendiente</option>
                            <option value="pagada">Pagada</option>
                            <option value="vencida">Vencida</option>
                            <option value="incompleta">Incompleta</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Estatus Contrato</label>
                        <select class="form-control" id="estatus_contrato" name="estatus_contrato">
                            <option value="activo" selected>Activo</option>
                            <option value="cancelado">Cancelado</option>
                            <option value="suspendido">Suspendido</option>
                            <option value="">Todos</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Filtrar por Contrato</label>
                        <input type="text" class="form-control" id="contrato" name="contrato"
                               placeholder="Ej: 00001">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Día Cobro Desde</label>
                        <input type="number" class="form-control" id="dia_cobro_desde"
                               name="dia_cobro_desde" min="1" max="31" step="1"
                               oninput="validarDiaCobro(this)" placeholder="1 – 31">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Día Cobro Hasta</label>
                        <input type="number" class="form-control" id="dia_cobro_hasta"
                               name="dia_cobro_hasta" min="1" max="31" step="1"
                               oninput="validarDiaCobro(this)" placeholder="1 – 31">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Fecha Emisión Desde</label>
                        <input type="date" class="form-control" id="fecha_desde_modal" name="fecha_desde">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Fecha Emisión Hasta</label>
                        <input type="date" class="form-control" id="fecha_hasta_modal" name="fecha_hasta">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Mes Factura Desde</label>
                        <input type="month" class="form-control" id="mes_desde_modal" name="mes_desde">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Mes Factura Hasta</label>
                        <input type="month" class="form-control" id="mes_hasta_modal" name="mes_hasta">
                    </div>
                </div>

                <!-- Preview de facturas -->
                <div id="preview-facturas" style="display:none;margin-top:18px;max-height:380px;overflow-y:auto;">
                    <div class="fsec-title"><i class="fas fa-list"></i> Facturas Encontradas</div>
                    <table class="mini-table">
                        <thead>
                            <tr>
                                <th>
                                    <input type="checkbox" id="seleccionar-todas"
                                           onclick="seleccionarTodas(this)"
                                           style="width:15px;height:15px;">
                                </th>
                                <th>No. Factura</th>
                                <th>Asignada</th>
                                <th>Contrato</th>
                                <th>Cliente</th>
                                <th>Monto</th>
                                <th>Fecha</th>
                            </tr>
                        </thead>
                        <tbody id="lista-facturas"></tbody>
                    </table>
                </div>
            </form>
        </div>
        <div class="mfooter">
            <div style="margin-right:auto;">
                <span id="total-seleccionadas" class="facturas-counter">0 facturas seleccionadas</span>
            </div>
            <button class="btn btn-secondary" onclick="cerrarModalImpresion()">
                <i class="fas fa-times"></i> Cerrar
            </button>
            <button class="btn btn-primary" onclick="cargarFacturas()">
                <i class="fas fa-search"></i> Cargar Facturas
            </button>
            <button class="btn btn-success" id="btn-imprimir" style="display:none;"
                    onclick="imprimirFacturas('preview')">
                <i class="fas fa-eye"></i> Ver Facturas
            </button>
            <button class="btn btn-warning" id="btn-imprimir-directo" style="display:none;"
                    onclick="imprimirFacturas('direct')">
                <i class="fas fa-print"></i> Imprimir Directo
            </button>
        </div>
    </div>
</div>


<!-- ==============================================================
     MODAL: IMPRIMIR POR LOTE
     ============================================================== -->
<div class="modal-overlay" id="modalImpresionLote">
    <div class="modal-box lg">
        <div class="mhdr">
            <div class="mhdr-title">
                <i class="fas fa-print" style="color:#7C3AED;"></i>
                Imprimir Facturas por Lote
            </div>
            <button class="modal-close-btn" onclick="cerrarModalImpresionLote()">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="mbody">
            <form id="formImpresionLote">
                <div class="fsec-title"><i class="fas fa-plus-circle"></i> Agregar Facturas</div>
                <div class="form-grid cols-2">
                    <div class="form-group">
                        <label class="form-label">No. Factura</label>
                        <input type="text" class="form-control" id="numero_factura_lote"
                               placeholder="Ej: 000123">
                    </div>
                    <div class="form-group" style="justify-content:flex-end;align-self:flex-end;">
                        <button type="button" class="btn btn-primary" onclick="agregarFacturaLote()">
                            <i class="fas fa-plus"></i> Agregar
                        </button>
                    </div>
                </div>

                <div id="lista_facturas_lote" style="display:none;margin-top:16px;">
                    <div class="fsec-title"><i class="fas fa-list"></i> Facturas Seleccionadas</div>
                    <table class="mini-table">
                        <thead>
                            <tr>
                                <th style="text-align:center;width:36px;">
                                    <input type="checkbox" id="selectAllLote"
                                           onchange="seleccionarTodasLote(this)"
                                           style="width:15px;height:15px;cursor:pointer;">
                                </th>
                                <th>No. Factura</th>
                                <th>Cliente</th>
                                <th>Contrato</th>
                                <th>Monto</th>
                                <th>Estado</th>
                                <th style="width:36px;"></th>
                            </tr>
                        </thead>
                        <tbody id="facturas_seleccionadas_lote"></tbody>
                        <tbody id="facturas_seleccionadas_lote"></tbody>
                    </table>
                </div>
            </form>
        <!-- Mensaje inline -->
                <div id="lote_msg"></div>
                    </div>
                    <div class="mfooter">
                        <span id="lote_contador" class="facturas-counter"
                              style="margin-right:auto;">0 facturas seleccionadas</span>
                        <button class="btn btn-secondary" onclick="cerrarModalImpresionLote()">
                            <i class="fas fa-times"></i> Cerrar
                        </button>
                        <button class="btn btn-purple" onclick="imprimirLote()">
                            <i class="fas fa-print"></i> Imprimir Seleccionadas
                        </button>
                    </div>
    </div>
</div>


<!-- ==============================================================
     MODAL: GENERACIÓN POR LOTE
     ============================================================== -->
<div class="modal-overlay" id="generacionLoteModal">
    <div class="modal-box lg">
        <div class="mhdr">
            <div class="mhdr-title">
                <i class="fas fa-layer-group" style="color:#D97706;"></i>
                Generar Facturas Por Lote
            </div>
            <button class="modal-close-btn" onclick="cerrarModalGeneracionLote()">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="mbody">
            <form id="formGeneracionLote">
                <div class="fsec-title"><i class="fas fa-file-contract"></i> Datos del Contrato</div>
                <div class="form-grid cols-2">
                    <div class="form-group">
                        <label class="form-label required">Número de Contrato</label>
                        <input type="text" class="form-control" id="contrato_lote"
                               placeholder="Ej: 00102" oninput="verificarContrato()">
                    </div>
                    <div class="form-group">
                        <label class="form-label required">Cantidad de Facturas</label>
                        <input type="number" class="form-control" id="cantidad_facturas"
                               min="1" max="12" placeholder="Máximo 12">
                    </div>
                </div>

                <div id="info_cliente" style="display:none;margin-top:14px;">
                    <div class="info-cliente-modal">
                        <i class="fas fa-user" style="margin-right:6px;"></i>
                        <strong>Cliente:</strong> <span id="nombre_cliente"></span>
                    </div>
                </div>

                <div id="preview_facturas" style="display:none;margin-top:14px;">
                    <div class="fsec-title"><i class="fas fa-eye"></i> Vista Previa de Facturas</div>
                    <div style="max-height:260px;overflow-y:auto;">
                        <table class="mini-table">
                            <thead>
                                <tr>
                                    <th>Contrato</th>
                                    <th>Mes</th>
                                    <th>Monto</th>
                                    <th>Cuota</th>
                                </tr>
                            </thead>
                            <tbody id="preview_facturas_body"></tbody>
                        </table>
                    </div>
                </div>

                <div id="progreso_generacion" style="display:none;margin-top:16px;">
                    <div style="font-size:13px;color:var(--gray-600);margin-bottom:8px;">
                        Generando facturas…
                    </div>
                    <div class="progress-wrap">
                        <div class="progress-bar-inner" id="progressBar" style="width:0%;"></div>
                    </div>
                </div>
            </form>
        </div>
        <div class="mfooter">
            <button class="btn btn-secondary" onclick="cerrarModalGeneracionLote()">
                <i class="fas fa-times"></i> Cancelar
            </button>
            <button class="btn btn-primary" onclick="preGenerarFacturas()">
                <i class="fas fa-eye"></i> Pre-generar
            </button>
            <button class="btn btn-success" id="btn_generar" style="display:none;"
                    onclick="generarFacturasLote()">
                <i class="fas fa-check"></i> Generar
            </button>
        </div>
    </div>
</div>


<!-- ==============================================================
     MODAL: CONFIRMACIÓN GENERACIÓN EXITOSA
     ============================================================== -->
<div class="modal-overlay" id="confirmacionGeneracionModal">
    <div class="modal-box sm">
        <div class="mhdr">
            <div class="mhdr-title" style="color:#15803D;">
                <i class="fas fa-check-circle"></i> Generación Exitosa
            </div>
            <button class="modal-close-btn" onclick="cerrarConfirmacionGeneracion()">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="mbody">
            <div style="text-align:center;padding:20px;">
                <i class="fas fa-check-circle" style="font-size:48px;color:#16A34A;display:block;margin-bottom:14px;"></i>
                <p style="font-size:15px;font-weight:600;color:var(--gray-800);">
                    Las facturas han sido generadas exitosamente.
                </p>
                <p style="font-size:13px;color:var(--gray-400);margin-top:6px;">
                    La página se actualizará en unos segundos…
                </p>
            </div>
        </div>
        <div class="mfooter">
            <button class="btn btn-primary" onclick="cerrarConfirmacionGeneracion()">
                <i class="fas fa-check"></i> Cerrar
            </button>
        </div>
    </div>
</div>


<!-- ==============================================================
     JAVASCRIPT
     ============================================================== -->
<script>
/* ═══════════════════════════════════════════════════════════
   HELPERS GENERALES
═══════════════════════════════════════════════════════════ */
function abrirOverlay(id) {
    var el = document.getElementById(id);
    if (el) { el.classList.add('open'); document.body.style.overflow = 'hidden'; }
}
function cerrarOverlay(id) {
    var el = document.getElementById(id);
    if (el) { el.classList.remove('open'); document.body.style.overflow = ''; }
}

function cambiarRPP(v) {
    document.cookie = 'facturas_por_pagina=' + v + '; path=/; max-age=31536000';
    var url = new URL(window.location.href);
    url.searchParams.set('pagina', '1');
    window.location.href = url.toString();
}

/* Auto-ocultar alerta */
(function(){
    var a = document.getElementById('alertaGlobal');
    if (a) setTimeout(function(){
        a.style.opacity = '0'; a.style.transition = 'opacity .5s';
        setTimeout(function(){ a.remove(); }, 500);
    }, 6000);
})();

/* ═══════════════════════════════════════════════════════════
   FILTROS — El formulario ahora usa GET estándar.
   Se mantiene este bloque vacío por compatibilidad.
═══════════════════════════════════════════════════════════ */

/* ─── Manejar clic en botón Pagar — verificación de facturas anteriores ─── */
function handlePagoClick(e, link, contratoId, facturaId) {
    e.preventDefault();
    link.style.opacity = '0.5';
    link.style.pointerEvents = 'none';
    fetch('verificar_facturas.php?contrato_id=' + contratoId + '&factura_id=' + facturaId)
        .then(function(r) { return r.json(); })
        .then(function(data) {
            link.style.opacity      = '';
            link.style.pointerEvents = '';
            if (data.tiene_pendientes && data.facturas && data.facturas.length > 0) {
                mostrarModalFacturasPendientes(data.facturas);
            } else {
                window.location.href = link.href;
            }
        })
        .catch(function(err) {
            link.style.opacity      = '';
            link.style.pointerEvents = '';
            console.error('Error al verificar facturas:', err);
            window.location.href = link.href;
        });
    return false;
}

function mostrarModalFacturasPendientes(facturas) {
    var tbody       = document.getElementById('fp-tabla-body');
    var totalEl     = document.getElementById('fp-total-pendiente');
    var introEl     = document.getElementById('fp-mensaje-intro');
    var totalPend   = 0;
    tbody.innerHTML = '';
    facturas.forEach(function(f) {
        var pend = parseFloat(f.monto_pendiente);
        totalPend += pend;
        var cls = f.estado === 'incompleta' ? 'badge-incompleta-fp'
                : f.estado === 'vencida'    ? 'badge-vencida-fp'
                : 'badge-pendiente-fp';
        var tr = document.createElement('tr');
        tr.innerHTML =
            '<td><a href="registrar_pago.php?factura_id=' + f.id +
            '" class="fp-link-factura">' + f.numero_factura + '</a></td>' +
            '<td>' + f.mes_factura + '</td>' +
            '<td>RD$' + parseFloat(f.monto).toLocaleString('es-DO',{minimumFractionDigits:2}) + '</td>' +
            '<td>RD$' + parseFloat(f.total_pagado).toLocaleString('es-DO',{minimumFractionDigits:2}) + '</td>' +
            '<td style="color:#DC2626;font-weight:700;">RD$' +
                pend.toLocaleString('es-DO',{minimumFractionDigits:2}) + '</td>' +
            '<td><span class="badge-estado-fp ' + cls + '">' + f.estado + '</span></td>';
        tbody.appendChild(tr);
    });
    totalEl.textContent = 'RD$' + totalPend.toLocaleString('es-DO',{minimumFractionDigits:2});
    introEl.textContent = 'Para pagar esta factura primero debe saldar ' +
        (facturas.length === 1 ? 'la siguiente factura pendiente:'
            : 'las siguientes ' + facturas.length + ' facturas pendientes:');
    var modal = document.getElementById('modalFacturasPendientes');
    modal.style.display = 'flex';
    document.body.style.overflow = 'hidden';
}

function cerrarModalFacturasPendientes() {
    var modal = document.getElementById('modalFacturasPendientes');
    if (modal) { modal.style.display = 'none'; }
    document.body.style.overflow = '';
}

/* Compatibilidad con llamadas antiguas */
async function verificarFacturasIncompletas(contratoId) {
    mostrarToast('Use el botón de pago para verificar facturas pendientes.', 'info');
}

/* Buscar al presionar Enter en el nuevo campo de búsqueda */
(function() {
    var bf = document.getElementById('buscarFactura');
    if (bf) {
        bf.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') { e.preventDefault(); this.form.submit(); }
        });
    }
})();

/* Select all checkboxes */
document.getElementById('selectAll').addEventListener('change', function() {
    document.querySelectorAll('.factura-checkbox').forEach(function(cb){
        cb.checked = this.checked;
    }, this);
});

/* ═══════════════════════════════════════════════════════════
   GENERAR FACTURAS — MODAL CONFIRMACIÓN
═══════════════════════════════════════════════════════════ */
var contadorInterval;
var tiempoRestante = 10;

function verificarYGenerarFacturas() {
    fetch('verificar_bloqueo_facturas.php')
        .then(function(r){ return r.json(); })
        .then(function(data){
            if (data.bloqueo) {
                mostrarModalConfirmacion(data.mensaje);
            } else {
                generarFacturas();
            }
        })
        .catch(function(e){ console.error('Error:', e); });
}

function mostrarModalConfirmacion(mensaje) {
    document.getElementById('mensajeBloqueo').textContent = mensaje || '';
    var modal = document.getElementById('confirmacionModal');
    modal.classList.add('open');
    document.body.style.overflow = 'hidden';
    iniciarContador();
}

function cerrarModal() {
    document.getElementById('confirmacionModal').classList.remove('open');
    document.body.style.overflow = '';
    detenerContador();
}

function iniciarContador() {
    tiempoRestante = 10;
    document.getElementById('contador').textContent = tiempoRestante;
    document.getElementById('btnGenerarFacturas').disabled = true;
    contadorInterval = setInterval(function() {
        tiempoRestante--;
        document.getElementById('contador').textContent = tiempoRestante;
        if (tiempoRestante <= 0) {
            detenerContador();
            document.getElementById('btnGenerarFacturas').disabled = false;
        }
    }, 1000);
}

function detenerContador() {
    clearInterval(contadorInterval);
    tiempoRestante = 10;
    var cnt = document.getElementById('contador');
    if (cnt) cnt.textContent = 10;
}

function generarFacturas() {
    cerrarModal();
    var form = document.createElement('form');
    form.method = 'POST';
    form.innerHTML = '<input type="hidden" name="action" value="generar_facturas">';
    document.body.appendChild(form);
    form.submit();
}

function exportarFacturas() {
    var estado   = document.getElementById('estadoFilter').value;
    var url = 'exportar_facturas.php?formato=excel';
    if (estado) url += '&estado=' + estado;
    window.location.href = url;
}

/* ═══════════════════════════════════════════════════════════
   IMPRIMIR FACTURA INDIVIDUAL
═══════════════════════════════════════════════════════════ */
function imprimirFactura(id) {
    window.open('imprimir_factura.php?id=' + id, '_blank');
}

/* ═══════════════════════════════════════════════════════════
   MODAL IMPRESIÓN DE FACTURAS POR DÍAS
═══════════════════════════════════════════════════════════ */
function mostrarModalImpresion() {
    var modal = document.getElementById('impresionModal');
    modal.classList.add('open');
    document.body.style.overflow = 'hidden';
    document.getElementById('fecha_desde_modal').value = '';
    document.getElementById('fecha_hasta_modal').value = '';
    limpiarFormularioImpresion();
}

function cerrarModalImpresion() {
    document.getElementById('impresionModal').classList.remove('open');
    document.body.style.overflow = '';
    limpiarFormularioImpresion();
}

function limpiarFormularioImpresion() {
    var campos = ['estado_factura','estatus_contrato','contrato',
                  'dia_cobro_desde','dia_cobro_hasta',
                  'fecha_desde_modal','fecha_hasta_modal',
                  'mes_desde_modal','mes_hasta_modal'];
    campos.forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.value = id === 'estado_factura' ? 'pendiente' : id === 'estatus_contrato' ? 'activo' : '';
    });
    document.getElementById('lista-facturas').innerHTML = '';
    document.getElementById('preview-facturas').style.display = 'none';
    document.getElementById('btn-imprimir').style.display = 'none';
    document.getElementById('btn-imprimir-directo').style.display = 'none';
    actualizarContadorImpresion();
}

function cargarFacturas() {
    var formData = new FormData(document.getElementById('formImpresion'));
    var params   = new URLSearchParams(formData);

    fetch('buscar_facturas.php?' + params.toString())
        .then(function(r){ return r.json(); })
        .then(function(data){
            var tbody = document.getElementById('lista-facturas');
            tbody.innerHTML = '';
            if (!data || data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--gray-400);padding:20px;">No se encontraron facturas.</td></tr>';
                document.getElementById('preview-facturas').style.display = 'block';
                document.getElementById('btn-imprimir').style.display = 'none';
                document.getElementById('btn-imprimir-directo').style.display = 'none';
                actualizarContadorImpresion();
                return;
            }
            data.forEach(function(f) {
                tbody.innerHTML += '<tr>' +
                    '<td><input type="checkbox" name="facturas[]" value="' + f.id + '" class="factura-check" onchange="actualizarContadorImpresion()"></td>' +
                    '<td><span style="font-family:monospace;font-weight:700;color:var(--accent);">' + f.numero_factura + '</span></td>' +
                    '<td>' + (f.esta_asignada > 0 ? '<span class="badge-asig-si">SÍ</span>' : '<span class="badge-asig-no">NO</span>') + '</td>' +
                    '<td><span style="font-family:monospace;font-size:11px;color:var(--accent);">' + (f.numero_contrato || '') + '</span></td>' +
                    '<td style="font-size:12px;">' + (f.cliente_nombre || '') + '</td>' +
                    '<td style="font-weight:700;">RD$' + parseFloat(f.monto || 0).toFixed(2) + '</td>' +
                    '<td style="font-size:11.5px;color:var(--gray-400);">' + (f.fecha_emision || '') + '</td>' +
                    '</tr>';
            });
            document.getElementById('preview-facturas').style.display = 'block';
            document.getElementById('btn-imprimir').style.display = 'inline-flex';
            document.getElementById('btn-imprimir-directo').style.display = 'inline-flex';
            actualizarContadorImpresion();
        })
        .catch(function(e){
            console.error('Error:', e);
            mostrarToast('Error al cargar facturas.', 'error');
        });
}

function actualizarContadorImpresion() {
    var sel = document.querySelectorAll('.factura-check:checked').length;
    var span = document.getElementById('total-seleccionadas');
    if (span) {
        span.textContent = sel + ' factura' + (sel !== 1 ? 's' : '') + ' seleccionada' + (sel !== 1 ? 's' : '');
        span.style.background = sel > 0 ? '#EFF6FF' : 'var(--gray-100)';
        span.style.color      = sel > 0 ? 'var(--accent)' : 'var(--gray-500)';
        span.style.borderColor= sel > 0 ? '#BFDBFE' : 'var(--gray-200)';
    }
}

function seleccionarTodas(cb) {
    document.querySelectorAll('.factura-check').forEach(function(c){ c.checked = cb.checked; });
    actualizarContadorImpresion();
}

function imprimirFacturas(tipo) {
    var facturas = Array.from(document.querySelectorAll('.factura-check:checked')).map(function(cb){ return cb.value; });
    if (facturas.length === 0) {
        mostrarToast('Por favor, seleccione al menos una factura para imprimir.', 'warning');
        return;
    }
    var params = new URLSearchParams(new FormData(document.getElementById('formImpresion')));
    params.delete('facturas[]');
    facturas.forEach(function(id){ params.append('facturas[]', id); });
    params.append('tipo', tipo);
    window.open('imprimirpordias.php?' + params.toString(), '_blank');
}

function validarDiaCobro(input) {
    input.value = input.value.replace(/[.,]/g, '');
    var val = parseInt(input.value);
    if (isNaN(val)) { input.value = ''; return; }
    if (val < 1)  input.value = '1';
    else if (val > 31) input.value = '31';
    else input.value = val;

    var desde = parseInt(document.getElementById('dia_cobro_desde').value) || 0;
    var hasta = parseInt(document.getElementById('dia_cobro_hasta').value) || 0;
    if (desde && hasta && desde > hasta) {
        mostrarToast('El día desde no puede ser mayor que el día hasta.', 'error');
        document.getElementById('dia_cobro_desde').value = '';
        document.getElementById('dia_cobro_hasta').value = '';
    }
}

/* ═══════════════════════════════════════════════════════════
   MODAL IMPRESIÓN POR LOTE
═══════════════════════════════════════════════════════════ */
var facturasLoteSeleccionadas = [];

function mostrarModalImpresionLote() {
    facturasLoteSeleccionadas = [];
    document.getElementById('modalImpresionLote').classList.add('open');
    document.body.style.overflow = 'hidden';
    document.getElementById('numero_factura_lote').value = '';
    document.getElementById('facturas_seleccionadas_lote').innerHTML = '';
    document.getElementById('lista_facturas_lote').style.display = 'none';

    var msgEl = document.getElementById('lote_msg');
    if (msgEl) msgEl.innerHTML = '';

    var cntEl = document.getElementById('lote_contador');
    if (cntEl) cntEl.textContent = '0 facturas seleccionadas';

    /* Bind Enter al input — directo, sin DOMContentLoaded */
    var inp = document.getElementById('numero_factura_lote');
    if (inp) {
        inp.onkeydown = function(e) {
            if (e.key === 'Enter') { e.preventDefault(); agregarFacturaLote(); }
        };
        setTimeout(function(){ inp.focus(); }, 150);
    }
}

function cerrarModalImpresionLote() {
    facturasLoteSeleccionadas = [];
    document.getElementById('modalImpresionLote').classList.remove('open');
    document.body.style.overflow = '';

    var form = document.getElementById('formImpresionLote');
    if (form) form.reset();

    document.getElementById('facturas_seleccionadas_lote').innerHTML = '';
    document.getElementById('lista_facturas_lote').style.display = 'none';

    var msgEl = document.getElementById('lote_msg');
    if (msgEl) msgEl.innerHTML = '';

    var cntEl = document.getElementById('lote_contador');
    if (cntEl) cntEl.textContent = '0 facturas seleccionadas';
}

/* ── Mostrar mensaje inline en el modal ── */
function mostrarMsgLote(texto, tipo) {
    var colores = {
        error:   { bg:'#FEF2F2', border:'#FCA5A5', color:'#DC2626', icon:'fa-times-circle' },
        warning: { bg:'#FEF3C7', border:'#FDE68A', color:'#B45309', icon:'fa-triangle-exclamation' },
        success: { bg:'#F0FDF4', border:'#BBF7D0', color:'#15803D', icon:'fa-check-circle' }
    };
    var c = colores[tipo] || colores.error;

    var msgEl = document.getElementById('lote_msg');
    if (!msgEl) {
        /* Fallback: usar toast si no existe el div */
        mostrarToast(texto.replace(/<[^>]*>/g, ''), tipo);
        return;
    }

    msgEl.innerHTML =
        '<div style="background:' + c.bg + ';border:1px solid ' + c.border + ';' +
        'border-radius:6px;padding:8px 12px;font-size:13px;color:' + c.color + ';' +
        'display:flex;align-items:center;gap:7px;margin-top:8px;">' +
        '<i class="fas ' + c.icon + '"></i>' + texto + '</div>';
}

/* ── Agregar factura al lote ── */
function agregarFacturaLote() {
    var inputEl = document.getElementById('numero_factura_lote');
    if (!inputEl) return;

    var numero = inputEl.value.trim();

    /* Limpiar mensaje anterior de forma segura */
    var msgEl = document.getElementById('lote_msg');
    if (msgEl) msgEl.innerHTML = '';

    if (!numero) {
        mostrarMsgLote('Ingrese un número de factura.', 'warning');
        return;
    }

    /* Verificar duplicado ANTES de ir al servidor */
    var yaExiste = false;
    for (var i = 0; i < facturasLoteSeleccionadas.length; i++) {
        if (String(facturasLoteSeleccionadas[i].numero_factura) === String(numero)) {
            yaExiste = true;
            break;
        }
    }
    if (yaExiste) {
        mostrarMsgLote('Esta factura ya está en la lista.', 'warning');
        inputEl.select();
        return;
    }

    /* Deshabilitar input mientras busca */
    inputEl.disabled = true;

    /* verificar_factura.php devuelve {success, factura:{...}} */
    fetch('verificar_factura.php?numero_factura=' + encodeURIComponent(numero))
        .then(function(r) {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        })
        .then(function(data) {
            inputEl.disabled = false;

            if (!data || !data.success || !data.factura) {
                mostrarMsgLote('Factura no encontrada.', 'error');
                inputEl.select();
                inputEl.focus();
                return;
            }

            /* Agregar al array y re-render */
            facturasLoteSeleccionadas.push(data.factura);
            renderTablaLote();

            /* Limpiar input y mostrar éxito */
            inputEl.value = '';
            inputEl.focus();
            mostrarMsgLote(
                'Factura <strong>' + data.factura.numero_factura + '</strong> agregada correctamente.',
                'success'
            );

            /* Auto-limpiar mensaje de éxito después de 3s */
            setTimeout(function() {
                var me = document.getElementById('lote_msg');
                if (me) me.innerHTML = '';
            }, 3000);
        })
        .catch(function(err) {
            inputEl.disabled = false;
            console.error('Error agregarFacturaLote:', err);
            mostrarMsgLote('Error de conexión al buscar la factura.', 'error');
            inputEl.focus();
        });
}

/* ── Renderizar tabla con checkboxes ── */
function renderTablaLote() {
    var tbody = document.getElementById('facturas_seleccionadas_lote');
    if (!tbody) return;

    tbody.innerHTML = '';

    for (var i = 0; i < facturasLoteSeleccionadas.length; i++) {
        var f = facturasLoteSeleccionadas[i];
        var idx = i;

        var badgeCls = f.estado === 'pagada'    ? 'badge-pagada'     :
                       f.estado === 'incompleta' ? 'badge-incompleta' :
                       f.estado === 'vencida'    ? 'badge-vencida'    : 'badge-pendiente';

        var nombreCliente = ((f.cliente_nombre || '') + ' ' + (f.cliente_apellidos || '')).trim();
        var asigBadge     = (parseInt(f.esta_asignada) > 0)
            ? '<span class="badge-asig-si">SÍ</span>'
            : '<span class="badge-asig-no">NO</span>';

        var tr = document.createElement('tr');
        tr.id  = 'lote_row_' + idx;
        tr.innerHTML =
            '<td style="text-align:center;">' +
                '<input type="checkbox" class="lote-check" value="' + f.id + '" ' +
                'data-idx="' + idx + '" checked ' +
                'style="width:15px;height:15px;cursor:pointer;">' +
            '</td>' +
            '<td><span style="font-family:monospace;font-weight:700;color:var(--accent);">' +
                f.numero_factura + '</span></td>' +
            '<td>' + asigBadge + '</td>' +
            '<td><span style="font-family:monospace;font-size:11px;color:var(--gray-500);">' +
                (f.numero_contrato || '') + '</span></td>' +
            '<td style="font-size:12.5px;font-weight:600;color:var(--gray-800);">' +
                nombreCliente + '</td>' +
            '<td style="font-weight:700;">RD$' + parseFloat(f.monto || 0).toFixed(2) + '</td>' +
            '<td><span class="badge ' + badgeCls + '">' + (f.estado || '') + '</span></td>' +
            '<td style="text-align:center;">' +
                '<button type="button" class="btn-tbl del" ' +
                'onclick="quitarFacturaLote(' + idx + ')" ' +
                'title="Quitar de la lista" style="width:26px;height:26px;">' +
                '<i class="fas fa-times" style="font-size:10px;"></i></button>' +
            '</td>';

        /* Bind change en el checkbox usando closure correcta */
        (function(tr) {
            var cb = tr.querySelector('.lote-check');
            if (cb) cb.addEventListener('change', actualizarContadorLote);
        })(tr);

        tbody.appendChild(tr);
    }

    /* Mostrar/ocultar sección */
    document.getElementById('lista_facturas_lote').style.display =
        facturasLoteSeleccionadas.length > 0 ? 'block' : 'none';

    actualizarContadorLote();
}

/* ── Actualizar contador de seleccionadas ── */
function actualizarContadorLote() {
    var sel   = document.querySelectorAll('.lote-check:checked').length;
    var total = facturasLoteSeleccionadas.length;
    var cntEl = document.getElementById('lote_contador');
    if (!cntEl) return;

    cntEl.textContent  = sel + ' de ' + total + ' factura' + (total !== 1 ? 's' : '') +
                         ' seleccionada' + (sel !== 1 ? 's' : '');
    cntEl.style.background  = sel > 0 ? '#EFF6FF'         : 'var(--gray-100)';
    cntEl.style.color       = sel > 0 ? 'var(--accent)'   : 'var(--gray-500)';
    cntEl.style.borderColor = sel > 0 ? '#BFDBFE'         : 'var(--gray-200)';
}

/* ── Quitar una factura de la lista ── */
function quitarFacturaLote(idx) {
    facturasLoteSeleccionadas.splice(idx, 1);
    renderTablaLote();

    if (facturasLoteSeleccionadas.length === 0) {
        var msgEl = document.getElementById('lote_msg');
        if (msgEl) msgEl.innerHTML = '';
    }
}

/* ── Seleccionar / deseleccionar todas ── */
function seleccionarTodasLote(cb) {
    document.querySelectorAll('.lote-check').forEach(function(c) {
        c.checked = cb.checked;
    });
    actualizarContadorLote();
}

/* ── Imprimir solo las facturas marcadas ── */
function imprimirLote() {
    var seleccionadas = Array.from(document.querySelectorAll('.lote-check:checked'))
                             .map(function(cb) { return cb.value; });

    if (seleccionadas.length === 0) {
        mostrarMsgLote('Seleccione al menos una factura para imprimir.', 'warning');
        return;
    }

    var params = seleccionadas.map(function(id) { return 'facturas[]=' + id; }).join('&');
    window.open('imprimirpordias.php?' + params + '&tipo=preview', '_blank');
}

/* ═══════════════════════════════════════════════════════════
   MODAL GENERACIÓN POR LOTE
═══════════════════════════════════════════════════════════ */
var modalLoteAbierto  = false;
var datosPreGeneracion = null;

function mostrarModalGeneracionLote() {
    fetch('verificar_modal_lote.php')
        .then(function(r){ return r.json(); })
        .then(function(data){
            if (data.bloqueado) {
                mostrarToast('El modal está siendo utilizado por otro usuario. Por favor, espere.', 'warning');
                return;
            }
            document.getElementById('generacionLoteModal').classList.add('open');
            document.body.style.overflow = 'hidden';
            registrarBloqueoModal();
            modalLoteAbierto = true;
        })
        .catch(function(e){ console.error('Error:', e); mostrarToast('Error al verificar disponibilidad del modal.', 'error'); });
}

function cerrarModalGeneracionLote() {
    if (!modalLoteAbierto) return;
    fetch('liberar_modal_lote.php')
        .then(function(r){ return r.json(); })
        .then(function(data){
            if (data.success) {
                document.getElementById('generacionLoteModal').classList.remove('open');
                document.body.style.overflow = '';
                document.getElementById('formGeneracionLote').reset();
                document.getElementById('preview_facturas').style.display = 'none';
                document.getElementById('info_cliente').style.display = 'none';
                document.getElementById('btn_generar').style.display = 'none';
                document.getElementById('preview_facturas_body').innerHTML = '';
                modalLoteAbierto  = false;
                datosPreGeneracion = null;
            }
        })
        .catch(function(e){ console.error('Error:', e); });
}

// ── debounce 2 segundos ──
var _verificarContratoTimer = null;

function verificarContrato() {
    clearTimeout(_verificarContratoTimer);

    var num = document.getElementById('contrato_lote').value.trim();

    /* Ocultar info mientras el usuario sigue escribiendo */
    document.getElementById('info_cliente').style.display = 'none';
    document.getElementById('preview_facturas').style.display  = 'none';
    document.getElementById('btn_generar').style.display       = 'none';
    document.getElementById('preview_facturas_body').innerHTML = '';

    if (!num) return;

    /* Esperar 2 segundos antes de consultar */
    _verificarContratoTimer = setTimeout(function() {
        fetch('verificar_contrato.php?contrato_id=' + encodeURIComponent(num))
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var infoCliente = document.getElementById('info_cliente');
                var nomCliente  = document.getElementById('nombre_cliente');

                if (data.success && data.cliente) {
                    nomCliente.textContent =
                        data.cliente.nombre + ' ' + (data.cliente.apellidos || '');
                    infoCliente.style.display = 'block';
                } else {
                    infoCliente.style.display = 'none';
                    /* Solo mostrar error si el campo tiene al menos 5 dígitos,
                       para no molestar mientras se escribe un número parcial */
                    if (num.length >= 5 && data.error) {
                        mostrarToast(data.error, 'error');
                    }
                }
            })
            .catch(function() {
                mostrarToast('Error al verificar el contrato.', 'error');
            });
    }, 1000);
}




function preGenerarFacturas() {
    var numeroContrato   = document.getElementById('contrato_lote').value.trim();
    var cantidadFacturas = document.getElementById('cantidad_facturas').value;

    if (!numeroContrato || !cantidadFacturas) {
        mostrarToast('Por favor, complete todos los campos.', 'warning');
        return;
    }

    if (parseInt(cantidadFacturas) > 12) {
        mostrarToast('La cantidad máxima de facturas es 12.', 'warning');
        return;
    }

    /* pre_generar_facturas.php espera la clave "contrato_id", NO "contrato" */
    fetch('pre_generar_facturas.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            contrato_id: numeroContrato,
            cantidad:    parseInt(cantidadFacturas)
        })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.error) {
            mostrarToast(data.error, 'error');
            return;
        }

        var tbody = document.getElementById('preview_facturas_body');
        tbody.innerHTML = '';

        (data.facturas || []).forEach(function(f) {
            tbody.innerHTML +=
                '<tr>' +
                '<td><span style="font-family:monospace;font-weight:700;color:var(--accent);">' + f.contrato + '</span></td>' +
                '<td>' + f.mes + '</td>' +
                '<td><strong>RD$' + parseFloat(f.monto).toFixed(2) + '</strong></td>' +
                '<td>' + f.cuota + '</td>' +
                '</tr>';
        });

        document.getElementById('preview_facturas').style.display = 'block';
        document.getElementById('btn_generar').style.display      = 'inline-flex';
        datosPreGeneracion = data;
    })
    .catch(function(e) {
        console.error('Error en pre-generación:', e);
        mostrarToast('Error al pre-generar las facturas.', 'error');
    });
}

function generarFacturasLote() {
    if (!datosPreGeneracion) {
        mostrarToast('No hay datos para generar facturas.', 'error'); return;
    }
    var progress = document.getElementById('progreso_generacion');
    var bar      = document.getElementById('progressBar');
    progress.style.display = 'block';
    bar.style.width = '30%';

    fetch('generar_facturas_lote.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(datosPreGeneracion)
    })
    .then(function(r){ return r.json(); })
    .then(function(data){
        bar.style.width = '100%';
        if (data.error) { mostrarToast(data.error, 'error'); progress.style.display = 'none'; return; }
        document.getElementById('confirmacionGeneracionModal').classList.add('open');
        setTimeout(function(){ window.location.reload(); }, 2500);
    })
    .catch(function(e){
        console.error('Error:', e);
        mostrarToast('Error al generar las facturas.', 'error');
        progress.style.display = 'none';
    });
}

function cerrarConfirmacionGeneracion() {
    document.getElementById('confirmacionGeneracionModal').classList.remove('open');
    cerrarModalGeneracionLote();
}

function registrarBloqueoModal() {
    fetch('bloquear_modal_lote.php', { method:'POST' })
        .catch(function(e){ console.error('Error al registrar bloqueo:', e); });
}
function liberarBloqueoModal() {
    fetch('liberar_modal_lote.php', { method:'POST' })
        .catch(function(e){ console.error('Error al liberar bloqueo:', e); });
}

/* ═══════════════════════════════════════════════════════════
   VERIFICAR FACTURAS INCOMPLETAS (para pago)
═══════════════════════════════════════════════════════════ */
async function verificarFacturasIncompletas(contratoId) {
    try {
        var response = await fetch('verificar_facturas.php?contrato_id=' + contratoId);
        var data     = await response.json();
        if (data.tiene_incompletas) {
            mostrarToast('Debe pagar primero la factura incompleta.', 'error', 8000);
            return false;
        }
        return true;
    } catch(e) {
        console.error('Error:', e);
        return false;
    }
}

/* ═══════════════════════════════════════════════════════════
   FORMATEO MESES
═══════════════════════════════════════════════════════════ */
function formatearMes(mesFactura) {
    if (!mesFactura) return '';
    var meses = {
        '01':'Ene','02':'Feb','03':'Mar','04':'Abr','05':'May','06':'Jun',
        '07':'Jul','08':'Ago','09':'Sep','10':'Oct','11':'Nov','12':'Dic'
    };
    var partes = mesFactura.split('/');
    return (meses[partes[0]] || partes[0]) + '/' + partes[1];
}

function formatearContrato(num) {
    if (!num) return '';
    return num.toString().padStart(5, '0');
}

/* ═══════════════════════════════════════════════════════════
   CERRAR MODALES CON ESC
═══════════════════════════════════════════════════════════ */
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal-overlay.open').forEach(function(m){
            m.classList.remove('open');
        });
        document.body.style.overflow = '';
    }
});

/* Cerrar al clic fuera */
document.querySelectorAll('.modal-overlay').forEach(function(overlay) {
    overlay.addEventListener('click', function(e) {
        if (e.target === overlay) {
            overlay.classList.remove('open');
            document.body.style.overflow = '';
        }
    });
});

/* ═══════════════════════════════════════════════════════════
   MOSTRAR TOAST (Fallback si footer no lo provee)
═══════════════════════════════════════════════════════════ */
if (typeof mostrarToast === 'undefined') {
    function mostrarToast(msg, tipo, dur) {
        dur = dur || 4000;
        var colores = {
            success: 'linear-gradient(135deg,#2E7D32,#388E3C)',
            error:   'linear-gradient(135deg,#C62828,#D32F2F)',
            warning: 'linear-gradient(135deg,#F57F17,#F9A825)',
            info:    'linear-gradient(135deg,#1565C0,#2196F3)'
        };
        if (typeof Toastify !== 'undefined') {
            Toastify({
                text:     msg,
                duration: dur,
                close:    true,
                gravity:  'top',
                position: 'right',
                style: { background: colores[tipo] || colores.info },
                stopOnFocus: true
            }).showToast();
        } else {
            alert(msg);
        }
    }
}
</script>

<!-- MODAL INFORMATIVO — Facturas Anteriores Pendientes -->
<div id="modalFacturasPendientes" style="display:none;position:fixed;inset:0;z-index:9999;
     background:rgba(15,23,42,.55);backdrop-filter:blur(3px);
     align-items:center;justify-content:center;">
  <div style="background:#fff;border-radius:14px;width:100%;max-width:640px;
              max-height:88vh;overflow:hidden;display:flex;flex-direction:column;
              box-shadow:0 20px 60px rgba(0,0,0,.25);">
    <!-- Cabecera -->
    <div style="display:flex;align-items:center;gap:14px;padding:18px 20px 14px;
                background:linear-gradient(135deg,#FEF3C7,#FDE68A);
                border-bottom:1px solid #FCD34D;position:relative;">
      <div style="width:44px;height:44px;border-radius:50%;background:#F59E0B;
                  display:flex;align-items:center;justify-content:center;
                  color:#fff;font-size:20px;flex-shrink:0;">
        <i class="fas fa-exclamation-triangle"></i>
      </div>
      <div>
        <h3 style="margin:0;font-size:17px;font-weight:700;color:#92400E;">Pago No Permitido</h3>
        <p style="margin:3px 0 0;font-size:12px;color:#B45309;">
          Este contrato tiene facturas anteriores con saldo pendiente
        </p>
      </div>
      <button onclick="cerrarModalFacturasPendientes()"
              style="position:absolute;top:12px;right:14px;background:none;border:none;
                     font-size:22px;cursor:pointer;color:#92400E;padding:4px 8px;
                     border-radius:6px;" title="Cerrar">&times;</button>
    </div>
    <!-- Cuerpo -->
    <div style="padding:18px 20px;overflow-y:auto;flex:1;">
      <div style="display:flex;gap:10px;align-items:flex-start;background:#FFF7ED;
                  border:1px solid #FED7AA;border-radius:8px;padding:12px 14px;
                  font-size:13px;color:#9A3412;margin-bottom:14px;">
        <i class="fas fa-info-circle" style="color:#EA580C;margin-top:1px;flex-shrink:0;"></i>
        <span id="fp-mensaje-intro">Para pagar esta factura primero debe saldar las facturas pendientes anteriores:</span>
      </div>
      <div style="overflow-x:auto;border-radius:8px;border:1px solid #E2E8F0;">
        <table style="width:100%;border-collapse:collapse;font-size:13px;">
          <thead>
            <tr style="background:#F1F5F9;">
              <th style="padding:9px 12px;text-align:left;font-weight:600;color:#475569;
                         border-bottom:1px solid #E2E8F0;">Factura</th>
              <th style="padding:9px 12px;text-align:left;font-weight:600;color:#475569;
                         border-bottom:1px solid #E2E8F0;">Período</th>
              <th style="padding:9px 12px;text-align:left;font-weight:600;color:#475569;
                         border-bottom:1px solid #E2E8F0;">Monto</th>
              <th style="padding:9px 12px;text-align:left;font-weight:600;color:#475569;
                         border-bottom:1px solid #E2E8F0;">Abonado</th>
              <th style="padding:9px 12px;text-align:left;font-weight:600;color:#475569;
                         border-bottom:1px solid #E2E8F0;">Pendiente</th>
              <th style="padding:9px 12px;text-align:left;font-weight:600;color:#475569;
                         border-bottom:1px solid #E2E8F0;">Estado</th>
            </tr>
          </thead>
          <tbody id="fp-tabla-body"></tbody>
          <tfoot>
            <tr style="background:#F8FAFC;">
              <td colspan="4" style="padding:10px 12px;text-align:right;font-weight:700;
                                     color:#334155;">Total a Saldar:</td>
              <td id="fp-total-pendiente" style="padding:10px 12px;font-weight:700;
                                                  color:#DC2626;"></td>
              <td></td>
            </tr>
          </tfoot>
        </table>
      </div>
      <p style="margin-top:12px;font-size:12px;color:#64748B;">
        <i class="fas fa-hand-point-right" style="color:#F59E0B;"></i>
        Haga clic en el número de factura para ir a registrar el pago correspondiente.
      </p>
    </div>
    <!-- Pie -->
    <div style="padding:14px 20px;border-top:1px solid #E2E8F0;
                display:flex;justify-content:flex-end;background:#F8FAFC;">
      <button onclick="cerrarModalFacturasPendientes()"
              style="display:inline-flex;align-items:center;gap:7px;padding:9px 20px;
                     background:#475569;color:#fff;border:none;border-radius:8px;
                     font-size:13px;font-weight:600;cursor:pointer;">
        <i class="fas fa-times"></i> Entendido, Cerrar
      </button>
    </div>
  </div>
</div>
<style>
.fp-link-factura{color:#1D4ED8;text-decoration:none;font-weight:600;}
.fp-link-factura:hover{text-decoration:underline;}
.badge-estado-fp{display:inline-block;padding:2px 8px;border-radius:20px;
                  font-size:11px;font-weight:600;text-transform:capitalize;}
.badge-pendiente-fp{background:#FEF3C7;color:#92400E;}
.badge-incompleta-fp{background:#DBEAFE;color:#1E40AF;}
.badge-vencida-fp{background:#FEE2E2;color:#991B1B;}
</style>
<script>
document.addEventListener('DOMContentLoaded',function(){
    var modal=document.getElementById('modalFacturasPendientes');
    if(modal){
        modal.addEventListener('click',function(e){
            if(e.target===modal) cerrarModalFacturasPendientes();
        });
    }
});
document.addEventListener('keydown',function(e){
    if(e.key==='Escape') cerrarModalFacturasPendientes();
});
</script>

<?php require_once 'footer.php'; ?>