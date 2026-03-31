<?php
/* ============================================================
   pagos.php — Gestión de Pagos y Cobros
   Sistema ORTHIIS — Seguros de Vida
   ============================================================ */
require_once 'config.php';
verificarSesion();

/* ── Helper URL paginador ─────────────────────────────────── */
function buildPagoUrl(int $p, string $qs): string {
    return 'pagos.php?pagina=' . $p . ($qs ? '&' . $qs : '');
}

/* ── Filtros ─────────────────────────────────────────────── */
$where  = "p.estado != 'eliminado'";
$params = [];

$buscar       = trim($_GET['buscar']      ?? '');
$f_metodo     = trim($_GET['metodo_pago'] ?? '');
$f_tipo       = trim($_GET['tipo_pago']   ?? '');
$f_cobrador   = trim($_GET['cobrador_id'] ?? '');
$f_estado     = trim($_GET['estado_pago'] ?? '');
$f_fecha_desde= trim($_GET['fecha_desde'] ?? '');
$f_fecha_hasta= trim($_GET['fecha_hasta'] ?? '');

if ($buscar !== '') {
    $t = "%$buscar%";
    $where   .= " AND (c.numero_contrato LIKE ? OR f.numero_factura LIKE ?
                   OR cl.nombre LIKE ? OR cl.apellidos LIKE ?
                   OR CONCAT(cl.nombre,' ',cl.apellidos) LIKE ?)";
    array_push($params, $t, $t, $t, $t, $t);
}
if ($f_metodo  !== '') { $where .= " AND p.metodo_pago = ?";  $params[] = $f_metodo; }
if ($f_tipo    !== '') { $where .= " AND p.tipo_pago   = ?";  $params[] = $f_tipo;   }
if ($f_cobrador!== '') { $where .= " AND p.cobrador_id = ?";  $params[] = (int)$f_cobrador; }
if ($f_estado  !== '') { $where .= " AND p.estado      = ?";  $params[] = $f_estado; }
if ($f_fecha_desde !== '') {
    $where   .= " AND p.fecha_pago >= ?";
    $params[] = $f_fecha_desde . ' 00:00:00';
}
if ($f_fecha_hasta !== '') {
    $where   .= " AND p.fecha_pago <= ?";
    $params[] = $f_fecha_hasta . ' 23:59:59';
}

/* ── Paginación ───────────────────────────────────────────── */
$por_pagina   = isset($_COOKIE['pagos_por_pagina']) ? (int)$_COOKIE['pagos_por_pagina'] : 50;
$pagina_actual = max(1, (int)($_GET['pagina'] ?? 1));
$offset        = ($pagina_actual - 1) * $por_pagina;

/* total */
$stmtCnt = $conn->prepare("
    SELECT COUNT(*) AS total
    FROM pagos p
    JOIN facturas  f  ON p.factura_id  = f.id
    JOIN contratos c  ON f.contrato_id = c.id
    JOIN clientes  cl ON c.cliente_id  = cl.id
    WHERE $where
");
$stmtCnt->execute($params);
$total_registros = (int)$stmtCnt->fetchColumn();
$total_paginas   = max(1, ceil($total_registros / $por_pagina));

/* listado */
$stmtList = $conn->prepare("
    SELECT p.*,
           f.numero_factura,
           f.mes_factura,
           c.numero_contrato,
           cl.nombre       AS cliente_nombre,
           cl.apellidos    AS cliente_apellidos,
           co.nombre_completo AS cobrador_nombre
    FROM pagos p
    JOIN facturas  f  ON p.factura_id  = f.id
    JOIN contratos c  ON f.contrato_id = c.id
    JOIN clientes  cl ON c.cliente_id  = cl.id
    LEFT JOIN cobradores co ON p.cobrador_id = co.id
    WHERE $where
    ORDER BY p.fecha_pago DESC, p.id DESC
    LIMIT ? OFFSET ?
");
$allP = array_merge($params, [$por_pagina, $offset]);
foreach ($allP as $i => $v) {
    $stmtList->bindValue($i + 1, $v, is_int($v) ? PDO::PARAM_INT : PDO::PARAM_STR);
}
$stmtList->execute();
$pagos = $stmtList->fetchAll();

/* ── KPI Totales filtro actual ─────────────────────────────── */
$stmtKpi = $conn->prepare("
    SELECT
        COALESCE(SUM(CASE WHEN p.estado='procesado' THEN p.monto ELSE 0 END), 0) AS total_recaudado,
        COALESCE(SUM(CASE WHEN p.estado='anulado'   THEN p.monto ELSE 0 END), 0) AS total_anulado,
        COUNT(CASE WHEN p.estado='procesado' THEN 1 END)  AS cant_procesados,
        COUNT(CASE WHEN p.estado='anulado'   THEN 1 END)  AS cant_anulados,
        COUNT(DISTINCT CASE WHEN p.estado='procesado' THEN cl.id END) AS clientes_unicos,
        COUNT(DISTINCT CASE WHEN p.estado='procesado' THEN f.id END)  AS facturas_unicas
    FROM pagos p
    JOIN facturas  f  ON p.factura_id  = f.id
    JOIN contratos c  ON f.contrato_id = c.id
    JOIN clientes  cl ON c.cliente_id  = cl.id
    WHERE $where
");
$stmtKpi->execute($params);
$kpi = $stmtKpi->fetch(PDO::FETCH_ASSOC);

/* ── Total del mes actual (siempre) ────────────────────────── */
$stmtMes = $conn->prepare("
    SELECT COALESCE(SUM(monto),0) AS total_mes,
           COUNT(*) AS cant_mes
    FROM pagos
    WHERE MONTH(fecha_pago) = MONTH(CURRENT_DATE())
      AND YEAR(fecha_pago)  = YEAR(CURRENT_DATE())
      AND estado = 'procesado'
");
$stmtMes->execute();
$kpiMes = $stmtMes->fetch(PDO::FETCH_ASSOC);

/* ── Cobradores activos (para filtro) ─────────────────────── */
$cobradores = $conn->query(
    "SELECT id, nombre_completo FROM cobradores WHERE estado='activo' ORDER BY nombre_completo"
)->fetchAll();

/* ── URL params para paginador ────────────────────────────── */
$params_url_arr = [];
foreach (['buscar','metodo_pago','tipo_pago','cobrador_id','estado_pago','fecha_desde','fecha_hasta'] as $k) {
    if (!empty($_GET[$k])) $params_url_arr[$k] = $_GET[$k];
}
$params_url = http_build_query($params_url_arr);

require_once 'header.php';
?>
<!-- ============================================================
     ESTILOS ESPECÍFICOS — PAGOS
     ============================================================ -->
<style>
/* ── KPI CARDS ── */
.kpi-pagos {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 18px;
    margin-bottom: 24px;
}
@media(max-width:1100px){ .kpi-pagos { grid-template-columns: repeat(2,1fr); } }
@media(max-width:560px) { .kpi-pagos { grid-template-columns: 1fr; } }

.kpi-pagos .kpi-card {
    border-radius: var(--radius);
    padding: 22px 22px 18px;
    position: relative;
    overflow: hidden;
    box-shadow: var(--shadow);
    transition: var(--transition);
    color: white;
    cursor: default;
}
.kpi-pagos .kpi-card:hover { transform: translateY(-3px); box-shadow: var(--shadow-md); }
.kpi-pagos .kpi-card::before {
    content:''; position:absolute; top:0; right:0;
    width:80px; height:80px;
    border-radius:0 var(--radius) 0 100%;
    opacity:.15; background:white;
}
.kpi-pagos .kpi-card.blue   { background: linear-gradient(135deg,#1565C0,#1976D2); }
.kpi-pagos .kpi-card.green  { background: linear-gradient(135deg,#1B5E20,#2E7D32); }
.kpi-pagos .kpi-card.amber  { background: linear-gradient(135deg,#E65100,#F57F17); }
.kpi-pagos .kpi-card.teal   { background: linear-gradient(135deg,#00695C,#00897B); }

.kpi-pagos .kpi-label {
    font-size:11px; font-weight:600; color:rgba(255,255,255,.80);
    text-transform:uppercase; letter-spacing:.8px; margin-bottom:10px;
}
.kpi-pagos .kpi-top {
    display:flex; align-items:flex-start; justify-content:space-between; margin-bottom:6px;
}
.kpi-pagos .kpi-value {
    font-size:26px; font-weight:800; color:white; line-height:1; margin-bottom:4px;
}
.kpi-pagos .kpi-value.lg { font-size:20px; }
.kpi-pagos .kpi-sub  { font-size:11px; color:rgba(255,255,255,.70); font-weight:500; }
.kpi-pagos .kpi-icon {
    width:48px; height:48px;
    background:rgba(255,255,255,.18); border-radius:var(--radius-sm);
    display:flex; align-items:center; justify-content:center;
    font-size:20px; color:white; flex-shrink:0;
}
.kpi-pagos .kpi-footer {
    margin-top:14px; padding-top:12px;
    border-top:1px solid rgba(255,255,255,.15);
    font-size:11.5px; color:rgba(255,255,255,.80); font-weight:600;
    display:flex; align-items:center; gap:6px;
}

/* ── Page Header ── */
.page-header {
    display:flex; align-items:flex-start; justify-content:space-between;
    flex-wrap:wrap; gap:14px; margin-bottom:24px;
}
.page-title   { font-size:22px; font-weight:700; color:var(--gray-800); margin:0 0 4px; }
.page-subtitle{ font-size:13px; color:var(--gray-500); margin:0; }

/* ── Action Bar ── */
.action-bar {
    display:flex; align-items:center; justify-content:space-between;
    gap:12px; flex-wrap:wrap; margin-bottom:16px;
}
.action-bar-left, .action-bar-right { display:flex; gap:10px; flex-wrap:wrap; }

/* ── Filter Bar ── */
.filter-bar {
    background:var(--white); border:1px solid var(--gray-200);
    border-radius:var(--radius); padding:14px 18px;
    display:flex; align-items:center; gap:12px;
    flex-wrap:wrap; margin-bottom:20px;
    box-shadow:var(--shadow-sm);
}
.search-wrap {
    position:relative; flex:1; min-width:220px; max-width:340px;
}
.search-wrap .si {
    position:absolute; left:12px; top:50%; transform:translateY(-50%);
    color:var(--gray-400); font-size:13px; pointer-events:none;
}
.search-wrap input {
    width:100%; padding:9px 12px 9px 36px;
    border:1.5px solid var(--gray-200); border-radius:var(--radius-sm);
    font-size:13px; font-family:var(--font); color:var(--gray-800);
    background:var(--gray-50); transition:var(--transition);
}
.search-wrap input:focus {
    outline:none; border-color:var(--accent);
    background:white; box-shadow:0 0 0 3px rgba(33,150,243,.10);
}
.filter-select {
    padding:9px 12px; border:1.5px solid var(--gray-200);
    border-radius:var(--radius-sm); font-size:13px; font-family:var(--font);
    color:var(--gray-700); background:var(--gray-50);
    cursor:pointer; transition:var(--transition);
}
.filter-select:focus { outline:none; border-color:var(--accent); background:white; }

/* ── Filtros avanzados ── */
.advanced-filters {
    background:var(--white); border:1px solid var(--gray-200);
    border-radius:var(--radius); padding:16px 20px;
    margin-bottom:16px; box-shadow:var(--shadow-sm);
}
.filter-grid {
    display:grid; grid-template-columns:repeat(auto-fill,minmax(200px,1fr)); gap:14px;
}
.form-label { display:block; font-size:11px; font-weight:600; color:var(--gray-600);
    text-transform:uppercase; letter-spacing:.5px; margin-bottom:5px; }
.form-control {
    width:100%; padding:9px 12px; border:1.5px solid var(--gray-200);
    border-radius:var(--radius-sm); font-size:13px; font-family:var(--font);
    color:var(--gray-800); background:var(--white); transition:var(--transition);
}
.form-control:focus { outline:none; border-color:var(--accent);
    box-shadow:0 0 0 3px rgba(33,150,243,.10); }

/* ── Buttons ── */
.btn {
    display:inline-flex; align-items:center; gap:7px;
    padding:9px 16px; border-radius:var(--radius-sm); border:none;
    font-size:13px; font-weight:600; font-family:var(--font);
    cursor:pointer; transition:var(--transition);
    text-decoration:none; white-space:nowrap;
}
.btn-primary   { background:var(--accent); color:white; }
.btn-primary:hover   { background:#1565C0; color:white; }
.btn-secondary { background:var(--gray-200); color:var(--gray-700); }
.btn-secondary:hover { background:var(--gray-300); }
.btn-success   { background:#DCFCE7; color:#15803D; }
.btn-success:hover   { background:#15803D; color:white; }
.btn-danger    { background:#FEE2E2; color:#DC2626; }
.btn-danger:hover    { background:#DC2626; color:white; }
.btn-info      { background:#E0F2FE; color:#0369A1; }
.btn-info:hover      { background:#0284C7; color:white; }
.btn-warning   { background:#FEF3C7; color:#92400E; }
.btn-warning:hover   { background:#D97706; color:white; }
.btn-sm  { padding:6px 12px; font-size:12px; }

/* ── Card ── */
.card {
    background:var(--white); border-radius:var(--radius);
    box-shadow:var(--shadow-sm); border:1px solid var(--gray-200); overflow:hidden;
}
.card-header {
    padding:16px 20px; border-bottom:1px solid var(--gray-200);
    display:flex; align-items:center; justify-content:space-between; background:var(--white);
}
.card-title    { font-size:15px; font-weight:700; color:var(--gray-800); }
.card-subtitle { font-size:12px; color:var(--gray-500); margin-top:2px; }

/* ── Tabla ── */
.data-table {
    width:100%; border-collapse:collapse; font-size:13px;
}
.data-table thead th {
    background:var(--gray-50); padding:11px 14px;
    text-align:left; font-weight:600; color:var(--gray-600);
    font-size:11.5px; text-transform:uppercase; letter-spacing:.5px;
    border-bottom:2px solid var(--gray-200); white-space:nowrap;
}
.data-table tbody td {
    padding:13px 14px; border-bottom:1px solid var(--gray-100);
    color:var(--gray-700); vertical-align:middle;
}
.data-table tbody tr:last-child td { border-bottom:none; }
.data-table tbody tr:hover { background:var(--gray-50); }

/* ── Badges ── */
.badge {
    display:inline-flex; align-items:center; gap:4px;
    padding:3px 10px; border-radius:20px;
    font-size:11px; font-weight:600; white-space:nowrap;
}
.badge-procesado { background:#DCFCE7; color:#166534; }
.badge-anulado   { background:#FEE2E2; color:#991B1B; }
.badge-total     { background:#DCFCE7; color:#166534; }
.badge-abono     { background:#DBEAFE; color:#1E40AF; }
.badge-efectivo     { background:#FEF3C7; color:#92400E; }
.badge-transferencia{ background:#E0F2FE; color:#0369A1; }
.badge-cheque       { background:#F5F3FF; color:#7C3AED; }
.badge-tarjeta      { background:#FCE7F3; color:#BE185D; }

/* ── Botones de tabla ── */
.btn-tbl {
    display:inline-flex; align-items:center; justify-content:center;
    width:32px; height:32px; border-radius:var(--radius-sm);
    border:none; cursor:pointer; transition:var(--transition); font-size:13px;
    text-decoration:none;
}
.btn-tbl.view    { background:#E0F2FE; color:#0369A1; }
.btn-tbl.view:hover  { background:#0284C7; color:white; }
.btn-tbl.print   { background:#F5F3FF; color:#7C3AED; }
.btn-tbl.print:hover { background:#7C3AED; color:white; }
.btn-tbl.del     { background:#FEE2E2; color:#DC2626; }
.btn-tbl.del:hover   { background:#DC2626; color:white; }
.btns-wrap { display:flex; align-items:center; gap:6px; }

/* ── Monto cell ── */
.monto-cell { font-weight:700; font-family:monospace; color:var(--gray-800); font-size:13px; }
.monto-cell.anulado { color:var(--gray-400); text-decoration:line-through; }

/* ── Client info ── */
.client-name { font-weight:600; color:var(--gray-800); }
.client-sub  { font-size:11px; color:var(--gray-500); margin-top:2px; }

/* ── Factura num ── */
.fact-num {
    display:inline-block; font-family:monospace; font-weight:700;
    font-size:13px; color:var(--accent); letter-spacing:.5px;
    background:#EFF6FF; padding:2px 8px; border-radius:6px;
}

/* ── Paginador ── */
.paginador-wrap {
    display:flex; align-items:center; justify-content:space-between;
    flex-wrap:wrap; gap:12px; padding:16px 20px;
    border-top:1px solid var(--gray-200); background:var(--white);
}
.paginador-info { font-size:13px; color:var(--gray-500); }
.paginador-info strong { color:var(--gray-700); }
.paginador-pages { display:flex; align-items:center; gap:4px; flex-wrap:wrap; }
.pag-btn {
    display:inline-flex; align-items:center; justify-content:center;
    min-width:36px; height:36px; padding:0 10px;
    border:1.5px solid var(--gray-200); border-radius:var(--radius-sm);
    font-size:13px; font-weight:600; color:var(--gray-600);
    background:var(--white); cursor:pointer;
    text-decoration:none; transition:var(--transition);
}
.pag-btn:hover:not(.disabled):not(.active) {
    border-color:var(--accent); color:var(--accent); background:#EFF6FF;
}
.pag-btn.active {
    background:var(--accent); border-color:var(--accent);
    color:white; cursor:default;
}
.pag-btn.disabled {
    opacity:.35; cursor:not-allowed; pointer-events:none;
}
.pag-btn.ellipsis { border-color:transparent; cursor:default; }
.paginador-rpp {
    display:flex; align-items:center; gap:8px;
    font-size:13px; color:var(--gray-500);
}
.paginador-rpp select {
    padding:6px 10px; border:1.5px solid var(--gray-200);
    border-radius:var(--radius-sm); font-size:13px; font-family:var(--font);
    color:var(--gray-700); background:var(--white); cursor:pointer;
}
.paginador-rpp select:focus { outline:none; border-color:var(--accent); }

/* ── Alert global ── */
.alert-global {
    padding:13px 18px; border-radius:var(--radius-sm); margin-bottom:16px;
    font-size:13px; font-weight:600; display:flex; align-items:center; gap:10px;
}
.alert-global.success { background:#DCFCE7; border:1px solid #86EFAC; color:#166534; }
.alert-global.danger  { background:#FEE2E2; border:1px solid #FCA5A5; color:#991B1B; }

/* ── Empty state ── */
.empty-state { text-align:center; padding:60px 20px; }
.empty-state i { font-size:48px; opacity:.25; display:block; margin-bottom:12px; color:var(--gray-500); }
.empty-state p { font-size:14px; font-weight:600; color:var(--gray-500); margin:0 0 5px; }
.empty-state small { font-size:12px; color:var(--gray-400); }

/* ── Fade in ── */
.fade-in { animation:fadeIn .4s ease both; }
.delay-1 { animation-delay:.10s; }
.delay-2 { animation-delay:.20s; }
@keyframes fadeIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
</style>

<!-- ============================================================
     PAGE HEADER
     ============================================================ -->
<div class="page-header fade-in">
    <div>
        <div class="page-title">
            <i class="fas fa-money-bill-wave" style="color:var(--accent);margin-right:8px;"></i>
            Pagos y Cobros
        </div>
        <div class="page-subtitle">
            <?php echo number_format($total_registros); ?> pago<?php echo $total_registros !== 1 ? 's' : ''; ?>
            <?php echo (!empty($buscar) || !empty($f_metodo) || !empty($f_cobrador) || !empty($f_fecha_desde))
                ? 'con filtros aplicados' : 'registrados en el sistema'; ?>
        </div>
    </div>
</div>

<!-- ============================================================
     KPI CARDS
     ============================================================ -->
<div class="kpi-pagos fade-in delay-1">

    <div class="kpi-card blue">
        <div class="kpi-label">Total Recaudado</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value lg">RD$<?php echo number_format($kpi['total_recaudado'],2); ?></div>
                <div class="kpi-sub"><?php echo number_format($kpi['cant_procesados']); ?> pago<?php echo $kpi['cant_procesados']!=1?'s':''; ?> procesado<?php echo $kpi['cant_procesados']!=1?'s':''; ?></div>
            </div>
            <div class="kpi-icon"><i class="fas fa-dollar-sign"></i></div>
        </div>
        <div class="kpi-footer">
            <i class="fas fa-filter"></i> Según filtros aplicados
        </div>
    </div>

    <div class="kpi-card green">
        <div class="kpi-label">Cobrado Este Mes</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value lg">RD$<?php echo number_format($kpiMes['total_mes'],2); ?></div>
                <div class="kpi-sub"><?php echo number_format($kpiMes['cant_mes']); ?> pago<?php echo $kpiMes['cant_mes']!=1?'s':''; ?> en <?php echo date('F Y'); ?></div>
            </div>
            <div class="kpi-icon"><i class="fas fa-calendar-check"></i></div>
        </div>
        <div class="kpi-footer">
            <i class="fas fa-clock"></i> Mes en curso
        </div>
    </div>

    <div class="kpi-card amber">
        <div class="kpi-label">Clientes Atendidos</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo number_format($kpi['clientes_unicos']); ?></div>
                <div class="kpi-sub"><?php echo number_format($kpi['facturas_unicas']); ?> factura<?php echo $kpi['facturas_unicas']!=1?'s':''; ?> pagada<?php echo $kpi['facturas_unicas']!=1?'s':''; ?></div>
            </div>
            <div class="kpi-icon"><i class="fas fa-users"></i></div>
        </div>
        <div class="kpi-footer">
            <i class="fas fa-id-card"></i> Clientes únicos
        </div>
    </div>

    <div class="kpi-card teal">
        <div class="kpi-label">Pagos Anulados</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo number_format($kpi['cant_anulados']); ?></div>
                <div class="kpi-sub">RD$<?php echo number_format($kpi['total_anulado'],2); ?> revertido</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-ban"></i></div>
        </div>
        <div class="kpi-footer">
            <i class="fas fa-rotate-left"></i> Total anulaciones
        </div>
    </div>

</div>

<!-- ============================================================
     BARRA DE FILTROS
     ============================================================ -->
<div class="filter-bar-h fade-in delay-2">
    <form method="GET" action="pagos.php" id="formFiltrosPagos">
        <div class="filter-row-fields">
            <!-- Búsqueda -->
            <div class="filter-field field-search">
                <label for="buscarPagos"><i class="fas fa-search"></i> Buscar</label>
                <div class="search-wrap-h">
                    <i class="fas fa-search search-icon-h"></i>
                    <input type="text"
                           id="buscarPagos"
                           name="buscar"
                           class="filter-input"
                           placeholder="Contrato, factura o cliente…"
                           value="<?php echo htmlspecialchars($buscar); ?>"
                           autocomplete="off">
                </div>
            </div>
            <!-- Método de Pago -->
            <div class="filter-field field-select">
                <label for="metodoPago"><i class="fas fa-credit-card"></i> Método</label>
                <select id="metodoPago" name="metodo_pago" class="filter-select-h" onchange="this.form.submit()">
                    <option value="">Todos los métodos</option>
                    <option value="efectivo"      <?php echo $f_metodo==='efectivo'?'selected':''; ?>>Efectivo</option>
                    <option value="transferencia" <?php echo $f_metodo==='transferencia'?'selected':''; ?>>Transferencia</option>
                    <option value="cheque"        <?php echo $f_metodo==='cheque'?'selected':''; ?>>Cheque</option>
                    <option value="tarjeta"       <?php echo $f_metodo==='tarjeta'?'selected':''; ?>>Tarjeta</option>
                </select>
            </div>
            <!-- Tipo de Pago -->
            <div class="filter-field field-select">
                <label for="tipoPago"><i class="fas fa-tag"></i> Tipo</label>
                <select id="tipoPago" name="tipo_pago" class="filter-select-h" onchange="this.form.submit()">
                    <option value="">Todos los tipos</option>
                    <option value="total" <?php echo $f_tipo==='total'?'selected':''; ?>>Total</option>
                    <option value="abono" <?php echo $f_tipo==='abono'?'selected':''; ?>>Abono</option>
                </select>
            </div>
            <!-- Estado -->
            <div class="filter-field field-select">
                <label for="estadoPago"><i class="fas fa-circle-half-stroke"></i> Estado</label>
                <select id="estadoPago" name="estado_pago" class="filter-select-h" onchange="this.form.submit()">
                    <option value="">Todos</option>
                    <option value="procesado" <?php echo $f_estado==='procesado'?'selected':''; ?>>Procesado</option>
                    <option value="anulado"   <?php echo $f_estado==='anulado'?'selected':''; ?>>Anulado</option>
                </select>
            </div>
            <!-- Cobrador -->
            <div class="filter-field field-select">
                <label for="cobradorPago"><i class="fas fa-motorcycle"></i> Cobrador</label>
                <select id="cobradorPago" name="cobrador_id" class="filter-select-h" onchange="this.form.submit()">
                    <option value="">Todos</option>
                    <?php foreach ($cobradores as $cob): ?>
                        <option value="<?php echo $cob['id']; ?>"
                            <?php echo (string)$f_cobrador===(string)$cob['id']?'selected':''; ?>>
                            <?php echo htmlspecialchars($cob['nombre_completo']); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <!-- Fecha Desde -->
            <div class="filter-field field-date">
                <label for="fechaDesdePagos"><i class="fas fa-calendar-days"></i> Desde</label>
                <input type="date"
                       id="fechaDesdePagos"
                       name="fecha_desde"
                       class="filter-select-h"
                       value="<?php echo htmlspecialchars($f_fecha_desde); ?>">
            </div>
            <!-- Fecha Hasta -->
            <div class="filter-field field-date">
                <label for="fechaHastaPagos"><i class="fas fa-calendar-check"></i> Hasta</label>
                <input type="date"
                       id="fechaHastaPagos"
                       name="fecha_hasta"
                       class="filter-select-h"
                       value="<?php echo htmlspecialchars($f_fecha_hasta); ?>">
            </div>
        </div>
        <div class="filter-row-btns">
            <button type="submit" class="btn btn-primary btn-sm">
                <i class="fas fa-search"></i> Buscar
            </button>
            <?php if (!empty($buscar)||!empty($f_metodo)||!empty($f_estado)||!empty($f_cobrador)||!empty($f_tipo)||!empty($f_fecha_desde)||!empty($f_fecha_hasta)): ?>
                <a href="pagos.php" class="btn btn-secondary btn-sm">
                    <i class="fas fa-times"></i> Limpiar
                </a>
            <?php endif; ?>
            <div class="filter-results-info">
                <?php echo number_format($total_registros); ?> pago<?php echo $total_registros !== 1 ? 's' : ''; ?>
            </div>
        </div>
    </form>
</div>

<!-- ============================================================
     TABLA DE PAGOS
     ============================================================ -->
<div class="card fade-in delay-2">
    <div class="card-header">
        <div>
            <div class="card-title">
                <i class="fas fa-list-check" style="color:var(--accent);margin-right:6px;"></i>
                Historial de Pagos
            </div>
            <div class="card-subtitle">
                Mostrando
                <?php echo $total_registros > 0 ? min($offset+1,$total_registros) : 0; ?>–<?php echo min($offset+$por_pagina,$total_registros); ?>
                de <?php echo number_format($total_registros); ?> registros
            </div>
        </div>
        <div style="display:flex;gap:8px;align-items:center;">
            <span style="font-size:12px;color:var(--gray-500);">
                <i class="fas fa-coins" style="color:var(--accent);"></i>
                Total filtro:
                <strong style="color:var(--gray-800);">RD$<?php echo number_format($kpi['total_recaudado'],2); ?></strong>
            </span>
        </div>
    </div>

    <div style="overflow-x:auto;">
        <table class="data-table" id="tablaPagos">
            <thead>
                <tr>
                    <th>Fecha</th>
                    <th>Factura</th>
                    <th>Contrato</th>
                    <th>Cliente</th>
                    <th>Monto</th>
                    <th>Método</th>
                    <th>Tipo</th>
                    <th>Cobrador</th>
                    <th>Referencia</th>
                    <th>Estado</th>
                    <th style="text-align:center;">Acciones</th>
                </tr>
            </thead>
            <tbody>
            <?php if (!empty($pagos)): ?>
                <?php foreach ($pagos as $pago): ?>
                <tr id="fila-pago-<?php echo $pago['id']; ?>">
                    <td style="white-space:nowrap;">
                        <div style="font-weight:600;font-size:13px;color:var(--gray-800);">
                            <?php echo date('d/m/Y', strtotime($pago['fecha_pago'])); ?>
                        </div>
                        <div style="font-size:11px;color:var(--gray-500);">
                            <?php echo date('H:i', strtotime($pago['fecha_pago'])); ?>
                        </div>
                    </td>
                    <td>
                        <a href="ver_factura.php?id=<?php echo $pago['factura_id']; ?>"
                           class="fact-num" title="Ver factura">
                            <?php echo htmlspecialchars($pago['numero_factura']); ?>
                        </a>
                        <?php if ($pago['mes_factura']): ?>
                        <div style="font-size:11px;color:var(--gray-500);margin-top:2px;">
                            <?php echo htmlspecialchars($pago['mes_factura']); ?>
                        </div>
                        <?php endif; ?>
                    </td>
                    <td>
                        <span style="font-family:monospace;font-weight:600;font-size:12px;color:var(--gray-700);">
                            <?php echo str_pad($pago['numero_contrato'],5,'0',STR_PAD_LEFT); ?>
                        </span>
                    </td>
                    <td>
                        <div class="client-name">
                            <?php echo htmlspecialchars($pago['cliente_nombre'].' '.$pago['cliente_apellidos']); ?>
                        </div>
                    </td>
                    <td>
                        <span class="monto-cell <?php echo $pago['estado']==='anulado'?'anulado':''; ?>">
                            RD$<?php echo number_format($pago['monto'],2); ?>
                        </span>
                    </td>
                    <td>
                        <?php
                        $metIcon = match($pago['metodo_pago']) {
                            'efectivo'      => 'fa-money-bill-wave',
                            'transferencia' => 'fa-building-columns',
                            'cheque'        => 'fa-money-check',
                            'tarjeta'       => 'fa-credit-card',
                            default         => 'fa-circle-dot',
                        };
                        $metCls = 'badge-'.$pago['metodo_pago'];
                        ?>
                        <span class="badge <?php echo $metCls; ?>">
                            <i class="fas <?php echo $metIcon; ?>"></i>
                            <?php echo ucfirst($pago['metodo_pago']); ?>
                        </span>
                    </td>
                    <td>
                        <span class="badge badge-<?php echo $pago['tipo_pago']; ?>">
                            <i class="fas <?php echo $pago['tipo_pago']==='total'?'fa-check-double':'fa-minus'; ?>"></i>
                            <?php echo ucfirst($pago['tipo_pago']); ?>
                        </span>
                    </td>
                    <td style="font-size:12px;color:var(--gray-600);">
                        <?php echo htmlspecialchars($pago['cobrador_nombre'] ?? '—'); ?>
                    </td>
                    <td style="font-family:monospace;font-size:12px;color:var(--gray-600);">
                        <?php echo htmlspecialchars($pago['referencia_pago'] ?? '—'); ?>
                    </td>
                    <td>
                        <span class="badge badge-<?php echo $pago['estado']; ?>">
                            <i class="fas <?php echo $pago['estado']==='procesado'?'fa-check-circle':'fa-ban'; ?>"></i>
                            <?php echo ucfirst($pago['estado']); ?>
                        </span>
                    </td>
                    <td>
                        <div class="btns-wrap">
                            <!-- Ver comprobante -->
                            <button class="btn-tbl view"
                                    title="Ver comprobante"
                                    onclick="verComprobante(<?php echo $pago['id']; ?>)">
                                <i class="fas fa-eye"></i>
                            </button>
                            <!-- Imprimir comprobante -->
                            <button class="btn-tbl print"
                                    title="Imprimir comprobante"
                                    onclick="imprimirComprobante(<?php echo $pago['id']; ?>)">
                                <i class="fas fa-print"></i>
                            </button>
                            <!-- Anular (solo admin + estado procesado) -->
                            <?php if ($pago['estado'] === 'procesado' && $_SESSION['rol'] === 'admin'): ?>
                            <button class="btn-tbl del"
                                    title="Anular pago"
                                    onclick="anularPago(<?php echo $pago['id']; ?>)">
                                <i class="fas fa-ban"></i>
                            </button>
                            <?php endif; ?>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr>
                    <td colspan="11">
                        <div class="empty-state">
                            <i class="fas fa-money-bill-wave"></i>
                            <p>No se encontraron pagos</p>
                            <small>Ajusta los filtros de búsqueda para ver resultados.</small>
                        </div>
                    </td>
                </tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>

    <!-- ── Paginador ── -->
    <?php if ($total_paginas > 1): ?>
    <div class="paginador-wrap">
        <div class="paginador-info">
            Mostrando
            <strong><?php echo min($offset+1,$total_registros); ?>–<?php echo min($offset+$por_pagina,$total_registros); ?></strong>
            de <strong><?php echo number_format($total_registros); ?></strong> pagos
        </div>

        <div class="paginador-pages">
            <a class="pag-btn <?php echo $pagina_actual<=1?'disabled':''; ?>"
               href="<?php echo buildPagoUrl(1,$params_url); ?>" title="Primera">
                <i class="fas fa-angles-left" style="font-size:10px;"></i>
            </a>
            <a class="pag-btn <?php echo $pagina_actual<=1?'disabled':''; ?>"
               href="<?php echo buildPagoUrl($pagina_actual-1,$params_url); ?>" title="Anterior">
                <i class="fas fa-angle-left" style="font-size:11px;"></i>
            </a>

            <?php
            $ri = max(1, $pagina_actual-2);
            $rf = min($total_paginas, $pagina_actual+2);
            if ($ri > 1): ?>
                <a class="pag-btn" href="<?php echo buildPagoUrl(1,$params_url); ?>">1</a>
            <?php endif;
            if ($ri > 2): ?>
                <span class="pag-btn ellipsis">…</span>
            <?php endif;
            for ($p = $ri; $p <= $rf; $p++): ?>
                <a class="pag-btn <?php echo $p===$pagina_actual?'active':''; ?>"
                   href="<?php echo buildPagoUrl($p,$params_url); ?>">
                    <?php echo $p; ?>
                </a>
            <?php endfor;
            if ($rf < $total_paginas-1): ?>
                <span class="pag-btn ellipsis">…</span>
            <?php endif;
            if ($rf < $total_paginas): ?>
                <a class="pag-btn" href="<?php echo buildPagoUrl($total_paginas,$params_url); ?>">
                    <?php echo $total_paginas; ?>
                </a>
            <?php endif; ?>

            <a class="pag-btn <?php echo $pagina_actual>=$total_paginas?'disabled':''; ?>"
               href="<?php echo buildPagoUrl($pagina_actual+1,$params_url); ?>" title="Siguiente">
                <i class="fas fa-angle-right" style="font-size:11px;"></i>
            </a>
            <a class="pag-btn <?php echo $pagina_actual>=$total_paginas?'disabled':''; ?>"
               href="<?php echo buildPagoUrl($total_paginas,$params_url); ?>" title="Última">
                <i class="fas fa-angles-right" style="font-size:10px;"></i>
            </a>
        </div>

        <div class="paginador-rpp">
            <span>Mostrar:</span>
            <select onchange="cambiarRPP(this.value)">
                <?php foreach ([25,50,100,200] as $rpp): ?>
                    <option value="<?php echo $rpp; ?>"
                        <?php echo $por_pagina===$rpp?'selected':''; ?>>
                        <?php echo $rpp; ?>
                    </option>
                <?php endforeach; ?>
            </select>
            <span>por página</span>
        </div>
    </div>
    <?php endif; ?>

</div>

<!-- ============================================================
     MODAL ANULAR PAGO — Con contraseña
     ============================================================ -->
<div id="modalAnular" style="display:none;position:fixed;inset:0;z-index:9999;
     background:rgba(15,23,42,.55);backdrop-filter:blur(3px);
     align-items:center;justify-content:center;">
    <div style="background:#fff;border-radius:14px;width:100%;max-width:420px;
                box-shadow:0 20px 60px rgba(0,0,0,.25);overflow:hidden;">
        <div style="padding:18px 20px;background:linear-gradient(135deg,#FEE2E2,#FCA5A5);
                    border-bottom:1px solid #FCA5A5;display:flex;align-items:center;gap:12px;">
            <div style="width:42px;height:42px;border-radius:50%;background:#DC2626;
                        display:flex;align-items:center;justify-content:center;
                        color:#fff;font-size:18px;flex-shrink:0;">
                <i class="fas fa-ban"></i>
            </div>
            <div style="flex:1;">
                <div style="font-size:16px;font-weight:700;color:#991B1B;">Anular Pago</div>
                <div style="font-size:12px;color:#B91C1C;">Esta acción no se puede deshacer</div>
            </div>
            <button onclick="cerrarModalAnular()"
                    style="background:none;border:none;font-size:20px;cursor:pointer;
                           color:#991B1B;padding:4px 8px;border-radius:6px;">&times;</button>
        </div>
        <div style="padding:20px;">
            <p style="font-size:13px;color:var(--gray-600);margin-bottom:16px;" id="msgAnular">
                ¿Desea anular este pago? Esta acción revertirá el estado de la factura.
            </p>
            <div id="passwordGroup" style="display:none;margin-bottom:16px;">
                <label style="display:block;font-size:12px;font-weight:600;color:var(--gray-700);
                    text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;">
                    <i class="fas fa-lock" style="color:var(--accent);margin-right:4px;"></i>
                    Confirme su contraseña de administrador
                </label>
                <input type="password" id="adminPassword" placeholder="Contraseña…"
                       style="width:100%;padding:10px 14px;border:1.5px solid var(--gray-200);
                              border-radius:var(--radius-sm);font-size:14px;font-family:var(--font);">
            </div>
            <input type="hidden" id="anularPagoId" value="">
        </div>
        <div style="padding:14px 20px;border-top:1px solid var(--gray-200);
                    display:flex;gap:10px;justify-content:flex-end;background:var(--gray-50);">
            <button onclick="cerrarModalAnular()"
                    style="display:inline-flex;align-items:center;gap:7px;padding:9px 18px;
                           background:var(--gray-200);color:var(--gray-700);border:none;
                           border-radius:var(--radius-sm);font-size:13px;font-weight:600;cursor:pointer;">
                <i class="fas fa-times"></i> Cancelar
            </button>
            <button onclick="confirmarAnulacion()"
                    style="display:inline-flex;align-items:center;gap:7px;padding:9px 18px;
                           background:#DC2626;color:white;border:none;
                           border-radius:var(--radius-sm);font-size:13px;font-weight:600;cursor:pointer;">
                <i class="fas fa-ban"></i> Confirmar Anulación
            </button>
        </div>
    </div>
</div>

<!-- ============================================================
     JAVASCRIPT
     ============================================================ -->
<script>
/* ── Filtros — El formulario ahora usa GET estándar ── */
(function() {
    var bp = document.getElementById('buscarPagos');
    if (bp) {
        bp.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') { e.preventDefault(); this.form.submit(); }
        });
    }
})();

/* ── Registros por página ── */
function cambiarRPP(val) {
    document.cookie = 'pagos_por_pagina=' + val + '; path=/; max-age=31536000';
    window.location.href = 'pagos.php?pagina=1&<?php echo $params_url; ?>';
}

/* ── Ver comprobante ── */
function verComprobante(id) {
    window.open('ver_comprobante.php?id=' + id + '&tipo=preview', '_blank',
        'width=800,height=700,scrollbars=yes,resizable=yes');
}

/* ── Imprimir comprobante ── */
function imprimirComprobante(id) {
    window.open('imprimir_comprobante.php?id=' + id + '&tipo=direct', '_blank',
        'width=800,height=700');
}

/* ── Anular pago ── */
var _anularId = null;

function anularPago(id) {
    _anularId = id;
    document.getElementById('anularPagoId').value = id;
    document.getElementById('adminPassword').value = '';
    document.getElementById('passwordGroup').style.display = 'none';
    document.getElementById('msgAnular').textContent =
        '¿Desea anular este pago? Esta acción revertirá el estado de la factura correspondiente.';

    // Verificar si requiere contraseña
    fetch('verificar_tiempo_pago.php?id=' + id)
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.requiere_password) {
                document.getElementById('passwordGroup').style.display = 'block';
                document.getElementById('msgAnular').textContent =
                    'Este pago tiene más de 5 minutos. Ingrese su contraseña de administrador para continuar.';
            }
            // Mostrar modal
            var modal = document.getElementById('modalAnular');
            modal.style.display = 'flex';
            document.body.style.overflow = 'hidden';
        })
        .catch(function() {
            // Si falla la verificación, mostrar modal sin contraseña
            var modal = document.getElementById('modalAnular');
            modal.style.display = 'flex';
            document.body.style.overflow = 'hidden';
        });
}

function cerrarModalAnular() {
    document.getElementById('modalAnular').style.display = 'none';
    document.body.style.overflow = '';
    _anularId = null;
}

function confirmarAnulacion() {
    var id       = _anularId;
    var password = document.getElementById('adminPassword').value;

    if (!id) return;

    var passwordGroup = document.getElementById('passwordGroup');
    if (passwordGroup.style.display !== 'none' && !password.trim()) {
        mostrarToast('Debe ingresar su contraseña para continuar.', 'error');
        document.getElementById('adminPassword').focus();
        return;
    }

    fetch('anular_pago.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: id, password: password })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        cerrarModalAnular();
        if (data.success) {
            mostrarToast('Pago anulado correctamente.', 'success');
            // Actualizar fila visualmente
            var fila = document.getElementById('fila-pago-' + id);
            if (fila) {
                var celdaMonto = fila.querySelector('.monto-cell');
                if (celdaMonto) celdaMonto.classList.add('anulado');
                var badges = fila.querySelectorAll('.badge-procesado');
                badges.forEach(function(b) {
                    b.className = 'badge badge-anulado';
                    b.innerHTML = '<i class="fas fa-ban"></i> Anulado';
                });
                var btnAnular = fila.querySelector('.btn-tbl.del');
                if (btnAnular) btnAnular.remove();
                // Resaltar brevemente
                fila.style.transition = 'background .4s';
                fila.style.background = '#FEE2E2';
                setTimeout(function() { fila.style.background = ''; }, 1500);
            }
        } else {
            mostrarToast(data.message || 'Error al anular el pago.', 'error');
        }
    })
    .catch(function() {
        cerrarModalAnular();
        mostrarToast('Error de conexión al intentar anular el pago.', 'error');
    });
}

/* ── Cerrar modal con Escape ── */
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') cerrarModalAnular();
});
document.getElementById('modalAnular').addEventListener('click', function(e) {
    if (e.target === this) cerrarModalAnular();
});

/* ── Enter en campo contraseña ── */
document.getElementById('adminPassword').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') confirmarAnulacion();
});
</script>

<?php require_once 'footer.php'; ?>