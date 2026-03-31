<?php
require_once 'header.php';

/* ============================================================
   ESTADÍSTICAS KPI
   ============================================================ */
$sql_stats = "
    SELECT
        COUNT(DISTINCT CASE WHEN af.estado = 'activa' AND f.estado IN ('pendiente','incompleta') THEN af.id END) AS total_asignadas,
        COUNT(DISTINCT CASE WHEN f.estado IN ('pendiente','incompleta') THEN f.id END)                           AS total_pendientes,
        COALESCE(SUM(CASE WHEN f.estado IN ('pendiente','incompleta') THEN f.monto ELSE 0 END), 0)               AS monto_pendiente,
        COALESCE(SUM(CASE WHEN af.estado = 'activa' AND f.estado IN ('pendiente','incompleta') THEN f.monto ELSE 0 END), 0) AS monto_asignado,
        COUNT(DISTINCT CASE WHEN af.estado = 'activa' AND f.estado IN ('pendiente','incompleta') THEN af.cobrador_id END) AS cobradores_activos
    FROM facturas f
    LEFT JOIN asignaciones_facturas af ON f.id = af.factura_id
    WHERE af.estado = 'activa' OR f.estado IN ('pendiente','incompleta')
";
$stats = $conn->query($sql_stats)->fetch(PDO::FETCH_ASSOC);

/* ── Cobradores activos ── */
$cobradores = $conn->query("
    SELECT id, codigo, nombre_completo
    FROM cobradores
    WHERE estado = 'activo'
    ORDER BY nombre_completo
")->fetchAll();

/* ============================================================
   FILTROS
   ============================================================ */
$where  = "1=1";
$params = [];

if (!empty($_GET['contrato'])) {
    $where   .= " AND (c.numero_contrato LIKE ? OR f.numero_factura LIKE ?)";
    $t        = '%' . $_GET['contrato'] . '%';
    $params[] = $t;
    $params[] = $t;
}
if (!empty($_GET['cobrador_id'])) {
    $where   .= " AND af.cobrador_id = ?";
    $params[] = (int)$_GET['cobrador_id'];
}
if (!empty($_GET['fecha_desde'])) {
    $where   .= " AND af.fecha_asignacion >= ?";
    $params[] = $_GET['fecha_desde'];
}
if (!empty($_GET['fecha_hasta'])) {
    $where   .= " AND af.fecha_asignacion <= ?";
    $params[] = $_GET['fecha_hasta'];
}
if (!empty($_GET['estado'])) {
    $where   .= " AND f.estado = ?";
    $params[] = $_GET['estado'];
}

/* ============================================================
   PAGINACIÓN
   ============================================================ */
if (isset($_GET['por_pagina'])) {
    $por_pagina = max(10, (int)$_GET['por_pagina']);
    setcookie('asignaciones_por_pagina', $por_pagina, time() + 60*60*24*30, '/');
} else {
    $por_pagina = isset($_COOKIE['asignaciones_por_pagina']) ? (int)$_COOKIE['asignaciones_por_pagina'] : 50;
}

$pagina_actual   = max(1, (int)($_GET['pagina'] ?? 1));
$offset          = ($pagina_actual - 1) * $por_pagina;

$stmt_total = $conn->prepare("
    SELECT COUNT(*) AS total
    FROM asignaciones_facturas af
    JOIN facturas  f  ON af.factura_id  = f.id
    JOIN contratos c  ON f.contrato_id  = c.id
    JOIN clientes  cl ON c.cliente_id   = cl.id
    JOIN cobradores co ON af.cobrador_id = co.id
    WHERE $where
");
$stmt_total->execute($params);
$total_registros = (int)$stmt_total->fetch()['total'];
$total_paginas   = max(1, ceil($total_registros / $por_pagina));

/* ============================================================
   CONSULTA PRINCIPAL
   ============================================================ */
$sql = "
    SELECT
        af.id            AS asignacion_id,
        af.fecha_asignacion,
        f.numero_factura,
        f.mes_factura,
        f.monto,
        f.estado,
        c.numero_contrato,
        c.dia_cobro,
        cl.nombre        AS cliente_nombre,
        cl.apellidos     AS cliente_apellidos,
        co.nombre_completo AS cobrador_nombre
    FROM asignaciones_facturas af
    JOIN facturas   f  ON af.factura_id  = f.id
    JOIN contratos  c  ON f.contrato_id  = c.id
    JOIN clientes   cl ON c.cliente_id   = cl.id
    JOIN cobradores co ON af.cobrador_id = co.id
    WHERE $where
    ORDER BY af.fecha_asignacion DESC, co.nombre_completo
    LIMIT $por_pagina OFFSET $offset
";
$stmt = $conn->prepare($sql);
$stmt->execute($params);
$asignaciones = $stmt->fetchAll(PDO::FETCH_ASSOC);

/* ── Helper URL paginador ── */
function buildUrlAsignacion(int $pag): string {
    $p = ['pagina' => $pag];
    if (!empty($_GET['contrato']))    $p['contrato']    = $_GET['contrato'];
    if (!empty($_GET['cobrador_id'])) $p['cobrador_id'] = $_GET['cobrador_id'];
    if (!empty($_GET['fecha_desde'])) $p['fecha_desde'] = $_GET['fecha_desde'];
    if (!empty($_GET['fecha_hasta'])) $p['fecha_hasta'] = $_GET['fecha_hasta'];
    if (!empty($_GET['estado']))      $p['estado']      = $_GET['estado'];
    if (!empty($_GET['por_pagina']))  $p['por_pagina']  = $_GET['por_pagina'];
    return 'asignacion.php?' . http_build_query($p);
}
?>

<!-- ============================================================
     ESTILOS ESPECÍFICOS DE LA PÁGINA
     ============================================================ -->
<style>
/* ── KPI CARDS ── */
.kpi-asignacion {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 18px;
    margin-bottom: 24px;
}
@media(max-width:1100px){ .kpi-asignacion { grid-template-columns: repeat(2,1fr); } }
@media(max-width:600px)  { .kpi-asignacion { grid-template-columns: 1fr; } }

.kpi-asignacion .kpi-card {
    border-radius: var(--radius);
    padding: 22px 22px 18px;
    position: relative;
    overflow: hidden;
    box-shadow: var(--shadow);
    transition: var(--transition);
    color: white;
    cursor: default;
}
.kpi-asignacion .kpi-card:hover { transform: translateY(-3px); box-shadow: var(--shadow-md); }
.kpi-asignacion .kpi-card::before {
    content:''; position:absolute; top:0; right:0;
    width:80px; height:80px;
    border-radius:0 var(--radius) 0 100%;
    opacity:.15; background:white;
}
.kpi-asignacion .kpi-card.blue   { background: linear-gradient(135deg,#1565C0,#1976D2); }
.kpi-asignacion .kpi-card.green  { background: linear-gradient(135deg,#1B5E20,#2E7D32); }
.kpi-asignacion .kpi-card.amber  { background: linear-gradient(135deg,#E65100,#F57F17); }
.kpi-asignacion .kpi-card.teal   { background: linear-gradient(135deg,#00695C,#00897B); }

.kpi-asignacion .kpi-label {
    font-size:11px; font-weight:600; color:rgba(255,255,255,.80);
    text-transform:uppercase; letter-spacing:.8px; margin-bottom:10px;
}
.kpi-asignacion .kpi-top {
    display:flex; align-items:flex-start; justify-content:space-between; margin-bottom:6px;
}
.kpi-asignacion .kpi-value {
    font-size:28px; font-weight:800; color:white; line-height:1; margin-bottom:4px;
}
.kpi-asignacion .kpi-value.sm { font-size:20px; }
.kpi-asignacion .kpi-sub  { font-size:11px; color:rgba(255,255,255,.70); font-weight:500; }
.kpi-asignacion .kpi-icon {
    width:48px; height:48px;
    background:rgba(255,255,255,.18); border-radius:var(--radius-sm);
    display:flex; align-items:center; justify-content:center;
    font-size:20px; color:white; flex-shrink:0;
}
.kpi-asignacion .kpi-footer {
    margin-top:14px; padding-top:12px;
    border-top:1px solid rgba(255,255,255,.15);
    font-size:11.5px; color:rgba(255,255,255,.80); font-weight:600;
    display:flex; align-items:center; gap:6px;
}

/* ── FILTER BAR ── */
.filter-bar {
    background: var(--white);
    border: 1px solid var(--gray-200);
    border-radius: var(--radius);
    padding: 14px 18px;
    margin-bottom: 18px;
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
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
    font-size: 13px;
    font-family: var(--font);
    color: var(--gray-700);
    background: var(--gray-50);
    transition: var(--transition);
    outline: none;
}
.filter-bar .search-wrap input:focus {
    border-color: var(--accent);
    background: var(--white);
    box-shadow: 0 0 0 3px rgba(33,150,243,.10);
}
.filter-bar .search-wrap .si {
    position: absolute; left:11px; top:50%; transform:translateY(-50%);
    color: var(--gray-400); font-size:13px; pointer-events:none;
}
.filter-bar .filter-select {
    padding: 9px 10px; min-width: 160px;
    border: 1px solid var(--gray-200); border-radius: var(--radius-sm);
    font-size: 13px; font-family: var(--font); color: var(--gray-700);
    background: var(--gray-50); cursor: pointer; transition: var(--transition);
    outline: none;
}
.filter-bar .filter-select:focus {
    border-color: var(--accent); background: var(--white);
    box-shadow: 0 0 0 3px rgba(33,150,243,.10);
}
.filter-bar input[type="date"] {
    padding: 9px 10px; min-width: 140px;
    border: 1px solid var(--gray-200); border-radius: var(--radius-sm);
    font-size: 13px; font-family: var(--font); color: var(--gray-700);
    background: var(--gray-50); cursor: pointer; transition: var(--transition);
    outline: none;
}
.filter-bar input[type="date"]:focus {
    border-color: var(--accent); background: var(--white);
    box-shadow: 0 0 0 3px rgba(33,150,243,.10);
}
.filter-label {
    font-size: 12px; color: var(--gray-500); font-weight:500; white-space:nowrap;
}

/* ── BADGES ESTADO ── */
.badge-asig {
    display:inline-flex; align-items:center; gap:4px;
    padding:4px 11px; border-radius:20px;
    font-size:11px; font-weight:700; white-space:nowrap;
}
.badge-asig.pendiente  { background:#FEF3C7; color:#B45309; }
.badge-asig.incompleta { background:#EDE9FE; color:#7C3AED; }
.badge-asig.pagada     { background:#DCFCE7; color:#15803D; }
.badge-asig.vencida    { background:#FEE2E2; color:#DC2626; }
.badge-asig.anulada    { background:var(--gray-100); color:var(--gray-500); }

/* ── TABLA ── */
.asig-num  { font-family:monospace; font-size:12.5px; font-weight:700; color:var(--accent); }
.asig-contrato { font-family:monospace; font-size:12px; color:var(--gray-600); }
.asig-cliente  { font-weight:600; color:var(--gray-800); font-size:13px; }
.asig-monto    { font-weight:700; color:var(--gray-800); }
.asig-mes      { font-size:12px; color:var(--gray-600); }
.asig-cobrador { font-size:12.5px; color:var(--gray-700); }
.asig-fecha    { font-size:12px; color:var(--gray-500); }

/* Botones acción en tabla */
.tbl-actions { display:flex; align-items:center; justify-content:center; gap:4px; }
.btn-tbl {
    width:32px; height:32px; border-radius:var(--radius-sm); border:none;
    display:inline-flex; align-items:center; justify-content:center;
    font-size:13px; cursor:pointer; transition:var(--transition);
}
.btn-tbl:hover { transform:translateY(-2px); box-shadow:var(--shadow); }
.btn-tbl.edit   { background:#EFF6FF; color:#1565C0; }
.btn-tbl.del    { background:#FEF2F2; color:#DC2626; }
.btn-tbl.edit:hover { background:#1565C0; color:white; }
.btn-tbl.del:hover  { background:#DC2626; color:white; }

/* Checkbox */
.tbl-check {
    width:16px; height:16px; cursor:pointer;
    accent-color: var(--accent);
}

/* ── PAGINADOR ── */
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
    min-width:34px; height:34px; padding:0 6px;
    display:inline-flex; align-items:center; justify-content:center;
    border-radius:var(--radius-sm); border:1px solid var(--gray-200);
    background:var(--white); color:var(--gray-600); font-size:13px; font-weight:600;
    text-decoration:none; transition:var(--transition);
}
.pag-btn:hover:not(.disabled):not(.active) { background:var(--accent); color:white; border-color:var(--accent); }
.pag-btn.active { background:var(--accent); color:white; border-color:var(--accent); box-shadow:0 2px 8px rgba(33,150,243,.30); }
.pag-btn.disabled { opacity:.4; pointer-events:none; }
.paginador-rpp { display:flex; align-items:center; gap:8px; font-size:12.5px; color:var(--gray-500); }
.paginador-rpp select {
    padding:5px 8px; border:1px solid var(--gray-200); border-radius:var(--radius-sm);
    font-size:12.5px; font-family:var(--font); background:var(--white); cursor:pointer;
    outline:none; transition:var(--transition);
}
.paginador-rpp select:focus { border-color:var(--accent); }

/* ── MODALES OVERLAY ── */
.modal-overlay {
    display:none; position:fixed; inset:0; z-index:9000;
    background:rgba(15,23,42,.55); backdrop-filter:blur(3px);
    align-items:center; justify-content:center; padding:16px;
}
.modal-overlay.open { display:flex; }

.modal-box {
    background:var(--white); border-radius:var(--radius);
    width:100%; box-shadow:0 20px 60px rgba(0,0,0,.25);
    display:flex; flex-direction:column;
    max-height:90vh; overflow:hidden;
    animation: modalSlideIn .22s ease;
}
@keyframes modalSlideIn {
    from { opacity:0; transform:translateY(-16px) scale(.97); }
    to   { opacity:1; transform:translateY(0)    scale(1); }
}
.modal-box.sm  { max-width:480px; }
.modal-box.md  { max-width:620px; }
.modal-box.lg  { max-width:820px; }

.modal-header {
    padding:18px 22px 16px;
    border-bottom:1px solid var(--gray-100);
    display:flex; align-items:center; justify-content:space-between;
    background:var(--gray-50);
}
.modal-header-title {
    font-size:16px; font-weight:700; color:var(--gray-800);
    display:flex; align-items:center; gap:10px;
}
.modal-header-icon {
    width:36px; height:36px; border-radius:var(--radius-sm);
    display:flex; align-items:center; justify-content:center;
    font-size:15px;
}
.modal-header-icon.blue   { background:#EFF6FF; color:#1565C0; }
.modal-header-icon.green  { background:#F0FDF4; color:#15803D; }
.modal-header-icon.amber  { background:#FFFBEB; color:#D97706; }
.modal-header-icon.red    { background:#FEF2F2; color:#DC2626; }
.modal-header-icon.purple { background:#F5F3FF; color:#7C3AED; }
.modal-header-icon.teal   { background:#F0FDFA; color:#0D9488; }

.btn-modal-close {
    width:30px; height:30px; border:none; background:var(--gray-100);
    border-radius:var(--radius-sm); cursor:pointer;
    display:flex; align-items:center; justify-content:center;
    font-size:14px; color:var(--gray-500); transition:var(--transition);
}
.btn-modal-close:hover { background:var(--gray-200); color:var(--gray-700); }

.modal-body {
    padding:22px; overflow-y:auto; flex:1;
}
.modal-body::-webkit-scrollbar { width:6px; }
.modal-body::-webkit-scrollbar-track { background:#f1f5f9; }
.modal-body::-webkit-scrollbar-thumb { background:#cbd5e1; border-radius:3px; }

.modal-footer {
    padding:14px 22px;
    border-top:1px solid var(--gray-100);
    display:flex; align-items:center; justify-content:flex-end;
    gap:10px; background:var(--gray-50);
}

/* Formulario dentro de modal */
.modal-form-row {
    display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:16px;
}
.modal-form-row.single { grid-template-columns:1fr; }
@media(max-width:500px){ .modal-form-row { grid-template-columns:1fr; } }

.form-field { display:flex; flex-direction:column; gap:6px; }
.form-label {
    font-size:12.5px; font-weight:600; color:var(--gray-600);
    text-transform:uppercase; letter-spacing:.4px;
}
.form-ctrl {
    padding:9px 12px; border:1px solid var(--gray-200);
    border-radius:var(--radius-sm); font-size:13px;
    font-family:var(--font); color:var(--gray-700);
    background:var(--white); transition:var(--transition); outline:none;
}
.form-ctrl:focus {
    border-color:var(--accent);
    box-shadow:0 0 0 3px rgba(33,150,243,.10);
}

/* Input group para agregar factura */
.input-add-group {
    display:flex; gap:8px; margin-bottom:16px;
}
.input-add-group .form-ctrl { flex:1; }
.btn-add-icon {
    width:40px; height:40px; border:none;
    border-radius:var(--radius-sm); cursor:pointer;
    background:var(--accent); color:white;
    display:flex; align-items:center; justify-content:center;
    font-size:16px; transition:var(--transition); flex-shrink:0;
}
.btn-add-icon:hover { background:#1565C0; }

/* Lista de facturas en modal asignación */
.facturas-list-wrap {
    border:1px solid var(--gray-200); border-radius:var(--radius-sm);
    overflow:hidden;
}
.facturas-list-header {
    padding:10px 14px; background:var(--gray-50);
    border-bottom:1px solid var(--gray-200);
    font-size:12px; font-weight:600; color:var(--gray-600);
}
.facturas-list-table {
    width:100%; border-collapse:collapse; font-size:12.5px;
}
.facturas-list-table thead th {
    padding:8px 12px; background:var(--gray-50);
    font-size:11px; font-weight:600; color:var(--gray-500);
    text-transform:uppercase; letter-spacing:.4px;
    border-bottom:1px solid var(--gray-200); text-align:left;
}
.facturas-list-table tbody td {
    padding:9px 12px; border-bottom:1px solid var(--gray-100);
    vertical-align:middle;
}
.facturas-list-table tbody tr:last-child td { border-bottom:none; }
.facturas-list-table tbody tr:hover { background:var(--gray-50); }

/* Alerta info dentro de modal */
.modal-alert {
    padding:12px 16px; border-radius:var(--radius-sm);
    font-size:13px; margin-bottom:14px;
    display:flex; align-items:flex-start; gap:10px;
}
.modal-alert.warning { background:#FFFBEB; border:1px solid #FDE68A; color:#92400E; }
.modal-alert.info    { background:#EFF6FF; border:1px solid #BFDBFE; color:#1E40AF; }
.modal-alert.danger  { background:#FEF2F2; border:1px solid #FECACA; color:#991B1B; }

/* Botones del sistema */
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
.btn-warning   { background:#FFFBEB; color:#D97706; }
.btn-warning:hover   { background:#D97706; color:white; }
.btn-info      { background:#E0F2FE; color:#0369A1; }
.btn-info:hover      { background:#0284C7; color:white; }
.btn-sm { padding:7px 12px; font-size:12px; }
.btn:disabled { opacity:.45; pointer-events:none; cursor:not-allowed; }

/* Empty state */
.empty-state {
    text-align:center; padding:48px 20px;
    color:var(--gray-400);
}
.empty-state i { font-size:40px; display:block; margin-bottom:14px; opacity:.4; }
.empty-state p { margin:0 0 4px; font-size:15px; font-weight:500; color:var(--gray-500); }
.empty-state small { font-size:12.5px; }

/* Scroll personalizado modal body */
.modal-body::-webkit-scrollbar { width:6px; }
.modal-body::-webkit-scrollbar-track { background:#f1f5f9; }
.modal-body::-webkit-scrollbar-thumb { background:#cbd5e1; border-radius:3px; }
.modal-body::-webkit-scrollbar-thumb:hover { background:#94a3b8; }

/* Preview facturas impresión */
.preview-table {
    width:100%; border-collapse:collapse; font-size:12.5px; margin-top:14px;
}
.preview-table thead th {
    padding:8px 10px; background:var(--gray-50);
    font-size:11px; font-weight:600; color:var(--gray-500);
    text-transform:uppercase; border-bottom:2px solid var(--gray-200);
    text-align:left;
}
.preview-table tbody td {
    padding:9px 10px; border-bottom:1px solid var(--gray-100);
}
.preview-total-row td {
    padding:10px; background:var(--gray-50);
    font-weight:700; border-top:2px solid var(--gray-200);
}

/* Página acciones responsive */
@media(max-width:768px){
    .page-header { flex-direction:column; align-items:flex-start; }
    .page-header-actions { flex-wrap:wrap; }
    .filter-bar { flex-direction:column; align-items:stretch; }
    .filter-bar .search-wrap { min-width:100%; }
    .filter-bar .filter-select,
    .filter-bar input[type="date"] { width:100%; }
}
</style>

<!-- ============================================================
     PAGE HEADER
     ============================================================ -->
<div class="page-header fade-in">
    <div>
        <div class="page-title">Asignación de Facturas</div>
        <div class="page-subtitle">
            Gestión de asignaciones de facturas a cobradores —
            <?php echo number_format($total_registros); ?> registro<?php echo $total_registros !== 1 ? 's' : ''; ?>
        </div>
    </div>
    <div class="page-header-actions">
        <!-- Imprimir Relación -->
        <button class="btn btn-info btn-sm" onclick="abrirModal('modalImpresion')">
            <i class="fas fa-print"></i> Imprimir Relación
        </button>
        <!-- Asignar Facturas -->
        <button class="btn btn-success btn-sm" onclick="abrirModal('modalAsignacion')">
            <i class="fas fa-plus"></i> Asignar Facturas
        </button>
        <!-- Reasignar (habilitado al seleccionar) -->
        <button class="btn btn-warning btn-sm" id="btnReasignarGrupo"
                onclick="reasignarGrupo()" disabled>
            <i class="fas fa-exchange-alt"></i>
            Reasignar <span id="contadorSeleccionadasReasignar" style="font-size:11px;"></span>
        </button>
        <!-- Eliminar (habilitado al seleccionar) -->
        <button class="btn btn-danger btn-sm" id="btnEliminarGrupo"
                onclick="eliminarGrupo()" disabled>
            <i class="fas fa-trash"></i>
            Eliminar <span id="contadorSeleccionadas" style="font-size:11px;"></span>
        </button>
    </div>
</div>

<!-- ============================================================
     KPI CARDS
     ============================================================ -->
<div class="kpi-asignacion fade-in delay-1">

    <!-- Facturas Pendientes -->
    <div class="kpi-card blue">
        <div class="kpi-label">Facturas Pendientes</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo number_format($stats['total_pendientes'] ?? 0); ?></div>
                <div class="kpi-sub">Sin cobrador asignado o pendientes</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-file-invoice"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-database"></i> Total en el sistema</div>
    </div>

    <!-- Asignadas -->
    <div class="kpi-card green">
        <div class="kpi-label">Facturas Asignadas</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo number_format($stats['total_asignadas'] ?? 0); ?></div>
                <div class="kpi-sub">Con cobrador activo</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-user-check"></i></div>
        </div>
        <div class="kpi-footer">
            <i class="fas fa-users"></i>
            <?php echo $stats['cobradores_activos'] ?? 0; ?> cobrador<?php echo ($stats['cobradores_activos'] ?? 0) !== 1 ? 'es' : ''; ?> activo<?php echo ($stats['cobradores_activos'] ?? 0) !== 1 ? 's' : ''; ?>
        </div>
    </div>

    <!-- Monto Pendiente -->
    <div class="kpi-card amber">
        <div class="kpi-label">Monto Total Pendiente</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value sm">RD$<?php echo number_format($stats['monto_pendiente'] ?? 0, 0, '.', ','); ?></div>
                <div class="kpi-sub">Total por cobrar</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-file-invoice-dollar"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-clock"></i> Pendiente de cobro</div>
    </div>

    <!-- Monto Asignado -->
    <div class="kpi-card teal">
        <div class="kpi-label">Monto Asignado</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value sm">RD$<?php echo number_format($stats['monto_asignado'] ?? 0, 0, '.', ','); ?></div>
                <div class="kpi-sub">En manos de cobradores</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-hand-holding-dollar"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-arrow-trend-up"></i> En gestión activa</div>
    </div>

</div>

<!-- ============================================================
     BARRA DE FILTROS
     ============================================================ -->
<div class="filter-bar-h fade-in delay-2">
    <form method="GET" action="asignacion.php" id="formFiltrosAsignacion">
        <div class="filter-row-fields">
            <!-- Búsqueda -->
            <div class="filter-field field-search">
                <label for="contratoSearch"><i class="fas fa-search"></i> Buscar</label>
                <div class="search-wrap-h">
                    <i class="fas fa-search search-icon-h"></i>
                    <input type="text"
                           id="contratoSearch"
                           name="contrato"
                           class="filter-input"
                           placeholder="No. factura o contrato…"
                           value="<?php echo htmlspecialchars($_GET['contrato'] ?? ''); ?>"
                           autocomplete="off">
                </div>
            </div>
            <!-- Cobrador -->
            <div class="filter-field field-select">
                <label for="cobradorFilter"><i class="fas fa-motorcycle"></i> Cobrador</label>
                <select id="cobradorFilter" name="cobrador_id" class="filter-select-h" onchange="this.form.submit()">
                    <option value="">Todos los cobradores</option>
                    <?php foreach ($cobradores as $cob): ?>
                        <option value="<?php echo $cob['id']; ?>"
                            <?php echo (($_GET['cobrador_id'] ?? '') == $cob['id']) ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($cob['codigo'] . ' - ' . $cob['nombre_completo']); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <!-- Estado -->
            <div class="filter-field field-select">
                <label for="estadoFilter"><i class="fas fa-circle-half-stroke"></i> Estado</label>
                <select id="estadoFilter" name="estado" class="filter-select-h" onchange="this.form.submit()">
                    <option value="">Todos</option>
                    <option value="pendiente"  <?php echo (($_GET['estado'] ?? '') === 'pendiente')  ? 'selected' : ''; ?>>Pendiente</option>
                    <option value="incompleta" <?php echo (($_GET['estado'] ?? '') === 'incompleta') ? 'selected' : ''; ?>>Incompleta</option>
                    <option value="vencida"    <?php echo (($_GET['estado'] ?? '') === 'vencida')    ? 'selected' : ''; ?>>Vencida</option>
                    <option value="pagada"     <?php echo (($_GET['estado'] ?? '') === 'pagada')     ? 'selected' : ''; ?>>Pagada</option>
                </select>
            </div>
            <!-- Fecha Desde -->
            <div class="filter-field field-date">
                <label for="fechaDesdeAsig"><i class="fas fa-calendar-days"></i> Desde</label>
                <input type="date"
                       id="fechaDesdeAsig"
                       name="fecha_desde"
                       class="filter-select-h"
                       value="<?php echo htmlspecialchars($_GET['fecha_desde'] ?? ''); ?>">
            </div>
            <!-- Fecha Hasta -->
            <div class="filter-field field-date">
                <label for="fechaHastaAsig"><i class="fas fa-calendar-check"></i> Hasta</label>
                <input type="date"
                       id="fechaHastaAsig"
                       name="fecha_hasta"
                       class="filter-select-h"
                       value="<?php echo htmlspecialchars($_GET['fecha_hasta'] ?? ''); ?>">
            </div>
        </div>
        <div class="filter-row-btns">
            <button type="submit" class="btn btn-primary btn-sm">
                <i class="fas fa-search"></i> Buscar
            </button>
            <?php if (!empty($_GET['contrato'])||!empty($_GET['cobrador_id'])||!empty($_GET['estado'])||!empty($_GET['fecha_desde'])||!empty($_GET['fecha_hasta'])): ?>
                <a href="asignacion.php" class="btn btn-secondary btn-sm">
                    <i class="fas fa-times"></i> Limpiar
                </a>
            <?php endif; ?>
            <div class="filter-results-info">
                <?php echo number_format($total_registros); ?> asignación<?php echo $total_registros !== 1 ? 'es' : ''; ?>
            </div>
        </div>
    </form>
</div>

<!-- ============================================================
     TABLA DE ASIGNACIONES
     ============================================================ -->
<div class="card fade-in delay-3">
    <div class="card-header">
        <div>
            <div class="card-title">
                <i class="fas fa-tasks" style="color:var(--accent);margin-right:6px;"></i>
                Asignaciones de Facturas
            </div>
            <div class="card-subtitle">
                Mostrando
                <strong><?php echo $total_registros > 0 ? min($offset+1,$total_registros) : 0; ?>–<?php echo min($offset+$por_pagina,$total_registros); ?></strong>
                de <strong><?php echo number_format($total_registros); ?></strong> asignaciones
            </div>
        </div>
    </div>

    <div style="overflow-x:auto;">
        <table class="data-table" id="tablaAsignaciones">
            <thead>
                <tr>
                    <th style="width:36px;">
                        <input type="checkbox" class="tbl-check" id="seleccionarTodas"
                               onclick="seleccionarTodasFacturas(this)">
                    </th>
                    <th>Fecha Asig.</th>
                    <th>No. Factura</th>
                    <th>Contrato</th>
                    <th>Cliente</th>
                    <th>Mes</th>
                    <th>Día Pago</th>
                    <th>Monto</th>
                    <th>Cobrador</th>
                    <th>Estado</th>
                    <th style="text-align:center;">Acciones</th>
                </tr>
            </thead>
            <tbody>
            <?php if (!empty($asignaciones)): ?>
                <?php foreach ($asignaciones as $asig):
                    $badgeCls = match($asig['estado']) {
                        'pendiente'  => 'pendiente',
                        'incompleta' => 'incompleta',
                        'pagada'     => 'pagada',
                        'vencida'    => 'vencida',
                        default      => 'anulada',
                    };
                    $badgeIcon = match($asig['estado']) {
                        'pendiente'  => 'fa-clock',
                        'incompleta' => 'fa-circle-half-stroke',
                        'pagada'     => 'fa-check-circle',
                        'vencida'    => 'fa-exclamation-triangle',
                        default      => 'fa-ban',
                    };
                    // Formatear mes
                    $meses = ['01'=>'Ene','02'=>'Feb','03'=>'Mar','04'=>'Abr','05'=>'May','06'=>'Jun',
                              '07'=>'Jul','08'=>'Ago','09'=>'Sep','10'=>'Oct','11'=>'Nov','12'=>'Dic'];
                    $partesMes = explode('/', $asig['mes_factura']);
                    $mesFormato = (count($partesMes) === 2 && isset($meses[$partesMes[0]]))
                                ? $meses[$partesMes[0]] . '/' . $partesMes[1]
                                : $asig['mes_factura'];
                ?>
                <tr>
                    <td>
                        <input type="checkbox" class="tbl-check seleccion-factura"
                               data-asignacion-id="<?php echo $asig['asignacion_id']; ?>"
                               onchange="actualizarContadorSeleccionadas()">
                    </td>
                    <td class="asig-fecha">
                        <?php echo date('d/m/Y', strtotime($asig['fecha_asignacion'])); ?>
                    </td>
                    <td>
                        <span class="asig-num"><?php echo htmlspecialchars($asig['numero_factura']); ?></span>
                    </td>
                    <td>
                        <span class="asig-contrato"><?php echo htmlspecialchars(str_pad($asig['numero_contrato'], 5, '0', STR_PAD_LEFT)); ?></span>
                    </td>
                    <td>
                        <span class="asig-cliente">
                            <?php echo htmlspecialchars($asig['cliente_nombre'] . ' ' . $asig['cliente_apellidos']); ?>
                        </span>
                    </td>
                    <td class="asig-mes"><?php echo htmlspecialchars($mesFormato); ?></td>
                    <td style="text-align:center;font-size:12.5px;color:var(--gray-600);">
                        <?php echo $asig['dia_cobro'] ? 'Día ' . $asig['dia_cobro'] : '—'; ?>
                    </td>
                    <td>
                        <span class="asig-monto">RD$<?php echo number_format($asig['monto'], 2); ?></span>
                    </td>
                    <td>
                        <span class="asig-cobrador"><?php echo htmlspecialchars($asig['cobrador_nombre']); ?></span>
                    </td>
                    <td>
                        <span class="badge-asig <?php echo $badgeCls; ?>">
                            <i class="fas <?php echo $badgeIcon; ?>"></i>
                            <?php echo ucfirst($asig['estado']); ?>
                        </span>
                    </td>
                    <td>
                        <div class="tbl-actions">
                            <button class="btn-tbl edit" title="Reasignar esta factura"
                                    onclick="reasignarFactura(<?php echo $asig['asignacion_id']; ?>)">
                                <i class="fas fa-exchange-alt"></i>
                            </button>
                            <button class="btn-tbl del" title="Eliminar asignación"
                                    onclick="eliminarAsignacion(<?php echo $asig['asignacion_id']; ?>)">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr>
                    <td colspan="11">
                        <div class="empty-state">
                            <i class="fas fa-tasks"></i>
                            <p>No se encontraron asignaciones</p>
                            <small>Usa los filtros para buscar o crea una nueva asignación.</small>
                        </div>
                    </td>
                </tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>

    <!-- ── Paginador ── -->
    <?php if ($total_registros > 0): ?>
    <div class="paginador-wrap">
        <!-- Info -->
        <div class="paginador-info">
            Mostrando <strong><?php echo min($offset+1,$total_registros); ?>–<?php echo min($offset+$por_pagina,$total_registros); ?></strong>
            de <strong><?php echo number_format($total_registros); ?></strong> asignaciones
        </div>

        <!-- Páginas -->
        <?php if ($total_paginas > 1): ?>
        <div class="paginador-pages">
            <a class="pag-btn <?php echo $pagina_actual<=1?'disabled':''; ?>"
               href="<?php echo buildUrlAsignacion(1); ?>" title="Primera">
                <i class="fas fa-angles-left" style="font-size:10px;"></i>
            </a>
            <a class="pag-btn <?php echo $pagina_actual<=1?'disabled':''; ?>"
               href="<?php echo buildUrlAsignacion($pagina_actual-1); ?>" title="Anterior">
                <i class="fas fa-angle-left" style="font-size:11px;"></i>
            </a>

            <?php
            $rango = 2;
            $ini   = max(1, $pagina_actual - $rango);
            $fin   = min($total_paginas, $pagina_actual + $rango);
            if ($ini > 1): ?>
                <a class="pag-btn" href="<?php echo buildUrlAsignacion(1); ?>">1</a>
                <?php if ($ini > 2): ?><span class="pag-btn disabled" style="pointer-events:none;">…</span><?php endif; ?>
            <?php endif; ?>

            <?php for ($p = $ini; $p <= $fin; $p++): ?>
                <a class="pag-btn <?php echo $p===$pagina_actual?'active':''; ?>"
                   href="<?php echo buildUrlAsignacion($p); ?>"><?php echo $p; ?></a>
            <?php endfor; ?>

            <?php if ($fin < $total_paginas): ?>
                <?php if ($fin < $total_paginas - 1): ?><span class="pag-btn disabled">…</span><?php endif; ?>
                <a class="pag-btn" href="<?php echo buildUrlAsignacion($total_paginas); ?>"><?php echo $total_paginas; ?></a>
            <?php endif; ?>

            <a class="pag-btn <?php echo $pagina_actual>=$total_paginas?'disabled':''; ?>"
               href="<?php echo buildUrlAsignacion($pagina_actual+1); ?>" title="Siguiente">
                <i class="fas fa-angle-right" style="font-size:11px;"></i>
            </a>
            <a class="pag-btn <?php echo $pagina_actual>=$total_paginas?'disabled':''; ?>"
               href="<?php echo buildUrlAsignacion($total_paginas); ?>" title="Última">
                <i class="fas fa-angles-right" style="font-size:10px;"></i>
            </a>
        </div>
        <?php endif; ?>

        <!-- Registros por página -->
        <div class="paginador-rpp">
            <span>Mostrar:</span>
            <select onchange="cambiarRegistrosPorPagina(this.value)">
                <?php foreach ([25,50,100,200] as $opt): ?>
                    <option value="<?php echo $opt; ?>" <?php echo $por_pagina==$opt?'selected':''; ?>>
                        <?php echo $opt; ?>
                    </option>
                <?php endforeach; ?>
            </select>
            <span>registros</span>
        </div>
    </div>
    <?php endif; ?>
</div><!-- /card -->


<!-- ============================================================
     MODAL 1 — ASIGNAR FACTURAS
     ============================================================ -->
<div class="modal-overlay" id="modalAsignacion">
    <div class="modal-box lg">
        <div class="modal-header">
            <div class="modal-header-title">
                <div class="modal-header-icon green"><i class="fas fa-plus"></i></div>
                Asignar Facturas
            </div>
            <button class="btn-modal-close" onclick="cerrarModal('modalAsignacion')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="modal-body">
            <form id="formAsignacion" autocomplete="off">
                <div class="modal-form-row">
                    <div class="form-field">
                        <label class="form-label">Cobrador *</label>
                        <select id="cobrador_asignacion" class="form-ctrl" required>
                            <option value="">Seleccione un cobrador</option>
                            <?php foreach ($cobradores as $cob): ?>
                                <option value="<?php echo $cob['id']; ?>">
                                    <?php echo htmlspecialchars($cob['codigo'] . ' - ' . $cob['nombre_completo']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-field">
                        <label class="form-label">Fecha de Asignación *</label>
                        <input type="date" id="fecha_asignacion" class="form-ctrl" required>
                    </div>
                </div>

                <!-- Input agregar factura -->
                <div class="form-field" style="margin-bottom:8px;">
                    <label class="form-label">Número de Factura</label>
                    <div class="input-add-group">
                        <input type="text" id="numero_factura" class="form-ctrl"
                               placeholder="Ej: F-00123 — Enter o clic en + para agregar">
                        <button type="button" class="btn-add-icon" onclick="agregarFactura()" title="Agregar factura">
                            <i class="fas fa-plus"></i>
                        </button>
                    </div>
                </div>

                <!-- Lista de facturas agregadas -->
                <div id="lista_facturas" style="display:none;">
                    <div class="facturas-list-wrap">
                        <div class="facturas-list-header">
                            <i class="fas fa-list" style="margin-right:6px;color:var(--accent);"></i>
                            Facturas en la lista
                            <span id="contadorFacturasLista" style="font-size:11px;color:var(--gray-500);margin-left:6px;"></span>
                        </div>
                        <div style="overflow-x:auto;max-height:280px;overflow-y:auto;">
                            <table class="facturas-list-table">
                                <thead>
                                    <tr>
                                        <th>Factura</th>
                                        <th>Contrato</th>
                                        <th>Cliente</th>
                                        <th>Mes</th>
                                        <th>Monto</th>
                                        <th style="text-align:center;">Quitar</th>
                                    </tr>
                                </thead>
                                <tbody id="facturas_seleccionadas"></tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button class="btn btn-secondary" onclick="cerrarModal('modalAsignacion')">
                <i class="fas fa-times"></i> Cancelar
            </button>
            <button class="btn btn-primary" onclick="guardarAsignacion()">
                <i class="fas fa-save"></i> Guardar Asignación
            </button>
        </div>
    </div>
</div>


<!-- ============================================================
     MODAL 2 — IMPRIMIR RELACIÓN
     ============================================================ -->
<div class="modal-overlay" id="modalImpresion">
    <div class="modal-box lg">
        <div class="modal-header">
            <div class="modal-header-title">
                <div class="modal-header-icon blue"><i class="fas fa-print"></i></div>
                Imprimir Relación de Facturas
            </div>
            <button class="btn-modal-close" onclick="cerrarModal('modalImpresion')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="modal-body">
            <form id="formImpresion" autocomplete="off">
                <div class="modal-form-row">
                    <div class="form-field">
                        <label class="form-label">Cobrador *</label>
                        <select id="cobrador_impresion" class="form-ctrl" required>
                            <option value="">Seleccione un cobrador</option>
                            <?php foreach ($cobradores as $cob): ?>
                                <option value="<?php echo $cob['id']; ?>">
                                    <?php echo htmlspecialchars($cob['codigo'] . ' - ' . $cob['nombre_completo']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-field">
                        <label class="form-label">Fecha de Asignación *</label>
                        <input type="date" id="fecha_impresion" class="form-ctrl" required>
                    </div>
                </div>
                <div class="modal-form-row">
                    <div class="form-field">
                        <label class="form-label">Estado</label>
                        <select id="estado_impresion" class="form-ctrl">
                            <option value="">Todos los estados</option>
                            <option value="pendiente">Pendiente</option>
                            <option value="incompleta">Incompleta</option>
                            <option value="vencida">Vencida</option>
                            <option value="pagada">Pagada</option>
                        </select>
                    </div>
                    <div class="form-field" style="justify-content:flex-end;align-self:flex-end;">
                        <button type="button" class="btn btn-info" onclick="previewImpresion()">
                            <i class="fas fa-eye"></i> Vista Previa
                        </button>
                    </div>
                </div>
            </form>

            <!-- Preview -->
            <div id="preview_facturas" style="display:none;">
                <hr style="margin:18px 0;border:none;border-top:1px solid var(--gray-200);">
                <div id="preview_resumen" style="margin-bottom:10px;font-size:13px;color:var(--gray-600);"></div>
                <div style="overflow-x:auto;max-height:320px;overflow-y:auto;">
                    <table class="preview-table">
                        <thead>
                            <tr>
                                <th>Factura</th>
                                <th>Contrato</th>
                                <th>Cliente</th>
                                <th>Mes</th>
                                <th>Monto</th>
                                <th>Estado</th>
                            </tr>
                        </thead>
                        <tbody id="facturas_imprimir"></tbody>
                    </table>
                </div>
            </div>
        </div>
        <div class="modal-footer">
            <button class="btn btn-secondary" onclick="cerrarModal('modalImpresion')">
                <i class="fas fa-times"></i> Cancelar
            </button>
            <button class="btn btn-primary" onclick="imprimirRelacion()">
                <i class="fas fa-print"></i> Imprimir
            </button>
        </div>
    </div>
</div>


<!-- ============================================================
     MODAL 3 — REASIGNAR FACTURA (individual)
     ============================================================ -->
<div class="modal-overlay" id="modalReasignacion">
    <div class="modal-box md">
        <div class="modal-header">
            <div class="modal-header-title">
                <div class="modal-header-icon amber"><i class="fas fa-exchange-alt"></i></div>
                Reasignar Factura
            </div>
            <button class="btn-modal-close" onclick="cerrarModal('modalReasignacion')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="modal-body">
            <div class="modal-alert info" style="margin-bottom:16px;">
                <i class="fas fa-circle-info" style="margin-top:2px;flex-shrink:0;"></i>
                <div id="info_asignacion_actual"></div>
            </div>
            <form id="formReasignacion" autocomplete="off">
                <input type="hidden" id="asignacion_id">
                <div class="modal-form-row">
                    <div class="form-field">
                        <label class="form-label">Nuevo Cobrador *</label>
                        <select id="nuevo_cobrador" class="form-ctrl" required>
                            <option value="">Seleccione un cobrador</option>
                            <?php foreach ($cobradores as $cob): ?>
                                <option value="<?php echo $cob['id']; ?>">
                                    <?php echo htmlspecialchars($cob['codigo'] . ' - ' . $cob['nombre_completo']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-field">
                        <label class="form-label">Nueva Fecha *</label>
                        <input type="date" id="nueva_fecha" class="form-ctrl" required>
                    </div>
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button class="btn btn-secondary" onclick="cerrarModal('modalReasignacion')">
                <i class="fas fa-times"></i> Cancelar
            </button>
            <button class="btn btn-warning" onclick="confirmarReasignacion()">
                <i class="fas fa-exchange-alt"></i> Confirmar Reasignación
            </button>
        </div>
    </div>
</div>


<!-- ============================================================
     MODAL 4 — REASIGNAR EN GRUPO
     ============================================================ -->
<div class="modal-overlay" id="modalReasignacionGrupo">
    <div class="modal-box md">
        <div class="modal-header">
            <div class="modal-header-title">
                <div class="modal-header-icon teal"><i class="fas fa-layer-group"></i></div>
                Reasignar Facturas en Grupo
            </div>
            <button class="btn-modal-close" onclick="cerrarModal('modalReasignacionGrupo')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="modal-body">
            <div class="modal-alert info" style="margin-bottom:16px;">
                <i class="fas fa-circle-info" style="margin-top:2px;flex-shrink:0;"></i>
                <div>
                    Seleccione el nuevo cobrador y fecha para todas las asignaciones seleccionadas.
                    <br><strong id="textoContadorGrupo"></strong>
                </div>
            </div>
            <form id="formReasignacionGrupo" autocomplete="off">
                <input type="hidden" id="asignaciones_reasignar_ids">
                <div class="modal-form-row">
                    <div class="form-field">
                        <label class="form-label">Nuevo Cobrador *</label>
                        <select id="nuevo_cobrador_grupo" class="form-ctrl" required>
                            <option value="">Seleccione un cobrador</option>
                            <?php foreach ($cobradores as $cob): ?>
                                <option value="<?php echo $cob['id']; ?>">
                                    <?php echo htmlspecialchars($cob['codigo'] . ' - ' . $cob['nombre_completo']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-field">
                        <label class="form-label">Nueva Fecha *</label>
                        <input type="date" id="nueva_fecha_grupo" class="form-ctrl" required>
                    </div>
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button class="btn btn-secondary" onclick="cerrarModal('modalReasignacionGrupo')">
                <i class="fas fa-times"></i> Cancelar
            </button>
            <button class="btn btn-warning" onclick="confirmarReasignacionGrupo()">
                <i class="fas fa-layer-group"></i> Confirmar Reasignación Grupal
            </button>
        </div>
    </div>
</div>


<!-- ============================================================
     MODAL 5 — CONFIRMAR ELIMINACIÓN (individual)
     ============================================================ -->
<div class="modal-overlay" id="modalConfirmarEliminar">
    <div class="modal-box sm">
        <div class="modal-header">
            <div class="modal-header-title">
                <div class="modal-header-icon red"><i class="fas fa-trash"></i></div>
                Confirmar Eliminación
            </div>
            <button class="btn-modal-close" onclick="cerrarModal('modalConfirmarEliminar')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="modal-body">
            <div class="modal-alert warning">
                <i class="fas fa-triangle-exclamation" style="margin-top:2px;flex-shrink:0;"></i>
                <div>
                    ¿Está seguro que desea eliminar esta asignación?
                    <br><strong>Esta acción no se puede deshacer.</strong>
                </div>
            </div>
            <input type="hidden" id="asignacion_eliminar_id">
        </div>
        <div class="modal-footer">
            <button class="btn btn-secondary" onclick="cerrarModal('modalConfirmarEliminar')">
                <i class="fas fa-times"></i> Cancelar
            </button>
            <button class="btn btn-danger" onclick="confirmarEliminarAsignacion()">
                <i class="fas fa-trash"></i> Sí, Eliminar
            </button>
        </div>
    </div>
</div>


<!-- ============================================================
     MODAL 6 — CONFIRMAR ELIMINACIÓN MÚLTIPLE
     ============================================================ -->
<div class="modal-overlay" id="modalConfirmarEliminarGrupo">
    <div class="modal-box sm">
        <div class="modal-header">
            <div class="modal-header-title">
                <div class="modal-header-icon red"><i class="fas fa-trash-can"></i></div>
                Confirmar Eliminación Múltiple
            </div>
            <button class="btn-modal-close" onclick="cerrarModal('modalConfirmarEliminarGrupo')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="modal-body">
            <div class="modal-alert danger">
                <i class="fas fa-triangle-exclamation" style="margin-top:2px;flex-shrink:0;"></i>
                <div>
                    ¿Está seguro que desea eliminar las asignaciones seleccionadas?
                    <br><strong id="textoEliminarGrupo"></strong>
                    <br>Esta acción <strong>no se puede deshacer.</strong>
                </div>
            </div>
            <input type="hidden" id="asignaciones_eliminar_ids">
        </div>
        <div class="modal-footer">
            <button class="btn btn-secondary" onclick="cerrarModal('modalConfirmarEliminarGrupo')">
                <i class="fas fa-times"></i> Cancelar
            </button>
            <button class="btn btn-danger" onclick="confirmarEliminarGrupo()">
                <i class="fas fa-trash-can"></i> Eliminar Todas
            </button>
        </div>
    </div>
</div>


<!-- ============================================================
     MODAL 7 — FACTURA YA ASIGNADA
     ============================================================ -->
<div class="modal-overlay" id="modalFacturaAsignada">
    <div class="modal-box sm">
        <div class="modal-header">
            <div class="modal-header-title">
                <div class="modal-header-icon purple"><i class="fas fa-circle-exclamation"></i></div>
                Factura Ya Asignada
            </div>
            <button class="btn-modal-close" onclick="cerrarModal('modalFacturaAsignada')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="modal-body">
            <div class="modal-alert info">
                <i class="fas fa-circle-info" style="margin-top:2px;flex-shrink:0;"></i>
                <div id="info_factura_asignada"></div>
            </div>
            <p style="font-size:13px;color:var(--gray-600);margin-top:12px;">
                ¿Desea eliminar la asignación actual para poder incluirla en la nueva lista?
            </p>
        </div>
        <div class="modal-footer">
            <button class="btn btn-secondary" onclick="cerrarModal('modalFacturaAsignada')">
                <i class="fas fa-times"></i> Cancelar
            </button>
            <button class="btn btn-primary" onclick="confirmarReasignacionDesdeVerificacion()">
                <i class="fas fa-exchange-alt"></i> Sí, Reasignar
            </button>
        </div>
    </div>
</div>


<!-- ============================================================
     JAVASCRIPT
     ============================================================ -->
<script>
/* ════════════════════════════════════════════════════════════
   VARIABLES GLOBALES
════════════════════════════════════════════════════════════ */
let facturasSeleccionadas   = [];   // facturas en lista de nueva asignación
let facturaParaReasignar    = null; // factura pendiente en modal "Ya Asignada"

/* ════════════════════════════════════════════════════════════
   HELPERS MODALES
════════════════════════════════════════════════════════════ */
function abrirModal(id) {
    const m = document.getElementById(id);
    if (m) { m.classList.add('open'); document.body.style.overflow = 'hidden'; }
}
function cerrarModal(id) {
    const m = document.getElementById(id);
    if (m) { m.classList.remove('open'); document.body.style.overflow = ''; }
}

// Cerrar con Escape
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal-overlay.open').forEach(function(m) {
            m.classList.remove('open');
        });
        document.body.style.overflow = '';
    }
});
// Cerrar al clic en overlay
document.querySelectorAll('.modal-overlay').forEach(function(overlay) {
    overlay.addEventListener('click', function(e) {
        if (e.target === overlay) {
            overlay.classList.remove('open');
            document.body.style.overflow = '';
        }
    });
});

/* ════════════════════════════════════════════════════════════
   FILTROS — El formulario usa GET estándar
════════════════════════════════════════════════════════════ */
function cambiarRegistrosPorPagina(valor) {
    const url = new URL(window.location.href);
    url.searchParams.set('por_pagina', valor);
    url.searchParams.set('pagina', 1);
    window.location.href = url.toString();
}

// Enter en buscador
(function() {
    var cs = document.getElementById('contratoSearch');
    if (cs) cs.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') { e.preventDefault(); this.form.submit(); }
    });
})();

/* ════════════════════════════════════════════════════════════
   SELECCIÓN DE FILAS
════════════════════════════════════════════════════════════ */
function actualizarContadorSeleccionadas() {
    const cantidad = document.querySelectorAll('.seleccion-factura:checked').length;
    const btnEliminar         = document.getElementById('btnEliminarGrupo');
    const btnReasignar        = document.getElementById('btnReasignarGrupo');
    const contadorEl          = document.getElementById('contadorSeleccionadas');
    const contadorReasignar   = document.getElementById('contadorSeleccionadasReasignar');

    if (cantidad > 0) {
        btnEliminar.disabled  = false;
        btnReasignar.disabled = false;
        contadorEl.textContent        = `(${cantidad})`;
        contadorReasignar.textContent = `(${cantidad})`;
    } else {
        btnEliminar.disabled  = true;
        btnReasignar.disabled = true;
        contadorEl.textContent        = '';
        contadorReasignar.textContent = '';
    }
}

function seleccionarTodasFacturas(checkbox) {
    document.querySelectorAll('.seleccion-factura').forEach(cb => {
        cb.checked = checkbox.checked;
    });
    actualizarContadorSeleccionadas();
}

/* ════════════════════════════════════════════════════════════
   HELPERS FORMATO
════════════════════════════════════════════════════════════ */
function formatearMes(mesFactura) {
    if (!mesFactura) return '';
    const meses = {'01':'Ene','02':'Feb','03':'Mar','04':'Abr','05':'May','06':'Jun',
                   '07':'Jul','08':'Ago','09':'Sep','10':'Oct','11':'Nov','12':'Dic'};
    const partes = mesFactura.split('/');
    return (meses[partes[0]] || partes[0]) + '/' + partes[1];
}
function formatearContrato(num) {
    return num ? num.toString().padStart(5, '0') : '';
}

/* ════════════════════════════════════════════════════════════
   MODAL ASIGNAR FACTURAS
════════════════════════════════════════════════════════════ */
function abrirModalAsignacion() {
    abrirModal('modalAsignacion');
    document.getElementById('fecha_asignacion').valueAsDate = new Date();
    limpiarFormularioAsignacion();
}

function limpiarFormularioAsignacion() {
    document.getElementById('formAsignacion').reset();
    document.getElementById('fecha_asignacion').valueAsDate = new Date();
    document.getElementById('facturas_seleccionadas').innerHTML = '';
    document.getElementById('lista_facturas').style.display = 'none';
    facturasSeleccionadas = [];
}

// Enter en campo factura
document.getElementById('numero_factura').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') { e.preventDefault(); agregarFactura(); }
});

async function agregarFactura() {
    const numeroFactura = document.getElementById('numero_factura').value.trim();
    if (!numeroFactura) return;

    // Verificar si ya está en la lista
    if (facturasSeleccionadas.some(f => f.numero_factura === numeroFactura)) {
        mostrarToast('Esta factura ya está en la lista', 'warning');
        document.getElementById('numero_factura').value = '';
        return;
    }

    try {
        const response = await fetch(`verificar_asignacion.php?numero_factura=${encodeURIComponent(numeroFactura)}`);
        const data     = await response.json();

        if (!data.success) {
            mostrarToast(data.message || 'Factura no encontrada o no está pendiente', 'error');
            return;
        }

        if (data.asignada) {
            // Mostrar modal "Factura Ya Asignada"
            mostrarModalFacturaAsignada(data.factura, data.asignacion);
            document.getElementById('numero_factura').value = '';
            return;
        }

        agregarFacturaALista(data.factura);
        document.getElementById('numero_factura').value = '';

    } catch (error) {
        console.error('Error:', error);
        mostrarToast('Error al verificar la factura', 'error');
    }
}

function agregarFacturaALista(factura) {
    if (facturasSeleccionadas.some(f => f.id === factura.id)) {
        mostrarToast('Esta factura ya está en la lista', 'warning');
        return;
    }
    facturasSeleccionadas.unshift(factura);
    actualizarTablaFacturas();
}

function actualizarTablaFacturas() {
    const tbody = document.getElementById('facturas_seleccionadas');
    tbody.innerHTML = '';

    facturasSeleccionadas.forEach((factura, index) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td style="font-family:monospace;font-size:12px;font-weight:700;color:var(--accent);">
                ${factura.numero_factura}
            </td>
            <td style="font-family:monospace;font-size:12px;">${formatearContrato(factura.numero_contrato)}</td>
            <td style="font-weight:600;font-size:12.5px;">${factura.cliente_nombre} ${factura.cliente_apellidos}</td>
            <td style="font-size:12px;">${formatearMes(factura.mes_factura)}</td>
            <td style="font-weight:700;">RD$${parseFloat(factura.monto).toFixed(2)}</td>
            <td style="text-align:center;">
                <button type="button"
                        style="width:26px;height:26px;border:none;background:#FEF2F2;color:#DC2626;
                               border-radius:6px;cursor:pointer;font-size:12px;display:inline-flex;
                               align-items:center;justify-content:center;"
                        onclick="removerFactura(${index})" title="Quitar">
                    <i class="fas fa-times"></i>
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });

    const lista = document.getElementById('lista_facturas');
    lista.style.display = facturasSeleccionadas.length > 0 ? 'block' : 'none';

    const contador = document.getElementById('contadorFacturasLista');
    if (contador) contador.textContent = `(${facturasSeleccionadas.length} factura${facturasSeleccionadas.length !== 1 ? 's' : ''})`;
}

function removerFactura(index) {
    facturasSeleccionadas.splice(index, 1);
    actualizarTablaFacturas();
}

async function guardarAsignacion() {
    if (facturasSeleccionadas.length === 0) {
        mostrarToast('Debe agregar al menos una factura a la lista', 'warning');
        return;
    }
    const cobradorId      = document.getElementById('cobrador_asignacion').value;
    const fechaAsignacion = document.getElementById('fecha_asignacion').value;

    if (!cobradorId || !fechaAsignacion) {
        mostrarToast('Debe completar todos los campos requeridos', 'warning');
        return;
    }

    try {
        const response = await fetch('guardar_asignacion.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                cobrador_id     : cobradorId,
                fecha_asignacion: fechaAsignacion,
                facturas        : facturasSeleccionadas.map(f => f.id)
            })
        });
        const data = await response.json();

        if (data.success) {
            mostrarToast('Asignación guardada exitosamente', 'success');
            cerrarModal('modalAsignacion');
            setTimeout(() => window.location.reload(), 1500);
        } else {
            mostrarToast(data.message || 'Error al guardar la asignación', 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        mostrarToast('Error al comunicarse con el servidor', 'error');
    }
}

/* ════════════════════════════════════════════════════════════
   MODAL FACTURA YA ASIGNADA
════════════════════════════════════════════════════════════ */
function mostrarModalFacturaAsignada(factura, asignacionActual) {
    facturaParaReasignar = factura;

    const fecha        = new Date(asignacionActual.fecha_asignacion + 'T00:00:00');
    const meses        = ['Ene','Feb','Mar','Abr','May','Jun','Jul','Ago','Sep','Oct','Nov','Dic'];
    const fechaFmt     = `${String(fecha.getDate()).padStart(2,'0')}/${meses[fecha.getMonth()]}/${fecha.getFullYear()}`;

    document.getElementById('info_factura_asignada').innerHTML = `
        <strong>Factura:</strong> ${factura.numero_factura}<br>
        <strong>Cliente:</strong> ${factura.cliente_nombre} ${factura.cliente_apellidos}<br>
        <strong>Contrato:</strong> ${formatearContrato(factura.numero_contrato)}<br>
        <strong>Monto:</strong> RD$${parseFloat(factura.monto).toFixed(2)}<br>
        <strong>Cobrador actual:</strong> ${asignacionActual.cobrador_nombre}<br>
        <strong>Fecha actual:</strong> ${fechaFmt}
    `;
    abrirModal('modalFacturaAsignada');
}

async function confirmarReasignacionDesdeVerificacion() {
    if (!facturaParaReasignar) return;
    try {
        const response = await fetch('eliminar_asignacion_factura.php', {
            method : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body   : JSON.stringify({ factura_id: facturaParaReasignar.id })
        });
        const data = await response.json();
        if (data.success) {
            agregarFacturaALista(facturaParaReasignar);
            cerrarModal('modalFacturaAsignada');
            facturaParaReasignar = null;
        } else {
            mostrarToast(data.message || 'Error al reasignar la factura', 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        mostrarToast('Error al procesar la reasignación', 'error');
    }
}

/* ════════════════════════════════════════════════════════════
   MODAL IMPRIMIR RELACIÓN
════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('fecha_impresion').valueAsDate = new Date();
});

async function previewImpresion() {
    const cobradorId = document.getElementById('cobrador_impresion').value;
    const fecha      = document.getElementById('fecha_impresion').value;
    const estado     = document.getElementById('estado_impresion').value;

    if (!cobradorId || !fecha) {
        mostrarToast('Debe seleccionar cobrador y fecha', 'warning');
        return;
    }

    try {
        let url = `buscar_facturas_disponibles.php?cobrador_id=${cobradorId}&fecha=${fecha}`;
        if (estado) url += `&estado=${estado}`;

        const response = await fetch(url);
        const data     = await response.json();

        if (!data.success) {
            mostrarToast(data.message || 'Error al buscar facturas', 'error');
            return;
        }

        const tbody = document.getElementById('facturas_imprimir');
        tbody.innerHTML = '';

        if (data.facturas.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:20px;color:var(--gray-400);">No hay facturas para esta selección</td></tr>`;
        } else {
            data.facturas.forEach(f => {
                const badgeMap = {
                    pendiente : { bg:'#FEF3C7', color:'#B45309' },
                    pagada    : { bg:'#DCFCE7', color:'#15803D' },
                    incompleta: { bg:'#EDE9FE', color:'#7C3AED' },
                    vencida   : { bg:'#FEE2E2', color:'#DC2626' },
                };
                const b = badgeMap[f.estado] || { bg:'#F3F4F6', color:'#6B7280' };
                tbody.innerHTML += `
                    <tr>
                        <td style="font-family:monospace;font-size:12px;font-weight:700;color:var(--accent);">${f.numero_factura}</td>
                        <td style="font-family:monospace;font-size:12px;">${formatearContrato(f.numero_contrato)}</td>
                        <td style="font-weight:600;font-size:12.5px;">${f.cliente_nombre} ${f.cliente_apellidos}</td>
                        <td style="font-size:12px;">${formatearMes(f.mes_factura)}</td>
                        <td style="font-weight:700;">RD$${parseFloat(f.monto).toFixed(2)}</td>
                        <td>
                            <span style="padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;
                                         background:${b.bg};color:${b.color};">
                                ${f.estado.charAt(0).toUpperCase() + f.estado.slice(1)}
                            </span>
                        </td>
                    </tr>
                `;
            });

            // Fila total
            tbody.innerHTML += `
                <tr class="preview-total-row">
                    <td colspan="4" style="font-weight:700;font-size:12.5px;">
                        Total: ${data.totales.cantidad} factura${data.totales.cantidad !== 1 ? 's' : ''}
                    </td>
                    <td colspan="2" style="font-weight:700;font-size:13px;">
                        RD$${parseFloat(data.totales.monto).toFixed(2)}
                    </td>
                </tr>
            `;
        }

        document.getElementById('preview_resumen').innerHTML =
            `<strong>${data.totales.cantidad}</strong> factura${data.totales.cantidad !== 1 ? 's' : ''} encontrada${data.totales.cantidad !== 1 ? 's' : ''} — Total: <strong>RD$${parseFloat(data.totales.monto).toFixed(2)}</strong>`;
        document.getElementById('preview_facturas').style.display = 'block';

    } catch (error) {
        console.error('Error:', error);
        mostrarToast('Error al buscar las facturas', 'error');
    }
}

function imprimirRelacion() {
    const cobradorId = document.getElementById('cobrador_impresion').value;
    const fecha      = document.getElementById('fecha_impresion').value;
    const estado     = document.getElementById('estado_impresion').value;

    if (!cobradorId || !fecha) {
        mostrarToast('Debe seleccionar cobrador y fecha', 'warning');
        return;
    }

    let url = `imprimir_relacion.php?cobrador_id=${cobradorId}&fecha=${fecha}`;
    if (estado) url += `&estado=${estado}`;
    window.open(url, '_blank');
}

/* ════════════════════════════════════════════════════════════
   MODAL REASIGNAR INDIVIDUAL
════════════════════════════════════════════════════════════ */
async function reasignarFactura(asignacionId) {
    try {
        const response = await fetch(`obtener_asignacion.php?id=${asignacionId}`);
        const data     = await response.json();

        if (!data.success) {
            mostrarToast(data.message || 'Error al obtener la asignación', 'error');
            return;
        }

        const a    = data.asignacion;
        const fecha = new Date(a.fecha_asignacion + 'T00:00:00');
        const meses = ['Ene','Feb','Mar','Abr','May','Jun','Jul','Ago','Sep','Oct','Nov','Dic'];
        const fechaFmt = `${String(fecha.getDate()).padStart(2,'0')}/${meses[fecha.getMonth()]}/${fecha.getFullYear()}`;

        document.getElementById('asignacion_id').value = asignacionId;
        document.getElementById('info_asignacion_actual').innerHTML = `
            <strong>Factura:</strong> ${a.factura.numero_factura} &nbsp;
            <strong>Cliente:</strong> ${a.factura.cliente} &nbsp;
            <strong>Contrato:</strong> ${formatearContrato(a.factura.contrato)}<br>
            <strong>Monto:</strong> RD$${parseFloat(a.factura.monto).toFixed(2)} &nbsp;
            <strong>Cobrador actual:</strong> ${a.cobrador.nombre} &nbsp;
            <strong>Fecha actual:</strong> ${fechaFmt}
        `;
        document.getElementById('nueva_fecha').valueAsDate = new Date();
        abrirModal('modalReasignacion');

    } catch (error) {
        console.error('Error:', error);
        mostrarToast('Error al obtener la información de la asignación', 'error');
    }
}

async function confirmarReasignacion() {
    const asignacionId  = document.getElementById('asignacion_id').value;
    const nuevoCobrador = document.getElementById('nuevo_cobrador').value;
    const nuevaFecha    = document.getElementById('nueva_fecha').value;

    if (!asignacionId || !nuevoCobrador || !nuevaFecha) {
        mostrarToast('Por favor complete todos los campos', 'warning');
        return;
    }

    try {
        const response = await fetch('reasignar_asignacion.php', {
            method : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body   : JSON.stringify({
                asignacion_id   : asignacionId,
                nuevo_cobrador_id: nuevoCobrador,
                nueva_fecha     : nuevaFecha
            })
        });
        const data = await response.json();

        if (data.success) {
            mostrarToast('Factura reasignada exitosamente', 'success');
            cerrarModal('modalReasignacion');
            setTimeout(() => window.location.reload(), 1500);
        } else {
            mostrarToast(data.message || 'Error al reasignar', 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        mostrarToast('Error al comunicarse con el servidor', 'error');
    }
}

/* ════════════════════════════════════════════════════════════
   MODAL REASIGNAR GRUPO
════════════════════════════════════════════════════════════ */
function reasignarGrupo() {
    const seleccionadas = Array.from(document.querySelectorAll('.seleccion-factura:checked'))
        .map(cb => cb.dataset.asignacionId);

    if (seleccionadas.length === 0) return;

    document.getElementById('asignaciones_reasignar_ids').value = seleccionadas.join(',');
    document.getElementById('nueva_fecha_grupo').valueAsDate     = new Date();
    document.getElementById('textoContadorGrupo').textContent    =
        `Se reasignarán ${seleccionadas.length} factura${seleccionadas.length !== 1 ? 's' : ''}.`;
    document.getElementById('formReasignacionGrupo').reset();
    document.getElementById('nueva_fecha_grupo').valueAsDate = new Date();

    abrirModal('modalReasignacionGrupo');
}

async function confirmarReasignacionGrupo() {
    const idsString     = document.getElementById('asignaciones_reasignar_ids').value;
    const ids           = idsString.split(',').filter(Boolean);
    const nuevoCobrador = document.getElementById('nuevo_cobrador_grupo').value;
    const nuevaFecha    = document.getElementById('nueva_fecha_grupo').value;

    if (!nuevoCobrador || !nuevaFecha) {
        mostrarToast('Por favor complete todos los campos', 'warning');
        return;
    }

    try {
        const response = await fetch('reasignar_asignaciones_grupo.php', {
            method : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body   : JSON.stringify({
                asignaciones_ids : ids,
                nuevo_cobrador_id: nuevoCobrador,
                nueva_fecha      : nuevaFecha
            })
        });

        const text = await response.text();
        let data;
        try { data = JSON.parse(text); }
        catch(e) {
            console.error('Respuesta inválida:', text);
            mostrarToast('Error en la respuesta del servidor', 'error');
            return;
        }

        if (data.success) {
            mostrarToast(`${data.registros_procesados} asignación${data.registros_procesados !== 1 ? 'es' : ''} reasignada${data.registros_procesados !== 1 ? 's' : ''} exitosamente`, 'success');
            cerrarModal('modalReasignacionGrupo');
            setTimeout(() => window.location.reload(), 1500);
        } else {
            mostrarToast(data.message || 'Error al reasignar', 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        mostrarToast('Error al comunicarse con el servidor', 'error');
    }
}

/* ════════════════════════════════════════════════════════════
   ELIMINAR INDIVIDUAL
════════════════════════════════════════════════════════════ */
function eliminarAsignacion(asignacionId) {
    document.getElementById('asignacion_eliminar_id').value = asignacionId;
    abrirModal('modalConfirmarEliminar');
}

async function confirmarEliminarAsignacion() {
    const asignacionId = document.getElementById('asignacion_eliminar_id').value;
    try {
        const response = await fetch('eliminar_asignacion.php', {
            method : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body   : JSON.stringify({ asignacion_id: asignacionId })
        });
        const data = await response.json();

        if (data.success) {
            mostrarToast('Asignación eliminada exitosamente', 'success');
            cerrarModal('modalConfirmarEliminar');
            setTimeout(() => window.location.reload(), 1500);
        } else {
            mostrarToast(data.message || 'Error al eliminar', 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        mostrarToast('Error al comunicarse con el servidor', 'error');
    }
}

/* ════════════════════════════════════════════════════════════
   ELIMINAR GRUPO
════════════════════════════════════════════════════════════ */
function eliminarGrupo() {
    const seleccionadas = Array.from(document.querySelectorAll('.seleccion-factura:checked'))
        .map(cb => cb.dataset.asignacionId);

    if (seleccionadas.length === 0) return;

    document.getElementById('asignaciones_eliminar_ids').value = seleccionadas.join(',');
    document.getElementById('textoEliminarGrupo').textContent  =
        `Se eliminarán ${seleccionadas.length} asignación${seleccionadas.length !== 1 ? 'es' : ''}.`;

    abrirModal('modalConfirmarEliminarGrupo');
}

async function confirmarEliminarGrupo() {
    const idsString = document.getElementById('asignaciones_eliminar_ids').value;
    const ids       = idsString.split(',').filter(Boolean);

    try {
        const response = await fetch('eliminar_asignaciones_grupo.php', {
            method : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body   : JSON.stringify({ asignaciones_ids: ids })
        });

        const text = await response.text();
        let data;
        try { data = JSON.parse(text); }
        catch(e) {
            console.error('Respuesta inválida:', text);
            mostrarToast('Error en la respuesta del servidor', 'error');
            return;
        }

        if (data.success) {
            mostrarToast(`${data.registros_eliminados} asignación${data.registros_eliminados !== 1 ? 'es' : ''} eliminada${data.registros_eliminados !== 1 ? 's' : ''} exitosamente`, 'success');
            cerrarModal('modalConfirmarEliminarGrupo');
            setTimeout(() => window.location.reload(), 1500);
        } else {
            mostrarToast(data.message || 'Error al eliminar las asignaciones', 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        mostrarToast('Error al comunicarse con el servidor', 'error');
    }
}

/* ════════════════════════════════════════════════════════════
   INICIALIZACIÓN
════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', function() {
    // Fecha impresión por defecto = hoy
    const fi = document.getElementById('fecha_impresion');
    if (fi) fi.valueAsDate = new Date();
});
</script>

<?php require_once 'footer.php'; ?>