<?php
/* ============================================================
   clientes.php — Gestión de Clientes
   Sistema ORTHIIS — Seguros de Vida
   ============================================================ */
require_once 'config.php';
verificarSesion();

/* ── Helper código ─────────────────────────────────────────── */
function siguienteCodigoCliente($conn): string {
    $r = $conn->query("SELECT MAX(CAST(codigo AS UNSIGNED)) AS u FROM clientes")->fetch();
    return str_pad(($r['u'] ?? 0) + 1, 5, '0', STR_PAD_LEFT);
}

$mensaje      = '';
$tipo_mensaje = '';

/* ============================================================
   PROCESAR POST
   ============================================================ */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    try {
        $conn->beginTransaction();

        switch ($_POST['action']) {

            case 'crear':
            case 'editar':
                /* Validar cédula única */
                $s = $conn->prepare("SELECT id FROM clientes WHERE cedula=? AND id!=?");
                $s->execute([$_POST['cedula'], $_POST['id'] ?? 0]);
                if ($s->fetch()) throw new Exception("Ya existe un cliente con esta cédula.");

                if ($_POST['action'] === 'crear') {
                    $codigo = siguienteCodigoCliente($conn);
                    $conn->prepare("
                        INSERT INTO clientes
                            (codigo,nombre,apellidos,cedula,telefono1,telefono2,telefono3,
                             direccion,email,fecha_nacimiento,fecha_registro,estado,
                             cobrador_id,vendedor_id,notas)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,'activo',?,?,?)
                    ")->execute([
                        $codigo,
                        trim($_POST['nombre']),   trim($_POST['apellidos']),
                        trim($_POST['cedula']),   trim($_POST['telefono1']),
                        $_POST['telefono2'] ?? null, $_POST['telefono3'] ?? null,
                        trim($_POST['direccion']),
                        $_POST['email'] ?? null,
                        $_POST['fecha_nacimiento'] ?? null,
                        $_POST['fecha_registro'],
                        $_POST['cobrador_id'] ?: null,
                        $_POST['vendedor_id'] ?: null,
                        trim($_POST['notas'] ?? ''),
                    ]);
                    $mensaje = "Cliente registrado exitosamente.";
                } else {
                    $conn->prepare("
                        UPDATE clientes SET
                            nombre=?,apellidos=?,cedula=?,telefono1=?,telefono2=?,
                            telefono3=?,direccion=?,email=?,fecha_nacimiento=?,
                            fecha_registro=?,cobrador_id=?,vendedor_id=?,notas=?,estado=?
                        WHERE id=?
                    ")->execute([
                        trim($_POST['nombre']),   trim($_POST['apellidos']),
                        trim($_POST['cedula']),   trim($_POST['telefono1']),
                        $_POST['telefono2'] ?? null, $_POST['telefono3'] ?? null,
                        trim($_POST['direccion']),
                        $_POST['email'] ?? null,
                        $_POST['fecha_nacimiento'] ?? null,
                        $_POST['fecha_registro'],
                        $_POST['cobrador_id'] ?: null,
                        $_POST['vendedor_id'] ?: null,
                        trim($_POST['notas'] ?? ''),
                        $_POST['estado'],
                        intval($_POST['id']),
                    ]);
                    $mensaje = "Cliente actualizado exitosamente.";
                }
                $tipo_mensaje = 'success';
                break;

            case 'desactivar':
                $conn->prepare("UPDATE clientes SET estado='inactivo' WHERE id=?")
                     ->execute([intval($_POST['id'])]);
                $mensaje      = "Cliente desactivado exitosamente.";
                $tipo_mensaje = 'success';
                break;
        }
        $conn->commit();

    } catch (Exception $e) {
        if ($conn->inTransaction()) $conn->rollBack();
        $mensaje      = "Error: " . $e->getMessage();
        $tipo_mensaje = 'danger';
    }
}

/* ── Listas de apoyo ───────────────────────────────────────── */
$cobradores = $conn->query(
    "SELECT id, codigo, nombre_completo FROM cobradores WHERE estado='activo' ORDER BY nombre_completo"
)->fetchAll();

$vendedores = $conn->query(
    "SELECT id, codigo, nombre_completo FROM vendedores WHERE estado='activo' ORDER BY nombre_completo"
)->fetchAll();

$planes = $conn->query(
    "SELECT id, nombre, precio_base FROM planes WHERE estado='activo' ORDER BY nombre"
)->fetchAll();

/* ── Estadísticas KPI ──────────────────────────────────────── */
$stats = $conn->query("
    SELECT
        COUNT(*)                                          AS total,
        SUM(estado='activo')                              AS activos,
        SUM(estado='inactivo')                            AS inactivos,
        SUM(estado='suspendido')                          AS suspendidos
    FROM clientes
")->fetch();

/* ── Filtros & Paginación ──────────────────────────────────── */
$registros_por_pagina = isset($_COOKIE['clientes_por_pagina']) ? (int)$_COOKIE['clientes_por_pagina'] : 15;
$pagina_actual        = max(1, intval($_GET['pagina']  ?? 1));
$filtro_estado        = trim($_GET['estado']   ?? '');
$filtro_vendedor      = trim($_GET['vendedor'] ?? '');
$buscar               = trim($_GET['buscar']   ?? '');
$offset               = ($pagina_actual - 1) * $registros_por_pagina;

$where  = "1=1";
$params = [];

if ($filtro_estado && $filtro_estado !== 'all') {
    $where   .= " AND cl.estado = ?";
    $params[] = $filtro_estado;
}
if ($filtro_vendedor && $filtro_vendedor !== 'all') {
    $where   .= " AND cl.vendedor_id = ?";
    $params[] = intval($filtro_vendedor);
}
if ($buscar !== '') {
    $t        = "%$buscar%";
    $where   .= " AND (cl.nombre LIKE ? OR cl.apellidos LIKE ? OR cl.cedula LIKE ?
                    OR cl.telefono1 LIKE ? OR cl.codigo LIKE ?
                    OR CONCAT(cl.nombre,' ',cl.apellidos) LIKE ?)";
    array_push($params, $t, $t, $t, $t, $t, $t);
}

/* total */
$stmtCnt = $conn->prepare("SELECT COUNT(*) FROM clientes cl WHERE $where");
$stmtCnt->execute($params);
$total_registros = (int)$stmtCnt->fetchColumn();
$total_paginas   = max(1, ceil($total_registros / $registros_por_pagina));

/* listado */
$sql = "
    SELECT cl.*,
           cb.nombre_completo AS cobrador_nombre,
           vd.nombre_completo AS vendedor_nombre,
           (SELECT COUNT(DISTINCT c.id)
            FROM contratos c WHERE c.cliente_id = cl.id AND c.estado='activo') AS contratos_activos,
           (SELECT COUNT(DISTINCT d.id)
            FROM contratos c
            JOIN dependientes d ON d.contrato_id = c.id
            WHERE c.cliente_id = cl.id AND d.estado='activo') AS total_dependientes
    FROM clientes cl
    LEFT JOIN cobradores cb ON cl.cobrador_id = cb.id
    LEFT JOIN vendedores  vd ON cl.vendedor_id = vd.id
    WHERE $where
    ORDER BY cl.id DESC
    LIMIT ? OFFSET ?
";
$stmtList = $conn->prepare($sql);
$allParams = array_merge($params, [$registros_por_pagina, $offset]);
foreach ($allParams as $i => $v) {
    $stmtList->bindValue($i + 1, $v, is_int($v) ? PDO::PARAM_INT : PDO::PARAM_STR);
}
$stmtList->execute();
$clientes = $stmtList->fetchAll();

/* ── Helper URL paginador ──────────────────────────────────── */
function buildClienteUrl(int $p, string $buscar, string $estado, string $vendedor): string {
    $q = ['pagina' => $p];
    if ($buscar   !== '')                        $q['buscar']   = $buscar;
    if ($estado   !== '' && $estado   !== 'all') $q['estado']   = $estado;
    if ($vendedor !== '' && $vendedor !== 'all') $q['vendedor'] = $vendedor;
    return 'clientes.php?' . http_build_query($q);
}

require_once 'header.php';
?>
<!-- ============================================================
     ESTILOS ESPECÍFICOS
     ============================================================ -->
<style>
/* ── KPI CARDS ── */
.kpi-clientes {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 18px;
    margin-bottom: 24px;
}
@media(max-width:1100px){ .kpi-clientes { grid-template-columns: repeat(2,1fr); } }
@media(max-width:600px)  { .kpi-clientes { grid-template-columns: 1fr; } }

.kpi-clientes .kpi-card {
    border-radius: var(--radius);
    padding: 22px 22px 18px;
    position: relative;
    overflow: hidden;
    box-shadow: var(--shadow);
    transition: var(--transition);
    color: white;
    cursor: default;
}
.kpi-clientes .kpi-card:hover { transform: translateY(-3px); box-shadow: var(--shadow-md); }
.kpi-clientes .kpi-card::before {
    content:''; position:absolute; top:0; right:0;
    width:80px; height:80px;
    border-radius:0 var(--radius) 0 100%;
    opacity:.15; background:white;
}
.kpi-clientes .kpi-card.blue   { background: linear-gradient(135deg,#1565C0,#1976D2); }
.kpi-clientes .kpi-card.green  { background: linear-gradient(135deg,#1B5E20,#2E7D32); }
.kpi-clientes .kpi-card.red    { background: linear-gradient(135deg,#B71C1C,#C62828); }
.kpi-clientes .kpi-card.amber  { background: linear-gradient(135deg,#E65100,#F57F17); }

.kpi-clientes .kpi-label {
    font-size:11px; font-weight:600; color:rgba(255,255,255,.80);
    text-transform:uppercase; letter-spacing:.8px; margin-bottom:10px;
}
.kpi-clientes .kpi-top {
    display:flex; align-items:flex-start; justify-content:space-between; margin-bottom:6px;
}
.kpi-clientes .kpi-value {
    font-size:30px; font-weight:800; color:white; line-height:1; margin-bottom:4px;
}
.kpi-clientes .kpi-sub  { font-size:11px; color:rgba(255,255,255,.70); font-weight:500; }
.kpi-clientes .kpi-icon {
    width:48px; height:48px;
    background:rgba(255,255,255,.18); border-radius:var(--radius-sm);
    display:flex; align-items:center; justify-content:center;
    font-size:20px; color:white; flex-shrink:0;
}
.kpi-clientes .kpi-footer {
    margin-top:14px; padding-top:12px;
    border-top:1px solid rgba(255,255,255,.15);
    font-size:11.5px; color:rgba(255,255,255,.80); font-weight:600;
    display:flex; align-items:center; gap:6px;
}

/* ── Barra de filtros ── */
.filter-bar {
    background:var(--white); border:1px solid var(--gray-200);
    border-radius:var(--radius); padding:14px 18px;
    display:flex; align-items:center; gap:10px; flex-wrap:wrap;
    margin-bottom:20px; box-shadow:var(--shadow-sm);
}
.filter-bar .search-wrap { position:relative; flex:1; min-width:220px; }
.filter-bar .search-wrap input {
    width:100%; padding:9px 12px 9px 36px;
    border:1px solid var(--gray-200); border-radius:var(--radius-sm);
    font-size:13.5px; font-family:var(--font); color:var(--gray-800);
    background:var(--gray-50); transition:var(--transition);
}
.filter-bar .search-wrap input:focus {
    outline:none; border-color:var(--accent);
    background:white; box-shadow:0 0 0 3px rgba(33,150,243,.10);
}
.filter-bar .search-wrap .si {
    position:absolute; left:11px; top:50%; transform:translateY(-50%);
    color:var(--gray-400); font-size:13px; pointer-events:none;
}
.filter-bar .filter-select {
    padding:9px 10px; min-width:160px;
    border:1px solid var(--gray-200); border-radius:var(--radius-sm);
    font-size:13px; font-family:var(--font); color:var(--gray-700);
    background:var(--gray-50); cursor:pointer; transition:var(--transition);
}
.filter-bar .filter-select:focus { outline:none; border-color:var(--accent); }

/* ── Tabla ── */
.client-name  { font-weight:600; color:var(--gray-800); font-size:13px; }
.client-code  { font-size:11px; color:var(--gray-400); font-family:monospace; }
.td-muted     { color:var(--gray-400); font-size:12px; }
.td-phone     { font-size:12.5px; color:var(--gray-700); }

/* Botón dependientes */
.btn-deps {
    display:inline-flex; align-items:center; gap:5px;
    padding:4px 10px; border-radius:20px;
    border:1.5px solid var(--gray-200); background:var(--white);
    cursor:pointer; transition:var(--transition); font-size:11px; font-weight:700;
    color:var(--gray-600);
}
.btn-deps:hover { background:#F0FDF4; border-color:#16A34A; color:#16A34A; }
.btn-deps .dep-num {
    background:var(--accent); color:white; font-size:10px; font-weight:800;
    min-width:17px; height:17px; border-radius:10px;
    display:inline-flex; align-items:center; justify-content:center; padding:0 3px;
}
.btn-deps .dep-num.zero { background:var(--gray-300); }

/* ── Estado badges ── */
.badge {
    display:inline-flex; align-items:center;
    padding:4px 12px; border-radius:20px;
    font-size:11px; font-weight:700; white-space:nowrap;
}
.badge-activo     { background:#DCFCE7; color:#15803D; }
.badge-inactivo   { background:#FEE2E2; color:#DC2626; }
.badge-suspendido { background:#FEF3C7; color:#B45309; }

/* ── Botones de acción ── */
.tbl-actions { display:flex; align-items:center; justify-content:center; gap:5px; }
.btn-tbl {
    width:32px; height:32px; border-radius:var(--radius-sm); border:none;
    display:inline-flex; align-items:center; justify-content:center;
    font-size:13px; cursor:pointer; transition:var(--transition); text-decoration:none;
}
.btn-tbl:hover { transform:translateY(-2px); box-shadow:var(--shadow); }
.btn-tbl.view   { background:#EFF6FF; color:#1565C0; }
.btn-tbl.edit   { background:#FFFBEB; color:#D97706; }
.btn-tbl.del    { background:#FEF2F2; color:#DC2626; }
.btn-tbl.view:hover   { background:#1565C0; color:white; }
.btn-tbl.edit:hover   { background:#D97706; color:white; }
.btn-tbl.del:hover    { background:#DC2626; color:white; }

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
    padding:5px 8px; border:1px solid var(--gray-200); border-radius:var(--radius-sm);
    font-size:12.5px; font-family:var(--font); background:var(--white); cursor:pointer;
}

/* ── Modales ── */
.modal-overlay {
    display:none; position:fixed; inset:0; z-index:900;
    background:rgba(15,23,42,.55); backdrop-filter:blur(4px);
    align-items:center; justify-content:center; padding:20px;
}
.modal-overlay.open { display:flex; }
.modal-box {
    background:var(--white); border-radius:var(--radius-lg);
    box-shadow:var(--shadow-lg); display:flex; flex-direction:column;
    width:100%; max-height:92vh; overflow:hidden;
}
.modal-box.sm  { max-width:460px; }
.modal-box.md  { max-width:580px; }
.modal-box.lg  { max-width:760px; }
.modal-box.xl  { max-width:940px; }
.mhdr {
    padding:18px 22px; border-bottom:1px solid var(--gray-100);
    display:flex; align-items:flex-start; justify-content:space-between;
    flex-shrink:0; background:var(--white);
    border-radius:var(--radius-lg) var(--radius-lg) 0 0;
}
.mhdr-title { display:flex; align-items:center; gap:10px; font-size:16px; font-weight:700; color:var(--gray-800); }
.mhdr-sub   { font-size:12px; color:var(--gray-400); margin-top:3px; }
.modal-close-btn {
    width:32px; height:32px; border:none; background:var(--gray-100);
    border-radius:var(--radius-sm); cursor:pointer; color:var(--gray-500);
    display:flex; align-items:center; justify-content:center;
    font-size:14px; transition:var(--transition); flex-shrink:0;
}
.modal-close-btn:hover { background:var(--gray-200); color:var(--gray-700); }
.mbody  { padding:22px; overflow-y:auto; flex:1; }
.mfooter {
    padding:14px 22px; border-top:1px solid var(--gray-100);
    display:flex; justify-content:flex-end; gap:10px;
    flex-shrink:0; background:var(--gray-50);
    border-radius:0 0 var(--radius-lg) var(--radius-lg);
}
.mftr {
    padding:14px 22px; border-top:1px solid var(--gray-100);
    display:flex; justify-content:flex-end; gap:10px;
    flex-shrink:0; background:var(--gray-50);
}

/* ── Modal VER — tabs ── */
.modal-tabs {
    display:flex; gap:0; border-bottom:2px solid var(--gray-100);
    margin:0 -22px 22px; padding:0 22px; flex-wrap:wrap;
    background:var(--gray-50);
}
.modal-tab {
    padding:12px 18px; font-size:13px; font-weight:600; color:var(--gray-500);
    cursor:pointer; border:none; background:none;
    border-bottom:2.5px solid transparent; margin-bottom:-2px;
    transition:var(--transition); font-family:var(--font);
    display:flex; align-items:center; gap:6px;
}
.modal-tab:hover  { color:var(--accent); background:rgba(33,150,243,.04); }
.modal-tab.active { color:var(--accent); border-bottom-color:var(--accent); background:white; }
.tab-badge {
    font-size:10px; font-weight:800; padding:1px 7px; border-radius:10px; color:white;
}
.tab-badge.blue  { background:var(--accent); }
.tab-badge.red   { background:#E53E3E; }
.tab-badge.green { background:#16A34A; }
.tab-badge.amber { background:#D97706; }
.tab-pane { display:none; }
.tab-pane.active { display:block; }

.view-block {
    background:var(--white); border:1px solid var(--gray-200);
    border-radius:var(--radius); margin-bottom:18px; overflow:hidden;
}
.view-block:last-child { margin-bottom:0; }
.view-block-header {
    display:flex; align-items:center; gap:10px;
    padding:12px 16px; background:var(--gray-50); border-bottom:1px solid var(--gray-100);
}
.view-block-icon {
    width:32px; height:32px; border-radius:8px;
    display:flex; align-items:center; justify-content:center; font-size:13px; flex-shrink:0;
}
.view-block-icon.blue   { background:#EFF6FF; color:var(--accent); }
.view-block-icon.green  { background:#F0FDF4; color:#16A34A; }
.view-block-icon.amber  { background:#FFFBEB; color:#D97706; }
.view-block-icon.red    { background:#FEF2F2; color:#DC2626; }
.view-block-icon.purple { background:#F5F3FF; color:#7C3AED; }
.view-block-title { font-size:13px; font-weight:700; color:var(--gray-800); }
.view-block-body  { padding:16px 18px; }

.info-grid { display:grid; grid-template-columns:repeat(2,1fr); gap:14px 24px; }
@media(max-width:560px){ .info-grid { grid-template-columns:1fr; } }
.info-grid.cols-3 { grid-template-columns:repeat(3,1fr); }
@media(max-width:700px){ .info-grid.cols-3 { grid-template-columns:repeat(2,1fr); } }

.info-item { display:flex; flex-direction:column; gap:3px; }
.info-label {
    font-size:10.5px; color:var(--gray-400); font-weight:700;
    text-transform:uppercase; letter-spacing:.5px;
}
.info-value { font-size:13.5px; color:var(--gray-800); font-weight:500; }
.info-value.mono { font-family:monospace; font-size:13px; color:var(--accent); font-weight:700; }

.view-stats-row { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; }
@media(max-width:600px){ .view-stats-row { grid-template-columns:repeat(2,1fr); } }
.view-stat-card {
    text-align:center; padding:14px 10px; border-radius:var(--radius-sm);
    border:1px solid var(--gray-100); background:var(--gray-50);
}
.view-stat-card .stat-num { font-size:20px; font-weight:800; color:var(--gray-800); line-height:1; }
.view-stat-card .stat-lbl {
    font-size:10.5px; font-weight:600; color:var(--gray-400);
    text-transform:uppercase; letter-spacing:.4px; margin-top:4px;
}
.view-stat-card.accent .stat-num { color:var(--accent); }
.view-stat-card.green  .stat-num { color:#16A34A; }
.view-stat-card.amber  .stat-num { color:#D97706; }
.view-stat-card.red    .stat-num { color:#DC2626; }

.mini-table { width:100%; border-collapse:collapse; font-size:13px; }
.mini-table th {
    padding:10px 14px; background:var(--gray-50);
    font-size:10.5px; font-weight:700; color:var(--gray-400);
    text-transform:uppercase; letter-spacing:.5px;
    border-bottom:1px solid var(--gray-100); white-space:nowrap;
}
.mini-table td {
    padding:11px 14px; border-bottom:1px solid var(--gray-100);
    color:var(--gray-700); vertical-align:middle;
}
.mini-table tr:last-child td { border-bottom:none; }
.mini-table tr:hover td { background:var(--gray-50); }

/* ── Formulario en modal ── */
.fsec-title {
    font-size:11px; font-weight:700; color:var(--gray-400);
    text-transform:uppercase; letter-spacing:.8px;
    margin:18px 0 12px; padding-bottom:8px;
    border-bottom:1px solid var(--gray-100);
    display:flex; align-items:center; gap:6px;
}
.fsec-title:first-child { margin-top:0; }
.form-grid { display:grid; gap:14px; }
.form-grid.cols-2 { grid-template-columns:repeat(2,1fr); }
.form-grid.cols-3 { grid-template-columns:repeat(3,1fr); }
@media(max-width:580px){ .form-grid.cols-2,.form-grid.cols-3 { grid-template-columns:1fr; } }
.form-group { display:flex; flex-direction:column; gap:5px; }
.form-label { font-size:12.5px; font-weight:600; color:var(--gray-600); }
.form-label.required::after { content:' *'; color:var(--red-light); }
.form-control {
    padding:9px 12px; border:1px solid var(--gray-200);
    border-radius:var(--radius-sm); font-size:13.5px;
    font-family:var(--font); color:var(--gray-800);
    background:var(--white); transition:var(--transition);
}
.form-control:focus { outline:none; border-color:var(--accent); box-shadow:0 0 0 3px rgba(33,150,243,.10); }
.form-control[readonly] { background:var(--gray-50); color:var(--gray-500); }
textarea.form-control { resize:vertical; min-height:80px; }

/* ── Dependientes ── */
.dep-empty {
    text-align:center; padding:30px 20px; color:var(--gray-400); font-size:13px;
}
.dep-empty i { font-size:30px; display:block; margin-bottom:10px; opacity:.4; }
.dep-card {
    background:var(--white); border:1px solid var(--gray-200);
    border-radius:var(--radius-sm); padding:14px 16px; margin-bottom:10px;
    display:flex; align-items:center; gap:12px;
    transition:var(--transition);
}
.dep-card:hover { box-shadow:var(--shadow-sm); }
.dep-card:last-child { margin-bottom:0; }
.dep-avatar {
    width:38px; height:38px; border-radius:50%;
    display:flex; align-items:center; justify-content:center;
    font-size:13px; font-weight:700; color:white;
    background:linear-gradient(135deg,#16A34A,#2E7D32);
    flex-shrink:0;
}
.dep-info { flex:1; }
.dep-name { font-size:13.5px; font-weight:700; color:var(--gray-800); }
.dep-meta { font-size:11.5px; color:var(--gray-400); margin-top:2px; }
.dep-actions { display:flex; gap:5px; flex-shrink:0; }

/* ── Selector de contrato ── */
.contrato-selector-wrap {
    background:var(--gray-50); border:1px solid var(--gray-200);
    border-radius:var(--radius-sm); padding:14px 16px; margin-bottom:16px;
}
.contrato-selector-label { font-size:12px; font-weight:600; color:var(--gray-600); margin-bottom:8px; }
.contratos-btns { display:flex; flex-wrap:wrap; gap:8px; }
.btn-contrato-sel {
    padding:6px 14px; border-radius:20px; font-size:12px; font-weight:700;
    border:1.5px solid var(--gray-200); background:var(--white);
    cursor:pointer; transition:var(--transition); color:var(--gray-600);
    font-family:var(--font);
}
.btn-contrato-sel:hover, .btn-contrato-sel.active {
    background:var(--accent); color:white; border-color:var(--accent);
}

/* ── Alerts globales ── */
.alert-global {
    padding:12px 18px; border-radius:var(--radius-sm); margin-bottom:20px;
    display:flex; align-items:center; gap:10px;
    font-size:13.5px; font-weight:500; animation:slideDown .3s ease;
}
.alert-global.success { background:#F0FDF4; color:#15803D; border:1px solid #BBF7D0; }
.alert-global.danger  { background:#FEF2F2; color:#DC2626; border:1px solid #FCA5A5; }
@keyframes slideDown { from{opacity:0;transform:translateY(-10px)} to{opacity:1;transform:translateY(0)} }

/* ── Spinner ── */
.spinner {
    width:36px; height:36px; border:3px solid var(--gray-200);
    border-top-color:var(--accent); border-radius:50%;
    animation:spin .7s linear infinite; margin:40px auto;
}
@keyframes spin { to { transform:rotate(360deg); } }

/* ── Modal aviso geriátrico ── */
.modal-alert {
    display:flex; align-items:flex-start; gap:10px;
    padding:12px 14px; border-radius:var(--radius-sm);
    font-size:13px; margin-top:14px;
}
.modal-alert.warn { background:#FEF3C7; border:1px solid #FDE68A; color:#92400E; }

/* ── Botones ── */
.btn {
    display:inline-flex; align-items:center; gap:7px;
    padding:9px 18px; border-radius:var(--radius-sm); border:none;
    font-size:13.5px; font-weight:600; font-family:var(--font);
    cursor:pointer; transition:var(--transition); text-decoration:none; white-space:nowrap;
}
.btn-primary   { background:var(--accent); color:white; }
.btn-primary:hover   { background:#1565C0; color:white; }
.btn-secondary { background:var(--gray-200); color:var(--gray-700); }
.btn-secondary:hover { background:var(--gray-300); }
.btn-danger    { background:#FEE2E2; color:#DC2626; }
.btn-danger:hover    { background:#DC2626; color:white; }
.btn-green     { background:#DCFCE7; color:#15803D; }
.btn-green:hover     { background:#16A34A; color:white; }
.btn-sm { padding:7px 14px; font-size:12.5px; }

/* ── Fade in ── */
.fade-in { animation:fadeIn .4s ease both; }
.delay-1 { animation-delay:.10s; }
.delay-2 { animation-delay:.20s; }
@keyframes fadeIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
</style>

<?php /* PAGE HEADER */ ?>
<div class="page-header fade-in">
    <div>
        <div class="page-title">Gestión de Clientes</div>
        <div class="page-subtitle">
            <?php echo number_format($total_registros); ?> cliente<?php echo $total_registros !== 1 ? 's' : ''; ?>
            <?php echo ($filtro_estado || $filtro_vendedor || $buscar) ? 'encontrados' : 'registrados en el sistema'; ?>
        </div>
    </div>
    <div class="page-header-actions">
        <button class="btn btn-primary" onclick="abrirModalNuevoCliente()">
            <i class="fas fa-user-plus"></i> Nuevo Cliente
        </button>
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
<div class="kpi-clientes fade-in delay-1">
    <div class="kpi-card blue">
        <div class="kpi-label">Total Clientes</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo number_format($stats['total']); ?></div>
                <div class="kpi-sub">Registrados en el sistema</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-users"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-database"></i> Todos los clientes</div>
    </div>

    <div class="kpi-card green">
        <div class="kpi-label">Clientes Activos</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo number_format($stats['activos']); ?></div>
                <div class="kpi-sub">Con contratos vigentes</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-user-check"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-arrow-trend-up"></i> Vigentes</div>
    </div>

    <div class="kpi-card red">
        <div class="kpi-label">Inactivos</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo number_format($stats['inactivos']); ?></div>
                <div class="kpi-sub">Clientes desactivados</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-user-slash"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-ban"></i> Dados de baja</div>
    </div>

    <div class="kpi-card amber">
        <div class="kpi-label">Suspendidos</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo number_format($stats['suspendidos']); ?></div>
                <div class="kpi-sub">Temporalmente pausados</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-user-clock"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-clock"></i> En espera</div>
    </div>
</div>

<!-- ============================================================
     BARRA DE BÚSQUEDA Y FILTROS
     ============================================================ -->
<div class="filter-bar-h fade-in delay-2">
    <form method="GET" action="clientes.php" id="formFiltrosClientes">
        <div class="filter-row-fields">
            <!-- Búsqueda -->
            <div class="filter-field field-search">
                <label for="buscarClientes">
                    <i class="fas fa-search"></i> Buscar
                </label>
                <div class="search-wrap-h">
                    <i class="fas fa-search search-icon-h"></i>
                    <input type="text"
                           id="buscarClientes"
                           name="buscar"
                           class="filter-input"
                           placeholder="Nombre, apellido, cédula o teléfono…"
                           value="<?php echo htmlspecialchars($buscar); ?>"
                           autocomplete="off">
                </div>
            </div>
            <!-- Estado -->
            <div class="filter-field field-select">
                <label for="estadoClientes"><i class="fas fa-circle-half-stroke"></i> Estado</label>
                <select id="estadoClientes" name="estado" class="filter-select-h" onchange="this.form.submit()">
                    <option value="all">Todos</option>
                    <option value="activo"     <?php echo $filtro_estado === 'activo'     ? 'selected' : ''; ?>>Activos</option>
                    <option value="inactivo"   <?php echo $filtro_estado === 'inactivo'   ? 'selected' : ''; ?>>Inactivos</option>
                    <option value="suspendido" <?php echo $filtro_estado === 'suspendido' ? 'selected' : ''; ?>>Suspendidos</option>
                </select>
            </div>
            <!-- Vendedor -->
            <div class="filter-field field-select">
                <label for="vendedorClientes"><i class="fas fa-user-tie"></i> Vendedor</label>
                <select id="vendedorClientes" name="vendedor" class="filter-select-h" onchange="this.form.submit()">
                    <option value="all">Todos los vendedores</option>
                    <?php foreach ($vendedores as $v): ?>
                        <option value="<?php echo $v['id']; ?>"
                                <?php echo $filtro_vendedor == $v['id'] ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($v['nombre_completo']); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
        </div>
        <div class="filter-row-btns">
            <button type="submit" class="btn btn-primary btn-sm">
                <i class="fas fa-search"></i> Buscar
            </button>
            <?php if ($buscar || ($filtro_estado && $filtro_estado !== 'all') || ($filtro_vendedor && $filtro_vendedor !== 'all')): ?>
                <a href="clientes.php" class="btn btn-secondary btn-sm">
                    <i class="fas fa-times"></i> Limpiar
                </a>
            <?php endif; ?>
            <div class="filter-results-info">
                <?php echo number_format($total_registros); ?> cliente<?php echo $total_registros !== 1 ? 's' : ''; ?>
            </div>
        </div>
    </form>
</div>

<!-- ============================================================
     TABLA DE CLIENTES
     ============================================================ -->
<div class="card fade-in">
    <div class="card-header">
        <div>
            <div class="card-title">Lista de Clientes</div>
            <div class="card-subtitle">
                Mostrando
                <?php echo $total_registros > 0 ? min($offset+1, $total_registros) : 0; ?>–<?php echo min($offset+$registros_por_pagina, $total_registros); ?>
                de <?php echo number_format($total_registros); ?> registros
                <?php if ($buscar): ?>
                    &nbsp;·&nbsp; Búsqueda: "<strong><?php echo htmlspecialchars($buscar); ?></strong>"
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div style="overflow-x:auto;">
        <table class="data-table">
            <thead>
                <tr>
                    <th>Cliente</th>
                    <th>Cédula</th>
                    <th>Teléfono</th>
                    <th>Cobrador</th>
                    <th>Vendedor</th>
                    <th style="text-align:center;">Contratos</th>
                    <th style="text-align:center;">Dependientes</th>
                    <th>Estado</th>
                    <th>Registro</th>
                    <th style="text-align:center;">Acciones</th>
                </tr>
            </thead>
            <tbody>
            <?php if (!empty($clientes)): ?>
                <?php foreach ($clientes as $cl):
                    $ini = strtoupper(substr($cl['nombre'],0,1).substr($cl['apellidos'],0,1));
                    $deps = (int)$cl['total_dependientes'];
                    $ctrs = (int)$cl['contratos_activos'];
                ?>
                <tr>
                    <td>
                        <div style="display:flex;align-items:center;gap:9px;">
                            <div style="width:34px;height:34px;border-radius:50%;
                                        background:linear-gradient(135deg,var(--accent),#1565C0);
                                        display:flex;align-items:center;justify-content:center;
                                        font-size:11px;font-weight:700;color:white;flex-shrink:0;">
                                <?php echo $ini; ?>
                            </div>
                            <div>
                                <div class="client-name">
                                    <?php echo htmlspecialchars($cl['nombre'].' '.$cl['apellidos']); ?>
                                </div>
                                <div class="client-code">Cód. <?php echo htmlspecialchars($cl['codigo']); ?></div>
                            </div>
                        </div>
                    </td>
                    <td><span class="td-muted" style="font-family:monospace;"><?php echo htmlspecialchars($cl['cedula']); ?></span></td>
                    <td><span class="td-phone"><?php echo htmlspecialchars($cl['telefono1']); ?></span></td>
                    <td><span class="td-muted"><?php echo $cl['cobrador_nombre'] ? htmlspecialchars($cl['cobrador_nombre']) : '—'; ?></span></td>
                    <td><span class="td-muted"><?php echo $cl['vendedor_nombre'] ? htmlspecialchars($cl['vendedor_nombre']) : '—'; ?></span></td>
                    <td style="text-align:center;">
                        <span style="display:inline-flex;align-items:center;gap:4px;
                                     background:<?php echo $ctrs > 0 ? '#EFF6FF' : 'var(--gray-100)'; ?>;
                                     color:<?php echo $ctrs > 0 ? 'var(--accent)' : 'var(--gray-400)'; ?>;
                                     padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;">
                            <i class="fas fa-file-contract" style="font-size:9px;"></i>
                            <?php echo $ctrs; ?>
                        </span>
                    </td>
                    <td style="text-align:center;">
                        <button class="btn-deps"
                                onclick='abrirModalDependientes(<?php echo json_encode([
                                    "id"       => $cl["id"],
                                    "nombre"   => $cl["nombre"],
                                    "apellidos"=> $cl["apellidos"],
                                    "codigo"   => $cl["codigo"],
                                ], JSON_HEX_APOS|JSON_HEX_QUOT); ?>)'
                                title="Ver / gestionar dependientes">
                            <span class="dep-num <?php echo $deps === 0 ? 'zero' : ''; ?>"><?php echo $deps; ?></span>
                            Dep.
                        </button>
                    </td>
                    <td>
                        <span class="badge badge-<?php echo $cl['estado']; ?>">
                            <?php echo ucfirst($cl['estado']); ?>
                        </span>
                    </td>
                    <td><span class="td-muted"><?php echo date('d/m/Y', strtotime($cl['fecha_registro'])); ?></span></td>
                    <td>
                        <div class="tbl-actions">
                            <button class="btn-tbl view" title="Ver detalles"
                                    onclick="verCliente(<?php echo $cl['id']; ?>)">
                                <i class="fas fa-eye"></i>
                            </button>
                            <button class="btn-tbl edit" title="Editar"
                                    onclick='editarCliente(<?php echo json_encode($cl, JSON_HEX_APOS|JSON_HEX_QUOT); ?>)'>
                                <i class="fas fa-pen"></i>
                            </button>
                            <?php if ($cl['estado'] === 'activo'): ?>
                            <button class="btn-tbl del" title="Desactivar"
                                    onclick='confirmarDesactivar(<?php echo json_encode([
                                        "id"       => $cl["id"],
                                        "nombre"   => $cl["nombre"],
                                        "apellidos"=> $cl["apellidos"],
                                        "codigo"   => $cl["codigo"],
                                        "cedula"   => $cl["cedula"],
                                        "estado"   => $cl["estado"],
                                    ], JSON_HEX_APOS|JSON_HEX_QUOT); ?>)'>
                                <i class="fas fa-ban"></i>
                            </button>
                            <?php endif; ?>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr>
                    <td colspan="10" style="text-align:center;padding:40px;color:var(--gray-400);">
                        <i class="fas fa-users" style="font-size:32px;display:block;margin-bottom:10px;opacity:.4;"></i>
                        No se encontraron clientes<?php echo ($buscar || $filtro_estado || $filtro_vendedor) ? ' con los filtros aplicados' : ''; ?>.
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
            Mostrando <strong><?php echo min($offset+1,$total_registros); ?>–<?php echo min($offset+$registros_por_pagina,$total_registros); ?></strong>
            de <strong><?php echo number_format($total_registros); ?></strong> clientes
        </div>

        <div class="paginador-pages">
            <a class="pag-btn <?php echo $pagina_actual <= 1 ? 'disabled' : ''; ?>"
               href="<?php echo buildClienteUrl(1,$buscar,$filtro_estado,$filtro_vendedor); ?>" title="Primera">
                <i class="fas fa-angles-left" style="font-size:10px;"></i>
            </a>
            <a class="pag-btn <?php echo $pagina_actual <= 1 ? 'disabled' : ''; ?>"
               href="<?php echo buildClienteUrl($pagina_actual-1,$buscar,$filtro_estado,$filtro_vendedor); ?>" title="Anterior">
                <i class="fas fa-angle-left" style="font-size:11px;"></i>
            </a>

            <?php for ($p = max(1,$pagina_actual-2); $p <= min($total_paginas,$pagina_actual+2); $p++): ?>
                <a class="pag-btn <?php echo $p===$pagina_actual?'active':''; ?>"
                   href="<?php echo buildClienteUrl($p,$buscar,$filtro_estado,$filtro_vendedor); ?>">
                    <?php echo $p; ?>
                </a>
            <?php endfor; ?>

            <a class="pag-btn <?php echo $pagina_actual >= $total_paginas ? 'disabled' : ''; ?>"
               href="<?php echo buildClienteUrl($pagina_actual+1,$buscar,$filtro_estado,$filtro_vendedor); ?>" title="Siguiente">
                <i class="fas fa-angle-right" style="font-size:11px;"></i>
            </a>
            <a class="pag-btn <?php echo $pagina_actual >= $total_paginas ? 'disabled' : ''; ?>"
               href="<?php echo buildClienteUrl($total_paginas,$buscar,$filtro_estado,$filtro_vendedor); ?>" title="Última">
                <i class="fas fa-angles-right" style="font-size:10px;"></i>
            </a>
        </div>

        <div class="paginador-rpp">
            <span>Mostrar:</span>
            <select onchange="cambiarRPP(this.value)">
                <?php foreach ([10,15,25,50,100] as $rpp): ?>
                    <option value="<?php echo $rpp; ?>" <?php echo $registros_por_pagina===$rpp?'selected':''; ?>>
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
     MODAL: VER CLIENTE (AJAX)
     ============================================================ -->
<div class="modal-overlay" id="overlayVerCliente">
    <div class="modal-box xl">
        <div class="mhdr">
            <div>
                <div class="mhdr-title">
                    <i class="fas fa-user-circle" style="color:var(--accent);"></i>
                    <span id="verClienteTitulo">Detalles del Cliente</span>
                </div>
                <div class="mhdr-sub" id="verClienteSubtitulo"></div>
            </div>
            <button class="modal-close-btn" onclick="cerrarOverlay('overlayVerCliente')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="mbody" id="verClienteBody">
            <div class="spinner"></div>
        </div>
        <div class="mfooter">
            <a id="btnVerClienteCompleto" href="#" target="_blank" class="btn btn-secondary btn-sm">
                <i class="fas fa-external-link-alt"></i> Ver página completa
            </a>
            <button class="btn btn-primary btn-sm" onclick="cerrarOverlay('overlayVerCliente')">
                <i class="fas fa-check"></i> Cerrar
            </button>
        </div>
    </div>
</div>


<!-- ============================================================
     MODAL: CREAR / EDITAR CLIENTE
     ============================================================ -->
<div class="modal-overlay" id="overlayCliente">
    <div class="modal-box lg">
        <div class="mhdr">
            <div class="mhdr-title" id="modalClienteTitulo">
                <i class="fas fa-user-plus" style="color:var(--accent);"></i>
                <span id="textoTituloCliente">Nuevo Cliente</span>
            </div>
            <button class="modal-close-btn" onclick="cerrarOverlay('overlayCliente')">
                <i class="fas fa-times"></i>
            </button>
        </div>

        <form id="clienteForm" method="POST">
            <div class="mbody">
                <input type="hidden" name="action" id="clienteAction" value="crear">
                <input type="hidden" name="id"     id="clienteId"     value="">

                <div class="fsec-title"><i class="fas fa-id-card"></i> Datos Personales</div>
                <div class="form-grid cols-3">
                    <div class="form-group">
                        <label class="form-label">Código</label>
                        <input type="text" id="codigoCl" class="form-control" readonly
                               value="Se generará automáticamente">
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="cl_nombre">Nombre</label>
                        <input type="text" name="nombre" id="cl_nombre" class="form-control"
                               required placeholder="Nombre(s)">
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="cl_apellidos">Apellidos</label>
                        <input type="text" name="apellidos" id="cl_apellidos" class="form-control"
                               required placeholder="Apellidos">
                    </div>
                </div>

                <div class="form-grid cols-2" style="margin-top:14px;">
                    <div class="form-group">
                        <label class="form-label required" for="cl_cedula">Cédula / Identif.</label>
                        <input type="text" name="cedula" id="cl_cedula" class="form-control"
                               required placeholder="000-0000000-0">
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="cl_fecha_nacimiento">Fecha de Nacimiento</label>
                        <input type="date" name="fecha_nacimiento" id="cl_fecha_nacimiento" class="form-control">
                    </div>
                </div>

                <div class="fsec-title" style="margin-top:18px;"><i class="fas fa-phone"></i> Contacto</div>
                <div class="form-grid cols-3">
                    <div class="form-group">
                        <label class="form-label required" for="cl_telefono1">Teléfono Principal</label>
                        <input type="text" name="telefono1" id="cl_telefono1" class="form-control"
                               required placeholder="809-000-0000">
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="cl_telefono2">Teléfono 2</label>
                        <input type="text" name="telefono2" id="cl_telefono2" class="form-control" placeholder="Opcional">
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="cl_telefono3">Teléfono 3</label>
                        <input type="text" name="telefono3" id="cl_telefono3" class="form-control" placeholder="Opcional">
                    </div>
                    <div class="form-group" style="grid-column:1/-1;">
                        <label class="form-label" for="cl_email">Email</label>
                        <input type="email" name="email" id="cl_email" class="form-control" placeholder="correo@ejemplo.com">
                    </div>
                </div>

                <div class="fsec-title" style="margin-top:18px;"><i class="fas fa-map-marker-alt"></i> Dirección</div>
                <div class="form-group">
                    <label class="form-label required" for="cl_direccion">Dirección</label>
                    <textarea name="direccion" id="cl_direccion" class="form-control"
                              rows="2" required placeholder="Dirección completa"></textarea>
                </div>

                <div class="fsec-title" style="margin-top:18px;"><i class="fas fa-users"></i> Asignaciones</div>
                <div class="form-grid cols-2">
                    <div class="form-group">
                        <label class="form-label" for="cl_cobrador_id">Cobrador</label>
                        <select name="cobrador_id" id="cl_cobrador_id" class="form-control">
                            <option value="">— Sin cobrador —</option>
                            <?php foreach ($cobradores as $cb): ?>
                                <option value="<?php echo $cb['id']; ?>">
                                    <?php echo htmlspecialchars($cb['codigo'].' - '.$cb['nombre_completo']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="cl_vendedor_id">Vendedor</label>
                        <select name="vendedor_id" id="cl_vendedor_id" class="form-control">
                            <option value="">— Sin vendedor —</option>
                            <?php foreach ($vendedores as $vd): ?>
                                <option value="<?php echo $vd['id']; ?>">
                                    <?php echo htmlspecialchars($vd['codigo'].' - '.$vd['nombre_completo']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="cl_fecha_registro">Fecha de Registro</label>
                        <input type="date" name="fecha_registro" id="cl_fecha_registro" class="form-control" required>
                    </div>
                </div>

                <!-- Estado — solo al editar -->
                <div id="estadoGrp" style="display:none;margin-top:14px;">
                    <div class="fsec-title"><i class="fas fa-toggle-on"></i> Estado</div>
                    <div class="form-group">
                        <label class="form-label" for="cl_estado">Estado del cliente</label>
                        <select name="estado" id="cl_estado" class="form-control">
                            <option value="activo">Activo</option>
                            <option value="inactivo">Inactivo</option>
                            <option value="suspendido">Suspendido</option>
                        </select>
                    </div>
                </div>

                <div class="form-group" style="margin-top:14px;">
                    <label class="form-label" for="cl_notas">Notas / Observaciones</label>
                    <textarea name="notas" id="cl_notas" class="form-control"
                              rows="2" placeholder="Observaciones adicionales (opcional)"></textarea>
                </div>
            </div>
            <div class="mftr">
                <button type="button" class="btn btn-secondary"
                        onclick="cerrarOverlay('overlayCliente')">
                    <i class="fas fa-times"></i> Cancelar
                </button>
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-save"></i>
                    <span id="btnClienteTexto">Guardar Cliente</span>
                </button>
            </div>
        </form>
    </div>
</div>


<!-- ============================================================
     MODAL: CONFIRMAR DESACTIVAR
     ============================================================ -->
<div class="modal-overlay" id="overlayDesactivar">
    <div class="modal-box sm">
        <div class="mhdr">
            <div class="mhdr-title" style="color:#DC2626;">
                <i class="fas fa-exclamation-triangle"></i> Desactivar Cliente
            </div>
            <button class="modal-close-btn" onclick="cerrarOverlay('overlayDesactivar')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="mbody">
            <div id="desactivarDetalles" style="margin-bottom:14px;"></div>
            <div style="background:#FEF2F2;border:1px solid #FCA5A5;border-radius:var(--radius-sm);
                        padding:14px 16px;color:#991B1B;font-size:13.5px;">
                <i class="fas fa-exclamation-circle" style="margin-right:6px;"></i>
                <strong>¿Confirmar desactivación?</strong><br>
                <span style="font-size:12.5px;opacity:.85;">
                    El estado cambiará a <strong>Inactivo</strong>. Puede revertirse editando el cliente.
                </span>
            </div>
        </div>
        <div class="mfooter">
            <button class="btn btn-secondary" onclick="cerrarOverlay('overlayDesactivar')">
                <i class="fas fa-arrow-left"></i> Volver
            </button>
            <button class="btn btn-danger" id="btnConfirmarDesactivar">
                <i class="fas fa-ban"></i> Sí, desactivar
            </button>
        </div>
    </div>
</div>


<!-- ============================================================
     MODAL: DEPENDIENTES
     ============================================================ -->
<div class="modal-overlay" id="overlayDependientes">
    <div class="modal-box xl">
        <div class="mhdr">
            <div>
                <div class="mhdr-title">
                    <i class="fas fa-user-group" style="color:#16A34A;"></i>
                    <span id="depModalNombre">Dependientes</span>
                </div>
                <div class="mhdr-sub" id="depModalSub"></div>
            </div>
            <button class="modal-close-btn" onclick="cerrarOverlay('overlayDependientes')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="mbody" id="depModalBody">
            <div class="spinner"></div>
        </div>
    </div>
</div>


<!-- ============================================================
     MODAL: FORMULARIO DEPENDIENTE (crear / editar)
     ============================================================ -->
<div class="modal-overlay" id="overlayFormDep">
    <div class="modal-box md">
        <div class="mhdr">
            <div class="mhdr-title" id="formDepTitulo">
                <i class="fas fa-user-plus" style="color:#16A34A;"></i>
                Nuevo Dependiente
            </div>
            <button class="modal-close-btn" onclick="cerrarOverlay('overlayFormDep')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <form id="formDependiente">
            <div class="mbody">
                <input type="hidden" id="dep_id"          name="id">
                <input type="hidden" id="dep_contrato_id" name="contrato_id">

                <!-- Selector múltiples contratos -->
                <div id="contratoSelectorWrap" style="display:none;">
                    <div class="contrato-selector-wrap">
                        <div class="contrato-selector-label">
                            <i class="fas fa-file-contract" style="color:var(--accent);margin-right:4px;"></i>
                            Este cliente tiene varios contratos. Seleccione uno:
                        </div>
                        <div class="contratos-btns" id="contratosBtns"></div>
                    </div>
                </div>

                <div class="fsec-title"><i class="fas fa-id-card"></i> Datos Personales</div>
                <div class="form-grid cols-2">
                    <div class="form-group">
                        <label class="form-label required">Nombre</label>
                        <input type="text" name="nombre" id="dep_nombre" class="form-control"
                               required placeholder="Nombre(s)">
                    </div>
                    <div class="form-group">
                        <label class="form-label required">Apellidos</label>
                        <input type="text" name="apellidos" id="dep_apellidos" class="form-control"
                               required placeholder="Apellidos">
                    </div>
                    <div class="form-group">
                        <label class="form-label required">Identificación</label>
                        <input type="text" name="identificacion" id="dep_identificacion"
                               class="form-control" required placeholder="Cédula o pasaporte">
                    </div>
                    <div class="form-group">
                        <label class="form-label required">Relación / Parentesco</label>
                        <input type="text" name="relacion" id="dep_relacion" class="form-control"
                               required placeholder="Ej: Hijo, Cónyuge…">
                    </div>
                    <div class="form-group">
                        <label class="form-label required">Fecha de Nacimiento</label>
                        <input type="date" name="fecha_nacimiento" id="dep_fecha_nacimiento"
                               class="form-control" required
                               onchange="verificarEdadDepPlan()">
                    </div>
                    <div class="form-group">
                        <label class="form-label required">Fecha de Registro</label>
                        <input type="date" name="fecha_registro" id="dep_fecha_registro"
                               class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Teléfono</label>
                        <input type="text" name="telefono" id="dep_telefono" class="form-control"
                               placeholder="Opcional">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Email</label>
                        <input type="email" name="email" id="dep_email" class="form-control"
                               placeholder="Opcional">
                    </div>
                    <div class="form-group" style="grid-column:1/-1;">
                        <label class="form-label required">Plan</label>
                        <select name="plan_id" id="dep_plan_id" class="form-control" required>
                            <?php foreach ($planes as $pl): ?>
                                <option value="<?php echo $pl['id']; ?>"
                                        data-precio="<?php echo $pl['precio_base']; ?>">
                                    <?php echo htmlspecialchars($pl['nombre']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-group" id="depEstadoGrp" style="display:none;grid-column:1/-1;">
                        <label class="form-label">Estado</label>
                        <select name="estado" id="dep_estado" class="form-control">
                            <option value="activo">Activo</option>
                            <option value="inactivo">Inactivo</option>
                        </select>
                    </div>
                </div>

                <!-- Aviso geriátrico -->
                <div id="aviso_geriatrico" class="modal-alert warn" style="display:none;">
                    <i class="fas fa-triangle-exclamation"></i>
                    <div>El dependiente tiene <strong>65 o más años</strong> — se asignará automáticamente al plan <strong>Geriátrico</strong>.</div>
                </div>
            </div>
            <div class="mftr">
                <button type="button" class="btn btn-secondary" onclick="cerrarOverlay('overlayFormDep')">
                    <i class="fas fa-times"></i> Cancelar
                </button>
                <button type="button" class="btn btn-green" onclick="guardarDependiente()">
                    <i class="fas fa-save"></i> Guardar Dependiente
                </button>
            </div>
        </form>
    </div>
</div>


<!-- ============================================================
     JAVASCRIPT
     ============================================================ -->
<script>
/* ═══════════════════════════════════════════════════════════
   HELPERS
═══════════════════════════════════════════════════════════ */
function abrirOverlay(id) {
    document.getElementById(id).classList.add('open');
    document.body.style.overflow = 'hidden';
}
function cerrarOverlay(id) {
    document.getElementById(id).classList.remove('open');
    document.body.style.overflow = '';
}
function esc(s)  { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function ucFirst(s) { return s ? s.charAt(0).toUpperCase()+s.slice(1) : ''; }
function numFmt(n) {
    return parseFloat(n||0).toLocaleString('es-DO',{minimumFractionDigits:2,maximumFractionDigits:2});
}
function dateFmt(d) {
    if (!d) return '—';
    var p = d.split(/[-T ]/);
    return p.length >= 3 ? p[2]+'/'+p[1]+'/'+p[0] : d;
}
function cambiarRPP(v) {
    document.cookie = 'clientes_por_pagina='+v+'; path=/; max-age=31536000';
    window.location.href = 'clientes.php';
}
function calcularEdad(fn) {
    var hoy = new Date(), nac = new Date(fn);
    var edad = hoy.getFullYear() - nac.getFullYear();
    var m = hoy.getMonth() - nac.getMonth();
    if (m < 0 || (m===0 && hoy.getDate() < nac.getDate())) edad--;
    return edad;
}

/* ═══════════════════════════════════════════════════════════
   MODAL: VER CLIENTE
═══════════════════════════════════════════════════════════ */
function verCliente(id) {
    document.getElementById('verClienteTitulo').textContent    = 'Cargando…';
    document.getElementById('verClienteSubtitulo').textContent = '';
    document.getElementById('verClienteBody').innerHTML        = '<div class="spinner"></div>';
    document.getElementById('btnVerClienteCompleto').href      = 'ver_cliente.php?id=' + id;
    abrirOverlay('overlayVerCliente');

    fetch('ajax_ver_cliente.php?id=' + id)
        .then(function(r){ return r.json(); })
        .then(function(d){ renderVerCliente(d); })
        .catch(function(){
            document.getElementById('verClienteBody').innerHTML =
                '<div style="text-align:center;padding:40px;color:#DC2626;">' +
                '<i class="fas fa-exclamation-circle" style="font-size:36px;display:block;margin-bottom:12px;"></i>' +
                '<p>No se pudo cargar la información del cliente.</p></div>';
        });
}

function infoItem(label, value, extra) {
    extra = extra || '';
    return '<div class="info-item">' +
           '<span class="info-label">' + label + '</span>' +
           '<span class="info-value ' + extra + '">' + (value || '—') + '</span></div>';
}
function vStatCard(num, lbl, cls) {
    return '<div class="view-stat-card ' + (cls||'') + '">' +
           '<div class="stat-num">' + num + '</div>' +
           '<div class="stat-lbl">' + lbl + '</div></div>';
}

function renderVerCliente(d) {
    if (d.error) {
        document.getElementById('verClienteBody').innerHTML =
            '<div style="text-align:center;padding:40px;color:#DC2626;">' +
            '<i class="fas fa-exclamation-circle" style="font-size:32px;display:block;margin-bottom:10px;"></i>' +
            '<p>' + esc(d.error) + '</p></div>';
        return;
    }

    var nombreCompleto = (d.nombre||'') + ' ' + (d.apellidos||'');
    document.getElementById('verClienteTitulo').textContent    = nombreCompleto;
    document.getElementById('verClienteSubtitulo').textContent = 'Cód. ' + (d.codigo||'') + ' · ' + ucFirst(d.estado||'');

    var badgeMap = { activo:'badge-activo', inactivo:'badge-inactivo', suspendido:'badge-suspendido' };
    var badge = '<span class="badge '+(badgeMap[d.estado]||'')+'">'+ucFirst(d.estado||'')+'</span>';

    var html = '';

    /* Tabs */
    html += '<div class="modal-tabs">' +
        '<button class="modal-tab active" onclick="showTabCl(\'tabClInfo\',this)">' +
            '<i class="fas fa-id-card"></i> Información</button>' +
        '<button class="modal-tab" onclick="showTabCl(\'tabClContratos\',this)">' +
            '<i class="fas fa-file-contract"></i> Contratos ' +
            '<span class="tab-badge blue">'+(d.contratos?d.contratos.length:0)+'</span></button>' +
        '<button class="modal-tab" onclick="showTabCl(\'tabClDependientes\',this)">' +
            '<i class="fas fa-users"></i> Dependientes ' +
            '<span class="tab-badge green">'+(d.total_dependientes||0)+'</span></button>' +
        '<button class="modal-tab" onclick="showTabCl(\'tabClFacturas\',this)">' +
            '<i class="fas fa-file-invoice"></i> Últimas Facturas ' +
            '<span class="tab-badge amber">'+(d.facturas?d.facturas.length:0)+'</span></button>' +
        '<button class="modal-tab" onclick="showTabCl(\'tabClPagos\',this)">' +
            '<i class="fas fa-money-bill-wave"></i> Pagos ' +
            '<span class="tab-badge red">'+(d.pagos?d.pagos.length:0)+'</span></button>' +
        '</div>';

    /* ── Tab Info ── */
    html += '<div id="tabClInfo" class="tab-pane active">';

    /* mini stats */
    html += '<div class="view-stats-row" style="margin-bottom:18px;">' +
        vStatCard(d.total_contratos||0, 'Contratos', 'accent') +
        vStatCard(d.total_dependientes||0, 'Dependientes', 'green') +
        vStatCard('RD$'+numFmt(d.total_pendiente||0), 'Pendiente', 'amber') +
        vStatCard('RD$'+numFmt(d.total_abonado||0), 'Abonado', 'green') +
        '</div>';

    /* datos personales */
    html += '<div class="view-block"><div class="view-block-header">' +
        '<div class="view-block-icon blue"><i class="fas fa-user"></i></div>' +
        '<div><div class="view-block-title">Datos Personales</div></div></div>' +
        '<div class="view-block-body"><div class="info-grid cols-3">' +
        infoItem('Código', esc(d.codigo), 'mono') +
        infoItem('Nombre Completo', '<strong>'+esc(nombreCompleto)+'</strong>') +
        infoItem('Cédula / Identif.', esc(d.cedula)) +
        infoItem('Fecha de Nacimiento', dateFmt(d.fecha_nacimiento)) +
        infoItem('Email', esc(d.email)) +
        infoItem('Estado', badge) +
        '</div></div></div>';

    /* contacto */
    var tels = [d.telefono1, d.telefono2, d.telefono3].filter(Boolean).map(function(t){ return esc(t); }).join(' · ') || '—';
    html += '<div class="view-block"><div class="view-block-header">' +
        '<div class="view-block-icon green"><i class="fas fa-phone"></i></div>' +
        '<div><div class="view-block-title">Contacto y Dirección</div></div></div>' +
        '<div class="view-block-body"><div class="info-grid">' +
        infoItem('Teléfonos', tels) +
        infoItem('Dirección', esc(d.direccion)) +
        infoItem('Cobrador', esc(d.cobrador_nombre)) +
        infoItem('Vendedor', esc(d.vendedor_nombre)) +
        infoItem('Fecha Registro', dateFmt(d.fecha_registro)) +
        (d.notas ? infoItem('Notas', esc(d.notas)) : '') +
        '</div></div></div>';

    html += '</div>'; /* /tabClInfo */

    /* ── Tab Contratos ── */
    html += '<div id="tabClContratos" class="tab-pane">';
    if (!d.contratos || d.contratos.length === 0) {
        html += '<div class="dep-empty"><i class="fas fa-file-contract"></i>No hay contratos registrados.</div>';
    } else {
        html += '<table class="mini-table"><thead><tr>' +
            '<th>No. Contrato</th><th>Plan</th><th>Inicio</th><th>Monto</th><th>Fact. Pend.</th><th>Estado</th>' +
            '</tr></thead><tbody>';
        d.contratos.forEach(function(c){
            var est = c.estado || '';
            var bMap = { activo:'badge-activo', suspendido:'badge-suspendido', cancelado:'badge-cancelado' };
            html += '<tr>' +
                '<td><span style="font-family:monospace;color:var(--accent);font-weight:700;">'+esc(c.numero_contrato)+'</span></td>' +
                '<td>'+esc(c.plan_nombre)+'</td>' +
                '<td>'+dateFmt(c.fecha_inicio)+'</td>' +
                '<td><strong>RD$'+numFmt(c.monto_mensual)+'</strong></td>' +
                '<td><span style="font-weight:700;color:'+(c.facturas_pendientes>0?'#DC2626':'#16A34A')+';">'+
                    (c.facturas_pendientes||0)+'</span></td>' +
                '<td><span class="badge '+(bMap[est]||'')+'">'+ucFirst(est)+'</span></td>' +
                '</tr>';
        });
        html += '</tbody></table>';
    }
    html += '</div>';

    /* ── Tab Dependientes ── */
    html += '<div id="tabClDependientes" class="tab-pane">';
    if (!d.dependientes || d.dependientes.length === 0) {
        html += '<div class="dep-empty"><i class="fas fa-users"></i>No hay dependientes registrados.</div>';
    } else {
        html += '<table class="mini-table"><thead><tr>' +
            '<th>Nombre</th><th>Relación</th><th>F. Nacimiento</th><th>Plan</th><th>Contrato</th><th>Estado</th>' +
            '</tr></thead><tbody>';
        d.dependientes.forEach(function(dep){
            html += '<tr>' +
                '<td><strong>'+esc(dep.nombre)+' '+esc(dep.apellidos)+'</strong></td>' +
                '<td>'+esc(dep.relacion||dep.parentesco||'')+'</td>' +
                '<td>'+dateFmt(dep.fecha_nacimiento)+'</td>' +
                '<td>'+esc(dep.plan_nombre)+'</td>' +
                '<td><span style="font-family:monospace;font-size:11px;color:var(--accent);">'+esc(dep.numero_contrato||'')+'</span></td>' +
                '<td><span class="badge badge-'+(dep.estado==='activo'?'activo':'inactivo')+'">'+ucFirst(dep.estado||'')+'</span></td>' +
                '</tr>';
        });
        html += '</tbody></table>';
    }
    html += '</div>';

    /* ── Tab Facturas ── */
    html += '<div id="tabClFacturas" class="tab-pane">';
    if (!d.facturas || d.facturas.length === 0) {
        html += '<div class="dep-empty"><i class="fas fa-file-invoice"></i>No hay facturas registradas.</div>';
    } else {
        html += '<table class="mini-table"><thead><tr>' +
            '<th>No. Factura</th><th>Contrato</th><th>Emisión</th><th>Monto</th><th>Estado</th>' +
            '</tr></thead><tbody>';
        d.facturas.forEach(function(f){
            var est = f.estado||'';
            var cls = est==='pagada'?'badge-activo': est==='vencida'?'badge-inactivo': est==='incompleta'?'badge-suspendido':'badge-suspendido';
            html += '<tr>' +
                '<td><span style="font-family:monospace;color:var(--accent);font-weight:700;">'+esc(f.numero_factura)+'</span></td>' +
                '<td><span style="font-family:monospace;font-size:11px;">'+esc(f.numero_contrato)+'</span></td>' +
                '<td>'+dateFmt(f.fecha_emision)+'</td>' +
                '<td><strong>RD$'+numFmt(f.monto)+'</strong></td>' +
                '<td><span class="badge '+cls+'">'+ucFirst(est)+'</span></td>' +
                '</tr>';
        });
        html += '</tbody></table>';
    }
    html += '</div>';

    /* ── Tab Pagos ── */
    html += '<div id="tabClPagos" class="tab-pane">';
    if (!d.pagos || d.pagos.length === 0) {
        html += '<div class="dep-empty"><i class="fas fa-money-bill"></i>No hay pagos registrados.</div>';
    } else {
        html += '<table class="mini-table"><thead><tr>' +
            '<th>Factura</th><th>Contrato</th><th>Fecha</th><th>Monto</th><th>Tipo</th><th>Estado</th>' +
            '</tr></thead><tbody>';
        d.pagos.forEach(function(pg){
            var est = pg.estado||'';
            var cls = est==='procesado'?'badge-activo': est==='anulado'?'badge-inactivo':'badge-suspendido';
            html += '<tr>' +
                '<td><span style="font-family:monospace;color:var(--accent);font-weight:700;">'+esc(pg.numero_factura)+'</span></td>' +
                '<td><span style="font-family:monospace;font-size:11px;">'+esc(pg.numero_contrato||'')+'</span></td>' +
                '<td>'+dateFmt(pg.fecha_pago)+'</td>' +
                '<td><strong>RD$'+numFmt(pg.monto)+'</strong></td>' +
                '<td>'+ucFirst(esc(pg.tipo_pago||''))+'</td>' +
                '<td><span class="badge '+cls+'">'+ucFirst(est)+'</span></td>' +
                '</tr>';
        });
        html += '</tbody></table>';
    }
    html += '</div>';

    document.getElementById('verClienteBody').innerHTML = html;
}

function showTabCl(id, btn) {
    document.querySelectorAll('#verClienteBody .tab-pane').forEach(function(p){ p.classList.remove('active'); });
    document.querySelectorAll('#verClienteBody .modal-tab').forEach(function(b){ b.classList.remove('active'); });
    document.getElementById(id).classList.add('active');
    btn.classList.add('active');
}


/* ═══════════════════════════════════════════════════════════
   MODAL: CREAR / EDITAR CLIENTE
═══════════════════════════════════════════════════════════ */
function abrirModalNuevoCliente() {
    document.getElementById('clienteForm').reset();
    document.getElementById('clienteAction').value        = 'crear';
    document.getElementById('clienteId').value            = '';
    document.getElementById('textoTituloCliente').textContent = 'Nuevo Cliente';
    document.getElementById('btnClienteTexto').textContent   = 'Guardar Cliente';
    document.getElementById('codigoCl').value             = 'Se generará automáticamente';
    document.getElementById('estadoGrp').style.display    = 'none';
    document.getElementById('cl_fecha_registro').valueAsDate = new Date();
    abrirOverlay('overlayCliente');
}

function editarCliente(cl) {
    document.getElementById('clienteForm').reset();
    document.getElementById('clienteAction').value        = 'editar';
    document.getElementById('clienteId').value            = cl.id;
    document.getElementById('textoTituloCliente').textContent = 'Editar Cliente';
    document.getElementById('btnClienteTexto').textContent   = 'Actualizar Cliente';

    document.getElementById('codigoCl').value              = cl.codigo;
    document.getElementById('cl_nombre').value             = cl.nombre;
    document.getElementById('cl_apellidos').value          = cl.apellidos;
    document.getElementById('cl_cedula').value             = cl.cedula;
    document.getElementById('cl_telefono1').value          = cl.telefono1;
    document.getElementById('cl_telefono2').value          = cl.telefono2 || '';
    document.getElementById('cl_telefono3').value          = cl.telefono3 || '';
    document.getElementById('cl_direccion').value          = cl.direccion;
    document.getElementById('cl_email').value              = cl.email || '';
    document.getElementById('cl_fecha_nacimiento').value   = cl.fecha_nacimiento || '';
    document.getElementById('cl_fecha_registro').value     = cl.fecha_registro
        ? cl.fecha_registro.split(' ')[0] : '';
    document.getElementById('cl_cobrador_id').value        = cl.cobrador_id || '';
    document.getElementById('cl_vendedor_id').value        = cl.vendedor_id || '';
    document.getElementById('cl_notas').value              = cl.notas || '';
    document.getElementById('cl_estado').value             = cl.estado || 'activo';
    document.getElementById('estadoGrp').style.display     = 'block';

    abrirOverlay('overlayCliente');
}


/* ═══════════════════════════════════════════════════════════
   MODAL: DESACTIVAR CLIENTE
═══════════════════════════════════════════════════════════ */
var _clADesactivar = null;

function confirmarDesactivar(cl) {
    _clADesactivar = cl;
    document.getElementById('desactivarDetalles').innerHTML =
        '<div style="background:var(--gray-50);border:1px solid var(--gray-200);' +
        'border-radius:var(--radius-sm);padding:14px 16px;margin-bottom:14px;">' +
        '<div style="display:grid;gap:8px;">' +
        '<div><span style="font-size:10.5px;text-transform:uppercase;letter-spacing:.5px;color:var(--gray-400);font-weight:700;">Cliente</span>' +
        '<div style="font-size:15px;font-weight:700;color:var(--gray-800);">' + esc(cl.nombre + ' ' + cl.apellidos) + '</div></div>' +
        '<div><span style="font-size:10.5px;text-transform:uppercase;letter-spacing:.5px;color:var(--gray-400);font-weight:700;">Código</span>' +
        '<div style="font-family:monospace;font-size:13px;font-weight:700;color:var(--accent);">' + esc(cl.codigo) + '</div></div>' +
        '<div><span style="font-size:10.5px;text-transform:uppercase;letter-spacing:.5px;color:var(--gray-400);font-weight:700;">Cédula</span>' +
        '<div style="font-size:13px;color:var(--gray-700);">' + esc(cl.cedula) + '</div></div>' +
        '</div></div>';
    abrirOverlay('overlayDesactivar');
}

document.getElementById('btnConfirmarDesactivar').addEventListener('click', function() {
    if (!_clADesactivar) return;
    var f = document.createElement('form');
    f.method = 'POST';
    f.innerHTML = '<input type="hidden" name="action" value="desactivar">' +
                  '<input type="hidden" name="id" value="' + _clADesactivar.id + '">';
    document.body.appendChild(f);
    f.submit();
});


/* ═══════════════════════════════════════════════════════════
   MODAL: DEPENDIENTES
═══════════════════════════════════════════════════════════ */
var _clienteSelDep  = null;
var _contratoSelDep = null;

function abrirModalDependientes(cl) {
    _clienteSelDep  = cl;
    _contratoSelDep = null;

    document.getElementById('depModalNombre').textContent =
        cl.nombre + ' ' + cl.apellidos + '  ·  Cód. ' + cl.codigo;
    document.getElementById('depModalSub').textContent = '';
    document.getElementById('depModalBody').innerHTML = '<div class="spinner"></div>';
    abrirOverlay('overlayDependientes');
    cargarDependientes(cl.id);
}

function cargarDependientes(clienteId) {
    fetch('get_dependientes.php?cliente_id=' + clienteId)
        .then(function(r){ return r.json(); })
        .then(function(data){ renderDependientes(data); })
        .catch(function(){
            document.getElementById('depModalBody').innerHTML =
                '<div class="dep-empty"><i class="fas fa-triangle-exclamation"></i>Error al cargar dependientes.</div>';
        });
}

function cargarDependientesContrato(contratoId) {
    fetch('get_dependientes.php?contrato_id=' + contratoId)
        .then(function(r){ return r.json(); })
        .then(function(data){ renderDependientes(data); })
        .catch(function(){
            document.getElementById('depModalBody').innerHTML =
                '<div class="dep-empty"><i class="fas fa-triangle-exclamation"></i>Error al cargar dependientes.</div>';
        });
}

function renderDependientes(data) {
    var body = document.getElementById('depModalBody');

    if (!data.success) {
        body.innerHTML = '<div class="dep-empty"><i class="fas fa-circle-exclamation"></i>' + esc(data.message) + '</div>';
        return;
    }

    var html = '';

    /* Múltiples contratos: mostrar selector de botones */
    if (data.multiple_contratos) {
        html += '<div class="contrato-selector-wrap" style="margin-bottom:16px;">' +
            '<div class="contrato-selector-label">' +
            '<i class="fas fa-file-contract" style="color:var(--accent);margin-right:4px;"></i>' +
            'Este cliente tiene varios contratos. Seleccione uno:</div>' +
            '<div class="contratos-btns" id="listaDepsContratosBtns">';
        data.contratos.forEach(function(c){
            html += '<button type="button" class="btn-contrato-sel" ' +
                'onclick="seleccionarContratoModal(' + c.id + ', this)">' +
                c.numero_contrato + '</button>';
        });
        html += '</div></div>';
        html += '<div id="listaDepsContrato"></div>';
        body.innerHTML = html;
        return;
    }

    /* Cabecera con botón agregar */
    html += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">' +
        '<div style="font-size:13px;color:var(--gray-500);">' +
        '<strong>' + (data.dependientes ? data.dependientes.length : 0) + '</strong> dependiente(s)' +
        (data.contrato_actual ? ' — Contrato <span style="font-family:monospace;color:var(--accent);font-weight:700;">' + esc(data.contrato_actual.numero_contrato||'') + '</span>' : '') +
        '</div>' +
        '<button class="btn btn-green btn-sm" onclick="abrirFormNuevoDep()">' +
        '<i class="fas fa-plus"></i> Nuevo Dependiente</button>' +
        '</div>';

    if (!data.dependientes || data.dependientes.length === 0) {
        html += '<div class="dep-empty" style="background:var(--gray-50);border-radius:var(--radius-sm);">' +
            '<i class="fas fa-users"></i>No hay dependientes en este contrato.</div>';
    } else {
        data.dependientes.forEach(function(d){
            var initials = ((d.nombre||'').charAt(0) + (d.apellidos||'').charAt(0)).toUpperCase();
            var isGeriatrico = d.plan_id == 5;
            html += '<div class="dep-card">' +
                '<div class="dep-avatar">' + initials + '</div>' +
                '<div class="dep-info">' +
                '<div class="dep-name">' + esc(d.nombre) + ' ' + esc(d.apellidos) +
                (isGeriatrico ? ' <span class="badge badge-suspendido" style="font-size:10px;padding:2px 8px;">Geriátrico</span>' : '') +
                '</div>' +
                '<div class="dep-meta">' +
                esc(d.relacion||'') + ' · ' + esc(d.plan_nombre||'') +
                ' · F. nac. ' + dateFmt(d.fecha_nacimiento||'') +
                '</div>' +
                '</div>' +
                '<div class="dep-actions">' +
                '<button class="btn-tbl edit" title="Editar" ' +
                'onclick=\'abrirFormEditarDep(' + JSON.stringify(d).replace(/'/g,"&#39;") + ')\'>' +
                '<i class="fas fa-pen"></i></button>' +
                '<button class="btn-tbl del" title="Eliminar" onclick="eliminarDependiente(' + d.id + ')">' +
                '<i class="fas fa-trash"></i></button>' +
                '</div>' +
                '</div>';
        });
    }

    /* Si tenemos múltiples contratos activos, actualizar el contenedor de lista */
    var listaCont = document.getElementById('listaDepsContrato');
    if (listaCont) {
        listaCont.innerHTML = html;
    } else {
        body.innerHTML = html;
    }

    /* Guardar contrato actual */
    if (data.contrato_actual) {
        _contratoSelDep = data.contrato_actual;
        document.getElementById('dep_contrato_id').value = data.contrato_actual.id;
    }
}

function seleccionarContratoModal(contratoId, btn) {
    if (!contratoId) return;

    /* Marcar botón activo */
    document.querySelectorAll('#listaDepsContratosBtns .btn-contrato-sel').forEach(function(b){
        b.classList.remove('active');
    });
    if (btn) btn.classList.add('active');

    var sub = document.getElementById('listaDepsContrato');
    if (sub) sub.innerHTML = '<div class="spinner"></div>';
    _contratoSelDep = { id: contratoId };
    document.getElementById('dep_contrato_id').value = contratoId;
    cargarDependientesContrato(contratoId);
}

function actualizarContadorDep(clienteId) {
    if (!clienteId) return;
    fetch('get_dependientes.php?cliente_id=' + clienteId)
        .then(function(r){ return r.json(); })
        .then(function(data){
            /* no actualizar contador si hay múltiples contratos ya que no es una suma directa */
        });
}


/* ═══════════════════════════════════════════════════════════
   FORMULARIO DEPENDIENTE — Nuevo / Editar
═══════════════════════════════════════════════════════════ */
function abrirFormNuevoDep() {
    document.getElementById('formDepTitulo').innerHTML =
        '<i class="fas fa-user-plus" style="color:#16A34A;"></i> Nuevo Dependiente';
    document.getElementById('dep_id').value = '';
    document.getElementById('formDependiente').reset();
    document.getElementById('dep_fecha_registro').valueAsDate = new Date();
    document.getElementById('depEstadoGrp').style.display = 'none';
    document.getElementById('aviso_geriatrico').style.display = 'none';
    document.getElementById('dep_plan_id').disabled = false;

    /* Manejo de contrato */
    if (_contratoSelDep && _contratoSelDep.id) {
        document.getElementById('dep_contrato_id').value          = _contratoSelDep.id;
        document.getElementById('contratoSelectorWrap').style.display = 'none';
    } else if (_clienteSelDep) {
        document.getElementById('dep_contrato_id').value = '';
        document.getElementById('contratoSelectorWrap').style.display = 'none';
        fetch('get_dependientes.php?cliente_id=' + _clienteSelDep.id)
            .then(function(r){ return r.json(); })
            .then(function(data){
                if (data.multiple_contratos) {
                    var btns = document.getElementById('contratosBtns');
                    btns.innerHTML = data.contratos.map(function(c){
                        return '<button type="button" class="btn-contrato-sel" ' +
                            'onclick="seleccionarContratoFormDep(' + c.id + ', this)">' +
                            c.numero_contrato + '</button>';
                    }).join('');
                    document.getElementById('contratoSelectorWrap').style.display = 'block';
                } else if (data.contrato_actual) {
                    document.getElementById('dep_contrato_id').value = data.contrato_actual.id;
                    _contratoSelDep = data.contrato_actual;
                }
            });
    }

    abrirOverlay('overlayFormDep');
}

function seleccionarContratoFormDep(id, btn) {
    document.getElementById('dep_contrato_id').value = id;
    _contratoSelDep = { id: id };
    document.querySelectorAll('#contratosBtns .btn-contrato-sel').forEach(function(b){
        b.classList.remove('active');
    });
    if (btn) btn.classList.add('active');
}

function abrirFormEditarDep(dep) {
    document.getElementById('formDepTitulo').innerHTML =
        '<i class="fas fa-pen" style="color:#16A34A;"></i> Editar Dependiente';

    document.getElementById('dep_id').value               = dep.id;
    document.getElementById('dep_contrato_id').value      = dep.contrato_id;
    document.getElementById('dep_nombre').value           = dep.nombre;
    document.getElementById('dep_apellidos').value        = dep.apellidos;
    document.getElementById('dep_identificacion').value   = dep.identificacion || '';
    document.getElementById('dep_relacion').value         = dep.relacion || '';
    document.getElementById('dep_fecha_nacimiento').value = (dep.fecha_nacimiento||'').split(' ')[0];
    document.getElementById('dep_fecha_registro').value   = (dep.fecha_registro||'').split(' ')[0];
    document.getElementById('dep_telefono').value         = dep.telefono || '';
    document.getElementById('dep_email').value            = dep.email || '';
    document.getElementById('dep_plan_id').value          = dep.plan_id;
    document.getElementById('dep_estado').value           = dep.estado || 'activo';
    document.getElementById('depEstadoGrp').style.display = 'block';
    document.getElementById('contratoSelectorWrap').style.display = 'none';
    document.getElementById('dep_plan_id').disabled       = false;

    verificarEdadDepPlan();
    abrirOverlay('overlayFormDep');
}

function cerrarFormDep() {
    cerrarOverlay('overlayFormDep');
}

function verificarEdadDepPlan() {
    var fn   = document.getElementById('dep_fecha_nacimiento').value;
    if (!fn) return;
    var edad = calcularEdad(fn);
    var aviso  = document.getElementById('aviso_geriatrico');
    var planSel = document.getElementById('dep_plan_id');

    if (edad >= 65) {
        planSel.value    = '5';
        planSel.disabled = true;
        aviso.style.display = 'flex';
    } else {
        planSel.disabled = false;
        aviso.style.display = 'none';
    }
}

function guardarDependiente() {
    var form      = document.getElementById('formDependiente');
    var formData  = new FormData(form);
    var isEdit    = !!document.getElementById('dep_id').value;
    var contratoId = document.getElementById('dep_contrato_id').value;

    if (!contratoId) {
        mostrarToast('Debe seleccionar un contrato.', 'error');
        return;
    }

    formData.append('action', isEdit ? 'editar' : 'crear');
    if (document.getElementById('dep_plan_id').disabled) {
        formData.set('plan_id', '5');
    }

    fetch('dependientes.php', { method:'POST', body:formData })
        .then(function(r){ return r.json(); })
        .then(function(data){
            if (data.success) {
                cerrarOverlay('overlayFormDep');
                mostrarToast(data.message || 'Dependiente guardado exitosamente.', 'success');
                /* Recargar lista */
                if (_contratoSelDep && _contratoSelDep.id) {
                    cargarDependientesContrato(_contratoSelDep.id);
                } else if (_clienteSelDep) {
                    cargarDependientes(_clienteSelDep.id);
                }
            } else {
                mostrarToast(data.message || 'Error al guardar el dependiente.', 'error');
            }
        })
        .catch(function(){ mostrarToast('Error de comunicación con el servidor.', 'error'); });
}

function eliminarDependiente(id) {
    if (!confirm('¿Está seguro de que desea eliminar este dependiente?')) return;

    fetch('dependientes.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=eliminar&id=' + id
    })
    .then(function(r){ return r.json(); })
    .then(function(data){
        if (data.success) {
            mostrarToast('Dependiente eliminado.', 'success');
            if (_contratoSelDep && _contratoSelDep.id) {
                cargarDependientesContrato(_contratoSelDep.id);
            } else if (_clienteSelDep) {
                cargarDependientes(_clienteSelDep.id);
            }
        } else {
            mostrarToast(data.message || 'Error al eliminar.', 'error');
        }
    })
    .catch(function(){ mostrarToast('Error de comunicación.', 'error'); });
}

/* Auto-ocultar alerta */
(function() {
    var a = document.getElementById('alertaGlobal');
    if (a) setTimeout(function(){
        a.style.opacity = '0'; a.style.transition = 'opacity .5s';
        setTimeout(function(){ a.remove(); }, 500);
    }, 5000);
})();
</script>

<?php require_once 'footer.php'; ?>