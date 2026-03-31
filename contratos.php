<?php
/* ============================================================
   contratos.php — Gestión de Contratos
   Sistema ORTHIIS — Seguros de Vida
   ============================================================ */
require_once 'config.php';
verificarSesion();

/* ── Helpers ──────────────────────────────────────────────── */
function siguienteNumeroContrato($conn): string {
    $r = $conn->query("SELECT MAX(CAST(NULLIF(numero_contrato,'') AS UNSIGNED)) AS u FROM contratos")->fetch();
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

            /* ── CREAR ── */
            case 'crear':
                if (empty($_POST['cliente_id'])) throw new Exception('Debe seleccionar un cliente.');

                $s = $conn->prepare("SELECT id FROM clientes WHERE id=? AND estado='activo'");
                $s->execute([$_POST['cliente_id']]);
                if (!$s->fetch()) throw new Exception('Cliente no encontrado o inactivo.');

                $num = siguienteNumeroContrato($conn);
                $conn->prepare("
                    INSERT INTO contratos
                        (numero_contrato,cliente_id,plan_id,fecha_inicio,fecha_fin,
                         monto_mensual,monto_total,dia_cobro,estado,vendedor_id,notas)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                ")->execute([
                    $num,
                    intval($_POST['cliente_id']),
                    intval($_POST['plan_id']),
                    $_POST['fecha_inicio'],
                    $_POST['fecha_fin'] ?: null,
                    floatval($_POST['monto_mensual']),
                    floatval($_POST['monto_total']),
                    intval($_POST['dia_cobro']),
                    $_POST['estado'] ?? 'activo',
                    intval($_POST['vendedor_id']) ?: null,
                    trim($_POST['notas'] ?? ''),
                ]);
                $contrato_id = $conn->lastInsertId();

                /* beneficiarios nuevos */
                if (!empty($_POST['beneficiarios'])) {
                    $stmtBen = $conn->prepare("
                        INSERT INTO beneficiarios (contrato_id,nombre,apellidos,parentesco,porcentaje,fecha_nacimiento)
                        VALUES (?,?,?,?,?,?)
                    ");
                    foreach ($_POST['beneficiarios'] as $b) {
                        if (!empty(trim($b['nombre'] ?? ''))) {
                            $stmtBen->execute([
                                $contrato_id, trim($b['nombre']), trim($b['apellidos'] ?? ''),
                                trim($b['parentesco'] ?? ''), floatval($b['porcentaje'] ?? 0),
                                $b['fecha_nacimiento'] ?: null,
                            ]);
                        }
                    }
                }
                $mensaje      = "Contrato <strong>$num</strong> creado exitosamente.";
                $tipo_mensaje = 'success';
                break;

            /* ── EDITAR ── */
            case 'editar':
                $id = intval($_POST['id']);
                $conn->prepare("
                    UPDATE contratos SET
                        plan_id=?, fecha_inicio=?, fecha_fin=?,
                        monto_mensual=?, monto_total=?, dia_cobro=?,
                        estado=?, vendedor_id=?, notas=?
                    WHERE id=?
                ")->execute([
                    intval($_POST['plan_id']),
                    $_POST['fecha_inicio'],
                    $_POST['fecha_fin'] ?: null,
                    floatval($_POST['monto_mensual']),
                    floatval($_POST['monto_total']),
                    intval($_POST['dia_cobro']),
                    $_POST['estado'],
                    intval($_POST['vendedor_id']) ?: null,
                    trim($_POST['notas'] ?? ''),
                    $id,
                ]);

                /* beneficiarios: eliminar y reinsertar */
                $conn->prepare("DELETE FROM beneficiarios WHERE contrato_id=?")->execute([$id]);
                if (!empty($_POST['beneficiarios'])) {
                    $stmtBen = $conn->prepare("
                        INSERT INTO beneficiarios (contrato_id,nombre,apellidos,parentesco,porcentaje,fecha_nacimiento)
                        VALUES (?,?,?,?,?,?)
                    ");
                    foreach ($_POST['beneficiarios'] as $b) {
                        if (!empty(trim($b['nombre'] ?? ''))) {
                            $stmtBen->execute([
                                $id, trim($b['nombre']), trim($b['apellidos'] ?? ''),
                                trim($b['parentesco'] ?? ''), floatval($b['porcentaje'] ?? 0),
                                $b['fecha_nacimiento'] ?: null,
                            ]);
                        }
                    }
                }
                $mensaje      = 'Contrato actualizado exitosamente.';
                $tipo_mensaje = 'success';
                break;

            /* ── CANCELAR ── */
            case 'eliminar':
                $conn->prepare("UPDATE contratos SET estado='cancelado' WHERE id=?")
                     ->execute([intval($_POST['id'])]);
                $mensaje      = 'Contrato cancelado exitosamente.';
                $tipo_mensaje = 'success';
                break;
        }
        $conn->commit();

    } catch (Exception $e) {
        if ($conn->inTransaction()) $conn->rollBack();
        $mensaje      = 'Error: ' . $e->getMessage();
        $tipo_mensaje = 'danger';
    }
}

/* ── Selectores ──────────────────────────────────────────── */
$planes = $conn->query("
    SELECT id, codigo, nombre, precio_base FROM planes WHERE estado='activo' ORDER BY nombre
")->fetchAll();

$vendedores = $conn->query("
    SELECT id, codigo, nombre_completo FROM vendedores WHERE estado='activo' ORDER BY nombre_completo
")->fetchAll();

/* ── Estadísticas KPI ────────────────────────────────────── */
$stats = $conn->query("
    SELECT
        COUNT(*)                                                AS total,
        SUM(estado='activo')                                    AS activos,
        SUM(estado='suspendido')                               AS suspendidos,
        SUM(estado='cancelado')                                AS cancelados,
        COALESCE(SUM(CASE WHEN estado='activo' THEN monto_mensual END),0) AS monto_activo
    FROM contratos
")->fetch();

/* ── Filtros y Paginación ────────────────────────────────── */
$registros_por_pagina = isset($_COOKIE['contratos_por_pagina']) ? (int)$_COOKIE['contratos_por_pagina'] : 15;
$pagina_actual        = max(1, intval($_GET['pagina']  ?? 1));
$filtro_estado        = trim($_GET['estado']   ?? '');
$filtro_vendedor      = trim($_GET['vendedor'] ?? '');
$buscar               = trim($_GET['buscar']   ?? '');
$offset               = ($pagina_actual - 1) * $registros_por_pagina;

$where  = '1=1';
$params = [];

if ($filtro_estado && $filtro_estado !== 'all') {
    $where   .= ' AND c.estado = ?';
    $params[] = $filtro_estado;
}
if ($filtro_vendedor && $filtro_vendedor !== 'all') {
    $where   .= ' AND c.vendedor_id = ?';
    $params[] = intval($filtro_vendedor);
}
if ($buscar !== '') {
    $t        = "%$buscar%";
    $where   .= " AND (c.numero_contrato LIKE ? OR cl.codigo LIKE ?
                    OR cl.nombre LIKE ? OR cl.apellidos LIKE ?
                    OR cl.cedula LIKE ? OR p.nombre LIKE ?)";
    array_push($params, $t, $t, $t, $t, $t, $t);
}

/* total */
$stmtCnt = $conn->prepare("
    SELECT COUNT(DISTINCT c.id)
    FROM contratos c
    JOIN clientes cl ON c.cliente_id = cl.id
    JOIN planes   p  ON c.plan_id    = p.id
    WHERE $where
");
$stmtCnt->execute($params);
$total_registros = (int)$stmtCnt->fetchColumn();
$total_paginas   = max(1, ceil($total_registros / $registros_por_pagina));

/* listado */
$sql = "
    SELECT c.*,
           cl.codigo       AS cliente_codigo,
           cl.nombre       AS cliente_nombre,
           cl.apellidos    AS cliente_apellidos,
           p.nombre        AS plan_nombre,
           v.nombre_completo AS vendedor_nombre,
           (SELECT COUNT(*) FROM dependientes d WHERE d.contrato_id=c.id AND d.estado='activo') AS total_dependientes
    FROM contratos c
    JOIN clientes cl ON c.cliente_id = cl.id
    JOIN planes   p  ON c.plan_id    = p.id
    LEFT JOIN vendedores v ON c.vendedor_id = v.id
    WHERE $where
    ORDER BY c.id DESC
    LIMIT ? OFFSET ?
";
$stmtList = $conn->prepare($sql);
$allParams = array_merge($params, [$registros_por_pagina, $offset]);
foreach ($allParams as $i => $val) {
    $stmtList->bindValue($i + 1, $val, is_int($val) ? PDO::PARAM_INT : PDO::PARAM_STR);
}
$stmtList->execute();
$contratos = $stmtList->fetchAll();

/* ── Helper URL paginador ─────────────────────────────────── */
function buildContratoUrl(int $pag, string $buscar, string $estado, string $vendedor): string {
    $p = ['pagina' => $pag];
    if ($buscar   !== '')                        $p['buscar']   = $buscar;
    if ($estado   !== '' && $estado   !== 'all') $p['estado']   = $estado;
    if ($vendedor !== '' && $vendedor !== 'all') $p['vendedor'] = $vendedor;
    return 'contratos.php?' . http_build_query($p);
}

require_once 'header.php';
?>
<!-- ============================================================
     ESTILOS ESPECÍFICOS DE LA PÁGINA
     ============================================================ -->
<style>
/* ── KPI CARDS ── */
.kpi-contratos {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 18px;
    margin-bottom: 24px;
}
@media(max-width:1100px){ .kpi-contratos { grid-template-columns: repeat(2,1fr); } }
@media(max-width:600px) { .kpi-contratos { grid-template-columns: 1fr; } }

.kpi-contratos .kpi-card {
    border-radius: var(--radius);
    padding: 22px 22px 18px;
    position: relative;
    overflow: hidden;
    box-shadow: var(--shadow);
    transition: var(--transition);
    color: white;
    cursor: default;
}
.kpi-contratos .kpi-card:hover { transform: translateY(-3px); box-shadow: var(--shadow-md); }
.kpi-contratos .kpi-card::before {
    content:''; position:absolute; top:0; right:0;
    width:80px; height:80px;
    border-radius:0 var(--radius) 0 100%;
    opacity:.15; background:white;
}
.kpi-contratos .kpi-card.blue  { background: linear-gradient(135deg,#1565C0,#1976D2); }
.kpi-contratos .kpi-card.green { background: linear-gradient(135deg,#1B5E20,#2E7D32); }
.kpi-contratos .kpi-card.amber { background: linear-gradient(135deg,#E65100,#F57F17); }
.kpi-contratos .kpi-card.red   { background: linear-gradient(135deg,#B71C1C,#C62828); }

.kpi-contratos .kpi-label {
    font-size:11px; font-weight:600; color:rgba(255,255,255,.80);
    text-transform:uppercase; letter-spacing:.8px; margin-bottom:10px;
}
.kpi-contratos .kpi-top {
    display:flex; align-items:flex-start; justify-content:space-between; margin-bottom:6px;
}
.kpi-contratos .kpi-value {
    font-size:30px; font-weight:800; color:white; line-height:1; margin-bottom:4px;
}
.kpi-contratos .kpi-sub { font-size:11px; color:rgba(255,255,255,.70); font-weight:500; }
.kpi-contratos .kpi-icon {
    width:48px; height:48px;
    background:rgba(255,255,255,.18); border-radius:var(--radius-sm);
    display:flex; align-items:center; justify-content:center;
    font-size:20px; color:white; flex-shrink:0;
}
.kpi-contratos .kpi-footer {
    margin-top:14px; padding-top:12px;
    border-top:1px solid rgba(255,255,255,.15);
    font-size:11.5px; color:rgba(255,255,255,.80); font-weight:600;
    display:flex; align-items:center; gap:6px;
}
.kpi-contratos .kpi-footer i { font-size:10px; }

/* ── Buscador / Filtros ── */
.filter-bar {
    background:var(--white);
    border:1px solid var(--gray-200);
    border-radius:var(--radius);
    padding:14px 18px;
    display:flex; align-items:center; gap:10px; flex-wrap:wrap;
    margin-bottom:20px;
    box-shadow:var(--shadow-sm);
}
.filter-bar .search-wrap {
    position:relative; flex:1; min-width:220px;
}
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
.filter-bar .search-wrap .search-icon {
    position:absolute; left:11px; top:50%; transform:translateY(-50%);
    color:var(--gray-400); font-size:13px; pointer-events:none;
}
.filter-bar .filter-select {
    padding:9px 10px; min-width:160px;
    border:1px solid var(--gray-200); border-radius:var(--radius-sm);
    font-size:13px; font-family:var(--font); color:var(--gray-700);
    background:var(--gray-50); cursor:pointer; transition:var(--transition);
}
.filter-bar .filter-select:focus {
    outline:none; border-color:var(--accent);
}

/* ── Tabla ── */
.contract-num  { font-family:monospace; font-size:12.5px; font-weight:700; color:var(--accent); }
.client-name   { font-weight:600; color:var(--gray-800); font-size:13px; line-height:1.3; }
.client-code   { font-size:11px; color:var(--gray-400); font-family:monospace; }
.plan-name     { font-weight:600; color:var(--gray-700); font-size:13px; }
.td-amount     { font-weight:700; color:var(--gray-800); font-size:13px; }
.td-muted      { color:var(--gray-400); font-size:12px; }

.dep-badge {
    display:inline-flex; align-items:center; gap:4px;
    padding:3px 9px; border-radius:20px;
    border:1.5px solid var(--gray-200); background:var(--white);
    color:var(--gray-600); font-size:11px; font-weight:700;
}
.dep-badge .dep-num {
    background:var(--accent); color:white; font-size:10px; font-weight:800;
    min-width:17px; height:17px; border-radius:10px;
    display:inline-flex; align-items:center; justify-content:center; padding:0 3px;
}
.dep-badge .dep-num.zero { background:var(--gray-300); }

/* ── Estado badges ── */
.badge {
    display:inline-flex; align-items:center;
    padding:4px 12px; border-radius:20px;
    font-size:11px; font-weight:700; white-space:nowrap;
}
.badge-activo     { background:#DCFCE7; color:#15803D; }
.badge-suspendido { background:#FEF3C7; color:#B45309; }
.badge-cancelado  { background:#FEE2E2; color:#DC2626; }

/* ── Botones de acción ── */
.tbl-actions { display:flex; align-items:center; justify-content:center; gap:5px; }
.btn-tbl {
    width:32px; height:32px; border-radius:var(--radius-sm);
    border:none; display:inline-flex; align-items:center; justify-content:center;
    font-size:13px; cursor:pointer; transition:var(--transition); text-decoration:none;
}
.btn-tbl:hover { transform:translateY(-2px); box-shadow:var(--shadow); }
.btn-tbl.view   { background:#EFF6FF; color:#1565C0; }
.btn-tbl.edit   { background:#FFFBEB; color:#D97706; }
.btn-tbl.cancel { background:#FEF2F2; color:#DC2626; }
.btn-tbl.view:hover   { background:#1565C0; color:white; }
.btn-tbl.edit:hover   { background:#D97706; color:white; }
.btn-tbl.cancel:hover { background:#DC2626; color:white; }

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
.pag-btn:hover:not(.disabled) { background:var(--accent); color:white; border-color:var(--accent); box-shadow:var(--shadow-sm); }
.pag-btn.active { background:var(--accent); color:white; border-color:var(--accent); }
.pag-btn.disabled { opacity:.4; pointer-events:none; }
.paginador-rpp { display:flex; align-items:center; gap:8px; font-size:12.5px; color:var(--gray-500); }
.paginador-rpp select {
    padding:5px 8px; border:1px solid var(--gray-200); border-radius:var(--radius-sm);
    font-size:12.5px; font-family:var(--font); background:var(--white); cursor:pointer;
}

/* ── Modal overlay ── */
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
.modal-box.md  { max-width:560px; }
.modal-box.lg  { max-width:720px; }
.modal-box.xl  { max-width:900px; }
.mhdr {
    padding:18px 22px; border-bottom:1px solid var(--gray-100);
    display:flex; align-items:flex-start; justify-content:space-between;
    flex-shrink:0; background:var(--white);
    border-radius:var(--radius-lg) var(--radius-lg) 0 0;
}
.mhdr-title {
    display:flex; align-items:center; gap:10px;
    font-size:16px; font-weight:700; color:var(--gray-800);
}
.mhdr-sub { font-size:12px; color:var(--gray-400); margin-top:3px; }
.modal-close-btn {
    width:32px; height:32px; border:none; background:var(--gray-100);
    border-radius:var(--radius-sm); cursor:pointer; color:var(--gray-500);
    display:flex; align-items:center; justify-content:center;
    font-size:14px; transition:var(--transition); flex-shrink:0;
}
.modal-close-btn:hover { background:var(--gray-200); color:var(--gray-700); }
.mbody { padding:22px; overflow-y:auto; flex:1; }
.mfooter {
    padding:14px 22px; border-top:1px solid var(--gray-100);
    display:flex; justify-content:flex-end; gap:10px;
    flex-shrink:0; background:var(--gray-50);
    border-radius:0 0 var(--radius-lg) var(--radius-lg);
}

/* ── Modal VER — tabs y bloques ── */
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
.modal-tab:hover { color:var(--accent); background:rgba(33,150,243,.04); }
.modal-tab.active { color:var(--accent); border-bottom-color:var(--accent); background:white; }
.tab-badge {
    font-size:10px; font-weight:800; padding:1px 7px; border-radius:10px; color:white;
}
.tab-badge.blue   { background:var(--accent); }
.tab-badge.red    { background:#E53E3E; }
.tab-badge.green  { background:#16A34A; }
.tab-pane { display:none; }
.tab-pane.active  { display:block; }

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
.view-stat-card .stat-num { font-size:22px; font-weight:800; color:var(--gray-800); line-height:1; }
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
    border-bottom:1px solid var(--gray-100);
    white-space:nowrap;
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
.form-label {
    font-size:12.5px; font-weight:600; color:var(--gray-600);
}
.form-label.required::after { content:' *'; color:var(--red-light); }
.form-control {
    padding:9px 12px; border:1px solid var(--gray-200);
    border-radius:var(--radius-sm); font-size:13.5px;
    font-family:var(--font); color:var(--gray-800);
    background:var(--white); transition:var(--transition);
}
.form-control:focus {
    outline:none; border-color:var(--accent);
    box-shadow:0 0 0 3px rgba(33,150,243,.10);
}
.form-control[readonly] { background:var(--gray-50); color:var(--gray-500); }
textarea.form-control { resize:vertical; min-height:80px; }

/* ── Búsqueda de cliente en modal ── */
.client-search-wrap { position:relative; }
.client-search-input-wrap { position:relative; }
.client-search-input-wrap .si {
    position:absolute; left:10px; top:50%; transform:translateY(-50%);
    color:var(--gray-400); font-size:13px; pointer-events:none;
}
.client-search-input-wrap input {
    padding-left:34px;
}
#clienteResultados {
    position:absolute; z-index:200; top:calc(100% + 4px);
    left:0; right:0; background:var(--white);
    border:1px solid var(--gray-200); border-radius:var(--radius-sm);
    box-shadow:var(--shadow-md); max-height:230px; overflow-y:auto; display:none;
}
.client-result-item {
    padding:10px 14px; cursor:pointer; font-size:13px;
    border-bottom:1px solid var(--gray-100); transition:var(--transition);
    display:flex; flex-direction:column; gap:2px;
}
.client-result-item:last-child { border-bottom:none; }
.client-result-item:hover { background:var(--gray-50); }
.client-result-item .cr-name { font-weight:600; color:var(--gray-800); }
.client-result-item .cr-meta { font-size:11px; color:var(--gray-400); font-family:monospace; }
.no-results-item { padding:12px 14px; color:var(--gray-400); font-size:13px; text-align:center; }

#clienteSeleccionado {
    display:none; align-items:center; justify-content:space-between;
    padding:10px 14px; background:#EFF6FF;
    border:1px solid #BFDBFE; border-radius:var(--radius-sm);
    margin-top:8px; gap:10px;
}
#clienteSeleccionado .cs-info { display:flex; align-items:center; gap:8px; }
#clienteSeleccionado .cs-icon {
    width:30px; height:30px; background:var(--accent); border-radius:50%;
    display:flex; align-items:center; justify-content:center;
    color:white; font-size:12px; flex-shrink:0;
}
#clienteSeleccionado .cs-name { font-size:13px; font-weight:600; color:#1E40AF; }
#clienteEdicionWrap {
    display:none; align-items:center; gap:8px;
    padding:10px 14px; background:var(--gray-50);
    border:1px solid var(--gray-200); border-radius:var(--radius-sm);
}
#clienteEdicionWrap .cs-icon2 {
    width:30px; height:30px; background:var(--accent); border-radius:50%;
    display:flex; align-items:center; justify-content:center;
    color:white; font-size:12px; flex-shrink:0;
}

/* ── Beneficiarios ── */
.ben-list-empty {
    text-align:center; padding:20px; color:var(--gray-400);
    font-size:13px; background:var(--gray-50);
    border-radius:var(--radius-sm); border:1.5px dashed var(--gray-200);
}
.ben-item {
    position:relative; background:var(--gray-50);
    border:1px solid var(--gray-200); border-radius:var(--radius-sm);
    padding:16px 16px 12px; margin-bottom:12px;
}
.ben-item:last-child { margin-bottom:0; }
.btn-remove-ben {
    position:absolute; top:10px; right:10px;
    width:24px; height:24px; border:none; background:#FEE2E2;
    border-radius:6px; cursor:pointer; color:#DC2626; font-size:11px;
    display:flex; align-items:center; justify-content:center;
    transition:var(--transition);
}
.btn-remove-ben:hover { background:#DC2626; color:white; }

/* ── Alert global ── */
.alert-global {
    padding:12px 18px; border-radius:var(--radius-sm);
    margin-bottom:20px; display:flex; align-items:center; gap:10px;
    font-size:13.5px; font-weight:500; animation:slideDown .3s ease;
}
.alert-global.success { background:#F0FDF4; color:#15803D; border:1px solid #BBF7D0; }
.alert-global.danger  { background:#FEF2F2; color:#DC2626; border:1px solid #FCA5A5; }
@keyframes slideDown { from{opacity:0;transform:translateY(-10px)} to{opacity:1;transform:translateY(0)} }

/* ── Spinner ── */
.spinner {
    width:36px; height:36px; border:3px solid var(--gray-200);
    border-top-color:var(--accent); border-radius:50%;
    animation:spin .7s linear infinite;
    margin:40px auto;
}
@keyframes spin { to { transform:rotate(360deg); } }

/* ── Botones globales ── */
.btn {
    display:inline-flex; align-items:center; gap:7px;
    padding:9px 18px; border-radius:var(--radius-sm); border:none;
    font-size:13.5px; font-weight:600; font-family:var(--font);
    cursor:pointer; transition:var(--transition); text-decoration:none;
    white-space:nowrap;
}
.btn-primary   { background:var(--accent); color:white; }
.btn-primary:hover   { background:#1565C0; color:white; }
.btn-secondary { background:var(--gray-200); color:var(--gray-700); }
.btn-secondary:hover { background:var(--gray-300); }
.btn-danger    { background:#FEE2E2; color:#DC2626; }
.btn-danger:hover    { background:#DC2626; color:white; }
.btn-sm { padding:7px 14px; font-size:12.5px; }

/* ── Fade in ── */
.fade-in  { animation:fadeIn .4s ease both; }
.delay-1  { animation-delay:.10s; }
.delay-2  { animation-delay:.20s; }
@keyframes fadeIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
</style>

<?php /* ── PAGE HEADER ── */ ?>
<div class="page-header fade-in">
    <div>
        <div class="page-title">Gestión de Contratos</div>
        <div class="page-subtitle">
            <?php echo number_format($total_registros); ?> contrato<?php echo $total_registros !== 1 ? 's' : ''; ?>
            <?php echo ($filtro_estado || $filtro_vendedor || $buscar) ? 'encontrados' : 'registrados en el sistema'; ?>
        </div>
    </div>
    <div class="page-header-actions">
        <button class="btn btn-primary" onclick="abrirModalNuevo()">
            <i class="fas fa-plus"></i> Nuevo Contrato
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
<div class="kpi-contratos fade-in delay-1">
    <div class="kpi-card blue">
        <div class="kpi-label">Total Contratos</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo number_format($stats['total']); ?></div>
                <div class="kpi-sub">Contratos registrados</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-file-contract"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-database"></i> Todos los contratos</div>
    </div>

    <div class="kpi-card green">
        <div class="kpi-label">Contratos Activos</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo number_format($stats['activos']); ?></div>
                <div class="kpi-sub">RD$<?php echo number_format($stats['monto_activo'], 0); ?>/mes</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-check-circle"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-arrow-trend-up"></i> Vigentes</div>
    </div>

    <div class="kpi-card amber">
        <div class="kpi-label">Suspendidos</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo number_format($stats['suspendidos']); ?></div>
                <div class="kpi-sub">Contratos en pausa</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-pause-circle"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-clock"></i> En espera de reactivación</div>
    </div>

    <div class="kpi-card red">
        <div class="kpi-label">Cancelados</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo number_format($stats['cancelados']); ?></div>
                <div class="kpi-sub">Contratos cancelados</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-times-circle"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-ban"></i> Dados de baja</div>
    </div>
</div>

<!-- ============================================================
     BARRA DE BÚSQUEDA Y FILTROS
     ============================================================ -->
<div class="filter-bar-h fade-in delay-2">
    <form method="GET" action="contratos.php" id="formFiltrosContratos">
        <!-- FILA 1: Campos de búsqueda y filtros -->
        <div class="filter-row-fields">
            <!-- Campo búsqueda -->
            <div class="filter-field field-search">
                <label for="buscarContratos">
                    <i class="fas fa-search"></i> Buscar
                </label>
                <div class="search-wrap-h">
                    <i class="fas fa-search search-icon-h"></i>
                    <input type="text"
                           id="buscarContratos"
                           name="buscar"
                           class="filter-input"
                           placeholder="Nombre, apellido, cédula o No. contrato…"
                           value="<?php echo htmlspecialchars($buscar); ?>"
                           autocomplete="off">
                </div>
            </div>
            <!-- Filtro Estado -->
            <div class="filter-field field-select">
                <label for="estadoContratos">
                    <i class="fas fa-circle-half-stroke"></i> Estado
                </label>
                <select id="estadoContratos" name="estado" class="filter-select-h" onchange="this.form.submit()">
                    <option value="all">Todos los estados</option>
                    <option value="activo"     <?php echo $filtro_estado === 'activo'     ? 'selected' : ''; ?>>Activos</option>
                    <option value="suspendido" <?php echo $filtro_estado === 'suspendido' ? 'selected' : ''; ?>>Suspendidos</option>
                    <option value="cancelado"  <?php echo $filtro_estado === 'cancelado'  ? 'selected' : ''; ?>>Cancelados</option>
                </select>
            </div>
            <!-- Filtro Vendedor -->
            <div class="filter-field field-select">
                <label for="vendedorContratos">
                    <i class="fas fa-user-tie"></i> Vendedor
                </label>
                <select id="vendedorContratos" name="vendedor" class="filter-select-h" onchange="this.form.submit()">
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
        <!-- FILA 2: Botones de acción -->
        <div class="filter-row-btns">
            <button type="submit" class="btn btn-primary btn-sm">
                <i class="fas fa-search"></i> Buscar
            </button>
            <?php if ($buscar || ($filtro_estado && $filtro_estado !== 'all') || ($filtro_vendedor && $filtro_vendedor !== 'all')): ?>
                <a href="contratos.php" class="btn btn-secondary btn-sm">
                    <i class="fas fa-times"></i> Limpiar filtros
                </a>
            <?php endif; ?>
            <div class="filter-results-info">
                <?php echo number_format($total_registros); ?> contrato<?php echo $total_registros !== 1 ? 's' : ''; ?> encontrado<?php echo $total_registros !== 1 ? 's' : ''; ?>
            </div>
        </div>
    </form>
</div>

<!-- ============================================================
     TABLA DE CONTRATOS
     ============================================================ -->
<div class="card fade-in">
    <div class="card-header">
        <div>
            <div class="card-title">Lista de Contratos</div>
            <div class="card-subtitle">
                Mostrando
                <?php echo $total_registros > 0 ? min($offset + 1, $total_registros) : 0; ?>–<?php echo min($offset + $registros_por_pagina, $total_registros); ?>
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
                    <th>No. Contrato</th>
                    <th>Cliente</th>
                    <th>Plan</th>
                    <th>Monto Mensual</th>
                    <th>Fecha Inicio</th>
                    <th>Vendedor</th>
                    <th style="text-align:center;">Dep.</th>
                    <th>Estado</th>
                    <th style="text-align:center;">Acciones</th>
                </tr>
            </thead>
            <tbody>
            <?php if (!empty($contratos)): ?>
                <?php foreach ($contratos as $ct):
                    $ini = htmlspecialchars($ct['cliente_nombre'][0] . ($ct['cliente_apellidos'][0] ?? ''));
                    $nombreCompleto = htmlspecialchars($ct['cliente_nombre'] . ' ' . $ct['cliente_apellidos']);
                ?>
                <tr>
                    <td>
                        <span class="contract-num"><?php echo htmlspecialchars($ct['numero_contrato']); ?></span>
                    </td>
                    <td>
                        <div style="display:flex;align-items:center;gap:9px;">
                            <div style="width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,var(--accent),#1565C0);
                                        display:flex;align-items:center;justify-content:center;
                                        font-size:11px;font-weight:700;color:white;flex-shrink:0;">
                                <?php echo strtoupper(substr($ct['cliente_nombre'],0,1).substr($ct['cliente_apellidos'],0,1)); ?>
                            </div>
                            <div>
                                <div class="client-name"><?php echo $nombreCompleto; ?></div>
                                <div class="client-code"><?php echo htmlspecialchars($ct['cliente_codigo']); ?></div>
                            </div>
                        </div>
                    </td>
                    <td><span class="plan-name"><?php echo htmlspecialchars($ct['plan_nombre']); ?></span></td>
                    <td><span class="td-amount">RD$<?php echo number_format($ct['monto_mensual'], 2); ?></span></td>
                    <td><span class="td-muted"><?php echo date('d/m/Y', strtotime($ct['fecha_inicio'])); ?></span></td>
                    <td>
                        <span class="td-muted">
                            <?php echo $ct['vendedor_nombre'] ? htmlspecialchars($ct['vendedor_nombre']) : '—'; ?>
                        </span>
                    </td>
                    <td style="text-align:center;">
                        <span class="dep-badge">
                            <span class="dep-num <?php echo $ct['total_dependientes'] == 0 ? 'zero' : ''; ?>">
                                <?php echo $ct['total_dependientes']; ?>
                            </span>
                            Dep
                        </span>
                    </td>
                    <td>
                        <span class="badge badge-<?php echo $ct['estado']; ?>">
                            <?php echo ucfirst($ct['estado']); ?>
                        </span>
                    </td>
                    <td>
                        <div class="tbl-actions">
                            <button class="btn-tbl view" title="Ver detalles"
                                    onclick="verContrato(<?php echo $ct['id']; ?>)">
                                <i class="fas fa-eye"></i>
                            </button>
                            <button class="btn-tbl edit" title="Editar"
                                    onclick='editarContrato(<?php echo json_encode([
                                        'id'               => $ct['id'],
                                        'cliente_id'       => $ct['cliente_id'],
                                        'cliente_nombre'   => $ct['cliente_nombre'],
                                        'cliente_apellidos'=> $ct['cliente_apellidos'],
                                        'cliente_codigo'   => $ct['cliente_codigo'],
                                        'plan_id'          => $ct['plan_id'],
                                        'plan_nombre'      => $ct['plan_nombre'],
                                        'fecha_inicio'     => $ct['fecha_inicio'],
                                        'fecha_fin'        => $ct['fecha_fin'],
                                        'monto_mensual'    => $ct['monto_mensual'],
                                        'monto_total'      => $ct['monto_total'],
                                        'dia_cobro'        => $ct['dia_cobro'],
                                        'estado'           => $ct['estado'],
                                        'vendedor_id'      => $ct['vendedor_id'],
                                        'notas'            => $ct['notas'],
                                    ], JSON_HEX_APOS|JSON_HEX_QUOT); ?>)'>
                                <i class="fas fa-edit"></i>
                            </button>
                            <?php if ($ct['estado'] !== 'cancelado'): ?>
                            <button class="btn-tbl cancel" title="Cancelar contrato"
                                    onclick='confirmarCancelar(<?php echo json_encode([
                                        'id'              => $ct['id'],
                                        'numero_contrato' => $ct['numero_contrato'],
                                        'cliente_nombre'  => $ct['cliente_nombre'].' '.$ct['cliente_apellidos'],
                                        'plan_nombre'     => $ct['plan_nombre'],
                                        'estado'          => $ct['estado'],
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
                    <td colspan="9" style="text-align:center;padding:40px;color:var(--gray-400);">
                        <i class="fas fa-file-contract" style="font-size:32px;display:block;margin-bottom:10px;opacity:.4;"></i>
                        No se encontraron contratos<?php echo ($buscar || $filtro_estado || $filtro_vendedor) ? ' con los filtros aplicados' : ''; ?>.
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
            de <strong><?php echo number_format($total_registros); ?></strong> contratos
        </div>

        <div class="paginador-pages">
            <a class="pag-btn <?php echo $pagina_actual <= 1 ? 'disabled' : ''; ?>"
               href="<?php echo buildContratoUrl(1, $buscar, $filtro_estado, $filtro_vendedor); ?>" title="Primera">
                <i class="fas fa-angles-left" style="font-size:10px;"></i>
            </a>
            <a class="pag-btn <?php echo $pagina_actual <= 1 ? 'disabled' : ''; ?>"
               href="<?php echo buildContratoUrl($pagina_actual-1, $buscar, $filtro_estado, $filtro_vendedor); ?>" title="Anterior">
                <i class="fas fa-angle-left" style="font-size:11px;"></i>
            </a>

            <?php
            $start = max(1, $pagina_actual - 2);
            $end   = min($total_paginas, $pagina_actual + 2);
            for ($p = $start; $p <= $end; $p++): ?>
                <a class="pag-btn <?php echo $p === $pagina_actual ? 'active' : ''; ?>"
                   href="<?php echo buildContratoUrl($p, $buscar, $filtro_estado, $filtro_vendedor); ?>">
                    <?php echo $p; ?>
                </a>
            <?php endfor; ?>

            <a class="pag-btn <?php echo $pagina_actual >= $total_paginas ? 'disabled' : ''; ?>"
               href="<?php echo buildContratoUrl($pagina_actual+1, $buscar, $filtro_estado, $filtro_vendedor); ?>" title="Siguiente">
                <i class="fas fa-angle-right" style="font-size:11px;"></i>
            </a>
            <a class="pag-btn <?php echo $pagina_actual >= $total_paginas ? 'disabled' : ''; ?>"
               href="<?php echo buildContratoUrl($total_paginas, $buscar, $filtro_estado, $filtro_vendedor); ?>" title="Última">
                <i class="fas fa-angles-right" style="font-size:10px;"></i>
            </a>
        </div>

        <div class="paginador-rpp">
            <span>Mostrar:</span>
            <select onchange="cambiarRPP(this.value)">
                <?php foreach ([10, 15, 25, 50, 100] as $rpp): ?>
                    <option value="<?php echo $rpp; ?>" <?php echo $registros_por_pagina === $rpp ? 'selected' : ''; ?>>
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
     MODAL: VER CONTRATO (carga AJAX)
     ============================================================ -->
<div class="modal-overlay" id="overlayVer">
    <div class="modal-box xl">
        <div class="mhdr">
            <div>
                <div class="mhdr-title">
                    <i class="fas fa-file-contract" style="color:var(--accent);"></i>
                    <span id="verTitulo">Detalles del Contrato</span>
                </div>
                <div class="mhdr-sub" id="verSubtitulo"></div>
            </div>
            <button class="modal-close-btn" onclick="cerrarOverlay('overlayVer')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="mbody" id="verBody">
            <div class="spinner"></div>
        </div>
        <div class="mfooter">
            <a id="btnVerCompleto" href="#" target="_blank" class="btn btn-secondary btn-sm">
                <i class="fas fa-external-link-alt"></i> Ver página completa
            </a>
            <button class="btn btn-primary btn-sm" onclick="cerrarOverlay('overlayVer')">
                <i class="fas fa-check"></i> Cerrar
            </button>
        </div>
    </div>
</div>


<!-- ============================================================
     MODAL: CREAR / EDITAR CONTRATO
     ============================================================ -->
<div class="modal-overlay" id="overlayContrato">
    <div class="modal-box xl">
        <div class="mhdr">
            <div class="mhdr-title">
                <i class="fas fa-file-contract" style="color:var(--accent);"></i>
                <span id="textoTitulo">Nuevo Contrato</span>
            </div>
            <button class="modal-close-btn" onclick="cerrarOverlay('overlayContrato')">
                <i class="fas fa-times"></i>
            </button>
        </div>

        <div class="mbody">
            <form id="formContrato" method="POST">
                <input type="hidden" name="action"     id="accionContrato" value="crear">
                <input type="hidden" name="id"         id="contratoId"     value="">
                <input type="hidden" name="cliente_id" id="clienteIdHidden" value="">

                <!-- ── Datos del contrato ── -->
                <div class="fsec-title"><i class="fas fa-info-circle"></i> Datos del Contrato</div>

                <div class="form-grid cols-3">
                    <!-- No. Contrato (solo lectura al crear) -->
                    <div class="form-group" id="grupoNumeroContrato">
                        <label class="form-label">No. Contrato</label>
                        <input type="text" id="numero_contrato_display" class="form-control"
                               value="Se generará automáticamente" readonly>
                    </div>

                    <div class="form-group">
                        <label class="form-label required" for="plan_id">Plan</label>
                        <select id="plan_id" name="plan_id" class="form-control" required
                                onchange="actualizarMonto()">
                            <option value="">— Seleccione un plan —</option>
                            <?php foreach ($planes as $pl): ?>
                                <option value="<?php echo $pl['id']; ?>"
                                        data-precio="<?php echo $pl['precio_base']; ?>">
                                    <?php echo htmlspecialchars($pl['codigo'].' - '.$pl['nombre']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div class="form-group" id="grupoEstado" style="display:none;">
                        <label class="form-label required" for="f_estado">Estado</label>
                        <select id="f_estado" name="estado" class="form-control" required>
                            <option value="activo">Activo</option>
                            <option value="suspendido">Suspendido</option>
                            <option value="cancelado">Cancelado</option>
                        </select>
                    </div>
                </div>

                <!-- ── Búsqueda de cliente (solo al crear) ── -->
                <div id="clienteBusquedaWrap">
                    <div class="fsec-title"><i class="fas fa-user"></i> Cliente</div>
                    <div class="client-search-wrap">
                        <div class="form-group">
                            <label class="form-label required">Buscar Cliente</label>
                            <div class="client-search-input-wrap" style="position:relative;">
                                <i class="fas fa-search si"></i>
                                <input type="text" id="buscarCliente" class="form-control"
                                       placeholder="Nombre, apellidos o cédula…"
                                       autocomplete="off"
                                       oninput="buscarClienteHandler(this.value)">
                            </div>
                            <div id="clienteResultados"></div>
                        </div>
                        <div id="clienteSeleccionado">
                            <div class="cs-info">
                                <div class="cs-icon"><i class="fas fa-user-check"></i></div>
                                <span class="cs-name" id="clienteSeleccionadoNombre"></span>
                            </div>
                            <button type="button" class="btn btn-secondary btn-sm"
                                    onclick="limpiarClienteSeleccionado()">
                                <i class="fas fa-times"></i> Cambiar
                            </button>
                        </div>
                    </div>
                </div>

                <!-- ── Visualización del cliente al editar ── -->
                <div id="clienteEdicionWrap">
                    <div class="fsec-title"><i class="fas fa-user"></i> Cliente</div>
                    <div style="display:flex;align-items:center;gap:8px;padding:10px 14px;
                                background:var(--gray-50);border:1px solid var(--gray-200);
                                border-radius:var(--radius-sm);">
                        <div class="cs-icon2"><i class="fas fa-user"></i></div>
                        <div>
                            <div style="font-size:13px;font-weight:600;color:var(--gray-800);"
                                 id="clienteEdicionNombre"></div>
                            <div style="font-size:11px;color:var(--gray-400);font-family:monospace;"
                                 id="clienteEdicionCodigo"></div>
                        </div>
                    </div>
                </div>

                <!-- ── Fechas y montos ── -->
                <div class="fsec-title" style="margin-top:18px;"><i class="fas fa-calendar-alt"></i> Vigencia y Montos</div>
                <div class="form-grid cols-2">
                    <div class="form-group">
                        <label class="form-label required" for="fecha_inicio">Fecha Inicio</label>
                        <input type="date" id="fecha_inicio" name="fecha_inicio" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="fecha_fin">Fecha Fin</label>
                        <input type="date" id="fecha_fin" name="fecha_fin" class="form-control">
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="monto_mensual">Monto Base (RD$)</label>
                        <input type="number" id="monto_mensual" name="monto_mensual"
                               step="0.01" min="0" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="monto_total">Monto Total (RD$)</label>
                        <input type="number" id="monto_total" name="monto_total"
                               step="0.01" min="0" class="form-control" required>
                    </div>
                </div>

                <!-- ── Cobro y vendedor ── -->
                <div class="fsec-title" style="margin-top:18px;"><i class="fas fa-users"></i> Cobro y Vendedor</div>
                <div class="form-grid cols-2">
                    <div class="form-group">
                        <label class="form-label required" for="dia_cobro">Día de Cobro</label>
                        <input type="number" id="dia_cobro" name="dia_cobro"
                               min="1" max="31" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="vendedor_id">Vendedor</label>
                        <select id="vendedor_id" name="vendedor_id" class="form-control" required>
                            <option value="">— Seleccione un vendedor —</option>
                            <?php foreach ($vendedores as $vd): ?>
                                <option value="<?php echo $vd['id']; ?>">
                                    <?php echo htmlspecialchars($vd['codigo'].' - '.$vd['nombre_completo']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>

                <!-- ── Notas ── -->
                <div class="form-group" style="margin-top:14px;">
                    <label class="form-label" for="f_notas">Notas</label>
                    <textarea id="f_notas" name="notas" class="form-control"
                              rows="3" placeholder="Observaciones adicionales…"></textarea>
                </div>

                <!-- ── Beneficiarios ── -->
                <div class="fsec-title" style="margin-top:18px;">
                    <i class="fas fa-heart"></i> Beneficiarios
                    <button type="button" class="btn btn-secondary btn-sm"
                            style="margin-left:auto;" onclick="agregarBeneficiario()">
                        <i class="fas fa-plus"></i> Agregar
                    </button>
                </div>
                <div id="beneficiariosContainer"></div>
                <div class="ben-list-empty" id="benEmpty">
                    <i class="fas fa-heart-broken" style="font-size:22px;display:block;margin-bottom:6px;opacity:.4;"></i>
                    No hay beneficiarios. Haz clic en <strong>Agregar</strong> para añadir uno.
                </div>

                <!-- Footer del form -->
                <div class="mfooter" style="margin:22px -22px -22px;border-radius:0 0 var(--radius-lg) var(--radius-lg);">
                    <button type="button" class="btn btn-secondary"
                            onclick="cerrarOverlay('overlayContrato')">
                        <i class="fas fa-times"></i> Cancelar
                    </button>
                    <button type="submit" class="btn btn-primary" id="btnSubmit">
                        <i class="fas fa-save"></i>
                        <span id="btnSubmitTexto">Guardar Contrato</span>
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>


<!-- ============================================================
     MODAL: CONFIRMAR CANCELACIÓN
     ============================================================ -->
<div class="modal-overlay" id="overlayCancelar">
    <div class="modal-box md">
        <div class="mhdr">
            <div class="mhdr-title" style="color:#DC2626;">
                <i class="fas fa-exclamation-triangle"></i> Cancelar Contrato
            </div>
            <button class="modal-close-btn" onclick="cerrarOverlay('overlayCancelar')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="mbody">
            <div id="cancelarDetalles" style="margin-bottom:16px;"></div>
            <div style="background:#FEF2F2;border:1px solid #FCA5A5;border-radius:var(--radius-sm);
                        padding:14px 16px;color:#991B1B;font-size:13.5px;">
                <i class="fas fa-exclamation-circle" style="margin-right:6px;"></i>
                <strong>¿Confirma la cancelación de este contrato?</strong><br>
                <span style="font-size:12.5px;opacity:.8;">
                    El estado del contrato cambiará a <strong>Cancelado</strong>. Esta acción puede revertirse editando el contrato.
                </span>
            </div>
        </div>
        <div class="mfooter">
            <button class="btn btn-secondary" onclick="cerrarOverlay('overlayCancelar')">
                <i class="fas fa-arrow-left"></i> Volver
            </button>
            <button class="btn btn-danger" id="btnConfirmarCancelar">
                <i class="fas fa-ban"></i> Sí, cancelar contrato
            </button>
        </div>
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
function esc2(s) { return String(s||'').replace(/'/g,"\\'"); }
function ucFirst(s) { return s ? s.charAt(0).toUpperCase()+s.slice(1) : ''; }
function numFmt(n) {
    return parseFloat(n||0).toLocaleString('es-DO', {minimumFractionDigits:2, maximumFractionDigits:2});
}
function dateFmt(d) {
    if (!d) return '—';
    var p = d.split(/[-T ]/);
    return p.length >= 3 ? p[2]+'/'+p[1]+'/'+p[0] : d;
}
function cambiarRPP(v) {
    document.cookie = 'contratos_por_pagina=' + v + '; path=/; max-age=31536000';
    window.location.href = 'contratos.php';
}

/* ═══════════════════════════════════════════════════════════
   MODAL: CANCELAR CONTRATO
═══════════════════════════════════════════════════════════ */
var _ctACancelar = null;

function confirmarCancelar(ct) {
    _ctACancelar = ct;
    document.getElementById('cancelarDetalles').innerHTML =
        '<div style="background:var(--gray-50);border:1px solid var(--gray-200);' +
        'border-radius:var(--radius-sm);padding:14px 16px;margin-bottom:0;">' +
        '<div style="display:grid;gap:8px;">' +
        '<div><span style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--gray-400);font-weight:700;">No. Contrato</span>' +
        '<div style="font-family:monospace;font-size:15px;font-weight:700;color:var(--accent);">' + esc(ct.numero_contrato) + '</div></div>' +
        '<div><span style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--gray-400);font-weight:700;">Cliente</span>' +
        '<div style="font-size:14px;font-weight:600;color:var(--gray-800);">' + esc(ct.cliente_nombre) + '</div></div>' +
        '<div><span style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--gray-400);font-weight:700;">Plan</span>' +
        '<div style="font-size:13px;color:var(--gray-700);">' + esc(ct.plan_nombre) + '</div></div>' +
        '</div></div>';
    abrirOverlay('overlayCancelar');
}

document.getElementById('btnConfirmarCancelar').addEventListener('click', function() {
    if (!_ctACancelar) return;
    var f = document.createElement('form');
    f.method = 'POST';
    f.innerHTML = '<input type="hidden" name="action" value="eliminar">' +
                  '<input type="hidden" name="id" value="' + _ctACancelar.id + '">';
    document.body.appendChild(f);
    f.submit();
});


/* ═══════════════════════════════════════════════════════════
   MODAL: VER CONTRATO
═══════════════════════════════════════════════════════════ */
function verContrato(id) {
    document.getElementById('verTitulo').textContent    = 'Cargando…';
    document.getElementById('verSubtitulo').textContent = '';
    document.getElementById('verBody').innerHTML        = '<div class="spinner"></div>';
    document.getElementById('btnVerCompleto').href      = 'ver_contrato.php?id=' + id;
    abrirOverlay('overlayVer');

    fetch('ajax_ver_contrato.php?id=' + id)
        .then(function(r) { return r.json(); })
        .then(function(d) { renderVerContrato(d); })
        .catch(function() {
            document.getElementById('verBody').innerHTML =
                '<div style="text-align:center;padding:40px;color:var(--red-light);">' +
                '<i class="fas fa-exclamation-circle" style="font-size:36px;display:block;margin-bottom:12px;"></i>' +
                '<p>No se pudo cargar la información del contrato.</p></div>';
        });
}

function infoItem(label, value, extra) {
    extra = extra || '';
    return '<div class="info-item">' +
           '<span class="info-label">' + label + '</span>' +
           '<span class="info-value ' + extra + '">' + (value || '—') + '</span></div>';
}

function renderVerContrato(d) {
    document.getElementById('verTitulo').textContent    = 'Contrato ' + d.numero_contrato;
    document.getElementById('verSubtitulo').textContent = d.cliente_nombre + ' — ' + d.plan_nombre;

    var badgeMap = { activo:'badge-activo', suspendido:'badge-suspendido', cancelado:'badge-cancelado' };
    var badge = '<span class="badge '+(badgeMap[d.estado]||'badge-secondary')+'">'+ucFirst(d.estado)+'</span>';

    var html = '';

    /* Tabs */
    html += '<div class="modal-tabs">' +
        '<button class="modal-tab active" onclick="showTab(\'tabInfo\',this)">' +
            '<i class="fas fa-info-circle"></i> Información</button>' +
        '<button class="modal-tab" onclick="showTab(\'tabDep\',this)">' +
            '<i class="fas fa-users"></i> Dependientes ' +
            '<span class="tab-badge blue">'+(d.total_dependientes||0)+'</span></button>' +
        '<button class="modal-tab" onclick="showTab(\'tabBen\',this)">' +
            '<i class="fas fa-heart"></i> Beneficiarios ' +
            '<span class="tab-badge red">'+(d.beneficiarios?d.beneficiarios.length:0)+'</span></button>' +
        '<button class="modal-tab" onclick="showTab(\'tabPagos\',this)">' +
            '<i class="fas fa-money-bill-wave"></i> Últimos Pagos ' +
            '<span class="tab-badge green">'+(d.pagos?d.pagos.length:0)+'</span></button>' +
        '</div>';

    /* ── Tab Info ── */
    html += '<div id="tabInfo" class="tab-pane active">';

    /* Mini stats */
    html += '<div class="view-stats-row" style="margin-bottom:18px;">' +
        '<div class="view-stat-card accent"><div class="stat-num">'+esc(d.numero_contrato)+'</div><div class="stat-lbl">No. Contrato</div></div>' +
        '<div class="view-stat-card '+(d.estado==='activo'?'green':d.estado==='suspendido'?'amber':'red')+'">' +
            '<div class="stat-num">'+ucFirst(d.estado)+'</div><div class="stat-lbl">Estado</div></div>' +
        '<div class="view-stat-card amber"><div class="stat-num">RD$'+numFmt(d.monto_mensual)+'</div><div class="stat-lbl">Monto Base</div></div>' +
        '<div class="view-stat-card green"><div class="stat-num">RD$'+numFmt(d.monto_total)+'</div><div class="stat-lbl">Monto Total</div></div>' +
        '</div>';

    /* Bloque cliente */
    html += '<div class="view-block"><div class="view-block-header">' +
        '<div class="view-block-icon blue"><i class="fas fa-user"></i></div>' +
        '<div><div class="view-block-title">Datos del Cliente</div></div></div>' +
        '<div class="view-block-body"><div class="info-grid cols-3">' +
        infoItem('Código', esc(d.cliente_codigo), 'mono') +
        infoItem('Nombre Completo', esc(d.cliente_nombre)) +
        infoItem('Teléfono', esc(d.cliente_telefono1)) +
        infoItem('Email', esc(d.cliente_email)) +
        infoItem('Dirección', esc(d.cliente_direccion)) +
        '</div></div></div>';

    /* Bloque contrato */
    html += '<div class="view-block"><div class="view-block-header">' +
        '<div class="view-block-icon green"><i class="fas fa-file-contract"></i></div>' +
        '<div><div class="view-block-title">Datos del Contrato</div></div></div>' +
        '<div class="view-block-body"><div class="info-grid cols-3">' +
        infoItem('Plan', esc(d.plan_nombre)) +
        infoItem('Fecha Inicio', dateFmt(d.fecha_inicio)) +
        infoItem('Fecha Fin', dateFmt(d.fecha_fin)) +
        infoItem('Día Cobro', 'Día '+esc(d.dia_cobro)) +
        infoItem('Vendedor', esc(d.vendedor_nombre)) +
        infoItem('Estado', badge) +
        '</div>' +
        (d.notas ? '<div style="margin-top:12px;padding:10px;background:var(--gray-50);border-radius:var(--radius-sm);font-size:13px;color:var(--gray-600);">'+
            '<i class="fas fa-sticky-note" style="margin-right:6px;color:var(--gray-400);"></i>'+esc(d.notas)+'</div>' : '') +
        '</div></div>';

    /* Bloque financiero */
    html += '<div class="view-block"><div class="view-block-header">' +
        '<div class="view-block-icon amber"><i class="fas fa-coins"></i></div>' +
        '<div><div class="view-block-title">Resumen Financiero</div></div></div>' +
        '<div class="view-block-body"><div class="info-grid">' +
        infoItem('Monto Base', 'RD$'+numFmt(d.monto_mensual)) +
        infoItem('Monto Total', 'RD$'+numFmt(d.monto_total)) +
        infoItem('Total Pendiente', 'RD$'+numFmt(d.total_pendiente)) +
        infoItem('Total Abonado', 'RD$'+numFmt(d.total_abonado)) +
        '</div></div></div>';

    html += '</div>'; /* /tabInfo */

    /* ── Tab Dependientes ── */
    html += '<div id="tabDep" class="tab-pane">';
    if (!d.dependientes || d.dependientes.length === 0) {
        html += '<div class="ben-list-empty"><i class="fas fa-users" style="font-size:28px;display:block;margin-bottom:8px;opacity:.4;"></i>No hay dependientes registrados.</div>';
    } else {
        html += '<table class="mini-table"><thead><tr>' +
            '<th>Nombre</th><th>Parentesco</th><th>F. Nacimiento</th><th>Plan</th><th>Estado</th>' +
            '</tr></thead><tbody>';
        d.dependientes.forEach(function(dep) {
            html += '<tr>' +
                '<td><strong>'+esc(dep.nombre)+' '+esc(dep.apellidos)+'</strong></td>' +
                '<td>'+esc(dep.parentesco)+'</td>' +
                '<td>'+dateFmt(dep.fecha_nacimiento)+'</td>' +
                '<td>'+esc(dep.plan_nombre)+'</td>' +
                '<td><span class="badge badge-'+(dep.estado==='activo'?'activo':'cancelado')+'">'+ucFirst(dep.estado)+'</span></td>' +
                '</tr>';
        });
        html += '</tbody></table>';
    }
    html += '</div>';

    /* ── Tab Beneficiarios ── */
    html += '<div id="tabBen" class="tab-pane">';
    if (!d.beneficiarios || d.beneficiarios.length === 0) {
        html += '<div class="ben-list-empty"><i class="fas fa-heart-broken" style="font-size:28px;display:block;margin-bottom:8px;opacity:.4;"></i>No hay beneficiarios registrados.</div>';
    } else {
        html += '<table class="mini-table"><thead><tr>' +
            '<th>Nombre</th><th>Parentesco</th><th>F. Nacimiento</th><th>Porcentaje</th>' +
            '</tr></thead><tbody>';
        d.beneficiarios.forEach(function(ben) {
            html += '<tr>' +
                '<td><strong>'+esc(ben.nombre)+' '+esc(ben.apellidos)+'</strong></td>' +
                '<td>'+esc(ben.parentesco)+'</td>' +
                '<td>'+dateFmt(ben.fecha_nacimiento)+'</td>' +
                '<td><span style="font-weight:700;color:var(--accent);">'+esc(ben.porcentaje)+'%</span></td>' +
                '</tr>';
        });
        html += '</tbody></table>';
    }
    html += '</div>';

    /* ── Tab Pagos ── */
    html += '<div id="tabPagos" class="tab-pane">';
    if (!d.pagos || d.pagos.length === 0) {
        html += '<div class="ben-list-empty"><i class="fas fa-money-bill" style="font-size:28px;display:block;margin-bottom:8px;opacity:.4;"></i>No hay pagos registrados.</div>';
    } else {
        html += '<table class="mini-table"><thead><tr>' +
            '<th>Factura</th><th>Fecha</th><th>Monto</th><th>Tipo</th><th>Estado</th>' +
            '</tr></thead><tbody>';
        d.pagos.forEach(function(pg) {
            var est = pg.estado || '';
            var estClass = est === 'procesado' ? 'badge-activo' : est === 'anulado' ? 'badge-cancelado' : 'badge-suspendido';
            html += '<tr>' +
                '<td><span style="font-family:monospace;color:var(--accent);font-weight:700;">'+esc(pg.numero_factura)+'</span></td>' +
                '<td>'+dateFmt(pg.fecha_pago)+'</td>' +
                '<td><strong>RD$'+numFmt(pg.monto)+'</strong></td>' +
                '<td>'+ucFirst(esc(pg.tipo_pago||''))+'</td>' +
                '<td><span class="badge '+estClass+'">'+ucFirst(est)+'</span></td>' +
                '</tr>';
        });
        html += '</tbody></table>';
    }
    html += '</div>';

    document.getElementById('verBody').innerHTML = html;
    /* Activar primer tab */
    var firstTab = document.querySelector('#verBody .modal-tab');
    if (firstTab) firstTab.click();
}

function showTab(id, btn) {
    document.querySelectorAll('#verBody .tab-pane').forEach(function(p){ p.classList.remove('active'); });
    document.querySelectorAll('#verBody .modal-tab').forEach(function(b){ b.classList.remove('active'); });
    document.getElementById(id).classList.add('active');
    btn.classList.add('active');
}


/* ═══════════════════════════════════════════════════════════
   MODAL: CREAR / EDITAR CONTRATO
═══════════════════════════════════════════════════════════ */
var benIdx = 0;

function abrirModalNuevo() {
    document.getElementById('formContrato').reset();
    document.getElementById('accionContrato').value    = 'crear';
    document.getElementById('contratoId').value        = '';
    document.getElementById('clienteIdHidden').value   = '';
    document.getElementById('textoTitulo').textContent = 'Nuevo Contrato';
    document.getElementById('btnSubmitTexto').textContent = 'Guardar Contrato';

    document.getElementById('grupoNumeroContrato').style.display = '';
    document.getElementById('grupoEstado').style.display         = 'none';
    document.getElementById('clienteBusquedaWrap').style.display = '';
    document.getElementById('clienteEdicionWrap').style.display  = 'none';
    document.getElementById('clienteSeleccionado').style.display = 'none';
    document.getElementById('clienteResultados').style.display   = 'none';
    document.getElementById('buscarCliente').value               = '';
    document.getElementById('beneficiariosContainer').innerHTML  = '';

    benIdx = 0;
    actualizarBenEmpty();
    document.getElementById('fecha_inicio').value = new Date().toISOString().split('T')[0];
    abrirOverlay('overlayContrato');
}

function editarContrato(ct) {
    document.getElementById('formContrato').reset();
    document.getElementById('accionContrato').value   = 'editar';
    document.getElementById('contratoId').value       = ct.id;
    document.getElementById('clienteIdHidden').value  = ct.cliente_id;
    document.getElementById('textoTitulo').textContent = 'Editar Contrato';
    document.getElementById('btnSubmitTexto').textContent = 'Actualizar Contrato';

    document.getElementById('grupoNumeroContrato').style.display = 'none';
    document.getElementById('grupoEstado').style.display         = '';
    document.getElementById('clienteBusquedaWrap').style.display = 'none';
    document.getElementById('clienteEdicionWrap').style.display  = 'flex';

    document.getElementById('clienteEdicionNombre').textContent =
        (ct.cliente_nombre || '') + ' ' + (ct.cliente_apellidos || '');
    document.getElementById('clienteEdicionCodigo').textContent =
        ct.cliente_codigo ? 'Cód. ' + ct.cliente_codigo : '';

    /* Llenar campos */
    document.getElementById('plan_id').value     = ct.plan_id || '';
    document.getElementById('fecha_inicio').value = (ct.fecha_inicio || '').split(' ')[0];
    document.getElementById('fecha_fin').value    = ct.fecha_fin ? ct.fecha_fin.split(' ')[0] : '';
    document.getElementById('monto_mensual').value = ct.monto_mensual || '';
    document.getElementById('monto_total').value   = ct.monto_total || '';
    document.getElementById('dia_cobro').value     = ct.dia_cobro || '';
    document.getElementById('vendedor_id').value   = ct.vendedor_id || '';
    document.getElementById('f_estado').value      = ct.estado || 'activo';
    document.getElementById('f_notas').value       = ct.notas || '';

    /* Cargar beneficiarios */
    document.getElementById('beneficiariosContainer').innerHTML = '';
    benIdx = 0;
    actualizarBenEmpty();
    cargarBeneficiariosEdicion(ct.id);

    abrirOverlay('overlayContrato');
}

/* ── Cargar beneficiarios existentes al editar ── */
function cargarBeneficiariosEdicion(contratoId) {
    fetch('ajax_ver_contrato.php?id=' + contratoId)
        .then(function(r){ return r.json(); })
        .then(function(d){
            if (d.beneficiarios && d.beneficiarios.length > 0) {
                d.beneficiarios.forEach(function(b){
                    agregarBeneficiario({
                        nombre:          b.nombre,
                        apellidos:       b.apellidos,
                        parentesco:      b.parentesco,
                        porcentaje:      b.porcentaje,
                        fecha_nacimiento: (b.fecha_nacimiento||'').split(' ')[0],
                    });
                });
            }
        })
        .catch(function(){});
}


/* ═══════════════════════════════════════════════════════════
   BÚSQUEDA DE CLIENTE EN EL MODAL
═══════════════════════════════════════════════════════════ */
var _buscarTimer = null;

function buscarClienteHandler(q) {
    clearTimeout(_buscarTimer);
    var res = document.getElementById('clienteResultados');

    if (q.trim().length < 2) {
        res.style.display = 'none';
        res.innerHTML = '';
        return;
    }

    res.style.display = 'block';
    res.innerHTML = '<div class="no-results-item"><i class="fas fa-circle-notch fa-spin" style="margin-right:6px;"></i>Buscando…</div>';

    _buscarTimer = setTimeout(function() {
        fetch('ajax_buscar_cliente.php?q=' + encodeURIComponent(q.trim()))
            .then(function(r){ return r.json(); })
            .then(function(data){
                if (!data || data.length === 0) {
                    res.innerHTML = '<div class="no-results-item">No se encontraron clientes.</div>';
                } else {
                    res.innerHTML = data.map(function(c){
                        return '<div class="client-result-item" onclick="seleccionarCliente(' +
                            c.id + ',\'' + esc2(c.nombre + ' ' + c.apellidos) + '\',\'' + esc2(c.codigo) + '\')">' +
                            '<span class="cr-name">' + esc(c.nombre + ' ' + c.apellidos) + '</span>' +
                            '<span class="cr-meta">Cód. ' + esc(c.codigo) + ' · ' + esc(c.cedula) + '</span>' +
                            '</div>';
                    }).join('');
                }
                res.style.display = 'block';
            })
            .catch(function(){
                res.innerHTML = '<div class="no-results-item" style="color:var(--red-light);">Error de búsqueda. Intente de nuevo.</div>';
            });
    }, 300);
}

function seleccionarCliente(id, nombre, codigo) {
    document.getElementById('clienteIdHidden').value        = id;
    document.getElementById('clienteSeleccionadoNombre').textContent = nombre + ' (Cód. ' + codigo + ')';
    document.getElementById('clienteSeleccionado').style.display = 'flex';
    document.getElementById('clienteResultados').style.display   = 'none';
    document.getElementById('clienteResultados').innerHTML        = '';
    document.getElementById('buscarCliente').value                = '';
}

function limpiarClienteSeleccionado() {
    document.getElementById('clienteIdHidden').value        = '';
    document.getElementById('clienteSeleccionado').style.display = 'none';
    document.getElementById('buscarCliente').value = '';
    document.getElementById('buscarCliente').focus();
}

/* Cerrar resultados al hacer clic fuera */
document.addEventListener('click', function(e) {
    var res = document.getElementById('clienteResultados');
    var inp = document.getElementById('buscarCliente');
    if (res && inp && !inp.contains(e.target) && !res.contains(e.target)) {
        res.style.display = 'none';
    }
});


/* ═══════════════════════════════════════════════════════════
   BENEFICIARIOS
═══════════════════════════════════════════════════════════ */
function actualizarBenEmpty() {
    var container = document.getElementById('beneficiariosContainer');
    var empty     = document.getElementById('benEmpty');
    if (!container || !empty) return;
    empty.style.display = container.children.length === 0 ? 'block' : 'none';
}

function agregarBeneficiario(data) {
    data = data || {};
    var idx  = benIdx++;
    var container = document.getElementById('beneficiariosContainer');
    var div  = document.createElement('div');
    div.className  = 'ben-item';
    div.id         = 'ben_' + idx;
    div.innerHTML  =
        '<button type="button" class="btn-remove-ben" onclick="quitarBeneficiario('+idx+')" title="Eliminar">' +
        '<i class="fas fa-times"></i></button>' +
        '<div class="form-grid cols-2" style="gap:10px;">' +
        '<div class="form-group">' +
            '<label class="form-label required">Nombre</label>' +
            '<input type="text" name="beneficiarios['+idx+'][nombre]" class="form-control" required ' +
                'value="' + esc(data.nombre||'') + '" placeholder="Nombre(s)">' +
        '</div>' +
        '<div class="form-group">' +
            '<label class="form-label required">Apellidos</label>' +
            '<input type="text" name="beneficiarios['+idx+'][apellidos]" class="form-control" required ' +
                'value="' + esc(data.apellidos||'') + '" placeholder="Apellidos">' +
        '</div>' +
        '<div class="form-group">' +
            '<label class="form-label required">Parentesco</label>' +
            '<input type="text" name="beneficiarios['+idx+'][parentesco]" class="form-control" required ' +
                'value="' + esc(data.parentesco||'') + '" placeholder="Ej: Cónyuge, Hijo…">' +
        '</div>' +
        '<div class="form-group">' +
            '<label class="form-label required">Porcentaje (%)</label>' +
            '<input type="number" name="beneficiarios['+idx+'][porcentaje]" class="form-control" required ' +
                'min="1" max="100" value="' + esc(data.porcentaje||'') + '" placeholder="0 – 100">' +
        '</div>' +
        '<div class="form-group" style="grid-column:1/-1;">' +
            '<label class="form-label">Fecha de Nacimiento</label>' +
            '<input type="date" name="beneficiarios['+idx+'][fecha_nacimiento]" class="form-control" ' +
                'value="' + esc(data.fecha_nacimiento||'') + '">' +
        '</div>' +
        '</div>';
    container.appendChild(div);
    actualizarBenEmpty();
}

function quitarBeneficiario(idx) {
    var el = document.getElementById('ben_' + idx);
    if (el) { el.remove(); actualizarBenEmpty(); }
}


/* ═══════════════════════════════════════════════════════════
   ACTUALIZAR MONTO DESDE PLAN
═══════════════════════════════════════════════════════════ */
function actualizarMonto() {
    var sel = document.getElementById('plan_id');
    var opt = sel && sel.options[sel.selectedIndex];
    if (opt && opt.dataset.precio) {
        var precio = parseFloat(opt.dataset.precio);
        document.getElementById('monto_mensual').value = precio.toFixed(2);
        document.getElementById('monto_total').value   = precio.toFixed(2);
    }
}


/* ═══════════════════════════════════════════════════════════
   VALIDACIÓN DEL FORMULARIO
═══════════════════════════════════════════════════════════ */
document.getElementById('formContrato').addEventListener('submit', function(e) {
    var accion = document.getElementById('accionContrato').value;

    /* Verificar cliente al crear */
    if (accion === 'crear') {
        var clienteId = document.getElementById('clienteIdHidden').value;
        if (!clienteId) {
            e.preventDefault();
            mostrarToast('Debe seleccionar un cliente.', 'error');
            document.getElementById('buscarCliente').focus();
            return;
        }
    }

    /* Validar suma de porcentajes beneficiarios */
    var total = 0;
    document.querySelectorAll('[name*="[porcentaje]"]').forEach(function(i){
        total += parseFloat(i.value || 0);
    });
    if (total > 100) {
        e.preventDefault();
        mostrarToast('La suma de porcentajes de beneficiarios no puede superar el 100%.', 'error');
        return;
    }
});

/* ═══════════════════════════════════════════════════════════
   AUTO-OCULTAR ALERTA
═══════════════════════════════════════════════════════════ */
(function() {
    var a = document.getElementById('alertaGlobal');
    if (a) setTimeout(function(){ a.style.opacity='0'; a.style.transition='opacity .5s';
        setTimeout(function(){ a.remove(); }, 500); }, 5000);
})();
</script>

<?php require_once 'footer.php'; ?>