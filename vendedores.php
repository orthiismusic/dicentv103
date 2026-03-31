<?php
/* ============================================================
   vendedores.php — Gestión de Vendedores
   Sistema ORTHIIS — Seguros de Vida
   ============================================================ */
require_once 'config.php';
verificarSesion();

$mensaje      = '';
$tipo_mensaje = '';

/* ── Helper código ─────────────────────────────────────────── */
function siguienteCodigoVendedor($conn): string {
    $r = $conn->query("SELECT MAX(CAST(codigo AS UNSIGNED)) AS u FROM vendedores")->fetch();
    return str_pad(($r['u'] ?? 0) + 1, 3, '0', STR_PAD_LEFT);
}

/* ============================================================
   PROCESAR POST
   ============================================================ */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    try {
        $conn->beginTransaction();

        switch ($_POST['action']) {

            case 'crear':
                $codigo = siguienteCodigoVendedor($conn);
                $conn->prepare("
                    INSERT INTO vendedores (codigo, nombre_completo, descripcion, fecha_ingreso, estado)
                    VALUES (?, ?, ?, ?, 'activo')
                ")->execute([
                    $codigo,
                    trim($_POST['nombre_completo']),
                    trim($_POST['descripcion'] ?? ''),
                    $_POST['fecha_ingreso'],
                ]);
                $mensaje      = "Vendedor <strong>" . htmlspecialchars($_POST['nombre_completo']) . "</strong> registrado exitosamente.";
                $tipo_mensaje = 'success';
                break;

            case 'editar':
                $conn->prepare("
                    UPDATE vendedores
                    SET nombre_completo=?, descripcion=?, fecha_ingreso=?, estado=?
                    WHERE id=?
                ")->execute([
                    trim($_POST['nombre_completo']),
                    trim($_POST['descripcion'] ?? ''),
                    $_POST['fecha_ingreso'],
                    $_POST['estado'],
                    intval($_POST['id']),
                ]);
                $mensaje      = "Vendedor actualizado exitosamente.";
                $tipo_mensaje = 'success';
                break;

            case 'eliminar':
                $id = intval($_POST['id']);
                $s  = $conn->prepare("SELECT COUNT(*) FROM clientes WHERE vendedor_id = ?");
                $s->execute([$id]);
                if ((int)$s->fetchColumn() > 0) {
                    throw new Exception("No se puede eliminar: el vendedor tiene clientes asignados.");
                }
                $conn->prepare("DELETE FROM vendedores WHERE id=?")->execute([$id]);
                $mensaje      = "Vendedor eliminado exitosamente.";
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

/* ── Query principal ─────────────────────────────────────── */
$vendedores = $conn->query("
    SELECT v.*,
           COUNT(DISTINCT cl.id)  AS total_clientes,
           COUNT(DISTINCT co.id)  AS total_contratos,
           COALESCE(SUM(CASE WHEN f.estado = 'pagada' THEN f.monto ELSE 0 END), 0) AS total_facturado
    FROM vendedores v
    LEFT JOIN clientes   cl ON cl.vendedor_id = v.id
    LEFT JOIN contratos  co ON co.vendedor_id = v.id AND co.estado = 'activo'
    LEFT JOIN facturas    f  ON f.contrato_id  = co.id
    GROUP BY v.id
    ORDER BY v.nombre_completo ASC
")->fetchAll();

/* ── KPI stats ───────────────────────────────────────────── */
$total_vend    = count($vendedores);
$vend_activos  = count(array_filter($vendedores, fn($v) => $v['estado'] === 'activo'));
$total_clients = array_sum(array_column($vendedores, 'total_clientes'));
$total_ctrs    = array_sum(array_column($vendedores, 'total_contratos'));

require_once 'header.php';
?>
<!-- ============================================================
     ESTILOS ESPECÍFICOS
     ============================================================ -->
<style>
/* ── KPI CARDS ── */
.kpi-vendedores {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 18px;
    margin-bottom: 28px;
}
@media(max-width:1100px){ .kpi-vendedores { grid-template-columns: repeat(2,1fr); } }
@media(max-width:600px)  { .kpi-vendedores { grid-template-columns: 1fr; } }

.kpi-vendedores .kpi-card {
    border-radius: var(--radius);
    padding: 22px 22px 18px;
    position: relative;
    overflow: hidden;
    box-shadow: var(--shadow);
    transition: var(--transition);
    color: white;
    cursor: default;
}
.kpi-vendedores .kpi-card:hover { transform: translateY(-3px); box-shadow: var(--shadow-md); }
.kpi-vendedores .kpi-card::before {
    content:''; position:absolute; top:0; right:0;
    width:80px; height:80px;
    border-radius:0 var(--radius) 0 100%;
    opacity:.15; background:white;
}
.kpi-vendedores .kpi-label {
    font-size:11px; font-weight:600; color:rgba(255,255,255,.80);
    text-transform:uppercase; letter-spacing:.8px; margin-bottom:10px;
}
.kpi-vendedores .kpi-top {
    display:flex; align-items:flex-start; justify-content:space-between; margin-bottom:6px;
}
.kpi-vendedores .kpi-value {
    font-size:30px; font-weight:800; color:white; line-height:1; margin-bottom:4px;
}
.kpi-vendedores .kpi-sub  { font-size:11px; color:rgba(255,255,255,.70); font-weight:500; }
.kpi-vendedores .kpi-icon {
    width:48px; height:48px;
    background:rgba(255,255,255,.18); border-radius:var(--radius-sm);
    display:flex; align-items:center; justify-content:center;
    font-size:20px; color:white; flex-shrink:0;
}
.kpi-vendedores .kpi-footer {
    margin-top:14px; padding-top:12px;
    border-top:1px solid rgba(255,255,255,.15);
    font-size:11.5px; color:rgba(255,255,255,.80); font-weight:600;
    display:flex; align-items:center; gap:6px;
}

/* ── Tabla ── */
.td-vend-name  { font-weight:700; color:var(--gray-800); font-size:13.5px; }
.td-vend-code  { font-family:monospace; font-size:11px; color:var(--gray-400); margin-top:2px; }
.td-muted      { color:var(--gray-400); font-size:12.5px; }
.td-num        { font-weight:700; color:var(--gray-800); font-size:13px; }
.td-amount     { font-weight:700; color:#16A34A; font-size:13px; }

/* ── Barra filtros ── */
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

/* ── Badges ── */
.badge {
    display:inline-flex; align-items:center;
    padding:4px 12px; border-radius:20px;
    font-size:11px; font-weight:700; white-space:nowrap;
}
.badge-activo   { background:#DCFCE7; color:#15803D; }
.badge-inactivo { background:#FEE2E2; color:#DC2626; }

/* ── Botones acción ── */
.tbl-actions { display:flex; align-items:center; justify-content:center; gap:5px; }
.btn-tbl {
    width:32px; height:32px; border-radius:var(--radius-sm); border:none;
    display:inline-flex; align-items:center; justify-content:center;
    font-size:13px; cursor:pointer; transition:var(--transition); text-decoration:none;
}
.btn-tbl:hover { transform:translateY(-2px); box-shadow:var(--shadow); }
.btn-tbl.edit { background:#FFFBEB; color:#D97706; }
.btn-tbl.del  { background:#FEF2F2; color:#DC2626; }
.btn-tbl.edit:hover { background:#D97706; color:white; }
.btn-tbl.del:hover  { background:#DC2626; color:white; }

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
.pag-btn.active  { background:var(--accent); color:white; border-color:var(--accent); }
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
.modal-box.md  { max-width:560px; }
.modal-box.lg  { max-width:680px; }
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
.mbody  { padding:22px; overflow-y:auto; flex:1; }
.mfooter {
    padding:14px 22px; border-top:1px solid var(--gray-100);
    display:flex; justify-content:flex-end; gap:10px;
    flex-shrink:0; background:var(--gray-50);
    border-radius:0 0 var(--radius-lg) var(--radius-lg);
}

/* ── Formulario ── */
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
@media(max-width:560px){ .form-grid.cols-2 { grid-template-columns:1fr; } }
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

/* ── Alert global ── */
.alert-global {
    padding:12px 18px; border-radius:var(--radius-sm); margin-bottom:20px;
    display:flex; align-items:center; gap:10px;
    font-size:13.5px; font-weight:500; animation:slideDown .3s ease;
}
.alert-global.success { background:#F0FDF4; color:#15803D; border:1px solid #BBF7D0; }
.alert-global.danger  { background:#FEF2F2; color:#DC2626; border:1px solid #FCA5A5; }
@keyframes slideDown { from{opacity:0;transform:translateY(-10px)} to{opacity:1;transform:translateY(0)} }

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
.btn-sm { padding:7px 14px; font-size:12.5px; }

/* ── Fade in ── */
.fade-in { animation:fadeIn .4s ease both; }
.delay-1 { animation-delay:.10s; }
.delay-2 { animation-delay:.20s; }
@keyframes fadeIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }

/* ── Avatar vendedor ── */
.vend-avatar {
    width:38px; height:38px; border-radius:50%;
    display:flex; align-items:center; justify-content:center;
    font-size:13px; font-weight:700; color:white;
    flex-shrink:0;
}

/* ── Mini stat chip ── */
.stat-chip {
    display:inline-flex; align-items:center; gap:5px;
    padding:4px 10px; border-radius:20px;
    font-size:11.5px; font-weight:700;
    border:1.5px solid var(--gray-200); background:var(--white);
    color:var(--gray-600); white-space:nowrap;
}
.stat-chip.blue  { background:#EFF6FF; border-color:#BFDBFE; color:var(--accent); }
.stat-chip.green { background:#F0FDF4; border-color:#BBF7D0; color:#16A34A; }
</style>

<!-- ============================================================
     PAGE HEADER
     ============================================================ -->
<div class="page-header fade-in">
    <div>
        <div class="page-title">Gestión de Vendedores</div>
        <div class="page-subtitle">
            <?php echo $total_vend; ?> vendedor<?php echo $total_vend !== 1 ? 'es' : ''; ?> registrados en el sistema
        </div>
    </div>
    <div class="page-header-actions">
        <button class="btn btn-primary" onclick="abrirModalNuevo()">
            <i class="fas fa-plus"></i> Nuevo Vendedor
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
<div class="kpi-vendedores fade-in delay-1">
    <div class="kpi-card" style="background:linear-gradient(135deg,#1565C0,#1976D2);">
        <div class="kpi-label">Total Vendedores</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo $total_vend; ?></div>
                <div class="kpi-sub">Registrados en el sistema</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-briefcase"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-database"></i> Todos los vendedores</div>
    </div>

    <div class="kpi-card" style="background:linear-gradient(135deg,#1B5E20,#2E7D32);">
        <div class="kpi-label">Vendedores Activos</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo $vend_activos; ?></div>
                <div class="kpi-sub">Disponibles para asignar</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-user-check"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-check-circle"></i> En operación</div>
    </div>

    <div class="kpi-card" style="background:linear-gradient(135deg,#E65100,#F57F17);">
        <div class="kpi-label">Clientes Asignados</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo number_format($total_clients); ?></div>
                <div class="kpi-sub">Total de clientes</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-users"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-user-tie"></i> Distribuidos entre vendedores</div>
    </div>

    <div class="kpi-card" style="background:linear-gradient(135deg,#4A148C,#6A1B9A);">
        <div class="kpi-label">Contratos Activos</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo number_format($total_ctrs); ?></div>
                <div class="kpi-sub">Contratos vigentes</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-file-contract"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-chart-line"></i> En cartera activa</div>
    </div>
</div>

<!-- ============================================================
     BARRA DE BÚSQUEDA Y FILTROS
     ============================================================ -->
<div class="filter-bar-h fade-in delay-2">
    <div class="filter-row-fields">
        <!-- Búsqueda (filtrado client-side) -->
        <div class="filter-field field-search" style="max-width:400px;">
            <label for="searchInput"><i class="fas fa-search"></i> Buscar</label>
            <div class="search-wrap-h">
                <i class="fas fa-search search-icon-h"></i>
                <input type="text"
                       id="searchInput"
                       class="filter-input"
                       placeholder="Buscar por nombre o código…"
                       oninput="filtrarTabla(this.value)"
                       autocomplete="off">
            </div>
        </div>
        <!-- Estado -->
        <div class="filter-field field-select">
            <label for="filtroEstado"><i class="fas fa-circle-half-stroke"></i> Estado</label>
            <select id="filtroEstado" class="filter-select-h"
                    onchange="filtrarTabla(document.getElementById('searchInput').value)">
                <option value="all">Todos los estados</option>
                <option value="activo">Activos</option>
                <option value="inactivo">Inactivos</option>
            </select>
        </div>
    </div>
    <div class="filter-row-btns">
        <button type="button" class="btn btn-secondary btn-sm" onclick="limpiarFiltros()">
            <i class="fas fa-times"></i> Limpiar
        </button>
        <div class="filter-results-info" id="tablaInfo">
            <?php echo $total_vend; ?> vendedor<?php echo $total_vend !== 1 ? 'es' : ''; ?>
        </div>
    </div>
</div>

<!-- ============================================================
     TABLA DE VENDEDORES
     ============================================================ -->
<div class="card fade-in">
    <div class="card-header">
        <div>
            <div class="card-title">Lista de Vendedores</div>
            <div class="card-subtitle" id="tablaInfo">
                <?php echo $total_vend; ?> vendedor<?php echo $total_vend !== 1 ? 'es' : ''; ?> registrados
            </div>
        </div>
    </div>

    <div style="overflow-x:auto;">
        <table class="data-table" id="tablaVendedores">
            <thead>
                <tr>
                    <th>Vendedor</th>
                    <th>F. Ingreso</th>
                    <th>Descripción</th>
                    <th style="text-align:center;">Clientes</th>
                    <th style="text-align:center;">Contratos</th>
                    <th>Facturado</th>
                    <th>Estado</th>
                    <th style="text-align:center;">Acciones</th>
                </tr>
            </thead>
            <tbody id="tablaBody">
            <?php if (!empty($vendedores)): ?>
                <?php
                $gradients = [
                    'linear-gradient(135deg,#1565C0,#1976D2)',
                    'linear-gradient(135deg,#1B5E20,#2E7D32)',
                    'linear-gradient(135deg,#E65100,#F57F17)',
                    'linear-gradient(135deg,#B71C1C,#C62828)',
                    'linear-gradient(135deg,#4A148C,#6A1B9A)',
                    'linear-gradient(135deg,#004D40,#00695C)',
                ];
                foreach ($vendedores as $i => $v):
                    $ini  = strtoupper(substr($v['nombre_completo'], 0, 1));
                    $grad = $gradients[$i % count($gradients)];
                ?>
                <tr data-nombre="<?php echo strtolower(htmlspecialchars($v['nombre_completo'])); ?>"
                    data-codigo="<?php echo strtolower(htmlspecialchars($v['codigo'])); ?>"
                    data-estado="<?php echo $v['estado']; ?>">
                    <td>
                        <div style="display:flex;align-items:center;gap:10px;">
                            <div class="vend-avatar" style="background:<?php echo $grad; ?>;">
                                <?php echo $ini; ?>
                            </div>
                            <div>
                                <div class="td-vend-name"><?php echo htmlspecialchars($v['nombre_completo']); ?></div>
                                <div class="td-vend-code">Cód. <?php echo htmlspecialchars($v['codigo']); ?></div>
                            </div>
                        </div>
                    </td>
                    <td><span class="td-muted"><?php echo date('d/m/Y', strtotime($v['fecha_ingreso'])); ?></span></td>
                    <td>
                        <span class="td-muted" style="max-width:200px;display:block;
                              overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
                              title="<?php echo htmlspecialchars($v['descripcion'] ?: ''); ?>">
                            <?php echo htmlspecialchars($v['descripcion'] ?: '—'); ?>
                        </span>
                    </td>
                    <td style="text-align:center;">
                        <span class="stat-chip <?php echo $v['total_clientes'] > 0 ? 'blue' : ''; ?>">
                            <i class="fas fa-users" style="font-size:10px;"></i>
                            <?php echo number_format($v['total_clientes']); ?>
                        </span>
                    </td>
                    <td style="text-align:center;">
                        <span class="stat-chip <?php echo $v['total_contratos'] > 0 ? 'green' : ''; ?>">
                            <i class="fas fa-file-contract" style="font-size:10px;"></i>
                            <?php echo number_format($v['total_contratos']); ?>
                        </span>
                    </td>
                    <td>
                        <span class="td-amount">
                            RD$<?php echo number_format($v['total_facturado'], 0); ?>
                        </span>
                    </td>
                    <td>
                        <span class="badge badge-<?php echo $v['estado']; ?>">
                            <?php echo ucfirst($v['estado']); ?>
                        </span>
                    </td>
                    <td>
                        <div class="tbl-actions">
                            <button class="btn-tbl edit" title="Editar"
                                    onclick='editarVendedor(<?php echo json_encode([
                                        "id"             => $v["id"],
                                        "codigo"         => $v["codigo"],
                                        "nombre_completo"=> $v["nombre_completo"],
                                        "descripcion"    => $v["descripcion"],
                                        "fecha_ingreso"  => $v["fecha_ingreso"],
                                        "estado"         => $v["estado"],
                                        "total_clientes" => $v["total_clientes"],
                                        "total_contratos"=> $v["total_contratos"],
                                    ], JSON_HEX_APOS|JSON_HEX_QUOT); ?>)'>
                                <i class="fas fa-pen"></i>
                            </button>
                            <?php if ($v['total_clientes'] == 0 && $v['total_contratos'] == 0): ?>
                            <button class="btn-tbl del" title="Eliminar vendedor"
                                    onclick="confirmarEliminar(<?php echo $v['id']; ?>, '<?php echo htmlspecialchars(addslashes($v['nombre_completo'])); ?>')">
                                <i class="fas fa-trash"></i>
                            </button>
                            <?php else: ?>
                            <button class="btn-tbl" title="Tiene clientes o contratos asignados — no eliminable"
                                    style="background:var(--gray-100);color:var(--gray-300);cursor:not-allowed;"
                                    disabled>
                                <i class="fas fa-lock"></i>
                            </button>
                            <?php endif; ?>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr>
                    <td colspan="8" style="text-align:center;padding:40px;color:var(--gray-400);">
                        <i class="fas fa-briefcase" style="font-size:32px;display:block;margin-bottom:10px;opacity:.4;"></i>
                        No hay vendedores registrados.
                    </td>
                </tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>

    <div class="paginador-wrap" id="paginadorWrap" style="display:none;">
        <div class="paginador-info" id="paginadorInfo"></div>
        <div class="paginador-pages" id="paginadorPages"></div>
        <div class="paginador-rpp">
            <span>Mostrar:</span>
            <select id="rppSelect" onchange="cambiarRPP(this.value)">
                <option value="10">10</option>
                <option value="15" selected>15</option>
                <option value="25">25</option>
                <option value="50">50</option>
            </select>
            <span>por página</span>
        </div>
    </div>
</div>


<!-- ============================================================
     MODAL: CREAR / EDITAR VENDEDOR
     ============================================================ -->
<div class="modal-overlay" id="overlayVendedor">
    <div class="modal-box md">
        <div class="mhdr">
            <div class="mhdr-title" id="vendedorModalTitulo">
                <i class="fas fa-briefcase" style="color:var(--accent);"></i>
                <span id="textoTituloVend">Nuevo Vendedor</span>
            </div>
            <button class="modal-close-btn" onclick="cerrarOverlay('overlayVendedor')">
                <i class="fas fa-times"></i>
            </button>
        </div>

        <form id="vendedorForm" method="POST">
            <div class="mbody">
                <input type="hidden" name="action" id="vendedorAction" value="crear">
                <input type="hidden" name="id"     id="vendedorId"     value="">

                <div class="fsec-title"><i class="fas fa-id-badge"></i> Datos del Vendedor</div>

                <div class="form-grid cols-2">
                    <div class="form-group">
                        <label class="form-label">Código</label>
                        <input type="text" id="codigoVend" class="form-control" readonly
                               value="Se generará automáticamente">
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="vend_fecha_ingreso">Fecha de Ingreso</label>
                        <input type="date" name="fecha_ingreso" id="vend_fecha_ingreso"
                               class="form-control" required>
                    </div>
                </div>

                <div class="form-group" style="margin-top:14px;">
                    <label class="form-label required" for="vend_nombre_completo">Nombre Completo</label>
                    <input type="text" name="nombre_completo" id="vend_nombre_completo"
                           class="form-control" required placeholder="Nombre y apellidos">
                </div>

                <div class="form-group" style="margin-top:14px;">
                    <label class="form-label" for="vend_descripcion">Descripción / Notas</label>
                    <textarea name="descripcion" id="vend_descripcion" class="form-control"
                              rows="3" placeholder="Información adicional (opcional)"></textarea>
                </div>

                <!-- Estado — solo al editar -->
                <div id="vendEstadoGrp" style="display:none;margin-top:14px;">
                    <div class="fsec-title"><i class="fas fa-toggle-on"></i> Estado</div>
                    <div class="form-group">
                        <label class="form-label" for="vend_estado">Estado del vendedor</label>
                        <select name="estado" id="vend_estado" class="form-control">
                            <option value="activo">Activo</option>
                            <option value="inactivo">Inactivo</option>
                        </select>
                    </div>
                </div>
            </div>
            <div class="mfooter">
                <button type="button" class="btn btn-secondary"
                        onclick="cerrarOverlay('overlayVendedor')">
                    <i class="fas fa-times"></i> Cancelar
                </button>
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-save"></i>
                    <span id="btnVendTexto">Guardar Vendedor</span>
                </button>
            </div>
        </form>
    </div>
</div>


<!-- ============================================================
     MODAL: CONFIRMAR ELIMINAR
     ============================================================ -->
<div class="modal-overlay" id="overlayEliminarVend">
    <div class="modal-box sm">
        <div class="mhdr">
            <div class="mhdr-title" style="color:#DC2626;">
                <i class="fas fa-trash"></i> Eliminar Vendedor
            </div>
            <button class="modal-close-btn" onclick="cerrarOverlay('overlayEliminarVend')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="mbody">
            <div id="eliminarVendDetalles" style="margin-bottom:14px;"></div>
            <div style="background:#FEF2F2;border:1px solid #FCA5A5;border-radius:var(--radius-sm);
                        padding:14px 16px;color:#991B1B;font-size:13.5px;">
                <i class="fas fa-exclamation-circle" style="margin-right:6px;"></i>
                <strong>¿Confirmar eliminación?</strong><br>
                <span style="font-size:12.5px;opacity:.85;">
                    Esta acción no puede revertirse.
                </span>
            </div>
        </div>
        <div class="mfooter">
            <button class="btn btn-secondary" onclick="cerrarOverlay('overlayEliminarVend')">
                <i class="fas fa-arrow-left"></i> Volver
            </button>
            <button class="btn btn-danger" id="btnConfirmarEliminarVend">
                <i class="fas fa-trash"></i> Sí, eliminar
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
function esc(s) {
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

/* ═══════════════════════════════════════════════════════════
   PAGINACIÓN CLIENTE (JS)
═══════════════════════════════════════════════════════════ */
var _allRows    = [];
var _filtered   = [];
var _currentPage = 1;
var _rpp        = 15;

function initTabla() {
    var rows = document.querySelectorAll('#tablaBody tr[data-nombre]');
    _allRows = Array.from(rows);
    _filtered = _allRows.slice();
    renderPaginador();
}

function filtrarTabla(q) {
    var estado = document.getElementById('filtroEstado').value;
    q = (q||'').toLowerCase().trim();

    _filtered = _allRows.filter(function(row) {
        var nombre = row.getAttribute('data-nombre') || '';
        var codigo = row.getAttribute('data-codigo') || '';
        var est    = row.getAttribute('data-estado') || '';

        var matchText  = !q || nombre.includes(q) || codigo.includes(q);
        var matchState = estado === 'all' || est === estado;
        return matchText && matchState;
    });

    _currentPage = 1;
    renderPaginador();
}

function limpiarFiltros() {
    document.getElementById('searchInput').value   = '';
    document.getElementById('filtroEstado').value  = 'all';
    filtrarTabla('');
}

function cambiarRPP(v) {
    _rpp = parseInt(v);
    _currentPage = 1;
    renderPaginador();
}

function renderPaginador() {
    var total       = _filtered.length;
    var totalPages  = Math.max(1, Math.ceil(total / _rpp));
    _currentPage    = Math.min(_currentPage, totalPages);

    var start = (_currentPage - 1) * _rpp;
    var end   = Math.min(start + _rpp, total);

    /* Mostrar/ocultar filas */
    _allRows.forEach(function(row){ row.style.display = 'none'; });
    _filtered.slice(start, end).forEach(function(row){ row.style.display = ''; });

    /* Fila vacía */
    var emptyRow = document.getElementById('emptyRow');
    if (total === 0) {
        if (!emptyRow) {
            var tr = document.createElement('tr');
            tr.id = 'emptyRow';
            tr.innerHTML = '<td colspan="8" style="text-align:center;padding:40px;color:var(--gray-400);">' +
                '<i class="fas fa-briefcase" style="font-size:32px;display:block;margin-bottom:10px;opacity:.4;"></i>' +
                'No se encontraron vendedores con los filtros aplicados.</td>';
            document.getElementById('tablaBody').appendChild(tr);
        }
    } else {
        if (emptyRow) emptyRow.remove();
    }

    /* Info */
    document.getElementById('tablaInfo').textContent =
        'Mostrando ' + (total > 0 ? start+1 : 0) + '–' + end + ' de ' + total + ' vendedores';

    /* Paginador */
    var wrap = document.getElementById('paginadorWrap');
    if (totalPages <= 1 && total > 0) {
        wrap.style.display = 'none';
        return;
    }
    wrap.style.display = 'flex';

    document.getElementById('paginadorInfo').innerHTML =
        'Mostrando <strong>' + (total > 0 ? start+1 : 0) + '–' + end + '</strong> de <strong>' + total + '</strong>';

    /* Botones de página */
    var pages = document.getElementById('paginadorPages');
    pages.innerHTML = '';

    /* Primera */
    pages.innerHTML += '<a class="pag-btn ' + (_currentPage<=1?'disabled':'') + '" onclick="irPagina(1)" href="javascript:void(0)">' +
        '<i class="fas fa-angles-left" style="font-size:10px;"></i></a>';
    pages.innerHTML += '<a class="pag-btn ' + (_currentPage<=1?'disabled':'') + '" onclick="irPagina(' + (_currentPage-1) + ')" href="javascript:void(0)">' +
        '<i class="fas fa-angle-left" style="font-size:11px;"></i></a>';

    var pStart = Math.max(1, _currentPage-2);
    var pEnd   = Math.min(totalPages, _currentPage+2);
    for (var p = pStart; p <= pEnd; p++) {
        pages.innerHTML += '<a class="pag-btn ' + (p===_currentPage?'active':'') + '" onclick="irPagina(' + p + ')" href="javascript:void(0)">' + p + '</a>';
    }

    pages.innerHTML += '<a class="pag-btn ' + (_currentPage>=totalPages?'disabled':'') + '" onclick="irPagina(' + (_currentPage+1) + ')" href="javascript:void(0)">' +
        '<i class="fas fa-angle-right" style="font-size:11px;"></i></a>';
    pages.innerHTML += '<a class="pag-btn ' + (_currentPage>=totalPages?'disabled':'') + '" onclick="irPagina(' + totalPages + ')" href="javascript:void(0)">' +
        '<i class="fas fa-angles-right" style="font-size:10px;"></i></a>';
}

function irPagina(p) {
    _currentPage = p;
    renderPaginador();
}

/* Init al cargar */
document.addEventListener('DOMContentLoaded', function() { initTabla(); });


/* ═══════════════════════════════════════════════════════════
   MODAL: NUEVO VENDEDOR
═══════════════════════════════════════════════════════════ */
function abrirModalNuevo() {
    document.getElementById('vendedorForm').reset();
    document.getElementById('vendedorAction').value         = 'crear';
    document.getElementById('vendedorId').value             = '';
    document.getElementById('textoTituloVend').textContent  = 'Nuevo Vendedor';
    document.getElementById('btnVendTexto').textContent     = 'Guardar Vendedor';
    document.getElementById('codigoVend').value             = 'Se generará automáticamente';
    document.getElementById('vendEstadoGrp').style.display  = 'none';
    document.getElementById('vend_fecha_ingreso').valueAsDate = new Date();
    abrirOverlay('overlayVendedor');
}


/* ═══════════════════════════════════════════════════════════
   MODAL: EDITAR VENDEDOR
═══════════════════════════════════════════════════════════ */
function editarVendedor(v) {
    document.getElementById('vendedorForm').reset();
    document.getElementById('vendedorAction').value         = 'editar';
    document.getElementById('vendedorId').value             = v.id;
    document.getElementById('textoTituloVend').textContent  = 'Editar Vendedor';
    document.getElementById('btnVendTexto').textContent     = 'Actualizar Vendedor';

    document.getElementById('codigoVend').value              = v.codigo;
    document.getElementById('vend_nombre_completo').value    = v.nombre_completo;
    document.getElementById('vend_descripcion').value        = v.descripcion || '';
    document.getElementById('vend_fecha_ingreso').value      = v.fecha_ingreso;
    document.getElementById('vend_estado').value             = v.estado;
    document.getElementById('vendEstadoGrp').style.display   = 'block';

    abrirOverlay('overlayVendedor');
}


/* ═══════════════════════════════════════════════════════════
   MODAL: ELIMINAR VENDEDOR
═══════════════════════════════════════════════════════════ */
var _vendAEliminar = null;

function confirmarEliminar(id, nombre) {
    _vendAEliminar = id;
    document.getElementById('eliminarVendDetalles').innerHTML =
        '<div style="background:var(--gray-50);border:1px solid var(--gray-200);' +
        'border-radius:var(--radius-sm);padding:14px 16px;margin-bottom:0;">' +
        '<div style="font-size:10.5px;text-transform:uppercase;letter-spacing:.5px;' +
        'color:var(--gray-400);font-weight:700;margin-bottom:4px;">Vendedor a eliminar</div>' +
        '<div style="font-size:15px;font-weight:800;color:var(--gray-800);">' + esc(nombre) + '</div>' +
        '</div>';
    abrirOverlay('overlayEliminarVend');
}

document.getElementById('btnConfirmarEliminarVend').addEventListener('click', function() {
    if (!_vendAEliminar) return;
    var f = document.createElement('form');
    f.method = 'POST';
    f.innerHTML = '<input type="hidden" name="action" value="eliminar">' +
                  '<input type="hidden" name="id"     value="' + _vendAEliminar + '">';
    document.body.appendChild(f);
    f.submit();
});


/* ═══════════════════════════════════════════════════════════
   CERRAR MODALES CON OVERLAY CLICK
═══════════════════════════════════════════════════════════ */
['overlayVendedor','overlayEliminarVend'].forEach(function(id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener('click', function(e){
        if (e.target === el) cerrarOverlay(id);
    });
});


/* ═══════════════════════════════════════════════════════════
   AUTO-OCULTAR ALERTA
═══════════════════════════════════════════════════════════ */
(function() {
    var a = document.getElementById('alertaGlobal');
    if (a) setTimeout(function(){
        a.style.opacity = '0'; a.style.transition = 'opacity .5s';
        setTimeout(function(){ a.remove(); }, 500);
    }, 5000);
})();
</script>

<?php require_once 'footer.php'; ?>