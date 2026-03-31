<?php
/* ============================================================
   cobradores.php — Gestión de Cobradores
   Sistema ORTHIIS — Seguros de Vida
   ============================================================ */
require_once 'config.php';
verificarSesion();

$mensaje      = '';
$tipo_mensaje = '';

/* ── Helper código ─────────────────────────────────────────── */
function siguienteCodigoCobrador($conn): string {
    $r = $conn->query("SELECT MAX(CAST(codigo AS UNSIGNED)) AS u FROM cobradores")->fetch();
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
                $codigo = siguienteCodigoCobrador($conn);
                $conn->prepare("
                    INSERT INTO cobradores
                        (codigo, nombre_completo, descripcion, fecha_ingreso, estado)
                    VALUES (?, ?, ?, ?, 'activo')
                ")->execute([
                    $codigo,
                    trim($_POST['nombre_completo']),
                    trim($_POST['descripcion'] ?? ''),
                    $_POST['fecha_ingreso'],
                ]);
                $mensaje      = "Cobrador registrado exitosamente.";
                $tipo_mensaje = 'success';
                break;

            case 'editar':
                $conn->prepare("
                    UPDATE cobradores
                    SET nombre_completo=?, descripcion=?, fecha_ingreso=?, estado=?
                    WHERE id=?
                ")->execute([
                    trim($_POST['nombre_completo']),
                    trim($_POST['descripcion'] ?? ''),
                    $_POST['fecha_ingreso'],
                    $_POST['estado'],
                    intval($_POST['id']),
                ]);
                $mensaje      = "Cobrador actualizado exitosamente.";
                $tipo_mensaje = 'success';
                break;

            case 'eliminar':
                $id = intval($_POST['id']);
                $s  = $conn->prepare("SELECT COUNT(*) FROM clientes WHERE cobrador_id=?");
                $s->execute([$id]);
                if ((int)$s->fetchColumn() > 0) {
                    throw new Exception("No se puede eliminar: este cobrador tiene clientes asignados.");
                }
                $conn->prepare("DELETE FROM cobradores WHERE id=?")->execute([$id]);
                $mensaje      = "Cobrador eliminado exitosamente.";
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

/* ── Query principal ────────────────────────────────────────── */
$cobradores = $conn->query("
    SELECT cb.*,
           COUNT(DISTINCT cl.id)     AS total_clientes,
           COUNT(DISTINCT pg.id)     AS total_pagos,
           COALESCE(SUM(pg.monto),0) AS total_cobrado,
           COUNT(DISTINCT af.id)     AS total_asignaciones
    FROM cobradores cb
    LEFT JOIN clientes              cl ON cl.cobrador_id  = cb.id
    LEFT JOIN pagos                 pg ON pg.cobrador_id  = cb.id AND pg.estado = 'procesado'
    LEFT JOIN asignaciones_facturas af ON af.cobrador_id  = cb.id AND af.estado = 'activa'
    GROUP BY cb.id
    ORDER BY cb.nombre_completo ASC
")->fetchAll();

/* ── KPI stats ──────────────────────────────────────────────── */
$total_cob       = count($cobradores);
$cob_activos     = count(array_filter($cobradores, fn($c) => $c['estado'] === 'activo'));
$total_clientes  = array_sum(array_column($cobradores, 'total_clientes'));
$total_cobrado   = array_sum(array_column($cobradores, 'total_cobrado'));

require_once 'header.php';
?>
<!-- ============================================================
     ESTILOS ESPECÍFICOS
     ============================================================ -->
<style>
/* ── KPI CARDS ── */
.kpi-cobradores {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 18px;
    margin-bottom: 28px;
}
@media(max-width:1100px){ .kpi-cobradores { grid-template-columns: repeat(2,1fr); } }
@media(max-width:600px)  { .kpi-cobradores { grid-template-columns: 1fr; } }

.kpi-cobradores .kpi-card {
    border-radius: var(--radius);
    padding: 22px 22px 18px;
    position: relative;
    overflow: hidden;
    box-shadow: var(--shadow);
    transition: var(--transition);
    color: white;
    cursor: default;
}
.kpi-cobradores .kpi-card:hover { transform: translateY(-3px); box-shadow: var(--shadow-md); }
.kpi-cobradores .kpi-card::before {
    content:''; position:absolute; top:0; right:0;
    width:80px; height:80px;
    border-radius:0 var(--radius) 0 100%;
    opacity:.15; background:white;
}
.kpi-cobradores .kpi-label {
    font-size:11px; font-weight:600; color:rgba(255,255,255,.80);
    text-transform:uppercase; letter-spacing:.8px; margin-bottom:10px;
}
.kpi-cobradores .kpi-top {
    display:flex; align-items:flex-start; justify-content:space-between; margin-bottom:6px;
}
.kpi-cobradores .kpi-value {
    font-size:30px; font-weight:800; color:white; line-height:1; margin-bottom:4px;
}
.kpi-cobradores .kpi-sub  { font-size:11px; color:rgba(255,255,255,.70); font-weight:500; }
.kpi-cobradores .kpi-icon {
    width:48px; height:48px;
    background:rgba(255,255,255,.18); border-radius:var(--radius-sm);
    display:flex; align-items:center; justify-content:center;
    font-size:20px; color:white; flex-shrink:0;
}
.kpi-cobradores .kpi-footer {
    margin-top:14px; padding-top:12px;
    border-top:1px solid rgba(255,255,255,.15);
    font-size:11.5px; color:rgba(255,255,255,.80); font-weight:600;
    display:flex; align-items:center; gap:6px;
}

/* ── Tabla ── */
.cobrador-name  { font-weight:600; color:var(--gray-800); font-size:13px; }
.cobrador-code  { font-size:11px; color:var(--gray-400); font-family:monospace; }
.td-muted       { color:var(--gray-400); font-size:12px; }
.td-amount      { font-weight:700; color:var(--gray-800); font-size:13px; }
.td-accent      { font-weight:700; color:var(--accent); font-size:13px; }

/* ── Badges ── */
.badge {
    display:inline-flex; align-items:center;
    padding:4px 12px; border-radius:20px;
    font-size:11px; font-weight:700; white-space:nowrap;
}
.badge-activo   { background:#DCFCE7; color:#15803D; }
.badge-inactivo { background:#FEE2E2; color:#DC2626; }

/* ── Botones de acción ── */
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
.modal-box.lg  { max-width:720px; }
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

/* ── Paginador (por si la lista crece) ── */
.paginador-wrap {
    display:flex; align-items:center; justify-content:space-between;
    padding:14px 20px; border-top:1px solid var(--gray-100);
    background:var(--gray-50); border-radius:0 0 var(--radius) var(--radius);
    flex-wrap:wrap; gap:10px;
}

/* ── Fade in ── */
.fade-in { animation:fadeIn .4s ease both; }
.delay-1 { animation-delay:.10s; }
.delay-2 { animation-delay:.20s; }
@keyframes fadeIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }

/* ── Avatar cobrador ── */
.cobrador-avatar {
    width:36px; height:36px; border-radius:50%;
    background:linear-gradient(135deg, #E65100, #F57F17);
    display:flex; align-items:center; justify-content:center;
    font-size:12px; font-weight:700; color:white; flex-shrink:0;
}

/* ── Mini stats row dentro del modal de confirmación ── */
.confirm-detail-row {
    background:var(--gray-50); border:1px solid var(--gray-200);
    border-radius:var(--radius-sm); padding:14px 16px;
    display:grid; gap:8px; margin-bottom:14px;
}
.confirm-detail-label {
    font-size:10.5px; text-transform:uppercase; letter-spacing:.5px;
    color:var(--gray-400); font-weight:700;
}
.confirm-detail-val {
    font-size:15px; font-weight:700; color:var(--gray-800);
}

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
</style>

<!-- ============================================================
     PAGE HEADER
     ============================================================ -->
<div class="page-header fade-in">
    <div>
        <div class="page-title">Gestión de Cobradores</div>
        <div class="page-subtitle">
            <?php echo $total_cob; ?> cobrador<?php echo $total_cob !== 1 ? 'es' : ''; ?> registrados en el sistema
        </div>
    </div>
    <div class="page-header-actions">
        <button class="btn btn-primary" onclick="abrirOverlay('overlayNuevoCobrador')">
            <i class="fas fa-plus"></i> Nuevo Cobrador
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
<div class="kpi-cobradores fade-in delay-1">

    <div class="kpi-card" style="background:linear-gradient(135deg,#1565C0,#1976D2);">
        <div class="kpi-label">Total Cobradores</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo $total_cob; ?></div>
                <div class="kpi-sub">Registrados en el sistema</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-users"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-database"></i> Total del equipo</div>
    </div>

    <div class="kpi-card" style="background:linear-gradient(135deg,#1B5E20,#2E7D32);">
        <div class="kpi-label">Cobradores Activos</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo $cob_activos; ?></div>
                <div class="kpi-sub">En operación actualmente</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-user-check"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-arrow-trend-up"></i> Disponibles</div>
    </div>

    <div class="kpi-card" style="background:linear-gradient(135deg,#E65100,#F57F17);">
        <div class="kpi-label">Clientes Asignados</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo number_format($total_clientes); ?></div>
                <div class="kpi-sub">Clientes bajo cobranza</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-user-group"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-arrow-right"></i> Total asignados</div>
    </div>

    <div class="kpi-card" style="background:linear-gradient(135deg,#1B5E20,#388E3C);">
        <div class="kpi-label">Total Cobrado</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value" style="font-size:22px;">
                    RD$<?php echo number_format($total_cobrado, 0); ?>
                </div>
                <div class="kpi-sub">Pagos procesados</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-money-bill-wave"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-coins"></i> Monto histórico</div>
    </div>

</div>

<!-- ============================================================
     BARRA DE BÚSQUEDA / FILTROS
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
                       placeholder="Buscar cobrador por nombre o código…"
                       oninput="filtrarTabla(this.value)"
                       autocomplete="off">
            </div>
        </div>
        <!-- Estado -->
        <div class="filter-field field-select">
            <label for="estadoFilter"><i class="fas fa-circle-half-stroke"></i> Estado</label>
            <select id="estadoFilter" class="filter-select-h" onchange="filtrarTabla()">
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
        <div class="filter-results-info" id="subtituloTabla">
            <?php echo $total_cob; ?> cobrador<?php echo $total_cob !== 1 ? 'es' : ''; ?>
        </div>
    </div>
</div>

<!-- ============================================================
     TABLA DE COBRADORES
     ============================================================ -->
<div class="card fade-in">
    <div class="card-header">
        <div>
            <div class="card-title">Lista de Cobradores</div>
            <div class="card-subtitle" id="subtituloTabla">
                <?php echo $total_cob; ?> cobrador<?php echo $total_cob !== 1 ? 'es' : ''; ?> registrados
            </div>
        </div>
    </div>

    <div style="overflow-x:auto;">
        <table class="data-table" id="cobradoresTable">
            <thead>
                <tr>
                    <th>Cobrador</th>
                    <th>Fecha Ingreso</th>
                    <th>Descripción / Zona</th>
                    <th style="text-align:center;">Clientes</th>
                    <th style="text-align:center;">Cobros</th>
                    <th style="text-align:right;">Total Cobrado</th>
                    <th style="text-align:center;">Asignaciones</th>
                    <th>Estado</th>
                    <th style="text-align:center;">Acciones</th>
                </tr>
            </thead>
            <tbody id="cobradoresTbody">
            <?php if (!empty($cobradores)): ?>
                <?php foreach ($cobradores as $c):
                    $ini = strtoupper(substr($c['nombre_completo'], 0, 2));
                    $puedeEliminar = ((int)$c['total_clientes'] === 0);
                ?>
                <tr data-nombre="<?php echo strtolower($c['nombre_completo']); ?>"
                    data-codigo="<?php echo strtolower($c['codigo']); ?>"
                    data-estado="<?php echo $c['estado']; ?>">
                    <td>
                        <div style="display:flex;align-items:center;gap:10px;">
                            <div class="cobrador-avatar"><?php echo $ini; ?></div>
                            <div>
                                <div class="cobrador-name">
                                    <?php echo htmlspecialchars($c['nombre_completo']); ?>
                                </div>
                                <div class="cobrador-code">Cód. <?php echo htmlspecialchars($c['codigo']); ?></div>
                            </div>
                        </div>
                    </td>
                    <td>
                        <span class="td-muted">
                            <?php echo date('d/m/Y', strtotime($c['fecha_ingreso'])); ?>
                        </span>
                    </td>
                    <td>
                        <span class="td-muted" style="max-width:200px;display:block;
                              overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                            <?php echo htmlspecialchars($c['descripcion'] ?: '—'); ?>
                        </span>
                    </td>
                    <td style="text-align:center;">
                        <span style="display:inline-flex;align-items:center;gap:4px;
                                     background:<?php echo $c['total_clientes'] > 0 ? '#EFF6FF' : 'var(--gray-100)'; ?>;
                                     color:<?php echo $c['total_clientes'] > 0 ? 'var(--accent)' : 'var(--gray-400)'; ?>;
                                     padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;">
                            <i class="fas fa-users" style="font-size:9px;"></i>
                            <?php echo number_format($c['total_clientes']); ?>
                        </span>
                    </td>
                    <td style="text-align:center;">
                        <span style="display:inline-flex;align-items:center;gap:4px;
                                     background:<?php echo $c['total_pagos'] > 0 ? '#F0FDF4' : 'var(--gray-100)'; ?>;
                                     color:<?php echo $c['total_pagos'] > 0 ? '#15803D' : 'var(--gray-400)'; ?>;
                                     padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;">
                            <i class="fas fa-receipt" style="font-size:9px;"></i>
                            <?php echo number_format($c['total_pagos']); ?>
                        </span>
                    </td>
                    <td style="text-align:right;">
                        <span class="td-amount">
                            RD$<?php echo number_format($c['total_cobrado'], 0); ?>
                        </span>
                    </td>
                    <td style="text-align:center;">
                        <span style="display:inline-flex;align-items:center;gap:4px;
                                     background:<?php echo $c['total_asignaciones'] > 0 ? '#FFFBEB' : 'var(--gray-100)'; ?>;
                                     color:<?php echo $c['total_asignaciones'] > 0 ? '#D97706' : 'var(--gray-400)'; ?>;
                                     padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;">
                            <i class="fas fa-file-invoice" style="font-size:9px;"></i>
                            <?php echo number_format($c['total_asignaciones']); ?>
                        </span>
                    </td>
                    <td>
                        <span class="badge badge-<?php echo $c['estado'] === 'activo' ? 'activo' : 'inactivo'; ?>">
                            <?php echo ucfirst($c['estado']); ?>
                        </span>
                    </td>
                    <td>
                        <div class="tbl-actions">
                            <button class="btn-tbl edit" title="Editar cobrador"
                                    onclick='editarCobrador(<?php echo json_encode([
                                        "id"              => $c["id"],
                                        "codigo"          => $c["codigo"],
                                        "nombre_completo" => $c["nombre_completo"],
                                        "descripcion"     => $c["descripcion"],
                                        "fecha_ingreso"   => $c["fecha_ingreso"],
                                        "estado"          => $c["estado"],
                                        "total_clientes"  => $c["total_clientes"],
                                        "total_pagos"     => $c["total_pagos"],
                                        "total_cobrado"   => $c["total_cobrado"],
                                    ], JSON_HEX_APOS|JSON_HEX_QUOT); ?>)'>
                                <i class="fas fa-pen"></i>
                            </button>
                            <?php if ($puedeEliminar): ?>
                            <button class="btn-tbl del" title="Eliminar cobrador"
                                    onclick='confirmarEliminar(<?php echo json_encode([
                                        "id"              => $c["id"],
                                        "codigo"          => $c["codigo"],
                                        "nombre_completo" => $c["nombre_completo"],
                                    ], JSON_HEX_APOS|JSON_HEX_QUOT); ?>)'>
                                <i class="fas fa-trash"></i>
                            </button>
                            <?php else: ?>
                            <button class="btn-tbl" title="Tiene <?php echo $c['total_clientes']; ?> cliente(s) asignado(s) — no puede eliminarse"
                                    style="background:var(--gray-100);color:var(--gray-400);cursor:not-allowed;"
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
                    <td colspan="9" style="text-align:center;padding:40px;color:var(--gray-400);">
                        <i class="fas fa-users" style="font-size:32px;display:block;margin-bottom:10px;opacity:.4;"></i>
                        No hay cobradores registrados.
                    </td>
                </tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>

    <!-- Pie de tabla: total visible -->
    <div class="paginador-wrap">
        <div style="font-size:12.5px;color:var(--gray-500);">
            <strong id="totalVisible"><?php echo $total_cob; ?></strong>
            cobrador<?php echo $total_cob !== 1 ? 'es' : ''; ?> mostrado<?php echo $total_cob !== 1 ? 's' : ''; ?>
        </div>
        <div style="font-size:12px;color:var(--gray-400);">
            <i class="fas fa-info-circle" style="margin-right:4px;"></i>
            El botón <i class="fas fa-lock" style="color:var(--gray-400);"></i> indica que el cobrador tiene clientes asignados y no puede eliminarse.
        </div>
    </div>
</div>


<!-- ============================================================
     MODAL: NUEVO COBRADOR
     ============================================================ -->
<div class="modal-overlay" id="overlayNuevoCobrador">
    <div class="modal-box md">
        <div class="mhdr">
            <div class="mhdr-title">
                <i class="fas fa-user-plus" style="color:var(--accent);"></i>
                Nuevo Cobrador
            </div>
            <button class="modal-close-btn" onclick="cerrarOverlay('overlayNuevoCobrador')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <form id="formNuevoCobrador" method="POST">
            <div class="mbody">
                <input type="hidden" name="action" value="crear">

                <div class="fsec-title"><i class="fas fa-id-card"></i> Datos del Cobrador</div>
                <div class="form-grid cols-2">
                    <div class="form-group">
                        <label class="form-label">Código</label>
                        <input type="text" class="form-control" readonly
                               value="Se generará automáticamente"
                               style="background:var(--gray-50);color:var(--gray-500);">
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="n_nombre_completo">Nombre Completo</label>
                        <input type="text" name="nombre_completo" id="n_nombre_completo"
                               class="form-control" required placeholder="Nombre y apellidos">
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="n_fecha_ingreso">Fecha de Ingreso</label>
                        <input type="date" name="fecha_ingreso" id="n_fecha_ingreso"
                               class="form-control" required>
                    </div>
                    <div class="form-group" style="grid-column:1/-1;">
                        <label class="form-label" for="n_descripcion">Descripción / Zona</label>
                        <textarea name="descripcion" id="n_descripcion" class="form-control"
                                  rows="3" placeholder="Zona de cobranza, notas adicionales…"></textarea>
                    </div>
                </div>
            </div>
            <div class="mfooter">
                <button type="button" class="btn btn-secondary"
                        onclick="cerrarOverlay('overlayNuevoCobrador')">
                    <i class="fas fa-times"></i> Cancelar
                </button>
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-save"></i> Guardar Cobrador
                </button>
            </div>
        </form>
    </div>
</div>


<!-- ============================================================
     MODAL: EDITAR COBRADOR
     ============================================================ -->
<div class="modal-overlay" id="overlayEditarCobrador">
    <div class="modal-box md">
        <div class="mhdr">
            <div class="mhdr-title" id="editarCobradorTitulo">
                <i class="fas fa-pen" style="color:var(--accent);"></i>
                Editar Cobrador
            </div>
            <button class="modal-close-btn" onclick="cerrarOverlay('overlayEditarCobrador')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <form id="formEditarCobrador" method="POST">
            <div class="mbody">
                <input type="hidden" name="action" value="editar">
                <input type="hidden" name="id"     id="edit_cob_id">

                <!-- Mini stats del cobrador -->
                <div id="editCobStats" style="display:none;
                     background:var(--gray-50);border:1px solid var(--gray-200);
                     border-radius:var(--radius-sm);padding:14px 16px;margin-bottom:18px;">
                    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;text-align:center;">
                        <div>
                            <div style="font-size:18px;font-weight:800;color:var(--accent);" id="statCliEdit">0</div>
                            <div style="font-size:10px;font-weight:700;color:var(--gray-400);text-transform:uppercase;letter-spacing:.4px;">Clientes</div>
                        </div>
                        <div>
                            <div style="font-size:18px;font-weight:800;color:#16A34A;" id="statPagEdit">0</div>
                            <div style="font-size:10px;font-weight:700;color:var(--gray-400);text-transform:uppercase;letter-spacing:.4px;">Cobros</div>
                        </div>
                        <div>
                            <div style="font-size:16px;font-weight:800;color:var(--gray-800);" id="statMonEdit">RD$0</div>
                            <div style="font-size:10px;font-weight:700;color:var(--gray-400);text-transform:uppercase;letter-spacing:.4px;">Cobrado</div>
                        </div>
                    </div>
                </div>

                <div class="fsec-title"><i class="fas fa-id-card"></i> Datos del Cobrador</div>
                <div class="form-grid cols-2">
                    <div class="form-group">
                        <label class="form-label">Código</label>
                        <input type="text" id="edit_cob_codigo" class="form-control" readonly>
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="edit_cob_nombre">Nombre Completo</label>
                        <input type="text" name="nombre_completo" id="edit_cob_nombre"
                               class="form-control" required placeholder="Nombre y apellidos">
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="edit_cob_fecha">Fecha de Ingreso</label>
                        <input type="date" name="fecha_ingreso" id="edit_cob_fecha"
                               class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="edit_cob_estado">Estado</label>
                        <select name="estado" id="edit_cob_estado" class="form-control" required>
                            <option value="activo">Activo</option>
                            <option value="inactivo">Inactivo</option>
                        </select>
                    </div>
                    <div class="form-group" style="grid-column:1/-1;">
                        <label class="form-label" for="edit_cob_descripcion">Descripción / Zona</label>
                        <textarea name="descripcion" id="edit_cob_descripcion" class="form-control"
                                  rows="3" placeholder="Zona de cobranza, notas adicionales…"></textarea>
                    </div>
                </div>
            </div>
            <div class="mfooter">
                <button type="button" class="btn btn-secondary"
                        onclick="cerrarOverlay('overlayEditarCobrador')">
                    <i class="fas fa-times"></i> Cancelar
                </button>
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-save"></i> Guardar Cambios
                </button>
            </div>
        </form>
    </div>
</div>


<!-- ============================================================
     MODAL: CONFIRMAR ELIMINAR
     ============================================================ -->
<div class="modal-overlay" id="overlayEliminarCobrador">
    <div class="modal-box sm">
        <div class="mhdr">
            <div class="mhdr-title" style="color:#DC2626;">
                <i class="fas fa-trash"></i> Eliminar Cobrador
            </div>
            <button class="modal-close-btn" onclick="cerrarOverlay('overlayEliminarCobrador')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="mbody">
            <div id="eliminarCobDetalles" class="confirm-detail-row"></div>
            <div style="background:#FEF2F2;border:1px solid #FCA5A5;border-radius:var(--radius-sm);
                        padding:14px 16px;color:#991B1B;font-size:13.5px;">
                <i class="fas fa-exclamation-circle" style="margin-right:6px;"></i>
                <strong>¿Confirmar eliminación?</strong><br>
                <span style="font-size:12.5px;opacity:.85;">
                    Esta acción es permanente. Solo es posible porque el cobrador no tiene clientes asignados.
                </span>
            </div>
        </div>
        <div class="mfooter">
            <button class="btn btn-secondary" onclick="cerrarOverlay('overlayEliminarCobrador')">
                <i class="fas fa-arrow-left"></i> Volver
            </button>
            <button class="btn btn-danger" id="btnConfirmarEliminar">
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
function numFmt(n) {
    return parseFloat(n||0).toLocaleString('es-DO', {minimumFractionDigits:0, maximumFractionDigits:0});
}

/* ═══════════════════════════════════════════════════════════
   MODAL: NUEVO COBRADOR
═══════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', function() {
    // Fecha de hoy por defecto al abrir el modal nuevo
    var btnNuevo = document.querySelector('[onclick="abrirOverlay(\'overlayNuevoCobrador\')"]');
    if (btnNuevo) {
        btnNuevo.addEventListener('click', function() {
            var fi = document.getElementById('n_fecha_ingreso');
            if (fi && !fi.value) {
                fi.valueAsDate = new Date();
            }
        });
    }
    // Reset del form al cerrar overlay nuevo
    document.getElementById('overlayNuevoCobrador').addEventListener('click', function(e) {
        if (e.target === this) cerrarOverlay('overlayNuevoCobrador');
    });
    document.getElementById('overlayEditarCobrador').addEventListener('click', function(e) {
        if (e.target === this) cerrarOverlay('overlayEditarCobrador');
    });
    document.getElementById('overlayEliminarCobrador').addEventListener('click', function(e) {
        if (e.target === this) cerrarOverlay('overlayEliminarCobrador');
    });
});

/* ═══════════════════════════════════════════════════════════
   MODAL: EDITAR COBRADOR
═══════════════════════════════════════════════════════════ */
function editarCobrador(c) {
    // Rellenar campos
    document.getElementById('edit_cob_id').value          = c.id;
    document.getElementById('edit_cob_codigo').value      = c.codigo;
    document.getElementById('edit_cob_nombre').value      = c.nombre_completo;
    document.getElementById('edit_cob_descripcion').value = c.descripcion || '';
    document.getElementById('edit_cob_fecha').value       = (c.fecha_ingreso || '').split(' ')[0];
    document.getElementById('edit_cob_estado').value      = c.estado || 'activo';

    // Actualizar título
    document.getElementById('editarCobradorTitulo').innerHTML =
        '<i class="fas fa-pen" style="color:var(--accent);"></i> Editar — ' + esc(c.nombre_completo);

    // Mostrar mini-stats
    var statsBox = document.getElementById('editCobStats');
    statsBox.style.display = 'block';
    document.getElementById('statCliEdit').textContent = numFmt(c.total_clientes  || 0);
    document.getElementById('statPagEdit').textContent = numFmt(c.total_pagos     || 0);
    document.getElementById('statMonEdit').textContent = 'RD$' + numFmt(c.total_cobrado  || 0);

    abrirOverlay('overlayEditarCobrador');
}

/* ═══════════════════════════════════════════════════════════
   MODAL: CONFIRMAR ELIMINAR
═══════════════════════════════════════════════════════════ */
var _cobAEliminar = null;

function confirmarEliminar(c) {
    _cobAEliminar = c.id;
    document.getElementById('eliminarCobDetalles').innerHTML =
        '<div>' +
            '<div class="confirm-detail-label">Cobrador a eliminar</div>' +
            '<div class="confirm-detail-val">' + esc(c.nombre_completo) + '</div>' +
        '</div>' +
        '<div>' +
            '<div class="confirm-detail-label">Código</div>' +
            '<div style="font-family:monospace;font-size:14px;font-weight:700;color:var(--accent);">'
                + esc(c.codigo) +
            '</div>' +
        '</div>' +
        '<div style="display:flex;align-items:center;gap:6px;padding:8px 0 0;' +
             'color:#16A34A;font-size:12.5px;font-weight:600;">' +
            '<i class="fas fa-circle-check"></i>' +
            'Sin clientes asignados — eliminación permitida.' +
        '</div>';
    abrirOverlay('overlayEliminarCobrador');
}

document.getElementById('btnConfirmarEliminar').addEventListener('click', function() {
    if (!_cobAEliminar) return;
    var f = document.createElement('form');
    f.method = 'POST';
    f.innerHTML =
        '<input type="hidden" name="action" value="eliminar">' +
        '<input type="hidden" name="id"     value="' + _cobAEliminar + '">';
    document.body.appendChild(f);
    f.submit();
});

/* ═══════════════════════════════════════════════════════════
   FILTRO EN TIEMPO REAL (cliente side)
═══════════════════════════════════════════════════════════ */
function filtrarTabla(valorBusqueda) {
    var q      = (valorBusqueda !== undefined ? valorBusqueda
                                               : document.getElementById('searchInput').value)
                    .toLowerCase().trim();
    var estado = document.getElementById('estadoFilter').value;
    var filas  = document.querySelectorAll('#cobradoresTbody tr[data-nombre]');
    var visible = 0;

    filas.forEach(function(tr) {
        var nombre = tr.dataset.nombre || '';
        var codigo = tr.dataset.codigo || '';
        var est    = tr.dataset.estado || '';

        var matchQ = (q === '' || nombre.includes(q) || codigo.includes(q));
        var matchE = (estado === 'all' || estado === '' || est === estado);

        if (matchQ && matchE) {
            tr.style.display = '';
            visible++;
        } else {
            tr.style.display = 'none';
        }
    });

    var tv = document.getElementById('totalVisible');
    if (tv) tv.textContent = visible;
}

function limpiarFiltros() {
    document.getElementById('searchInput').value    = '';
    document.getElementById('estadoFilter').value   = 'all';
    filtrarTabla('');
}

/* ═══════════════════════════════════════════════════════════
   AUTO-OCULTAR ALERTA
═══════════════════════════════════════════════════════════ */
(function() {
    var a = document.getElementById('alertaGlobal');
    if (a) setTimeout(function() {
        a.style.opacity = '0';
        a.style.transition = 'opacity .5s';
        setTimeout(function() { a.remove(); }, 500);
    }, 5000);
})();

/* ESC cierra modales abiertos */
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        ['overlayNuevoCobrador','overlayEditarCobrador','overlayEliminarCobrador']
            .forEach(function(id) {
                var el = document.getElementById(id);
                if (el && el.classList.contains('open')) cerrarOverlay(id);
            });
    }
});
</script>

<?php require_once 'footer.php'; ?>