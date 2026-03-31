<?php
/* ============================================================
   planes.php — Gestión de Planes de Seguro
   Sistema ORTHIIS — Seguros de Vida
   ============================================================ */
require_once 'config.php';
verificarSesion();

/* Solo admin puede acceder */
if ($_SESSION['rol'] !== 'admin') {
    header('Location: dashboard.php');
    exit();
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
                $conn->prepare("
                    INSERT INTO planes
                        (codigo, nombre, descripcion, precio_base,
                         cobertura_maxima, edad_minima, edad_maxima,
                         periodo_carencia, estado)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'activo')
                ")->execute([
                    strtoupper(trim($_POST['codigo'])),
                    trim($_POST['nombre']),
                    trim($_POST['descripcion']),
                    floatval($_POST['precio_base']),
                    floatval($_POST['cobertura_maxima']),
                    intval($_POST['edad_minima']),
                    intval($_POST['edad_maxima']),
                    intval($_POST['periodo_carencia']),
                ]);
                $plan_id = $conn->lastInsertId();

                if (!empty($_POST['beneficios']) && is_array($_POST['beneficios'])) {
                    $stmtB = $conn->prepare("
                        INSERT INTO beneficios_planes (plan_id, nombre, descripcion, monto_cobertura)
                        VALUES (?,?,?,?)
                    ");
                    foreach ($_POST['beneficios'] as $b) {
                        if (!empty(trim($b['nombre'] ?? ''))) {
                            $stmtB->execute([
                                $plan_id,
                                trim($b['nombre']),
                                trim($b['descripcion'] ?? ''),
                                floatval($b['monto_cobertura'] ?? 0),
                            ]);
                        }
                    }
                }
                $mensaje      = "Plan <strong>" . htmlspecialchars($_POST['nombre']) . "</strong> creado exitosamente.";
                $tipo_mensaje = 'success';
                break;

            /* ── EDITAR ── */
            case 'editar':
                $pid = intval($_POST['id']);
                /* Protección plan geriátrico */
                if ($pid == 5) {
                    if (intval($_POST['edad_minima']) < 65 || intval($_POST['edad_maxima']) < 65) {
                        throw new Exception('El plan Geriátrico debe mantener edad mínima y máxima ≥ 65 años.');
                    }
                }
                $conn->prepare("
                    UPDATE planes SET
                        nombre=?, descripcion=?, precio_base=?,
                        cobertura_maxima=?, edad_minima=?, edad_maxima=?,
                        periodo_carencia=?, estado=?
                    WHERE id=?
                ")->execute([
                    trim($_POST['nombre']),
                    trim($_POST['descripcion']),
                    floatval($_POST['precio_base']),
                    floatval($_POST['cobertura_maxima']),
                    intval($_POST['edad_minima']),
                    intval($_POST['edad_maxima']),
                    intval($_POST['periodo_carencia']),
                    $_POST['estado'],
                    $pid,
                ]);

                /* Reemplazar beneficios */
                $conn->prepare("DELETE FROM beneficios_planes WHERE plan_id=?")->execute([$pid]);
                if (!empty($_POST['beneficios']) && is_array($_POST['beneficios'])) {
                    $stmtB = $conn->prepare("
                        INSERT INTO beneficios_planes (plan_id, nombre, descripcion, monto_cobertura)
                        VALUES (?,?,?,?)
                    ");
                    foreach ($_POST['beneficios'] as $b) {
                        if (!empty(trim($b['nombre'] ?? ''))) {
                            $stmtB->execute([
                                $pid,
                                trim($b['nombre']),
                                trim($b['descripcion'] ?? ''),
                                floatval($b['monto_cobertura'] ?? 0),
                            ]);
                        }
                    }
                }
                $mensaje      = "Plan actualizado exitosamente.";
                $tipo_mensaje = 'success';
                break;

            /* ── ELIMINAR / INACTIVAR ── */
            case 'eliminar':
                $pid = intval($_POST['plan_id']);
                if ($pid == 5) {
                    throw new Exception('El plan Geriátrico es del sistema y no puede eliminarse.');
                }

                $cContratos  = (int)$conn->prepare("SELECT COUNT(*) FROM contratos  WHERE plan_id=?")->execute([$pid]) ? 0 : 0;
                $stmtCt = $conn->prepare("SELECT COUNT(*) FROM contratos   WHERE plan_id=?"); $stmtCt->execute([$pid]);
                $stmtDp = $conn->prepare("SELECT COUNT(*) FROM dependientes WHERE plan_id=?"); $stmtDp->execute([$pid]);
                $cContratos  = (int)$stmtCt->fetchColumn();
                $cDeps       = (int)$stmtDp->fetchColumn();

                if ($cContratos > 0 || $cDeps > 0) {
                    throw new Exception("Este plan tiene {$cContratos} contrato(s) y {$cDeps} dependiente(s) asignados. No puede eliminarse.");
                }

                $conn->prepare("DELETE FROM beneficios_planes WHERE plan_id=?")->execute([$pid]);
                $conn->prepare("DELETE FROM planes WHERE id=?")->execute([$pid]);
                $mensaje      = "Plan eliminado exitosamente.";
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
$planes = $conn->query("
    SELECT p.*,
           COUNT(DISTINCT c.id)  AS total_contratos,
           COUNT(DISTINCT d.id)  AS total_dependientes,
           GROUP_CONCAT(DISTINCT bp.nombre   ORDER BY bp.id SEPARATOR '||') AS beneficios_nombres,
           GROUP_CONCAT(DISTINCT bp.descripcion  ORDER BY bp.id SEPARATOR '||') AS beneficios_descs,
           GROUP_CONCAT(DISTINCT bp.monto_cobertura ORDER BY bp.id SEPARATOR '||') AS beneficios_montos,
           GROUP_CONCAT(DISTINCT bp.id        ORDER BY bp.id SEPARATOR '||') AS beneficios_ids
    FROM planes p
    LEFT JOIN contratos    c  ON p.id = c.plan_id
    LEFT JOIN dependientes d  ON p.id = d.plan_id
    LEFT JOIN beneficios_planes bp ON p.id = bp.plan_id
    GROUP BY p.id
    ORDER BY p.id
")->fetchAll();

/* ── KPI stats ───────────────────────────────────────────── */
$total_planes    = count($planes);
$planes_activos  = count(array_filter($planes, fn($p) => $p['estado'] === 'activo'));
$total_contratos = array_sum(array_column($planes, 'total_contratos'));
$total_deps      = array_sum(array_column($planes, 'total_dependientes'));

/* Colores / íconos rotativos por plan */
$kpi_colors = ['blue','green','amber','red','purple','teal'];
$plan_icons = ['fas fa-umbrella','fas fa-heart','fas fa-shield-halved','fas fa-star','fas fa-user-nurse','fas fa-leaf'];
$kpi_gradients = [
    'blue'   => 'linear-gradient(135deg,#1565C0,#1976D2)',
    'green'  => 'linear-gradient(135deg,#1B5E20,#2E7D32)',
    'amber'  => 'linear-gradient(135deg,#E65100,#F57F17)',
    'red'    => 'linear-gradient(135deg,#B71C1C,#C62828)',
    'purple' => 'linear-gradient(135deg,#4A148C,#6A1B9A)',
    'teal'   => 'linear-gradient(135deg,#004D40,#00695C)',
];

require_once 'header.php';
?>
<!-- ============================================================
     ESTILOS ESPECÍFICOS
     ============================================================ -->
<style>
/* ── KPI CARDS ── */
.kpi-planes {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 18px;
    margin-bottom: 28px;
}
@media(max-width:1100px){ .kpi-planes { grid-template-columns: repeat(2,1fr); } }
@media(max-width:600px)  { .kpi-planes { grid-template-columns: 1fr; } }

.kpi-planes .kpi-card {
    border-radius: var(--radius);
    padding: 22px 22px 18px;
    position: relative;
    overflow: hidden;
    box-shadow: var(--shadow);
    transition: var(--transition);
    color: white;
    cursor: default;
}
.kpi-planes .kpi-card:hover { transform: translateY(-3px); box-shadow: var(--shadow-md); }
.kpi-planes .kpi-card::before {
    content:''; position:absolute; top:0; right:0;
    width:80px; height:80px;
    border-radius:0 var(--radius) 0 100%;
    opacity:.15; background:white;
}
.kpi-planes .kpi-label {
    font-size:11px; font-weight:600; color:rgba(255,255,255,.80);
    text-transform:uppercase; letter-spacing:.8px; margin-bottom:10px;
}
.kpi-planes .kpi-top {
    display:flex; align-items:flex-start; justify-content:space-between; margin-bottom:6px;
}
.kpi-planes .kpi-value {
    font-size:30px; font-weight:800; color:white; line-height:1; margin-bottom:4px;
}
.kpi-planes .kpi-sub  { font-size:11px; color:rgba(255,255,255,.70); font-weight:500; }
.kpi-planes .kpi-icon {
    width:48px; height:48px;
    background:rgba(255,255,255,.18); border-radius:var(--radius-sm);
    display:flex; align-items:center; justify-content:center;
    font-size:20px; color:white; flex-shrink:0;
}
.kpi-planes .kpi-footer {
    margin-top:14px; padding-top:12px;
    border-top:1px solid rgba(255,255,255,.15);
    font-size:11.5px; color:rgba(255,255,255,.80); font-weight:600;
    display:flex; align-items:center; gap:6px;
}

/* ── PLANES GRID ── */
.planes-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
    gap: 20px;
}
@media(max-width:760px) { .planes-grid { grid-template-columns: 1fr; } }

/* ── PLAN CARD ── */
.plan-card {
    background: var(--white);
    border: 1px solid var(--gray-200);
    border-radius: var(--radius);
    box-shadow: var(--shadow-sm);
    overflow: hidden;
    display: flex;
    flex-direction: column;
    transition: var(--transition);
}
.plan-card:hover { transform: translateY(-4px); box-shadow: var(--shadow-md); }

/* Banda superior de color */
.plan-card-band {
    height: 6px;
    width: 100%;
}

.plan-card-head {
    padding: 18px 20px 14px;
    display: flex;
    align-items: flex-start;
    gap: 14px;
    border-bottom: 1px solid var(--gray-100);
}
.plan-avatar {
    width: 50px; height: 50px; border-radius: 14px;
    display: flex; align-items: center; justify-content: center;
    font-size: 22px; color: white; flex-shrink: 0;
    box-shadow: 0 4px 12px rgba(0,0,0,.18);
}
.plan-title-block { flex: 1; }
.plan-name { font-size: 15px; font-weight: 800; color: var(--gray-800); line-height: 1.2; }
.plan-code { font-size: 11px; color: var(--gray-400); font-family: monospace; margin-top: 3px; }

/* Precio destacado */
.plan-price-wrap {
    padding: 16px 20px 12px;
    display: flex; align-items: baseline; gap: 4px;
}
.plan-price-amount {
    font-size: 28px; font-weight: 900; color: var(--gray-800); line-height: 1;
}
.plan-price-label {
    font-size: 12px; color: var(--gray-400); font-weight: 500;
}

/* Detalles del plan */
.plan-body { padding: 0 20px 14px; flex: 1; }
.plan-desc {
    font-size: 13px; color: var(--gray-500); line-height: 1.6;
    margin-bottom: 14px;
    display: -webkit-box; -webkit-line-clamp: 3;
    -webkit-box-orient: vertical; overflow: hidden;
}

.plan-specs {
    display: grid; grid-template-columns: repeat(2, 1fr);
    gap: 10px; margin-bottom: 14px;
}
.plan-spec-item {
    background: var(--gray-50); border-radius: var(--radius-sm);
    padding: 10px 12px; border: 1px solid var(--gray-100);
}
.plan-spec-label {
    font-size: 10px; font-weight: 700; color: var(--gray-400);
    text-transform: uppercase; letter-spacing: .5px; margin-bottom: 3px;
}
.plan-spec-val {
    font-size: 13px; font-weight: 700; color: var(--gray-800);
}

/* Beneficios */
.plan-beneficios { margin-bottom: 14px; }
.plan-ben-title {
    font-size: 10px; font-weight: 700; color: var(--gray-400);
    text-transform: uppercase; letter-spacing: .5px;
    margin-bottom: 8px; display: flex; align-items: center; gap: 5px;
}
.plan-ben-item {
    display: flex; align-items: center; gap: 7px;
    font-size: 12.5px; color: var(--gray-700); padding: 3px 0;
}
.plan-ben-item i { font-size: 10px; color: #16A34A; flex-shrink: 0; }

/* Stats strip */
.plan-stats-strip {
    border-top: 1px solid var(--gray-100);
    display: grid; grid-template-columns: 1fr 1fr;
}
.plan-stat {
    padding: 12px 16px; text-align: center;
    border-right: 1px solid var(--gray-100);
}
.plan-stat:last-child { border-right: none; }
.plan-stat-val {
    font-size: 20px; font-weight: 800; color: var(--gray-800); line-height: 1;
}
.plan-stat-label {
    font-size: 10px; font-weight: 600; color: var(--gray-400);
    text-transform: uppercase; letter-spacing: .5px; margin-top: 3px;
}

/* Footer acciones */
.plan-footer {
    padding: 14px 20px;
    border-top: 1px solid var(--gray-100);
    background: var(--gray-50);
    display: flex; gap: 8px; flex-wrap: wrap;
}

/* ── Badges ── */
.badge {
    display:inline-flex; align-items:center;
    padding:4px 12px; border-radius:20px;
    font-size:11px; font-weight:700; white-space:nowrap;
}
.badge-activo     { background:#DCFCE7; color:#15803D; }
.badge-inactivo   { background:#FEE2E2; color:#DC2626; }
.badge-geriatrico { background:#F5F3FF; color:#7C3AED; }

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
.modal-box.md  { max-width:560px; }
.modal-box.lg  { max-width:760px; }
.modal-box.xl  { max-width:920px; }
.modal-box.sm  { max-width:460px; }
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

/* Beneficio row */
.beneficio-row {
    position:relative; background:var(--gray-50);
    border:1px solid var(--gray-200); border-radius:var(--radius-sm);
    padding:14px 14px 12px 14px; margin-bottom:12px;
}
.beneficio-row:last-child { margin-bottom:0; }
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
.btn-amber     { background:#FEF3C7; color:#B45309; }
.btn-amber:hover     { background:#D97706; color:white; }
.btn-sm { padding:7px 14px; font-size:12.5px; }

/* ── Fade in ── */
.fade-in { animation:fadeIn .4s ease both; }
.delay-1 { animation-delay:.10s; }
.delay-2 { animation-delay:.20s; }
@keyframes fadeIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }

/* ── Aviso plan protegido ── */
.plan-protegido-aviso {
    background:#F5F3FF; border:1px solid #DDD6FE;
    border-radius:var(--radius-sm); padding:10px 14px;
    font-size:12.5px; color:#6D28D9;
    display:flex; align-items:center; gap:8px;
    margin-bottom:16px;
}
</style>

<!-- ============================================================
     PAGE HEADER
     ============================================================ -->
<div class="page-header fade-in">
    <div>
        <div class="page-title">Planes de Seguro</div>
        <div class="page-subtitle"><?php echo $total_planes; ?> plan<?php echo $total_planes !== 1 ? 'es' : ''; ?> registrados en el sistema</div>
    </div>
    <div class="page-header-actions">
        <button class="btn btn-primary" onclick="abrirOverlay('overlayNuevoPlan')">
            <i class="fas fa-plus"></i> Nuevo Plan
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
<div class="kpi-planes fade-in delay-1">
    <div class="kpi-card" style="background:linear-gradient(135deg,#1565C0,#1976D2);">
        <div class="kpi-label">Total de Planes</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo $total_planes; ?></div>
                <div class="kpi-sub">Registrados en el sistema</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-layer-group"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-database"></i> Todos los planes</div>
    </div>

    <div class="kpi-card" style="background:linear-gradient(135deg,#1B5E20,#2E7D32);">
        <div class="kpi-label">Planes Activos</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo $planes_activos; ?></div>
                <div class="kpi-sub">Disponibles para contratos</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-check-circle"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-arrow-trend-up"></i> Vigentes</div>
    </div>

    <div class="kpi-card" style="background:linear-gradient(135deg,#E65100,#F57F17);">
        <div class="kpi-label">Contratos Activos</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo number_format($total_contratos); ?></div>
                <div class="kpi-sub">Contratos usando estos planes</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-file-contract"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-users"></i> Total asignados</div>
    </div>

    <div class="kpi-card" style="background:linear-gradient(135deg,#4A148C,#6A1B9A);">
        <div class="kpi-label">Dependientes</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo number_format($total_deps); ?></div>
                <div class="kpi-sub">En estos planes</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-user-friends"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-heart"></i> Beneficiados</div>
    </div>
</div>

<!-- ============================================================
     TARJETAS DE PLANES
     ============================================================ -->
<div class="planes-grid fade-in delay-2">
<?php foreach ($planes as $i => $plan):
    $color   = $kpi_gradients[ $kpi_colors[$i % count($kpi_colors)] ];
    $iconPlan = $plan_icons[$i % count($plan_icons)];
    $benNombres  = $plan['beneficios_nombres'] ? explode('||', $plan['beneficios_nombres']) : [];
    $benDescs    = $plan['beneficios_descs']   ? explode('||', $plan['beneficios_descs'])   : [];
    $benMontos   = $plan['beneficios_montos']  ? explode('||', $plan['beneficios_montos'])  : [];
    $benIds      = $plan['beneficios_ids']     ? explode('||', $plan['beneficios_ids'])     : [];
    $puedeEliminar = ($plan['id'] != 5 && $plan['total_contratos'] == 0 && $plan['total_dependientes'] == 0);
    $puedeInactivar = ($plan['id'] != 5 && $plan['estado'] === 'activo' && ($plan['total_contratos'] > 0 || $plan['total_dependientes'] > 0));
    $esGeriatrico = ($plan['id'] == 5);
?>
<div class="plan-card">
    <!-- Banda de color superior -->
    <div class="plan-card-band" style="background:<?php echo $color; ?>;"></div>

    <!-- Cabecera -->
    <div class="plan-card-head">
        <div class="plan-avatar" style="background:<?php echo $color; ?>;">
            <i class="<?php echo $iconPlan; ?>"></i>
        </div>
        <div class="plan-title-block">
            <div class="plan-name"><?php echo htmlspecialchars($plan['nombre']); ?></div>
            <div class="plan-code">Código: <?php echo htmlspecialchars($plan['codigo']); ?></div>
        </div>
        <div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px;flex-shrink:0;">
            <span class="badge badge-<?php echo $plan['estado'] === 'activo' ? 'activo' : 'inactivo'; ?>">
                <?php echo ucfirst($plan['estado']); ?>
            </span>
            <?php if ($esGeriatrico): ?>
                <span class="badge badge-geriatrico">Geriátrico</span>
            <?php endif; ?>
        </div>
    </div>

    <!-- Precio -->
    <div class="plan-price-wrap">
        <div class="plan-price-amount">RD$<?php echo number_format($plan['precio_base'], 2); ?></div>
        <div class="plan-price-label">/ mes</div>
    </div>

    <!-- Cuerpo -->
    <div class="plan-body">
        <p class="plan-desc"><?php echo htmlspecialchars($plan['descripcion']); ?></p>

        <div class="plan-specs">
            <div class="plan-spec-item">
                <div class="plan-spec-label">Cobertura Máxima</div>
                <div class="plan-spec-val">RD$<?php echo number_format($plan['cobertura_maxima'], 0); ?></div>
            </div>
            <div class="plan-spec-item">
                <div class="plan-spec-label">Rango de Edad</div>
                <div class="plan-spec-val"><?php echo $plan['edad_minima']; ?> – <?php echo $plan['edad_maxima']; ?> años</div>
            </div>
            <div class="plan-spec-item">
                <div class="plan-spec-label">Tiempo de Cobertura</div>
                <div class="plan-spec-val"><?php echo $plan['periodo_carencia']; ?> días</div>
            </div>
            <div class="plan-spec-item">
                <div class="plan-spec-label">Beneficios</div>
                <div class="plan-spec-val"><?php echo count($benNombres); ?> incluido<?php echo count($benNombres) !== 1 ? 's' : ''; ?></div>
            </div>
        </div>

        <?php if (!empty($benNombres)): ?>
        <div class="plan-beneficios">
            <div class="plan-ben-title"><i class="fas fa-list-check"></i> Beneficios incluidos</div>
            <?php foreach (array_slice($benNombres, 0, 4) as $bn): ?>
                <div class="plan-ben-item">
                    <i class="fas fa-circle-check"></i>
                    <?php echo htmlspecialchars(trim($bn)); ?>
                </div>
            <?php endforeach; ?>
            <?php if (count($benNombres) > 4): ?>
                <div class="plan-ben-item" style="color:var(--gray-400);">
                    <i class="fas fa-ellipsis"></i>
                    +<?php echo count($benNombres) - 4; ?> más…
                </div>
            <?php endif; ?>
        </div>
        <?php endif; ?>
    </div>

    <!-- Stats -->
    <div class="plan-stats-strip">
        <div class="plan-stat">
            <div class="plan-stat-val"><?php echo number_format($plan['total_contratos']); ?></div>
            <div class="plan-stat-label">Contratos</div>
        </div>
        <div class="plan-stat">
            <div class="plan-stat-val"><?php echo number_format($plan['total_dependientes']); ?></div>
            <div class="plan-stat-label">Dependientes</div>
        </div>
    </div>

    <!-- Footer acciones -->
    <div class="plan-footer">
        <button class="btn btn-primary btn-sm"
                onclick='editarPlan(<?php echo json_encode([
                    "id"               => $plan["id"],
                    "codigo"           => $plan["codigo"],
                    "nombre"           => $plan["nombre"],
                    "descripcion"      => $plan["descripcion"],
                    "precio_base"      => $plan["precio_base"],
                    "cobertura_maxima" => $plan["cobertura_maxima"],
                    "edad_minima"      => $plan["edad_minima"],
                    "edad_maxima"      => $plan["edad_maxima"],
                    "periodo_carencia" => $plan["periodo_carencia"],
                    "estado"           => $plan["estado"],
                    "total_contratos"  => $plan["total_contratos"],
                    "total_dependientes"=> $plan["total_dependientes"],
                ], JSON_HEX_APOS|JSON_HEX_QUOT); ?>)'>
            <i class="fas fa-pen"></i> Editar
        </button>

        <?php if ($puedeEliminar): ?>
            <button class="btn btn-danger btn-sm"
                    onclick="confirmarEliminarPlan(<?php echo $plan['id']; ?>, '<?php echo htmlspecialchars(addslashes($plan['nombre'])); ?>')">
                <i class="fas fa-trash"></i> Eliminar
            </button>
        <?php elseif ($puedeInactivar): ?>
            <button class="btn btn-amber btn-sm"
                    title="Tiene <?php echo $plan['total_contratos']; ?> contrato(s) y <?php echo $plan['total_dependientes']; ?> dependiente(s). No puede eliminarse."
                    onclick="mostrarToast('Este plan tiene <?php echo $plan['total_contratos']; ?> contrato(s) y <?php echo $plan['total_dependientes']; ?> dependiente(s) asignados. Solo puede editarse.', 'warning')">
                <i class="fas fa-lock"></i> Protegido
            </button>
        <?php elseif ($esGeriatrico): ?>
            <button class="btn btn-sm" style="background:#F5F3FF;color:#7C3AED;cursor:default;"
                    title="Plan del sistema — no eliminable" disabled>
                <i class="fas fa-shield-halved"></i> Sistema
            </button>
        <?php endif; ?>
    </div>
</div>
<?php endforeach; ?>
</div>


<!-- ============================================================
     MODAL: NUEVO PLAN
     ============================================================ -->
<div class="modal-overlay" id="overlayNuevoPlan">
    <div class="modal-box xl">
        <div class="mhdr">
            <div class="mhdr-title">
                <i class="fas fa-plus-circle" style="color:var(--accent);"></i>
                Nuevo Plan de Seguro
            </div>
            <button class="modal-close-btn" onclick="cerrarOverlay('overlayNuevoPlan')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <form id="formNuevoPlan" method="POST">
            <div class="mbody">
                <input type="hidden" name="action" value="crear">

                <div class="fsec-title"><i class="fas fa-info-circle"></i> Información Básica</div>
                <div class="form-grid cols-3">
                    <div class="form-group">
                        <label class="form-label required" for="n_codigo">Código</label>
                        <input type="text" name="codigo" id="n_codigo" class="form-control"
                               required placeholder="Ej. PL-006" style="text-transform:uppercase;">
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="n_nombre">Nombre del Plan</label>
                        <input type="text" name="nombre" id="n_nombre" class="form-control"
                               required placeholder="Ej. Plan Familiar Plus">
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="n_precio_base">Precio Base (RD$)</label>
                        <input type="number" name="precio_base" id="n_precio_base" class="form-control"
                               step="0.01" min="0" required placeholder="0.00">
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="n_cobertura_maxima">Cobertura Máxima (RD$)</label>
                        <input type="number" name="cobertura_maxima" id="n_cobertura_maxima" class="form-control"
                               step="0.01" min="0" required placeholder="0.00">
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="n_edad_minima">Edad Mínima</label>
                        <input type="number" name="edad_minima" id="n_edad_minima" class="form-control"
                               min="0" max="120" required placeholder="0">
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="n_edad_maxima">Edad Máxima</label>
                        <input type="number" name="edad_maxima" id="n_edad_maxima" class="form-control"
                               min="0" max="120" required placeholder="120">
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="n_periodo_carencia">Tiempo de Cobertura (días)</label>
                        <input type="number" name="periodo_carencia" id="n_periodo_carencia" class="form-control"
                               min="0" required placeholder="90">
                    </div>
                    <div class="form-group" style="grid-column:1/-1;">
                        <label class="form-label required" for="n_descripcion">Descripción</label>
                        <textarea name="descripcion" id="n_descripcion" class="form-control"
                                  rows="3" required placeholder="Descripción detallada del plan…"></textarea>
                    </div>
                </div>

                <div class="fsec-title" style="margin-top:18px;">
                    <i class="fas fa-list-check"></i> Beneficios del Plan
                    <button type="button" class="btn btn-secondary btn-sm" style="margin-left:auto;"
                            onclick="agregarBeneficioNuevo()">
                        <i class="fas fa-plus"></i> Agregar
                    </button>
                </div>
                <div id="nuevoBenContainer"></div>
                <div id="nuevoBenEmpty" style="text-align:center;padding:20px;color:var(--gray-400);
                     background:var(--gray-50);border-radius:var(--radius-sm);
                     border:1.5px dashed var(--gray-200);font-size:13px;">
                    <i class="fas fa-list" style="font-size:22px;display:block;margin-bottom:6px;opacity:.4;"></i>
                    Sin beneficios agregados. Haz clic en <strong>Agregar</strong>.
                </div>
            </div>
            <div class="mfooter">
                <button type="button" class="btn btn-secondary"
                        onclick="cerrarOverlay('overlayNuevoPlan')">
                    <i class="fas fa-times"></i> Cancelar
                </button>
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-save"></i> Guardar Plan
                </button>
            </div>
        </form>
    </div>
</div>


<!-- ============================================================
     MODAL: EDITAR PLAN
     ============================================================ -->
<div class="modal-overlay" id="overlayEditarPlan">
    <div class="modal-box xl">
        <div class="mhdr">
            <div class="mhdr-title" id="editarPlanTitulo">
                <i class="fas fa-pen" style="color:var(--accent);"></i>
                Editar Plan
            </div>
            <button class="modal-close-btn" onclick="cerrarOverlay('overlayEditarPlan')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <form id="formEditarPlan" method="POST">
            <div class="mbody">
                <input type="hidden" name="action" value="editar">
                <input type="hidden" name="id"     id="edit_id">

                <!-- Aviso plan geriátrico -->
                <div id="avisoGeriatrico" class="plan-protegido-aviso" style="display:none;">
                    <i class="fas fa-shield-halved" style="font-size:16px;flex-shrink:0;"></i>
                    <div><strong>Plan Geriátrico del sistema.</strong> Las edades mínima y máxima están bloqueadas (≥ 65 años). El código no puede cambiarse.</div>
                </div>

                <div class="fsec-title"><i class="fas fa-info-circle"></i> Información Básica</div>
                <div class="form-grid cols-3">
                    <div class="form-group">
                        <label class="form-label">Código</label>
                        <input type="text" id="edit_codigo_display" class="form-control" readonly>
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="edit_nombre">Nombre del Plan</label>
                        <input type="text" name="nombre" id="edit_nombre" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="edit_precio_base">Precio Base (RD$)</label>
                        <input type="number" name="precio_base" id="edit_precio_base"
                               class="form-control" step="0.01" min="0" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="edit_cobertura_maxima">Cobertura Máxima (RD$)</label>
                        <input type="number" name="cobertura_maxima" id="edit_cobertura_maxima"
                               class="form-control" step="0.01" min="0" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="edit_edad_minima">Edad Mínima</label>
                        <input type="number" name="edad_minima" id="edit_edad_minima"
                               class="form-control" min="0" max="120" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="edit_edad_maxima">Edad Máxima</label>
                        <input type="number" name="edad_maxima" id="edit_edad_maxima"
                               class="form-control" min="0" max="120" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="edit_periodo_carencia">Tiempo de Cobertura (días)</label>
                        <input type="number" name="periodo_carencia" id="edit_periodo_carencia"
                               class="form-control" min="0" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="edit_estado">Estado</label>
                        <select name="estado" id="edit_estado" class="form-control" required>
                            <option value="activo">Activo</option>
                            <option value="inactivo">Inactivo</option>
                        </select>
                    </div>
                    <div class="form-group" style="grid-column:1/-1;">
                        <label class="form-label required" for="edit_descripcion">Descripción</label>
                        <textarea name="descripcion" id="edit_descripcion" class="form-control" rows="3" required></textarea>
                    </div>
                </div>

                <div class="fsec-title" style="margin-top:18px;">
                    <i class="fas fa-list-check"></i> Beneficios del Plan
                    <button type="button" class="btn btn-secondary btn-sm" style="margin-left:auto;"
                            onclick="agregarBeneficioEdicion()">
                        <i class="fas fa-plus"></i> Agregar
                    </button>
                </div>
                <div id="editBenContainer"></div>
                <div id="editBenEmpty" style="text-align:center;padding:20px;color:var(--gray-400);
                     background:var(--gray-50);border-radius:var(--radius-sm);
                     border:1.5px dashed var(--gray-200);font-size:13px;">
                    <i class="fas fa-list" style="font-size:22px;display:block;margin-bottom:6px;opacity:.4;"></i>
                    Sin beneficios. Haz clic en <strong>Agregar</strong> para añadir.
                </div>
            </div>
            <div class="mfooter">
                <button type="button" class="btn btn-secondary"
                        onclick="cerrarOverlay('overlayEditarPlan')">
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
<div class="modal-overlay" id="overlayEliminarPlan">
    <div class="modal-box sm">
        <div class="mhdr">
            <div class="mhdr-title" style="color:#DC2626;">
                <i class="fas fa-trash"></i> Eliminar Plan
            </div>
            <button class="modal-close-btn" onclick="cerrarOverlay('overlayEliminarPlan')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="mbody">
            <div id="eliminarPlanDetalles" style="margin-bottom:14px;"></div>
            <div style="background:#FEF2F2;border:1px solid #FCA5A5;border-radius:var(--radius-sm);
                        padding:14px 16px;color:#991B1B;font-size:13.5px;">
                <i class="fas fa-exclamation-circle" style="margin-right:6px;"></i>
                <strong>¿Confirmar la eliminación permanente?</strong><br>
                <span style="font-size:12.5px;opacity:.85;">
                    Esta acción no puede revertirse. Los beneficios del plan también serán eliminados.
                </span>
            </div>
        </div>
        <div class="mfooter">
            <button class="btn btn-secondary" onclick="cerrarOverlay('overlayEliminarPlan')">
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
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
                        .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

/* ═══════════════════════════════════════════════════════════
   BENEFICIOS — Nuevo Plan
═══════════════════════════════════════════════════════════ */
var _benNuevoIdx = 0;

function actualizarNuevoBenEmpty() {
    var c = document.getElementById('nuevoBenContainer');
    var e = document.getElementById('nuevoBenEmpty');
    if (c && e) e.style.display = c.children.length === 0 ? 'block' : 'none';
}

function agregarBeneficioNuevo(data) {
    data = data || {};
    var idx = _benNuevoIdx++;
    var container = document.getElementById('nuevoBenContainer');
    var div = document.createElement('div');
    div.className = 'beneficio-row';
    div.id = 'nben_' + idx;
    div.innerHTML = _buildBenHtml('beneficios', idx, data);
    container.appendChild(div);
    actualizarNuevoBenEmpty();
}

function quitarBenNuevo(idx) {
    var el = document.getElementById('nben_' + idx);
    if (el) { el.remove(); actualizarNuevoBenEmpty(); }
}

/* ═══════════════════════════════════════════════════════════
   BENEFICIOS — Editar Plan
═══════════════════════════════════════════════════════════ */
var _benEditIdx = 0;

function actualizarEditBenEmpty() {
    var c = document.getElementById('editBenContainer');
    var e = document.getElementById('editBenEmpty');
    if (c && e) e.style.display = c.children.length === 0 ? 'block' : 'none';
}

function agregarBeneficioEdicion(data) {
    data = data || {};
    var idx = _benEditIdx++;
    var container = document.getElementById('editBenContainer');
    var div = document.createElement('div');
    div.className = 'beneficio-row';
    div.id = 'eben_' + idx;
    div.innerHTML = _buildBenHtml('beneficios', idx, data, 'edit');
    container.appendChild(div);
    actualizarEditBenEmpty();
}

function quitarBenEdit(idx) {
    var el = document.getElementById('eben_' + idx);
    if (el) { el.remove(); actualizarEditBenEmpty(); }
}

function _buildBenHtml(prefix, idx, data, type) {
    type = type || 'nuevo';
    var removeFunc = type === 'edit' ? 'quitarBenEdit(' + idx + ')' : 'quitarBenNuevo(' + idx + ')';
    return '<button type="button" class="btn-remove-ben" onclick="' + removeFunc + '" title="Quitar">' +
           '<i class="fas fa-times"></i></button>' +
           '<div class="form-grid cols-3" style="gap:10px;">' +
           '<div class="form-group">' +
               '<label class="form-label required">Nombre del Beneficio</label>' +
               '<input type="text" name="' + prefix + '[' + idx + '][nombre]" class="form-control" required ' +
                      'value="' + esc(data.nombre||'') + '" placeholder="Ej. Cobertura Funeral">' +
           '</div>' +
           '<div class="form-group">' +
               '<label class="form-label">Descripción</label>' +
               '<input type="text" name="' + prefix + '[' + idx + '][descripcion]" class="form-control" ' +
                      'value="' + esc(data.descripcion||'') + '" placeholder="Descripción breve">' +
           '</div>' +
           '<div class="form-group">' +
               '<label class="form-label">Monto de Cobertura (RD$)</label>' +
               '<input type="number" name="' + prefix + '[' + idx + '][monto_cobertura]" ' +
                      'class="form-control" step="0.01" min="0" value="' + esc(String(data.monto_cobertura||'')) + '" placeholder="0.00">' +
           '</div>' +
           '</div>';
}

/* ═══════════════════════════════════════════════════════════
   MODAL EDITAR PLAN
═══════════════════════════════════════════════════════════ */
function editarPlan(plan) {
    document.getElementById('formEditarPlan').reset();
    document.getElementById('editBenContainer').innerHTML = '';
    _benEditIdx = 0;
    actualizarEditBenEmpty();

    document.getElementById('edit_id').value                  = plan.id;
    document.getElementById('edit_codigo_display').value      = plan.codigo;
    document.getElementById('edit_nombre').value              = plan.nombre;
    document.getElementById('edit_descripcion').value         = plan.descripcion;
    document.getElementById('edit_precio_base').value         = plan.precio_base;
    document.getElementById('edit_cobertura_maxima').value    = plan.cobertura_maxima;
    document.getElementById('edit_edad_minima').value         = plan.edad_minima;
    document.getElementById('edit_edad_maxima').value         = plan.edad_maxima;
    document.getElementById('edit_periodo_carencia').value    = plan.periodo_carencia;
    document.getElementById('edit_estado').value              = plan.estado;
    document.getElementById('editarPlanTitulo').innerHTML     =
        '<i class="fas fa-pen" style="color:var(--accent);"></i> Editar Plan — ' + esc(plan.nombre);

    /* Bloquear edades si es geriátrico */
    var esGer = (plan.id == 5);
    document.getElementById('edit_edad_minima').readOnly  = esGer;
    document.getElementById('edit_edad_maxima').readOnly  = esGer;
    document.getElementById('avisoGeriatrico').style.display = esGer ? 'flex' : 'none';

    /* Cargar beneficios existentes */
    fetch('get_beneficios_plan.php?plan_id=' + plan.id)
        .then(function(r){ return r.json(); })
        .then(function(bens){
            if (Array.isArray(bens)) {
                bens.forEach(function(b){ agregarBeneficioEdicion(b); });
            }
        })
        .catch(function(){ /* sin beneficios cargados */ });

    abrirOverlay('overlayEditarPlan');
}

/* ═══════════════════════════════════════════════════════════
   MODAL ELIMINAR PLAN
═══════════════════════════════════════════════════════════ */
var _planAEliminar = null;

function confirmarEliminarPlan(id, nombre) {
    _planAEliminar = id;
    document.getElementById('eliminarPlanDetalles').innerHTML =
        '<div style="background:var(--gray-50);border:1px solid var(--gray-200);' +
        'border-radius:var(--radius-sm);padding:14px 16px;">' +
        '<div style="font-size:10.5px;text-transform:uppercase;letter-spacing:.5px;' +
        'color:var(--gray-400);font-weight:700;margin-bottom:4px;">Plan a eliminar</div>' +
        '<div style="font-size:16px;font-weight:800;color:var(--gray-800);">' + esc(nombre) + '</div>' +
        '<div style="font-size:12px;color:var(--gray-400);margin-top:4px;">' +
        '<i class="fas fa-info-circle" style="margin-right:4px;"></i>' +
        'Sin contratos ni dependientes asignados — eliminación permitida.' +
        '</div></div>';
    abrirOverlay('overlayEliminarPlan');
}

document.getElementById('btnConfirmarEliminar').addEventListener('click', function() {
    if (!_planAEliminar) return;
    var f = document.createElement('form');
    f.method = 'POST';
    f.innerHTML = '<input type="hidden" name="action"   value="eliminar">' +
                  '<input type="hidden" name="plan_id"  value="' + _planAEliminar + '">';
    document.body.appendChild(f);
    f.submit();
});

/* ═══════════════════════════════════════════════════════════
   RESET MODAL NUEVO AL CERRAR
═══════════════════════════════════════════════════════════ */
document.getElementById('overlayNuevoPlan').addEventListener('click', function(e){
    if (e.target === this) cerrarOverlay('overlayNuevoPlan');
});

document.getElementById('formNuevoPlan').addEventListener('reset', function(){
    setTimeout(function(){
        document.getElementById('nuevoBenContainer').innerHTML = '';
        _benNuevoIdx = 0;
        actualizarNuevoBenEmpty();
    }, 10);
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