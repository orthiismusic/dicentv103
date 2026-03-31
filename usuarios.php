<?php
/* ============================================================
   usuarios.php — Gestión de Usuarios del Sistema
   ORTHIIS — Seguros de Vida
   ============================================================ */
require_once 'config.php';
verificarSesion();

/* Solo admin */
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
        switch ($_POST['action']) {

            /* ── CREAR ── */
            case 'crear':
                /* Verificar usuario único */
                $s = $conn->prepare("SELECT id FROM usuarios WHERE usuario = ?");
                $s->execute([trim($_POST['usuario'])]);
                if ($s->fetch()) throw new Exception("El nombre de usuario ya existe.");

                if (empty($_POST['password'])) throw new Exception("La contraseña es obligatoria.");

                $conn->prepare("
                    INSERT INTO usuarios (usuario, password, nombre, email, rol, estado)
                    VALUES (?,?,?,?,?,'activo')
                ")->execute([
                    trim($_POST['usuario']),
                    password_hash($_POST['password'], PASSWORD_DEFAULT),
                    trim($_POST['nombre']),
                    trim($_POST['email']),
                    $_POST['rol'],
                ]);
                $mensaje      = "Usuario <strong>" . htmlspecialchars($_POST['usuario']) . "</strong> creado exitosamente.";
                $tipo_mensaje = 'success';
                break;

            /* ── EDITAR ── */
            case 'editar':
                $uid = intval($_POST['usuario_id']);

                /* No puede quitarse a sí mismo el rol admin ni desactivarse */
                if ($uid === intval($_SESSION['id'] ?? 0)) {
                    if ($_POST['rol'] !== 'admin') {
                        throw new Exception("No puedes cambiar tu propio rol de administrador.");
                    }
                    if ($_POST['estado'] !== 'activo') {
                        throw new Exception("No puedes desactivar tu propia cuenta.");
                    }
                }

                $sql    = "UPDATE usuarios SET nombre=?, email=?, rol=?, estado=?";
                $params = [
                    trim($_POST['nombre']),
                    trim($_POST['email']),
                    $_POST['rol'],
                    $_POST['estado'],
                ];

                if (!empty($_POST['password'])) {
                    $sql   .= ", password=?";
                    $params[] = password_hash($_POST['password'], PASSWORD_DEFAULT);
                }

                $sql .= " WHERE id=?";
                $params[] = $uid;

                $conn->prepare($sql)->execute($params);
                $mensaje      = "Usuario actualizado exitosamente.";
                $tipo_mensaje = 'success';
                break;

            /* ── ELIMINAR ── */
            case 'eliminar':
                $uid = intval($_POST['usuario_id']);
                if ($uid === intval($_SESSION['id'] ?? 0)) {
                    throw new Exception("No puedes eliminar tu propia cuenta.");
                }
                $conn->prepare("DELETE FROM usuarios WHERE id=?")->execute([$uid]);
                $mensaje      = "Usuario eliminado exitosamente.";
                $tipo_mensaje = 'success';
                break;
        }

    } catch (Exception $e) {
        $mensaje      = "Error: " . $e->getMessage();
        $tipo_mensaje = 'danger';
    }
}

/* ── Query usuarios ─────────────────────────────────────── */
$buscar          = trim($_GET['buscar']  ?? '');
$filtro_rol      = trim($_GET['rol']     ?? '');
$filtro_estado   = trim($_GET['estado']  ?? '');

$registros_por_pagina = isset($_COOKIE['usuarios_por_pagina']) ? (int)$_COOKIE['usuarios_por_pagina'] : 15;
$pagina_actual        = max(1, intval($_GET['pagina'] ?? 1));
$offset               = ($pagina_actual - 1) * $registros_por_pagina;

$where  = "1=1";
$params = [];

if ($filtro_rol && $filtro_rol !== 'all') {
    $where   .= " AND u.rol = ?";
    $params[] = $filtro_rol;
}
if ($filtro_estado && $filtro_estado !== 'all') {
    $where   .= " AND u.estado = ?";
    $params[] = $filtro_estado;
}
if ($buscar !== '') {
    $t        = "%$buscar%";
    $where   .= " AND (u.usuario LIKE ? OR u.nombre LIKE ? OR u.email LIKE ?)";
    array_push($params, $t, $t, $t);
}

$stmtCnt = $conn->prepare("SELECT COUNT(*) FROM usuarios u WHERE $where");
$stmtCnt->execute($params);
$total_registros = (int)$stmtCnt->fetchColumn();
$total_paginas   = max(1, ceil($total_registros / $registros_por_pagina));

$stmtList = $conn->prepare("
    SELECT u.*
    FROM usuarios u
    WHERE $where
    ORDER BY u.nombre ASC
    LIMIT ? OFFSET ?
");
$allParams = array_merge($params, [$registros_por_pagina, $offset]);
foreach ($allParams as $i => $v) {
    $stmtList->bindValue($i + 1, $v, is_int($v) ? PDO::PARAM_INT : PDO::PARAM_STR);
}
$stmtList->execute();
$usuarios = $stmtList->fetchAll();

/* ── KPI stats ───────────────────────────────────────────── */
$allUsers = $conn->query("SELECT rol, estado FROM usuarios")->fetchAll();
$stats = [
    'total'        => count($allUsers),
    'activos'      => count(array_filter($allUsers, fn($u) => $u['estado'] === 'activo')),
    'inactivos'    => count(array_filter($allUsers, fn($u) => $u['estado'] === 'inactivo')),
    'admins'       => count(array_filter($allUsers, fn($u) => $u['rol'] === 'admin')),
    'vendedores'   => count(array_filter($allUsers, fn($u) => $u['rol'] === 'vendedor')),
    'cobradores'   => count(array_filter($allUsers, fn($u) => $u['rol'] === 'cobrador')),
    'supervisores' => count(array_filter($allUsers, fn($u) => $u['rol'] === 'supervisor')),
];

/* ── Helper URL ──────────────────────────────────────────── */
function buildUsuarioUrl(int $p, string $buscar, string $rol, string $estado): string {
    $q = ['pagina' => $p];
    if ($buscar !== '')                     $q['buscar']  = $buscar;
    if ($rol    !== '' && $rol    !== 'all') $q['rol']    = $rol;
    if ($estado !== '' && $estado !== 'all') $q['estado'] = $estado;
    return 'usuarios.php?' . http_build_query($q);
}

require_once 'header.php';
?>
<!-- ============================================================
     ESTILOS ESPECÍFICOS
     ============================================================ -->
<style>
/* ── KPI CARDS ── */
.kpi-usuarios {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 18px;
    margin-bottom: 24px;
}
@media(max-width:1100px){ .kpi-usuarios { grid-template-columns: repeat(2,1fr); } }
@media(max-width:600px)  { .kpi-usuarios { grid-template-columns: 1fr; } }

.kpi-usuarios .kpi-card {
    border-radius: var(--radius);
    padding: 22px 22px 18px;
    position: relative;
    overflow: hidden;
    box-shadow: var(--shadow);
    transition: var(--transition);
    color: white;
    cursor: default;
}
.kpi-usuarios .kpi-card:hover { transform: translateY(-3px); box-shadow: var(--shadow-md); }
.kpi-usuarios .kpi-card::before {
    content:''; position:absolute; top:0; right:0;
    width:80px; height:80px;
    border-radius:0 var(--radius) 0 100%;
    opacity:.15; background:white;
}
.kpi-usuarios .kpi-label {
    font-size:11px; font-weight:600; color:rgba(255,255,255,.80);
    text-transform:uppercase; letter-spacing:.8px; margin-bottom:10px;
}
.kpi-usuarios .kpi-top {
    display:flex; align-items:flex-start; justify-content:space-between; margin-bottom:6px;
}
.kpi-usuarios .kpi-value {
    font-size:30px; font-weight:800; color:white; line-height:1; margin-bottom:4px;
}
.kpi-usuarios .kpi-sub  { font-size:11px; color:rgba(255,255,255,.70); font-weight:500; }
.kpi-usuarios .kpi-icon {
    width:48px; height:48px;
    background:rgba(255,255,255,.18); border-radius:var(--radius-sm);
    display:flex; align-items:center; justify-content:center;
    font-size:20px; color:white; flex-shrink:0;
}
.kpi-usuarios .kpi-footer {
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
.user-name  { font-weight:700; color:var(--gray-800); font-size:13px; }
.user-login { font-size:11px; color:var(--gray-400); font-family:monospace; }
.td-muted   { color:var(--gray-400); font-size:12.5px; }
.td-email   { color:var(--gray-600); font-size:12.5px; }

/* ── Avatar del usuario ── */
.user-avatar {
    width:36px; height:36px; border-radius:50%;
    display:flex; align-items:center; justify-content:center;
    font-size:13px; font-weight:700; color:white;
    flex-shrink:0;
}

/* ── Rol badges ── */
.badge {
    display:inline-flex; align-items:center;
    padding:4px 12px; border-radius:20px;
    font-size:11px; font-weight:700; white-space:nowrap;
}
.badge-activo     { background:#DCFCE7; color:#15803D; }
.badge-inactivo   { background:#FEE2E2; color:#DC2626; }
.badge-admin      { background:#EFF6FF; color:#1565C0; }
.badge-vendedor   { background:#FEF3C7; color:#B45309; }
.badge-cobrador   { background:#F0FDF4; color:#15803D; }
.badge-supervisor { background:#F5F3FF; color:#7C3AED; }

/* ── Botones de acción ── */
.tbl-actions { display:flex; align-items:center; justify-content:center; gap:5px; }
.btn-tbl {
    width:32px; height:32px; border-radius:var(--radius-sm); border:none;
    display:inline-flex; align-items:center; justify-content:center;
    font-size:13px; cursor:pointer; transition:var(--transition); text-decoration:none;
}
.btn-tbl:hover { transform:translateY(-2px); box-shadow:var(--shadow); }
.btn-tbl.edit   { background:#FFFBEB; color:#D97706; }
.btn-tbl.del    { background:#FEF2F2; color:#DC2626; }
.btn-tbl.edit:hover { background:#D97706; color:white; }
.btn-tbl.del:hover  { background:#DC2626; color:white; }
.btn-tbl:disabled, .btn-tbl.disabled {
    opacity:.35; pointer-events:none; cursor:not-allowed;
}

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
@media(max-width:540px){ .form-grid.cols-2 { grid-template-columns:1fr; } }
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

/* ── Password toggle ── */
.password-wrap { position:relative; }
.password-wrap .form-control { padding-right:42px; }
.btn-toggle-pass {
    position:absolute; right:10px; top:50%; transform:translateY(-50%);
    background:none; border:none; cursor:pointer;
    color:var(--gray-400); font-size:14px; padding:4px;
    transition:var(--transition);
}
.btn-toggle-pass:hover { color:var(--accent); }

/* ── Chip de rol en formulario ── */
.rol-chips { display:flex; flex-wrap:wrap; gap:8px; }
.rol-chip {
    display:flex; align-items:center; gap:6px;
    padding:8px 14px; border-radius:var(--radius-sm);
    border:1.5px solid var(--gray-200); background:var(--white);
    cursor:pointer; font-size:12.5px; font-weight:600;
    color:var(--gray-600); transition:var(--transition);
    font-family:var(--font);
}
.rol-chip:hover { border-color:var(--accent); color:var(--accent); background:#EFF6FF; }
.rol-chip.selected { color:white; border-color:transparent; }
.rol-chip.selected.admin      { background:linear-gradient(135deg,#1565C0,#1976D2); }
.rol-chip.selected.vendedor   { background:linear-gradient(135deg,#B45309,#D97706); }
.rol-chip.selected.cobrador   { background:linear-gradient(135deg,#15803D,#16A34A); }
.rol-chip.selected.supervisor { background:linear-gradient(135deg,#6D28D9,#7C3AED); }
input[name="rol"].rol-radio { display:none; }

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
.btn-sm { padding:7px 14px; font-size:12.5px; }

/* ── Aviso propio usuario ── */
.self-badge {
    display:inline-flex; align-items:center; gap:4px;
    padding:2px 8px; border-radius:20px; font-size:10px; font-weight:700;
    background:#EFF6FF; color:var(--accent); border:1px solid #BFDBFE;
    margin-left:6px; vertical-align:middle;
}

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
        <div class="page-title">Gestión de Usuarios</div>
        <div class="page-subtitle">
            <?php echo number_format($total_registros); ?> usuario<?php echo $total_registros !== 1 ? 's' : ''; ?>
            <?php echo ($filtro_rol || $filtro_estado || $buscar) ? 'encontrados' : 'registrados en el sistema'; ?>
        </div>
    </div>
    <div class="page-header-actions">
        <button class="btn btn-primary" onclick="abrirOverlay('overlayNuevoUsuario')">
            <i class="fas fa-user-plus"></i> Nuevo Usuario
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
<div class="kpi-usuarios fade-in delay-1">

    <div class="kpi-card" style="background:linear-gradient(135deg,#1565C0,#1976D2);">
        <div class="kpi-label">Total Usuarios</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo $stats['total']; ?></div>
                <div class="kpi-sub"><?php echo $stats['activos']; ?> activos · <?php echo $stats['inactivos']; ?> inactivos</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-users"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-database"></i> Registrados en el sistema</div>
    </div>

    <div class="kpi-card" style="background:linear-gradient(135deg,#B71C1C,#C62828);">
        <div class="kpi-label">Administradores</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo $stats['admins']; ?></div>
                <div class="kpi-sub">Acceso completo al sistema</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-user-shield"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-shield-halved"></i> Control total</div>
    </div>

    <div class="kpi-card" style="background:linear-gradient(135deg,#E65100,#F57F17);">
        <div class="kpi-label">Vendedores</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo $stats['vendedores']; ?></div>
                <div class="kpi-sub"><?php echo $stats['supervisores']; ?> supervisor<?php echo $stats['supervisores'] !== 1 ? 'es' : ''; ?> también</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-user-tie"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-chart-line"></i> Gestión de ventas</div>
    </div>

    <div class="kpi-card" style="background:linear-gradient(135deg,#1B5E20,#2E7D32);">
        <div class="kpi-label">Cobradores</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo $stats['cobradores']; ?></div>
                <div class="kpi-sub">Gestión de cobros y pagos</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-hand-holding-dollar"></i></div>
        </div>
        <div class="kpi-footer"><i class="fas fa-money-bill-wave"></i> Recaudación</div>
    </div>

</div>

<!-- ============================================================
     BARRA DE BÚSQUEDA Y FILTROS
     ============================================================ -->
<div class="filter-bar-h fade-in delay-2">
    <form method="GET" action="usuarios.php" id="formFiltrosUsuarios">
        <div class="filter-row-fields">
            <!-- Búsqueda -->
            <div class="filter-field field-search">
                <label for="buscarUsuarios"><i class="fas fa-search"></i> Buscar</label>
                <div class="search-wrap-h">
                    <i class="fas fa-search search-icon-h"></i>
                    <input type="text"
                           id="buscarUsuarios"
                           name="buscar"
                           class="filter-input"
                           placeholder="Usuario, nombre o email…"
                           value="<?php echo htmlspecialchars($buscar); ?>"
                           autocomplete="off">
                </div>
            </div>
            <!-- Rol -->
            <div class="filter-field field-select">
                <label for="rolUsuarios"><i class="fas fa-user-shield"></i> Rol</label>
                <select id="rolUsuarios" name="rol" class="filter-select-h" onchange="this.form.submit()">
                    <option value="all">Todos los roles</option>
                    <option value="admin"      <?php echo $filtro_rol === 'admin'      ? 'selected' : ''; ?>>Administrador</option>
                    <option value="vendedor"   <?php echo $filtro_rol === 'vendedor'   ? 'selected' : ''; ?>>Vendedor</option>
                    <option value="cobrador"   <?php echo $filtro_rol === 'cobrador'   ? 'selected' : ''; ?>>Cobrador</option>
                    <option value="supervisor" <?php echo $filtro_rol === 'supervisor' ? 'selected' : ''; ?>>Supervisor</option>
                </select>
            </div>
            <!-- Estado -->
            <div class="filter-field field-select">
                <label for="estadoUsuarios"><i class="fas fa-circle-half-stroke"></i> Estado</label>
                <select id="estadoUsuarios" name="estado" class="filter-select-h" onchange="this.form.submit()">
                    <option value="all">Todos</option>
                    <option value="activo"   <?php echo $filtro_estado === 'activo'   ? 'selected' : ''; ?>>Activos</option>
                    <option value="inactivo" <?php echo $filtro_estado === 'inactivo' ? 'selected' : ''; ?>>Inactivos</option>
                </select>
            </div>
        </div>
        <div class="filter-row-btns">
            <button type="submit" class="btn btn-primary btn-sm">
                <i class="fas fa-search"></i> Buscar
            </button>
            <?php if ($buscar || ($filtro_rol && $filtro_rol !== 'all') || ($filtro_estado && $filtro_estado !== 'all')): ?>
                <a href="usuarios.php" class="btn btn-secondary btn-sm">
                    <i class="fas fa-times"></i> Limpiar
                </a>
            <?php endif; ?>
            <div class="filter-results-info">
                <?php echo number_format($total_registros); ?> usuario<?php echo $total_registros !== 1 ? 's' : ''; ?>
            </div>
        </div>
    </form>
</div>

<!-- ============================================================
     TABLA DE USUARIOS
     ============================================================ -->
<div class="card fade-in">
    <div class="card-header">
        <div>
            <div class="card-title">Lista de Usuarios</div>
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
                    <th>Usuario</th>
                    <th>Email</th>
                    <th>Rol</th>
                    <th>Estado</th>
                    <th>Último Acceso</th>
                    <th style="text-align:center;">Acciones</th>
                </tr>
            </thead>
            <tbody>
            <?php if (!empty($usuarios)): ?>
                <?php foreach ($usuarios as $u):
                    $esSelf   = ($u['id'] == ($_SESSION['id'] ?? 0));
                    $rolColor = [
                        'admin'      => 'linear-gradient(135deg,#1565C0,#1976D2)',
                        'vendedor'   => 'linear-gradient(135deg,#B45309,#D97706)',
                        'cobrador'   => 'linear-gradient(135deg,#15803D,#16A34A)',
                        'supervisor' => 'linear-gradient(135deg,#6D28D9,#7C3AED)',
                    ][$u['rol']] ?? 'linear-gradient(135deg,var(--gray-500),var(--gray-600))';
                    $initial  = strtoupper(mb_substr($u['nombre'], 0, 1));
                ?>
                <tr>
                    <td>
                        <div style="display:flex;align-items:center;gap:10px;">
                            <div class="user-avatar" style="background:<?php echo $rolColor; ?>;">
                                <?php echo $initial; ?>
                            </div>
                            <div>
                                <div class="user-name">
                                    <?php echo htmlspecialchars($u['nombre']); ?>
                                    <?php if ($esSelf): ?>
                                        <span class="self-badge"><i class="fas fa-circle-dot" style="font-size:8px;"></i> Tú</span>
                                    <?php endif; ?>
                                </div>
                                <div class="user-login">@<?php echo htmlspecialchars($u['usuario']); ?></div>
                            </div>
                        </div>
                    </td>
                    <td><span class="td-email"><?php echo htmlspecialchars($u['email']); ?></span></td>
                    <td>
                        <span class="badge badge-<?php echo $u['rol']; ?>">
                            <?php
                            $rolLabels = [
                                'admin'      => 'Administrador',
                                'vendedor'   => 'Vendedor',
                                'cobrador'   => 'Cobrador',
                                'supervisor' => 'Supervisor',
                            ];
                            echo $rolLabels[$u['rol']] ?? ucfirst($u['rol']);
                            ?>
                        </span>
                    </td>
                    <td>
                        <span class="badge badge-<?php echo $u['estado']; ?>">
                            <?php echo ucfirst($u['estado']); ?>
                        </span>
                    </td>
                    <td>
                        <span class="td-muted">
                            <?php echo $u['ultimo_acceso']
                                ? date('d/m/Y H:i', strtotime($u['ultimo_acceso']))
                                : '—'; ?>
                        </span>
                    </td>
                    <td>
                        <div class="tbl-actions">
                            <button class="btn-tbl edit" title="Editar usuario"
                                    onclick='editarUsuario(<?php echo json_encode([
                                        "id"      => $u["id"],
                                        "usuario" => $u["usuario"],
                                        "nombre"  => $u["nombre"],
                                        "email"   => $u["email"],
                                        "rol"     => $u["rol"],
                                        "estado"  => $u["estado"],
                                    ], JSON_HEX_APOS|JSON_HEX_QUOT); ?>)'>
                                <i class="fas fa-pen"></i>
                            </button>
                            <button class="btn-tbl del <?php echo $esSelf ? 'disabled' : ''; ?>"
                                    title="<?php echo $esSelf ? 'No puedes eliminar tu propia cuenta' : 'Eliminar usuario'; ?>"
                                    <?php echo $esSelf ? 'disabled' : ''; ?>
                                    onclick='<?php echo $esSelf ? '' : 'confirmarEliminar(' . json_encode([
                                        "id"      => $u["id"],
                                        "usuario" => $u["usuario"],
                                        "nombre"  => $u["nombre"],
                                        "rol"     => $u["rol"],
                                    ], JSON_HEX_APOS|JSON_HEX_QUOT) . ')'; ?>'>
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr>
                    <td colspan="6" style="text-align:center;padding:40px;color:var(--gray-400);">
                        <i class="fas fa-users" style="font-size:32px;display:block;margin-bottom:10px;opacity:.4;"></i>
                        No se encontraron usuarios<?php echo ($buscar || $filtro_rol || $filtro_estado) ? ' con los filtros aplicados' : ''; ?>.
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
            de <strong><?php echo number_format($total_registros); ?></strong> usuarios
        </div>

        <div class="paginador-pages">
            <a class="pag-btn <?php echo $pagina_actual<=1?'disabled':''; ?>"
               href="<?php echo buildUsuarioUrl(1,$buscar,$filtro_rol,$filtro_estado); ?>" title="Primera">
                <i class="fas fa-angles-left" style="font-size:10px;"></i>
            </a>
            <a class="pag-btn <?php echo $pagina_actual<=1?'disabled':''; ?>"
               href="<?php echo buildUsuarioUrl($pagina_actual-1,$buscar,$filtro_rol,$filtro_estado); ?>" title="Anterior">
                <i class="fas fa-angle-left" style="font-size:11px;"></i>
            </a>

            <?php for ($p = max(1,$pagina_actual-2); $p <= min($total_paginas,$pagina_actual+2); $p++): ?>
                <a class="pag-btn <?php echo $p===$pagina_actual?'active':''; ?>"
                   href="<?php echo buildUsuarioUrl($p,$buscar,$filtro_rol,$filtro_estado); ?>">
                    <?php echo $p; ?>
                </a>
            <?php endfor; ?>

            <a class="pag-btn <?php echo $pagina_actual>=$total_paginas?'disabled':''; ?>"
               href="<?php echo buildUsuarioUrl($pagina_actual+1,$buscar,$filtro_rol,$filtro_estado); ?>" title="Siguiente">
                <i class="fas fa-angle-right" style="font-size:11px;"></i>
            </a>
            <a class="pag-btn <?php echo $pagina_actual>=$total_paginas?'disabled':''; ?>"
               href="<?php echo buildUsuarioUrl($total_paginas,$buscar,$filtro_rol,$filtro_estado); ?>" title="Última">
                <i class="fas fa-angles-right" style="font-size:10px;"></i>
            </a>
        </div>

        <div class="paginador-rpp">
            <span>Mostrar:</span>
            <select onchange="cambiarRPP(this.value)">
                <?php foreach ([10,15,25,50] as $rpp): ?>
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
     MODAL: NUEVO USUARIO
     ============================================================ -->
<div class="modal-overlay" id="overlayNuevoUsuario">
    <div class="modal-box lg">
        <div class="mhdr">
            <div class="mhdr-title">
                <i class="fas fa-user-plus" style="color:var(--accent);"></i>
                Nuevo Usuario
            </div>
            <button class="modal-close-btn" onclick="cerrarOverlay('overlayNuevoUsuario')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <form id="formNuevoUsuario" method="POST">
            <div class="mbody">
                <input type="hidden" name="action" value="crear">

                <div class="fsec-title"><i class="fas fa-id-card"></i> Datos de Acceso</div>
                <div class="form-grid cols-2">
                    <div class="form-group">
                        <label class="form-label required" for="n_usuario">Nombre de Usuario</label>
                        <input type="text" name="usuario" id="n_usuario" class="form-control"
                               required placeholder="usuario123" autocomplete="off">
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="n_nombre">Nombre Completo</label>
                        <input type="text" name="nombre" id="n_nombre" class="form-control"
                               required placeholder="Nombre y apellidos">
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="n_email">Email</label>
                        <input type="email" name="email" id="n_email" class="form-control"
                               required placeholder="correo@ejemplo.com">
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="n_password">Contraseña</label>
                        <div class="password-wrap">
                            <input type="password" name="password" id="n_password" class="form-control"
                                   required placeholder="Mínimo 6 caracteres" autocomplete="new-password">
                            <button type="button" class="btn-toggle-pass" onclick="togglePass('n_password', this)">
                                <i class="fas fa-eye"></i>
                            </button>
                        </div>
                    </div>
                </div>

                <div class="fsec-title" style="margin-top:18px;"><i class="fas fa-user-tag"></i> Rol del Usuario</div>
                <div class="rol-chips" id="nuevoRolChips">
                    <label class="rol-chip admin selected" onclick="seleccionarRol(this,'admin','nuevo')">
                        <input type="radio" name="rol" value="admin" class="rol-radio" checked>
                        <i class="fas fa-user-shield"></i> Administrador
                    </label>
                    <label class="rol-chip vendedor" onclick="seleccionarRol(this,'vendedor','nuevo')">
                        <input type="radio" name="rol" value="vendedor" class="rol-radio">
                        <i class="fas fa-user-tie"></i> Vendedor
                    </label>
                    <label class="rol-chip cobrador" onclick="seleccionarRol(this,'cobrador','nuevo')">
                        <input type="radio" name="rol" value="cobrador" class="rol-radio">
                        <i class="fas fa-hand-holding-dollar"></i> Cobrador
                    </label>
                    <label class="rol-chip supervisor" onclick="seleccionarRol(this,'supervisor','nuevo')">
                        <input type="radio" name="rol" value="supervisor" class="rol-radio">
                        <i class="fas fa-glasses"></i> Supervisor
                    </label>
                </div>
                <div style="margin-top:12px;padding:10px 14px;background:var(--gray-50);
                            border-radius:var(--radius-sm);font-size:12.5px;color:var(--gray-500);"
                     id="nuevoRolDesc">
                    <i class="fas fa-info-circle" style="color:var(--accent);margin-right:5px;"></i>
                    <strong>Administrador:</strong> Acceso completo a todos los módulos del sistema.
                </div>
            </div>
            <div class="mfooter">
                <button type="button" class="btn btn-secondary"
                        onclick="cerrarOverlay('overlayNuevoUsuario')">
                    <i class="fas fa-times"></i> Cancelar
                </button>
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-user-plus"></i> Crear Usuario
                </button>
            </div>
        </form>
    </div>
</div>


<!-- ============================================================
     MODAL: EDITAR USUARIO
     ============================================================ -->
<div class="modal-overlay" id="overlayEditarUsuario">
    <div class="modal-box lg">
        <div class="mhdr">
            <div>
                <div class="mhdr-title" id="editarUsuarioTitulo">
                    <i class="fas fa-pen" style="color:var(--accent);"></i>
                    Editar Usuario
                </div>
                <div class="mhdr-sub" id="editarUsuarioSub"></div>
            </div>
            <button class="modal-close-btn" onclick="cerrarOverlay('overlayEditarUsuario')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <form id="formEditarUsuario" method="POST">
            <div class="mbody">
                <input type="hidden" name="action"     value="editar">
                <input type="hidden" name="usuario_id" id="edit_usuario_id">

                <div class="fsec-title"><i class="fas fa-id-card"></i> Datos del Usuario</div>
                <div class="form-grid cols-2">
                    <div class="form-group">
                        <label class="form-label">Usuario (login)</label>
                        <input type="text" id="edit_usuario_display" class="form-control" readonly>
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="edit_nombre">Nombre Completo</label>
                        <input type="text" name="nombre" id="edit_nombre" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label required" for="edit_email">Email</label>
                        <input type="email" name="email" id="edit_email" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="edit_password">
                            Nueva Contraseña
                            <span style="font-size:10.5px;color:var(--gray-400);font-weight:400;">(dejar en blanco para mantener)</span>
                        </label>
                        <div class="password-wrap">
                            <input type="password" name="password" id="edit_password" class="form-control"
                                   placeholder="••••••••" autocomplete="new-password">
                            <button type="button" class="btn-toggle-pass" onclick="togglePass('edit_password', this)">
                                <i class="fas fa-eye"></i>
                            </button>
                        </div>
                    </div>
                </div>

                <div class="fsec-title" style="margin-top:18px;"><i class="fas fa-user-tag"></i> Rol</div>
                <div class="rol-chips" id="editRolChips">
                    <label class="rol-chip admin" onclick="seleccionarRol(this,'admin','editar')">
                        <input type="radio" name="rol" value="admin" class="rol-radio">
                        <i class="fas fa-user-shield"></i> Administrador
                    </label>
                    <label class="rol-chip vendedor" onclick="seleccionarRol(this,'vendedor','editar')">
                        <input type="radio" name="rol" value="vendedor" class="rol-radio">
                        <i class="fas fa-user-tie"></i> Vendedor
                    </label>
                    <label class="rol-chip cobrador" onclick="seleccionarRol(this,'cobrador','editar')">
                        <input type="radio" name="rol" value="cobrador" class="rol-radio">
                        <i class="fas fa-hand-holding-dollar"></i> Cobrador
                    </label>
                    <label class="rol-chip supervisor" onclick="seleccionarRol(this,'supervisor','editar')">
                        <input type="radio" name="rol" value="supervisor" class="rol-radio">
                        <i class="fas fa-glasses"></i> Supervisor
                    </label>
                </div>
                <div style="margin-top:12px;padding:10px 14px;background:var(--gray-50);
                            border-radius:var(--radius-sm);font-size:12.5px;color:var(--gray-500);"
                     id="editRolDesc">
                </div>

                <div class="fsec-title" style="margin-top:18px;"><i class="fas fa-toggle-on"></i> Estado</div>
                <div class="form-group" style="max-width:260px;">
                    <label class="form-label" for="edit_estado_sel">Estado de la cuenta</label>
                    <select name="estado" id="edit_estado_sel" class="form-control">
                        <option value="activo">Activo</option>
                        <option value="inactivo">Inactivo</option>
                    </select>
                </div>
            </div>
            <div class="mfooter">
                <button type="button" class="btn btn-secondary"
                        onclick="cerrarOverlay('overlayEditarUsuario')">
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
<div class="modal-overlay" id="overlayEliminarUsuario">
    <div class="modal-box sm">
        <div class="mhdr">
            <div class="mhdr-title" style="color:#DC2626;">
                <i class="fas fa-trash"></i> Eliminar Usuario
            </div>
            <button class="modal-close-btn" onclick="cerrarOverlay('overlayEliminarUsuario')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="mbody">
            <div id="eliminarUsuarioDetalles" style="margin-bottom:14px;"></div>
            <div style="background:#FEF2F2;border:1px solid #FCA5A5;border-radius:var(--radius-sm);
                        padding:14px 16px;color:#991B1B;font-size:13.5px;">
                <i class="fas fa-exclamation-circle" style="margin-right:6px;"></i>
                <strong>¿Confirmar la eliminación permanente?</strong><br>
                <span style="font-size:12.5px;opacity:.85;">
                    Esta acción no puede revertirse. El usuario perderá acceso al sistema inmediatamente.
                </span>
            </div>
        </div>
        <div class="mfooter">
            <button class="btn btn-secondary" onclick="cerrarOverlay('overlayEliminarUsuario')">
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
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;')
                        .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function cambiarRPP(v) {
    document.cookie = 'usuarios_por_pagina='+v+'; path=/; max-age=31536000';
    window.location.href = 'usuarios.php';
}

/* ── Toggle visibilidad contraseña ── */
function togglePass(inputId, btn) {
    var input = document.getElementById(inputId);
    var icon  = btn.querySelector('i');
    if (input.type === 'password') {
        input.type = 'text';
        icon.className = 'fas fa-eye-slash';
    } else {
        input.type = 'password';
        icon.className = 'fas fa-eye';
    }
}

/* ═══════════════════════════════════════════════════════════
   CHIPS DE ROL
═══════════════════════════════════════════════════════════ */
var _rolDescs = {
    admin      : '<strong>Administrador:</strong> Acceso completo a todos los módulos del sistema.',
    vendedor   : '<strong>Vendedor:</strong> Gestión de clientes, contratos y seguimiento de ventas.',
    cobrador   : '<strong>Cobrador:</strong> Gestión de cobros, pagos y asignaciones de facturas.',
    supervisor : '<strong>Supervisor:</strong> Visualización de reportes y supervisión del equipo.',
};

function seleccionarRol(chip, rol, contexto) {
    var container = contexto === 'nuevo'
        ? document.getElementById('nuevoRolChips')
        : document.getElementById('editRolChips');
    var descEl = document.getElementById(contexto === 'nuevo' ? 'nuevoRolDesc' : 'editRolDesc');

    /* Quitar selected de todos */
    container.querySelectorAll('.rol-chip').forEach(function(c){
        c.classList.remove('selected');
    });

    /* Marcar el seleccionado */
    chip.classList.add('selected');
    var radio = chip.querySelector('input[type="radio"]');
    if (radio) radio.checked = true;

    /* Actualizar descripción */
    if (descEl) {
        descEl.innerHTML = '<i class="fas fa-info-circle" style="color:var(--accent);margin-right:5px;"></i>' +
            (_rolDescs[rol] || '');
    }
}

function establecerRolChip(rol, contexto) {
    var container = contexto === 'nuevo'
        ? document.getElementById('nuevoRolChips')
        : document.getElementById('editRolChips');
    if (!container) return;

    container.querySelectorAll('.rol-chip').forEach(function(c){
        c.classList.remove('selected');
        var r = c.querySelector('input[type="radio"]');
        if (r && r.value === rol) {
            c.classList.add('selected');
            r.checked = true;
        }
    });

    var descEl = document.getElementById(contexto === 'nuevo' ? 'nuevoRolDesc' : 'editRolDesc');
    if (descEl) {
        descEl.innerHTML = '<i class="fas fa-info-circle" style="color:var(--accent);margin-right:5px;"></i>' +
            (_rolDescs[rol] || '');
    }
}


/* ═══════════════════════════════════════════════════════════
   MODAL CREAR USUARIO
═══════════════════════════════════════════════════════════ */
/* Reset el formulario cuando se abre el modal */
document.getElementById('overlayNuevoUsuario').addEventListener('click', function(e){
    if (e.target === this) cerrarOverlay('overlayNuevoUsuario');
});

/* Asegurar rol admin seleccionado por defecto al abrir */
document.querySelector('[onclick="abrirOverlay(\'overlayNuevoUsuario\')"]')
    ?.addEventListener('click', function(){
        setTimeout(function(){
            document.getElementById('formNuevoUsuario').reset();
            establecerRolChip('admin', 'nuevo');
        }, 50);
    });


/* ═══════════════════════════════════════════════════════════
   MODAL EDITAR USUARIO
═══════════════════════════════════════════════════════════ */
function editarUsuario(u) {
    document.getElementById('formEditarUsuario').reset();
    document.getElementById('edit_usuario_id').value        = u.id;
    document.getElementById('edit_usuario_display').value   = u.usuario;
    document.getElementById('edit_nombre').value            = u.nombre;
    document.getElementById('edit_email').value             = u.email;
    document.getElementById('edit_password').value          = '';
    document.getElementById('edit_estado_sel').value        = u.estado;
    document.getElementById('editarUsuarioTitulo').innerHTML =
        '<i class="fas fa-pen" style="color:var(--accent);"></i> Editar: ' + esc(u.nombre);
    document.getElementById('editarUsuarioSub').textContent =
        '@' + u.usuario + ' · ' + _rolDescs[u.rol]?.replace(/<[^>]+>/g,'').split(':')[0] || '';

    establecerRolChip(u.rol, 'editar');
    abrirOverlay('overlayEditarUsuario');
}


/* ═══════════════════════════════════════════════════════════
   MODAL ELIMINAR USUARIO
═══════════════════════════════════════════════════════════ */
var _usuarioAEliminar = null;

function confirmarEliminar(u) {
    _usuarioAEliminar = u;

    var rolLabel = {
        admin:'Administrador', vendedor:'Vendedor',
        cobrador:'Cobrador', supervisor:'Supervisor'
    }[u.rol] || u.rol;

    var rolGrad = {
        admin      : 'linear-gradient(135deg,#1565C0,#1976D2)',
        vendedor   : 'linear-gradient(135deg,#B45309,#D97706)',
        cobrador   : 'linear-gradient(135deg,#15803D,#16A34A)',
        supervisor : 'linear-gradient(135deg,#6D28D9,#7C3AED)',
    }[u.rol] || 'var(--gray-500)';

    document.getElementById('eliminarUsuarioDetalles').innerHTML =
        '<div style="background:var(--gray-50);border:1px solid var(--gray-200);' +
        'border-radius:var(--radius-sm);padding:16px;">' +
        '<div style="display:flex;align-items:center;gap:12px;">' +
        '<div style="width:44px;height:44px;border-radius:50%;' +
            'background:' + rolGrad + ';display:flex;align-items:center;' +
            'justify-content:center;font-size:16px;font-weight:700;color:white;flex-shrink:0;">' +
            esc(u.nombre.charAt(0).toUpperCase()) +
        '</div>' +
        '<div>' +
        '<div style="font-size:15px;font-weight:700;color:var(--gray-800);">' + esc(u.nombre) + '</div>' +
        '<div style="font-size:12px;color:var(--gray-400);font-family:monospace;margin-top:1px;">@' + esc(u.usuario) + '</div>' +
        '</div>' +
        '<div style="margin-left:auto;">' +
        '<span class="badge badge-' + u.rol + '">' + rolLabel + '</span>' +
        '</div>' +
        '</div>' +
        '</div>';

    abrirOverlay('overlayEliminarUsuario');
}

document.getElementById('btnConfirmarEliminar').addEventListener('click', function() {
    if (!_usuarioAEliminar) return;
    var f = document.createElement('form');
    f.method = 'POST';
    f.innerHTML = '<input type="hidden" name="action"      value="eliminar">' +
                  '<input type="hidden" name="usuario_id"  value="' + _usuarioAEliminar.id + '">';
    document.body.appendChild(f);
    f.submit();
});

/* Cerrar con clic en overlay */
['overlayNuevoUsuario','overlayEditarUsuario','overlayEliminarUsuario'].forEach(function(id){
    var el = document.getElementById(id);
    if (el) el.addEventListener('click', function(e){
        if (e.target === this) cerrarOverlay(id);
    });
});

/* Cerrar con Escape */
document.addEventListener('keydown', function(e){
    if (e.key === 'Escape') {
        ['overlayNuevoUsuario','overlayEditarUsuario','overlayEliminarUsuario'].forEach(function(id){
            cerrarOverlay(id);
        });
    }
});

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