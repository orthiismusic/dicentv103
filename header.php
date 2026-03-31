<?php
// header.php
require_once 'config.php';
require_once 'toast.php';
verificarSesion();

// Configuración del sistema (logo)
$stmtConfig = $conn->prepare("SELECT logo_url FROM configuracion_sistema WHERE id = 1");
$stmtConfig->execute();
$config = $stmtConfig->fetch();

// Datos del usuario en sesión
$usuarioNombre = $_SESSION['usuario_nombre'] ?? 'Usuario';
$usuarioRol    = ucfirst($_SESSION['rol'] ?? 'usuario');

// Iniciales para el avatar (máx. 2 caracteres)
$palabras  = explode(' ', trim($usuarioNombre));
$iniciales = strtoupper(substr($palabras[0], 0, 1));
if (isset($palabras[1])) {
    $iniciales .= strtoupper(substr($palabras[1], 0, 1));
}

// Página actual para marcar nav-item activo y breadcrumb
$paginaActual = basename($_SERVER['PHP_SELF']);

// Mapa de páginas → nombre amigable para breadcrumb
$nombresPagina = [
    'dashboard.php'    => 'Dashboard',
    'clientes.php'     => 'Clientes',
    'contratos.php'    => 'Contratos',
    'carnet.php'       => 'Carnet',
    'planes.php'       => 'Planes de Seguro',
    'facturacion.php'  => 'Facturación',
    'asignacion.php'   => 'Asignación de Facturas',
    'pagos.php'        => 'Pagos y Cobros',
    'reportes.php'     => 'Reportes',
    'usuarios.php'     => 'Usuarios',
    'direccion.php'    => 'Dirección',
    'configuracion.php'=> 'Configuración',
    'vendedores.php'   => 'Vendedores',
    'cobradores.php'   => 'Cobradores',
];
$tituloActual = $nombresPagina[$paginaActual] ?? ucfirst(str_replace('.php', '', $paginaActual));

// Función auxiliar: devuelve clase 'active' si la página coincide
function navActive(string $pagina): string {
    return basename($_SERVER['PHP_SELF']) === $pagina ? ' active' : '';
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SEFURE — <?php echo htmlspecialchars($tituloActual); ?></title>

    <!-- ===== FUENTES ===== -->
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">

    <!-- ===== FONT AWESOME ===== -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" rel="stylesheet">

    <!-- ===== TOASTIFY ===== -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/toastify-js/src/toastify.min.css">
    <script src="https://cdn.jsdelivr.net/npm/toastify-js"></script>

    <!-- ===== JQUERY (primero, requerido por Bootstrap 4 y plugins) ===== -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>

    <!-- ===== SWEETALERT2 ===== -->
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>

    <!-- ===== BOOTSTRAP 5 (CSS + JS) ===== -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>

    <!-- ===== BOOTSTRAP 4 (compatibilidad con módulos que lo usen) ===== -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
    <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.min.js"></script>

    <!-- ===== CHART.JS ===== -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <!-- ===== HOJA DE ESTILOS PRINCIPAL ===== -->
    <link rel="stylesheet" href="styles.css">

    <!-- ===== TOAST SYSTEM ===== -->
    <?php echo Toast::render(); ?>

    <!-- ===== MANEJO DE SESIÓN EXPIRADA (AJAX) ===== -->
    <script>
    $(document).ajaxError(function(event, jqXHR) {
        if (jqXHR.status === 401 || jqXHR.responseText === 'Sesion_expirada') {
            alert('Su sesión ha expirado. Por favor, vuelva a iniciar sesión.');
            window.location.href = 'login.php?mensaje=sesion_expirada';
        }
    });
    </script>
</head>
<body>

<!-- ============================================================
     SIDEBAR
     ============================================================ -->
<aside class="sidebar" id="sidebar">

    <!-- Brand / Logo -->
    <div class="sidebar-brand">
        <?php if (!empty($config['logo_url'])): ?>
            <img src="<?php echo htmlspecialchars($config['logo_url']); ?>"
                 alt="Orthiis Logo"
                 style="height:34px;width:auto;border-radius:8px;object-fit:contain;">
        <?php else: ?>
            <div class="brand-icon">
                <i class="fas fa-shield-halved"></i>
            </div>
        <?php endif; ?>
        <div class="brand-text">
            <div class="brand-name">ORTHIIS</div>
            <div class="brand-sub">Sistema de Seguros</div>
        </div>
    </div>

    <!-- Navegación -->
    <nav class="sidebar-nav">

        <!-- ── PRINCIPAL ── -->
        <div class="nav-section-label">Principal</div>

        <a class="nav-item<?php echo navActive('dashboard.php'); ?>" href="dashboard.php">
            <span class="nav-icon"><i class="fas fa-chart-pie"></i></span>
            Dashboard
        </a>

        <!-- ── GESTIÓN ── -->
        <div class="nav-section-label">Gestión</div>

        <a class="nav-item<?php echo navActive('planes.php'); ?>" href="planes.php">
            <span class="nav-icon"><i class="fas fa-umbrella"></i></span>
            Planes de Seguro
        </a>

        <a class="nav-item<?php echo navActive('clientes.php'); ?>" href="clientes.php">
            <span class="nav-icon"><i class="fas fa-users"></i></span>
            Clientes
        </a>

        <a class="nav-item<?php echo navActive('contratos.php'); ?>" href="contratos.php">
            <span class="nav-icon"><i class="fas fa-file-contract"></i></span>
            Contratos
        </a>

        <a class="nav-item<?php echo navActive('carnet.php'); ?>" href="carnet.php">
            <span class="nav-icon"><i class="fas fa-id-card"></i></span>
            Carnet
        </a>

        <!-- ── FINANZAS ── -->
        <div class="nav-section-label">Finanzas</div>

        <a class="nav-item<?php echo navActive('facturacion.php'); ?>" href="facturacion.php">
            <span class="nav-icon"><i class="fas fa-file-invoice-dollar"></i></span>
            Facturación
        </a>

        <a class="nav-item<?php echo navActive('pagos.php'); ?>" href="pagos.php">
            <span class="nav-icon"><i class="fas fa-money-bill-wave"></i></span>
            Pagos y Cobros
        </a>

        <a class="nav-item<?php echo navActive('asignacion.php'); ?>" href="asignacion.php">
            <span class="nav-icon"><i class="fas fa-list-check"></i></span>
            Asignación Facturas
        </a>
        
        <a class="nav-item<?php echo navActive('vigencia.php'); ?>" href="vigencia.php">
            <span class="nav-icon"><i class="fas fa-shield-halved"></i></span>
            Control Vigencias
        </a>

        <!-- ── PERSONAL ── -->
        <div class="nav-section-label">Personal</div>

        <a class="nav-item<?php echo navActive('vendedores.php'); ?>" href="vendedores.php">
            <span class="nav-icon"><i class="fas fa-briefcase"></i></span>
            Vendedores
        </a>

        <a class="nav-item<?php echo navActive('cobradores.php'); ?>" href="cobradores.php">
            <span class="nav-icon"><i class="fas fa-motorcycle"></i></span>
            Cobradores
        </a>

        <a class="nav-item<?php echo navActive('direccion.php'); ?>" href="direccion.php">
            <span class="nav-icon"><i class="fas fa-map-marker-alt"></i></span>
            Dirección
        </a>

        <!-- ── SISTEMA ── -->
        <div class="nav-section-label">Sistema</div>

        <a class="nav-item<?php echo navActive('reportes.php'); ?>" href="reportes.php">
            <span class="nav-icon"><i class="fas fa-chart-bar"></i></span>
            Reportes
        </a>

        <a class="nav-item<?php echo navActive('usuarios.php'); ?>" href="usuarios.php">
            <span class="nav-icon"><i class="fas fa-user-friends"></i></span>
            Usuarios
        </a>

        <a class="nav-item<?php echo navActive('configuracion.php'); ?>" href="configuracion.php">
            <span class="nav-icon"><i class="fas fa-gear"></i></span>
            Configuración
        </a>

    </nav>

    <!-- Footer del sidebar: usuario logueado -->
    <div class="sidebar-footer">
        <div class="sidebar-user">
            <div class="sidebar-avatar">
                <?php echo htmlspecialchars($iniciales); ?>
            </div>
            <div class="sidebar-user-info">
                <div class="user-name"><?php echo htmlspecialchars($usuarioNombre); ?></div>
                <div class="user-role"><?php echo htmlspecialchars($usuarioRol); ?></div>
            </div>
            <i class="fas fa-ellipsis-vertical"
               style="color:rgba(255,255,255,0.3);margin-left:auto;font-size:12px;"></i>
        </div>
    </div>

</aside>
<!-- FIN SIDEBAR -->


<!-- ============================================================
     MAIN WRAPPER
     ============================================================ -->
<div class="main-wrapper" id="mainWrapper">

    <!-- ============================================================
         TOPBAR
         ============================================================ -->
    <header class="topbar">

        <!-- Botón toggle sidebar (mobile) -->
        <button class="topbar-toggle" id="sidebarToggle" title="Menú">
            <i class="fas fa-bars"></i>
        </button>

        <!-- Breadcrumb -->
        <div class="topbar-breadcrumb">
            <a href="dashboard.php">Inicio</a>
            <?php if ($paginaActual !== 'dashboard.php'): ?>
                <span class="sep"><i class="fas fa-chevron-right" style="font-size:10px;"></i></span>
                <span class="current"><?php echo htmlspecialchars($tituloActual); ?></span>
            <?php endif; ?>
        </div>

        <!-- Buscador global inteligente -->
        <div class="topbar-search-global" id="topbarSearchGlobal">
            <i class="fas fa-search tsg-icon"></i>
            <input type="text"
                   id="topbarSearchInput"
                   placeholder="Buscar cliente, contrato o factura..."
                   autocomplete="off"
                   spellcheck="false">
            <button class="tsg-clear" id="tsgClear" title="Limpiar">
                <i class="fas fa-times"></i>
            </button>
            <!-- Dropdown resultados -->
            <div class="tsg-dropdown" id="tsgDropdown">
                <div class="tsg-loading" id="tsgLoading" style="display:none;">
                    <i class="fas fa-spinner"></i> Buscando...
                </div>
                <div id="tsgResultsContainer"></div>
            </div>
        </div>

        <!-- Spacer -->
        <div class="topbar-spacer"></div>

        <!-- Acciones topbar -->
        <div class="topbar-actions">

            <!-- Botón notificaciones -->
            <button class="topbar-btn" title="Notificaciones">
                <i class="fas fa-bell"></i>
            </button>

            <!-- Botón ayuda -->
            <button class="topbar-btn" title="Ayuda">
                <i class="fas fa-circle-question"></i>
            </button>

            <!-- Usuario / dropdown -->
            <div class="topbar-user" id="topbarUser">
                <div class="topbar-avatar">
                    <?php echo htmlspecialchars($iniciales); ?>
                </div>
                <div class="topbar-user-info">
                    <div class="user-name"><?php echo htmlspecialchars($usuarioNombre); ?></div>
                    <div class="user-role"><?php echo htmlspecialchars($usuarioRol); ?></div>
                </div>
                <i class="fas fa-chevron-down"
                   style="font-size:11px;color:var(--gray-400);margin-left:2px;"></i>

                <!-- Dropdown -->
                <div class="user-dropdown" id="userDropdown">
                    <ul>
                        <li>
                            <a href="#">
                                <i class="fas fa-user"></i> Ver Perfil
                            </a>
                        </li>
                        <li>
                            <a href="#">
                                <i class="fas fa-key"></i> Cambiar Contraseña
                            </a>
                        </li>
                        <li class="divider"></li>
                        <li>
                            <a href="logout.php">
                                <i class="fas fa-right-from-bracket"></i> Cerrar Sesión
                            </a>
                        </li>
                    </ul>
                </div>
            </div>
            <!-- /dropdown usuario -->

        </div>
        <!-- /topbar-actions -->

    </header>
    <!-- FIN TOPBAR -->


    <!-- ============================================================
         CONTENIDO DE PÁGINA
         (Cada módulo coloca su HTML aquí)
         ============================================================ -->
    <div class="page-content">

    <!-- ← Los módulos insertan su contenido aquí →
         footer.php cierra este div y el main-wrapper -->

<?php
/*
 * header.php termina aquí.
 * El módulo escribe su HTML y luego hace:  require_once 'footer.php';
 */
?>