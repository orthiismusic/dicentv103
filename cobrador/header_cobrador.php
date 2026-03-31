<?php
/* ============================================================
   cobrador/header_cobrador.php — VERSIÓN CORREGIDA
   ============================================================ */

// Iniciar buffer de salida para capturar warnings antes del HTML
ob_start();

require_once __DIR__ . '/config_cobrador.php';
verificarSesionCobrador();

// Datos del cobrador en sesión
$nombreCobrador = $_SESSION['cobrador_portal_nombre'] ?? 'Cobrador';
$codigoCobrador = $_SESSION['cobrador_portal_codigo'] ?? '';

// Iniciales del avatar
$partes   = explode(' ', trim($nombreCobrador));
$iniciales = strtoupper(substr($partes[0] ?? 'C', 0, 1));
if (!empty($partes[1])) $iniciales .= strtoupper(substr($partes[1], 0, 1));

// Mensajes no leídos
$msgNoLeidos = getMensajesNoLeidos();

// Logo del sistema
$cfg = ['logo_url' => '', 'nombre_empresa' => 'ORTHIIS'];
try {
    $stmtCfg = $conn->query("SELECT logo_url, nombre_empresa FROM configuracion_sistema WHERE id=1 LIMIT 1");
    $cfg = $stmtCfg->fetch(PDO::FETCH_ASSOC) ?: $cfg;
} catch (PDOException $e) { /* silencioso */ }

// Página actual
$paginaActual = basename($_SERVER['PHP_SELF']);
$tituloPagina = $paginaActualTitulo ?? 'Portal Cobrador';

function navActivo(string $pagina): string {
    return basename($_SERVER['PHP_SELF']) === $pagina ? ' active' : '';
}

// Limpiar cualquier warning acumulado en el buffer
// antes de enviar el primer byte de HTML
ob_clean();
?>
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <meta name="theme-color" content="#1e2d4a">
  <meta name="mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <title><?= htmlspecialchars($tituloPagina) ?> — Cobrador ORTHIIS</title>

  <!-- CSS del portal (ruta relativa a /cobrador/) -->
  <link rel="stylesheet" href="css/cobrador.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>

<!-- ═══════════════════════════════════════════════════
     TOPBAR
═══════════════════════════════════════════════════ -->
<header class="app-topbar" id="appTopbar">
  <div class="topbar-left">
    <button class="btn-hamburger" onclick="toggleSidebar()" aria-label="Menú">
      <i class="fas fa-bars"></i>
    </button>
    <span class="topbar-page-title"><?= htmlspecialchars($tituloPagina) ?></span>
  </div>
  <div class="topbar-right">
    <div class="topbar-avatar" id="topbarAvatar" onclick="toggleDropdown()">
      <?= htmlspecialchars($iniciales) ?>
      <?php if ($msgNoLeidos > 0): ?>
        <span class="msg-badge" id="topbarMsgBadge"><?= min($msgNoLeidos, 99) ?></span>
      <?php endif; ?>
    </div>
    <div class="topbar-dropdown" id="topbarDropdown">
      <div class="dropdown-header">
        <div class="dropdown-name"><?= htmlspecialchars($nombreCobrador) ?></div>
        <div class="dropdown-role">
          <i class="fas fa-motorcycle" style="font-size:10px;margin-right:3px;"></i>
          Cobrador · <?= htmlspecialchars($codigoCobrador) ?>
        </div>
      </div>
      <a href="mensajes.php" class="dropdown-item">
        <i class="fas fa-comments"></i>
        Mensajes
        <?php if ($msgNoLeidos > 0): ?>
          <span style="margin-left:auto;background:var(--danger);color:#fff;border-radius:10px;
                       font-size:10px;padding:1px 7px;font-weight:700;">
            <?= $msgNoLeidos ?>
          </span>
        <?php endif; ?>
      </a>
      <div class="dropdown-divider"></div>
      <a href="logout.php" class="dropdown-item danger">
        <i class="fas fa-right-from-bracket"></i>
        Cerrar Sesión
      </a>
    </div>
  </div>
</header>

<!-- Overlay sidebar móvil -->
<div class="sidebar-overlay" id="sidebarOverlay" onclick="closeSidebar()"></div>

<!-- ═══════════════════════════════════════════════════
     SIDEBAR
═══════════════════════════════════════════════════ -->
<nav class="app-sidebar" id="appSidebar">

  <div class="sidebar-logo-area">
    <?php if (!empty($cfg['logo_url'])): ?>
      <img src="../<?= htmlspecialchars($cfg['logo_url']) ?>"
           alt="Logo" class="sidebar-logo-img"
           onerror="this.style.display='none';this.nextElementSibling.style.display='block'">
      <div class="sidebar-logo-text" style="display:none;">
        <i class="fas fa-shield-halved" style="margin-right:6px;color:#60a5fa;"></i>
        <?= htmlspecialchars($cfg['nombre_empresa']) ?>
      </div>
    <?php else: ?>
      <div class="sidebar-logo-text">
        <i class="fas fa-shield-halved" style="margin-right:6px;color:#60a5fa;"></i>
        <?= htmlspecialchars($cfg['nombre_empresa']) ?>
      </div>
    <?php endif; ?>
  </div>

  <div class="sidebar-cobrador-info">
    <div style="display:flex;align-items:center;gap:10px;">
      <div style="width:38px;height:38px;border-radius:50%;background:var(--accent);color:#fff;
                  display:flex;align-items:center;justify-content:center;font-size:13px;
                  font-weight:700;flex-shrink:0;border:2px solid rgba(255,255,255,.2);">
        <?= htmlspecialchars($iniciales) ?>
      </div>
      <div>
        <div class="sidebar-cobrador-name"><?= htmlspecialchars($nombreCobrador) ?></div>
        <div class="sidebar-cobrador-code">
          <i class="fas fa-motorcycle" style="font-size:9px;margin-right:3px;"></i>
          Cód. <?= htmlspecialchars($codigoCobrador) ?>
        </div>
      </div>
    </div>
  </div>

  <div class="sidebar-nav">

    <div class="nav-section-label">Principal</div>

    <a href="dashboard.php" class="nav-item<?= navActivo('dashboard.php') ?>">
      <i class="fas fa-house"></i> Dashboard
    </a>

    <a href="clientes.php" class="nav-item<?= navActivo('clientes.php') ?>">
      <i class="fas fa-users"></i> Mis Clientes
    </a>

    <a href="facturas.php" class="nav-item<?= navActivo('facturas.php') && !isset($_GET['vista']) ? ' active' : (navActivo('facturas.php') && ($_GET['vista'] ?? '') !== 'ruta' ? ' active' : '') ?>">
      <i class="fas fa-file-invoice-dollar"></i> Facturas Pendientes
    </a>

    <a href="facturas.php?vista=ruta" class="nav-item<?= navActivo('facturas.php') && ($_GET['vista'] ?? '') === 'ruta' ? ' active' : '' ?>">
      <i class="fas fa-route"></i> Planear Ruta
    </a>

    <div class="nav-section-label" style="margin-top:8px;">Comunicación</div>

    <a href="mensajes.php" class="nav-item<?= navActivo('mensajes.php') ?>" id="navMensajes">
      <i class="fas fa-comments"></i>
      Mensajes
      <?php if ($msgNoLeidos > 0): ?>
        <span class="nav-badge" id="navMsgBadge"><?= min($msgNoLeidos, 99) ?></span>
      <?php endif; ?>
    </a>

    <div class="nav-section-label" style="margin-top:8px;">Sistema</div>

    <a href="logout.php" class="nav-item" style="color:rgba(255,120,120,.85);">
      <i class="fas fa-right-from-bracket"></i> Cerrar Sesión
    </a>

  </div>

  <div class="sidebar-footer">
    <?= htmlspecialchars($cfg['nombre_empresa']) ?> © <?= date('Y') ?><br>
    <span style="font-size:10px;">Portal del Cobrador v1.0</span>
  </div>

</nav>

<!-- ═══════════════════════════════════════════════════
     BOTTOM NAV (solo móvil)
═══════════════════════════════════════════════════ -->
<nav class="app-bottomnav">
  <div class="bottomnav-inner">

    <a href="dashboard.php" class="bottomnav-item<?= navActivo('dashboard.php') ?>">
      <i class="fas fa-house"></i>
      <span>Inicio</span>
    </a>

    <a href="clientes.php" class="bottomnav-item<?= navActivo('clientes.php') ?>">
      <i class="fas fa-users"></i>
      <span>Clientes</span>
    </a>

    <a href="facturas.php" class="bottomnav-item<?= navActivo('facturas.php') ?>">
      <i class="fas fa-file-invoice-dollar"></i>
      <span>Facturas</span>
    </a>

    <a href="facturas.php?vista=ruta" class="bottomnav-item">
      <i class="fas fa-route"></i>
      <span>Ruta</span>
    </a>

    <a href="mensajes.php" class="bottomnav-item<?= navActivo('mensajes.php') ?>">
      <i class="fas fa-comments"></i>
      <span>Mensajes</span>
      <?php if ($msgNoLeidos > 0): ?>
        <span class="bn-badge" id="bnMsgBadge"><?= min($msgNoLeidos, 99) ?></span>
      <?php endif; ?>
    </a>

  </div>
</nav>

<!-- Contenedor de Toasts -->
<div class="toast-container" id="toastContainer"></div>

<!-- ═══════════════════════════════════════════════════
     SCRIPTS GLOBALES
═══════════════════════════════════════════════════ -->
<script>
var CSRF_TOKEN = '<?= htmlspecialchars($_SESSION['csrf_token_cobrador'] ?? '') ?>';

/* ── Sidebar ── */
function toggleSidebar() {
  document.getElementById('appSidebar').classList.toggle('open');
  document.getElementById('sidebarOverlay').classList.toggle('open');
}
function closeSidebar() {
  document.getElementById('appSidebar').classList.remove('open');
  document.getElementById('sidebarOverlay').classList.remove('open');
}

/* ── Dropdown topbar ── */
function toggleDropdown() {
  document.getElementById('topbarDropdown').classList.toggle('open');
}
document.addEventListener('click', function(e) {
  if (!e.target.closest('#topbarAvatar') && !e.target.closest('#topbarDropdown')) {
    var dd = document.getElementById('topbarDropdown');
    if (dd) dd.classList.remove('open');
  }
});

/* ── Toast notifications ── */
function showToast(msg, tipo, duracion) {
  tipo = tipo || 'info';
  duracion = duracion || 4000;
  var icons = { success:'check-circle', error:'circle-xmark', warning:'triangle-exclamation', info:'circle-info' };
  var tc = document.getElementById('toastContainer');
  if (!tc) return;
  var t = document.createElement('div');
  t.className = 'toast ' + tipo;
  t.innerHTML = '<i class="fas fa-' + (icons[tipo] || 'circle-info') + '"></i><span>' + msg + '</span>';
  tc.appendChild(t);
  setTimeout(function() {
    t.style.animation = 'toast-out .3s ease forwards';
    setTimeout(function() { if (t.parentNode) t.parentNode.removeChild(t); }, 300);
  }, duracion);
}

/* ── Polling mensajes no leídos (cada 60s) ── */
var _prevMsgCount = <?= $msgNoLeidos ?>;
function actualizarBadgeMensajes() {
  fetch('api/get_mensajes_count.php', { credentials: 'same-origin' })
    .then(function(r) { return r.json(); })
    .then(function(d) {
      var count = d.count || 0;
      var ids = ['topbarMsgBadge', 'navMsgBadge', 'bnMsgBadge'];
      ids.forEach(function(id) {
        var el = document.getElementById(id);
        if (count > 0) {
          if (!el) {
            /* crear badge si no existe */
            el = document.createElement('span');
            el.id = id;
            if (id === 'topbarMsgBadge') { el.className = 'msg-badge'; var av = document.getElementById('topbarAvatar'); if(av) av.appendChild(el); }
            else if (id === 'navMsgBadge') { el.className = 'nav-badge'; var nm = document.getElementById('navMensajes'); if(nm) nm.appendChild(el); }
          }
          if (el) el.textContent = Math.min(count, 99);
        } else {
          if (el) el.style.display = 'none';
        }
      });
      if (count > _prevMsgCount && _prevMsgCount >= 0) {
        showToast('📩 Tienes ' + count + ' mensaje(s) sin leer', 'info');
      }
      _prevMsgCount = count;
    })
    .catch(function() {});
}
setTimeout(function() { setInterval(actualizarBadgeMensajes, 60000); }, 5000);

/* ── Cerrar sidebar en resize desktop ── */
window.addEventListener('resize', function() {
  if (window.innerWidth >= 768) closeSidebar();
});
</script>