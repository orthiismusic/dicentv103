<?php
/* ============================================================
   cobrador/dashboard.php — VERSIÓN CORREGIDA
   ============================================================ */
$paginaActualTitulo = 'Dashboard';
require_once __DIR__ . '/header_cobrador.php';

$cobradorId = (int)$_SESSION['cobrador_portal_id'];
$nombre     = $_SESSION['cobrador_portal_nombre'] ?? 'Cobrador';

// ── KPIs ──
$totalClientes = 0;
$totalPend     = 0;
$montoPend     = 0.0;
$totalVencidas = 0;
$msgNoLeidosDash = 0;

try {
    $s = $conn->prepare("SELECT COUNT(*) FROM clientes WHERE cobrador_id = ? AND estado = 'activo'");
    $s->execute([$cobradorId]);
    $totalClientes = (int)$s->fetchColumn();
} catch (PDOException $e) { error_log('dash kpi1: '.$e->getMessage()); }

try {
    $s = $conn->prepare("
        SELECT COUNT(*) AS total, COALESCE(SUM(f.monto),0) AS monto
        FROM asignaciones_facturas af
        JOIN facturas f ON af.factura_id = f.id
        WHERE af.cobrador_id = ? AND af.estado = 'activa'
          AND f.estado IN ('pendiente','vencida','incompleta')
    ");
    $s->execute([$cobradorId]);
    $row = $s->fetch(PDO::FETCH_ASSOC);
    $totalPend = (int)($row['total'] ?? 0);
    $montoPend = (float)($row['monto'] ?? 0);
} catch (PDOException $e) { error_log('dash kpi2: '.$e->getMessage()); }

try {
    $s = $conn->prepare("
        SELECT COUNT(*) FROM asignaciones_facturas af
        JOIN facturas f ON af.factura_id = f.id
        WHERE af.cobrador_id = ? AND af.estado = 'activa' AND f.estado = 'vencida'
    ");
    $s->execute([$cobradorId]);
    $totalVencidas = (int)$s->fetchColumn();
} catch (PDOException $e) { error_log('dash kpi3: '.$e->getMessage()); }

try {
    $s = $conn->prepare("SELECT COUNT(*) FROM cobrador_mensajes WHERE cobrador_id = ? AND leido = 0");
    $s->execute([$cobradorId]);
    $msgNoLeidosDash = (int)$s->fetchColumn();
} catch (PDOException $e) { $msgNoLeidosDash = 0; }

// ── Cobros próximos ──
$cobrosHoy = [];
try {
    $diaHoy = (int)date('j');
    $s = $conn->prepare("
        SELECT cl.nombre, cl.apellidos, cl.telefono1, cl.direccion,
               c.numero_contrato, c.dia_cobro,
               f.id AS factura_id, f.numero_factura, f.monto, f.estado AS factura_estado
        FROM clientes cl
        JOIN contratos c  ON c.cliente_id  = cl.id AND c.estado = 'activo'
        JOIN facturas  f  ON f.contrato_id = c.id  AND f.estado IN ('pendiente','vencida','incompleta')
        JOIN asignaciones_facturas af ON af.factura_id = f.id AND af.cobrador_id = ? AND af.estado = 'activa'
        WHERE cl.cobrador_id = ?
          AND c.dia_cobro BETWEEN ? AND ?
        ORDER BY c.dia_cobro ASC, cl.nombre ASC
        LIMIT 6
    ");
    $s->execute([$cobradorId, $cobradorId, $diaHoy, $diaHoy + 3]);
    $cobrosHoy = $s->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) { error_log('dash cobros: '.$e->getMessage()); }

// ── Facturas urgentes ──
$urgentes = [];
try {
    $s = $conn->prepare("
        SELECT cl.nombre, cl.apellidos, cl.telefono1,
               c.numero_contrato,
               f.numero_factura, f.monto, f.fecha_vencimiento,
               DATEDIFF(NOW(), f.fecha_vencimiento) AS dias_atraso
        FROM asignaciones_facturas af
        JOIN facturas f  ON af.factura_id = f.id  AND f.estado = 'vencida'
        JOIN contratos c ON f.contrato_id = c.id
        JOIN clientes cl ON c.cliente_id  = cl.id
        WHERE af.cobrador_id = ? AND af.estado = 'activa'
        ORDER BY dias_atraso DESC
        LIMIT 4
    ");
    $s->execute([$cobradorId]);
    $urgentes = $s->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) { error_log('dash urgentes: '.$e->getMessage()); }

// Saludo según hora
$hora   = (int)date('H');
$saludo = $hora < 12 ? 'Buenos días' : ($hora < 19 ? 'Buenas tardes' : 'Buenas noches');
$meses  = [1=>'enero',2=>'febrero',3=>'marzo',4=>'abril',5=>'mayo',6=>'junio',
           7=>'julio',8=>'agosto',9=>'septiembre',10=>'octubre',11=>'noviembre',12=>'diciembre'];
$fechaHoy = date('j') . ' de ' . $meses[(int)date('n')] . ' de ' . date('Y');
$primerNombre = explode(' ', trim($nombre))[0];
?>

<div class="app-content">

  <!-- Saludo -->
  <div class="page-header">
    <div class="page-title"><?= $saludo ?>, <?= htmlspecialchars($primerNombre) ?> 👋</div>
    <div class="page-subtitle">
      <i class="fas fa-calendar-day" style="color:var(--accent);font-size:11px;margin-right:4px;"></i>
      <?= $fechaHoy ?>
    </div>
  </div>

  <!-- Alerta mensajes no leídos -->
  <?php if ($msgNoLeidosDash > 0): ?>
  <div class="alert alert-info">
    <i class="fas fa-envelope"></i>
    <span>
      Tienes <strong><?= $msgNoLeidosDash ?></strong>
      mensaje<?= $msgNoLeidosDash > 1 ? 's' : '' ?> sin leer de la oficina.
    </span>
    <a href="mensajes.php" class="btn btn-sm"
       style="margin-left:auto;background:var(--accent);color:#fff;min-height:28px;">
      <i class="fas fa-envelope-open"></i> Ver
    </a>
  </div>
  <?php endif; ?>

  <!-- KPI Cards -->
  <div class="kpi-grid">

    <a href="clientes.php" class="kpi-card blue">
      <div class="kpi-icon"><i class="fas fa-users"></i></div>
      <div>
        <div class="kpi-value"><?= number_format($totalClientes) ?></div>
        <div class="kpi-label">Mis Clientes</div>
      </div>
    </a>

    <a href="facturas.php" class="kpi-card orange">
      <div class="kpi-icon" style="background:var(--orange-light);color:var(--orange);">
        <i class="fas fa-file-invoice-dollar"></i>
      </div>
      <div>
        <div class="kpi-value"><?= number_format($totalPend) ?></div>
        <div class="kpi-label">Por Cobrar</div>
      </div>
    </a>

    <a href="facturas.php" class="kpi-card green">
      <div class="kpi-icon"><i class="fas fa-money-bill-wave"></i></div>
      <div>
        <div class="kpi-value" style="font-size:15px;line-height:1.2;">
          RD$<?= number_format($montoPend, 0) ?>
        </div>
        <div class="kpi-label">Monto Pendiente</div>
      </div>
    </a>

    <a href="facturas.php?estado=vencida" class="kpi-card red">
      <div class="kpi-icon"><i class="fas fa-triangle-exclamation"></i></div>
      <div>
        <div class="kpi-value" style="<?= $totalVencidas > 0 ? 'color:var(--danger)' : '' ?>">
          <?= number_format($totalVencidas) ?>
        </div>
        <div class="kpi-label">Vencidas</div>
      </div>
    </a>

  </div>

  <!-- Accesos rápidos -->
  <div class="section-title"><i class="fas fa-bolt"></i> Accesos Rápidos</div>
  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:20px;">
    <a href="clientes.php" class="btn btn-secondary"
       style="flex-direction:column;gap:5px;height:68px;font-size:12px;">
      <i class="fas fa-users" style="font-size:20px;color:var(--accent);"></i>Clientes
    </a>
    <a href="facturas.php" class="btn btn-secondary"
       style="flex-direction:column;gap:5px;height:68px;font-size:12px;">
      <i class="fas fa-file-invoice" style="font-size:20px;color:var(--orange);"></i>Facturas
    </a>
    <a href="facturas.php?vista=ruta" class="btn btn-secondary"
       style="flex-direction:column;gap:5px;height:68px;font-size:12px;">
      <i class="fas fa-route" style="font-size:20px;color:var(--success);"></i>Mi Ruta
    </a>
  </div>

  <!-- Cobros próximos -->
  <?php if (!empty($cobrosHoy)): ?>
  <div class="section-title">
    <i class="fas fa-calendar-check"></i> Cobros de Hoy / Próximos
  </div>
  <div class="card" style="margin-bottom:16px;">
    <div class="card-header">
      <div class="card-title">
        <i class="fas fa-clock"></i>
        Clientes con día de cobro próximo
      </div>
    </div>
    <?php foreach ($cobrosHoy as $c): ?>
    <div style="padding:12px 16px;border-bottom:1px solid var(--border);
                display:flex;align-items:center;gap:12px;">
      <div style="width:36px;height:36px;border-radius:50%;background:var(--warning-light);
                  color:var(--warning-text);display:flex;align-items:center;justify-content:center;
                  font-size:12px;font-weight:700;flex-shrink:0;">
        <?= strtoupper(substr($c['nombre'],0,1) . substr($c['apellidos'],0,1)) ?>
      </div>
      <div style="flex:1;min-width:0;">
        <div style="font-size:13px;font-weight:700;color:var(--gray-800);
                    white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
          <?= htmlspecialchars($c['nombre'] . ' ' . $c['apellidos']) ?>
        </div>
        <div style="font-size:11px;color:var(--text-muted);">
          <?= htmlspecialchars($c['numero_contrato']) ?>
          &bull; Día <?= (int)$c['dia_cobro'] ?>
          &bull; <strong>RD$<?= number_format((float)$c['monto'], 2) ?></strong>
        </div>
      </div>
      <a href="facturas.php?factura_id=<?= (int)$c['factura_id'] ?>"
         class="btn btn-sm btn-primary">
        <i class="fas fa-file-invoice"></i>
      </a>
    </div>
    <?php endforeach; ?>
  </div>
  <?php endif; ?>

  <!-- Facturas urgentes vencidas -->
  <?php if (!empty($urgentes)): ?>
  <div class="section-title">
    <i class="fas fa-fire" style="color:var(--danger);"></i>
    Facturas Vencidas — Urgentes
  </div>
  <div class="card" style="margin-bottom:16px;">
    <?php foreach ($urgentes as $u): ?>
    <div style="padding:12px 14px;border-bottom:1px solid var(--border);
                display:flex;align-items:center;gap:10px;">
      <div style="flex:1;min-width:0;">
        <div style="font-size:13px;font-weight:700;color:var(--gray-800);">
          <?= htmlspecialchars($u['nombre'] . ' ' . $u['apellidos']) ?>
        </div>
        <div style="font-size:11px;color:var(--text-muted);">
          <?= htmlspecialchars($u['numero_factura']) ?>
          &bull; Vencida hace
          <strong style="color:var(--danger);"><?= (int)$u['dias_atraso'] ?> día(s)</strong>
        </div>
      </div>
      <div style="text-align:right;flex-shrink:0;">
        <div style="font-size:14px;font-weight:700;color:var(--danger);">
          RD$<?= number_format((float)$u['monto'], 2) ?>
        </div>
        <?php if (!empty($u['telefono1'])): ?>
        <a href="tel:<?= preg_replace('/[^0-9+]/', '', $u['telefono1']) ?>"
           style="font-size:11px;color:var(--accent);text-decoration:none;">
          <i class="fas fa-phone"></i> Llamar
        </a>
        <?php endif; ?>
      </div>
    </div>
    <?php endforeach; ?>
    <div style="padding:10px 14px;">
      <a href="facturas.php?estado=vencida" class="btn btn-danger btn-sm btn-full">
        <i class="fas fa-list"></i> Ver todas las vencidas
      </a>
    </div>
  </div>
  <?php endif; ?>

  <!-- Estado vacío si no hay nada -->
  <?php if ($totalClientes === 0 && $totalPend === 0): ?>
  <div class="empty-state">
    <i class="fas fa-check-circle" style="color:var(--success);opacity:1;"></i>
    <h3>Todo al día</h3>
    <p>No tienes clientes o facturas asignadas en este momento.<br>
       Contacta a la oficina si crees que hay un error.</p>
  </div>
  <?php endif; ?>

</div><!-- /.app-content -->

</body>
</html>