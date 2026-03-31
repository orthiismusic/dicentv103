<?php
/* ============================================================
   cobrador/imprimir.php — Recibo Térmico 58mm
   Compatible con impresoras Bluetooth Android/iOS/Windows
   ============================================================ */

ob_start();
if (!defined('DB_HOST')) {
    require_once __DIR__ . '/../config.php';
}
ob_clean();

require_once __DIR__ . '/config_cobrador.php';
verificarSesionCobrador();

$facturaId  = (int)($_GET['factura_id'] ?? 0);
$cobradorId = (int)$_SESSION['cobrador_portal_id'];

if (!$facturaId) {
    die('<p style="font-family:sans-serif;color:red;padding:20px;">
         Error: Debes indicar el ID de la factura en la URL.</p>');
}

// ── Verificar acceso ──
if (!verificarAccesoFactura($facturaId, $cobradorId)) {
    die('<p style="font-family:sans-serif;color:red;padding:20px;">
         Acceso denegado: Esta factura no pertenece a ninguno de tus clientes asignados.</p>');
}

// ── Datos de la factura ──
try {
    $stmt = $conn->prepare("
        SELECT
            f.id,
            f.numero_factura,
            f.mes_factura,
            f.cuota,
            f.monto,
            f.fecha_emision,
            f.fecha_vencimiento,
            f.estado,
            f.notas,
            c.numero_contrato,
            c.dia_cobro,
            c.monto_mensual,
            cl.nombre,
            cl.apellidos,
            cl.cedula,
            cl.direccion,
            cl.telefono1,
            cl.telefono2,
            p.nombre          AS plan_nombre,
            co.nombre_completo AS cobrador_nombre,
            co.codigo          AS cobrador_codigo,
            cfg.nombre_empresa,
            cfg.rif            AS empresa_rif,
            cfg.direccion      AS empresa_dir,
            cfg.telefono       AS empresa_tel,
            cfg.email          AS empresa_email,
            COALESCE(
                (SELECT SUM(pg.monto)
                 FROM pagos pg
                 WHERE pg.factura_id = f.id
                   AND pg.estado     = 'procesado'), 0
            ) AS total_abonado
        FROM facturas f
        JOIN contratos            c   ON f.contrato_id  = c.id
        JOIN clientes             cl  ON c.cliente_id   = cl.id
        JOIN planes               p   ON c.plan_id      = p.id
        JOIN cobradores           co  ON co.id          = cl.cobrador_id
        CROSS JOIN configuracion_sistema cfg
        WHERE f.id = ?
        LIMIT 1
    ");
    $stmt->execute([$facturaId]);
    $f = $stmt->fetch(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log('imprimir.php: ' . $e->getMessage());
    die('<p style="font-family:sans-serif;color:red;padding:20px;">
         Error al cargar la factura. Intenta de nuevo.</p>');
}

if (!$f) {
    die('<p style="font-family:sans-serif;color:red;padding:20px;">
         Factura no encontrada en la base de datos.</p>');
}

// ── Cálculos ──
$montoPendiente = max(0, (float)$f['monto'] - (float)$f['total_abonado']);

// ── Historial de abonos ──
$abonos = [];
try {
    $stmtAb = $conn->prepare("
        SELECT monto, fecha_pago, metodo_pago
        FROM pagos
        WHERE factura_id = ? AND estado = 'procesado'
        ORDER BY fecha_pago ASC
    ");
    $stmtAb->execute([$facturaId]);
    $abonos = $stmtAb->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log('imprimir.php abonos: ' . $e->getMessage());
}

$fechaImpresion = date('d/m/Y h:i A');
?>
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Recibo <?= htmlspecialchars($f['numero_factura']) ?></title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
  <style>

    /* ═══════════════════════════════════════
       ESTILOS DE PANTALLA (previsualización)
    ═══════════════════════════════════════ */
    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: 'Inter', -apple-system, sans-serif;
      background: #f1f5f9;
      min-height: 100vh;
    }

    /* Barra superior de controles */
    .controles {
      background: #1e2d4a;
      padding: 12px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 10px;
      position: sticky;
      top: 0;
      z-index: 100;
    }

    .controles-titulo {
      color: #fff;
      font-size: 14px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .controles-titulo i { color: #60a5fa; }

    .controles-btns {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }

    .btn-ctrl {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 8px 16px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      border: none;
      text-decoration: none;
      transition: all .15s;
    }

    .btn-imprimir {
      background: #2563EB;
      color: #fff;
      font-size: 14px;
      padding: 10px 22px;
    }

    .btn-imprimir:hover { background: #1d4ed8; }

    .btn-volver {
      background: rgba(255,255,255,.12);
      color: #fff;
      border: 1px solid rgba(255,255,255,.2);
    }

    .btn-volver:hover { background: rgba(255,255,255,.2); }

    /* Instrucciones Bluetooth */
    .instrucciones {
      background: #eff6ff;
      border: 1px solid #bfdbfe;
      border-radius: 10px;
      padding: 14px 18px;
      margin: 20px auto;
      max-width: 400px;
      font-size: 12px;
      color: #1e40af;
      line-height: 1.7;
    }

    .instrucciones strong {
      display: block;
      font-size: 13px;
      margin-bottom: 6px;
      color: #1e3a8a;
    }

    .instrucciones ol {
      padding-left: 18px;
    }

    /* Contenedor centrado */
    .pagina-wrapper {
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 20px 16px 40px;
    }

    /* Etiqueta "Vista previa" */
    .label-preview {
      font-size: 11px;
      color: #94a3b8;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 12px;
      font-weight: 600;
    }

    /* ═══════════════════════════════════════
       RECIBO TÉRMICO 58mm
    ═══════════════════════════════════════ */
    .recibo {
      width: 58mm;
      background: #fff;
      padding: 4mm 4mm 6mm;
      border: 1px dashed #d1d5db;
      box-shadow: 0 4px 20px rgba(0,0,0,.12);
      font-family: 'Courier New', Courier, monospace;
      font-size: 8.5pt;
      color: #000;
      line-height: 1.45;
    }

    /* Utilitarios del recibo */
    .r-c  { text-align: center; }
    .r-r  { text-align: right; }
    .r-b  { font-weight: 700; }
    .r-lg { font-size: 10.5pt; font-weight: 700; }
    .r-sm { font-size: 7.5pt; }
    .r-xs { font-size: 7pt; }

    .r-sep {
      border-top: 1px dashed #000;
      margin: 2.5mm 0;
    }

    .r-sep2 {
      border-top: 2px solid #000;
      margin: 2.5mm 0;
    }

    .r-row {
      display: flex;
      justify-content: space-between;
      gap: 4px;
    }

    .r-row span:first-child { flex-shrink: 0; }
    .r-row span:last-child  { text-align: right; }

    /* ═══════════════════════════════════════
       ESTILOS DE IMPRESIÓN
    ═══════════════════════════════════════ */
    @media print {
      @page {
        size: 58mm auto;
        margin: 0;
      }

      body {
        background: #fff;
        margin: 0;
        padding: 0;
      }

      /* Ocultar todo excepto el recibo */
      .controles,
      .instrucciones,
      .pagina-wrapper > .label-preview,
      .no-print {
        display: none !important;
      }

      .pagina-wrapper {
        padding: 0;
        align-items: flex-start;
      }

      .recibo {
        width: 100%;
        border: none;
        box-shadow: none;
        padding: 2mm 3mm 8mm;
        font-size: 8pt;
        line-height: 1.4;
      }
    }

  </style>
</head>
<body>

<!-- ═══════════════════════════════════════
     BARRA DE CONTROLES (solo pantalla)
═══════════════════════════════════════ -->
<div class="controles no-print">
  <div class="controles-titulo">
    <i class="fas fa-receipt"></i>
    Recibo: <?= htmlspecialchars($f['numero_factura']) ?>
    &nbsp;·&nbsp;
    <?= htmlspecialchars($f['nombre'] . ' ' . $f['apellidos']) ?>
  </div>
  <div class="controles-btns">
    <a href="javascript:history.back()" class="btn-ctrl btn-volver">
      <i class="fas fa-arrow-left"></i> Volver
    </a>
    <a href="facturas.php" class="btn-ctrl btn-volver">
      <i class="fas fa-list"></i> Facturas
    </a>
    <button class="btn-ctrl btn-imprimir" onclick="window.print()">
      <i class="fas fa-print"></i> Imprimir Recibo
    </button>
  </div>
</div>

<!-- ═══════════════════════════════════════
     INSTRUCCIONES BLUETOOTH (solo pantalla)
═══════════════════════════════════════ -->
<div class="pagina-wrapper">
  <div class="instrucciones no-print">
    <strong>
      <i class="fas fa-bluetooth" style="color:#2563EB;margin-right:4px;"></i>
      Cómo imprimir en impresora térmica Bluetooth (58mm):
    </strong>
    <ol>
      <li>Enciende la impresora térmica de 2 pulgadas (58mm).</li>
      <li>Activa el Bluetooth del celular y vincúlala (si no lo has hecho).</li>
      <li>En <strong>Android (Chrome)</strong>: toca Imprimir → selecciona tu impresora.</li>
      <li>En <strong>iOS</strong>: usa AirPrint o una app de impresión Bluetooth.</li>
      <li>En <strong>Windows</strong>: selecciona la impresora BT como destino.</li>
      <li>Toca el botón azul <strong>Imprimir Recibo</strong> de arriba.</li>
    </ol>
  </div>

  <!-- Etiqueta vista previa -->
  <div class="label-preview no-print">
    Vista previa del recibo (tamaño real 58mm)
  </div>

  <!-- ═══════════════════════════════════════
       RECIBO TÉRMICO
  ═══════════════════════════════════════ -->
  <div class="recibo">

    <!-- Encabezado empresa -->
    <div class="r-c r-lg">
      <?= htmlspecialchars(mb_strtoupper($f['nombre_empresa'])) ?>
    </div>
    <?php if ($f['empresa_rif']): ?>
    <div class="r-c r-sm">
      RNC/RIF: <?= htmlspecialchars($f['empresa_rif']) ?>
    </div>
    <?php endif; ?>
    <?php if ($f['empresa_dir']): ?>
    <div class="r-c r-sm">
      <?= htmlspecialchars(mb_substr($f['empresa_dir'], 0, 42)) ?>
    </div>
    <?php endif; ?>
    <?php if ($f['empresa_tel']): ?>
    <div class="r-c r-sm">
      Tel: <?= htmlspecialchars($f['empresa_tel']) ?>
    </div>
    <?php endif; ?>

    <div class="r-sep2"></div>

    <!-- Título -->
    <div class="r-c r-b" style="font-size:10pt;letter-spacing:2px;">
      R E C I B O
    </div>
    <div class="r-c r-xs">Documento no fiscal</div>

    <div class="r-sep"></div>

    <!-- Número y fecha -->
    <div class="r-row r-sm">
      <span>No. Factura:</span>
      <span class="r-b"><?= htmlspecialchars($f['numero_factura']) ?></span>
    </div>
    <div class="r-row r-sm">
      <span>Contrato:</span>
      <span class="r-b"><?= htmlspecialchars($f['numero_contrato']) ?></span>
    </div>
    <div class="r-row r-sm">
      <span>Fecha impresión:</span>
      <span><?= date('d/m/Y') ?></span>
    </div>
    <div class="r-row r-sm">
      <span>Hora:</span>
      <span><?= date('h:i A') ?></span>
    </div>

    <div class="r-sep"></div>

    <!-- Datos del titular -->
    <div class="r-sm r-b">TITULAR:</div>
    <div class="r-sm">
      <?= htmlspecialchars(mb_strtoupper($f['nombre'] . ' ' . $f['apellidos'])) ?>
    </div>
    <?php if ($f['direccion']): ?>
    <div class="r-sm" style="word-break:break-word;">
      <?= htmlspecialchars(mb_substr($f['direccion'], 0, 50)) ?>
    </div>
    <?php endif; ?>
    <?php if ($f['telefono1']): ?>
    <div class="r-sm">
      Tel: <?= htmlspecialchars($f['telefono1']) ?>
    </div>
    <?php endif; ?>

    <div class="r-sep"></div>

    <!-- Detalle del seguro -->
    <div class="r-sm r-b">DETALLE:</div>
    <div class="r-row r-sm">
      <span>Plan:</span>
      <span><?= htmlspecialchars(mb_substr($f['plan_nombre'], 0, 20)) ?></span>
    </div>
    <div class="r-row r-sm">
      <span>Mes:</span>
      <span><?= htmlspecialchars($f['mes_factura']) ?></span>
    </div>
    <?php if ($f['cuota']): ?>
    <div class="r-row r-sm">
      <span>Cuota:</span>
      <span>N° <?= (int)$f['cuota'] ?></span>
    </div>
    <?php endif; ?>
    <div class="r-row r-sm">
      <span>Día de cobro:</span>
      <span><?= (int)$f['dia_cobro'] ?></span>
    </div>
    <div class="r-row r-sm">
      <span>Vencimiento:</span>
      <span><?= date('d/m/Y', strtotime($f['fecha_vencimiento'])) ?></span>
    </div>

    <div class="r-sep"></div>

    <!-- Montos -->
    <div class="r-row r-sm">
      <span>Monto factura:</span>
      <span>RD$<?= number_format((float)$f['monto'], 2) ?></span>
    </div>

    <?php if (!empty($abonos)): ?>
    <div class="r-sm" style="margin-top:1mm;">Abonos anteriores:</div>
    <?php foreach ($abonos as $ab): ?>
    <div class="r-row r-sm">
      <span><?= date('d/m/Y', strtotime($ab['fecha_pago'])) ?></span>
      <span>-RD$<?= number_format((float)$ab['monto'], 2) ?></span>
    </div>
    <?php endforeach; ?>
    <?php endif; ?>

    <div class="r-sep"></div>

    <!-- Monto pendiente (el dato más importante) -->
    <div class="r-row r-b" style="font-size:10.5pt;">
      <span>PENDIENTE:</span>
      <span>RD$<?= number_format($montoPendiente, 2) ?></span>
    </div>

    <div class="r-sep2"></div>

    <!-- Cobrador -->
    <div class="r-row r-sm">
      <span>Cobrador:</span>
      <span><?= htmlspecialchars(mb_substr($f['cobrador_nombre'], 0, 22)) ?></span>
    </div>
    <div class="r-row r-sm">
      <span>Código:</span>
      <span><?= htmlspecialchars($f['cobrador_codigo']) ?></span>
    </div>

    <div class="r-sep"></div>

    <!-- Pie del recibo -->
    <div class="r-c r-sm" style="margin-top:1mm;">
      Gracias por su pago puntual.
    </div>
    <div class="r-c r-sm">
      <?= htmlspecialchars($f['nombre_empresa']) ?>
    </div>
    <?php if ($f['empresa_tel']): ?>
    <div class="r-c r-sm">
      <?= htmlspecialchars($f['empresa_tel']) ?>
    </div>
    <?php endif; ?>
    <div class="r-c r-xs" style="margin-top:1.5mm;color:#555;">
      Impreso: <?= $fechaImpresion ?>
    </div>

    <!-- Espacio final para avance de papel -->
    <div style="height:8mm;"></div>

  </div><!-- /.recibo -->

</div><!-- /.pagina-wrapper -->

</body>
</html>