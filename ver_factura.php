<?php
/* ============================================================
   ver_factura.php — Detalle de Factura
   Sistema ORTHIIS — Seguros de Vida
   ============================================================ */
require_once 'header.php';

if (!isset($_GET['id'])) {
    header('Location: facturacion.php');
    exit();
}
$id = (int)$_GET['id'];

/* ── Datos de la factura ──────────────────────────────────── */
$stmt = $conn->prepare("
    SELECT f.*,
           c.numero_contrato,
           c.monto_mensual,
           c.dia_cobro,
           cl.codigo       AS cliente_codigo,
           cl.nombre       AS cliente_nombre,
           cl.apellidos    AS cliente_apellidos,
           cl.cedula       AS cliente_cedula,
           cl.telefono1    AS cliente_telefono1,
           cl.telefono2    AS cliente_telefono2,
           cl.email        AS cliente_email,
           cl.direccion    AS cliente_direccion,
           p.nombre        AS plan_nombre,
           p.descripcion   AS plan_descripcion,
           co.nombre_completo AS cobrador_nombre,
           v.nombre_completo  AS vendedor_nombre,
           (SELECT COALESCE(SUM(pg.monto),0)
            FROM pagos pg WHERE pg.factura_id=f.id
              AND pg.estado='procesado') AS total_abonado,
           (SELECT COUNT(*) FROM asignaciones_facturas af
            WHERE af.factura_id=f.id AND af.estado='activa') AS esta_asignada
    FROM facturas f
    JOIN contratos  c  ON f.contrato_id = c.id
    JOIN clientes   cl ON c.cliente_id  = cl.id
    JOIN planes     p  ON c.plan_id     = p.id
    LEFT JOIN cobradores co ON co.id    = cl.cobrador_id
    LEFT JOIN vendedores  v  ON v.id    = cl.vendedor_id
    WHERE f.id = ?
");
$stmt->execute([$id]);
$factura = $stmt->fetch();

if (!$factura) {
    header('Location: facturacion.php');
    exit();
}

/* ── Historial de pagos ───────────────────────────────────── */
$stmt = $conn->prepare("
    SELECT p.*, co.nombre_completo AS cobrador_nombre
    FROM pagos p
    LEFT JOIN cobradores co ON p.cobrador_id = co.id
    WHERE p.factura_id = ?
    ORDER BY p.fecha_pago DESC
");
$stmt->execute([$id]);
$pagos = $stmt->fetchAll();

/* ── Cálculos ────────────────────────────────────────────── */
$montoPendiente  = max(0, (float)$factura['monto'] - (float)$factura['total_abonado']);
$porcentajePagado= $factura['monto']>0
    ? min(100, round(((float)$factura['total_abonado']/(float)$factura['monto'])*100))
    : 0;
$estaVencida     = strtotime($factura['fecha_vencimiento']) < time()
                   && $factura['estado'] !== 'pagada';
$puedePagar      = in_array($factura['estado'], ['pendiente','vencida','incompleta'])
                   && $montoPendiente > 0;

/* ── Config de estado ───────────────────────────────────────*/
$estadoConfig = [
    'pendiente'  => ['cls'=>'badge-pendiente',  'icon'=>'fa-clock',           'label'=>'Pendiente',  'color'=>'#92400E','bg'=>'#FEF3C7'],
    'pagada'     => ['cls'=>'badge-pagada',      'icon'=>'fa-check-circle',    'label'=>'Pagada',     'color'=>'#166534','bg'=>'#DCFCE7'],
    'incompleta' => ['cls'=>'badge-incompleta',  'icon'=>'fa-circle-half-stroke','label'=>'Incompleta','color'=>'#1E40AF','bg'=>'#DBEAFE'],
    'vencida'    => ['cls'=>'badge-vencida',     'icon'=>'fa-exclamation-circle','label'=>'Vencida',  'color'=>'#991B1B','bg'=>'#FEE2E2'],
    'anulada'    => ['cls'=>'badge-anulada',     'icon'=>'fa-ban',             'label'=>'Anulada',    'color'=>'#475569','bg'=>'#F1F5F9'],
];
$sc = $estadoConfig[$factura['estado']] ?? $estadoConfig['pendiente'];

/* ── Config sistema ─────────────────────────────────────── */
$stmtCfg = $conn->prepare("SELECT * FROM configuracion_sistema WHERE id=1");
$stmtCfg->execute();
$config = $stmtCfg->fetch();
?>
<!-- ============================================================
     ESTILOS ESPECÍFICOS
     ============================================================ -->
<style>
/* ── Page Header ── */
.page-header{display:flex;align-items:flex-start;justify-content:space-between;
    flex-wrap:wrap;gap:14px;margin-bottom:24px;}
.page-title{font-size:22px;font-weight:700;color:var(--gray-800);margin:0 0 4px;}
.page-subtitle{font-size:13px;color:var(--gray-500);margin:0;}
.page-actions{display:flex;gap:10px;flex-wrap:wrap;}

/* ── KPI row ── */
.kpi-vf-row{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px;}
@media(max-width:900px){.kpi-vf-row{grid-template-columns:repeat(2,1fr);}}
@media(max-width:500px){.kpi-vf-row{grid-template-columns:1fr;}}
.kpi-vf{border-radius:var(--radius);padding:20px 20px 16px;position:relative;
    overflow:hidden;box-shadow:var(--shadow);transition:var(--transition);color:white;}
.kpi-vf:hover{transform:translateY(-3px);box-shadow:var(--shadow-md);}
.kpi-vf::before{content:'';position:absolute;top:0;right:0;width:70px;height:70px;
    border-radius:0 var(--radius) 0 100%;opacity:.15;background:white;}
.kpi-vf.blue  {background:linear-gradient(135deg,#1565C0,#1976D2);}
.kpi-vf.green {background:linear-gradient(135deg,#1B5E20,#2E7D32);}
.kpi-vf.amber {background:linear-gradient(135deg,#E65100,#F57F17);}
.kpi-vf.purple{background:linear-gradient(135deg,#4A148C,#6A1B9A);}
.kpi-vf .kv-label{font-size:10.5px;font-weight:600;color:rgba(255,255,255,.80);
    text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px;}
.kpi-vf .kv-top{display:flex;align-items:flex-start;justify-content:space-between;}
.kpi-vf .kv-value{font-size:20px;font-weight:800;color:white;line-height:1.2;}
.kpi-vf .kv-sub{font-size:11px;color:rgba(255,255,255,.70);margin-top:3px;}
.kpi-vf .kv-icon{width:42px;height:42px;background:rgba(255,255,255,.18);
    border-radius:var(--radius-sm);display:flex;align-items:center;
    justify-content:center;font-size:18px;color:white;flex-shrink:0;}
.kpi-vf .kv-footer{margin-top:12px;padding-top:10px;
    border-top:1px solid rgba(255,255,255,.15);
    font-size:11px;color:rgba(255,255,255,.80);font-weight:600;
    display:flex;align-items:center;gap:5px;}

/* ── Progress bar ── */
.pbar-outer{height:6px;background:rgba(255,255,255,.25);border-radius:10px;overflow:hidden;margin-top:8px;}
.pbar-inner{height:100%;border-radius:10px;background:rgba(255,255,255,.9);transition:width .5s ease;}
.pbar-label{font-size:10px;color:rgba(255,255,255,.80);margin-top:4px;text-align:right;}

/* ── Grid ── */
.vf-grid{display:grid;grid-template-columns:1fr 340px;gap:20px;align-items:start;}
@media(max-width:950px){.vf-grid{grid-template-columns:1fr;}}

/* ── Cards ── */
.card{background:var(--white);border:1px solid var(--gray-200);
    border-radius:var(--radius);box-shadow:var(--shadow-sm);overflow:hidden;}
.card-header{padding:16px 20px;border-bottom:1px solid var(--gray-200);
    display:flex;align-items:center;justify-content:space-between;background:var(--white);}
.card-title{font-size:15px;font-weight:700;color:var(--gray-800);}
.card-subtitle{font-size:12px;color:var(--gray-500);margin-top:2px;}
.card-body{padding:20px;}

/* ── Info blocks ── */
.info-section-label{font-size:11px;font-weight:700;color:var(--gray-500);
    text-transform:uppercase;letter-spacing:.8px;margin-bottom:14px;
    display:flex;align-items:center;gap:7px;}
.info-section-label i{color:var(--accent);}
.info-2col{display:grid;grid-template-columns:1fr 1fr;gap:10px;}
@media(max-width:600px){.info-2col{grid-template-columns:1fr;}}
.iblock{background:var(--gray-50);border:1px solid var(--gray-200);
    border-radius:var(--radius-sm);padding:11px 14px;}
.iblock .ib-label{font-size:10.5px;color:var(--gray-500);font-weight:600;
    text-transform:uppercase;letter-spacing:.5px;margin-bottom:3px;}
.iblock .ib-value{font-size:14px;font-weight:600;color:var(--gray-800);}
.iblock.full{grid-column:1/-1;}
.iblock.accent-border{border-left:3px solid var(--accent);}

/* ── Estado badge ── */
.est-badge{display:inline-flex;align-items:center;gap:5px;
    padding:4px 12px;border-radius:20px;font-size:12px;font-weight:600;}
.badge-pendiente {background:#FEF3C7;color:#92400E;}
.badge-pagada    {background:#DCFCE7;color:#166534;}
.badge-incompleta{background:#DBEAFE;color:#1E40AF;}
.badge-vencida   {background:#FEE2E2;color:#991B1B;}
.badge-anulada   {background:#F1F5F9;color:#475569;}

/* ── Panel de estado (lateral) ── */
.estado-panel{border-radius:var(--radius);padding:20px;margin-bottom:16px;
    border:1px solid;text-align:center;}
.estado-panel .ep-icon{font-size:36px;margin-bottom:10px;}
.estado-panel .ep-label{font-size:11px;font-weight:600;text-transform:uppercase;
    letter-spacing:.8px;margin-bottom:4px;}
.estado-panel .ep-estado{font-size:20px;font-weight:800;margin-bottom:12px;}
.estado-panel .ep-monto{font-size:28px;font-weight:900;line-height:1;}
.estado-panel .ep-monto-label{font-size:11px;opacity:.80;margin-top:3px;}
.progress-ring{width:100%;margin-top:12px;}
.progress-bg{height:8px;border-radius:10px;overflow:hidden;
    background:rgba(0,0,0,.08);margin:8px 0 4px;}
.progress-fill{height:100%;border-radius:10px;transition:width .6s ease;}
.progress-pct{font-size:11px;text-align:right;font-weight:600;opacity:.85;}

/* ── Botones de acción lateral ── */
.btn{display:inline-flex;align-items:center;gap:7px;padding:10px 16px;
    border-radius:var(--radius-sm);border:none;font-size:13px;font-weight:600;
    font-family:var(--font);cursor:pointer;transition:var(--transition);
    text-decoration:none;white-space:nowrap;justify-content:center;}
.btn-primary  {background:var(--accent);color:white;}
.btn-primary:hover  {background:#1565C0;color:white;}
.btn-secondary{background:var(--gray-200);color:var(--gray-700);}
.btn-secondary:hover{background:var(--gray-300);}
.btn-success  {background:#DCFCE7;color:#166534;}
.btn-success:hover  {background:#166534;color:white;}
.btn-danger   {background:#FEE2E2;color:#DC2626;}
.btn-danger:hover   {background:#DC2626;color:white;}
.btn-warning  {background:#FEF3C7;color:#92400E;}
.btn-warning:hover  {background:#D97706;color:white;}
.btn-info     {background:#E0F2FE;color:#0369A1;}
.btn-info:hover     {background:#0284C7;color:white;}
.btn-block    {width:100%;display:flex;}
.btn-sm       {padding:6px 12px;font-size:12px;}

/* ── Tabla historial ── */
.data-table-vf{width:100%;border-collapse:collapse;font-size:13px;}
.data-table-vf thead th{background:var(--gray-50);padding:10px 12px;
    text-align:left;font-weight:600;color:var(--gray-600);font-size:11.5px;
    text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid var(--gray-200);}
.data-table-vf tbody td{padding:11px 12px;border-bottom:1px solid var(--gray-100);
    color:var(--gray-700);}
.data-table-vf tbody tr:last-child td{border-bottom:none;}
.data-table-vf tbody tr:hover{background:var(--gray-50);}
.tfoot-row td{padding:12px;font-weight:700;background:var(--gray-50);
    border-top:2px solid var(--gray-200);}
.amount-mono{font-family:monospace;font-weight:700;color:var(--gray-800);}

/* ── Tag de asignación ── */
.asig-tag{display:inline-flex;align-items:center;gap:5px;padding:4px 10px;
    border-radius:20px;font-size:11.5px;font-weight:600;}
.asig-si{background:#DCFCE7;color:#166534;}
.asig-no{background:#F1F5F9;color:#64748B;}

/* ── Fade-in ── */
.fade-in{animation:fadeIn .4s ease both;}
.delay-1{animation-delay:.10s;}
.delay-2{animation-delay:.20s;}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
</style>

<!-- ============================================================
     PAGE HEADER
     ============================================================ -->
<div class="page-header fade-in">
    <div>
        <div class="page-title">
            <i class="fas fa-file-invoice-dollar" style="color:var(--accent);margin-right:8px;"></i>
            Detalle de Factura
        </div>
        <div class="page-subtitle">
            N° <strong><?php echo htmlspecialchars($factura['numero_factura']); ?></strong>
            &mdash;
            <?php echo htmlspecialchars($factura['cliente_nombre'].' '.$factura['cliente_apellidos']); ?>
        </div>
    </div>
    <div class="page-actions">
        <?php if ($puedePagar): ?>
        <a href="registrar_pago.php?factura_id=<?php echo $id; ?>" class="btn btn-primary">
            <i class="fas fa-dollar-sign"></i> Registrar Pago
        </a>
        <?php endif; ?>
        <a href="imprimir_factura.php?id=<?php echo $id; ?>&tipo=preview"
           class="btn btn-info" target="_blank">
            <i class="fas fa-print"></i> Imprimir
        </a>
        <a href="facturacion.php" class="btn btn-secondary">
            <i class="fas fa-arrow-left"></i> Volver
        </a>
    </div>
</div>

<!-- ============================================================
     KPI CARDS
     ============================================================ -->
<div class="kpi-vf-row fade-in delay-1">

    <div class="kpi-vf blue">
        <div class="kv-label">Monto Facturado</div>
        <div class="kv-top">
            <div>
                <div class="kv-value">RD$<?php echo number_format($factura['monto'],2); ?></div>
                <div class="kv-sub">Período: <?php echo htmlspecialchars($factura['mes_factura']); ?></div>
            </div>
            <div class="kv-icon"><i class="fas fa-file-invoice-dollar"></i></div>
        </div>
        <div class="kv-footer">
            <i class="fas fa-hashtag"></i>
            Cuota N° <?php echo $factura['cuota']; ?>
        </div>
    </div>

    <div class="kpi-vf green">
        <div class="kv-label">Total Abonado</div>
        <div class="kv-top">
            <div>
                <div class="kv-value">RD$<?php echo number_format($factura['total_abonado'],2); ?></div>
                <div class="kv-sub"><?php echo $porcentajePagado; ?>% cobrado</div>
            </div>
            <div class="kv-icon"><i class="fas fa-check-circle"></i></div>
        </div>
        <div class="pbar-outer">
            <div class="pbar-inner" style="width:<?php echo $porcentajePagado; ?>%;"></div>
        </div>
        <div class="pbar-label"><?php echo count($pagos); ?> pago<?php echo count($pagos)!==1?'s':''; ?> registrado<?php echo count($pagos)!==1?'s':''; ?></div>
    </div>

    <div class="kpi-vf <?php echo $montoPendiente>0?'amber':'green'; ?>">
        <div class="kv-label">Saldo Pendiente</div>
        <div class="kv-top">
            <div>
                <div class="kv-value">RD$<?php echo number_format($montoPendiente,2); ?></div>
                <div class="kv-sub">
                    <?php echo $montoPendiente>0 ? 'Por cobrar' : 'Pagada completa'; ?>
                </div>
            </div>
            <div class="kv-icon">
                <i class="fas <?php echo $montoPendiente>0?'fa-hourglass-half':'fa-check-double'; ?>"></i>
            </div>
        </div>
        <div class="kv-footer">
            <i class="fas fa-calendar-xmark"></i>
            Vence: <?php echo date('d/m/Y', strtotime($factura['fecha_vencimiento'])); ?>
        </div>
    </div>

    <div class="kpi-vf purple">
        <div class="kv-label">Estado</div>
        <div class="kv-top">
            <div>
                <div class="kv-value"><?php echo $sc['label']; ?></div>
                <div class="kv-sub">
                    <?php echo $factura['esta_asignada']>0 ? '📋 Asignada a cobrador' : 'Sin asignar'; ?>
                </div>
            </div>
            <div class="kv-icon"><i class="fas <?php echo $sc['icon']; ?>"></i></div>
        </div>
        <div class="kv-footer">
            <i class="fas fa-user-tie"></i>
            <?php echo htmlspecialchars($factura['cobrador_nombre'] ?? 'Sin cobrador'); ?>
        </div>
    </div>

</div>

<!-- ============================================================
     GRID PRINCIPAL
     ============================================================ -->
<div class="vf-grid fade-in delay-2">

    <!-- ─ Columna izquierda ────────────────────────────────── -->
    <div style="display:flex;flex-direction:column;gap:20px;">

        <!-- Info General -->
        <div class="card">
            <div class="card-header">
                <div>
                    <div class="card-title">
                        <i class="fas fa-file-invoice" style="color:var(--accent);margin-right:6px;"></i>
                        Información de la Factura
                    </div>
                    <div class="card-subtitle">
                        Contrato N° <?php echo str_pad($factura['numero_contrato'],5,'0',STR_PAD_LEFT); ?>
                    </div>
                </div>
                <span class="est-badge <?php echo $sc['cls']; ?>">
                    <i class="fas <?php echo $sc['icon']; ?>"></i>
                    <?php echo $sc['label']; ?>
                </span>
            </div>
            <div class="card-body">

                <!-- Cliente -->
                <div class="info-section-label">
                    <i class="fas fa-user"></i> Datos del Cliente
                </div>
                <div class="info-2col" style="margin-bottom:20px;">
                    <div class="iblock full">
                        <div class="ib-label">Cliente</div>
                        <div class="ib-value" style="font-size:16px;">
                            <?php echo htmlspecialchars($factura['cliente_nombre'].' '.$factura['cliente_apellidos']); ?>
                        </div>
                    </div>
                    <?php if ($factura['cliente_cedula']): ?>
                    <div class="iblock">
                        <div class="ib-label">Cédula</div>
                        <div class="ib-value" style="font-family:monospace;">
                            <?php echo htmlspecialchars($factura['cliente_cedula']); ?>
                        </div>
                    </div>
                    <?php endif; ?>
                    <?php if ($factura['cliente_telefono1']): ?>
                    <div class="iblock">
                        <div class="ib-label">Teléfono</div>
                        <div class="ib-value">
                            <?php echo htmlspecialchars($factura['cliente_telefono1']); ?>
                            <?php if ($factura['cliente_telefono2']): ?>
                                <br><small><?php echo htmlspecialchars($factura['cliente_telefono2']); ?></small>
                            <?php endif; ?>
                        </div>
                    </div>
                    <?php endif; ?>
                    <?php if ($factura['cliente_email']): ?>
                    <div class="iblock">
                        <div class="ib-label">Email</div>
                        <div class="ib-value" style="font-size:12px;word-break:break-all;">
                            <?php echo htmlspecialchars($factura['cliente_email']); ?>
                        </div>
                    </div>
                    <?php endif; ?>
                    <?php if ($factura['cliente_direccion']): ?>
                    <div class="iblock full">
                        <div class="ib-label">Dirección</div>
                        <div class="ib-value" style="font-size:13px;">
                            <?php echo htmlspecialchars($factura['cliente_direccion']); ?>
                        </div>
                    </div>
                    <?php endif; ?>
                </div>

                <!-- Factura -->
                <div class="info-section-label">
                    <i class="fas fa-receipt"></i> Datos de la Factura
                </div>
                <div class="info-2col" style="margin-bottom:20px;">
                    <div class="iblock accent-border">
                        <div class="ib-label">N° Factura</div>
                        <div class="ib-value" style="font-family:monospace;font-size:18px;color:var(--accent);">
                            <?php echo htmlspecialchars($factura['numero_factura']); ?>
                        </div>
                    </div>
                    <div class="iblock">
                        <div class="ib-label">N° Contrato</div>
                        <div class="ib-value" style="font-family:monospace;">
                            <?php echo str_pad($factura['numero_contrato'],5,'0',STR_PAD_LEFT); ?>
                        </div>
                    </div>
                    <div class="iblock">
                        <div class="ib-label">Plan</div>
                        <div class="ib-value"><?php echo htmlspecialchars($factura['plan_nombre']); ?></div>
                    </div>
                    <div class="iblock">
                        <div class="ib-label">Período</div>
                        <div class="ib-value"><?php echo htmlspecialchars($factura['mes_factura']); ?></div>
                    </div>
                    <div class="iblock">
                        <div class="ib-label">Cuota N°</div>
                        <div class="ib-value"><?php echo $factura['cuota']; ?></div>
                    </div>
                    <div class="iblock">
                        <div class="ib-label">Día de Cobro</div>
                        <div class="ib-value"><?php echo $factura['dia_cobro']; ?></div>
                    </div>
                    <div class="iblock">
                        <div class="ib-label">Fecha Emisión</div>
                        <div class="ib-value">
                            <?php echo date('d/m/Y', strtotime($factura['fecha_emision'])); ?>
                        </div>
                    </div>
                    <div class="iblock" style="<?php echo $estaVencida?'border-color:#FCA5A5;':'' ?>">
                        <div class="ib-label">Fecha Vencimiento</div>
                        <div class="ib-value" style="<?php echo $estaVencida?'color:#DC2626;':'' ?>">
                            <?php echo date('d/m/Y', strtotime($factura['fecha_vencimiento'])); ?>
                            <?php if ($estaVencida): ?>
                                <span style="font-size:10px;background:#FEE2E2;color:#991B1B;
                                    padding:1px 6px;border-radius:10px;margin-left:5px;">VENCIDA</span>
                            <?php endif; ?>
                        </div>
                    </div>
                    <div class="iblock">
                        <div class="ib-label">Asignada</div>
                        <div class="ib-value">
                            <span class="asig-tag <?php echo $factura['esta_asignada']>0?'asig-si':'asig-no'; ?>">
                                <i class="fas <?php echo $factura['esta_asignada']>0?'fa-check':'fa-minus'; ?>"></i>
                                <?php echo $factura['esta_asignada']>0?'Sí':'No'; ?>
                            </span>
                        </div>
                    </div>
                    <div class="iblock">
                        <div class="ib-label">Cobrador</div>
                        <div class="ib-value" style="font-size:13px;">
                            <?php echo htmlspecialchars($factura['cobrador_nombre'] ?? '—'); ?>
                        </div>
                    </div>
                </div>

                <!-- Montos -->
                <div class="info-section-label">
                    <i class="fas fa-coins"></i> Resumen de Montos
                </div>
                <div class="info-2col">
                    <div class="iblock">
                        <div class="ib-label">Monto Factura</div>
                        <div class="ib-value" style="font-size:18px;">
                            RD$<?php echo number_format($factura['monto'],2); ?>
                        </div>
                    </div>
                    <div class="iblock">
                        <div class="ib-label">Total Abonado</div>
                        <div class="ib-value" style="font-size:18px;color:#166534;">
                            RD$<?php echo number_format($factura['total_abonado'],2); ?>
                        </div>
                    </div>
                    <div class="iblock full" style="border-left:4px solid <?php echo $montoPendiente>0?'#F97316':'#22C55E'; ?>;">
                        <div class="ib-label">Saldo Pendiente</div>
                        <div class="ib-value" style="font-size:24px;
                            color:<?php echo $montoPendiente>0?'#DC2626':'#166534'; ?>;">
                            RD$<?php echo number_format($montoPendiente,2); ?>
                        </div>
                        <!-- Barra visual -->
                        <div style="margin-top:10px;">
                            <div style="display:flex;justify-content:space-between;
                                font-size:11px;color:var(--gray-500);margin-bottom:5px;">
                                <span>Progreso de pago</span>
                                <span><?php echo $porcentajePagado; ?>%</span>
                            </div>
                            <div style="height:8px;background:var(--gray-200);border-radius:10px;overflow:hidden;">
                                <div style="height:100%;border-radius:10px;
                                    width:<?php echo $porcentajePagado; ?>%;
                                    background:<?php echo $porcentajePagado>=100?'#22C55E':'#3B82F6'; ?>;
                                    transition:width .6s ease;"></div>
                            </div>
                        </div>
                    </div>
                </div>

                <?php if ($factura['notas']): ?>
                <div style="margin-top:14px;padding:12px 16px;background:#FFF7ED;
                    border:1px solid #FED7AA;border-radius:var(--radius-sm);
                    font-size:13px;color:#92400E;">
                    <i class="fas fa-note-sticky" style="margin-right:6px;"></i>
                    <strong>Notas:</strong> <?php echo htmlspecialchars($factura['notas']); ?>
                </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Historial de pagos -->
        <?php if (!empty($pagos)): ?>
        <div class="card">
            <div class="card-header">
                <div>
                    <div class="card-title">
                        <i class="fas fa-history" style="color:var(--accent);margin-right:6px;"></i>
                        Historial de Pagos
                    </div>
                    <div class="card-subtitle">
                        <?php echo count($pagos); ?> pago<?php echo count($pagos)!==1?'s':''; ?> registrado<?php echo count($pagos)!==1?'s':''; ?>
                    </div>
                </div>
            </div>
            <div style="overflow-x:auto;">
                <table class="data-table-vf">
                    <thead>
                        <tr>
                            <th>Fecha</th>
                            <th>Monto</th>
                            <th>Tipo</th>
                            <th>Método</th>
                            <th>Referencia</th>
                            <th>Cobrador</th>
                            <th>Acción</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($pagos as $pago): ?>
                        <tr>
                            <td><?php echo date('d/m/Y H:i', strtotime($pago['fecha_pago'])); ?></td>
                            <td class="amount-mono">
                                RD$<?php echo number_format($pago['monto'],2); ?>
                            </td>
                            <td>
                                <span class="est-badge <?php echo $pago['tipo_pago']==='total'?'badge-pagada':'badge-incompleta'; ?>"
                                      style="padding:3px 9px;font-size:11px;">
                                    <i class="fas <?php echo $pago['tipo_pago']==='total'?'fa-check':'fa-minus'; ?>"></i>
                                    <?php echo ucfirst($pago['tipo_pago']); ?>
                                </span>
                            </td>
                            <td>
                                <span style="display:inline-flex;align-items:center;gap:5px;font-size:12px;">
                                    <i class="fas <?php
                                        $mp=$pago['metodo_pago'];
                                        echo $mp==='efectivo'?'fa-money-bill':($mp==='transferencia'?'fa-building-columns':($mp==='cheque'?'fa-money-check':'fa-credit-card'));
                                    ?>"></i>
                                    <?php echo ucfirst($pago['metodo_pago']); ?>
                                </span>
                            </td>
                            <td style="font-family:monospace;font-size:12px;">
                                <?php echo htmlspecialchars($pago['referencia_pago']??'—'); ?>
                            </td>
                            <td style="font-size:12px;">
                                <?php echo htmlspecialchars($pago['cobrador_nombre']??'—'); ?>
                            </td>
                            <td>
                                <a href="imprimir_comprobante.php?id=<?php echo $pago['id']; ?>"
                                   class="btn btn-info btn-sm" target="_blank" title="Comprobante">
                                    <i class="fas fa-receipt"></i>
                                </a>
                            </td>
                        </tr>
                        <?php if ($pago['notas']): ?>
                        <tr>
                            <td colspan="7" style="padding:4px 12px 8px;font-size:12px;
                                color:var(--gray-500);background:var(--gray-50);">
                                <i class="fas fa-note-sticky" style="margin-right:4px;"></i>
                                <?php echo htmlspecialchars($pago['notas']); ?>
                            </td>
                        </tr>
                        <?php endif; ?>
                        <?php endforeach; ?>
                    </tbody>
                    <tfoot>
                        <tr class="tfoot-row">
                            <td colspan="1" style="color:var(--gray-500);">Total</td>
                            <td class="amount-mono" style="color:#166534;">
                                RD$<?php echo number_format(array_sum(array_column($pagos,'monto')),2); ?>
                            </td>
                            <td colspan="5"></td>
                        </tr>
                    </tfoot>
                </table>
            </div>
        </div>
        <?php else: ?>
        <div class="card">
            <div class="card-body" style="text-align:center;padding:40px;color:var(--gray-400);">
                <i class="fas fa-receipt" style="font-size:36px;display:block;margin-bottom:10px;opacity:.4;"></i>
                <p style="font-size:14px;font-weight:600;color:var(--gray-500);">Sin pagos registrados</p>
                <p style="font-size:12px;">Aún no se han registrado pagos para esta factura.</p>
            </div>
        </div>
        <?php endif; ?>
    </div>

    <!-- ─ Columna derecha (panel de acciones) ──────────────── -->
    <div style="display:flex;flex-direction:column;gap:16px;">

        <!-- Panel de estado -->
        <div class="estado-panel"
             style="background:<?php echo $sc['bg']; ?>;
                    border-color:<?php echo $montoPendiente>0?'#FCA5A5':'#86EFAC'; ?>;
                    color:<?php echo $sc['color']; ?>;">
            <div class="ep-icon">
                <i class="fas <?php echo $sc['icon']; ?>"></i>
            </div>
            <div class="ep-label">Estado de la Factura</div>
            <div class="ep-estado"><?php echo $sc['label']; ?></div>
            <div class="ep-monto">
                RD$<?php echo number_format($montoPendiente,2); ?>
            </div>
            <div class="ep-monto-label">Saldo pendiente</div>
            <div class="progress-ring">
                <div class="progress-bg">
                    <div class="progress-fill"
                         style="width:<?php echo $porcentajePagado; ?>%;
                                background:<?php echo $sc['color']; ?>;opacity:.7;"></div>
                </div>
                <div class="progress-pct" style="color:<?php echo $sc['color']; ?>;">
                    <?php echo $porcentajePagado; ?>% cobrado
                </div>
            </div>
        </div>

        <!-- Acciones -->
        <div class="card">
            <div class="card-header">
                <div class="card-title">
                    <i class="fas fa-bolt" style="color:var(--accent);margin-right:6px;"></i>
                    Acciones
                </div>
            </div>
            <div class="card-body" style="display:flex;flex-direction:column;gap:10px;">
                <?php if ($puedePagar): ?>
                <a href="registrar_pago.php?factura_id=<?php echo $id; ?>"
                   class="btn btn-primary btn-block">
                    <i class="fas fa-dollar-sign"></i> Registrar Pago
                </a>
                <?php endif; ?>
                <a href="imprimir_factura.php?id=<?php echo $id; ?>&tipo=preview"
                   class="btn btn-info btn-block" target="_blank">
                    <i class="fas fa-print"></i> Imprimir Factura
                </a>
                <a href="imprimir_factura.php?id=<?php echo $id; ?>&tipo=direct"
                   class="btn btn-secondary btn-block" target="_blank">
                    <i class="fas fa-file-pdf"></i> Imprimir Directamente
                </a>
                <div style="height:1px;background:var(--gray-200);"></div>
                <a href="ver_contrato.php?id=<?php echo $factura['contrato_id']; ?>"
                   class="btn btn-secondary btn-block">
                    <i class="fas fa-file-contract"></i> Ver Contrato
                </a>
                <a href="facturacion.php?numero_contrato=<?php echo urlencode($factura['numero_contrato']); ?>"
                   class="btn btn-secondary btn-block">
                    <i class="fas fa-list"></i> Facturas del Contrato
                </a>
                <a href="facturacion.php" class="btn btn-secondary btn-block">
                    <i class="fas fa-arrow-left"></i> Volver a Facturación
                </a>
            </div>
        </div>

        <!-- Datos rápidos -->
        <div class="card">
            <div class="card-header">
                <div class="card-title">
                    <i class="fas fa-info-circle" style="color:var(--accent);margin-right:6px;"></i>
                    Datos Rápidos
                </div>
            </div>
            <div class="card-body" style="padding:14px 16px;">
                <div style="display:flex;flex-direction:column;gap:10px;">
                    <div style="display:flex;justify-content:space-between;
                        font-size:13px;padding-bottom:9px;border-bottom:1px solid var(--gray-100);">
                        <span style="color:var(--gray-500);font-weight:500;">Plan</span>
                        <span style="font-weight:600;color:var(--gray-800);">
                            <?php echo htmlspecialchars($factura['plan_nombre']); ?>
                        </span>
                    </div>
                    <div style="display:flex;justify-content:space-between;
                        font-size:13px;padding-bottom:9px;border-bottom:1px solid var(--gray-100);">
                        <span style="color:var(--gray-500);font-weight:500;">Vendedor</span>
                        <span style="font-weight:600;color:var(--gray-800);font-size:12px;">
                            <?php echo htmlspecialchars($factura['vendedor_nombre'] ?? '—'); ?>
                        </span>
                    </div>
                    <div style="display:flex;justify-content:space-between;
                        font-size:13px;padding-bottom:9px;border-bottom:1px solid var(--gray-100);">
                        <span style="color:var(--gray-500);font-weight:500;">Cobrador</span>
                        <span style="font-weight:600;color:var(--gray-800);font-size:12px;">
                            <?php echo htmlspecialchars($factura['cobrador_nombre'] ?? '—'); ?>
                        </span>
                    </div>
                    <div style="display:flex;justify-content:space-between;
                        font-size:13px;padding-bottom:9px;border-bottom:1px solid var(--gray-100);">
                        <span style="color:var(--gray-500);font-weight:500;">Pagos registrados</span>
                        <span style="font-weight:700;color:var(--gray-800);">
                            <?php echo count($pagos); ?>
                        </span>
                    </div>
                    <div style="display:flex;justify-content:space-between;font-size:13px;">
                        <span style="color:var(--gray-500);font-weight:500;">Asignada</span>
                        <span class="asig-tag <?php echo $factura['esta_asignada']>0?'asig-si':'asig-no'; ?>"
                              style="padding:2px 8px;font-size:11px;">
                            <?php echo $factura['esta_asignada']>0?'Sí':'No'; ?>
                        </span>
                    </div>
                </div>
            </div>
        </div>

    </div>
</div>

<?php require_once 'footer.php'; ?>