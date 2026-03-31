<?php
/* ============================================================
   registrar_pago.php — Registro de Pago de Factura
   Sistema ORTHIIS — Seguros de Vida
   ============================================================ */
error_reporting(E_ALL);
ini_set('display_errors', 1);
ob_start();
require_once 'header.php';

/* ── Función auxiliar ─────────────────────────────────────── */
function actualizarFechaFinContrato($conn, $contrato_id) {
    $stmt = $conn->prepare("
        SELECT f.fecha_vencimiento FROM facturas f
        WHERE f.contrato_id = ? AND f.estado = 'pagada'
        AND EXISTS (SELECT 1 FROM pagos p WHERE p.factura_id = f.id
                    AND p.tipo_pago = 'total' AND p.estado = 'procesado')
        ORDER BY f.fecha_vencimiento DESC LIMIT 1
    ");
    $stmt->execute([$contrato_id]);
    $res = $stmt->fetch();
    if ($res) {
        $conn->prepare("UPDATE contratos SET fecha_fin=? WHERE id=?")
             ->execute([$res['fecha_vencimiento'], $contrato_id]);
    }
}

/* ── Validar parámetro ───────────────────────────────────── */
if (!isset($_GET['factura_id'])) {
    ob_end_clean();
    header('Location: facturacion.php');
    exit();
}
$factura_id = (int)$_GET['factura_id'];

/* ── Obtener datos de la factura ─────────────────────────── */
$stmt = $conn->prepare("
    SELECT f.*,
           c.numero_contrato,
           c.id AS contrato_id,
           cl.nombre  AS cliente_nombre,
           cl.apellidos AS cliente_apellidos,
           COALESCE(cl.cobrador_id, 0) AS cobrador_cliente_id,
           (SELECT COALESCE(SUM(p.monto),0) FROM pagos p
            WHERE p.factura_id = f.id AND p.estado = 'procesado') AS total_abonado
    FROM facturas f
    JOIN contratos c  ON f.contrato_id = c.id
    JOIN clientes  cl ON c.cliente_id  = cl.id
    WHERE f.id = ?
");
$stmt->execute([$factura_id]);
$factura = $stmt->fetch();

if (!$factura) {
    ob_end_clean();
    header('Location: facturacion.php');
    exit();
}

$montoPendiente = max(0, (float)$factura['monto'] - (float)$factura['total_abonado']);

/* ── Validación server-side: facturas anteriores pendientes ── */
$stmtPrev = $conn->prepare("
    SELECT f2.id, f2.numero_factura, f2.monto, f2.estado,
           COALESCE((SELECT SUM(p.monto) FROM pagos p
                     WHERE p.factura_id=f2.id AND p.estado='procesado'),0) AS total_pagado
    FROM facturas f2
    WHERE f2.contrato_id=? AND f2.id<? AND f2.estado NOT IN('pagada','anulada')
    ORDER BY f2.id ASC
");
$stmtPrev->execute([$factura['contrato_id'], $factura_id]);
$prevRows = $stmtPrev->fetchAll(PDO::FETCH_ASSOC);
$hay_anteriores = false;
foreach ($prevRows as $row) {
    if (round((float)$row['monto']-(float)$row['total_pagado'],2)>0) {
        $hay_anteriores = true; break;
    }
}
if ($hay_anteriores) {
    ob_end_clean();
    header('Location: facturacion.php?error=facturas_anteriores_pendientes');
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
$stmt->execute([$factura_id]);
$pagos_previos = $stmt->fetchAll();

/* ── Toast desde redirección ─────────────────────────────── */
if (isset($_GET['mensaje'], $_GET['tipo'])) {
    echo "<script>document.addEventListener('DOMContentLoaded',function(){
        mostrarToast('".addslashes(htmlspecialchars($_GET['mensaje']))."','".htmlspecialchars($_GET['tipo'])."');
    });</script>";
}

/* ── Factura ya pagada ───────────────────────────────────── */
if ($factura['estado'] === 'pagada') {
    echo "<script>document.addEventListener('DOMContentLoaded',function(){
        mostrarToast('Esta factura ya está pagada completamente.','error');
    });</script>";
}

/* ── Procesar POST ───────────────────────────────────────── */
$error_pago   = '';
$exito_pago   = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' &&
    in_array($factura['estado'], ['pendiente','vencida','incompleta'])) {
    try {
        $conn->beginTransaction();
        $monto_pago   = (float)$_POST['monto'];
        $tipo_pago    = $monto_pago >= $montoPendiente ? 'total' : 'abono';
        $nuevo_estado = $tipo_pago === 'total' ? 'pagada' : 'incompleta';

        if ($monto_pago <= 0)
            throw new Exception("El monto debe ser mayor a 0.");
        if ($monto_pago > $montoPendiente)
            throw new Exception("El monto no puede superar el saldo pendiente (RD$".number_format($montoPendiente,2).").");

        $stmt = $conn->prepare("
            INSERT INTO pagos
                (factura_id, monto, fecha_pago, metodo_pago, referencia_pago,
                 cobrador_id, estado, tipo_pago, notas)
            VALUES (?,?,NOW(),?,?,
                (SELECT COALESCE(
                    (SELECT id FROM cobradores WHERE id=? AND estado='activo' LIMIT 1),
                    (SELECT id FROM cobradores WHERE estado='activo' ORDER BY id LIMIT 1)
                )),
                'procesado',?,?)
        ");
        $stmt->execute([
            $factura_id,
            $monto_pago,
            $_POST['metodo_pago'],
            $_POST['referencia_pago'] ?? '',
            $factura['cobrador_cliente_id'],
            $tipo_pago,
            $_POST['notas'] ?? ''
        ]);

        $conn->prepare("UPDATE facturas SET estado=?,monto_pendiente=? WHERE id=?")
             ->execute([$nuevo_estado, max(0,$montoPendiente-$monto_pago), $factura_id]);

        if ($tipo_pago === 'total')
            actualizarFechaFinContrato($conn, $factura['contrato_id']);

        $conn->commit();
        ob_end_clean();
        $msg   = $tipo_pago === 'total' ? 'Pago+total+registrado+correctamente' : 'Abono+registrado+correctamente';
        $color = $tipo_pago === 'total' ? 'success' : 'warning';
        header("Location: registrar_pago.php?factura_id={$factura_id}&mensaje={$msg}&tipo={$color}");
        exit();
    } catch (Exception $e) {
        if ($conn->inTransaction()) $conn->rollBack();
        $error_pago = $e->getMessage();
    }
}
/* Re-calcular tras posible pago parcial (para el HTML) */
$stmt = $conn->prepare("
    SELECT COALESCE(SUM(p.monto),0) AS total_abonado
    FROM pagos p WHERE p.factura_id=? AND p.estado='procesado'
");
$stmt->execute([$factura_id]);
$factura['total_abonado'] = (float)$stmt->fetchColumn();
$montoPendiente = max(0, (float)$factura['monto'] - $factura['total_abonado']);
$porcentajePagado = $factura['monto'] > 0
    ? min(100, round(($factura['total_abonado'] / $factura['monto']) * 100))
    : 0;

/* ── Etiquetas de estado ─────────────────────────────────── */
$estadoConfig = [
    'pendiente'  => ['cls'=>'badge-pendiente',  'icon'=>'fa-clock',         'label'=>'Pendiente'],
    'pagada'     => ['cls'=>'badge-pagada',      'icon'=>'fa-check-circle',  'label'=>'Pagada'],
    'incompleta' => ['cls'=>'badge-incompleta',  'icon'=>'fa-circle-half-stroke','label'=>'Incompleta'],
    'vencida'    => ['cls'=>'badge-vencida',     'icon'=>'fa-exclamation-circle','label'=>'Vencida'],
    'anulada'    => ['cls'=>'badge-anulada',     'icon'=>'fa-ban',           'label'=>'Anulada'],
];
$sc = $estadoConfig[$factura['estado']] ?? $estadoConfig['pendiente'];
$puedePagar = in_array($factura['estado'], ['pendiente','vencida','incompleta']) && $montoPendiente > 0;
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
.kpi-pago-row{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px;}
@media(max-width:900px){.kpi-pago-row{grid-template-columns:repeat(2,1fr);}}
@media(max-width:500px){.kpi-pago-row{grid-template-columns:1fr;}}
.kpi-pago{border-radius:var(--radius);padding:20px 20px 16px;position:relative;
    overflow:hidden;box-shadow:var(--shadow);transition:var(--transition);color:white;}
.kpi-pago:hover{transform:translateY(-3px);box-shadow:var(--shadow-md);}
.kpi-pago::before{content:'';position:absolute;top:0;right:0;width:70px;height:70px;
    border-radius:0 var(--radius) 0 100%;opacity:.15;background:white;}
.kpi-pago.blue  {background:linear-gradient(135deg,#1565C0,#1976D2);}
.kpi-pago.green {background:linear-gradient(135deg,#1B5E20,#2E7D32);}
.kpi-pago.amber {background:linear-gradient(135deg,#E65100,#F57F17);}
.kpi-pago.teal  {background:linear-gradient(135deg,#00695C,#00897B);}
.kpi-pago .kp-label{font-size:10.5px;font-weight:600;color:rgba(255,255,255,.80);
    text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px;}
.kpi-pago .kp-top{display:flex;align-items:flex-start;justify-content:space-between;}
.kpi-pago .kp-value{font-size:20px;font-weight:800;color:white;line-height:1.2;}
.kpi-pago .kp-sub{font-size:11px;color:rgba(255,255,255,.70);margin-top:3px;}
.kpi-pago .kp-icon{width:42px;height:42px;background:rgba(255,255,255,.18);
    border-radius:var(--radius-sm);display:flex;align-items:center;
    justify-content:center;font-size:18px;color:white;flex-shrink:0;}
.kpi-pago .kp-footer{margin-top:12px;padding-top:10px;
    border-top:1px solid rgba(255,255,255,.15);
    font-size:11px;color:rgba(255,255,255,.80);font-weight:600;
    display:flex;align-items:center;gap:5px;}

/* ── Progress bar ── */
.progress-wrap{margin-top:8px;}
.progress-bar-outer{height:6px;background:rgba(255,255,255,.25);
    border-radius:10px;overflow:hidden;}
.progress-bar-inner{height:100%;border-radius:10px;
    background:rgba(255,255,255,.90);transition:width .5s ease;}
.progress-label{font-size:10px;color:rgba(255,255,255,.80);margin-top:4px;text-align:right;}

/* ── Content grid ── */
.pago-grid{display:grid;grid-template-columns:1fr 380px;gap:20px;align-items:start;}
@media(max-width:900px){.pago-grid{grid-template-columns:1fr;}}

/* ── Info card (detalles factura) ── */
.info-section-title{font-size:11px;font-weight:700;color:var(--gray-500);
    text-transform:uppercase;letter-spacing:.8px;margin-bottom:14px;
    display:flex;align-items:center;gap:7px;}
.info-section-title i{color:var(--accent);}
.info-grid-2{display:grid;grid-template-columns:1fr 1fr;gap:10px;}
@media(max-width:600px){.info-grid-2{grid-template-columns:1fr;}}
.info-item-block{background:var(--gray-50);border:1px solid var(--gray-200);
    border-radius:var(--radius-sm);padding:12px 14px;}
.info-item-block .iib-label{font-size:10.5px;color:var(--gray-500);
    font-weight:600;text-transform:uppercase;letter-spacing:.6px;margin-bottom:3px;}
.info-item-block .iib-value{font-size:14px;font-weight:600;color:var(--gray-800);}
.info-item-block.full{grid-column:1/-1;}

/* ── Badge de estado ── */
.badge-pago-estado{display:inline-flex;align-items:center;gap:5px;
    padding:4px 12px;border-radius:20px;font-size:12px;font-weight:600;}
.badge-pendiente {background:#FEF3C7;color:#92400E;}
.badge-pagada    {background:#DCFCE7;color:#166534;}
.badge-incompleta{background:#DBEAFE;color:#1E40AF;}
.badge-vencida   {background:#FEE2E2;color:#991B1B;}
.badge-anulada   {background:#F1F5F9;color:#475569;}

/* ── Formulario de pago ── */
.form-section{background:var(--white);border:1px solid var(--gray-200);
    border-radius:var(--radius);box-shadow:var(--shadow-sm);}
.form-section-header{padding:16px 20px;border-bottom:1px solid var(--gray-200);
    display:flex;align-items:center;gap:10px;}
.form-section-header .fsh-icon{width:36px;height:36px;border-radius:var(--radius-sm);
    background:linear-gradient(135deg,#1565C0,#1976D2);
    display:flex;align-items:center;justify-content:center;color:white;font-size:15px;}
.form-section-header .fsh-title{font-size:15px;font-weight:700;color:var(--gray-800);}
.form-section-header .fsh-sub{font-size:12px;color:var(--gray-500);}
.form-section-body{padding:20px;}
.form-group-rp{margin-bottom:16px;}
.form-label-rp{display:block;font-size:12px;font-weight:600;
    color:var(--gray-700);margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px;}
.form-control-rp{width:100%;padding:10px 14px;border:1.5px solid var(--gray-200);
    border-radius:var(--radius-sm);font-size:14px;font-family:var(--font);
    color:var(--gray-800);background:var(--white);transition:var(--transition);}
.form-control-rp:focus{outline:none;border-color:var(--accent);
    box-shadow:0 0 0 3px rgba(33,150,243,.12);}
.form-control-rp::placeholder{color:var(--gray-400);}
.form-control-rp.monto-input{font-size:22px;font-weight:700;
    color:var(--gray-800);text-align:center;letter-spacing:.5px;}

/* ── Pago info badge ── */
.pago-info-banner{border-radius:var(--radius-sm);padding:12px 16px;
    margin-top:10px;font-size:13px;display:none;}
.pago-info-banner.total{background:#DCFCE7;border:1px solid #86EFAC;color:#166534;}
.pago-info-banner.abono{background:#FEF3C7;border:1px solid #FDE68A;color:#92400E;}
.pib-row{display:flex;justify-content:space-between;align-items:center;}
.pib-label{font-weight:600;}
.pib-value{font-weight:800;font-size:15px;}

/* ── Botones ── */
.btn{display:inline-flex;align-items:center;gap:7px;padding:10px 18px;
    border-radius:var(--radius-sm);border:none;font-size:13px;font-weight:600;
    font-family:var(--font);cursor:pointer;transition:var(--transition);
    text-decoration:none;white-space:nowrap;}
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
.btn-block    {width:100%;justify-content:center;}
.btn-lg       {padding:13px 22px;font-size:15px;}

/* ── Alert ── */
.alert-rp{padding:12px 16px;border-radius:var(--radius-sm);font-size:13px;
    margin-bottom:16px;display:flex;align-items:flex-start;gap:10px;}
.alert-rp.error  {background:#FEE2E2;border:1px solid #FCA5A5;color:#991B1B;}
.alert-rp.success{background:#DCFCE7;border:1px solid #86EFAC;color:#166534;}
.alert-rp.warning{background:#FEF3C7;border:1px solid #FDE68A;color:#92400E;}
.alert-rp i{flex-shrink:0;margin-top:1px;}

/* ── Tabla historial ── */
.data-table-rp{width:100%;border-collapse:collapse;font-size:13px;}
.data-table-rp thead th{background:var(--gray-50);padding:10px 12px;
    text-align:left;font-weight:600;color:var(--gray-600);font-size:11.5px;
    text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid var(--gray-200);}
.data-table-rp tbody td{padding:11px 12px;border-bottom:1px solid var(--gray-100);
    color:var(--gray-700);}
.data-table-rp tbody tr:last-child td{border-bottom:none;}
.data-table-rp tbody tr:hover{background:var(--gray-50);}
.amount-cell{font-weight:700;color:var(--gray-800);font-family:monospace;}

/* ── Método de pago chips ── */
.metodo-chips{display:flex;gap:8px;flex-wrap:wrap;}
.metodo-chip{flex:1;min-width:80px;}
.metodo-chip input[type=radio]{display:none;}
.metodo-chip label{display:flex;flex-direction:column;align-items:center;gap:5px;
    padding:10px 8px;border:1.5px solid var(--gray-200);border-radius:var(--radius-sm);
    cursor:pointer;transition:var(--transition);font-size:12px;font-weight:600;
    color:var(--gray-600);text-align:center;background:var(--white);}
.metodo-chip input:checked+label{border-color:var(--accent);
    background:#EFF6FF;color:var(--accent);}
.metodo-chip label i{font-size:18px;}

/* ── Divider ── */
.divider{height:1px;background:var(--gray-200);margin:20px 0;}

/* ── Modal Confirmar ── */
.modal-overlay-cp{position:fixed;inset:0;z-index:9999;
    background:rgba(15,23,42,.5);backdrop-filter:blur(3px);
    display:none;align-items:center;justify-content:center;}
.modal-overlay-cp.show{display:flex;}
.modal-box-cp{background:var(--white);border-radius:14px;width:100%;max-width:460px;
    box-shadow:0 20px 60px rgba(0,0,0,.2);overflow:hidden;
    animation:cpSlide .25s ease;}
@keyframes cpSlide{from{transform:translateY(20px);opacity:0}to{transform:translateY(0);opacity:1}}
.modal-hd-cp{padding:18px 20px;border-bottom:1px solid var(--gray-200);
    display:flex;align-items:center;gap:12px;}
.modal-hd-cp .mhcp-icon{width:40px;height:40px;border-radius:var(--radius-sm);
    background:linear-gradient(135deg,#1565C0,#1976D2);
    display:flex;align-items:center;justify-content:center;color:white;font-size:17px;}
.modal-hd-cp .mhcp-title{font-size:16px;font-weight:700;color:var(--gray-800);}
.modal-hd-cp .mhcp-close{margin-left:auto;background:none;border:none;
    font-size:20px;cursor:pointer;color:var(--gray-500);padding:4px 8px;
    border-radius:6px;transition:var(--transition);}
.modal-hd-cp .mhcp-close:hover{background:var(--gray-100);}
.modal-bd-cp{padding:20px;}
.detalle-row{display:flex;justify-content:space-between;align-items:center;
    padding:9px 0;border-bottom:1px solid var(--gray-100);font-size:13px;}
.detalle-row:last-child{border-bottom:none;}
.detalle-row .dr-label{color:var(--gray-500);font-weight:500;}
.detalle-row .dr-value{font-weight:600;color:var(--gray-800);}
.detalle-row .dr-value.green{color:#166534;}
.detalle-row .dr-value.blue{color:#1D4ED8;}
.aviso-confirmar{padding:12px 16px;border-radius:var(--radius-sm);
    font-size:13px;font-weight:600;text-align:center;margin:16px 0 0;}
.aviso-confirmar.total{background:#DCFCE7;color:#166534;border:1px solid #86EFAC;}
.aviso-confirmar.abono{background:#FEF3C7;color:#92400E;border:1px solid #FDE68A;}
.modal-ft-cp{padding:14px 20px;border-top:1px solid var(--gray-200);
    display:flex;gap:10px;justify-content:flex-end;background:var(--gray-50);}

/* ── Fade-in ── */
.fade-in{animation:fadeIn .4s ease both;}
.delay-1{animation-delay:.10s;}
.delay-2{animation-delay:.20s;}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
</style>

<?php
/* ── Datos para las KPI ─────────────────────────────────── */
$cuotas_totales = $conn->prepare(
    "SELECT COUNT(*) FROM facturas WHERE contrato_id=?"
);
$cuotas_totales->execute([$factura['contrato_id']]);
$total_cuotas = (int)$cuotas_totales->fetchColumn();

$cuotas_pagadas = $conn->prepare(
    "SELECT COUNT(*) FROM facturas WHERE contrato_id=? AND estado='pagada'"
);
$cuotas_pagadas->execute([$factura['contrato_id']]);
$total_pagadas = (int)$cuotas_pagadas->fetchColumn();

$total_abonado_contrato_stmt = $conn->prepare("
    SELECT COALESCE(SUM(pg.monto),0)
    FROM pagos pg JOIN facturas f ON pg.factura_id=f.id
    WHERE f.contrato_id=? AND pg.estado='procesado'
");
$total_abonado_contrato_stmt->execute([$factura['contrato_id']]);
$total_cobrado_contrato = (float)$total_abonado_contrato_stmt->fetchColumn();
?>

<!-- ============================================================
     PAGE HEADER
     ============================================================ -->
<div class="page-header fade-in">
    <div>
        <div class="page-title">
            <i class="fas fa-money-bill-wave" style="color:var(--accent);margin-right:8px;"></i>
            Registrar Pago
        </div>
        <div class="page-subtitle">
            Factura <strong><?php echo htmlspecialchars($factura['numero_factura']); ?></strong>
            &mdash;
            <?php echo htmlspecialchars($factura['cliente_nombre'].' '.$factura['cliente_apellidos']); ?>
        </div>
    </div>
    <div class="page-actions">
        <a href="ver_factura.php?id=<?php echo $factura_id; ?>" class="btn btn-info">
            <i class="fas fa-eye"></i> Ver Factura
        </a>
        <a href="imprimir_factura.php?id=<?php echo $factura_id; ?>&tipo=preview"
           class="btn btn-secondary" target="_blank">
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
<div class="kpi-pago-row fade-in delay-1">

    <div class="kpi-pago blue">
        <div class="kp-label">Monto Factura</div>
        <div class="kp-top">
            <div>
                <div class="kp-value">RD$<?php echo number_format($factura['monto'],2); ?></div>
                <div class="kp-sub">Mes: <?php echo htmlspecialchars($factura['mes_factura']); ?></div>
            </div>
            <div class="kp-icon"><i class="fas fa-file-invoice-dollar"></i></div>
        </div>
        <div class="kp-footer">
            <i class="fas fa-hashtag"></i>
            Cuota <?php echo $factura['cuota']; ?> de <?php echo $total_cuotas; ?>
        </div>
    </div>

    <div class="kpi-pago green">
        <div class="kp-label">Total Abonado</div>
        <div class="kp-top">
            <div>
                <div class="kp-value">RD$<?php echo number_format($factura['total_abonado'],2); ?></div>
                <div class="kp-sub"><?php echo $porcentajePagado; ?>% de la factura</div>
            </div>
            <div class="kp-icon"><i class="fas fa-check-circle"></i></div>
        </div>
        <div class="progress-wrap">
            <div class="progress-bar-outer">
                <div class="progress-bar-inner" style="width:<?php echo $porcentajePagado; ?>%;"></div>
            </div>
            <div class="progress-label"><?php echo $porcentajePagado; ?>% pagado</div>
        </div>
    </div>

    <div class="kpi-pago amber">
        <div class="kp-label">Saldo Pendiente</div>
        <div class="kp-top">
            <div>
                <div class="kp-value">RD$<?php echo number_format($montoPendiente,2); ?></div>
                <div class="kp-sub">Por cobrar esta factura</div>
            </div>
            <div class="kp-icon"><i class="fas fa-hourglass-half"></i></div>
        </div>
        <div class="kp-footer">
            <i class="fas fa-calendar-xmark"></i>
            Vence: <?php echo date('d/m/Y', strtotime($factura['fecha_vencimiento'])); ?>
        </div>
    </div>

    <div class="kpi-pago teal">
        <div class="kp-label">Cuotas Pagadas</div>
        <div class="kp-top">
            <div>
                <div class="kp-value"><?php echo $total_pagadas; ?> / <?php echo $total_cuotas; ?></div>
                <div class="kp-sub">Este contrato</div>
            </div>
            <div class="kp-icon"><i class="fas fa-receipt"></i></div>
        </div>
        <div class="kp-footer">
            <i class="fas fa-coins"></i>
            Total cobrado: RD$<?php echo number_format($total_cobrado_contrato,0); ?>
        </div>
    </div>

</div>

<!-- ============================================================
     ALERT DE ERROR
     ============================================================ -->
<?php if ($error_pago): ?>
<div class="alert-rp error fade-in">
    <i class="fas fa-exclamation-circle"></i>
    <span><?php echo htmlspecialchars($error_pago); ?></span>
</div>
<?php endif; ?>

<!-- ============================================================
     GRID PRINCIPAL
     ============================================================ -->
<div class="pago-grid fade-in delay-2">

    <!-- ─ Columna izquierda: info + historial ────────────────── -->
    <div style="display:flex;flex-direction:column;gap:20px;">

        <!-- Info de la Factura -->
        <div class="card">
            <div class="card-header">
                <div>
                    <div class="card-title">
                        <i class="fas fa-file-invoice" style="color:var(--accent);margin-right:6px;"></i>
                        Detalle de la Factura
                    </div>
                    <div class="card-subtitle">
                        Contrato N°
                        <?php echo str_pad($factura['numero_contrato'],5,'0',STR_PAD_LEFT); ?>
                    </div>
                </div>
                <span class="badge-pago-estado <?php echo $sc['cls']; ?>">
                    <i class="fas <?php echo $sc['icon']; ?>"></i>
                    <?php echo $sc['label']; ?>
                </span>
            </div>
            <div class="card-body">
                <div class="info-section-title">
                    <i class="fas fa-user"></i> Información del Cliente
                </div>
                <div class="info-grid-2" style="margin-bottom:20px;">
                    <div class="info-item-block full">
                        <div class="iib-label">Cliente</div>
                        <div class="iib-value">
                            <?php echo htmlspecialchars($factura['cliente_nombre'].' '.$factura['cliente_apellidos']); ?>
                        </div>
                    </div>
                    <div class="info-item-block">
                        <div class="iib-label">N° Contrato</div>
                        <div class="iib-value" style="font-family:monospace;">
                            <?php echo str_pad($factura['numero_contrato'],5,'0',STR_PAD_LEFT); ?>
                        </div>
                    </div>
                    <div class="info-item-block">
                        <div class="iib-label">N° Factura</div>
                        <div class="iib-value" style="font-family:monospace;color:var(--accent);">
                            <?php echo htmlspecialchars($factura['numero_factura']); ?>
                        </div>
                    </div>
                </div>

                <div class="info-section-title">
                    <i class="fas fa-calendar-alt"></i> Fechas y Montos
                </div>
                <div class="info-grid-2">
                    <div class="info-item-block">
                        <div class="iib-label">Período</div>
                        <div class="iib-value"><?php echo htmlspecialchars($factura['mes_factura']); ?></div>
                    </div>
                    <div class="info-item-block">
                        <div class="iib-label">Fecha Emisión</div>
                        <div class="iib-value">
                            <?php echo date('d/m/Y', strtotime($factura['fecha_emision'])); ?>
                        </div>
                    </div>
                    <div class="info-item-block">
                        <div class="iib-label">Fecha Vencimiento</div>
                        <div class="iib-value" style="<?php echo strtotime($factura['fecha_vencimiento'])<time() && $factura['estado']!=='pagada' ? 'color:#DC2626;' : ''; ?>">
                            <?php echo date('d/m/Y', strtotime($factura['fecha_vencimiento'])); ?>
                        </div>
                    </div>
                    <div class="info-item-block">
                        <div class="iib-label">Cuota N°</div>
                        <div class="iib-value"><?php echo $factura['cuota']; ?></div>
                    </div>
                    <div class="info-item-block">
                        <div class="iib-label">Monto Total</div>
                        <div class="iib-value" style="color:var(--gray-800);">
                            RD$<?php echo number_format($factura['monto'],2); ?>
                        </div>
                    </div>
                    <div class="info-item-block">
                        <div class="iib-label">Total Abonado</div>
                        <div class="iib-value" style="color:#166534;">
                            RD$<?php echo number_format($factura['total_abonado'],2); ?>
                        </div>
                    </div>
                    <div class="info-item-block" style="border-color:<?php echo $montoPendiente>0?'#FCA5A5':'#86EFAC'; ?>;">
                        <div class="iib-label">Saldo Pendiente</div>
                        <div class="iib-value" style="color:<?php echo $montoPendiente>0?'#DC2626':'#166534'; ?>;font-size:18px;">
                            RD$<?php echo number_format($montoPendiente,2); ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Historial de pagos -->
        <?php if (!empty($pagos_previos)): ?>
        <div class="card">
            <div class="card-header">
                <div>
                    <div class="card-title">
                        <i class="fas fa-history" style="color:var(--accent);margin-right:6px;"></i>
                        Historial de Pagos
                    </div>
                    <div class="card-subtitle">
                        <?php echo count($pagos_previos); ?> pago<?php echo count($pagos_previos)!==1?'s':''; ?>
                        registrado<?php echo count($pagos_previos)!==1?'s':''; ?>
                    </div>
                </div>
            </div>
            <div style="overflow-x:auto;">
                <table class="data-table-rp">
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
                        <?php foreach ($pagos_previos as $pago): ?>
                        <tr>
                            <td><?php echo date('d/m/Y H:i', strtotime($pago['fecha_pago'])); ?></td>
                            <td class="amount-cell">
                                RD$<?php echo number_format($pago['monto'],2); ?>
                            </td>
                            <td>
                                <span class="badge-pago-estado <?php echo $pago['tipo_pago']==='total'?'badge-pagada':'badge-incompleta'; ?>"
                                      style="padding:3px 9px;font-size:11px;">
                                    <?php echo ucfirst($pago['tipo_pago']); ?>
                                </span>
                            </td>
                            <td>
                                <span style="display:inline-flex;align-items:center;gap:5px;font-size:12px;">
                                    <i class="fas <?php
                                        $m=$pago['metodo_pago'];
                                        echo $m==='efectivo'?'fa-money-bill':($m==='transferencia'?'fa-building-columns':($m==='cheque'?'fa-money-check':'fa-credit-card'));
                                    ?>"></i>
                                    <?php echo ucfirst($pago['metodo_pago']); ?>
                                </span>
                            </td>
                            <td style="font-family:monospace;font-size:12px;">
                                <?php echo htmlspecialchars($pago['referencia_pago']??'-'); ?>
                            </td>
                            <td><?php echo htmlspecialchars($pago['cobrador_nombre']??'-'); ?></td>
                            <td>
                                <a href="imprimir_comprobante.php?id=<?php echo $pago['id']; ?>"
                                   class="btn btn-info" style="padding:5px 10px;font-size:11px;"
                                   target="_blank" title="Ver comprobante">
                                    <i class="fas fa-receipt"></i>
                                </a>
                            </td>
                        </tr>
                        <?php if ($pago['notas']): ?>
                        <tr>
                            <td colspan="7" style="padding:4px 12px 10px;font-size:12px;
                                color:var(--gray-500);background:var(--gray-50);">
                                <i class="fas fa-note-sticky" style="margin-right:5px;"></i>
                                <?php echo htmlspecialchars($pago['notas']); ?>
                            </td>
                        </tr>
                        <?php endif; ?>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <?php endif; ?>
    </div>

    <!-- ─ Columna derecha: formulario de pago ────────────────── -->
    <div>
        <div class="form-section">
            <div class="form-section-header">
                <div class="fsh-icon">
                    <i class="fas fa-dollar-sign"></i>
                </div>
                <div>
                    <div class="fsh-title">
                        <?php echo $puedePagar ? 'Registrar Pago' : 'Pago no disponible'; ?>
                    </div>
                    <div class="fsh-sub">
                        <?php if ($puedePagar): ?>
                            Saldo pendiente: <strong>RD$<?php echo number_format($montoPendiente,2); ?></strong>
                        <?php elseif($factura['estado']==='pagada'): ?>
                            Esta factura ya está completamente pagada
                        <?php else: ?>
                            Estado: <?php echo $sc['label']; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <div class="form-section-body">

                <?php if (!$puedePagar): ?>
                <div class="alert-rp <?php echo $factura['estado']==='pagada'?'success':'warning'; ?>">
                    <i class="fas <?php echo $factura['estado']==='pagada'?'fa-check-circle':'fa-exclamation-triangle'; ?>"></i>
                    <span>
                        <?php if ($factura['estado']==='pagada'): ?>
                            Esta factura ya ha sido pagada completamente.
                        <?php elseif($factura['estado']==='anulada'): ?>
                            Esta factura está anulada y no acepta pagos.
                        <?php else: ?>
                            No es posible registrar pagos en este momento.
                        <?php endif; ?>
                    </span>
                </div>
                <?php else: ?>

                <form id="formPago" method="POST" action="" autocomplete="off">

                    <!-- Monto -->
                    <div class="form-group-rp">
                        <label class="form-label-rp">
                            <i class="fas fa-dollar-sign" style="color:var(--accent);margin-right:3px;"></i>
                            Monto a Pagar
                        </label>
                        <div style="position:relative;">
                            <span style="position:absolute;left:14px;top:50%;transform:translateY(-50%);
                                font-size:15px;font-weight:700;color:var(--gray-500);">RD$</span>
                            <input type="number" id="monto" name="monto"
                                   class="form-control-rp monto-input"
                                   style="padding-left:50px;"
                                   placeholder="0.00"
                                   step="0.01" min="0.01"
                                   max="<?php echo $montoPendiente; ?>"
                                   required>
                        </div>
                        <!-- Acceso rápido al monto completo -->
                        <button type="button"
                                onclick="document.getElementById('monto').value='<?php echo number_format($montoPendiente,2,'.',''); ?>';actualizarInfoPago();"
                                style="margin-top:8px;width:100%;padding:7px;background:var(--gray-100);
                                       border:1.5px dashed var(--gray-300);border-radius:var(--radius-sm);
                                       font-size:12px;font-weight:600;color:var(--gray-600);cursor:pointer;
                                       transition:var(--transition);"
                                onmouseover="this.style.background='var(--gray-200)'"
                                onmouseout="this.style.background='var(--gray-100)'">
                            <i class="fas fa-bolt" style="color:var(--accent);margin-right:4px;"></i>
                            Pagar saldo completo: RD$<?php echo number_format($montoPendiente,2); ?>
                        </button>
                        <!-- Banner info tipo de pago -->
                        <div id="pagoInfoBanner" class="pago-info-banner">
                            <div class="pib-row">
                                <span class="pib-label" id="tipoPagoText">—</span>
                                <span class="pib-value" id="montoRestanteText"></span>
                            </div>
                        </div>
                    </div>

                    <!-- Método de pago -->
                    <div class="form-group-rp">
                        <label class="form-label-rp">
                            <i class="fas fa-credit-card" style="color:var(--accent);margin-right:3px;"></i>
                            Método de Pago
                        </label>
                        <div class="metodo-chips">
                            <div class="metodo-chip">
                                <input type="radio" id="m_efectivo" name="metodo_pago"
                                       value="efectivo" required checked>
                                <label for="m_efectivo">
                                    <i class="fas fa-money-bill-wave"></i>
                                    Efectivo
                                </label>
                            </div>
                            <div class="metodo-chip">
                                <input type="radio" id="m_transferencia" name="metodo_pago"
                                       value="transferencia">
                                <label for="m_transferencia">
                                    <i class="fas fa-building-columns"></i>
                                    Transfer.
                                </label>
                            </div>
                            <div class="metodo-chip">
                                <input type="radio" id="m_cheque" name="metodo_pago"
                                       value="cheque">
                                <label for="m_cheque">
                                    <i class="fas fa-money-check"></i>
                                    Cheque
                                </label>
                            </div>
                            <div class="metodo-chip">
                                <input type="radio" id="m_tarjeta" name="metodo_pago"
                                       value="tarjeta">
                                <label for="m_tarjeta">
                                    <i class="fas fa-credit-card"></i>
                                    Tarjeta
                                </label>
                            </div>
                        </div>
                    </div>

                    <!-- Referencia -->
                    <div class="form-group-rp" id="referenciaGroup" style="display:none;">
                        <label class="form-label-rp" for="referencia_pago">
                            <i class="fas fa-hashtag" style="color:var(--accent);margin-right:3px;"></i>
                            Referencia / N° Transacción
                        </label>
                        <input type="text" id="referencia_pago" name="referencia_pago"
                               class="form-control-rp" placeholder="Ej: TRF-00123456"
                               maxlength="20">
                    </div>

                    <!-- Notas -->
                    <div class="form-group-rp">
                        <label class="form-label-rp" for="notas">
                            <i class="fas fa-note-sticky" style="color:var(--accent);margin-right:3px;"></i>
                            Notas <span style="font-weight:400;color:var(--gray-400);">(opcional)</span>
                        </label>
                        <textarea id="notas" name="notas" class="form-control-rp"
                                  rows="3" placeholder="Observaciones del pago…"
                                  style="resize:vertical;"></textarea>
                    </div>

                    <div class="divider"></div>

                    <button type="submit" class="btn btn-primary btn-block btn-lg">
                        <i class="fas fa-check-circle"></i>
                        Registrar Pago
                    </button>
                    <a href="facturacion.php" class="btn btn-secondary btn-block"
                       style="margin-top:10px;">
                        <i class="fas fa-times"></i> Cancelar
                    </a>
                </form>

                <?php endif; ?>
            </div>
        </div>
    </div>

</div>

<!-- ============================================================
     MODAL DE CONFIRMACIÓN
     ============================================================ -->
<div id="modalConfirmarPago" class="modal-overlay-cp">
    <div class="modal-box-cp">
        <div class="modal-hd-cp">
            <div class="mhcp-icon"><i class="fas fa-shield-check"></i></div>
            <div>
                <div class="mhcp-title">Confirmar Pago</div>
            </div>
            <button class="mhcp-close" onclick="cerrarModalConfirmarPago()">&times;</button>
        </div>
        <div class="modal-bd-cp">
            <div id="detalles_pago_modal"></div>
            <div id="aviso_tipo_pago" class="aviso-confirmar"></div>
        </div>
        <div class="modal-ft-cp">
            <button class="btn btn-secondary" onclick="cerrarModalConfirmarPago()">
                <i class="fas fa-times"></i> Cancelar
            </button>
            <button class="btn btn-primary" onclick="confirmarPago()">
                <i class="fas fa-check-circle"></i> Confirmar y Registrar
            </button>
        </div>
    </div>
</div>

<!-- ============================================================
     JAVASCRIPT
     ============================================================ -->
<script>
const MONTO_PENDIENTE = <?php echo $montoPendiente; ?>;

function fmt(n) {
    return 'RD$' + parseFloat(n).toLocaleString('es-DO', {minimumFractionDigits:2, maximumFractionDigits:2});
}

function actualizarInfoPago() {
    const monto  = parseFloat(document.getElementById('monto').value) || 0;
    const banner = document.getElementById('pagoInfoBanner');
    const tipTxt = document.getElementById('tipoPagoText');
    const restTxt= document.getElementById('montoRestanteText');

    if (monto > 0 && monto <= MONTO_PENDIENTE) {
        const esTotal  = monto >= MONTO_PENDIENTE;
        const restante = Math.max(0, MONTO_PENDIENTE - monto);
        tipTxt.textContent  = esTotal ? '✅ Pago Total — Salda la factura' : '⚡ Abono Parcial';
        restTxt.textContent = esTotal ? '' : 'Quedan: ' + fmt(restante);
        banner.className = 'pago-info-banner ' + (esTotal ? 'total' : 'abono');
        banner.style.display = 'block';
    } else {
        banner.style.display = 'none';
    }
}

/* ── Métodos de pago ── */
document.querySelectorAll('input[name="metodo_pago"]').forEach(function(r) {
    r.addEventListener('change', function() {
        const rg  = document.getElementById('referenciaGroup');
        const ref = document.getElementById('referencia_pago');
        if (this.value === 'efectivo') {
            rg.style.display = 'none';
            ref.removeAttribute('required');
            ref.value = '';
        } else {
            rg.style.display = 'block';
            ref.setAttribute('required', 'required');
        }
    });
});

/* ── Validación y modal ── */
document.getElementById('formPago')?.addEventListener('submit', function(e) {
    e.preventDefault();
    const monto    = parseFloat(document.getElementById('monto').value);
    const metodo   = document.querySelector('input[name="metodo_pago"]:checked')?.value;
    const referencia = document.getElementById('referencia_pago')?.value || '';
    const notas    = document.getElementById('notas').value || '';
    const errores  = [];

    if (!monto || monto <= 0)
        errores.push('El monto debe ser mayor a 0.');
    if (monto > MONTO_PENDIENTE)
        errores.push('El monto no puede superar el saldo pendiente (' + fmt(MONTO_PENDIENTE) + ').');
    if (!metodo)
        errores.push('Seleccione un método de pago.');
    if (metodo && metodo !== 'efectivo' && !referencia.trim())
        errores.push('Ingrese una referencia para el método seleccionado.');
    if (referencia.length > 20)
        errores.push('La referencia no puede superar 20 caracteres.');

    if (errores.length > 0) {
        errores.forEach(function(er){ mostrarToast(er, 'error'); });
        return;
    }

    const esTotal  = monto >= MONTO_PENDIENTE;
    const restante = Math.max(0, MONTO_PENDIENTE - monto);
    const metLabel = metodo.charAt(0).toUpperCase() + metodo.slice(1);

    let html = `
        <div class="detalle-row">
            <span class="dr-label">Contrato</span>
            <span class="dr-value"><?php echo str_pad($factura['numero_contrato'],5,'0',STR_PAD_LEFT); ?></span>
        </div>
        <div class="detalle-row">
            <span class="dr-label">Factura</span>
            <span class="dr-value blue"><?php echo htmlspecialchars($factura['numero_factura']); ?></span>
        </div>
        <div class="detalle-row">
            <span class="dr-label">Cliente</span>
            <span class="dr-value"><?php echo htmlspecialchars($factura['cliente_nombre'].' '.$factura['cliente_apellidos']); ?></span>
        </div>
        <div class="detalle-row">
            <span class="dr-label">Monto a Pagar</span>
            <span class="dr-value green" style="font-size:16px;">${fmt(monto)}</span>
        </div>
        <div class="detalle-row">
            <span class="dr-label">Método</span>
            <span class="dr-value">${metLabel}</span>
        </div>`;
    if (metodo !== 'efectivo' && referencia.trim()) {
        html += `<div class="detalle-row">
            <span class="dr-label">Referencia</span>
            <span class="dr-value" style="font-family:monospace;">${referencia}</span>
        </div>`;
    }
    if (!esTotal) {
        html += `<div class="detalle-row">
            <span class="dr-label">Saldo restante</span>
            <span class="dr-value" style="color:#DC2626;">${fmt(restante)}</span>
        </div>`;
    }
    if (notas.trim()) {
        html += `<div class="detalle-row">
            <span class="dr-label">Notas</span>
            <span class="dr-value">${notas}</span>
        </div>`;
    }

    document.getElementById('detalles_pago_modal').innerHTML = html;
    const aviso = document.getElementById('aviso_tipo_pago');
    aviso.className = 'aviso-confirmar ' + (esTotal ? 'total' : 'abono');
    aviso.innerHTML = esTotal
        ? '<i class="fas fa-check-circle"></i> ¿Registrar pago TOTAL? La factura quedará PAGADA.'
        : '<i class="fas fa-circle-half-stroke"></i> ¿Registrar este ABONO? La factura quedará INCOMPLETA.';

    document.getElementById('modalConfirmarPago').classList.add('show');
    document.body.style.overflow = 'hidden';
});

function cerrarModalConfirmarPago() {
    document.getElementById('modalConfirmarPago').classList.remove('show');
    document.body.style.overflow = '';
}
function confirmarPago() {
    document.getElementById('formPago').submit();
}

document.getElementById('monto')?.addEventListener('input', actualizarInfoPago);
document.getElementById('monto')?.addEventListener('blur', function() {
    if (this.value) this.value = parseFloat(this.value).toFixed(2);
});
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') cerrarModalConfirmarPago();
});
document.getElementById('modalConfirmarPago')?.addEventListener('click', function(e) {
    if (e.target === this) cerrarModalConfirmarPago();
});
document.addEventListener('DOMContentLoaded', actualizarInfoPago);
</script>

<?php require_once 'footer.php'; ?>