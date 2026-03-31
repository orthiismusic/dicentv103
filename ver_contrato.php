<?php
require_once 'header.php';

if (!isset($_GET['id'])) {
    header('Location: contratos.php');
    exit();
}

$id = (int)$_GET['id'];

// Obtener datos del contrato con toda la información relacionada
$stmt = $conn->prepare("
    SELECT c.*, 
           cl.codigo as cliente_codigo,
           cl.nombre as cliente_nombre,
           cl.apellidos as cliente_apellidos,
           cl.direccion as cliente_direccion,
           cl.telefono1 as cliente_telefono1,
           cl.telefono2 as cliente_telefono2,
           cl.telefono3 as cliente_telefono3,
           cl.email as cliente_email,
           cl.cedula as cliente_cedula,
           p.nombre as plan_nombre,
           p.descripcion as plan_descripcion,
           p.cobertura_maxima,
           p.codigo as plan_codigo,
           v.nombre_completo as vendedor_nombre,
           (SELECT COUNT(*) FROM dependientes d WHERE d.contrato_id = c.id AND d.estado = 'activo') as total_dependientes,
           (SELECT COUNT(*) FROM dependientes d WHERE d.contrato_id = c.id AND d.estado = 'activo' AND d.plan_id = 5) as total_geriatricos,
           (SELECT COUNT(*) FROM facturas f WHERE f.contrato_id = c.id AND f.estado = 'incompleta') as facturas_incompletas,
           (SELECT COUNT(*) FROM facturas f WHERE f.contrato_id = c.id AND f.estado IN ('pendiente','vencida')) as facturas_pendientes,
           (SELECT COUNT(*) FROM facturas f WHERE f.contrato_id = c.id AND f.estado = 'pagada') as facturas_pagadas,
           (SELECT COUNT(*) FROM facturas f WHERE f.contrato_id = c.id) as total_facturas,
           (SELECT COALESCE(SUM(pg.monto),0) FROM facturas f JOIN pagos pg ON f.id = pg.factura_id WHERE f.contrato_id = c.id AND pg.tipo_pago = 'abono' AND pg.estado = 'procesado') as total_abonado,
           (SELECT COALESCE(SUM(f.monto),0) FROM facturas f WHERE f.contrato_id = c.id AND f.estado IN ('pendiente','incompleta','vencida')) as total_pendiente,
           (SELECT COALESCE(SUM(f.monto),0) FROM facturas f WHERE f.contrato_id = c.id) as total_facturado,
           (SELECT COALESCE(SUM(f.monto),0) FROM facturas f WHERE f.contrato_id = c.id AND f.estado = 'pagada') as total_cobrado
    FROM contratos c
    JOIN clientes cl ON c.cliente_id = cl.id
    JOIN planes p ON c.plan_id = p.id
    LEFT JOIN vendedores v ON c.vendedor_id = v.id
    WHERE c.id = ?
");
$stmt->execute([$id]);
$contrato = $stmt->fetch();

if (!$contrato) {
    header('Location: contratos.php');
    exit();
}

// Obtener beneficiarios
$stmt = $conn->prepare("SELECT * FROM beneficiarios WHERE contrato_id = ? ORDER BY nombre, apellidos");
$stmt->execute([$id]);
$beneficiarios = $stmt->fetchAll();

// Obtener dependientes
$stmt = $conn->prepare("
    SELECT d.*, 
           p.nombre as plan_nombre, 
           p.precio_base,
           DATE_FORMAT(d.fecha_registro, '%d/%m/%Y') as fecha_registro_formateada,
           (SELECT COUNT(*) FROM historial_cambios_plan_dependientes h WHERE h.dependiente_id = d.id) as total_cambios_plan
    FROM dependientes d
    JOIN planes p ON d.plan_id = p.id
    WHERE d.contrato_id = ? AND d.estado = 'activo'
    ORDER BY d.nombre, d.apellidos
");
$stmt->execute([$id]);
$dependientes = $stmt->fetchAll();

// Obtener planes disponibles
$stmtPl = $conn->query("SELECT id, nombre, precio_base FROM planes WHERE estado = 'activo' ORDER BY nombre");
$planes_disponibles = $stmtPl->fetchAll();

// Obtener facturas del contrato
$stmt = $conn->prepare("
    SELECT f.*,
           (SELECT COALESCE(SUM(p.monto),0) FROM pagos p WHERE p.factura_id = f.id AND p.estado = 'procesado') AS total_abonado,
           (SELECT GROUP_CONCAT(CONCAT(DATE_FORMAT(p.fecha_pago,'%d/%m/%Y'),': RD$',FORMAT(p.monto,2)) ORDER BY p.fecha_pago ASC SEPARATOR '|') FROM pagos p WHERE p.factura_id = f.id AND p.estado = 'procesado') as detalle_pagos,
           (SELECT COUNT(*) FROM pagos p WHERE p.factura_id = f.id AND p.estado = 'procesado') as total_pagos
    FROM facturas f
    WHERE f.contrato_id = ?
    ORDER BY f.numero_factura DESC
");
$stmt->execute([$id]);
$facturas = $stmt->fetchAll();

// Obtener historial de pagos
$stmt = $conn->prepare("
    SELECT p.*, f.numero_factura, f.mes_factura, u.nombre as cobrador_nombre
    FROM pagos p
    JOIN facturas f ON p.factura_id = f.id
    LEFT JOIN usuarios u ON p.cobrador_id = u.id
    WHERE f.contrato_id = ? AND p.estado = 'procesado'
    ORDER BY p.fecha_pago DESC
    LIMIT 20
");
$stmt->execute([$id]);
$pagos = $stmt->fetchAll();

// Calcular estadísticas
$total_facturado = 0;
$total_cobrado   = 0;
$total_pendiente = 0;
$facturas_vencidas = 0;
$facturas_incompletas_cnt = 0;

foreach ($facturas as $factura) {
    $total_facturado += $factura['monto'];
    if ($factura['estado'] == 'pagada') {
        $total_cobrado += $factura['monto'];
    } else {
        if ($factura['estado'] == 'incompleta') {
            $total_pendiente += $factura['monto'] - ($factura['total_abonado'] ?? 0);
            $facturas_incompletas_cnt++;
        } elseif (in_array($factura['estado'], ['pendiente','vencida'])) {
            $total_pendiente += $factura['monto'];
            if ($factura['estado'] == 'vencida') $facturas_vencidas++;
        }
    }
}

// Preparar pagos desglosados para modal
$pagos_desglosados = [];
foreach ($facturas as $factura) {
    if (!empty($factura['detalle_pagos'])) {
        $pagos_desglosados[$factura['id']] = explode('|', $factura['detalle_pagos']);
    }
}
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

/* ── KPI CARDS ── */
.kpi-contrato-row{display:grid;grid-template-columns:repeat(5,1fr);gap:16px;margin-bottom:24px;}
@media(max-width:1200px){.kpi-contrato-row{grid-template-columns:repeat(3,1fr);}}
@media(max-width:700px){.kpi-contrato-row{grid-template-columns:repeat(2,1fr);}}
@media(max-width:430px){.kpi-contrato-row{grid-template-columns:1fr;}}
.kpi-co{border-radius:var(--radius);padding:20px 20px 16px;position:relative;
    overflow:hidden;box-shadow:var(--shadow);transition:var(--transition);color:white;}
.kpi-co:hover{transform:translateY(-3px);box-shadow:var(--shadow-md);}
.kpi-co::before{content:'';position:absolute;top:0;right:0;width:65px;height:65px;
    border-radius:0 var(--radius) 0 100%;opacity:.15;background:white;}
.kpi-co.blue  {background:linear-gradient(135deg,#1565C0,#1976D2);}
.kpi-co.green {background:linear-gradient(135deg,#1B5E20,#2E7D32);}
.kpi-co.amber {background:linear-gradient(135deg,#E65100,#F57F17);}
.kpi-co.red   {background:linear-gradient(135deg,#B71C1C,#C62828);}
.kpi-co.teal  {background:linear-gradient(135deg,#00695C,#00897B);}
.kpi-co.purple{background:linear-gradient(135deg,#4A148C,#6A1B9A);}
.kpi-co .ko-label{font-size:10.5px;font-weight:600;color:rgba(255,255,255,.80);
    text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px;}
.kpi-co .ko-top{display:flex;align-items:flex-start;justify-content:space-between;}
.kpi-co .ko-value{font-size:24px;font-weight:800;color:white;line-height:1.1;margin-bottom:3px;}
.kpi-co .ko-value.sm{font-size:17px;}
.kpi-co .ko-sub{font-size:11px;color:rgba(255,255,255,.70);}
.kpi-co .ko-icon{width:42px;height:42px;background:rgba(255,255,255,.18);
    border-radius:var(--radius-sm);display:flex;align-items:center;
    justify-content:center;font-size:18px;color:white;flex-shrink:0;}
.kpi-co .ko-footer{margin-top:12px;padding-top:10px;
    border-top:1px solid rgba(255,255,255,.15);
    font-size:11px;color:rgba(255,255,255,.80);font-weight:600;
    display:flex;align-items:center;gap:5px;}

/* ── Cards ── */
.co-card{background:var(--white);border-radius:var(--radius);
    box-shadow:var(--shadow);margin-bottom:20px;overflow:hidden;}
.co-card-header{padding:16px 22px;border-bottom:1px solid var(--gray-200);
    display:flex;align-items:center;justify-content:space-between;gap:12px;}
.co-card-title{display:flex;align-items:center;gap:10px;}
.co-card-icon{width:36px;height:36px;border-radius:var(--radius-sm);
    display:flex;align-items:center;justify-content:center;font-size:15px;color:white;}
.co-card-icon.blue   {background:linear-gradient(135deg,#1565C0,#1976D2);}
.co-card-icon.green  {background:linear-gradient(135deg,#1B5E20,#2E7D32);}
.co-card-icon.amber  {background:linear-gradient(135deg,#E65100,#F57F17);}
.co-card-icon.red    {background:linear-gradient(135deg,#B71C1C,#C62828);}
.co-card-icon.teal   {background:linear-gradient(135deg,#00695C,#00897B);}
.co-card-icon.purple {background:linear-gradient(135deg,#4A148C,#6A1B9A);}
.co-card-icon.gray   {background:linear-gradient(135deg,#455A64,#607D8B);}
.co-title-text{font-size:14px;font-weight:700;color:var(--gray-800);}
.co-title-sub{font-size:11px;color:var(--gray-500);margin-top:1px;}
.co-card-body{padding:20px 22px;}

/* ── Layout 2 columnas ── */
.co-two-col{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px;}
@media(max-width:900px){.co-two-col{grid-template-columns:1fr;}}

/* ── Info Grid ── */
.info-grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;}
.info-grid-2{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;}
@media(max-width:700px){.info-grid-3{grid-template-columns:repeat(2,1fr);}}
@media(max-width:450px){.info-grid-3,.info-grid-2{grid-template-columns:1fr;}}
.iib{background:var(--gray-50);border:1px solid var(--gray-200);
    border-radius:var(--radius-sm);padding:11px 14px;}
.iib.full{grid-column:1/-1;}
.iib .iib-label{font-size:10.5px;color:var(--gray-500);font-weight:600;
    text-transform:uppercase;letter-spacing:.6px;margin-bottom:3px;}
.iib .iib-value{font-size:13.5px;font-weight:600;color:var(--gray-800);}
.iib .iib-value.mono{font-family:monospace;color:var(--accent);}
.iib .iib-value a{color:var(--accent);text-decoration:none;}
.iib .iib-value a:hover{text-decoration:underline;}

/* ── Badges ── */
.badge-co{display:inline-flex;align-items:center;gap:4px;padding:3px 10px;
    border-radius:20px;font-size:11px;font-weight:700;}
.badge-co.activo    {background:#DCFCE7;color:#166534;}
.badge-co.cancelado {background:#FEE2E2;color:#991B1B;}
.badge-co.suspendido{background:#FEF3C7;color:#92400E;}
.badge-co.pendiente {background:#FEF3C7;color:#B45309;}
.badge-co.pagada    {background:#DCFCE7;color:#15803D;}
.badge-co.incompleta{background:#EDE9FE;color:#7C3AED;}
.badge-co.vencida   {background:#FEE2E2;color:#DC2626;}
.badge-co.total     {background:#DCFCE7;color:#15803D;}
.badge-co.abono     {background:#DBEAFE;color:#1E40AF;}

/* ── Dependientes Grid ── */
.dep-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px;}
.dep-card{background:var(--white);border:1px solid var(--gray-200);
    border-radius:var(--radius);padding:15px;transition:var(--transition);}
.dep-card:hover{box-shadow:var(--shadow);border-color:var(--accent);}
.dep-card-header{display:flex;justify-content:space-between;align-items:flex-start;
    margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid var(--gray-100);}
.dep-card-name{font-size:13px;font-weight:700;color:var(--gray-800);margin-bottom:2px;}
.dep-card-rel{font-size:11px;color:var(--gray-500);}
.dep-age-badge{padding:3px 9px;border-radius:20px;font-size:11px;font-weight:700;flex-shrink:0;}
.dep-age-badge.geriatrico{background:#FEF3C7;color:#B45309;}
.dep-age-badge.normal{background:#DBEAFE;color:#1E40AF;}
.dep-info-row{display:flex;align-items:center;gap:6px;font-size:12px;
    color:var(--gray-600);margin-bottom:4px;}
.dep-info-row i{width:13px;color:var(--gray-400);}
.dep-actions{display:flex;gap:5px;margin-top:10px;padding-top:8px;
    border-top:1px solid var(--gray-100);}
.dep-actions .btn-dep{height:28px;padding:0 10px;border-radius:var(--radius-sm);
    border:none;display:inline-flex;align-items:center;gap:4px;font-size:11px;
    font-weight:600;cursor:pointer;transition:var(--transition);}
.dep-actions .btn-dep:hover{transform:translateY(-1px);}
.dep-actions .btn-dep.edit   {background:#EFF6FF;color:#1565C0;}
.dep-actions .btn-dep.history{background:#F0FDF4;color:#15803D;}
.dep-actions .btn-dep.delete {background:#FEF2F2;color:#DC2626;}
.dep-actions .btn-dep.edit:hover   {background:#1565C0;color:white;}
.dep-actions .btn-dep.history:hover{background:#15803D;color:white;}
.dep-actions .btn-dep.delete:hover {background:#DC2626;color:white;}

/* ── Beneficiarios ── */
.ben-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:14px;}
.ben-card{background:var(--gray-50);border:1px solid var(--gray-200);
    border-radius:var(--radius-sm);padding:14px;}
.ben-card-name{font-size:13px;font-weight:700;color:var(--gray-800);margin-bottom:8px;
    padding-bottom:8px;border-bottom:1px solid var(--gray-200);}
.ben-row{display:flex;justify-content:space-between;font-size:12px;
    color:var(--gray-600);margin-bottom:4px;}
.ben-row strong{color:var(--gray-800);}
.ben-pct{font-size:18px;font-weight:800;color:var(--accent);text-align:right;}

/* ── Tabla ── */
.co-table-wrap{overflow-x:auto;}
.co-table{width:100%;border-collapse:collapse;font-size:12.5px;}
.co-table thead th{background:var(--gray-50);padding:10px 12px;text-align:left;
    font-size:11px;font-weight:700;color:var(--gray-500);text-transform:uppercase;
    letter-spacing:.6px;border-bottom:1px solid var(--gray-200);white-space:nowrap;}
.co-table tbody td{padding:11px 12px;border-bottom:1px solid var(--gray-100);
    color:var(--gray-700);vertical-align:middle;}
.co-table tbody tr:hover{background:var(--gray-50);}
.co-table tbody tr:last-child td{border-bottom:none;}
.td-num{font-family:monospace;font-weight:700;color:var(--accent);}
.td-num a{color:var(--accent);text-decoration:none;}
.td-num a:hover{text-decoration:underline;}
.td-strong{font-weight:600;color:var(--gray-800);}
.td-muted{color:var(--gray-400);font-size:11.5px;}
.td-amount{font-weight:700;color:var(--gray-800);}
.td-red{font-weight:700;color:#DC2626;}
.td-green{font-weight:700;color:#15803D;}

/* ── Botones tabla ── */
.tbl-actions{display:flex;align-items:center;gap:5px;}
.btn-tbl{width:30px;height:30px;border-radius:var(--radius-sm);border:none;
    display:inline-flex;align-items:center;justify-content:center;
    font-size:12px;cursor:pointer;transition:var(--transition);text-decoration:none;}
.btn-tbl:hover{transform:translateY(-2px);box-shadow:var(--shadow);}
.btn-tbl.view   {background:#EFF6FF;color:#1565C0;}
.btn-tbl.pay    {background:#F0FDF4;color:#15803D;}
.btn-tbl.print  {background:#F5F3FF;color:#7C3AED;}
.btn-tbl.hist   {background:#FFF7ED;color:#C2410C;}
.btn-tbl.view:hover  {background:#1565C0;color:white;}
.btn-tbl.pay:hover   {background:#15803D;color:white;}
.btn-tbl.print:hover {background:#7C3AED;color:white;}
.btn-tbl.hist:hover  {background:#C2410C;color:white;}

/* ── Empty state ── */
.empty-state{text-align:center;padding:40px 20px;color:var(--gray-400);}
.empty-state i{font-size:36px;margin-bottom:10px;display:block;}

/* ── Anims ── */
.fade-in{animation:fadeIn .4s ease both;}
.delay-1{animation-delay:.08s;}
.delay-2{animation-delay:.16s;}
.delay-3{animation-delay:.24s;}
.delay-4{animation-delay:.32s;}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}

/* ── Modal Historial Pagos ── */
.modal-overlay-co{position:fixed;inset:0;background:rgba(0,0,0,.5);
    z-index:9000;display:none;align-items:center;justify-content:center;padding:20px;}
.modal-overlay-co.show{display:flex;}
.modal-box-co{background:var(--white);border-radius:var(--radius-lg);
    width:100%;max-width:580px;max-height:80vh;display:flex;flex-direction:column;
    box-shadow:var(--shadow-lg);}
.modal-box-co .mhdr-co{padding:16px 22px;border-bottom:1px solid var(--gray-200);
    display:flex;align-items:center;justify-content:space-between;flex-shrink:0;}
.modal-box-co .mbody-co{padding:20px 22px;overflow-y:auto;flex:1;}
.modal-close-co{background:none;border:none;cursor:pointer;
    width:32px;height:32px;border-radius:var(--radius-sm);
    display:flex;align-items:center;justify-content:center;
    color:var(--gray-500);font-size:14px;transition:var(--transition);}
.modal-close-co:hover{background:var(--gray-100);color:var(--gray-800);}

/* ── Modal Historial Plan ── */
.modal-overlay-hp{position:fixed;inset:0;background:rgba(0,0,0,.5);
    z-index:9100;display:none;align-items:center;justify-content:center;padding:20px;}
.modal-overlay-hp.show{display:flex;}
.modal-box-hp{background:var(--white);border-radius:var(--radius-lg);
    width:100%;max-width:700px;max-height:85vh;display:flex;flex-direction:column;
    box-shadow:var(--shadow-lg);}
.modal-box-hp .mhdr-hp{padding:16px 22px;border-bottom:1px solid var(--gray-200);
    display:flex;align-items:center;justify-content:space-between;flex-shrink:0;}
.modal-box-hp .mbody-hp{padding:20px 22px;overflow-y:auto;flex:1;}

/* ── Modal Editar Dependiente ── */
.modal-overlay-dep{position:fixed;inset:0;background:rgba(0,0,0,.5);
    z-index:9200;display:none;align-items:center;justify-content:center;padding:20px;}
.modal-overlay-dep.show{display:flex;}
.modal-box-dep{background:var(--white);border-radius:var(--radius-lg);
    width:100%;max-width:580px;max-height:90vh;display:flex;flex-direction:column;
    box-shadow:var(--shadow-lg);}
.modal-box-dep .mhdr-dep{padding:16px 22px;border-bottom:1px solid var(--gray-200);
    display:flex;align-items:center;justify-content:space-between;flex-shrink:0;}
.modal-box-dep .mbody-dep{padding:20px 22px;overflow-y:auto;flex:1;}
.modal-box-dep .mfooter-dep{padding:14px 22px;border-top:1px solid var(--gray-200);
    display:flex;justify-content:flex-end;gap:10px;flex-shrink:0;}
.form-row-dep{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px;}
@media(max-width:500px){.form-row-dep{grid-template-columns:1fr;}}
.form-group-dep label{display:block;font-size:11px;font-weight:600;
    color:var(--gray-600);margin-bottom:5px;text-transform:uppercase;letter-spacing:.5px;}
.form-group-dep input, .form-group-dep select{width:100%;padding:9px 12px;
    border:1.5px solid var(--gray-200);border-radius:var(--radius-sm);
    font-size:13px;color:var(--gray-800);background:var(--white);
    transition:var(--transition);outline:none;}
.form-group-dep input:focus, .form-group-dep select:focus{
    border-color:var(--accent);box-shadow:0 0 0 3px rgba(33,150,243,.15);}

/* ── Spinner ── */
.spinner-co{width:36px;height:36px;border:3px solid var(--gray-200);
    border-top-color:var(--accent);border-radius:50%;
    animation:spin .8s linear infinite;margin:30px auto;}
@keyframes spin{to{transform:rotate(360deg)}}

/* ── Lista pagos ── */
.lista-pagos{list-style:none;padding:0;margin:0;}
.lista-pagos li{padding:10px 14px;border-bottom:1px solid var(--gray-100);
    font-size:13px;color:var(--gray-700);display:flex;align-items:center;gap:8px;}
.lista-pagos li:last-child{border-bottom:none;}
.lista-pagos li::before{content:'•';color:var(--accent);font-size:18px;line-height:1;}

/* ── Historial timeline (plan dep) ── */
.hist-timeline{position:relative;padding-left:28px;}
.hist-timeline::before{content:'';position:absolute;left:8px;top:0;bottom:0;
    width:2px;background:var(--gray-200);}
.hist-item{position:relative;margin-bottom:20px;}
.hist-item::before{content:'';position:absolute;left:-23px;top:4px;
    width:10px;height:10px;border-radius:50%;background:var(--accent);
    border:2px solid var(--white);box-shadow:0 0 0 2px var(--accent);}
.hist-item-header{display:flex;align-items:center;justify-content:space-between;
    margin-bottom:6px;flex-wrap:wrap;gap:6px;}
.hist-item-date{font-size:11.5px;font-weight:700;color:var(--gray-500);}
.hist-item-user{font-size:11px;color:var(--gray-400);}
.hist-item-body{background:var(--gray-50);border:1px solid var(--gray-200);
    border-radius:var(--radius-sm);padding:12px 14px;}
.hist-plan-change{display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap;}
.hist-plan-name{font-size:12px;font-weight:700;padding:3px 10px;border-radius:20px;}
.hist-plan-name.anterior{background:#FEE2E2;color:#991B1B;}
.hist-plan-name.nuevo{background:#DCFCE7;color:#166534;}
.hist-motivo{font-size:12px;color:var(--gray-600);margin-top:6px;}
.hist-empty{text-align:center;padding:30px;color:var(--gray-400);}
.hist-empty i{font-size:32px;display:block;margin-bottom:8px;}
</style>

<!-- ============================================================
     PAGE HEADER
     ============================================================ -->
<div class="page-header fade-in">
    <div>
        <div class="page-title">
            <i class="fas fa-file-contract" style="color:var(--accent);margin-right:8px;"></i>
            Contrato N° <?php echo str_pad($contrato['numero_contrato'], 5, '0', STR_PAD_LEFT); ?>
        </div>
        <div class="page-subtitle">
            Cliente: <strong><?php echo htmlspecialchars($contrato['cliente_nombre'] . ' ' . $contrato['cliente_apellidos']); ?></strong>
            &mdash; Plan: <strong><?php echo htmlspecialchars($contrato['plan_nombre']); ?></strong>
        </div>
    </div>
    <div class="page-actions">
        <a href="editar_contrato.php?id=<?php echo $id; ?>" class="btn btn-primary">
            <i class="fas fa-edit"></i> Editar
        </a>
        <a href="ver_cliente.php?id=<?php echo $contrato['cliente_id']; ?>" class="btn btn-secondary">
            <i class="fas fa-user"></i> Ver Cliente
        </a>
        <a href="facturacion.php?numero_contrato=<?php echo urlencode($contrato['numero_contrato']); ?>" class="btn btn-secondary">
            <i class="fas fa-file-invoice-dollar"></i> Facturas
        </a>
        <a href="contratos.php" class="btn btn-secondary">
            <i class="fas fa-arrow-left"></i> Volver
        </a>
    </div>
</div>

<!-- ============================================================
     KPI CARDS
     ============================================================ -->
<div class="kpi-contrato-row fade-in delay-1">
    <div class="kpi-co blue">
        <div class="ko-label">Total Facturado</div>
        <div class="ko-top">
            <div>
                <div class="ko-value sm">RD$<?php echo number_format($total_facturado, 0); ?></div>
                <div class="ko-sub"><?php echo count($facturas); ?> facturas generadas</div>
            </div>
            <div class="ko-icon"><i class="fas fa-file-invoice-dollar"></i></div>
        </div>
        <div class="ko-footer"><i class="fas fa-hashtag"></i> Histórico total</div>
    </div>
    <div class="kpi-co green">
        <div class="ko-label">Total Cobrado</div>
        <div class="ko-top">
            <div>
                <div class="ko-value sm">RD$<?php echo number_format($total_cobrado, 0); ?></div>
                <div class="ko-sub"><?php echo $contrato['facturas_pagadas']; ?> factura(s) pagada(s)</div>
            </div>
            <div class="ko-icon"><i class="fas fa-check-circle"></i></div>
        </div>
        <div class="ko-footer"><i class="fas fa-dollar-sign"></i> Pagos procesados</div>
    </div>
    <div class="kpi-co <?php echo $total_pendiente > 0 ? 'red' : 'teal'; ?>">
        <div class="ko-label">Pendiente de Cobro</div>
        <div class="ko-top">
            <div>
                <div class="ko-value sm">RD$<?php echo number_format($total_pendiente, 0); ?></div>
                <div class="ko-sub"><?php echo ($contrato['facturas_pendientes'] + $facturas_incompletas_cnt); ?> factura(s)</div>
            </div>
            <div class="ko-icon"><i class="fas fa-clock"></i></div>
        </div>
        <div class="ko-footer">
            <i class="fas fa-exclamation-circle"></i>
            <?php echo $facturas_vencidas; ?> vencida(s), <?php echo $facturas_incompletas_cnt; ?> incompleta(s)
        </div>
    </div>
    <div class="kpi-co purple">
        <div class="ko-label">Dependientes</div>
        <div class="ko-top">
            <div>
                <div class="ko-value"><?php echo $contrato['total_dependientes']; ?></div>
                <div class="ko-sub"><?php echo $contrato['total_geriatricos']; ?> geriátrico(s)</div>
            </div>
            <div class="ko-icon"><i class="fas fa-users"></i></div>
        </div>
        <div class="ko-footer"><i class="fas fa-star"></i> Beneficiarios: <?php echo count($beneficiarios); ?></div>
    </div>
    <div class="kpi-co <?php echo $contrato['estado'] == 'activo' ? 'green' : ($contrato['estado'] == 'suspendido' ? 'amber' : 'red'); ?>">
        <div class="ko-label">Estado del Contrato</div>
        <div class="ko-top">
            <div>
                <div class="ko-value"><?php echo ucfirst($contrato['estado']); ?></div>
                <div class="ko-sub">Monto: RD$<?php echo number_format($contrato['monto_mensual'], 2); ?>/mes</div>
            </div>
            <div class="ko-icon"><i class="fas fa-shield-heart"></i></div>
        </div>
        <div class="ko-footer">
            <i class="fas fa-calendar"></i>
            Día cobro: <?php echo $contrato['dia_cobro']; ?> de cada mes
        </div>
    </div>
</div>

<!-- ============================================================
     INFORMACIÓN: CONTRATO + CLIENTE (2 columnas)
     ============================================================ -->
<div class="co-two-col fade-in delay-2">

    <!-- Contrato -->
    <div class="co-card">
        <div class="co-card-header">
            <div class="co-card-title">
                <div class="co-card-icon green"><i class="fas fa-file-contract"></i></div>
                <div>
                    <div class="co-title-text">Datos del Contrato</div>
                    <div class="co-title-sub">Información contractual</div>
                </div>
            </div>
            <span class="badge-co <?php echo $contrato['estado']; ?>">
                <i class="fas fa-circle" style="font-size:7px;"></i>
                <?php echo ucfirst($contrato['estado']); ?>
            </span>
        </div>
        <div class="co-card-body">
            <div class="info-grid-2">
                <div class="iib">
                    <div class="iib-label">N° Contrato</div>
                    <div class="iib-value mono"><?php echo str_pad($contrato['numero_contrato'], 5, '0', STR_PAD_LEFT); ?></div>
                </div>
                <div class="iib">
                    <div class="iib-label">Plan</div>
                    <div class="iib-value"><?php echo htmlspecialchars($contrato['plan_nombre']); ?></div>
                </div>
                <div class="iib">
                    <div class="iib-label">Fecha Inicio</div>
                    <div class="iib-value"><?php echo date('d/m/Y', strtotime($contrato['fecha_inicio'])); ?></div>
                </div>
                <div class="iib">
                    <div class="iib-label">Vigente Hasta</div>
                    <div class="iib-value"><?php echo $contrato['fecha_fin'] ? date('d/m/Y', strtotime($contrato['fecha_fin'])) : '—'; ?></div>
                </div>
                <div class="iib">
                    <div class="iib-label">Monto Mensual</div>
                    <div class="iib-value">RD$<?php echo number_format($contrato['monto_mensual'], 2); ?></div>
                </div>
                <div class="iib">
                    <div class="iib-label">Monto Total</div>
                    <div class="iib-value">RD$<?php echo number_format($contrato['monto_total'], 2); ?></div>
                </div>
                <div class="iib">
                    <div class="iib-label">Día de Cobro</div>
                    <div class="iib-value">Día <?php echo $contrato['dia_cobro']; ?> de cada mes</div>
                </div>
                <div class="iib">
                    <div class="iib-label">Vendedor</div>
                    <div class="iib-value"><?php echo htmlspecialchars($contrato['vendedor_nombre'] ?? '—'); ?></div>
                </div>
                <?php if (!empty($contrato['notas']) && $contrato['notas'] != 'null'): ?>
                <div class="iib full">
                    <div class="iib-label">Notas</div>
                    <div class="iib-value"><?php echo htmlspecialchars($contrato['notas']); ?></div>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Cliente -->
    <div class="co-card">
        <div class="co-card-header">
            <div class="co-card-title">
                <div class="co-card-icon blue"><i class="fas fa-user"></i></div>
                <div>
                    <div class="co-title-text">Datos del Cliente</div>
                    <div class="co-title-sub">Información del titular</div>
                </div>
            </div>
            <a href="ver_cliente.php?id=<?php echo $contrato['cliente_id']; ?>" 
               class="btn btn-secondary" style="font-size:12px;padding:6px 12px;">
                <i class="fas fa-external-link-alt"></i> Ver cliente
            </a>
        </div>
        <div class="co-card-body">
            <div class="info-grid-2">
                <div class="iib">
                    <div class="iib-label">Código</div>
                    <div class="iib-value mono">
                        <a href="ver_cliente.php?id=<?php echo $contrato['cliente_id']; ?>">
                            <?php echo htmlspecialchars($contrato['cliente_codigo']); ?>
                        </a>
                    </div>
                </div>
                <div class="iib">
                    <div class="iib-label">Nombre Completo</div>
                    <div class="iib-value"><?php echo htmlspecialchars($contrato['cliente_nombre'] . ' ' . $contrato['cliente_apellidos']); ?></div>
                </div>
                <div class="iib">
                    <div class="iib-label">Cédula</div>
                    <div class="iib-value mono"><?php echo htmlspecialchars($contrato['cliente_cedula'] ?? '—'); ?></div>
                </div>
                <div class="iib">
                    <div class="iib-label">Email</div>
                    <div class="iib-value">
                        <?php if ($contrato['cliente_email']): ?>
                            <a href="mailto:<?php echo htmlspecialchars($contrato['cliente_email']); ?>">
                                <?php echo htmlspecialchars($contrato['cliente_email']); ?>
                            </a>
                        <?php else: ?> — <?php endif; ?>
                    </div>
                </div>
                <div class="iib">
                    <div class="iib-label">Teléfonos</div>
                    <div class="iib-value">
                        <?php
                        $tels = array_filter([
                            $contrato['cliente_telefono1'] ?? '',
                            $contrato['cliente_telefono2'] ?? '',
                            $contrato['cliente_telefono3'] ?? ''
                        ]);
                        echo $tels ? htmlspecialchars(implode(' / ', $tels)) : '—';
                        ?>
                    </div>
                </div>
                <div class="iib full">
                    <div class="iib-label">Dirección</div>
                    <div class="iib-value"><?php echo htmlspecialchars($contrato['cliente_direccion'] ?? '—'); ?></div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- ============================================================
     DEPENDIENTES
     ============================================================ -->
<div class="co-card fade-in delay-2">
    <div class="co-card-header">
        <div class="co-card-title">
            <div class="co-card-icon purple"><i class="fas fa-users"></i></div>
            <div>
                <div class="co-title-text">Dependientes del Contrato</div>
                <div class="co-title-sub">
                    <?php echo count($dependientes); ?> activo(s) &mdash;
                    <?php echo $contrato['total_geriatricos']; ?> geriátrico(s)
                </div>
            </div>
        </div>
    </div>
    <div class="co-card-body">
        <?php if (empty($dependientes)): ?>
            <div class="empty-state">
                <i class="fas fa-users"></i>
                <p>No hay dependientes activos en este contrato.</p>
            </div>
        <?php else: ?>
        <div class="dep-grid">
            <?php foreach ($dependientes as $dep):
                $edad = date_diff(date_create($dep['fecha_nacimiento']), date_create('today'))->y;
                $esGer = $edad >= 65;
            ?>
            <div class="dep-card">
                <div class="dep-card-header">
                    <div>
                        <div class="dep-card-name"><?php echo htmlspecialchars($dep['nombre'] . ' ' . $dep['apellidos']); ?></div>
                        <div class="dep-card-rel"><?php echo htmlspecialchars($dep['relacion']); ?></div>
                    </div>
                    <span class="dep-age-badge <?php echo $esGer ? 'geriatrico' : 'normal'; ?>">
                        <?php echo $edad; ?> años
                    </span>
                </div>
                <div class="dep-info-row">
                    <i class="fas fa-shield-heart"></i>
                    <span><strong>Plan:</strong> <?php echo htmlspecialchars($dep['plan_nombre']); ?></span>
                </div>
                <div class="dep-info-row">
                    <i class="fas fa-dollar-sign"></i>
                    <span><strong>Costo:</strong> RD$<?php echo number_format($dep['precio_base'], 2); ?></span>
                </div>
                <div class="dep-info-row">
                    <i class="fas fa-calendar"></i>
                    <span><strong>Ingreso:</strong> <?php echo $dep['fecha_registro_formateada']; ?></span>
                </div>
                <?php if (!empty($dep['identificacion'])): ?>
                <div class="dep-info-row">
                    <i class="fas fa-id-card"></i>
                    <span><?php echo htmlspecialchars($dep['identificacion']); ?></span>
                </div>
                <?php endif; ?>
                <?php if ($dep['total_cambios_plan'] > 0): ?>
                <div style="font-size:10.5px;color:var(--gray-400);margin-top:3px;">
                    <i class="fas fa-history"></i> <?php echo $dep['total_cambios_plan']; ?> cambio(s) de plan
                </div>
                <?php endif; ?>
                <div class="dep-actions">
                    <button class="btn-dep edit" onclick="abrirEditarDependiente(<?php echo htmlspecialchars(json_encode($dep)); ?>)">
                        <i class="fas fa-edit"></i> Editar
                    </button>
                    <button class="btn-dep history" onclick="verHistorialPlanDep(<?php echo $dep['id']; ?>, '<?php echo htmlspecialchars($dep['nombre'] . ' ' . $dep['apellidos']); ?>')">
                        <i class="fas fa-history"></i> Historial
                    </button>
                    <button class="btn-dep delete" onclick="eliminarDependiente(<?php echo $dep['id']; ?>)">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
    </div>
</div>

<!-- ============================================================
     BENEFICIARIOS
     ============================================================ -->
<div class="co-card fade-in delay-3">
    <div class="co-card-header">
        <div class="co-card-title">
            <div class="co-card-icon red"><i class="fas fa-heart"></i></div>
            <div>
                <div class="co-title-text">Beneficiarios</div>
                <div class="co-title-sub"><?php echo count($beneficiarios); ?> beneficiario(s) registrado(s)</div>
            </div>
        </div>
    </div>
    <div class="co-card-body">
        <?php if (empty($beneficiarios)): ?>
            <div class="empty-state">
                <i class="fas fa-heart"></i>
                <p>No hay beneficiarios registrados en este contrato.</p>
            </div>
        <?php else: ?>
        <div class="ben-grid">
            <?php foreach ($beneficiarios as $ben): ?>
            <div class="ben-card">
                <div class="ben-card-name">
                    <i class="fas fa-user" style="color:var(--accent);margin-right:6px;"></i>
                    <?php echo htmlspecialchars($ben['nombre'] . ' ' . $ben['apellidos']); ?>
                </div>
                <div class="ben-row">
                    <span>Parentesco:</span>
                    <strong><?php echo htmlspecialchars($ben['parentesco']); ?></strong>
                </div>
                <div class="ben-row">
                    <span>F. Nacimiento:</span>
                    <strong><?php echo $ben['fecha_nacimiento'] ? date('d/m/Y', strtotime($ben['fecha_nacimiento'])) : '—'; ?></strong>
                </div>
                <div class="ben-row" style="align-items:flex-start;margin-top:8px;">
                    <span style="font-size:11px;color:var(--gray-400);">Porcentaje</span>
                    <div class="ben-pct"><?php echo number_format($ben['porcentaje'], 0); ?>%</div>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
    </div>
</div>

<!-- ============================================================
     FACTURAS DEL CONTRATO
     ============================================================ -->
<div class="co-card fade-in delay-3">
    <div class="co-card-header">
        <div class="co-card-title">
            <div class="co-card-icon amber"><i class="fas fa-file-invoice-dollar"></i></div>
            <div>
                <div class="co-title-text">Facturas del Contrato</div>
                <div class="co-title-sub"><?php echo count($facturas); ?> facturas generadas</div>
            </div>
        </div>
        <a href="facturacion.php?numero_contrato=<?php echo urlencode($contrato['numero_contrato']); ?>" 
           class="btn btn-secondary" style="font-size:12px;padding:6px 12px;">
            <i class="fas fa-external-link-alt"></i> Ver todas
        </a>
    </div>
    <div class="co-card-body" style="padding:0;">
        <?php if (empty($facturas)): ?>
            <div class="empty-state">
                <i class="fas fa-file-invoice"></i>
                <p>No hay facturas generadas para este contrato.</p>
            </div>
        <?php else: ?>
        <div class="co-table-wrap">
            <table class="co-table">
                <thead>
                    <tr>
                        <th>N° Factura</th>
                        <th>Período</th>
                        <th>Emisión</th>
                        <th>Vencimiento</th>
                        <th>Monto</th>
                        <th>Abonado</th>
                        <th>Pendiente</th>
                        <th>Estado</th>
                        <th>Historial</th>
                        <th>Acciones</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($facturas as $factura):
                        $montoPend = max(0, $factura['monto'] - ($factura['total_abonado'] ?? 0));
                    ?>
                    <tr>
                        <td class="td-num">
                            <a href="ver_factura.php?id=<?php echo $factura['id']; ?>">
                                <?php echo htmlspecialchars($factura['numero_factura']); ?>
                            </a>
                        </td>
                        <td><?php echo htmlspecialchars($factura['mes_factura']); ?></td>
                        <td class="td-muted"><?php echo date('d/m/Y', strtotime($factura['fecha_emision'])); ?></td>
                        <td class="td-muted"><?php echo date('d/m/Y', strtotime($factura['fecha_vencimiento'])); ?></td>
                        <td class="td-amount">RD$<?php echo number_format($factura['monto'], 2); ?></td>
                        <td>
                            <?php if ($factura['total_abonado'] > 0): ?>
                                <span class="td-green">RD$<?php echo number_format($factura['total_abonado'], 2); ?></span>
                            <?php else: ?><span class="td-muted">—</span><?php endif; ?>
                        </td>
                        <td>
                            <?php if ($montoPend > 0): ?>
                                <span class="td-red">RD$<?php echo number_format($montoPend, 2); ?></span>
                            <?php else: ?><span class="td-muted">—</span><?php endif; ?>
                        </td>
                        <td>
                            <span class="badge-co <?php echo $factura['estado']; ?>">
                                <?php echo ucfirst($factura['estado']); ?>
                            </span>
                        </td>
                        <td>
                            <?php if (!empty($pagos_desglosados[$factura['id']])): ?>
                            <button class="btn-tbl hist" title="Ver historial de pagos"
                                onclick="mostrarHistorialPagos(<?php echo htmlspecialchars(json_encode($pagos_desglosados[$factura['id']])); ?>, '<?php echo htmlspecialchars($factura['numero_factura']); ?>')">
                                <i class="fas fa-history"></i>
                            </button>
                            <?php else: ?><span class="td-muted">—</span><?php endif; ?>
                        </td>
                        <td>
                            <div class="tbl-actions">
                                <a href="ver_factura.php?id=<?php echo $factura['id']; ?>" class="btn-tbl view" title="Ver factura">
                                    <i class="fas fa-eye"></i>
                                </a>
                                <?php if (!in_array($factura['estado'], ['pagada', 'anulada'])): ?>
                                <a href="registrar_pago.php?factura_id=<?php echo $factura['id']; ?>" class="btn-tbl pay" title="Registrar pago">
                                    <i class="fas fa-dollar-sign"></i>
                                </a>
                                <?php endif; ?>
                                <a href="imprimir_factura.php?id=<?php echo $factura['id']; ?>&tipo=preview" class="btn-tbl print" title="Imprimir" target="_blank">
                                    <i class="fas fa-print"></i>
                                </a>
                            </div>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>
    </div>
</div>

<!-- ============================================================
     HISTORIAL DE PAGOS
     ============================================================ -->
<?php if (!empty($pagos)): ?>
<div class="co-card fade-in delay-4">
    <div class="co-card-header">
        <div class="co-card-title">
            <div class="co-card-icon teal"><i class="fas fa-money-bill-wave"></i></div>
            <div>
                <div class="co-title-text">Historial de Pagos</div>
                <div class="co-title-sub">Últimos <?php echo count($pagos); ?> pagos procesados</div>
            </div>
        </div>
    </div>
    <div class="co-card-body" style="padding:0;">
        <div class="co-table-wrap">
            <table class="co-table">
                <thead>
                    <tr>
                        <th>Fecha</th>
                        <th>N° Factura</th>
                        <th>Período</th>
                        <th>Monto</th>
                        <th>Tipo</th>
                        <th>Método</th>
                        <th>Referencia</th>
                        <th>Cobrador</th>
                        <th>Acciones</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($pagos as $pago): ?>
                    <tr>
                        <td class="td-muted"><?php echo date('d/m/Y H:i', strtotime($pago['fecha_pago'])); ?></td>
                        <td class="td-num"><?php echo htmlspecialchars($pago['numero_factura']); ?></td>
                        <td><?php echo htmlspecialchars($pago['mes_factura']); ?></td>
                        <td class="td-amount">RD$<?php echo number_format($pago['monto'], 2); ?></td>
                        <td>
                            <span class="badge-co <?php echo $pago['tipo_pago']; ?>">
                                <?php echo ucfirst($pago['tipo_pago']); ?>
                            </span>
                        </td>
                        <td><?php echo ucfirst($pago['metodo_pago']); ?></td>
                        <td class="td-muted"><?php echo htmlspecialchars($pago['referencia_pago'] ?? '—'); ?></td>
                        <td><?php echo htmlspecialchars($pago['cobrador_nombre'] ?? '—'); ?></td>
                        <td>
                            <div class="tbl-actions">
                                <button class="btn-tbl view" title="Ver comprobante" onclick="verComprobante(<?php echo $pago['id']; ?>)">
                                    <i class="fas fa-receipt"></i>
                                </button>
                            </div>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>
<?php endif; ?>


<!-- ============================================================
     MODAL: HISTORIAL DE PAGOS (por factura)
     ============================================================ -->
<div class="modal-overlay-co" id="modalHistPagos">
    <div class="modal-box-co">
        <div class="mhdr-co">
            <div style="display:flex;align-items:center;gap:10px;">
                <div class="co-card-icon teal" style="width:34px;height:34px;font-size:14px;">
                    <i class="fas fa-history"></i>
                </div>
                <div>
                    <div style="font-size:14px;font-weight:700;color:var(--gray-800);">Historial de Pagos</div>
                    <div id="histPagosFactura" style="font-size:11.5px;color:var(--gray-500);">Factura</div>
                </div>
            </div>
            <button class="modal-close-co" onclick="cerrarModalHistPagos()">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="mbody-co">
            <ul class="lista-pagos" id="listaPagos"></ul>
        </div>
    </div>
</div>


<!-- ============================================================
     MODAL: HISTORIAL DE PLAN (dependiente)
     ============================================================ -->
<div class="modal-overlay-hp" id="modalHistPlanDep">
    <div class="modal-box-hp">
        <div class="mhdr-hp">
            <div style="display:flex;align-items:center;gap:10px;">
                <div class="co-card-icon green" style="width:34px;height:34px;font-size:14px;">
                    <i class="fas fa-history"></i>
                </div>
                <div>
                    <div style="font-size:14px;font-weight:700;color:var(--gray-800);">Historial de Cambios de Plan</div>
                    <div id="histPlanDepNombre" style="font-size:11.5px;color:var(--gray-500);">Dependiente</div>
                </div>
            </div>
            <button class="modal-close-co" onclick="cerrarModalHistPlan()">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="mbody-hp" id="histPlanDepBody">
            <div class="spinner-co"></div>
        </div>
    </div>
</div>


<!-- ============================================================
     MODAL: EDITAR DEPENDIENTE
     ============================================================ -->
<div class="modal-overlay-dep" id="modalEditarDep">
    <div class="modal-box-dep">
        <div class="mhdr-dep">
            <div style="display:flex;align-items:center;gap:10px;">
                <div class="co-card-icon purple" style="width:34px;height:34px;font-size:14px;">
                    <i class="fas fa-user-edit"></i>
                </div>
                <div>
                    <div style="font-size:14px;font-weight:700;color:var(--gray-800);">Editar Dependiente</div>
                    <div style="font-size:11.5px;color:var(--gray-500);">Modifique los datos del dependiente</div>
                </div>
            </div>
            <button class="modal-close-co" onclick="cerrarModalDep()">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <form id="formEditarDep">
            <div class="mbody-dep">
                <input type="hidden" name="action" value="update">
                <input type="hidden" name="id" id="dep_edit_id">
                <input type="hidden" name="contrato_id" id="dep_edit_contrato_id">

                <div class="form-row-dep">
                    <div class="form-group-dep">
                        <label>Nombre *</label>
                        <input type="text" name="nombre" id="dep_edit_nombre" required>
                    </div>
                    <div class="form-group-dep">
                        <label>Apellidos *</label>
                        <input type="text" name="apellidos" id="dep_edit_apellidos" required>
                    </div>
                </div>
                <div class="form-row-dep">
                    <div class="form-group-dep">
                        <label>Relación *</label>
                        <input type="text" name="relacion" id="dep_edit_relacion" required>
                    </div>
                    <div class="form-group-dep">
                        <label>Identificación</label>
                        <input type="text" name="identificacion" id="dep_edit_identificacion">
                    </div>
                </div>
                <div class="form-row-dep">
                    <div class="form-group-dep">
                        <label>Fecha Nacimiento *</label>
                        <input type="date" name="fecha_nacimiento" id="dep_edit_fecha_nac" required>
                    </div>
                    <div class="form-group-dep">
                        <label>Fecha Registro</label>
                        <input type="date" name="fecha_registro" id="dep_edit_fecha_reg">
                    </div>
                </div>
                <div class="form-row-dep">
                    <div class="form-group-dep">
                        <label>Teléfono</label>
                        <input type="text" name="telefono" id="dep_edit_telefono">
                    </div>
                    <div class="form-group-dep">
                        <label>Email</label>
                        <input type="email" name="email" id="dep_edit_email">
                    </div>
                </div>
                <div class="form-row-dep">
                    <div class="form-group-dep">
                        <label>Plan *</label>
                        <select name="plan_id" id="dep_edit_plan" required>
                            <?php foreach ($planes_disponibles as $plan): ?>
                            <option value="<?php echo $plan['id']; ?>">
                                <?php echo htmlspecialchars($plan['nombre']); ?> — RD$<?php echo number_format($plan['precio_base'], 2); ?>
                            </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-group-dep">
                        <label>Estado</label>
                        <select name="estado" id="dep_edit_estado">
                            <option value="activo">Activo</option>
                            <option value="inactivo">Inactivo</option>
                        </select>
                    </div>
                </div>
            </div>
            <div class="mfooter-dep">
                <button type="button" class="btn btn-secondary" onclick="cerrarModalDep()">
                    <i class="fas fa-times"></i> Cancelar
                </button>
                <button type="submit" class="btn btn-primary" id="btnGuardarDep">
                    <i class="fas fa-save"></i> Guardar Cambios
                </button>
            </div>
        </form>
    </div>
</div>


<!-- ============================================================
     SCRIPTS
     ============================================================ -->
<script>
// ── Comprobante ──
function verComprobante(id) {
    window.open('ver_comprobante.php?id=' + id, '_blank');
}

// ── Modal Historial de Pagos (por factura) ──
function mostrarHistorialPagos(pagos, numFactura) {
    document.getElementById('histPagosFactura').textContent = 'Factura ' + (numFactura || '');
    const lista = document.getElementById('listaPagos');
    lista.innerHTML = pagos.map(p => '<li><i class="fas fa-check-circle" style="color:#16A34A;"></i>' + esc(p) + '</li>').join('');
    document.getElementById('modalHistPagos').classList.add('show');
}
function cerrarModalHistPagos() {
    document.getElementById('modalHistPagos').classList.remove('show');
}

// ── Modal Historial Plan Dependiente ──
function verHistorialPlanDep(depId, nombre) {
    document.getElementById('histPlanDepNombre').textContent = nombre || 'Dependiente';
    document.getElementById('histPlanDepBody').innerHTML = '<div class="spinner-co"></div>';
    document.getElementById('modalHistPlanDep').classList.add('show');

    fetch('historial_plan_dependiente.php?id=' + depId)
        .then(r => r.json())
        .then(data => {
            if (!data.success) {
                document.getElementById('histPlanDepBody').innerHTML =
                    '<div class="hist-empty"><i class="fas fa-exclamation-circle"></i><p>' + esc(data.message || 'Error') + '</p></div>';
                return;
            }
            if (!data.data || data.data.length === 0) {
                document.getElementById('histPlanDepBody').innerHTML =
                    '<div class="hist-empty"><i class="fas fa-history"></i><p>No hay cambios de plan registrados para este dependiente.</p></div>';
                return;
            }
            let html = '<div class="hist-timeline">';
            data.data.forEach(function(h) {
                const fecha = new Date(h.fecha_cambio);
                const fechaFmt = fecha.toLocaleDateString('es-DO', {day:'2-digit',month:'short',year:'numeric'}) + ' ' +
                                 fecha.toLocaleTimeString('es-DO', {hour:'2-digit',minute:'2-digit'});
                const diff = parseFloat(h.diferencia_precio);
                let diffHtml = '';
                if (diff > 0) diffHtml = '<div style="font-size:11.5px;font-weight:700;color:#16A34A;margin-top:5px;"><i class="fas fa-arrow-up"></i> Aumento RD$' + Math.abs(diff).toFixed(2) + '/mes</div>';
                else if (diff < 0) diffHtml = '<div style="font-size:11.5px;font-weight:700;color:#DC2626;margin-top:5px;"><i class="fas fa-arrow-down"></i> Reducción RD$' + Math.abs(diff).toFixed(2) + '/mes</div>';

                html += '<div class="hist-item">' +
                    '<div class="hist-item-header">' +
                        '<span class="hist-item-date"><i class="fas fa-clock" style="margin-right:4px;"></i>' + fechaFmt + '</span>' +
                        '<span class="hist-item-user"><i class="fas fa-user" style="margin-right:3px;"></i>' + esc(h.usuario_nombre) + '</span>' +
                    '</div>' +
                    '<div class="hist-item-body">' +
                        '<div class="hist-plan-change">' +
                            '<span class="hist-plan-name anterior">' + esc(h.plan_anterior_nombre) + ' — RD$' + parseFloat(h.plan_anterior_precio).toFixed(2) + '</span>' +
                            '<i class="fas fa-arrow-right" style="color:var(--gray-400);"></i>' +
                            '<span class="hist-plan-name nuevo">' + esc(h.plan_nuevo_nombre) + ' — RD$' + parseFloat(h.plan_nuevo_precio).toFixed(2) + '</span>' +
                            (h.es_cambio_geriatrico ? '<span style="background:#FEF3C7;color:#92400E;padding:2px 8px;border-radius:20px;font-size:10.5px;font-weight:700;"><i class="fas fa-star"></i> Geriátrico</span>' : '') +
                        '</div>' +
                        diffHtml +
                        '<div class="hist-motivo"><strong>Motivo:</strong> ' + esc(h.motivo) + '</div>' +
                    '</div>' +
                '</div>';
            });
            html += '</div>';
            document.getElementById('histPlanDepBody').innerHTML = html;
        })
        .catch(() => {
            document.getElementById('histPlanDepBody').innerHTML =
                '<div class="hist-empty"><i class="fas fa-exclamation-triangle"></i><p>Error de comunicación al cargar el historial.</p></div>';
        });
}
function cerrarModalHistPlan() {
    document.getElementById('modalHistPlanDep').classList.remove('show');
}

// ── Modal Editar Dependiente ──
function abrirEditarDependiente(dep) {
    document.getElementById('dep_edit_id').value          = dep.id;
    document.getElementById('dep_edit_contrato_id').value = dep.contrato_id;
    document.getElementById('dep_edit_nombre').value      = dep.nombre;
    document.getElementById('dep_edit_apellidos').value   = dep.apellidos;
    document.getElementById('dep_edit_relacion').value    = dep.relacion;
    document.getElementById('dep_edit_identificacion').value = dep.identificacion || '';
    document.getElementById('dep_edit_fecha_nac').value   = dep.fecha_nacimiento ? dep.fecha_nacimiento.split(' ')[0] : '';
    document.getElementById('dep_edit_fecha_reg').value   = dep.fecha_registro || '';
    document.getElementById('dep_edit_telefono').value    = dep.telefono || '';
    document.getElementById('dep_edit_email').value       = dep.email || '';
    document.getElementById('dep_edit_plan').value        = dep.plan_id;
    document.getElementById('dep_edit_estado').value      = dep.estado || 'activo';
    document.getElementById('modalEditarDep').classList.add('show');
}
function cerrarModalDep() {
    document.getElementById('modalEditarDep').classList.remove('show');
}

document.getElementById('formEditarDep').addEventListener('submit', function(e) {
    e.preventDefault();
    const btn = document.getElementById('btnGuardarDep');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Guardando…';
    fetch('dependientes.php', { method: 'POST', body: new FormData(this) })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                cerrarModalDep();
                mostrarToast(data.message || 'Dependiente actualizado.', 'success');
                setTimeout(() => location.reload(), 1200);
            } else {
                mostrarToast(data.message || 'Error al actualizar.', 'error');
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-save"></i> Guardar Cambios';
            }
        })
        .catch(() => {
            mostrarToast('Error de comunicación.', 'error');
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-save"></i> Guardar Cambios';
        });
});

// ── Eliminar Dependiente ──
function eliminarDependiente(depId) {
    Swal.fire({
        title: '¿Eliminar dependiente?',
        text: 'Esta acción lo marcará como inactivo.',
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#DC2626',
        cancelButtonColor: '#64748B',
        confirmButtonText: '<i class="fas fa-trash"></i> Sí, eliminar',
        cancelButtonText: 'Cancelar'
    }).then(result => {
        if (result.isConfirmed) {
            const fd = new FormData();
            fd.append('action', 'delete');
            fd.append('id', depId);
            fetch('dependientes.php', { method: 'POST', body: fd })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        mostrarToast('Dependiente eliminado.', 'success');
                        setTimeout(() => location.reload(), 1200);
                    } else {
                        mostrarToast(data.message || 'Error al eliminar.', 'error');
                    }
                })
                .catch(() => mostrarToast('Error de comunicación.', 'error'));
        }
    });
}

// ── Escape ──
function esc(str) {
    if (!str) return '—';
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Toast ──
function mostrarToast(mensaje, tipo = 'info', duracion = 4000) {
    Toastify({
        text: mensaje, duration: duracion, close: true,
        gravity: 'top', position: 'right',
        backgroundColor: tipo === 'success' ? '#28a745' :
                        (tipo === 'error'   ? '#dc3545' :
                        (tipo === 'warning' ? '#ffc107' : '#17a2b8')),
        stopOnFocus: true
    }).showToast();
}

// ── Cerrar modales con Escape y clic en overlay ──
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        cerrarModalHistPagos();
        cerrarModalHistPlan();
        cerrarModalDep();
    }
});
['modalHistPagos','modalHistPlanDep','modalEditarDep'].forEach(function(id) {
    document.getElementById(id).addEventListener('click', function(e) {
        if (e.target === this) {
            cerrarModalHistPagos();
            cerrarModalHistPlan();
            cerrarModalDep();
        }
    });
});

<?php if (!empty($mensaje_toast)): ?>
document.addEventListener('DOMContentLoaded', function() {
    mostrarToast('<?php echo addslashes($mensaje_toast); ?>', '<?php echo $tipo_toast; ?>');
});
<?php endif; ?>
</script>

<?php require_once 'footer.php'; ?>