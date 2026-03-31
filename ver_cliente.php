<?php
require_once 'header.php';

error_reporting(E_ALL);
ini_set('display_errors', 1);

if (!isset($_GET['id'])) {
    header('Location: clientes.php');
    exit();
}

$id = (int)$_GET['id'];

// Obtener datos del cliente con estadísticas
$stmt = $conn->prepare("
    SELECT 
        c.*,
        (SELECT COUNT(DISTINCT id) FROM contratos WHERE cliente_id = c.id) as total_contratos,
        (
            SELECT COUNT(DISTINCT f.id) 
            FROM contratos con 
            JOIN facturas f ON con.id = f.contrato_id 
            WHERE con.cliente_id = c.id
        ) as total_facturas,
        (
            SELECT COUNT(DISTINCT d.id) 
            FROM contratos con
            JOIN dependientes d ON d.contrato_id = con.id 
            WHERE con.cliente_id = c.id AND d.estado = 'activo'
        ) as total_dependientes,
        COALESCE(
            (
                SELECT SUM(f.monto)
                FROM contratos con 
                JOIN facturas f ON con.id = f.contrato_id 
                WHERE con.cliente_id = c.id 
                AND f.estado IN ('pendiente', 'vencida', 'incompleta')
            ), 0
        ) as total_pendiente,
        COALESCE(
            (
                SELECT SUM(p.monto)
                FROM contratos con 
                JOIN facturas f ON con.id = f.contrato_id
                JOIN pagos p ON f.id = p.factura_id
                WHERE con.cliente_id = c.id 
                AND p.estado = 'procesado'
                AND p.tipo_pago = 'abono'
            ), 0
        ) as total_abonado,
        (
            SELECT COUNT(DISTINCT f.id)
            FROM contratos con 
            JOIN facturas f ON con.id = f.contrato_id 
            WHERE con.cliente_id = c.id 
            AND f.estado = 'incompleta'
        ) as facturas_incompletas
    FROM clientes c
    WHERE c.id = ?
");
$stmt->execute([$id]);
$cliente = $stmt->fetch();

if (!$cliente) {
    header('Location: clientes.php');
    exit();
}

// Obtener contratos del cliente
$stmt = $conn->prepare("
    SELECT c.*, 
           p.nombre as plan_nombre,
           (SELECT COUNT(f.id) FROM facturas f WHERE f.contrato_id = c.id AND f.estado IN ('pendiente', 'vencida', 'incompleta')) as facturas_pendientes,
           (SELECT COUNT(f.id) FROM facturas f WHERE f.contrato_id = c.id AND f.estado = 'incompleta') as facturas_incompletas,
           (SELECT SUM(pg.monto) FROM facturas f JOIN pagos pg ON f.id = pg.factura_id WHERE f.contrato_id = c.id AND pg.estado = 'procesado' AND pg.tipo_pago = 'abono') as total_abonado
    FROM contratos c
    JOIN planes p ON c.plan_id = p.id 
    WHERE cliente_id = ? 
    ORDER BY fecha_inicio DESC
");
$stmt->execute([$id]);
$contratos = $stmt->fetchAll();

// Obtener últimas facturas
$stmt = $conn->prepare("
    SELECT f.*,
           c.numero_contrato,
           (SELECT SUM(p.monto) FROM pagos p WHERE p.factura_id = f.id AND p.estado = 'procesado' AND p.tipo_pago = 'abono') as total_abonado,
           (SELECT COUNT(p.id) FROM pagos p WHERE p.factura_id = f.id AND p.estado = 'procesado') as total_pagos
    FROM facturas f
    JOIN contratos c ON f.contrato_id = c.id
    WHERE c.cliente_id = ?
    ORDER BY f.fecha_emision DESC
    LIMIT 12
");
$stmt->execute([$id]);
$facturas = $stmt->fetchAll();

// Obtener dependientes
$stmt = $conn->prepare("
    SELECT d.*,
           p.nombre as plan_nombre,
           p.precio_base,
           DATE_FORMAT(d.fecha_registro, '%d/%m/%Y') as fecha_registro_formateada,
           (SELECT COUNT(*) FROM historial_cambios_plan_dependientes h WHERE h.dependiente_id = d.id) as total_cambios_plan
    FROM contratos c
    JOIN dependientes d ON d.contrato_id = c.id
    JOIN planes p ON d.plan_id = p.id
    WHERE c.cliente_id = ? AND d.estado = 'activo'
    ORDER BY d.nombre, d.apellidos
");
$stmt->execute([$id]);
$dependientes = $stmt->fetchAll();

// Obtener planes disponibles para el modal de edición
$stmt = $conn->query("SELECT id, nombre, precio_base FROM planes WHERE estado = 'activo' ORDER BY nombre");
$planes_disponibles = $stmt->fetchAll();

// Obtener historial de pagos recientes
$stmt = $conn->prepare("
    SELECT p.*,
           f.numero_factura,
           c.numero_contrato,
           u.nombre as cobrador_nombre
    FROM pagos p
    JOIN facturas f ON p.factura_id = f.id
    JOIN contratos c ON f.contrato_id = c.id
    LEFT JOIN usuarios u ON p.cobrador_id = u.id
    WHERE c.cliente_id = ? AND p.estado = 'procesado'
    ORDER BY p.fecha_pago DESC
    LIMIT 10
");
$stmt->execute([$id]);
$pagos_recientes = $stmt->fetchAll();

// Calcular estadísticas adicionales
$total_monto_pendiente = 0;
$total_abonado_calc = 0;
foreach ($facturas as $factura) {
    if ($factura['estado'] === 'incompleta') {
        $total_monto_pendiente += $factura['monto'] - ($factura['total_abonado'] ?? 0);
    } elseif (in_array($factura['estado'], ['pendiente', 'vencida'])) {
        $total_monto_pendiente += $factura['monto'];
    }
    $total_abonado_calc += $factura['total_abonado'] ?? 0;
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
.kpi-cliente-row{display:grid;grid-template-columns:repeat(6,1fr);gap:16px;margin-bottom:24px;}
@media(max-width:1200px){.kpi-cliente-row{grid-template-columns:repeat(3,1fr);}}
@media(max-width:700px){.kpi-cliente-row{grid-template-columns:repeat(2,1fr);}}
@media(max-width:430px){.kpi-cliente-row{grid-template-columns:1fr;}}
.kpi-c{border-radius:var(--radius);padding:18px 18px 14px;position:relative;
    overflow:hidden;box-shadow:var(--shadow);transition:var(--transition);color:white;}
.kpi-c:hover{transform:translateY(-3px);box-shadow:var(--shadow-md);}
.kpi-c::before{content:'';position:absolute;top:0;right:0;width:60px;height:60px;
    border-radius:0 var(--radius) 0 100%;opacity:.15;background:white;}
.kpi-c.blue  {background:linear-gradient(135deg,#1565C0,#1976D2);}
.kpi-c.green {background:linear-gradient(135deg,#1B5E20,#2E7D32);}
.kpi-c.amber {background:linear-gradient(135deg,#E65100,#F57F17);}
.kpi-c.red   {background:linear-gradient(135deg,#B71C1C,#C62828);}
.kpi-c.teal  {background:linear-gradient(135deg,#00695C,#00897B);}
.kpi-c.purple{background:linear-gradient(135deg,#4A148C,#6A1B9A);}
.kpi-c .kc-label{font-size:10px;font-weight:600;color:rgba(255,255,255,.80);
    text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px;}
.kpi-c .kc-value{font-size:22px;font-weight:800;color:white;line-height:1.1;margin-bottom:3px;}
.kpi-c .kc-sub{font-size:10.5px;color:rgba(255,255,255,.70);}
.kpi-c .kc-icon{position:absolute;bottom:14px;right:16px;font-size:28px;
    color:rgba(255,255,255,.20);}

/* ── Cards / Bloques ── */
.vc-card{background:var(--white);border-radius:var(--radius);
    box-shadow:var(--shadow);margin-bottom:20px;overflow:hidden;}
.vc-card-header{padding:16px 22px;border-bottom:1px solid var(--gray-200);
    display:flex;align-items:center;justify-content:space-between;gap:12px;}
.vc-card-title{display:flex;align-items:center;gap:10px;}
.vc-card-icon{width:36px;height:36px;border-radius:var(--radius-sm);
    display:flex;align-items:center;justify-content:center;font-size:15px;color:white;}
.vc-card-icon.blue   {background:linear-gradient(135deg,#1565C0,#1976D2);}
.vc-card-icon.green  {background:linear-gradient(135deg,#1B5E20,#2E7D32);}
.vc-card-icon.amber  {background:linear-gradient(135deg,#E65100,#F57F17);}
.vc-card-icon.red    {background:linear-gradient(135deg,#B71C1C,#C62828);}
.vc-card-icon.teal   {background:linear-gradient(135deg,#00695C,#00897B);}
.vc-card-icon.purple {background:linear-gradient(135deg,#4A148C,#6A1B9A);}
.vc-card-icon.gray   {background:linear-gradient(135deg,#455A64,#607D8B);}
.vc-title-text{font-size:14px;font-weight:700;color:var(--gray-800);}
.vc-title-sub{font-size:11px;color:var(--gray-500);margin-top:1px;}
.vc-card-body{padding:20px 22px;}

/* ── Info Grid ── */
.info-grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;}
.info-grid-2{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;}
@media(max-width:900px){.info-grid-3{grid-template-columns:repeat(2,1fr);}}
@media(max-width:600px){.info-grid-3,.info-grid-2{grid-template-columns:1fr;}}
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
.badge-vc{display:inline-flex;align-items:center;gap:4px;padding:3px 10px;
    border-radius:20px;font-size:11px;font-weight:700;}
.badge-vc.activo    {background:#DCFCE7;color:#166534;}
.badge-vc.inactivo  {background:#FEE2E2;color:#991B1B;}
.badge-vc.suspendido{background:#FEF3C7;color:#92400E;}
.badge-vc.pendiente {background:#FEF3C7;color:#B45309;}
.badge-vc.pagada    {background:#DCFCE7;color:#15803D;}
.badge-vc.incompleta{background:#EDE9FE;color:#7C3AED;}
.badge-vc.vencida   {background:#FEE2E2;color:#DC2626;}
.badge-vc.cancelado {background:var(--gray-100);color:var(--gray-500);}
.badge-vc.total     {background:#DCFCE7;color:#15803D;}
.badge-vc.abono     {background:#DBEAFE;color:#1E40AF;}

/* ── Dependientes Grid ── */
.dep-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px;}
.dep-card{background:var(--white);border:1px solid var(--gray-200);
    border-radius:var(--radius);padding:16px;transition:var(--transition);}
.dep-card:hover{box-shadow:var(--shadow);border-color:var(--accent);}
.dep-card-header{display:flex;justify-content:space-between;align-items:flex-start;
    margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid var(--gray-100);}
.dep-card-name{font-size:13.5px;font-weight:700;color:var(--gray-800);margin-bottom:3px;}
.dep-card-rel{font-size:11px;color:var(--gray-500);}
.dep-age-badge{padding:4px 10px;border-radius:20px;font-size:11px;font-weight:700;flex-shrink:0;}
.dep-age-badge.geriatrico{background:#FEF3C7;color:#B45309;}
.dep-age-badge.normal{background:#DBEAFE;color:#1E40AF;}
.dep-info-row{display:flex;align-items:center;gap:6px;font-size:12px;
    color:var(--gray-600);margin-bottom:5px;}
.dep-info-row i{width:14px;color:var(--gray-400);}
.dep-actions{display:flex;gap:6px;margin-top:12px;padding-top:10px;
    border-top:1px solid var(--gray-100);}
.dep-actions .btn-dep{height:30px;padding:0 12px;border-radius:var(--radius-sm);
    border:none;display:inline-flex;align-items:center;gap:5px;font-size:11.5px;
    font-weight:600;cursor:pointer;transition:var(--transition);text-decoration:none;}
.dep-actions .btn-dep:hover{transform:translateY(-1px);box-shadow:var(--shadow-sm);}
.dep-actions .btn-dep.edit   {background:#EFF6FF;color:#1565C0;}
.dep-actions .btn-dep.history{background:#F0FDF4;color:#15803D;}
.dep-actions .btn-dep.delete {background:#FEF2F2;color:#DC2626;}
.dep-actions .btn-dep.edit:hover   {background:#1565C0;color:white;}
.dep-actions .btn-dep.history:hover{background:#15803D;color:white;}
.dep-actions .btn-dep.delete:hover {background:#DC2626;color:white;}
.dep-cambios-badge{display:inline-flex;align-items:center;gap:3px;margin-top:4px;
    font-size:10px;color:var(--gray-400);}

/* ── Tabla general ── */
.vc-table-wrap{overflow-x:auto;}
.vc-table{width:100%;border-collapse:collapse;font-size:12.5px;}
.vc-table thead th{background:var(--gray-50);padding:10px 12px;text-align:left;
    font-size:11px;font-weight:700;color:var(--gray-500);text-transform:uppercase;
    letter-spacing:.6px;border-bottom:1px solid var(--gray-200);white-space:nowrap;}
.vc-table tbody td{padding:11px 12px;border-bottom:1px solid var(--gray-100);
    color:var(--gray-700);vertical-align:middle;}
.vc-table tbody tr:hover{background:var(--gray-50);}
.vc-table tbody tr:last-child td{border-bottom:none;}
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
.btn-tbl.view  {background:#EFF6FF;color:#1565C0;}
.btn-tbl.pay   {background:#F0FDF4;color:#15803D;}
.btn-tbl.print {background:#F5F3FF;color:#7C3AED;}
.btn-tbl.view:hover  {background:#1565C0;color:white;}
.btn-tbl.pay:hover   {background:#15803D;color:white;}
.btn-tbl.print:hover {background:#7C3AED;color:white;}

/* ── Sección vacía ── */
.empty-state{text-align:center;padding:40px 20px;color:var(--gray-400);}
.empty-state i{font-size:36px;margin-bottom:10px;display:block;}
.empty-state p{font-size:13px;margin:0;}

/* ── Anims ── */
.fade-in{animation:fadeIn .4s ease both;}
.delay-1{animation-delay:.08s;}
.delay-2{animation-delay:.16s;}
.delay-3{animation-delay:.24s;}
.delay-4{animation-delay:.32s;}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}

/* ── Modal Historial Plan ── */
.modal-overlay-vc{position:fixed;inset:0;background:rgba(0,0,0,.5);
    z-index:9000;display:none;align-items:center;justify-content:center;padding:20px;}
.modal-overlay-vc.show{display:flex;}
.modal-box-vc{background:var(--white);border-radius:var(--radius-lg);
    width:100%;max-width:700px;max-height:85vh;display:flex;flex-direction:column;
    box-shadow:var(--shadow-lg);}
.modal-box-vc .mhdr-vc{padding:18px 22px;border-bottom:1px solid var(--gray-200);
    display:flex;align-items:center;justify-content:space-between;flex-shrink:0;}
.modal-box-vc .mhdr-title-vc{display:flex;align-items:center;gap:10px;
    font-size:15px;font-weight:700;color:var(--gray-800);}
.modal-box-vc .mhdr-icon-vc{width:34px;height:34px;border-radius:var(--radius-sm);
    background:linear-gradient(135deg,#1B5E20,#2E7D32);
    display:flex;align-items:center;justify-content:center;
    font-size:14px;color:white;}
.modal-box-vc .mbody-vc{padding:20px 22px;overflow-y:auto;flex:1;}
.modal-close-vc{background:none;border:none;cursor:pointer;
    width:32px;height:32px;border-radius:var(--radius-sm);
    display:flex;align-items:center;justify-content:center;
    color:var(--gray-500);font-size:14px;transition:var(--transition);}
.modal-close-vc:hover{background:var(--gray-100);color:var(--gray-800);}

/* ── Modal Editar Dependiente ── */
.modal-overlay-dep{position:fixed;inset:0;background:rgba(0,0,0,.5);
    z-index:9100;display:none;align-items:center;justify-content:center;padding:20px;}
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
.form-row-dep.full{grid-template-columns:1fr;}
@media(max-width:500px){.form-row-dep{grid-template-columns:1fr;}}
.form-group-dep label{display:block;font-size:11.5px;font-weight:600;
    color:var(--gray-600);margin-bottom:5px;text-transform:uppercase;letter-spacing:.5px;}
.form-group-dep input, .form-group-dep select{width:100%;padding:9px 12px;
    border:1.5px solid var(--gray-200);border-radius:var(--radius-sm);
    font-size:13px;color:var(--gray-800);background:var(--white);
    transition:var(--transition);outline:none;}
.form-group-dep input:focus, .form-group-dep select:focus{
    border-color:var(--accent);box-shadow:0 0 0 3px rgba(33,150,243,.15);}

/* ── Spinner ── */
.spinner-vc{width:36px;height:36px;border:3px solid var(--gray-200);
    border-top-color:var(--accent);border-radius:50%;
    animation:spin .8s linear infinite;margin:30px auto;}
@keyframes spin{to{transform:rotate(360deg)}}

/* ── Historial timeline ── */
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
.hist-plan-name{font-size:12.5px;font-weight:700;padding:3px 10px;border-radius:20px;}
.hist-plan-name.anterior{background:#FEE2E2;color:#991B1B;}
.hist-plan-name.nuevo{background:#DCFCE7;color:#166534;}
.hist-arrow{color:var(--gray-400);font-size:12px;}
.hist-motivo{font-size:12px;color:var(--gray-600);margin-top:6px;}
.hist-motivo strong{color:var(--gray-700);}
.hist-precio-diff{font-size:11.5px;font-weight:700;margin-top:5px;}
.hist-precio-diff.up{color:#16A34A;}
.hist-precio-diff.down{color:#DC2626;}
.hist-empty{text-align:center;padding:30px;color:var(--gray-400);}
.hist-empty i{font-size:32px;display:block;margin-bottom:8px;}
</style>

<!-- ============================================================
     PAGE HEADER
     ============================================================ -->
<div class="page-header fade-in">
    <div>
        <div class="page-title">
            <i class="fas fa-user" style="color:var(--accent);margin-right:8px;"></i>
            <?php echo htmlspecialchars($cliente['nombre'] . ' ' . $cliente['apellidos']); ?>
        </div>
        <div class="page-subtitle">
            Código: <strong><?php echo htmlspecialchars($cliente['codigo']); ?></strong>
            &mdash; Detalle completo del cliente
        </div>
    </div>
    <div class="page-actions">
        <a href="editar_cliente.php?id=<?php echo $id; ?>" class="btn btn-primary">
            <i class="fas fa-edit"></i> Editar
        </a>
        <a href="carnet.php?cliente_id=<?php echo $id; ?>" class="btn btn-secondary" target="_blank">
            <i class="fas fa-id-card"></i> Carnet
        </a>
        <a href="clientes.php" class="btn btn-secondary">
            <i class="fas fa-arrow-left"></i> Volver
        </a>
    </div>
</div>

<?php if (isset($_GET['mensaje'])): ?>
<div class="alert-global success fade-in" id="alertaVer">
    <i class="fas fa-check-circle"></i>
    <?php echo htmlspecialchars($_GET['mensaje']); ?>
</div>
<script>setTimeout(()=>{ const a=document.getElementById('alertaVer'); if(a)a.style.display='none'; },4000);</script>
<?php endif; ?>

<!-- ============================================================
     KPI CARDS
     ============================================================ -->
<div class="kpi-cliente-row fade-in delay-1">
    <div class="kpi-c blue">
        <div class="kc-label">Contratos</div>
        <div class="kc-value"><?php echo number_format($cliente['total_contratos']); ?></div>
        <div class="kc-sub">Total registrados</div>
        <i class="fas fa-file-contract kc-icon"></i>
    </div>
    <div class="kpi-c teal">
        <div class="kc-label">Facturas</div>
        <div class="kc-value"><?php echo number_format($cliente['total_facturas']); ?></div>
        <div class="kc-sub">Total generadas</div>
        <i class="fas fa-file-invoice-dollar kc-icon"></i>
    </div>
    <div class="kpi-c purple">
        <div class="kc-label">Dependientes</div>
        <div class="kc-value"><?php echo number_format($cliente['total_dependientes']); ?></div>
        <div class="kc-sub">Activos</div>
        <i class="fas fa-users kc-icon"></i>
    </div>
    <div class="kpi-c <?php echo $cliente['facturas_incompletas'] > 0 ? 'amber' : 'green'; ?>">
        <div class="kc-label">Incompletas</div>
        <div class="kc-value"><?php echo number_format($cliente['facturas_incompletas']); ?></div>
        <div class="kc-sub">Facturas incompletas</div>
        <i class="fas fa-hourglass-half kc-icon"></i>
    </div>
    <div class="kpi-c <?php echo $total_monto_pendiente > 0 ? 'red' : 'green'; ?>">
        <div class="kc-label">Pendiente</div>
        <div class="kc-value" style="font-size:16px;">RD$<?php echo number_format($total_monto_pendiente, 0); ?></div>
        <div class="kc-sub">Por cobrar</div>
        <i class="fas fa-clock kc-icon"></i>
    </div>
    <div class="kpi-c green">
        <div class="kc-label">Total Abonado</div>
        <div class="kc-value" style="font-size:16px;">RD$<?php echo number_format($total_abonado_calc, 0); ?></div>
        <div class="kc-sub">Pagos procesados</div>
        <i class="fas fa-dollar-sign kc-icon"></i>
    </div>
</div>

<!-- ============================================================
     INFORMACIÓN PERSONAL
     ============================================================ -->
<div class="vc-card fade-in delay-2">
    <div class="vc-card-header">
        <div class="vc-card-title">
            <div class="vc-card-icon blue"><i class="fas fa-user"></i></div>
            <div>
                <div class="vc-title-text">Información Personal</div>
                <div class="vc-title-sub">Datos generales del cliente</div>
            </div>
        </div>
        <span class="badge-vc <?php echo $cliente['estado']; ?>">
            <i class="fas fa-circle" style="font-size:7px;"></i>
            <?php echo ucfirst($cliente['estado']); ?>
        </span>
    </div>
    <div class="vc-card-body">
        <div class="info-grid-3">
            <div class="iib">
                <div class="iib-label">Código</div>
                <div class="iib-value mono"><?php echo htmlspecialchars($cliente['codigo']); ?></div>
            </div>
            <div class="iib">
                <div class="iib-label">Nombre Completo</div>
                <div class="iib-value"><?php echo htmlspecialchars($cliente['nombre'] . ' ' . $cliente['apellidos']); ?></div>
            </div>
            <div class="iib">
                <div class="iib-label">Cédula / Pasaporte</div>
                <div class="iib-value mono"><?php echo htmlspecialchars($cliente['cedula'] ?? '-'); ?></div>
            </div>
            <div class="iib">
                <div class="iib-label">Email</div>
                <div class="iib-value">
                    <?php if ($cliente['email']): ?>
                        <a href="mailto:<?php echo htmlspecialchars($cliente['email']); ?>">
                            <?php echo htmlspecialchars($cliente['email']); ?>
                        </a>
                    <?php else: ?> — <?php endif; ?>
                </div>
            </div>
            <div class="iib">
                <div class="iib-label">Teléfono Principal</div>
                <div class="iib-value"><?php echo htmlspecialchars($cliente['telefono1'] ?? '-'); ?></div>
            </div>
            <div class="iib">
                <div class="iib-label">Teléfonos Adicionales</div>
                <div class="iib-value">
                    <?php
                    $tels = array_filter([$cliente['telefono2'] ?? '', $cliente['telefono3'] ?? '']);
                    echo $tels ? htmlspecialchars(implode(' / ', $tels)) : '—';
                    ?>
                </div>
            </div>
            <div class="iib full">
                <div class="iib-label">Dirección</div>
                <div class="iib-value"><?php echo htmlspecialchars($cliente['direccion'] ?? '-'); ?></div>
            </div>
            <?php if (!empty($cliente['fecha_nacimiento'])): ?>
            <div class="iib">
                <div class="iib-label">Fecha de Nacimiento</div>
                <div class="iib-value"><?php echo date('d/m/Y', strtotime($cliente['fecha_nacimiento'])); ?></div>
            </div>
            <?php endif; ?>
            <div class="iib">
                <div class="iib-label">Cliente desde</div>
                <div class="iib-value"><?php echo date('d/m/Y', strtotime($cliente['created_at'])); ?></div>
            </div>
        </div>
    </div>
</div>

<!-- ============================================================
     DEPENDIENTES
     ============================================================ -->
<div class="vc-card fade-in delay-2">
    <div class="vc-card-header">
        <div class="vc-card-title">
            <div class="vc-card-icon purple"><i class="fas fa-users"></i></div>
            <div>
                <div class="vc-title-text">Dependientes</div>
                <div class="vc-title-sub"><?php echo count($dependientes); ?> dependiente(s) activo(s)</div>
            </div>
        </div>
    </div>
    <div class="vc-card-body">
        <?php if (empty($dependientes)): ?>
            <div class="empty-state">
                <i class="fas fa-users"></i>
                <p>No hay dependientes activos registrados para este cliente.</p>
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
                            <div class="dep-card-name">
                                <?php echo htmlspecialchars($dep['nombre'] . ' ' . $dep['apellidos']); ?>
                            </div>
                            <div class="dep-card-rel">
                                <?php echo htmlspecialchars($dep['relacion']); ?>
                            </div>
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
                    <div class="dep-cambios-badge">
                        <i class="fas fa-history"></i>
                        <?php echo $dep['total_cambios_plan']; ?> cambio(s) de plan registrado(s)
                    </div>
                    <?php endif; ?>
                    <div class="dep-actions">
                        <button class="btn-dep edit" onclick="abrirEditarDependiente(<?php echo htmlspecialchars(json_encode($dep)); ?>)">
                            <i class="fas fa-edit"></i> Editar
                        </button>
                        <button class="btn-dep history" onclick="verHistorialPlan(<?php echo $dep['id']; ?>, '<?php echo htmlspecialchars($dep['nombre'] . ' ' . $dep['apellidos']); ?>')">
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
     CONTRATOS
     ============================================================ -->
<div class="vc-card fade-in delay-3">
    <div class="vc-card-header">
        <div class="vc-card-title">
            <div class="vc-card-icon green"><i class="fas fa-file-contract"></i></div>
            <div>
                <div class="vc-title-text">Contratos</div>
                <div class="vc-title-sub"><?php echo count($contratos); ?> contrato(s) registrado(s)</div>
            </div>
        </div>
    </div>
    <div class="vc-card-body" style="padding:0;">
        <?php if (empty($contratos)): ?>
            <div class="empty-state">
                <i class="fas fa-file-contract"></i>
                <p>No hay contratos registrados para este cliente.</p>
            </div>
        <?php else: ?>
        <div class="vc-table-wrap">
            <table class="vc-table">
                <thead>
                    <tr>
                        <th>N° Contrato</th>
                        <th>Plan</th>
                        <th>Fecha Inicio</th>
                        <th>Monto Base</th>
                        <th>Estado</th>
                        <th>Fact. Pendientes</th>
                        <th>Fact. Incompletas</th>
                        <th>Total Abonado</th>
                        <th>Acciones</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($contratos as $contrato): ?>
                    <tr>
                        <td class="td-num">
                            <a href="ver_contrato.php?id=<?php echo $contrato['id']; ?>">
                                <?php echo str_pad($contrato['numero_contrato'], 5, '0', STR_PAD_LEFT); ?>
                            </a>
                        </td>
                        <td><?php echo htmlspecialchars($contrato['plan_nombre']); ?></td>
                        <td class="td-muted"><?php echo date('d/m/Y', strtotime($contrato['fecha_inicio'])); ?></td>
                        <td class="td-amount">RD$<?php echo number_format($contrato['monto_mensual'], 2); ?></td>
                        <td>
                            <span class="badge-vc <?php echo $contrato['estado']; ?>">
                                <?php echo ucfirst($contrato['estado']); ?>
                            </span>
                        </td>
                        <td>
                            <?php if ($contrato['facturas_pendientes'] > 0): ?>
                                <span class="badge-vc pendiente"><?php echo $contrato['facturas_pendientes']; ?></span>
                            <?php else: ?>
                                <span style="color:var(--gray-400);font-size:12px;">—</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php if ($contrato['facturas_incompletas'] > 0): ?>
                                <span class="badge-vc incompleta"><?php echo $contrato['facturas_incompletas']; ?></span>
                            <?php else: ?>
                                <span style="color:var(--gray-400);font-size:12px;">—</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php if ($contrato['total_abonado'] > 0): ?>
                                <span class="td-green">RD$<?php echo number_format($contrato['total_abonado'], 2); ?></span>
                            <?php else: ?>
                                <span style="color:var(--gray-400);">—</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <div class="tbl-actions">
                                <a href="ver_contrato.php?id=<?php echo $contrato['id']; ?>" class="btn-tbl view" title="Ver contrato">
                                    <i class="fas fa-eye"></i>
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
     ÚLTIMAS FACTURAS
     ============================================================ -->
<div class="vc-card fade-in delay-3">
    <div class="vc-card-header">
        <div class="vc-card-title">
            <div class="vc-card-icon amber"><i class="fas fa-file-invoice-dollar"></i></div>
            <div>
                <div class="vc-title-text">Últimas Facturas</div>
                <div class="vc-title-sub">Las 12 más recientes</div>
            </div>
        </div>
    </div>
    <div class="vc-card-body" style="padding:0;">
        <?php if (empty($facturas)): ?>
            <div class="empty-state">
                <i class="fas fa-file-invoice"></i>
                <p>No hay facturas registradas para este cliente.</p>
            </div>
        <?php else: ?>
        <div class="vc-table-wrap">
            <table class="vc-table">
                <thead>
                    <tr>
                        <th>N° Factura</th>
                        <th>Contrato</th>
                        <th>Período</th>
                        <th>Emisión</th>
                        <th>Vencimiento</th>
                        <th>Monto</th>
                        <th>Abonado</th>
                        <th>Pendiente</th>
                        <th>Estado</th>
                        <th>Acciones</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($facturas as $factura):
                        $montoPend = $factura['monto'] - ($factura['total_abonado'] ?? 0);
                        if ($montoPend < 0) $montoPend = 0;
                    ?>
                    <tr>
                        <td class="td-num"><?php echo htmlspecialchars($factura['numero_factura']); ?></td>
                        <td class="td-num">
                            <a href="ver_contrato.php?id=<?php echo $factura['contrato_id']; ?>">
                                <?php echo htmlspecialchars($factura['numero_contrato']); ?>
                            </a>
                        </td>
                        <td><?php echo htmlspecialchars($factura['mes_factura']); ?></td>
                        <td class="td-muted"><?php echo date('d/m/Y', strtotime($factura['fecha_emision'])); ?></td>
                        <td class="td-muted"><?php echo date('d/m/Y', strtotime($factura['fecha_vencimiento'])); ?></td>
                        <td class="td-amount">RD$<?php echo number_format($factura['monto'], 2); ?></td>
                        <td>
                            <?php if ($factura['total_abonado'] > 0): ?>
                                <span class="td-green">RD$<?php echo number_format($factura['total_abonado'], 2); ?></span>
                            <?php else: ?> <span class="td-muted">—</span> <?php endif; ?>
                        </td>
                        <td>
                            <?php if ($montoPend > 0): ?>
                                <span class="td-red">RD$<?php echo number_format($montoPend, 2); ?></span>
                            <?php else: ?> <span class="td-muted">—</span> <?php endif; ?>
                        </td>
                        <td>
                            <span class="badge-vc <?php echo $factura['estado']; ?>">
                                <?php echo ucfirst($factura['estado']); ?>
                            </span>
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
     HISTORIAL DE PAGOS RECIENTES
     ============================================================ -->
<?php if (!empty($pagos_recientes)): ?>
<div class="vc-card fade-in delay-4">
    <div class="vc-card-header">
        <div class="vc-card-title">
            <div class="vc-card-icon teal"><i class="fas fa-money-bill-wave"></i></div>
            <div>
                <div class="vc-title-text">Últimos Pagos</div>
                <div class="vc-title-sub">10 pagos más recientes procesados</div>
            </div>
        </div>
    </div>
    <div class="vc-card-body" style="padding:0;">
        <div class="vc-table-wrap">
            <table class="vc-table">
                <thead>
                    <tr>
                        <th>Fecha / Hora</th>
                        <th>N° Factura</th>
                        <th>Contrato</th>
                        <th>Monto</th>
                        <th>Tipo</th>
                        <th>Método</th>
                        <th>Referencia</th>
                        <th>Cobrador</th>
                        <th>Acciones</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($pagos_recientes as $pago): ?>
                    <tr>
                        <td class="td-muted"><?php echo date('d/m/Y H:i', strtotime($pago['fecha_pago'])); ?></td>
                        <td class="td-num"><?php echo htmlspecialchars($pago['numero_factura']); ?></td>
                        <td class="td-num"><?php echo htmlspecialchars($pago['numero_contrato']); ?></td>
                        <td class="td-amount">RD$<?php echo number_format($pago['monto'], 2); ?></td>
                        <td>
                            <span class="badge-vc <?php echo $pago['tipo_pago']; ?>">
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
     MODAL: HISTORIAL DE PLAN DEL DEPENDIENTE
     ============================================================ -->
<div class="modal-overlay-vc" id="modalHistorialPlan">
    <div class="modal-box-vc">
        <div class="mhdr-vc">
            <div class="mhdr-title-vc">
                <div class="mhdr-icon-vc"><i class="fas fa-history"></i></div>
                <div>
                    <div style="font-size:14px;font-weight:700;color:var(--gray-800);">
                        Historial de Cambios de Plan
                    </div>
                    <div id="histModalNombre" style="font-size:11.5px;color:var(--gray-500);margin-top:1px;"></div>
                </div>
            </div>
            <button class="modal-close-vc" onclick="cerrarModalHistorial()">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="mbody-vc" id="histModalBody">
            <div class="spinner-vc"></div>
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
                <div class="vc-card-icon purple" style="width:34px;height:34px;font-size:14px;">
                    <i class="fas fa-user-edit"></i>
                </div>
                <div>
                    <div style="font-size:14px;font-weight:700;color:var(--gray-800);">Editar Dependiente</div>
                    <div style="font-size:11.5px;color:var(--gray-500);">Modifique los datos del dependiente</div>
                </div>
            </div>
            <button class="modal-close-vc" onclick="cerrarModalDep()">
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
                        <label>Fecha de Nacimiento *</label>
                        <input type="date" name="fecha_nacimiento" id="dep_edit_fecha_nac" required>
                    </div>
                    <div class="form-group-dep">
                        <label>Fecha de Registro</label>
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

// ── Modal Historial de Plan ──
function verHistorialPlan(depId, nombre) {
    document.getElementById('histModalNombre').textContent = nombre || 'Dependiente';
    document.getElementById('histModalBody').innerHTML = '<div class="spinner-vc"></div>';
    document.getElementById('modalHistorialPlan').classList.add('show');

    fetch('historial_plan_dependiente.php?id=' + depId)
        .then(r => r.json())
        .then(data => {
            if (!data.success) {
                document.getElementById('histModalBody').innerHTML =
                    '<div class="hist-empty"><i class="fas fa-exclamation-circle"></i>' +
                    '<p>' + (data.message || 'Error al cargar el historial.') + '</p></div>';
                return;
            }
            if (!data.data || data.data.length === 0) {
                document.getElementById('histModalBody').innerHTML =
                    '<div class="hist-empty"><i class="fas fa-history"></i>' +
                    '<p>Este dependiente no tiene cambios de plan registrados.</p></div>';
                return;
            }
            let html = '<div class="hist-timeline">';
            data.data.forEach(function(h) {
                const fecha = new Date(h.fecha_cambio);
                const fechaFmt = fecha.toLocaleDateString('es-DO', {day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit'});
                const diffPrecio = parseFloat(h.diferencia_precio);
                let diffHtml = '';
                if (diffPrecio > 0) {
                    diffHtml = '<div class="hist-precio-diff up"><i class="fas fa-arrow-up"></i> Aumento de RD$' + Math.abs(diffPrecio).toFixed(2) + '/mes</div>';
                } else if (diffPrecio < 0) {
                    diffHtml = '<div class="hist-precio-diff down"><i class="fas fa-arrow-down"></i> Reducción de RD$' + Math.abs(diffPrecio).toFixed(2) + '/mes</div>';
                }
                html += '<div class="hist-item">' +
                    '<div class="hist-item-header">' +
                        '<span class="hist-item-date"><i class="fas fa-clock" style="margin-right:4px;"></i>' + fechaFmt + '</span>' +
                        '<span class="hist-item-user"><i class="fas fa-user" style="margin-right:3px;"></i>' + esc(h.usuario_nombre) + '</span>' +
                    '</div>' +
                    '<div class="hist-item-body">' +
                        '<div class="hist-plan-change">' +
                            '<span class="hist-plan-name anterior">' + esc(h.plan_anterior_nombre) + ' — RD$' + parseFloat(h.plan_anterior_precio).toFixed(2) + '</span>' +
                            '<span class="hist-arrow"><i class="fas fa-arrow-right"></i></span>' +
                            '<span class="hist-plan-name nuevo">' + esc(h.plan_nuevo_nombre) + ' — RD$' + parseFloat(h.plan_nuevo_precio).toFixed(2) + '</span>' +
                            (h.es_cambio_geriatrico ? '<span style="background:#FEF3C7;color:#92400E;padding:2px 8px;border-radius:20px;font-size:10.5px;font-weight:700;"><i class="fas fa-star"></i> Geriátrico</span>' : '') +
                        '</div>' +
                        diffHtml +
                        '<div class="hist-motivo"><strong>Motivo:</strong> ' + esc(h.motivo) + '</div>' +
                    '</div>' +
                '</div>';
            });
            html += '</div>';
            document.getElementById('histModalBody').innerHTML = html;
        })
        .catch(() => {
            document.getElementById('histModalBody').innerHTML =
                '<div class="hist-empty"><i class="fas fa-exclamation-triangle"></i>' +
                '<p>Error de comunicación al cargar el historial.</p></div>';
        });
}

function cerrarModalHistorial() {
    document.getElementById('modalHistorialPlan').classList.remove('show');
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

    const formData = new FormData(this);

    fetch('dependientes.php', {
        method: 'POST',
        body: formData
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            cerrarModalDep();
            mostrarToast(data.message || 'Dependiente actualizado correctamente.', 'success');
            setTimeout(() => location.reload(), 1200);
        } else {
            mostrarToast(data.message || 'Error al actualizar el dependiente.', 'error');
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-save"></i> Guardar Cambios';
        }
    })
    .catch(() => {
        mostrarToast('Error de comunicación con el servidor.', 'error');
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-save"></i> Guardar Cambios';
    });
});

// ── Eliminar Dependiente ──
function eliminarDependiente(depId) {
    Swal.fire({
        title: '¿Eliminar dependiente?',
        text: 'Esta acción lo marcará como inactivo. ¿Desea continuar?',
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#DC2626',
        cancelButtonColor: '#64748B',
        confirmButtonText: '<i class="fas fa-trash"></i> Sí, eliminar',
        cancelButtonText: 'Cancelar'
    }).then(result => {
        if (result.isConfirmed) {
            const formData = new FormData();
            formData.append('action', 'delete');
            formData.append('id', depId);
            fetch('dependientes.php', { method: 'POST', body: formData })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        mostrarToast('Dependiente eliminado correctamente.', 'success');
                        setTimeout(() => location.reload(), 1200);
                    } else {
                        mostrarToast(data.message || 'Error al eliminar.', 'error');
                    }
                })
                .catch(() => mostrarToast('Error de comunicación.', 'error'));
        }
    });
}

// ── Función escape ──
function esc(str) {
    if (!str) return '—';
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Toast ──
function mostrarToast(mensaje, tipo = 'info', duracion = 4000) {
    Toastify({
        text: mensaje,
        duration: duracion,
        close: true,
        gravity: 'top',
        position: 'right',
        backgroundColor: tipo === 'success' ? '#28a745' :
                        (tipo === 'error'   ? '#dc3545' :
                        (tipo === 'warning' ? '#ffc107' : '#17a2b8')),
        stopOnFocus: true
    }).showToast();
}

// ── Cerrar modales con Escape ──
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        cerrarModalHistorial();
        cerrarModalDep();
    }
});

// ── Cerrar modales al clic en overlay ──
document.getElementById('modalHistorialPlan').addEventListener('click', function(e) {
    if (e.target === this) cerrarModalHistorial();
});
document.getElementById('modalEditarDep').addEventListener('click', function(e) {
    if (e.target === this) cerrarModalDep();
});

// ── Mensaje al cargar ──
<?php if (isset($_GET['mensaje'])): ?>
document.addEventListener('DOMContentLoaded', function() {
    mostrarToast('<?php echo addslashes($_GET['mensaje']); ?>', 'success');
});
<?php endif; ?>
</script>

<?php require_once 'footer.php'; ?>