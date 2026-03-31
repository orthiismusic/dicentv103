<?php
require_once 'header.php';

/* ============================================================
   BLOQUE 1 — KPI CARDS: Estadísticas principales
   ============================================================ */

// Contratos activos
$stmt = $conn->query("SELECT COUNT(*) as total FROM contratos WHERE estado = 'activo'");
$contratos_activos = $stmt->fetch()['total'];

// Ingresos del mes actual (procesados y anulados)
$stmt = $conn->query("
    SELECT
        COALESCE(SUM(CASE WHEN estado = 'procesado' THEN monto ELSE 0 END), 0) AS ingresos_procesados,
        COALESCE(SUM(CASE WHEN estado = 'anulado'   THEN monto ELSE 0 END), 0) AS ingresos_anulados
    FROM pagos
    WHERE MONTH(fecha_pago) = MONTH(CURRENT_DATE())
      AND YEAR(fecha_pago)  = YEAR(CURRENT_DATE())
");
$ingresos              = $stmt->fetch();
$ingresos_mes          = $ingresos['ingresos_procesados'];
$ingresos_mes_anulados = $ingresos['ingresos_anulados'];

// Monto total pendiente (facturas vencidas sin cobrar)
$stmt = $conn->query("
    SELECT
        COALESCE(SUM(monto), 0)  AS monto_pendiente,
        COUNT(*)                 AS cant_vencidas
    FROM facturas
    WHERE estado = 'vencida'
");
$vencidas        = $stmt->fetch();
$monto_pendiente = $vencidas['monto_pendiente'];
$cant_vencidas   = $vencidas['cant_vencidas'];

// Tasa de morosidad = facturas vencidas / total facturas * 100
$stmt = $conn->query("SELECT COUNT(*) as total FROM facturas");
$total_facturas  = $stmt->fetch()['total'];
$tasa_morosidad  = $total_facturas > 0
    ? round(($cant_vencidas / $total_facturas) * 100, 1)
    : 0;

/* ============================================================
   BLOQUE 2 — MINI STATS: Estadísticas secundarias
   ============================================================ */

// Clientes activos e inactivos
$stmt = $conn->query("
    SELECT
        SUM(CASE WHEN estado = 'activo'   THEN 1 ELSE 0 END) AS activos,
        SUM(CASE WHEN estado = 'inactivo' THEN 1 ELSE 0 END) AS inactivos
    FROM clientes
");
$clientes_stats   = $stmt->fetch();
$clientes_activos = $clientes_stats['activos'];
$clientes_inact   = $clientes_stats['inactivos'];

// Dependientes activos y nuevos este mes
$stmt = $conn->query("
    SELECT
        SUM(CASE WHEN estado = 'activo' THEN 1 ELSE 0 END) AS activos,
        SUM(CASE
                WHEN estado = 'activo'
                 AND MONTH(fecha_registro) = MONTH(CURRENT_DATE())
                 AND YEAR(fecha_registro)  = YEAR(CURRENT_DATE())
                THEN 1 ELSE 0 END) AS nuevos_mes
    FROM dependientes
");
$dep_stats          = $stmt->fetch();
$dependientes_act   = $dep_stats['activos'];
$dependientes_mes   = $dep_stats['nuevos_mes'];

// Facturas pendientes y próximas a vencer (en los próximos 7 días)
$stmt = $conn->query("
    SELECT
        SUM(CASE WHEN estado = 'pendiente' THEN 1 ELSE 0 END) AS pendientes,
        SUM(CASE
                WHEN estado = 'pendiente'
                 AND fecha_vencimiento BETWEEN CURRENT_DATE()
                                           AND DATE_ADD(CURRENT_DATE(), INTERVAL 7 DAY)
                THEN 1 ELSE 0 END) AS proximas
    FROM facturas
");
$fact_stats       = $stmt->fetch();
$facturas_pend    = $fact_stats['pendientes'];
$facturas_prox    = $fact_stats['proximas'];

// ── Vigencias de contratos (alineado con vigencias.php) ──
$stmt = $conn->query("
    SELECT
        SUM(CASE WHEN fecha_fin < CURDATE()                                                                                   THEN 1 ELSE 0 END) AS vig_vencidas,
        SUM(CASE WHEN fecha_fin >= CURDATE()  AND fecha_fin <= DATE_ADD(CURDATE(), INTERVAL 7  DAY) THEN 1 ELSE 0 END) AS vig_criticas,
        SUM(CASE WHEN fecha_fin >  DATE_ADD(CURDATE(), INTERVAL 7  DAY) AND fecha_fin <= DATE_ADD(CURDATE(), INTERVAL 15 DAY) THEN 1 ELSE 0 END) AS vig_urgentes,
        SUM(CASE WHEN fecha_fin >  DATE_ADD(CURDATE(), INTERVAL 15 DAY) AND fecha_fin <= DATE_ADD(CURDATE(), INTERVAL 30 DAY) THEN 1 ELSE 0 END) AS vig_por_vencer,
        SUM(CASE WHEN fecha_fin >  DATE_ADD(CURDATE(), INTERVAL 30 DAY) AND fecha_fin <= DATE_ADD(CURDATE(), INTERVAL 60 DAY) THEN 1 ELSE 0 END) AS vig_atencion
    FROM contratos
    WHERE estado = 'activo'
");
$vig_stats      = $stmt->fetch();
$vig_vencidas   = (int)($vig_stats['vig_vencidas']   ?? 0);
$vig_criticas   = (int)($vig_stats['vig_criticas']   ?? 0);
$vig_urgentes   = (int)($vig_stats['vig_urgentes']   ?? 0);
$vig_por_vencer = (int)($vig_stats['vig_por_vencer'] ?? 0);
$vig_atencion   = (int)($vig_stats['vig_atencion']   ?? 0);

// Mantener compatibilidad con mini-stat existente
$contratos_por_vencer = $vig_criticas + $vig_urgentes + $vig_por_vencer;

// Monto global pendiente de contratos activos (igual que vigencias.php)
$stmt = $conn->query("
    SELECT COALESCE(SUM(
        f.monto - COALESCE(
            (SELECT SUM(pg.monto) FROM pagos pg
             WHERE pg.factura_id = f.id AND pg.estado = 'procesado'), 0
        )
    ), 0) AS monto_global_vig
    FROM facturas f
    JOIN contratos c ON f.contrato_id = c.id
    WHERE c.estado = 'activo'
      AND f.estado IN ('pendiente', 'incompleta', 'vencida')
");
$monto_global_vigencias = (float)$stmt->fetchColumn();

/* ============================================================
   BLOQUE 3 — GRÁFICO LÍNEAS: Ingresos mensuales
   ============================================================ */
$year = isset($_GET['year']) ? intval($_GET['year']) : date('Y');
$stmt = $conn->prepare("
    SELECT
        MONTH(fecha_pago)                                     AS mes,
        SUM(CASE WHEN estado = 'procesado' THEN monto ELSE 0 END) AS monto_procesado,
        SUM(CASE WHEN estado = 'anulado'   THEN monto ELSE 0 END) AS monto_anulado
    FROM pagos
    WHERE YEAR(fecha_pago) = ?
    GROUP BY MONTH(fecha_pago)
    ORDER BY mes
");
$stmt->execute([$year]);
$ingresos_mensuales = $stmt->fetchAll();

// Preparar arrays para Chart.js
$meses_labels   = ['Ene','Feb','Mar','Abr','May','Jun','Jul','Ago','Sep','Oct','Nov','Dic'];
$datos_procesados = array_fill(0, 12, 0);
$datos_anulados   = array_fill(0, 12, 0);
foreach ($ingresos_mensuales as $ing) {
    $idx = $ing['mes'] - 1;
    $datos_procesados[$idx] = floatval($ing['monto_procesado']);
    $datos_anulados[$idx]   = floatval($ing['monto_anulado']);
}

/* ============================================================
   BLOQUE 4 — GRÁFICO DONUT: Distribución de contratos por plan
   ============================================================ */
$stmt = $conn->query("
    SELECT
        p.nombre,
        COUNT(*) AS total_contratos,
        ROUND(COUNT(*) * 100.0 / NULLIF((
            SELECT COUNT(*) FROM contratos WHERE estado = 'activo'
        ), 0), 1) AS porcentaje
    FROM contratos c
    JOIN planes p ON c.plan_id = p.id
    WHERE c.estado = 'activo'
    GROUP BY p.id, p.nombre
    ORDER BY total_contratos DESC
");
$distribucion_planes = $stmt->fetchAll();

$planesLabels = [];
$planesData   = [];
$planesPct    = [];
foreach ($distribucion_planes as $plan) {
    $planesLabels[] = $plan['nombre'];
    $planesData[]   = floatval($plan['porcentaje']);
    $planesPct[]    = $plan['porcentaje'];
}

/* ============================================================
   BLOQUE 5 — TABLA: Últimos contratos registrados
   ============================================================ */
$stmt = $conn->query("
    SELECT
        c.numero_contrato,
        CONCAT(cl.nombre, ' ', cl.apellidos) AS cliente_nombre,
        p.nombre                             AS plan_nombre,
        c.monto_mensual,
        c.fecha_inicio,
        c.estado
    FROM contratos c
    JOIN clientes cl ON c.cliente_id = cl.id
    JOIN planes   p  ON c.plan_id    = p.id
    ORDER BY c.id DESC
    LIMIT 5
");
$ultimos_contratos = $stmt->fetchAll();

/* ============================================================
   BLOQUE 6 — TABLA: Últimos pagos registrados
   ============================================================ */
$stmt = $conn->query("
    SELECT
        c.numero_contrato,
        CONCAT(cl.nombre, ' ', cl.apellidos) AS cliente_nombre,
        p.fecha_pago,
        p.monto,
        p.estado,
        p.metodo_pago
    FROM pagos p
    JOIN facturas f  ON p.factura_id   = f.id
    JOIN contratos c ON f.contrato_id  = c.id
    JOIN clientes cl ON c.cliente_id   = cl.id
    ORDER BY p.fecha_pago DESC, p.id DESC
    LIMIT 5
");
$ultimos_pagos = $stmt->fetchAll();

/* ============================================================
   BLOQUE 7 — TOP VENDEDORES
   ============================================================ */
$stmt = $conn->query("
    SELECT
        v.nombre_completo,
        COUNT(DISTINCT c.id)    AS total_contratos,
        COALESCE(SUM(f.monto), 0) AS monto_total
    FROM vendedores v
    JOIN contratos c  ON c.vendedor_id = v.id
    JOIN facturas  f  ON f.contrato_id = c.id
    WHERE c.estado    = 'activo'
      AND f.estado    = 'pagada'
    GROUP BY v.id, v.nombre_completo
    ORDER BY monto_total DESC
    LIMIT 5
");
$top_vendedores = $stmt->fetchAll();

/* ============================================================
   BLOQUE 8 — ÚLTIMAS ACTIVIDADES (logs del sistema)
   ============================================================ */
$stmt = $conn->query("
    SELECT l.*, u.nombre AS usuario_nombre
    FROM logs_sistema l
    JOIN usuarios u ON l.usuario_id = u.id
    ORDER BY l.created_at DESC
    LIMIT 5
");
$ultimas_actividades = $stmt->fetchAll();

/* ============================================================
   Años disponibles para selector de gráfico
   ============================================================ */
$currentYear = (int) date('Y');
?>

<!-- ============================================================
     ESTILOS ESPECÍFICOS DEL DASHBOARD
     ============================================================ -->
<style>
/* ── KPI CARDS ── */
.kpi-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 18px;
    margin-bottom: 24px;
}

.kpi-card {
    border-radius: var(--radius);
    padding: 22px 22px 18px;
    position: relative;
    overflow: hidden;
    box-shadow: var(--shadow);
    transition: var(--transition);
    text-decoration: none;
}

.kpi-card:hover { transform: translateY(-3px); box-shadow: var(--shadow-md); }

.kpi-card::before {
    content: '';
    position: absolute;
    top: 0; right: 0;
    width: 80px; height: 80px;
    border-radius: 0 var(--radius) 0 100%;
    opacity: 0.15;
    background: white;
}

.kpi-card.blue   { background: linear-gradient(135deg, #1565C0, #1976D2); }
.kpi-card.green  { background: linear-gradient(135deg, #1B5E20, #2E7D32); }
.kpi-card.amber  { background: linear-gradient(135deg, #E65100, #F57F17); }
.kpi-card.red    { background: linear-gradient(135deg, #B71C1C, #C62828); }

.kpi-label { font-size: 11px; font-weight: 600; color: rgba(255,255,255,0.8); text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 12px; }

.kpi-top { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 6px; }

.kpi-icon {
    width: 48px; height: 48px;
    background: rgba(255,255,255,0.18);
    border-radius: var(--radius-sm);
    display: flex; align-items: center; justify-content: center;
    font-size: 20px; color: white;
    flex-shrink: 0;
}

.kpi-value       { font-size: 30px; font-weight: 800; color: white; line-height: 1; margin-bottom: 4px; }
.kpi-value.large { font-size: 22px; }
.kpi-sub         { font-size: 11px; color: rgba(255,255,255,0.70); font-weight: 500; }

.kpi-footer {
    margin-top: 14px;
    padding-top: 12px;
    border-top: 1px solid rgba(255,255,255,0.15);
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.kpi-link {
    font-size: 12px; color: rgba(255,255,255,0.85); font-weight: 600;
    display: flex; align-items: center; gap: 5px;
    text-decoration: none; transition: var(--transition);
}
.kpi-link:hover { color: white; gap: 8px; text-decoration: none; }

.kpi-change {
    display: inline-flex; align-items: center; gap: 4px;
    font-size: 11px; font-weight: 700;
    padding: 3px 8px; border-radius: 20px;
    background: rgba(255,255,255,0.18);
    color: rgba(255,255,255,0.95);
}

/* ── MINI STATS ── */
.mini-stats-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px;
    margin-bottom: 24px;
}

.mini-stat {
    background: white;
    border-radius: var(--radius);
    padding: 16px;
    display: flex;
    align-items: center;
    gap: 14px;
    box-shadow: var(--shadow-sm);
    border: 1px solid var(--gray-200);
    transition: var(--transition);
}

.mini-stat:hover { transform: translateY(-2px); box-shadow: var(--shadow); }

.mini-stat-icon {
    width: 42px; height: 42px;
    border-radius: var(--radius-sm);
    display: flex; align-items: center; justify-content: center;
    font-size: 17px; flex-shrink: 0;
}

.mini-stat-icon.blue-soft   { background: #EFF6FF; color: var(--accent); }
.mini-stat-icon.green-soft  { background: #F0FDF4; color: #16A34A; }
.mini-stat-icon.amber-soft  { background: #FFFBEB; color: #D97706; }
.mini-stat-icon.red-soft    { background: #FEF2F2; color: #DC2626; }

.mini-stat-info .stat-label { font-size: 11px; color: var(--gray-400); font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
.mini-stat-info .stat-value { font-size: 20px; font-weight: 800; color: var(--gray-800); line-height: 1.2; margin: 2px 0; }
.mini-stat-info .stat-sub   { font-size: 11px; color: var(--gray-400); }

/* ── PAGE HEADER ── */
.page-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    margin-bottom: 24px;
    flex-wrap: wrap;
    gap: 12px;
}

.page-title    { font-size: 22px; font-weight: 700; color: var(--gray-900); }
.page-subtitle { font-size: 13px; color: var(--gray-500); margin-top: 3px; }

.page-header-actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }

.date-badge {
    display: flex; align-items: center; gap: 6px;
    padding: 8px 14px;
    background: white;
    border: 1px solid var(--gray-200);
    border-radius: var(--radius-sm);
    font-size: 12.5px; color: var(--gray-600); font-weight: 500;
    box-shadow: var(--shadow-sm);
}

/* ── CHARTS GRID ── */
.charts-grid {
    display: grid;
    grid-template-columns: 1.6fr 1fr;
    gap: 18px;
    margin-bottom: 24px;
}

/* ── CHART CARD HEADER ── */
.card-header {
    padding: 16px 20px;
    border-bottom: 1px solid var(--gray-100);
    display: flex; align-items: center; justify-content: space-between;
    flex-wrap: wrap; gap: 8px;
}

.card-title    { font-size: 14px; font-weight: 700; color: var(--gray-800); }
.card-subtitle { font-size: 12px; color: var(--gray-400); margin-top: 2px; }

.card-body { padding: 20px; }

/* Selector de año en gráfico */
.year-selector {
    border: 1px solid var(--gray-200);
    border-radius: 6px;
    padding: 5px 8px;
    font-size: 12px;
    color: var(--gray-700);
    background: var(--white);
    outline: none;
    cursor: pointer;
    font-family: var(--font);
    width: auto;
    min-width: 80px;
    max-width: 100px;
}

.year-selector:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(33,150,243,.10);
}

/* ── LEYENDA PLANES ── */
.plan-legend { display: flex; flex-direction: column; gap: 10px; margin-top: 4px; }

.legend-row {
    display: flex; align-items: center; gap: 10px;
    font-size: 13px; color: var(--gray-700);
}

.legend-dot-sq {
    width: 10px; height: 10px;
    border-radius: 3px; flex-shrink: 0;
}

.legend-bar-wrap {
    flex: 1;
    background: var(--gray-100);
    border-radius: 4px;
    height: 6px;
    overflow: hidden;
}

.legend-bar-fill { height: 100%; border-radius: 4px; transition: width 0.6s ease; }

.legend-pct {
    font-size: 11px; font-weight: 700;
    color: var(--gray-500); min-width: 36px; text-align: right;
}

/* ── QUICK ACTIONS ── */
.quick-actions {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 14px;
    margin-bottom: 24px;
}

.quick-btn {
    background: white;
    border: 1.5px dashed var(--gray-200);
    border-radius: var(--radius);
    padding: 18px 14px;
    display: flex; flex-direction: column; align-items: center; gap: 10px;
    cursor: pointer; transition: var(--transition);
    text-decoration: none;
}

.quick-btn:hover {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(33,150,243,0.10);
    transform: translateY(-2px);
    text-decoration: none;
}

.qb-icon {
    width: 44px; height: 44px;
    border-radius: var(--radius-sm);
    display: flex; align-items: center; justify-content: center;
    font-size: 18px;
}

.qb-icon.blue-soft   { background: #EFF6FF; color: var(--accent); }
.qb-icon.green-soft  { background: #F0FDF4; color: #16A34A; }
.qb-icon.amber-soft  { background: #FFFBEB; color: #D97706; }
.qb-icon.purple-soft { background: #F5F3FF; color: #7C3AED; }
.qb-icon.red-soft    { background: #FEF2F2; color: #DC2626; }

.qb-label { font-size: 12px; font-weight: 600; color: var(--gray-700); text-align: center; }

/* ── TABLES GRID ── */
.tables-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 18px;
    margin-bottom: 24px;
}

/* ── BOTTOM GRID ── */
.bottom-grid {
    display: grid;
    grid-template-columns: 1.4fr 1fr;
    gap: 18px;
    margin-bottom: 24px;
}

/* ── ALERTAS ── */
.alert-list { display: flex; flex-direction: column; gap: 10px; }

.alert-item {
    display: flex; align-items: center; gap: 12px;
    padding: 12px 14px;
    border-radius: var(--radius-sm);
    border: 1px solid;
}

.alert-item.danger { background: #FEF2F2; border-color: #FECACA; }
.alert-item.warn   { background: #FFFBEB; border-color: #FDE68A; }
.alert-item.info   { background: #EFF6FF; border-color: #BFDBFE; }

.alert-icon {
    width: 34px; height: 34px;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 14px; flex-shrink: 0;
}

.alert-item.danger .alert-icon { background: #FEE2E2; color: #DC2626; }
.alert-item.warn   .alert-icon { background: #FEF3C7; color: #D97706; }
.alert-item.info   .alert-icon { background: #DBEAFE; color: #2563EB; }

.alert-content { flex: 1; }
.alert-title { font-size: 13px; font-weight: 700; color: var(--gray-800); }
.alert-desc  { font-size: 11.5px; color: var(--gray-500); margin-top: 2px; }

.alert-action {
    padding: 5px 12px;
    border-radius: 6px; border: none;
    cursor: pointer; font-size: 11.5px; font-weight: 700;
    font-family: var(--font); transition: var(--transition);
    flex-shrink: 0; white-space: nowrap; text-decoration: none;
    display: inline-block;
}

.alert-item.danger .alert-action { background: #FEE2E2; color: #DC2626; }
.alert-item.danger .alert-action:hover { background: #EF4444; color: white; }
.alert-item.warn   .alert-action { background: #FEF3C7; color: #B45309; }
.alert-item.warn   .alert-action:hover { background: #F59E0B; color: white; }
.alert-item.info   .alert-action { background: #DBEAFE; color: #1D4ED8; }
.alert-item.info   .alert-action:hover { background: #3B82F6; color: white; }

/* ── TOP VENDEDORES ── */
.vendor-list  { display: flex; flex-direction: column; gap: 14px; }

.vendor-item  { display: flex; align-items: center; gap: 12px; }
.vendor-rank  { font-size: 13px; font-weight: 800; color: var(--gray-300); width: 20px; text-align: center; flex-shrink: 0; }
.vendor-rank.top { color: var(--amber); }
.vendor-info  { flex: 1; }
.vendor-name  { font-size: 13px; font-weight: 700; color: var(--gray-800); }
.vendor-meta  { font-size: 11.5px; color: var(--gray-400); }
.vendor-stats { text-align: right; }
.vendor-amount    { font-size: 13px; font-weight: 800; color: var(--gray-800); }
.vendor-contracts { font-size: 11px; color: var(--gray-400); }

/* ── ACTIVITY TABLE ── */
.activity-card { margin-bottom: 24px; }

.td-mono   { font-family: monospace; font-size: 12px; font-weight: 700; color: var(--accent); }
.td-client { font-weight: 600; color: var(--gray-800); }
.td-amount { font-weight: 700; color: var(--gray-800); }
.td-muted  { color: var(--gray-400); font-size: 12px; }

.activity-type {
    display: inline-flex; align-items: center;
    padding: 3px 9px; border-radius: 20px;
    font-size: 11px; font-weight: 700;
    background: var(--gray-100); color: var(--gray-600);
}

/* Status badges del dashboard */
.badge-active  { background: #DCFCE7; color: #15803D; }
.badge-pending { background: #FEF3C7; color: #B45309; }
.badge-expired { background: #FEE2E2; color: #DC2626; }
.badge-cancel  { background: var(--gray-100); color: var(--gray-500); }

/* ── RESPONSIVE ── */
@media (max-width: 1280px) {
    .kpi-grid       { grid-template-columns: repeat(2, 1fr); }
    .quick-actions  { grid-template-columns: repeat(3, 1fr); }
}
@media (max-width: 1024px) {
    .charts-grid    { grid-template-columns: 1fr; }
    .tables-grid    { grid-template-columns: 1fr; }
    .bottom-grid    { grid-template-columns: 1fr; }
    .mini-stats-row { grid-template-columns: repeat(2, 1fr); }
}
@media (max-width: 768px) {
    .kpi-grid       { grid-template-columns: 1fr 1fr; }
    .mini-stats-row { grid-template-columns: 1fr 1fr; }
    .quick-actions  { grid-template-columns: repeat(2, 1fr); }
}
@media (max-width: 480px) {
    .kpi-grid       { grid-template-columns: 1fr; }
    .quick-actions  { grid-template-columns: 1fr 1fr; }
}
</style>

<!-- ============================================================
     PAGE HEADER
     ============================================================ -->
<div class="page-header fade-in">
    <div>
        <div class="page-title">Dashboard</div>
        <div class="page-subtitle">Resumen general del sistema — ORTHIIS</div>
    </div>
    <div class="page-header-actions">
        <div class="date-badge">
            <i class="fas fa-calendar" style="color:var(--accent);font-size:12px;"></i>
            <?php
                $meses_es = [
                    1=>'enero',2=>'febrero',3=>'marzo',4=>'abril',
                    5=>'mayo',6=>'junio',7=>'julio',8=>'agosto',
                    9=>'septiembre',10=>'octubre',11=>'noviembre',12=>'diciembre'
                ];
                echo date('j').' de '.$meses_es[(int)date('n')].' de '.date('Y');
            ?>
        </div>
        <a href="clientes.php" class="btn btn-outline btn-sm">
            <i class="fas fa-user-plus"></i> Nuevo Cliente
        </a>
        <a href="contratos.php" class="btn btn-primary btn-sm">
            <i class="fas fa-file-contract"></i> Nuevo Contrato
        </a>
    </div>
</div>


<!-- ============================================================
     KPI CARDS
     ============================================================ -->
<div class="kpi-grid fade-in delay-1">

    <!-- Contratos Activos -->
    <div class="kpi-card blue">
        <div class="kpi-label">Contratos Activos</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo number_format($contratos_activos); ?></div>
                <div class="kpi-sub">Total de contratos vigentes</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-file-contract"></i></div>
        </div>
        <div class="kpi-footer">
            <a class="kpi-link" href="contratos.php">Ver detalles <i class="fas fa-arrow-right"></i></a>
            <span class="kpi-change"><i class="fas fa-arrow-trend-up"></i> Activos</span>
        </div>
    </div>

    <!-- Ingresos del Mes -->
    <div class="kpi-card green">
        <div class="kpi-label">Ingresos del Mes (RD$)</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value large">
                    RD$<?php echo number_format($ingresos_mes, 0, '.', ','); ?>
                </div>
                <div class="kpi-sub">
                    Cobros procesados en <?php echo $meses_es[(int)date('n')]; ?>
                </div>
            </div>
            <div class="kpi-icon"><i class="fas fa-dollar-sign"></i></div>
        </div>
        <div class="kpi-footer">
            <a class="kpi-link" href="pagos.php">Ver reporte <i class="fas fa-arrow-right"></i></a>
            <?php if ($ingresos_mes_anulados > 0): ?>
                <span class="kpi-change">
                    <i class="fas fa-triangle-exclamation"></i>
                    RD$<?php echo number_format($ingresos_mes_anulados, 0); ?> anulado
                </span>
            <?php else: ?>
                <span class="kpi-change"><i class="fas fa-check"></i> Sin anulaciones</span>
            <?php endif; ?>
        </div>
    </div>

    <!-- Monto Pendiente -->
    <div class="kpi-card amber">
        <div class="kpi-label">Monto Pendiente de Cobro</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value large">
                    RD$<?php echo number_format($monto_pendiente, 0, '.', ','); ?>
                </div>
                <div class="kpi-sub">Facturas vencidas sin cobrar</div>
            </div>
            <div class="kpi-icon"><i class="fas fa-hand-holding-dollar"></i></div>
        </div>
        <div class="kpi-footer">
            <a class="kpi-link" href="facturacion.php">Gestionar cobros <i class="fas fa-arrow-right"></i></a>
            <span class="kpi-change">
                <i class="fas fa-triangle-exclamation"></i>
                <?php echo number_format($cant_vencidas); ?> facturas
            </span>
        </div>
    </div>

    <!-- Tasa de Morosidad -->
    <div class="kpi-card red">
        <div class="kpi-label">Tasa de Morosidad</div>
        <div class="kpi-top">
            <div>
                <div class="kpi-value"><?php echo $tasa_morosidad; ?>%</div>
                <div class="kpi-sub">
                    <?php echo $tasa_morosidad > 10 ? 'Requiere atención inmediata' : 'Dentro del rango normal'; ?>
                </div>
            </div>
            <div class="kpi-icon"><i class="fas fa-chart-line"></i></div>
        </div>
        <div class="kpi-footer">
            <a class="kpi-link" href="reportes.php">Ver análisis <i class="fas fa-arrow-right"></i></a>
            <span class="kpi-change">
                <i class="fas fa-file-invoice"></i>
                <?php echo number_format($total_facturas); ?> facturas total
            </span>
        </div>
    </div>

</div>


<!-- ============================================================
     MINI STATS
     ============================================================ -->
<div class="mini-stats-row fade-in delay-2">

    <div class="mini-stat">
        <div class="mini-stat-icon blue-soft"><i class="fas fa-users"></i></div>
        <div class="mini-stat-info">
            <div class="stat-label">Clientes Activos</div>
            <div class="stat-value"><?php echo number_format($clientes_activos); ?></div>
            <div class="stat-sub"><?php echo number_format($clientes_inact); ?> inactivos</div>
        </div>
    </div>

    <div class="mini-stat">
        <div class="mini-stat-icon green-soft"><i class="fas fa-user-group"></i></div>
        <div class="mini-stat-info">
            <div class="stat-label">Dependientes Activos</div>
            <div class="stat-value"><?php echo number_format($dependientes_act); ?></div>
            <div class="stat-sub">
                Este mes +<?php echo number_format($dependientes_mes); ?>
            </div>
        </div>
    </div>

    <div class="mini-stat">
        <div class="mini-stat-icon amber-soft"><i class="fas fa-file-invoice"></i></div>
        <div class="mini-stat-info">
            <div class="stat-label">Facturas Pendientes</div>
            <div class="stat-value"><?php echo number_format($facturas_pend); ?></div>
            <div class="stat-sub">
                <?php echo number_format($facturas_prox); ?> próximas a vencer
            </div>
        </div>
    </div>

    <div class="mini-stat">
        <div class="mini-stat-icon red-soft"><i class="fas fa-clock"></i></div>
        <div class="mini-stat-info">
            <div class="stat-label">Contratos por Vencer</div>
            <div class="stat-value"><?php echo number_format($contratos_por_vencer); ?></div>
            <div class="stat-sub">Próximos 30 días</div>
        </div>
    </div>

</div>


<!-- ============================================================
     CHARTS GRID: Ingresos + Distribución de planes
     ============================================================ -->
<div class="charts-grid fade-in delay-2">

    <!-- Gráfico de líneas: Ingresos mensuales -->
    <div class="card">
        <div class="card-header">
            <div>
                <div class="card-title">Evolución de Ingresos Mensuales</div>
                <div class="card-subtitle">Pagos procesados vs. anulados por mes</div>
            </div>
            <select class="year-selector" id="yearSelector" style="width:auto;min-width:90px;max-width:120px;padding:5px 8px;font-size:12px;">
                <?php for ($y = $currentYear; $y >= $currentYear - 2; $y--): ?>
                    <option value="<?php echo $y; ?>" <?php echo $y == $year ? 'selected' : ''; ?>>
                        <?php echo $y; ?>
                    </option>
                <?php endfor; ?>
            </select>
        </div>
        <div class="card-body" style="padding-top:12px;">
            <div class="chart-container" style="height:260px;">
                <canvas id="chartIngresos"></canvas>
            </div>
        </div>
    </div>

    <!-- Gráfico donut: Distribución de planes -->
    <div class="card">
        <div class="card-header">
            <div>
                <div class="card-title">Distribución por Plan</div>
                <div class="card-subtitle">Contratos activos por plan</div>
            </div>
            <a href="planes.php" class="btn btn-outline btn-sm">
                Ver planes <i class="fas fa-arrow-right" style="font-size:10px;"></i>
            </a>
        </div>
        <div class="card-body" style="padding-top:12px;">
            <div class="chart-container" style="height:180px;margin-bottom:16px;">
                <canvas id="chartPlanes"></canvas>
            </div>
            <!-- Leyenda con barras -->
            <?php
            $colores_planes = ['#1565C0','#2E7D32','#E65100','#7B1FA2','#00838F','#558B2F'];
            ?>
            <div class="plan-legend">
                <?php foreach ($distribucion_planes as $i => $plan):
                    $color = $colores_planes[$i % count($colores_planes)];
                ?>
                <div class="legend-row">
                    <div class="legend-dot-sq" style="background:<?php echo $color; ?>;"></div>
                    <span style="flex:1;font-size:12px;color:var(--gray-700);font-weight:500;">
                        <?php echo htmlspecialchars($plan['nombre']); ?>
                    </span>
                    <div class="legend-bar-wrap">
                        <div class="legend-bar-fill"
                             style="width:<?php echo $plan['porcentaje']; ?>%;background:<?php echo $color; ?>;"></div>
                    </div>
                    <span class="legend-pct"><?php echo $plan['porcentaje']; ?>%</span>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

</div>


<!-- ============================================================
     ACCIONES RÁPIDAS
     ============================================================ -->
<div style="margin-bottom:14px;" class="fade-in delay-2">
    <div style="font-size:12px;font-weight:700;color:var(--gray-500);text-transform:uppercase;letter-spacing:0.8px;">
        Acciones Rápidas
    </div>
</div>
<div class="quick-actions fade-in delay-2">
    <a class="quick-btn" href="clientes.php">
        <div class="qb-icon blue-soft"><i class="fas fa-user-plus"></i></div>
        <span class="qb-label">Nuevo Cliente</span>
    </a>
    <a class="quick-btn" href="contratos.php">
        <div class="qb-icon green-soft"><i class="fas fa-file-contract"></i></div>
        <span class="qb-label">Nuevo Contrato</span>
    </a>
    <a class="quick-btn" href="facturacion.php">
        <div class="qb-icon amber-soft"><i class="fas fa-file-invoice"></i></div>
        <span class="qb-label">Facturación</span>
    </a>
    <a class="quick-btn" href="pagos.php">
        <div class="qb-icon purple-soft"><i class="fas fa-money-check-dollar"></i></div>
        <span class="qb-label">Registrar Pago</span>
    </a>
    <a class="quick-btn" href="reportes.php">
        <div class="qb-icon red-soft"><i class="fas fa-chart-bar"></i></div>
        <span class="qb-label">Generar Reporte</span>
    </a>
</div>


<!-- ============================================================
     TABLES GRID: Últimos contratos + Últimos pagos
     ============================================================ -->
<div class="tables-grid fade-in delay-3">

    <!-- Últimos contratos -->
    <div class="card">
        <div class="card-header">
            <div>
                <div class="card-title">Últimos Contratos Registrados</div>
                <div class="card-subtitle">5 contratos más recientes</div>
            </div>
            <a href="contratos.php" class="btn btn-outline btn-sm">
                Ver todos <i class="fas fa-arrow-right" style="font-size:10px;"></i>
            </a>
        </div>
        <div style="overflow-x:auto;">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Contrato</th>
                        <th>Cliente</th>
                        <th>Plan</th>
                        <th>Monto</th>
                        <th>Estado</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($ultimos_contratos as $c): ?>
                    <tr>
                        <td><span class="td-mono"><?php echo htmlspecialchars($c['numero_contrato']); ?></span></td>
                        <td><span class="td-client"><?php echo htmlspecialchars($c['cliente_nombre']); ?></span></td>
                        <td class="td-muted"><?php echo htmlspecialchars($c['plan_nombre']); ?></td>
                        <td><span class="td-amount">RD$<?php echo number_format($c['monto_mensual'], 2); ?></span></td>
                        <td>
                            <?php
                                $est = $c['estado'];
                                $cls = $est === 'activo' ? 'badge-active' :
                                      ($est === 'vencido' ? 'badge-expired' : 'badge-cancel');
                            ?>
                            <span class="badge <?php echo $cls; ?>">
                                <?php echo ucfirst($est); ?>
                            </span>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                    <?php if (empty($ultimos_contratos)): ?>
                    <tr>
                        <td colspan="5" style="text-align:center;color:var(--gray-400);padding:24px;">
                            No hay contratos registrados
                        </td>
                    </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Últimos pagos -->
    <div class="card">
        <div class="card-header">
            <div>
                <div class="card-title">Últimos Pagos Registrados</div>
                <div class="card-subtitle">5 pagos más recientes</div>
            </div>
            <a href="pagos.php" class="btn btn-outline btn-sm">
                Ver todos <i class="fas fa-arrow-right" style="font-size:10px;"></i>
            </a>
        </div>
        <div style="overflow-x:auto;">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Contrato</th>
                        <th>Cliente</th>
                        <th>Monto</th>
                        <th>Fecha</th>
                        <th>Estado</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($ultimos_pagos as $p): ?>
                    <tr>
                        <td><span class="td-mono"><?php echo htmlspecialchars($p['numero_contrato']); ?></span></td>
                        <td><span class="td-client"><?php echo htmlspecialchars($p['cliente_nombre']); ?></span></td>
                        <td><span class="td-amount">RD$<?php echo number_format($p['monto'], 2); ?></span></td>
                        <td class="td-muted"><?php echo date('d/m/Y', strtotime($p['fecha_pago'])); ?></td>
                        <td>
                            <?php
                                $ep  = $p['estado'];
                                $bcp = $ep === 'procesado' ? 'badge-active' :
                                      ($ep === 'anulado'   ? 'badge-expired' : 'badge-pending');
                            ?>
                            <span class="badge <?php echo $bcp; ?>">
                                <?php echo ucfirst($ep); ?>
                            </span>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                    <?php if (empty($ultimos_pagos)): ?>
                    <tr>
                        <td colspan="5" style="text-align:center;color:var(--gray-400);padding:24px;">
                            No hay pagos registrados
                        </td>
                    </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

</div>


<!-- ============================================================
     BOTTOM GRID: Centro de alertas + Top vendedores
     ============================================================ -->
<div class="bottom-grid fade-in delay-4">

    <!-- ============================================================
         CENTRO DE ALERTAS — Alineado con vigencias.php
         ============================================================ -->
    <?php
    // Calcular total de alertas activas para el badge
    $total_alertas_vig = ($cant_vencidas   > 0 ? 1 : 0)
                       + ($vig_vencidas    > 0 ? 1 : 0)
                       + ($vig_criticas    > 0 ? 1 : 0)
                       + ($vig_urgentes    > 0 ? 1 : 0)
                       + ($vig_por_vencer  > 0 ? 1 : 0)
                       + ($vig_atencion    > 0 ? 1 : 0);
    $todo_ok = ($total_alertas_vig === 0 && $facturas_prox == 0);
    ?>
    <div class="card" style="display:flex;flex-direction:column;">
        <!-- ── Header ── -->
        <div class="card-header" style="flex-shrink:0;">
            <div>
                <div class="card-title">
                    <i class="fas fa-shield-exclamation"
                       style="color:#F59E0B;margin-right:6px;font-size:14px;"></i>
                    Centro de Alertas
                </div>
                <div class="card-subtitle">Vigencias y situaciones que requieren atención</div>
            </div>
            <div style="display:flex;align-items:center;gap:8px;">
                <?php if (!$todo_ok): ?>
                <span class="badge badge-pending" style="font-size:11px;padding:4px 10px;">
                    <?php echo $total_alertas_vig; ?>
                    alerta<?php echo $total_alertas_vig > 1 ? 's' : ''; ?>
                </span>
                <?php endif; ?>
                <a href="vigencia.php" class="btn btn-outline btn-sm"
                   style="font-size:11px;padding:5px 10px;white-space:nowrap;">
                    <i class="fas fa-shield-halved" style="font-size:10px;"></i>
                    Ver Vigencias
                </a>
            </div>
        </div>

        <!-- ── Monto Global Pendiente (siempre visible) ── -->
        <div style="padding:14px 20px;background:linear-gradient(135deg,#0D47A1,#1565C0);
                    display:flex;align-items:center;justify-content:space-between;gap:12px;
                    flex-shrink:0;">
            <div style="display:flex;align-items:center;gap:10px;">
                <div style="width:36px;height:36px;background:rgba(255,255,255,.18);
                            border-radius:8px;display:flex;align-items:center;
                            justify-content:center;font-size:15px;color:white;flex-shrink:0;">
                    <i class="fas fa-globe"></i>
                </div>
                <div>
                    <div style="font-size:10px;font-weight:700;color:rgba(255,255,255,.75);
                                text-transform:uppercase;letter-spacing:.7px;margin-bottom:1px;">
                        Monto Pendiente Global
                    </div>
                    <div style="font-size:20px;font-weight:800;color:white;line-height:1;">
                        RD$<?php echo number_format($monto_global_vigencias, 2); ?>
                    </div>
                </div>
            </div>
            <div style="text-align:right;">
                <div style="font-size:10px;color:rgba(255,255,255,.65);font-weight:600;
                            text-transform:uppercase;letter-spacing:.6px;">Contratos activos</div>
                <div style="font-size:13px;font-weight:700;color:white;margin-top:2px;">
                    Fact. pend. + incompletas + vencidas
                </div>
            </div>
        </div>

        <!-- ── Lista de alertas ── -->
        <div class="card-body" style="flex:1;padding:14px 16px;">
            <div class="alert-list" style="gap:8px;">

                <?php if ($todo_ok): ?>
                <!-- Todo OK -->
                <div style="text-align:center;padding:28px 16px;color:var(--gray-400);">
                    <i class="fas fa-circle-check"
                       style="font-size:32px;color:#16A34A;display:block;margin-bottom:10px;"></i>
                    <div style="font-size:13px;font-weight:700;color:var(--gray-700);">
                        ¡Todo está en orden!
                    </div>
                    <div style="font-size:12px;margin-top:4px;">
                        No hay vigencias ni alertas pendientes.
                    </div>
                </div>
                <?php endif; ?>

                <?php if ($cant_vencidas > 0): ?>
                <!-- 1. Facturas Vencidas sin Cobrar -->
                <div class="alert-item danger" style="flex-direction:column;align-items:flex-start;gap:8px;padding:12px 14px;">
                    <div style="display:flex;align-items:center;gap:10px;width:100%;">
                        <div class="alert-icon" style="flex-shrink:0;">
                            <i class="fas fa-file-invoice-dollar"></i>
                        </div>
                        <div class="alert-content" style="flex:1;min-width:0;">
                            <div class="alert-title">
                                <i class="fas fa-circle-xmark" style="font-size:10px;margin-right:3px;"></i>
                                <?php echo number_format($cant_vencidas); ?>
                                Factura<?php echo $cant_vencidas > 1 ? 's' : ''; ?>
                                Vencida<?php echo $cant_vencidas > 1 ? 's' : ''; ?> sin Cobrar
                            </div>
                            <div class="alert-desc">
                                Monto pendiente:
                                <strong>RD$<?php echo number_format($monto_pendiente, 2); ?></strong>
                            </div>
                        </div>
                        <a href="facturacion.php?estado=vencida" class="alert-action" style="flex-shrink:0;">
                            Gestionar
                        </a>
                    </div>
                </div>
                <?php endif; ?>

                <?php if ($vig_vencidas > 0): ?>
                <!-- 2. Vigencias Vencidas -->
                <div class="alert-item danger" style="padding:11px 14px;">
                    <div class="alert-icon" style="flex-shrink:0;">
                        <i class="fas fa-calendar-xmark"></i>
                    </div>
                    <div class="alert-content" style="flex:1;min-width:0;">
                        <div class="alert-title">
                            <i class="fas fa-circle" style="font-size:7px;margin-right:4px;color:#DC2626;"></i>
                            <?php echo number_format($vig_vencidas); ?>
                            Vigencia<?php echo $vig_vencidas > 1 ? 's' : ''; ?> Vencida<?php echo $vig_vencidas > 1 ? 's' : ''; ?>
                        </div>
                        <div class="alert-desc">Contratos activos con fecha de vigencia expirada</div>
                    </div>
                    <a href="vigencia.php?clasificacion=vencido" class="alert-action" style="flex-shrink:0;">
                        Ver
                    </a>
                </div>
                <?php endif; ?>

                <?php if ($vig_criticas > 0): ?>
                <!-- 3. Vigencias Críticas (≤ 7 días) -->
                <div class="alert-item danger" style="background:#FFF5F5;border-color:#FECACA;padding:11px 14px;">
                    <div class="alert-icon" style="flex-shrink:0;background:#FEE2E2;color:#C62828;">
                        <i class="fas fa-circle-radiation"></i>
                    </div>
                    <div class="alert-content" style="flex:1;min-width:0;">
                        <div class="alert-title">
                            <i class="fas fa-circle" style="font-size:7px;margin-right:4px;color:#C62828;"></i>
                            <?php echo number_format($vig_criticas); ?>
                            Vigencia<?php echo $vig_criticas > 1 ? 's' : ''; ?> Crítica<?php echo $vig_criticas > 1 ? 's' : ''; ?>
                        </div>
                        <div class="alert-desc">Vencen dentro de los próximos <strong>7 días</strong></div>
                    </div>
                    <a href="vigencia.php?clasificacion=critico" class="alert-action" style="flex-shrink:0;">
                        Atender
                    </a>
                </div>
                <?php endif; ?>

                <?php if ($vig_urgentes > 0): ?>
                <!-- 4. Vigencias Urgentes (8-15 días) -->
                <div class="alert-item warn" style="background:#FFF7ED;border-color:#FED7AA;padding:11px 14px;">
                    <div class="alert-icon" style="flex-shrink:0;background:#FFEDD5;color:#C2410C;">
                        <i class="fas fa-triangle-exclamation"></i>
                    </div>
                    <div class="alert-content" style="flex:1;min-width:0;">
                        <div class="alert-title">
                            <i class="fas fa-circle" style="font-size:7px;margin-right:4px;color:#C2410C;"></i>
                            <?php echo number_format($vig_urgentes); ?>
                            Vigencia<?php echo $vig_urgentes > 1 ? 's' : ''; ?> Urgente<?php echo $vig_urgentes > 1 ? 's' : ''; ?>
                        </div>
                        <div class="alert-desc">Vencen entre <strong>8 y 15 días</strong></div>
                    </div>
                    <a href="vigencia.php?dias_max=15" class="alert-action"
                       style="flex-shrink:0;background:#FFEDD5;color:#C2410C;">
                        Revisar
                    </a>
                </div>
                <?php endif; ?>

                <?php if ($vig_por_vencer > 0): ?>
                <!-- 5. Vigencias Por Vencer (16-30 días) -->
                <div class="alert-item warn" style="padding:11px 14px;">
                    <div class="alert-icon" style="flex-shrink:0;">
                        <i class="fas fa-hourglass-half"></i>
                    </div>
                    <div class="alert-content" style="flex:1;min-width:0;">
                        <div class="alert-title">
                            <i class="fas fa-circle" style="font-size:7px;margin-right:4px;color:#D97706;"></i>
                            <?php echo number_format($vig_por_vencer); ?>
                            Vigencia<?php echo $vig_por_vencer > 1 ? 's' : ''; ?> Por Vencer
                        </div>
                        <div class="alert-desc">Vencen entre <strong>16 y 30 días</strong></div>
                    </div>
                    <a href="vigencia.php?dias_max=30" class="alert-action" style="flex-shrink:0;">
                        Ver
                    </a>
                </div>
                <?php endif; ?>

                <?php if ($vig_atencion > 0): ?>
                <!-- 6. Vigencias Atención (31-60 días) -->
                <div class="alert-item info" style="padding:11px 14px;">
                    <div class="alert-icon" style="flex-shrink:0;">
                        <i class="fas fa-eye"></i>
                    </div>
                    <div class="alert-content" style="flex:1;min-width:0;">
                        <div class="alert-title">
                            <i class="fas fa-circle" style="font-size:7px;margin-right:4px;color:#2563EB;"></i>
                            <?php echo number_format($vig_atencion); ?>
                            Vigencia<?php echo $vig_atencion > 1 ? 's' : ''; ?> en Atención
                        </div>
                        <div class="alert-desc">Vencen entre <strong>31 y 60 días</strong> — Monitoreo preventivo</div>
                    </div>
                    <a href="vigencia.php?dias_max=60" class="alert-action" style="flex-shrink:0;">
                        Monitorear
                    </a>
                </div>
                <?php endif; ?>

                <?php if ($facturas_prox > 0): ?>
                <!-- 7. Facturas próximas a vencer esta semana -->
                <div class="alert-item info" style="background:#F0FDF4;border-color:#BBF7D0;padding:11px 14px;">
                    <div class="alert-icon" style="flex-shrink:0;background:#DCFCE7;color:#16A34A;">
                        <i class="fas fa-clock"></i>
                    </div>
                    <div class="alert-content" style="flex:1;min-width:0;">
                        <div class="alert-title">
                            <i class="fas fa-circle" style="font-size:7px;margin-right:4px;color:#16A34A;"></i>
                            <?php echo number_format($facturas_prox); ?>
                            Factura<?php echo $facturas_prox > 1 ? 's' : ''; ?> por Vencer esta Semana
                        </div>
                        <div class="alert-desc">Vencen en los próximos <strong>7 días</strong></div>
                    </div>
                    <a href="facturacion.php?estado=pendiente" class="alert-action"
                       style="flex-shrink:0;background:#DCFCE7;color:#15803D;">
                        Cobrar
                    </a>
                </div>
                <?php endif; ?>

            </div>
        </div>

        <!-- ── Footer con resumen de contadores ── -->
        <?php if (!$todo_ok): ?>
        <div style="padding:10px 16px;border-top:1px solid var(--gray-200);
                    background:var(--gray-50);flex-shrink:0;
                    display:flex;align-items:center;justify-content:space-between;
                    flex-wrap:wrap;gap:6px;">
            <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
                <?php if ($vig_vencidas > 0): ?>
                <span style="display:inline-flex;align-items:center;gap:4px;
                             font-size:11px;font-weight:700;
                             background:#FEE2E2;color:#991B1B;
                             padding:3px 9px;border-radius:20px;">
                    <i class="fas fa-circle" style="font-size:6px;"></i>
                    <?php echo $vig_vencidas; ?> Vencida<?php echo $vig_vencidas>1?'s':''; ?>
                </span>
                <?php endif; ?>
                <?php if ($vig_criticas > 0): ?>
                <span style="display:inline-flex;align-items:center;gap:4px;
                             font-size:11px;font-weight:700;
                             background:#FEE2E2;color:#C62828;
                             padding:3px 9px;border-radius:20px;">
                    <i class="fas fa-circle" style="font-size:6px;"></i>
                    <?php echo $vig_criticas; ?> Crítica<?php echo $vig_criticas>1?'s':''; ?>
                </span>
                <?php endif; ?>
                <?php if ($vig_urgentes > 0): ?>
                <span style="display:inline-flex;align-items:center;gap:4px;
                             font-size:11px;font-weight:700;
                             background:#FFEDD5;color:#C2410C;
                             padding:3px 9px;border-radius:20px;">
                    <i class="fas fa-circle" style="font-size:6px;"></i>
                    <?php echo $vig_urgentes; ?> Urgente<?php echo $vig_urgentes>1?'s':''; ?>
                </span>
                <?php endif; ?>
                <?php if ($vig_por_vencer > 0): ?>
                <span style="display:inline-flex;align-items:center;gap:4px;
                             font-size:11px;font-weight:700;
                             background:#FEF3C7;color:#B45309;
                             padding:3px 9px;border-radius:20px;">
                    <i class="fas fa-circle" style="font-size:6px;"></i>
                    <?php echo $vig_por_vencer; ?> Por vencer
                </span>
                <?php endif; ?>
                <?php if ($vig_atencion > 0): ?>
                <span style="display:inline-flex;align-items:center;gap:4px;
                             font-size:11px;font-weight:700;
                             background:#DBEAFE;color:#1E40AF;
                             padding:3px 9px;border-radius:20px;">
                    <i class="fas fa-circle" style="font-size:6px;"></i>
                    <?php echo $vig_atencion; ?> Atención
                </span>
                <?php endif; ?>
            </div>
            <a href="vigencia.php" style="font-size:11.5px;font-weight:700;
                                          color:var(--accent);text-decoration:none;
                                          display:flex;align-items:center;gap:4px;">
                Ver reporte completo
                <i class="fas fa-arrow-right" style="font-size:10px;"></i>
            </a>
        </div>
        <?php endif; ?>
    </div>

    <!-- Top vendedores -->
    <div class="card">
        <div class="card-header">
            <div>
                <div class="card-title">
                    <i class="fas fa-trophy" style="color:var(--amber);margin-right:6px;font-size:14px;"></i>
                    Top Vendedores
                </div>
                <div class="card-subtitle">Por monto total cobrado</div>
            </div>
            <a href="vendedores.php" class="btn btn-outline btn-sm">
                Ver todos <i class="fas fa-arrow-right" style="font-size:10px;"></i>
            </a>
        </div>
        <div class="card-body">
            <div class="vendor-list">
                <?php if (!empty($top_vendedores)): ?>
                    <?php foreach ($top_vendedores as $i => $v): ?>
                    <div class="vendor-item">
                        <div class="vendor-rank <?php echo $i === 0 ? 'top' : ''; ?>">
                            <?php echo $i + 1; ?>
                        </div>
                        <div class="vendor-info">
                            <div class="vendor-name">
                                <?php echo htmlspecialchars($v['nombre_completo']); ?>
                            </div>
                            <div class="vendor-meta">
                                <?php echo number_format($v['total_contratos']); ?> contrato<?php echo $v['total_contratos'] != 1 ? 's' : ''; ?>
                            </div>
                        </div>
                        <div class="vendor-stats">
                            <div class="vendor-amount">
                                RD$<?php echo number_format($v['monto_total'], 0); ?>
                            </div>
                            <div class="vendor-contracts">Total cobrado</div>
                        </div>
                    </div>
                    <?php endforeach; ?>
                <?php else: ?>
                    <div style="text-align:center;padding:20px;color:var(--gray-400);">
                        <i class="fas fa-user-tie" style="font-size:24px;display:block;margin-bottom:8px;"></i>
                        <div style="font-size:13px;">Sin datos de vendedores</div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

</div>


<!-- ============================================================
     TABLA DE ACTIVIDADES RECIENTES
     ============================================================ -->
<div class="card activity-card fade-in delay-4">
    <div class="card-header">
        <div>
            <div class="card-title">Últimas Actividades del Sistema</div>
            <div class="card-subtitle">Acciones recientes registradas en el log</div>
        </div>
    </div>
    <div style="overflow-x:auto;">
        <table class="data-table">
            <thead>
                <tr>
                    <th>Fecha / Hora</th>
                    <th>Usuario</th>
                    <th>Acción</th>
                    <th>Detalles</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($ultimas_actividades as $act): ?>
                <tr>
                    <td class="td-muted">
                        <?php echo date('d/m/Y H:i', strtotime($act['created_at'])); ?>
                    </td>
                    <td>
                        <span class="td-client">
                            <?php echo htmlspecialchars($act['usuario_nombre']); ?>
                        </span>
                    </td>
                    <td>
                        <span class="activity-type">
                            <?php echo htmlspecialchars($act['accion']); ?>
                        </span>
                    </td>
                    <td class="td-muted">
                        <?php echo htmlspecialchars($act['detalles']); ?>
                    </td>
                </tr>
                <?php endforeach; ?>
                <?php if (empty($ultimas_actividades)): ?>
                <tr>
                    <td colspan="4" style="text-align:center;color:var(--gray-400);padding:24px;">
                        No hay actividades registradas
                    </td>
                </tr>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>


<!-- ============================================================
     SCRIPTS DE GRÁFICAS
     ============================================================ -->
<script>
/* ============================================================
   DATOS PHP → JAVASCRIPT
   ============================================================ */
const datosIngresos = {
    procesados : [<?php echo implode(',', $datos_procesados); ?>],
    anulados   : [<?php echo implode(',', $datos_anulados); ?>]
};
const planesLabels  = <?php echo json_encode($planesLabels); ?>;
const planesData    = <?php echo json_encode($planesData); ?>;

/* ============================================================
   COLORES CONSISTENTES CON EL DISEÑO
   ============================================================ */
const COLORS = {
    blue      : '#1976D2',
    blueAlpha : 'rgba(25,118,210,0.12)',
    red       : '#D32F2F',
    redAlpha  : 'rgba(211,47,47,0.12)',
    planes    : ['#1565C0','#2E7D32','#E65100','#7B1FA2','#00838F','#558B2F']
};

/* ============================================================
   OPCIONES BASE PARA TODOS LOS GRÁFICOS
   ============================================================ */
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.font.size   = 12;

/* ============================================================
   GRÁFICO 1 — LÍNEAS: Ingresos Mensuales
   ============================================================ */
(function () {
    const ctx = document.getElementById('chartIngresos');
    if (!ctx) return;

    new Chart(ctx, {
        type : 'line',
        data : {
            labels   : ['Ene','Feb','Mar','Abr','May','Jun','Jul','Ago','Sep','Oct','Nov','Dic'],
            datasets : [
                {
                    label           : 'Ingresos Procesados (RD$)',
                    data            : datosIngresos.procesados,
                    borderColor     : COLORS.blue,
                    backgroundColor : COLORS.blueAlpha,
                    borderWidth     : 2.5,
                    pointBackgroundColor : COLORS.blue,
                    pointRadius     : 4,
                    pointHoverRadius: 6,
                    fill            : true,
                    tension         : 0.4
                },
                {
                    label           : 'Pagos Anulados (RD$)',
                    data            : datosIngresos.anulados,
                    borderColor     : COLORS.red,
                    backgroundColor : COLORS.redAlpha,
                    borderWidth     : 2,
                    borderDash      : [5, 4],
                    pointBackgroundColor : COLORS.red,
                    pointRadius     : 3,
                    pointHoverRadius: 5,
                    fill            : true,
                    tension         : 0.4
                }
            ]
        },
        options : {
            responsive          : true,
            maintainAspectRatio : false,
            interaction : { mode : 'index', intersect : false },
            plugins : {
                legend : {
                    position : 'bottom',
                    labels   : { padding: 16, usePointStyle: true, pointStyleWidth: 10, boxHeight: 8 }
                },
                tooltip : {
                    callbacks : {
                        label : ctx => ' RD$' + ctx.parsed.y.toLocaleString('es-DO', { minimumFractionDigits: 2 })
                    }
                }
            },
            scales : {
                x : {
                    grid : { display: false },
                    ticks: { color: '#94A3B8' }
                },
                y : {
                    beginAtZero : true,
                    grid        : { color: 'rgba(0,0,0,0.05)' },
                    ticks       : {
                        color    : '#94A3B8',
                        callback : v => 'RD$' + (v >= 1000 ? (v/1000).toFixed(0)+'K' : v)
                    }
                }
            }
        }
    });
})();


/* ============================================================
   GRÁFICO 2 — DONUT: Distribución de Planes
   ============================================================ */
(function () {
    const ctx = document.getElementById('chartPlanes');
    if (!ctx || planesData.length === 0) return;

    new Chart(ctx, {
        type : 'doughnut',
        data : {
            labels   : planesLabels,
            datasets : [{
                data            : planesData,
                backgroundColor : COLORS.planes,
                borderColor     : '#ffffff',
                borderWidth     : 3,
                hoverOffset     : 6
            }]
        },
        options : {
            responsive          : true,
            maintainAspectRatio : false,
            cutout              : '65%',
            plugins : {
                legend  : { display: false },
                tooltip : {
                    callbacks : {
                        label : ctx => ' ' + ctx.label + ': ' + ctx.parsed + '%'
                    }
                }
            }
        }
    });
})();


/* ============================================================
   SELECTOR DE AÑO → recarga la página con el año seleccionado
   ============================================================ */
(function () {
    const sel = document.getElementById('yearSelector');
    if (sel) {
        sel.addEventListener('change', function () {
            window.location.href = 'dashboard.php?year=' + this.value;
        });
    }
})();
</script>

<?php require_once 'footer.php'; ?>