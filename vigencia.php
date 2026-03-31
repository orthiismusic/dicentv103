<?php
/* ============================================================
   vigencia.php — Control de Vigencias de Contratos
   Sistema ORTHIIS — Seguros de Vida
   ============================================================ */
require_once 'config.php';
verificarSesion();

/* ── Helpers ────────────────────────────────────────────────── */
function diasRestantes($fecha_fin): int {
    if (!$fecha_fin) return 9999;
    $hoy  = new DateTime(date('Y-m-d'));
    $fin  = new DateTime($fecha_fin);
    $diff = $hoy->diff($fin);
    return $diff->invert ? -$diff->days : $diff->days;
}

function clasificarVigencia(int $dias): array {
    if ($dias < 0)   return ['cls'=>'vencida',  'label'=>'Vencida',      'color'=>'#B71C1C','bg'=>'#FEE2E2','icon'=>'fa-circle-xmark'];
    if ($dias === 0) return ['cls'=>'hoy',       'label'=>'Vence Hoy',   'color'=>'#7B1FA2','bg'=>'#F3E5F5','icon'=>'fa-circle-exclamation'];
    if ($dias <= 7)  return ['cls'=>'critica',   'label'=>'Crítica',     'color'=>'#C62828','bg'=>'#FFEBEE','icon'=>'fa-triangle-exclamation'];
    if ($dias <= 15) return ['cls'=>'urgente',   'label'=>'Urgente',     'color'=>'#E65100','bg'=>'#FFF3E0','icon'=>'fa-circle-exclamation'];
    if ($dias <= 30) return ['cls'=>'proxima',   'label'=>'Por Vencer',  'color'=>'#F57F17','bg'=>'#FFFDE7','icon'=>'fa-clock'];
    if ($dias <= 60) return ['cls'=>'atencion',  'label'=>'Atención',    'color'=>'#0277BD','bg'=>'#E1F5FE','icon'=>'fa-eye'];
    return             ['cls'=>'vigente',    'label'=>'Al Día',      'color'=>'#1B5E20','bg'=>'#E8F5E9','icon'=>'fa-circle-check'];
}

function buildVigUrl(int $pag, string $qs = ''): string {
    return 'vigencia.php?pagina=' . $pag . ($qs ? '&'.$qs : '');
}

/* ── Filtros ────────────────────────────────────────────────── */
$buscar       = trim($_GET['buscar']       ?? '');
$filtro_clasif= trim($_GET['clasificacion']?? '');
$filtro_cobrad= trim($_GET['cobrador_id']  ?? '');
$filtro_plan  = trim($_GET['plan_id']      ?? '');
$filtro_dias  = trim($_GET['dias_max']     ?? '60');  // por defecto 60 días
$mostrar_al_dia = ($_GET['mostrar_al_dia'] ?? '0') === '1';

/* ── Paginación ─────────────────────────────────────────────── */
$por_pagina    = isset($_COOKIE['vigencia_por_pagina']) ? (int)$_COOKIE['vigencia_por_pagina'] : 50;
$pagina_actual = max(1, intval($_GET['pagina'] ?? 1));
$offset        = ($pagina_actual - 1) * $por_pagina;

/* ── Query base de contratos activos con vigencia ─────────────
   Obtenemos contratos activos con su monto pendiente total,
   cantidad de facturas pendientes y días de vigencia restantes.
   ─────────────────────────────────────────────────────────── */
$hoy = date('Y-m-d');

$whereContratos = "c.estado = 'activo'";
$paramsContratos = [];

if ($buscar !== '') {
    $t = "%$buscar%";
    $whereContratos .= " AND (c.numero_contrato LIKE ? OR cl.nombre LIKE ?
                           OR cl.apellidos LIKE ? OR CONCAT(cl.nombre,' ',cl.apellidos) LIKE ?
                           OR cl.telefono1 LIKE ? OR cl.cedula LIKE ?)";
    array_push($paramsContratos, $t, $t, $t, $t, $t, $t);
}
if ($filtro_cobrad !== '') {
    $whereContratos .= " AND cl.cobrador_id = ?";
    $paramsContratos[] = (int)$filtro_cobrad;
}
if ($filtro_plan !== '') {
    $whereContratos .= " AND c.plan_id = ?";
    $paramsContratos[] = (int)$filtro_plan;
}

/* Filtro por días (si no se muestran todos) */
$whereDias = '';
if (!$mostrar_al_dia) {
    if ($filtro_dias !== '' && is_numeric($filtro_dias)) {
        $diasMax = (int)$filtro_dias;
        $fechaLimite = date('Y-m-d', strtotime("+{$diasMax} days"));
        $whereDias = " AND (c.fecha_fin IS NULL OR c.fecha_fin <= ?)";
        $paramsContratos[] = $fechaLimite;
    }
}

$sqlBase = "
    FROM contratos c
    JOIN clientes    cl ON c.cliente_id  = cl.id
    JOIN planes      p  ON c.plan_id     = p.id
    LEFT JOIN cobradores co ON cl.cobrador_id = co.id
    LEFT JOIN vendedores  v  ON c.vendedor_id = v.id
    WHERE $whereContratos $whereDias
";

/* total */
$stmtCnt = $conn->prepare("SELECT COUNT(*) AS total $sqlBase");
$stmtCnt->execute($paramsContratos);
$total_registros = (int)$stmtCnt->fetchColumn();
$total_paginas   = max(1, ceil($total_registros / $por_pagina));

/* listado principal */
$sqlMain = "
    SELECT
        c.id                AS contrato_id,
        c.numero_contrato,
        c.fecha_inicio,
        c.fecha_fin,
        c.monto_mensual,
        c.monto_total,
        c.dia_cobro,
        c.estado,
        cl.id               AS cliente_id,
        cl.nombre           AS cliente_nombre,
        cl.apellidos        AS cliente_apellidos,
        cl.cedula           AS cliente_cedula,
        cl.telefono1        AS cliente_telefono1,
        cl.telefono2        AS cliente_telefono2,
        cl.direccion        AS cliente_direccion,
        p.nombre            AS plan_nombre,
        co.nombre_completo  AS cobrador_nombre,
        co.id               AS cobrador_id,
        v.nombre_completo   AS vendedor_nombre,
        /* ── Facturas pendientes ── */
        (SELECT COUNT(*)
         FROM facturas f
         WHERE f.contrato_id = c.id
           AND f.estado IN ('pendiente','incompleta','vencida')) AS total_facturas_pendientes,
        /* ── Monto total pendiente real ── */
        (SELECT COALESCE(SUM(
             f2.monto - COALESCE(
                 (SELECT SUM(pg.monto) FROM pagos pg
                  WHERE pg.factura_id = f2.id AND pg.estado = 'procesado'), 0)
         ), 0)
         FROM facturas f2
         WHERE f2.contrato_id = c.id
           AND f2.estado IN ('pendiente','incompleta','vencida')) AS monto_pendiente_total,
        /* ── Última factura pagada ── */
        (SELECT MAX(f3.fecha_vencimiento)
         FROM facturas f3
         WHERE f3.contrato_id = c.id AND f3.estado = 'pagada') AS ultima_factura_pagada,
        /* ── Total facturas emitidas ── */
        (SELECT COUNT(*) FROM facturas f4
         WHERE f4.contrato_id = c.id) AS total_facturas_emitidas,
        /* ── Total pagado en el contrato ── */
        (SELECT COALESCE(SUM(pg2.monto),0)
         FROM pagos pg2
         JOIN facturas f5 ON pg2.factura_id = f5.id
         WHERE f5.contrato_id = c.id AND pg2.estado = 'procesado') AS total_cobrado_contrato,
        /* ── Mes de inicio de atraso (factura pendiente más antigua) ── */
        (
            SELECT f2.mes_factura
            FROM facturas f2
            WHERE f2.contrato_id = c.id
              AND f2.estado IN ('pendiente','incompleta','vencida')
            ORDER BY f2.id ASC
            LIMIT 1
        ) AS mes_atraso_inicio
    $sqlBase
    ORDER BY c.fecha_fin ASC, c.numero_contrato ASC
    LIMIT ? OFFSET ?
";
$stmtMain = $conn->prepare($sqlMain);
$allP = array_merge($paramsContratos, [$por_pagina, $offset]);
foreach ($allP as $i => $v) {
    $stmtMain->bindValue($i + 1, $v, is_int($v) ? PDO::PARAM_INT : PDO::PARAM_STR);
}
$stmtMain->execute();
$contratos = $stmtMain->fetchAll(PDO::FETCH_ASSOC);

/* ── KPI Stats globales ─────────────────────────────────────── */
$stmtKpi = $conn->query("
    SELECT
        COUNT(*)                                     AS total_contratos,
        SUM(c.estado='activo')                        AS total_activos,
        SUM(c.fecha_fin < CURDATE() AND c.estado='activo')     AS vencidos,
        SUM(c.fecha_fin >= CURDATE() AND c.fecha_fin <= DATE_ADD(CURDATE(), INTERVAL 7 DAY) AND c.estado='activo') AS criticos,
        SUM(c.fecha_fin > DATE_ADD(CURDATE(), INTERVAL 7 DAY)
            AND c.fecha_fin <= DATE_ADD(CURDATE(), INTERVAL 30 DAY) AND c.estado='activo') AS proximos,
        SUM(c.fecha_fin > DATE_ADD(CURDATE(), INTERVAL 30 DAY) AND c.estado='activo') AS al_dia
    FROM contratos c
    WHERE c.estado = 'activo'
");
$kpi = $stmtKpi->fetch(PDO::FETCH_ASSOC);

/* Monto total pendiente global */
$stmtMonto = $conn->query("
    SELECT COALESCE(SUM(
        f.monto - COALESCE(
            (SELECT SUM(pg.monto) FROM pagos pg
             WHERE pg.factura_id = f.id AND pg.estado='procesado'), 0)
    ), 0) AS monto_global_pendiente
    FROM facturas f
    JOIN contratos c ON f.contrato_id = c.id
    WHERE c.estado = 'activo'
      AND f.estado IN ('pendiente','incompleta','vencida')
");
$montoGlobal = (float)$stmtMonto->fetchColumn();

/* ── Listas para filtros ────────────────────────────────────── */
$cobradores = $conn->query("
    SELECT id, nombre_completo FROM cobradores WHERE estado='activo' ORDER BY nombre_completo
")->fetchAll();

$planes = $conn->query("
    SELECT id, nombre FROM planes WHERE estado='activo' ORDER BY nombre
")->fetchAll();

/* ── Parámetros para paginador ─────────────────────────────── */
$params_url = http_build_query(array_filter([
    'buscar'        => $buscar,
    'clasificacion' => $filtro_clasif,
    'cobrador_id'   => $filtro_cobrad,
    'plan_id'       => $filtro_plan,
    'dias_max'      => $filtro_dias,
    'mostrar_al_dia'=> $mostrar_al_dia ? '1' : '',
]));

/* ── Nombre de empresa para WhatsApp ── */
$stmtEmpresa = $conn->query("SELECT nombre_empresa FROM configuracion_sistema WHERE id = 1 LIMIT 1");
$nombreEmpresa = $stmtEmpresa ? (string)($stmtEmpresa->fetchColumn() ?: 'SEFURE S.A.') : 'SEFURE S.A.';

require_once 'header.php';
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
.page-actions{display:flex;gap:10px;flex-wrap:wrap;align-items:center;}

/* ── KPI Cards ── */
.kpi-vigencia{display:grid;grid-template-columns:repeat(5,1fr);gap:16px;margin-bottom:24px;}
@media(max-width:1200px){.kpi-vigencia{grid-template-columns:repeat(3,1fr);}}
@media(max-width:700px) {.kpi-vigencia{grid-template-columns:repeat(2,1fr);}}
@media(max-width:460px) {.kpi-vigencia{grid-template-columns:1fr;}}
.kpi-card-v{border-radius:var(--radius);padding:20px 20px 16px;position:relative;
    overflow:hidden;box-shadow:var(--shadow);transition:var(--transition);
    color:white;cursor:default;border:none;}
.kpi-card-v:hover{transform:translateY(-3px);box-shadow:var(--shadow-md);}
.kpi-card-v::before{content:'';position:absolute;top:0;right:0;width:70px;height:70px;
    border-radius:0 var(--radius) 0 100%;opacity:.15;background:white;}
.kpi-card-v.red    {background:linear-gradient(135deg,#B71C1C,#C62828);}
.kpi-card-v.orange {background:linear-gradient(135deg,#BF360C,#D84315);}
.kpi-card-v.amber  {background:linear-gradient(135deg,#E65100,#F57F17);}
.kpi-card-v.blue   {background:linear-gradient(135deg,#1565C0,#1976D2);}
.kpi-card-v.green  {background:linear-gradient(135deg,#1B5E20,#2E7D32);}
.kpi-card-v.purple {background:linear-gradient(135deg,#4A148C,#6A1B9A);}
.kpi-v-label{font-size:10.5px;font-weight:600;color:rgba(255,255,255,.80);
    text-transform:uppercase;letter-spacing:.8px;margin-bottom:9px;}
.kpi-v-top{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:5px;}
.kpi-v-value{font-size:30px;font-weight:800;color:white;line-height:1;margin-bottom:3px;}
.kpi-v-sub{font-size:11px;color:rgba(255,255,255,.70);font-weight:500;}
.kpi-v-icon{width:44px;height:44px;background:rgba(255,255,255,.18);border-radius:var(--radius-sm);
    display:flex;align-items:center;justify-content:center;font-size:19px;color:white;flex-shrink:0;}
.kpi-v-footer{margin-top:12px;padding-top:10px;border-top:1px solid rgba(255,255,255,.15);
    font-size:11px;color:rgba(255,255,255,.80);font-weight:600;
    display:flex;align-items:center;gap:5px;}

/* ── Alerta urgencia global ── */
.urgency-banner{border-radius:var(--radius);padding:14px 20px;margin-bottom:20px;
    display:flex;align-items:center;gap:14px;font-size:13px;font-weight:600;}
.urgency-banner.danger{background:linear-gradient(135deg,#FEE2E2,#FECACA);
    border:1px solid #FCA5A5;color:#991B1B;}
.urgency-banner.warning{background:linear-gradient(135deg,#FEF3C7,#FDE68A);
    border:1px solid #FCD34D;color:#92400E;}
.urgency-banner.success{background:linear-gradient(135deg,#DCFCE7,#BBF7D0);
    border:1px solid #86EFAC;color:#166534;}
.urgency-banner .ub-icon{width:42px;height:42px;border-radius:var(--radius-sm);
    display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0;}
.urgency-banner.danger  .ub-icon{background:#DC2626;color:white;}
.urgency-banner.warning .ub-icon{background:#D97706;color:white;}
.urgency-banner.success .ub-icon{background:#16A34A;color:white;}
.urgency-banner .ub-text{flex:1;}
.urgency-banner .ub-title{font-size:14px;font-weight:700;margin-bottom:2px;}
.urgency-banner .ub-sub{font-size:12px;font-weight:500;opacity:.85;}

/* ── Action bar ── */
.action-bar{display:flex;align-items:center;justify-content:space-between;
    flex-wrap:wrap;gap:12px;margin-bottom:16px;}
.action-bar-left,.action-bar-right{display:flex;gap:10px;flex-wrap:wrap;align-items:center;}

/* ── Filter bar ── */
.filter-bar{background:var(--white);border:1px solid var(--gray-200);
    border-radius:var(--radius);padding:14px 16px;margin-bottom:16px;
    display:flex;align-items:center;gap:12px;flex-wrap:wrap;}
.search-wrap{flex:1;min-width:200px;max-width:320px;position:relative;}
.search-wrap .si{position:absolute;left:11px;top:50%;transform:translateY(-50%);
    color:var(--gray-400);font-size:13px;pointer-events:none;}
.search-wrap input{width:100%;padding:9px 12px 9px 32px;border:1.5px solid var(--gray-200);
    border-radius:var(--radius-sm);font-size:13px;font-family:var(--font);
    color:var(--gray-700);background:var(--gray-50);transition:var(--transition);}
.search-wrap input:focus{outline:none;border-color:var(--accent);
    background:var(--white);box-shadow:0 0 0 3px rgba(33,150,243,.10);}
.filter-select{padding:9px 12px;border:1.5px solid var(--gray-200);
    border-radius:var(--radius-sm);font-size:13px;font-family:var(--font);
    color:var(--gray-700);background:var(--white);cursor:pointer;transition:var(--transition);}
.filter-select:focus{outline:none;border-color:var(--accent);}

/* Filtros avanzados */
.advanced-filters{background:var(--gray-50);border:1px solid var(--gray-200);
    border-radius:var(--radius);padding:16px;margin-bottom:16px;}
.filter-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:12px;}
.form-group{display:flex;flex-direction:column;gap:5px;}
.form-label{font-size:11.5px;font-weight:600;color:var(--gray-600);
    text-transform:uppercase;letter-spacing:.4px;}
.form-control{padding:9px 12px;border:1.5px solid var(--gray-200);
    border-radius:var(--radius-sm);font-size:13px;font-family:var(--font);
    color:var(--gray-700);background:var(--white);transition:var(--transition);}
.form-control:focus{outline:none;border-color:var(--accent);
    box-shadow:0 0 0 3px rgba(33,150,243,.08);}

/* ── Botones ── */
.btn{display:inline-flex;align-items:center;gap:7px;padding:9px 16px;
    border-radius:var(--radius-sm);border:none;font-size:13px;font-weight:600;
    font-family:var(--font);cursor:pointer;transition:var(--transition);
    text-decoration:none;white-space:nowrap;}
.btn-primary   {background:var(--accent);color:white;}
.btn-primary:hover   {background:#1565C0;color:white;}
.btn-secondary {background:var(--gray-200);color:var(--gray-700);}
.btn-secondary:hover {background:var(--gray-300);}
.btn-success   {background:#DCFCE7;color:#166534;}
.btn-success:hover   {background:#166534;color:white;}
.btn-danger    {background:#FEE2E2;color:#DC2626;}
.btn-danger:hover    {background:#DC2626;color:white;}
.btn-warning   {background:#FEF3C7;color:#92400E;}
.btn-warning:hover   {background:#D97706;color:white;}
.btn-info      {background:#E0F2FE;color:#0369A1;}
.btn-info:hover      {background:#0284C7;color:white;}
.btn-purple    {background:#F5F3FF;color:#6D28D9;}
.btn-purple:hover    {background:#6D28D9;color:white;}
.btn-sm{padding:6px 12px;font-size:12px;}
.btn-xs{padding:4px 9px;font-size:11px;}

/* ── Card ── */
.card{background:var(--white);border:1px solid var(--gray-200);
    border-radius:var(--radius);box-shadow:var(--shadow-sm);overflow:hidden;}
.card-header{padding:16px 20px;border-bottom:1px solid var(--gray-200);
    display:flex;align-items:center;justify-content:space-between;}
.card-title{font-size:15px;font-weight:700;color:var(--gray-800);}
.card-subtitle{font-size:12px;color:var(--gray-500);margin-top:2px;}

/* ── Tabla ── */
.data-table{width:100%;border-collapse:collapse;font-size:13px;}
.data-table thead th{background:var(--gray-50);padding:11px 14px;
    text-align:left;font-weight:600;color:var(--gray-600);font-size:11.5px;
    text-transform:uppercase;letter-spacing:.5px;
    border-bottom:2px solid var(--gray-200);white-space:nowrap;}
.data-table tbody td{padding:12px 14px;border-bottom:1px solid var(--gray-100);
    color:var(--gray-700);vertical-align:middle;}
.data-table tbody tr:last-child td{border-bottom:none;}
.data-table tbody tr:hover{background:var(--gray-50);}

/* Highlight rows by urgency */
.row-vencida  {background:#FFF5F5!important;}
.row-critica  {background:#FFFBF5!important;}
.row-proxima  {}

/* ── Badge de vigencia ── */
.badge-vig{display:inline-flex;align-items:center;gap:5px;padding:4px 11px;
    border-radius:20px;font-size:11.5px;font-weight:700;white-space:nowrap;}

/* ── Días restantes chip ── */
.dias-chip{display:inline-flex;align-items:center;justify-content:center;
    min-width:52px;padding:4px 9px;border-radius:20px;font-size:12px;
    font-weight:800;text-align:center;}

/* ── Barra progreso mini ── */
.mini-progress{height:5px;border-radius:10px;background:var(--gray-200);
    overflow:hidden;margin-top:5px;}
.mini-progress-fill{height:100%;border-radius:10px;transition:width .4s ease;}

/* ── Celda cliente ── */
.client-name{font-weight:600;color:var(--gray-800);font-size:13px;}
.client-sub{font-size:11.5px;color:var(--gray-500);margin-top:2px;}
.contrato-num{font-family:monospace;font-weight:700;font-size:13px;color:var(--accent);}

/* ── Monto pendiente ── */
.monto-pend{font-weight:700;font-family:monospace;}
.monto-pend.rojo{color:#DC2626;}
.monto-pend.verde{color:#166534;}

/* ── Botones tabla ── */
.tbl-actions{display:flex;gap:5px;align-items:center;flex-wrap:wrap;}
.btn-tbl{display:inline-flex;align-items:center;justify-content:center;
    height:30px;padding:0 10px;border-radius:var(--radius-sm);border:none;
    cursor:pointer;transition:var(--transition);font-size:12px;font-weight:600;gap:5px;}
.btn-tbl.info   {background:#E0F2FE;color:#0369A1;}
.btn-tbl.info:hover   {background:#0284C7;color:white;}
.btn-tbl.warn   {background:#FEF3C7;color:#92400E;}
.btn-tbl.warn:hover   {background:#D97706;color:white;}
.btn-tbl.prim   {background:#EFF6FF;color:#1D4ED8;}
.btn-tbl.prim:hover   {background:#1D4ED8;color:white;}
.btn-tbl.suc    {background:#DCFCE7;color:#166534;}
.btn-tbl.suc:hover    {background:#166534;color:white;}

/* ── Paginador ── */
.paginador-wrap{display:flex;align-items:center;justify-content:space-between;
    flex-wrap:wrap;gap:12px;padding:14px 20px;
    border-top:1px solid var(--gray-200);background:var(--white);}
.paginador-info{font-size:13px;color:var(--gray-500);}
.paginador-info strong{color:var(--gray-700);}
.paginador-pages{display:flex;align-items:center;gap:4px;}
.pag-btn{display:inline-flex;align-items:center;justify-content:center;
    min-width:34px;height:34px;padding:0 10px;border-radius:var(--radius-sm);
    border:1.5px solid var(--gray-200);background:var(--white);
    font-size:13px;font-weight:500;color:var(--gray-600);
    cursor:pointer;transition:var(--transition);text-decoration:none;}
.pag-btn:hover:not(.disabled):not(.active){background:var(--gray-100);border-color:var(--gray-300);}
.pag-btn.active{background:var(--accent);border-color:var(--accent);color:white;font-weight:700;}
.pag-btn.disabled{opacity:.4;cursor:not-allowed;pointer-events:none;}
.pag-btn.ellipsis{border:none;cursor:default;background:none;}

/* ── Empty state ── */
.empty-state{text-align:center;padding:70px 20px;color:var(--gray-400);}
.empty-state .es-icon{font-size:52px;margin-bottom:16px;opacity:.35;}
.empty-state .es-title{font-size:16px;font-weight:700;color:var(--gray-600);margin-bottom:6px;}
.empty-state .es-sub{font-size:13px;color:var(--gray-400);}

/* ── Resumen barra ── */
.stats-bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;}
.stats-bar-item{display:flex;align-items:center;gap:6px;padding:6px 13px;
    border-radius:20px;font-size:12px;font-weight:600;cursor:pointer;
    border:1.5px solid transparent;transition:var(--transition);}
.stats-bar-item:hover{opacity:.85;transform:translateY(-1px);}
.stats-bar-item.active{box-shadow:0 0 0 2px var(--accent);}
.stats-bar-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0;}

/* ── Modal facturas pendientes ── */
.modal-overlay-fp2{position:fixed;inset:0;z-index:9999;
    background:rgba(15,23,42,.55);backdrop-filter:blur(4px);
    display:none;align-items:center;justify-content:center;padding:20px;}
.modal-overlay-fp2.show{display:flex;}
.modal-box-fp2{background:var(--white);border-radius:16px;width:100%;max-width:760px;
    max-height:88vh;overflow:hidden;display:flex;flex-direction:column;
    box-shadow:0 24px 80px rgba(0,0,0,.25);animation:fp2Slide .25s ease;}
@keyframes fp2Slide{from{transform:translateY(30px);opacity:0}to{transform:translateY(0);opacity:1}}
.modal-hd-fp2{padding:20px 24px 16px;
    background:linear-gradient(135deg,#1565C0 0%,#1976D2 100%);
    display:flex;align-items:flex-start;gap:14px;flex-shrink:0;}
.modal-hd-fp2 .mhf-icon{width:46px;height:46px;border-radius:var(--radius-sm);
    background:rgba(255,255,255,.2);display:flex;align-items:center;
    justify-content:center;color:white;font-size:20px;flex-shrink:0;}
.modal-hd-fp2 .mhf-title{font-size:17px;font-weight:700;color:white;margin-bottom:2px;}
.modal-hd-fp2 .mhf-sub{font-size:12px;color:rgba(255,255,255,.75);}
.modal-hd-fp2 .mhf-close{margin-left:auto;background:rgba(255,255,255,.15);border:none;
    width:32px;height:32px;border-radius:8px;font-size:18px;cursor:pointer;
    color:white;display:flex;align-items:center;justify-content:center;
    transition:var(--transition);flex-shrink:0;}
.modal-hd-fp2 .mhf-close:hover{background:rgba(255,255,255,.25);}

/* Info chips dentro del modal */
.modal-chips{display:flex;gap:10px;flex-wrap:wrap;padding:14px 24px;
    background:#F8FAFC;border-bottom:1px solid var(--gray-200);flex-shrink:0;}
.info-chip{display:flex;align-items:center;gap:6px;padding:6px 12px;
    background:var(--white);border:1px solid var(--gray-200);
    border-radius:20px;font-size:12px;font-weight:600;color:var(--gray-700);}
.info-chip i{color:var(--accent);}
.info-chip.red i,.info-chip.red span{color:#DC2626;}
.info-chip.green i,.info-chip.green span{color:#166534;}

.modal-bd-fp2{overflow-y:auto;flex:1;padding:0;}

/* Tabs del modal */
.modal-tabs{display:flex;border-bottom:2px solid var(--gray-200);
    background:var(--white);flex-shrink:0;padding:0 24px;}
.modal-tab-btn{padding:12px 18px;font-size:13px;font-weight:600;
    color:var(--gray-500);border:none;background:none;cursor:pointer;
    border-bottom:2px solid transparent;margin-bottom:-2px;transition:var(--transition);}
.modal-tab-btn:hover{color:var(--gray-700);}
.modal-tab-btn.active{color:var(--accent);border-bottom-color:var(--accent);}
.modal-tab-content{display:none;padding:20px 24px;}
.modal-tab-content.active{display:block;}

/* Tabla dentro del modal */
.modal-table{width:100%;border-collapse:collapse;font-size:13px;}
.modal-table thead th{background:var(--gray-50);padding:9px 12px;
    text-align:left;font-weight:600;color:var(--gray-600);font-size:11.5px;
    text-transform:uppercase;border-bottom:2px solid var(--gray-200);}
.modal-table tbody td{padding:10px 12px;border-bottom:1px solid var(--gray-100);
    color:var(--gray-700);}
.modal-table tbody tr:last-child td{border-bottom:none;}
.modal-table tbody tr:hover{background:var(--gray-50);}
.modal-table tfoot td{padding:10px 12px;font-weight:700;background:var(--gray-50);
    border-top:2px solid var(--gray-200);}

/* Resumen en el modal */
.modal-summary{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;
    padding:16px 24px;background:#F8FAFC;border-bottom:1px solid var(--gray-200);
    flex-shrink:0;}
.msumm-card{background:var(--white);border:1px solid var(--gray-200);
    border-radius:var(--radius-sm);padding:12px 14px;text-align:center;}
.msumm-value{font-size:18px;font-weight:800;margin-bottom:2px;}
.msumm-label{font-size:11px;color:var(--gray-500);font-weight:500;text-transform:uppercase;}

.modal-ft-fp2{padding:14px 24px;border-top:1px solid var(--gray-200);
    display:flex;justify-content:space-between;align-items:center;
    background:var(--gray-50);flex-shrink:0;}

/* ── Leyenda colores ── */
.leyenda-vigencia{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;}
.ley-item{display:inline-flex;align-items:center;gap:6px;
    padding:5px 12px;border-radius:20px;font-size:12px;font-weight:600;cursor:pointer;
    transition:var(--transition);border:1.5px solid rgba(0,0,0,.06);}
.ley-item:hover{transform:translateY(-1px);box-shadow:0 3px 8px rgba(0,0,0,.12);}
.ley-dot{width:10px;height:10px;border-radius:50%;}

/* ── Toggle al-día ── */
.toggle-wrap{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--gray-600);}
.toggle-switch{position:relative;width:38px;height:20px;cursor:pointer;}
.toggle-switch input{opacity:0;width:0;height:0;}
.toggle-slider{position:absolute;inset:0;background:var(--gray-300);
    border-radius:20px;transition:.3s;}
.toggle-slider:before{content:'';position:absolute;height:14px;width:14px;
    left:3px;bottom:3px;background:white;border-radius:50%;transition:.3s;}
.toggle-switch input:checked+.toggle-slider{background:var(--accent);}
.toggle-switch input:checked+.toggle-slider:before{transform:translateX(18px);}

/* ── Por página ── */
.por-pagina-wrap{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--gray-500);}
.por-pagina-select{padding:5px 10px;border:1.5px solid var(--gray-200);
    border-radius:var(--radius-sm);font-size:13px;font-family:var(--font);}

/* ── Fade-in ── */
.fade-in{animation:fadeIn .4s ease both;}
.delay-1{animation-delay:.10s;}
.delay-2{animation-delay:.20s;}
.delay-3{animation-delay:.30s;}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
</style>

<?php
/* ── Pre-calcular datos para la barra y banner ──────────────── */
$cnt_vencidos  = (int)($kpi['vencidos']  ?? 0);
$cnt_criticos  = (int)($kpi['criticos']  ?? 0);
$cnt_proximos  = (int)($kpi['proximos']  ?? 0);
$cnt_al_dia    = (int)($kpi['al_dia']    ?? 0);
$cnt_activos   = (int)($kpi['total_activos'] ?? 0);

$bannerTipo  = 'success';
$bannerTitle = '✅ Todos los contratos están al día';
$bannerSub   = 'No hay contratos con vigencias pendientes o próximas a vencer.';
if ($cnt_vencidos > 0) {
    $bannerTipo  = 'danger';
    $bannerTitle = "⚠️ {$cnt_vencidos} contrato" . ($cnt_vencidos>1?'s':'') . " con vigencia vencida";
    $bannerSub   = "Requieren atención inmediata. Monto global pendiente: RD$" . number_format($montoGlobal, 2);
} elseif ($cnt_criticos > 0) {
    $bannerTipo  = 'warning';
    $bannerTitle = "⚡ {$cnt_criticos} contrato" . ($cnt_criticos>1?'s':'') . " con vigencia crítica (≤7 días)";
    $bannerSub   = "Próximos a vencer esta semana. Revise y envíe cobrador.";
}
?>

<!-- ============================================================
     PAGE HEADER
     ============================================================ -->
<div class="page-header fade-in">
    <div>
        <div class="page-title">
            <i class="fas fa-shield-halved" style="color:var(--accent);margin-right:8px;"></i>
            Control de Vigencias
        </div>
        <div class="page-subtitle">
            Seguimiento de vencimientos y pendientes de contratos activos
            &mdash; <?php echo number_format($cnt_activos); ?> contratos activos
        </div>
    </div>
    <div class="page-actions">
        <a href="contratos.php" class="btn btn-secondary">
            <i class="fas fa-file-contract"></i> Contratos
        </a>
        <a href="facturacion.php" class="btn btn-primary">
            <i class="fas fa-file-invoice-dollar"></i> Facturación
        </a>
    </div>
</div>

<!-- ============================================================
     BANNER DE URGENCIA
     ============================================================ -->
<div class="urgency-banner <?php echo $bannerTipo; ?> fade-in">
    <div class="ub-icon">
        <i class="fas <?php echo $bannerTipo==='danger'?'fa-circle-xmark':($bannerTipo==='warning'?'fa-triangle-exclamation':'fa-circle-check'); ?>"></i>
    </div>
    <div class="ub-text">
        <div class="ub-title"><?php echo $bannerTitle; ?></div>
        <div class="ub-sub"><?php echo $bannerSub; ?></div>
    </div>
    <?php if ($cnt_vencidos > 0 || $cnt_criticos > 0): ?>
    <a href="facturacion.php?estado=pendiente" class="btn btn-danger btn-sm">
        <i class="fas fa-arrow-right"></i> Ver Facturas Pendientes
    </a>
    <?php endif; ?>
</div>

<!-- ============================================================
     KPI CARDS
     ============================================================ -->
<div class="kpi-vigencia fade-in delay-1">

    <div class="kpi-card-v red">
        <div class="kpi-v-label">Vigencias Vencidas</div>
        <div class="kpi-v-top">
            <div>
                <div class="kpi-v-value"><?php echo number_format($cnt_vencidos); ?></div>
                <div class="kpi-v-sub">Fecha fin ya pasó</div>
            </div>
            <div class="kpi-v-icon"><i class="fas fa-circle-xmark"></i></div>
        </div>
        <div class="kpi-v-footer">
            <i class="fas fa-exclamation-circle"></i>
            Requieren pago inmediato
        </div>
    </div>

    <div class="kpi-card-v orange">
        <div class="kpi-v-label">Críticas (≤7 días)</div>
        <div class="kpi-v-top">
            <div>
                <div class="kpi-v-value"><?php echo number_format($cnt_criticos); ?></div>
                <div class="kpi-v-sub">Vencen esta semana</div>
            </div>
            <div class="kpi-v-icon"><i class="fas fa-triangle-exclamation"></i></div>
        </div>
        <div class="kpi-v-footer">
            <i class="fas fa-bell"></i>
            Enviar cobrador urgente
        </div>
    </div>

    <div class="kpi-card-v amber">
        <div class="kpi-v-label">Por Vencer (≤30 días)</div>
        <div class="kpi-v-top">
            <div>
                <div class="kpi-v-value"><?php echo number_format($cnt_proximos); ?></div>
                <div class="kpi-v-sub">Próximas a vencer</div>
            </div>
            <div class="kpi-v-icon"><i class="fas fa-clock"></i></div>
        </div>
        <div class="kpi-v-footer">
            <i class="fas fa-calendar-days"></i>
            Gestionar cobro próximo
        </div>
    </div>

    <div class="kpi-card-v blue">
        <div class="kpi-v-label">Monto Pendiente Global</div>
        <div class="kpi-v-top">
            <div>
                <div class="kpi-v-value" style="font-size:18px;">
                    RD$<?php echo number_format($montoGlobal, 0); ?>
                </div>
                <div class="kpi-v-sub">Todos los contratos activos</div>
            </div>
            <div class="kpi-v-icon"><i class="fas fa-coins"></i></div>
        </div>
        <div class="kpi-v-footer">
            <i class="fas fa-arrow-trend-up"></i>
            Total por cobrar
        </div>
    </div>

    <div class="kpi-card-v green">
        <div class="kpi-v-label">Al Día (>30 días)</div>
        <div class="kpi-v-top">
            <div>
                <div class="kpi-v-value"><?php echo number_format($cnt_al_dia); ?></div>
                <div class="kpi-v-sub">Vigentes sin urgencia</div>
            </div>
            <div class="kpi-v-icon"><i class="fas fa-circle-check"></i></div>
        </div>
        <div class="kpi-v-footer">
            <i class="fas fa-shield-check"></i>
            <?php echo $cnt_activos > 0 ? round(($cnt_al_dia/$cnt_activos)*100) : 0; ?>% del total
        </div>
    </div>

</div>

<!-- ============================================================
     LEYENDA DE COLORES
     ============================================================ -->
<div class="leyenda-vigencia fade-in delay-1">
    <span style="font-size:12px;font-weight:600;color:var(--gray-500);align-self:center;margin-right:4px;">
        <i class="fas fa-circle-info"></i> Leyenda:
    </span>
    <div class="ley-item" style="background:#FEE2E2;color:#991B1B;">
        <div class="ley-dot" style="background:#DC2626;"></div> Vencida
    </div>
    <div class="ley-item" style="background:#FFEBEE;color:#C62828;">
        <div class="ley-dot" style="background:#E53935;"></div> Crítica ≤7 días
    </div>
    <div class="ley-item" style="background:#FFF3E0;color:#E65100;">
        <div class="ley-dot" style="background:#F57C00;"></div> Urgente ≤15 días
    </div>
    <div class="ley-item" style="background:#FFFDE7;color:#F57F17;">
        <div class="ley-dot" style="background:#FBC02D;"></div> Por Vencer ≤30 días
    </div>
    <div class="ley-item" style="background:#E1F5FE;color:#0277BD;">
        <div class="ley-dot" style="background:#0288D1;"></div> Atención ≤60 días
    </div>
    <div class="ley-item" style="background:#E8F5E9;color:#1B5E20;">
        <div class="ley-dot" style="background:#388E3C;"></div> Al Día >60 días
    </div>
</div>

<!-- ============================================================
     BARRA DE FILTROS
     ============================================================ -->
<div class="filter-bar-h fade-in delay-2">
    <form method="GET" action="vigencia.php" id="formFiltrosVigencia">
        <div class="filter-row-fields">
            <!-- Búsqueda -->
            <div class="filter-field field-search">
                <label for="searchInput"><i class="fas fa-search"></i> Buscar</label>
                <div class="search-wrap-h">
                    <i class="fas fa-search search-icon-h"></i>
                    <input type="text"
                           id="searchInput"
                           name="buscar"
                           class="filter-input"
                           placeholder="Nombre, contrato, cédula…"
                           value="<?php echo htmlspecialchars($buscar); ?>"
                           autocomplete="off">
                </div>
            </div>
            <!-- Días -->
            <div class="filter-field field-select">
                <label for="diasFilter"><i class="fas fa-hourglass-half"></i> Horizonte</label>
                <select id="diasFilter" name="dias_max" class="filter-select-h" onchange="this.form.submit()">
                    <option value="7"   <?php echo $filtro_dias==='7'  ?'selected':''; ?>>7 días</option>
                    <option value="15"  <?php echo $filtro_dias==='15' ?'selected':''; ?>>15 días</option>
                    <option value="30"  <?php echo $filtro_dias==='30' ?'selected':''; ?>>30 días</option>
                    <option value="60"  <?php echo ($filtro_dias==='60'||$filtro_dias==='')?'selected':''; ?>>60 días</option>
                    <option value="90"  <?php echo $filtro_dias==='90' ?'selected':''; ?>>90 días</option>
                    <option value="180" <?php echo $filtro_dias==='180'?'selected':''; ?>>180 días</option>
                </select>
            </div>
            <!-- Plan -->
            <div class="filter-field field-select">
                <label for="planFilter"><i class="fas fa-umbrella"></i> Plan</label>
                <select id="planFilter" name="plan_id" class="filter-select-h" onchange="this.form.submit()">
                    <option value="">Todos los planes</option>
                    <?php foreach ($planes as $pl): ?>
                    <option value="<?php echo $pl['id']; ?>"
                        <?php echo $filtro_plan==(string)$pl['id']?'selected':''; ?>>
                        <?php echo htmlspecialchars($pl['nombre']); ?>
                    </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <!-- Cobrador -->
            <div class="filter-field field-select">
                <label for="cobradorFilter"><i class="fas fa-motorcycle"></i> Cobrador</label>
                <select id="cobradorFilter" name="cobrador_id" class="filter-select-h" onchange="this.form.submit()">
                    <option value="">Todos</option>
                    <?php foreach ($cobradores as $cob): ?>
                    <option value="<?php echo $cob['id']; ?>"
                        <?php echo $filtro_cobrad==(string)$cob['id']?'selected':''; ?>>
                        <?php echo htmlspecialchars($cob['nombre_completo']); ?>
                    </option>
                    <?php endforeach; ?>
                </select>
            </div>
        </div>
        <div class="filter-row-btns">
            <button type="submit" class="btn btn-primary btn-sm">
                <i class="fas fa-search"></i> Buscar
            </button>
            <?php if ($buscar || !empty($filtro_cobrad) || !empty($filtro_plan)): ?>
                <a href="vigencia.php?dias_max=60" class="btn btn-secondary btn-sm">
                    <i class="fas fa-times"></i> Limpiar
                </a>
            <?php endif; ?>
            <!-- Checkbox: Mostrar todos (incluidos al día) -->
            <label style="display:flex;align-items:center;gap:6px;font-size:12px;color:var(--gray-600);cursor:pointer;margin-left:4px;">
                <input type="checkbox"
                       id="toggleAlDia"
                       name="mostrar_al_dia"
                       value="1"
                       <?php echo $mostrar_al_dia?'checked':''; ?>
                       onchange="this.form.submit()"
                       style="width:16px;height:16px;cursor:pointer;">
                Mostrar todos (incl. al día)
            </label>
            <!-- Registros por página -->
            <div style="display:flex;align-items:center;gap:6px;margin-left:8px;">
                <span style="font-size:12px;color:var(--gray-500);">Mostrar</span>
                <select class="filter-select-h" style="width:auto;" onchange="cambiarPorPagina(this.value)">
                    <?php foreach ([25,50,100,200] as $n): ?>
                    <option value="<?php echo $n; ?>" <?php echo $por_pagina==$n?'selected':''; ?>><?php echo $n; ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="filter-results-info">
                <?php echo number_format($total_registros); ?> contrato<?php echo $total_registros !== 1 ? 's' : ''; ?>
            </div>
        </div>
    </form>
</div>

<!-- ============================================================
     TABLA PRINCIPAL
     ============================================================ -->
<div class="card fade-in delay-3">
    <div class="card-header">
        <div>
            <div class="card-title">
                <i class="fas fa-shield-halved" style="color:var(--accent);margin-right:6px;"></i>
                Contratos con Vigencias
            </div>
            <div class="card-subtitle">
                Mostrando
                <?php echo $total_registros>0 ? min($offset+1,$total_registros) : 0; ?>–<?php echo min($offset+$por_pagina,$total_registros); ?>
                de <?php echo number_format($total_registros); ?> contratos
                <?php if (!$mostrar_al_dia): ?>
                    (vencidos y próximos a vencer en <?php echo $filtro_dias?:60; ?> días)
                <?php endif; ?>
            </div>
        </div>
        <div style="font-size:12px;color:var(--gray-500);">
            Ordenado por fecha de vencimiento más antigua
        </div>
    </div>

    <div style="overflow-x:auto;">
        <table class="data-table" id="tablaVigencias">
            <thead>
                <tr>
                    <th>N° Contrato</th>
                    <th>Cliente</th>
                    <th>Plan</th>
                    <th>Fecha Fin</th>
                    <th>Días Rest.</th>
                    <th>Estado Vigencia</th>
                    <th>Facturas Pend.</th>
                    <th>Monto Pendiente</th>
                    <th>Cobrador</th>
                    <th style="text-align:center;">Acciones</th>
                </tr>
            </thead>
            <tbody>
            <?php if (!empty($contratos)): ?>
                <?php foreach ($contratos as $c):
                    $dias   = diasRestantes($c['fecha_fin']);
                    $vc     = clasificarVigencia($dias);
                    $monPend= (float)$c['monto_pendiente_total'];
                    $factPend=(int)$c['total_facturas_pendientes'];

                    /* Clase de fila */
                    $rowCls = '';
                    if ($vc['cls']==='vencida')  $rowCls='row-vencida';
                    elseif ($vc['cls']==='critica') $rowCls='row-critica';

                    /* Días display */
                    if ($dias < 0) {
                        $diasLabel = abs($dias).' día'.( abs($dias)!==1?'s':'').' VENCIDO';
                        $diasStyle = "background:#FEE2E2;color:#991B1B;";
                    } elseif($dias===0) {
                        $diasLabel = 'HOY';
                        $diasStyle = "background:#F3E5F5;color:#6A1B9A;";
                    } else {
                        $diasLabel = $dias.' día'.($dias!==1?'s':'');
                        if ($dias<=7)   $diasStyle="background:#FFEBEE;color:#C62828;";
                        elseif($dias<=15) $diasStyle="background:#FFF3E0;color:#E65100;";
                        elseif($dias<=30) $diasStyle="background:#FFFDE7;color:#F57F17;";
                        elseif($dias<=60) $diasStyle="background:#E1F5FE;color:#0277BD;";
                        else              $diasStyle="background:#E8F5E9;color:#1B5E20;";
                    }

                    /* Fecha fin display */
                    $fechaFinStr = $c['fecha_fin']
                        ? date('d/m/Y', strtotime($c['fecha_fin']))
                        : 'Sin definir';
                ?>
                <tr class="<?php echo $rowCls; ?>">
                    <!-- N° Contrato -->
                    <td>
                        <a href="ver_contrato.php?id=<?php echo $c['contrato_id']; ?>"
                           class="contrato-num" title="Ver contrato">
                            <?php echo str_pad($c['numero_contrato'],5,'0',STR_PAD_LEFT); ?>
                        </a>
                        <div style="font-size:11px;color:var(--gray-400);margin-top:2px;">
                            Día cobro: <?php echo $c['dia_cobro']; ?>
                        </div>
                    </td>
                    <!-- Cliente -->
                    <td>
                        <div class="client-name">
                            <?php echo htmlspecialchars($c['cliente_nombre'].' '.$c['cliente_apellidos']); ?>
                        </div>
                        <?php if ($c['cliente_telefono1']): ?>
                        <div class="client-sub">
                            <i class="fas fa-phone" style="font-size:10px;"></i>
                            <?php echo htmlspecialchars($c['cliente_telefono1']); ?>
                            <?php if ($c['cliente_telefono2']): ?>
                                / <?php echo htmlspecialchars($c['cliente_telefono2']); ?>
                            <?php endif; ?>
                        </div>
                        <?php endif; ?>
                    </td>
                    <!-- Plan -->
                    <td>
                        <span style="font-size:12px;background:var(--gray-100);
                            color:var(--gray-700);padding:3px 9px;border-radius:20px;
                            font-weight:600;">
                            <?php echo htmlspecialchars($c['plan_nombre']); ?>
                        </span>
                    </td>
                    <!-- Fecha fin -->
                    <td>
                        <div style="font-weight:600;font-size:13px;
                            color:<?php echo $dias<0?'#DC2626':($dias<=7?'#C62828':($dias<=30?'#E65100':'var(--gray-800)')); ?>;">
                            <?php echo $fechaFinStr; ?>
                        </div>
                        <div style="font-size:11px;color:var(--gray-400);margin-top:2px;">
                            Inicio: <?php echo date('d/m/Y', strtotime($c['fecha_inicio'])); ?>
                        </div>
                    </td>
                    <!-- Días restantes -->
                    <td>
                        <span class="dias-chip" style="<?php echo $diasStyle; ?>">
                            <?php echo $diasLabel; ?>
                        </span>
                    </td>
                    <!-- Estado vigencia -->
                    <td>
                        <span class="badge-vig"
                              style="background:<?php echo $vc['bg']; ?>;color:<?php echo $vc['color']; ?>;">
                            <i class="fas <?php echo $vc['icon']; ?>"></i>
                            <?php echo $vc['label']; ?>
                        </span>
                    </td>
                    <!-- Facturas pendientes -->
                    <td style="text-align:center;">
                        <?php if ($factPend > 0): ?>
                        <span style="display:inline-flex;align-items:center;gap:5px;
                            background:#FEE2E2;color:#DC2626;padding:4px 11px;
                            border-radius:20px;font-size:12px;font-weight:700;">
                            <i class="fas fa-exclamation-circle"></i>
                            <?php echo $factPend; ?>
                        </span>
                        <?php else: ?>
                        <span style="display:inline-flex;align-items:center;gap:5px;
                            background:#DCFCE7;color:#166534;padding:4px 11px;
                            border-radius:20px;font-size:12px;font-weight:700;">
                            <i class="fas fa-check-circle"></i> Al día
                        </span>
                        <?php endif; ?>
                    </td>
                    <!-- Monto pendiente -->
                    <td>
                        <span class="monto-pend <?php echo $monPend>0?'rojo':'verde'; ?>">
                            RD$<?php echo number_format($monPend,2); ?>
                        </span>
                        <?php if ($c['monto_mensual'] > 0): ?>
                        <div class="mini-progress">
                            <?php
                            $cobrado = (float)$c['total_cobrado_contrato'];
                            $facturado_total = (float)$c['total_facturas_emitidas'] * (float)$c['monto_mensual'];
                            $pct = $facturado_total > 0 ? min(100, round(($cobrado / $facturado_total) * 100)) : 0;
                            $pctColor = $pct >= 80 ? '#22C55E' : ($pct >= 50 ? '#F59E0B' : '#EF4444');
                            ?>
                            <div class="mini-progress-fill"
                                 style="width:<?php echo $pct; ?>%;background:<?php echo $pctColor; ?>;"></div>
                        </div>
                        <div style="font-size:10px;color:var(--gray-400);margin-top:2px;text-align:right;">
                            <?php echo $pct; ?>% cobrado
                        </div>
                        <?php endif; ?>
                    </td>
                    <!-- Cobrador -->
                    <td style="font-size:12px;color:var(--gray-600);">
                        <?php if ($c['cobrador_nombre']): ?>
                            <div style="font-weight:600;">
                                <?php echo htmlspecialchars($c['cobrador_nombre']); ?>
                            </div>
                        <?php else: ?>
                            <span style="color:var(--gray-400);font-style:italic;">Sin cobrador</span>
                        <?php endif; ?>
                    </td>
                    <!-- Acciones -->
                    <td>
                        <div class="tbl-actions">
                            <?php if ($factPend > 0): ?>
                            <button class="btn-tbl warn"
                                    title="Ver facturas pendientes"
                                    onclick="verFacturasPendientes(<?php echo $c['contrato_id']; ?>,
                                        '<?php echo str_pad($c['numero_contrato'],5,'0',STR_PAD_LEFT); ?>',
                                        '<?php echo htmlspecialchars(addslashes($c['cliente_nombre'].' '.$c['cliente_apellidos'])); ?>')">
                                <i class="fas fa-file-invoice-dollar"></i>
                                Facturas Pendientes
                            </button>
                            <?php endif; ?>
                            <a href="ver_contrato.php?id=<?php echo $c['contrato_id']; ?>"
                               class="btn-tbl info" title="Ver contrato">
                                <i class="fas fa-eye"></i>
                            </a>
                            <?php
                            /* ── Botón WhatsApp: solo para vencidos y próximos a vencer ── */
                            $telWa     = trim($c['cliente_telefono1'] ?? '');
                            $nombreWa  = htmlspecialchars($c['cliente_nombre'], ENT_QUOTES, 'UTF-8');
                            $montoWa   = number_format((float)($c['monto_pendiente_total'] ?? 0), 2, '.', ',');
                            $esVencida = ($vc['cls'] === 'vencida');
                            $esProxima = (!$esVencida && isset($vc['cls']) && $vc['cls'] !== 'vigente');
                            $mesesEs = [
                                '01'=>'Enero','02'=>'Febrero','03'=>'Marzo','04'=>'Abril',
                                '05'=>'Mayo','06'=>'Junio','07'=>'Julio','08'=>'Agosto',
                                '09'=>'Septiembre','10'=>'Octubre','11'=>'Noviembre','12'=>'Diciembre'
                            ];
                            $mesAtrasoDB   = $c['mes_atraso_inicio'] ?? '';
                            $mesAtrasoLabel = '';
                            if ($mesAtrasoDB) {
                                if (preg_match('/^(\d{2})\/(\d{4})$/', $mesAtrasoDB, $m2)) {
                                    $mesAtrasoLabel = ($mesesEs[$m2[1]] ?? $m2[1]) . ' ' . $m2[2];
                                } elseif (preg_match('/^(\d{4})-(\d{2})$/', $mesAtrasoDB, $m2)) {
                                    $mesAtrasoLabel = ($mesesEs[$m2[2]] ?? $m2[2]) . ' ' . $m2[1];
                                } else {
                                    $mesAtrasoLabel = $mesAtrasoDB;
                                }
                            }
                            if (!$mesAtrasoLabel && !empty($c['fecha_fin'])) {
                                $mf = date('m', strtotime($c['fecha_fin']));
                                $yf = date('Y', strtotime($c['fecha_fin']));
                                $mesAtrasoLabel = ($mesesEs[$mf] ?? $mf) . ' ' . $yf;
                            }
                            $tipoWa = $esVencida ? 'vencida' : 'proxima';
                            if ($telWa && ($esVencida || $esProxima)):
                            ?>
                            <button
                                onclick="enviarWhatsApp(
                                    '<?php echo htmlspecialchars($telWa, ENT_QUOTES, 'UTF-8'); ?>',
                                    '<?php echo $nombreWa; ?>',
                                    '<?php echo htmlspecialchars($mesAtrasoLabel, ENT_QUOTES, 'UTF-8'); ?>',
                                    '<?php echo $montoWa; ?>',
                                    '<?php echo $tipoWa; ?>'
                                )"
                                class="btn-tbl <?php echo $esVencida ? 'danger' : 'warn'; ?>"
                                title="<?php echo $esVencida ? 'Vigencia VENCIDA: Notificar por WhatsApp' : 'Próximo a vencer: Notificar por WhatsApp'; ?>"
                                style="background:<?php echo $esVencida ? '#25D366' : '#f59e0b'; ?>;color:#fff;border:none;cursor:pointer;border-radius:6px;padding:5px 8px;">
                                <i class="fab fa-whatsapp"></i>
                            </button>
                            <?php endif; ?>
                            <a href="facturacion.php?numero_contrato=<?php echo urlencode($c['numero_contrato']); ?>"
                               class="btn-tbl prim" title="Ver facturas">
                                <i class="fas fa-list"></i>
                            </a>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr>
                    <td colspan="10">
                        <div class="empty-state">
                            <div class="es-icon">
                                <i class="fas fa-circle-check" style="color:#22C55E;opacity:1;"></i>
                            </div>
                            <div class="es-title" style="color:#166534;">
                                ¡Todos los contratos están al día!
                            </div>
                            <div class="es-sub">
                                No hay contratos con vigencias vencidas ni próximas a vencer
                                en los próximos <?php echo $filtro_dias?:60; ?> días.
                            </div>
                            <div style="margin-top:20px;">
                                <button onclick="toggleMostrarAlDia(true)" class="btn btn-primary btn-sm">
                                    <i class="fas fa-eye"></i> Ver todos los contratos
                                </button>
                            </div>
                        </div>
                    </td>
                </tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>

    <!-- ── Paginador ── -->
    <?php if ($total_paginas > 1): ?>
    <div class="paginador-wrap">
        <div class="paginador-info">
            Mostrando
            <strong><?php echo min($offset+1,$total_registros); ?>–<?php echo min($offset+$por_pagina,$total_registros); ?></strong>
            de <strong><?php echo number_format($total_registros); ?></strong> contratos
        </div>
        <div class="paginador-pages">
            <a class="pag-btn <?php echo $pagina_actual<=1?'disabled':''; ?>"
               href="<?php echo buildVigUrl(1,$params_url); ?>" title="Primera">
                <i class="fas fa-angles-left" style="font-size:10px;"></i>
            </a>
            <a class="pag-btn <?php echo $pagina_actual<=1?'disabled':''; ?>"
               href="<?php echo buildVigUrl($pagina_actual-1,$params_url); ?>" title="Anterior">
                <i class="fas fa-angle-left" style="font-size:11px;"></i>
            </a>
            <?php
            $ri = max(1, $pagina_actual-2);
            $rf = min($total_paginas, $pagina_actual+2);
            if ($ri > 1) echo '<a href="'.buildVigUrl(1,$params_url).'" class="pag-btn">1</a>';
            if ($ri > 2) echo '<span class="pag-btn ellipsis">…</span>';
            for ($pg=$ri; $pg<=$rf; $pg++):
            ?>
                <a class="pag-btn <?php echo $pg===$pagina_actual?'active':''; ?>"
                   href="<?php echo buildVigUrl($pg,$params_url); ?>"><?php echo $pg; ?></a>
            <?php endfor;
            if ($rf < $total_paginas-1) echo '<span class="pag-btn ellipsis">…</span>';
            if ($rf < $total_paginas) echo '<a href="'.buildVigUrl($total_paginas,$params_url).'" class="pag-btn">'.$total_paginas.'</a>';
            ?>
            <a class="pag-btn <?php echo $pagina_actual>=$total_paginas?'disabled':''; ?>"
               href="<?php echo buildVigUrl($pagina_actual+1,$params_url); ?>" title="Siguiente">
                <i class="fas fa-angle-right" style="font-size:11px;"></i>
            </a>
            <a class="pag-btn <?php echo $pagina_actual>=$total_paginas?'disabled':''; ?>"
               href="<?php echo buildVigUrl($total_paginas,$params_url); ?>" title="Última">
                <i class="fas fa-angles-right" style="font-size:10px;"></i>
            </a>
        </div>
    </div>
    <?php endif; ?>
</div>

<!-- ============================================================
     MODAL — FACTURAS PENDIENTES DEL CONTRATO
     ============================================================ -->
<div id="modalFacturasPend" class="modal-overlay-fp2">
    <div class="modal-box-fp2">

        <!-- Header -->
        <div class="modal-hd-fp2">
            <div class="mhf-icon"><i class="fas fa-file-invoice-dollar"></i></div>
            <div>
                <div class="mhf-title" id="mfp-titulo">Facturas Pendientes</div>
                <div class="mhf-sub" id="mfp-sub">Cargando información…</div>
            </div>
            <button class="mhf-close" onclick="cerrarModalFactPend()">&times;</button>
        </div>

        <!-- Chips de info rápida -->
        <div class="modal-chips" id="mfp-chips">
            <div class="info-chip">
                <i class="fas fa-spinner fa-spin"></i>
                <span>Cargando…</span>
            </div>
        </div>

        <!-- Resumen de montos -->
        <div class="modal-summary" id="mfp-summary" style="display:none;">
            <div class="msumm-card">
                <div class="msumm-value" id="mfp-total-fact" style="color:var(--accent);">—</div>
                <div class="msumm-label">Facturas Pendientes</div>
            </div>
            <div class="msumm-card">
                <div class="msumm-value" id="mfp-monto-total" style="color:#DC2626;">—</div>
                <div class="msumm-label">Monto Total Pendiente</div>
            </div>
            <div class="msumm-card">
                <div class="msumm-value" id="mfp-meses-atraso" style="color:#D97706;">—</div>
                <div class="msumm-label">Meses en Atraso</div>
            </div>
        </div>

        <!-- Tabs -->
        <div class="modal-tabs" id="mfp-tabs" style="display:none;">
            <button class="modal-tab-btn active" onclick="switchTab(this,'tab-pendientes')">
                <i class="fas fa-clock"></i> Pendientes
            </button>
            <button class="modal-tab-btn" onclick="switchTab(this,'tab-incompletas')">
                <i class="fas fa-circle-half-stroke"></i> Con Abonos
            </button>
            <button class="modal-tab-btn" onclick="switchTab(this,'tab-vencidas')">
                <i class="fas fa-circle-xmark"></i> Vencidas
            </button>
        </div>

        <!-- Body con tabs -->
        <div class="modal-bd-fp2" id="mfp-body">
            <div style="text-align:center;padding:50px;color:var(--gray-400);">
                <i class="fas fa-spinner fa-spin" style="font-size:28px;margin-bottom:10px;display:block;"></i>
                <p>Cargando facturas…</p>
            </div>
        </div>

        <!-- Footer -->
        <div class="modal-ft-fp2">
            <div id="mfp-footer-info" style="font-size:12px;color:var(--gray-500);">
            </div>
            <div style="display:flex;gap:10px;">
                <button class="btn btn-secondary btn-sm" onclick="cerrarModalFactPend()">
                    <i class="fas fa-times"></i> Cerrar
                </button>
                <a id="mfp-link-facturacion" href="facturacion.php" class="btn btn-primary btn-sm">
                    <i class="fas fa-file-invoice-dollar"></i> Ver en Facturación
                </a>
            </div>
        </div>
    </div>
</div>

<!-- ============================================================
     JAVASCRIPT
     ============================================================ -->
<script>
/* ── Filtros ── */
let searchTimer = null;
/* ── Filtros — El formulario usa GET estándar ── */
(function() {
    var si = document.getElementById('searchInput');
    if (si) si.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') { e.preventDefault(); this.form.submit(); }
    });
})();

function cambiarPorPagina(val) {
    document.cookie = 'vigencia_por_pagina=' + val + '; path=/; max-age=31536000';
    var form = document.getElementById('formFiltrosVigencia');
    if (form) form.submit();
}

/* ── Modal Facturas Pendientes ── */
let contratoIdActual = null;

function verFacturasPendientes(contratoId, numeroContrato, clienteNombre) {
    contratoIdActual = contratoId;
    document.getElementById('mfp-titulo').textContent = 'Facturas Pendientes — Contrato ' + numeroContrato;
    document.getElementById('mfp-sub').textContent = clienteNombre;
    document.getElementById('mfp-chips').innerHTML =
        '<div class="info-chip"><i class="fas fa-spinner fa-spin"></i><span>Cargando…</span></div>';
    document.getElementById('mfp-body').innerHTML =
        '<div style="text-align:center;padding:50px;color:var(--gray-400);">' +
        '<i class="fas fa-spinner fa-spin" style="font-size:28px;margin-bottom:10px;display:block;"></i>' +
        '<p>Cargando facturas…</p></div>';
    document.getElementById('mfp-summary').style.display = 'none';
    document.getElementById('mfp-tabs').style.display = 'none';
    document.getElementById('mfp-link-facturacion').href =
        'facturacion.php?numero_contrato=' + encodeURIComponent(numeroContrato);

    document.getElementById('modalFacturasPend').classList.add('show');
    document.body.style.overflow = 'hidden';

    /* Cargar facturas vía AJAX */
    fetch('ajax_facturas_vigencia.php?contrato_id=' + contratoId)
        .then(r => r.json())
        .then(data => renderizarFacturasPend(data, numeroContrato, clienteNombre))
        .catch(() => {
            document.getElementById('mfp-body').innerHTML =
                '<div style="text-align:center;padding:40px;color:#DC2626;">' +
                '<i class="fas fa-circle-xmark" style="font-size:28px;margin-bottom:10px;display:block;"></i>' +
                '<p>Error al cargar las facturas.</p></div>';
        });
}

function renderizarFacturasPend(data, numeroContrato, clienteNombre) {
    const facturas   = data.facturas || [];
    const pendientes  = facturas.filter(f => f.estado === 'pendiente' && f.monto_pendiente > 0);
    const incompletas = facturas.filter(f => f.estado === 'incompleta');
    const vencidas    = facturas.filter(f => f.estado === 'vencida');

    const montoTotal = facturas.reduce((s, f) => s + parseFloat(f.monto_pendiente || 0), 0);
    const mesesAtraso = facturas.length;

    /* Chips */
    document.getElementById('mfp-chips').innerHTML = `
        <div class="info-chip"><i class="fas fa-hashtag"></i><span>Contrato ${numeroContrato}</span></div>
        <div class="info-chip"><i class="fas fa-user"></i><span>${clienteNombre}</span></div>
        <div class="info-chip red"><i class="fas fa-exclamation-circle"></i>
            <span>${facturas.length} factura${facturas.length!==1?'s':''} pendiente${facturas.length!==1?'s':''}</span>
        </div>
        <div class="info-chip red"><i class="fas fa-coins"></i>
            <span>RD$${montoTotal.toLocaleString('es-DO',{minimumFractionDigits:2})}</span>
        </div>
    `;

    /* Resumen */
    document.getElementById('mfp-total-fact').textContent  = facturas.length;
    document.getElementById('mfp-monto-total').textContent = 'RD$' + montoTotal.toLocaleString('es-DO',{minimumFractionDigits:2});
    document.getElementById('mfp-meses-atraso').textContent = mesesAtraso + ' mes' + (mesesAtraso!==1?'es':'');
    document.getElementById('mfp-summary').style.display = 'grid';

    /* Tabs */
    document.getElementById('mfp-tabs').style.display = 'flex';

    /* Construir contenido de tabs */
    let html = buildTablaFacturas('tab-pendientes', pendientes, 'Pendientes de pago (sin abono)', true);
    html    += buildTablaFacturas('tab-incompletas', incompletas, 'Con abonos parciales (saldo pendiente)');
    html    += buildTablaFacturas('tab-vencidas', vencidas, 'Vencidas');

    document.getElementById('mfp-body').innerHTML = html;

    /* Footer info */
    document.getElementById('mfp-footer-info').innerHTML =
        '<i class="fas fa-info-circle" style="color:var(--accent);margin-right:5px;"></i>' +
        'Haga clic en "Ver" para registrar el pago de cada factura.';
}

function buildTablaFacturas(tabId, facturas, titulo, activo = false) {
    let html = `<div id="${tabId}" class="modal-tab-content ${activo?'active':''}">`;

    if (facturas.length === 0) {
        html += `<div style="text-align:center;padding:30px;color:var(--gray-400);">
            <i class="fas fa-check-circle" style="font-size:24px;color:#22C55E;display:block;margin-bottom:8px;"></i>
            <p style="font-weight:600;color:var(--gray-500);">No hay facturas en esta categoría</p>
            </div>`;
    } else {
        let montoSubtotal = 0;
        let rows = '';
        facturas.forEach(f => {
            const pend = parseFloat(f.monto_pendiente || 0);
            montoSubtotal += pend;
            const estadoColor = f.estado==='vencida'?'#FEE2E2;color:#991B1B':
                                f.estado==='incompleta'?'#DBEAFE;color:#1E40AF':
                                '#FEF3C7;color:#92400E';
            rows += `<tr>
                <td style="font-family:monospace;font-weight:700;color:var(--accent);">
                    <a href="ver_factura.php?id=${f.id}" target="_blank" style="color:var(--accent);text-decoration:none;">
                        ${f.numero_factura}
                    </a>
                </td>
                <td>${f.mes_factura}</td>
                <td style="font-family:monospace;">RD$${parseFloat(f.monto).toLocaleString('es-DO',{minimumFractionDigits:2})}</td>
                <td style="font-family:monospace;color:#166534;">RD$${parseFloat(f.total_abonado||0).toLocaleString('es-DO',{minimumFractionDigits:2})}</td>
                <td style="font-family:monospace;color:#DC2626;font-weight:700;">
                    RD$${pend.toLocaleString('es-DO',{minimumFractionDigits:2})}
                </td>
                <td>
                    <span style="display:inline-flex;align-items:center;gap:4px;padding:3px 9px;
                        border-radius:20px;font-size:11px;font-weight:600;
                        background:${estadoColor};">
                        ${ucFirst(f.estado)}
                    </span>
                </td>
                <td>
                    <a href="registrar_pago.php?factura_id=${f.id}"
                       class="btn btn-primary btn-xs">
                        <i class="fas fa-dollar-sign"></i> Pagar
                    </a>
                </td>
            </tr>`;
        });

        html += `<table class="modal-table">
            <thead>
                <tr>
                    <th>N° Factura</th>
                    <th>Período</th>
                    <th>Monto</th>
                    <th>Abonado</th>
                    <th>Pendiente</th>
                    <th>Estado</th>
                    <th>Acción</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
            <tfoot>
                <tr>
                    <td colspan="4" style="text-align:right;">Subtotal pendiente:</td>
                    <td style="color:#DC2626;font-size:15px;">
                        RD$${montoSubtotal.toLocaleString('es-DO',{minimumFractionDigits:2})}
                    </td>
                    <td colspan="2"></td>
                </tr>
            </tfoot>
        </table>`;
    }
    html += '</div>';
    return html;
}

function switchTab(btn, tabId) {
    document.querySelectorAll('.modal-tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.modal-tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    const tab = document.getElementById(tabId);
    if (tab) tab.classList.add('active');
}

function cerrarModalFactPend() {
    document.getElementById('modalFacturasPend').classList.remove('show');
    document.body.style.overflow = '';
    contratoIdActual = null;
}

function ucFirst(str) {
    return str ? str.charAt(0).toUpperCase() + str.slice(1) : '';
}

/* Cerrar con Escape o click fuera */
document.addEventListener('keydown', e => {
    if (e.key === 'Escape') cerrarModalFactPend();
});
document.getElementById('modalFacturasPend')?.addEventListener('click', function(e) {
    if (e.target === this) cerrarModalFactPend();
});

const nombreEmpresaWA = <?php echo json_encode($nombreEmpresa); ?>;

/* ── WhatsApp Notificación de Vigencia ── */
function enviarWhatsApp(numero, nombre, mes, monto, tipo) {
    /* ── Saludo según hora local del dispositivo ── */
    const hora = new Date().getHours();
    let saludo = '';
    if (hora >= 6 && hora < 12) {
        saludo = 'Buenos días';
    } else if (hora >= 12 && hora < 18) {
        saludo = 'Buenas tardes';
    } else {
        saludo = 'Buenas noches';
    }
    /* ── Limpiar y normalizar número dominicano ── */
    let numLimpio = numero.replace(/[\s\-\(\)\+]/g, '');
    if (numLimpio.startsWith('0')) {
        numLimpio = '1' + numLimpio.substring(1);
    }
    if (numLimpio.length === 10 && numLimpio.startsWith('8')) {
        numLimpio = '1' + numLimpio;
    }
    /* ── Construir mensaje según tipo de vigencia ── */
    let mensaje = '';
    if (tipo === 'vencida') {
        mensaje = saludo + ', ' + nombre + ', tienes un saldo pendiente desde ' + mes +
                  ' por RD$' + monto + '. Te agradecemos ponerte al día lo antes ' +
                  'posible para evitar la suspensión definitiva de tu servicio. ' +
                  'Para más información comunícate con nosotros. - ' + nombreEmpresaWA;
    } else {
        mensaje = saludo + ', ' + nombre + ', te recordamos que tu contrato está próximo ' +
                  'a vencer y tienes un saldo pendiente de RD$' + monto + ' desde ' +
                  mes + '. Te invitamos a ponerte al día para evitar interrupciones ' +
                  'en tu servicio. Para más información comunícate con nosotros. - ' + nombreEmpresaWA;
    }
    let url = 'https://wa.me/' + numLimpio + '?text=' + encodeURIComponent(mensaje);
    window.open(url, '_blank');
}
</script>

<?php require_once 'footer.php'; ?>