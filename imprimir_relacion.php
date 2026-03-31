<?php
require_once 'config.php';

if (!isset($_GET['cobrador_id'], $_GET['fecha'])) {
    die('Parámetros incompletos.');
}

function fmtMes($mes) {
    $m = ['01'=>'Ene','02'=>'Feb','03'=>'Mar','04'=>'Abr','05'=>'May','06'=>'Jun',
          '07'=>'Jul','08'=>'Ago','09'=>'Sep','10'=>'Oct','11'=>'Nov','12'=>'Dic'];
    $p = explode('/', $mes);
    return count($p) === 2 ? ($m[$p[0]] ?? $p[0]) . '/' . $p[1] : $mes;
}

try {
    $stmtCob = $conn->prepare("SELECT codigo, nombre_completo FROM cobradores WHERE id = ?");
    $stmtCob->execute([$_GET['cobrador_id']]);
    $cobrador = $stmtCob->fetch(PDO::FETCH_ASSOC);

    $stmtConf = $conn->prepare("SELECT * FROM configuracion_sistema WHERE id = 1");
    $stmtConf->execute();
    $config = $stmtConf->fetch(PDO::FETCH_ASSOC);

    $sql = "
        SELECT
            f.numero_factura, f.monto, f.mes_factura, f.estado,
            c.numero_contrato, c.dia_cobro,
            cl.nombre AS cliente_nombre, cl.apellidos AS cliente_apellidos
        FROM asignaciones_facturas af
        JOIN facturas  f  ON af.factura_id  = f.id
        JOIN contratos c  ON f.contrato_id  = c.id
        JOIN clientes  cl ON c.cliente_id   = cl.id
        WHERE af.cobrador_id     = ?
          AND af.fecha_asignacion = ?
          AND af.estado           = 'activa'
    ";
    $params = [$_GET['cobrador_id'], $_GET['fecha']];

    if (!empty($_GET['estado'])) {
        $sql .= " AND f.estado = ?";
        $params[] = $_GET['estado'];
    }

    $sql .= " ORDER BY c.dia_cobro ASC, cl.nombre ASC";

    $stmt = $conn->prepare($sql);
    $stmt->execute($params);
    $facturas = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $total_monto = array_sum(array_column($facturas, 'monto'));

} catch (PDOException $e) {
    die('Error al obtener datos: ' . $e->getMessage());
}

$empresa    = $config['nombre_empresa'] ?? 'SeguroVida RD';
$fecha_fmt  = date('d/m/Y', strtotime($_GET['fecha']));
$fecha_imp  = date('d/m/Y H:i');
$estadoFmt  = !empty($_GET['estado']) ? ucfirst($_GET['estado']) : 'Todos';
?>
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Relación de Facturas — <?php echo htmlspecialchars($cobrador['nombre_completo'] ?? ''); ?></title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:'Segoe UI',Arial,sans-serif; font-size:12px; color:#1a1a1a; background:white; }
.page { padding:20px 24px; }

/* Encabezado */
.header { display:flex; justify-content:space-between; align-items:flex-start;
          border-bottom:3px solid #1565C0; padding-bottom:14px; margin-bottom:16px; }
.header .empresa { font-size:18px; font-weight:800; color:#1565C0; }
.header .sub     { font-size:11px; color:#555; margin-top:3px; }
.header .right   { text-align:right; font-size:11px; color:#555; line-height:1.8; }

/* Info cobrador */
.info-bar {
    background:#EFF6FF; border:1px solid #BFDBFE; border-radius:6px;
    padding:10px 16px; margin-bottom:16px;
    display:flex; gap:30px; flex-wrap:wrap;
}
.info-bar .item label {
    font-size:10px; font-weight:700; color:#64748B;
    text-transform:uppercase; letter-spacing:.5px; display:block;
}
.info-bar .item span { font-size:12.5px; font-weight:600; color:#1E40AF; }

/* Tabla */
table { width:100%; border-collapse:collapse; margin-bottom:16px; }
thead tr { background:#1565C0; color:white; }
thead th {
    padding:8px 10px; font-size:10.5px; font-weight:700;
    text-transform:uppercase; letter-spacing:.5px; white-space:nowrap;
}
tbody tr:nth-child(even) { background:#F8FAFC; }
tbody tr:hover { background:#EFF6FF; }
tbody td { padding:7px 10px; border-bottom:1px solid #E2E8F0; }
.mono  { font-family:monospace; font-size:11.5px; }
.bold  { font-weight:700; }
.center{ text-align:center; }
.right { text-align:right; }

/* Badges */
.badge {
    display:inline-block; padding:2px 8px; border-radius:20px;
    font-size:10px; font-weight:700;
}
.b-pagada    { background:#DCFCE7; color:#15803D; }
.b-pendiente { background:#FEF9C3; color:#A16207; }
.b-incompleta{ background:#DBEAFE; color:#1D4ED8; }
.b-vencida   { background:#FEE2E2; color:#DC2626; }

/* Totales */
.totales-row td {
    border-top:2px solid #1565C0; padding:10px;
    font-weight:800; background:#EFF6FF;
}

/* Pie */
.footer {
    text-align:center; font-size:10px; color:#888;
    border-top:1px solid #E2E8F0; padding-top:10px; margin-top:6px;
}
.empty { text-align:center; padding:30px; color:#888; }

@media print {
    body { print-color-adjust:exact; -webkit-print-color-adjust:exact; }
    .no-print { display:none; }
}
</style>
</head>
<body>
<div class="page">

    <!-- Botón imprimir (no se imprime) -->
    <div class="no-print" style="text-align:right;margin-bottom:12px;">
        <button onclick="window.print()"
                style="background:#1565C0;color:white;border:none;padding:8px 20px;
                       border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;">
            🖨 Imprimir
        </button>
        <button onclick="window.close()"
                style="background:#6B7280;color:white;border:none;padding:8px 16px;
                       border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;margin-left:8px;">
            Cerrar
        </button>
    </div>

    <!-- Encabezado -->
    <div class="header">
        <div>
            <div class="empresa"><?php echo htmlspecialchars($empresa); ?></div>
            <div class="sub">Relación de Facturas Asignadas</div>
        </div>
        <div class="right">
            <strong>Fecha de impresión:</strong> <?php echo $fecha_imp; ?><br>
            <strong>Fecha de asignación:</strong> <?php echo $fecha_fmt; ?><br>
            <strong>Estado filtrado:</strong> <?php echo $estadoFmt; ?>
        </div>
    </div>

    <!-- Info cobrador -->
    <div class="info-bar">
        <div class="item">
            <label>Cobrador</label>
            <span><?php echo htmlspecialchars($cobrador['nombre_completo'] ?? 'N/A'); ?></span>
        </div>
        <div class="item">
            <label>Código</label>
            <span><?php echo htmlspecialchars($cobrador['codigo'] ?? 'N/A'); ?></span>
        </div>
        <div class="item">
            <label>Total Facturas</label>
            <span><?php echo count($facturas); ?></span>
        </div>
        <div class="item">
            <label>Monto Total</label>
            <span>RD$<?php echo number_format($total_monto, 2); ?></span>
        </div>
    </div>

    <!-- Tabla -->
    <?php if (empty($facturas)): ?>
    <div class="empty">No se encontraron facturas con los criterios indicados.</div>
    <?php else: ?>
    <table>
        <thead>
            <tr>
                <th class="center">#</th>
                <th>No. Factura</th>
                <th>Contrato</th>
                <th>Cliente</th>
                <th class="center">Mes</th>
                <th class="center">Día</th>
                <th class="right">Monto</th>
                <th class="center">Estado</th>
            </tr>
        </thead>
        <tbody>
        <?php $i = 0; foreach ($facturas as $f): $i++; ?>
        <tr>
            <td class="center"><?php echo $i; ?></td>
            <td class="mono"><?php echo htmlspecialchars($f['numero_factura']); ?></td>
            <td class="mono"><?php echo htmlspecialchars($f['numero_contrato']); ?></td>
            <td class="bold"><?php echo htmlspecialchars($f['cliente_nombre'].' '.$f['cliente_apellidos']); ?></td>
            <td class="center"><?php echo fmtMes($f['mes_factura']); ?></td>
            <td class="center"><?php echo (int)$f['dia_cobro']; ?></td>
            <td class="right bold">RD$<?php echo number_format($f['monto'], 2); ?></td>
            <td class="center">
                <?php
                $bc = ['pagada'=>'b-pagada','pendiente'=>'b-pendiente',
                       'incompleta'=>'b-incompleta','vencida'=>'b-vencida'];
                $cls = $bc[$f['estado']] ?? '';
                ?>
                <span class="badge <?php echo $cls; ?>">
                    <?php echo ucfirst($f['estado']); ?>
                </span>
            </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
        <tfoot>
            <tr class="totales-row">
                <td colspan="6" style="text-align:right;">TOTAL:</td>
                <td class="right">RD$<?php echo number_format($total_monto, 2); ?></td>
                <td></td>
            </tr>
        </tfoot>
    </table>
    <?php endif; ?>

    <!-- Pie de página -->
    <div class="footer">
        <?php echo htmlspecialchars($empresa); ?> &bull;
        Relación generada el <?php echo $fecha_imp; ?> &bull;
        <?php echo count($facturas); ?> factura(s) &bull;
        Total: RD$<?php echo number_format($total_monto, 2); ?>
    </div>
</div>
</body>
</html>