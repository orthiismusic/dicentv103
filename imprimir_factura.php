<?php
require_once 'config.php';
verificarSesion();

if (!isset($_GET['id'])) {
    die('ID de factura no proporcionado');
}

function mesATexto($fecha) {
    $meses = [
        '01' => 'Enero', '02' => 'Febrero', '03' => 'Marzo',
        '04' => 'Abril', '05' => 'Mayo', '06' => 'Junio',
        '07' => 'Julio', '08' => 'Agosto', '09' => 'Septiembre',
        '10' => 'Octubre', '11' => 'Noviembre', '12' => 'Diciembre'
    ];
    
    $partes = explode('/', $fecha);
    return (count($partes) == 2) ? $meses[$partes[0]] . '/' . $partes[1] : $fecha;
}

$id = (int)$_GET['id'];
$tipo = $_GET['tipo'] ?? 'preview';

$stmtConfig = $conn->prepare("SELECT *, logo_url FROM configuracion_sistema WHERE id = 1");
$stmtConfig->execute();
$config = $stmtConfig->fetch();

$stmt = $conn->prepare("
    SELECT f.*, c.numero_contrato, c.dia_cobro,
           cl.nombre as cliente_nombre, cl.apellidos as cliente_apellidos,
           cl.direccion as cliente_direccion, cl.telefono1, cl.telefono2,
           cl.notas as notas,
           p.nombre as plan_nombre,
           co.nombre_completo as cobrador_nombre,
           v.nombre_completo as vendedor_nombre
    FROM facturas f
    JOIN contratos c ON f.contrato_id = c.id
    JOIN clientes cl ON c.cliente_id = cl.id
    JOIN planes p ON c.plan_id = p.id
    LEFT JOIN cobradores co ON co.id = cl.cobrador_id
    LEFT JOIN vendedores v ON v.id = cl.vendedor_id
    WHERE f.id = ?
");

$stmt->execute([$id]);
$factura = $stmt->fetch();



// Verificar si la factura está asignada
$stmtAsignacion = $conn->prepare("
    SELECT COUNT(*) as asignada 
    FROM asignaciones_facturas 
    WHERE factura_id = ? AND estado = 'activa'
");
$stmtAsignacion->execute([$id]);
$asignacion = $stmtAsignacion->fetch();
$facturaAsignada = $asignacion['asignada'] > 0;




if (!$factura) {
    die('Factura no encontrada');
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Imprimir Factura</title>
    <style>
        @page {
            size: 8.5in 11in;
            margin: 0;
        }
        body {
            margin: 0;
            padding: 0;
            font-family: "Draft", "Letter Gothic", "Arial", monospace;
        }
        .pagina {
            width: 8.5in;
            height: 11in;
            position: relative;
            page-break-after: always;
        }
        .factura {
            width: 8.5in;
            height: 5.5in;
            padding: 0.25in;
            box-sizing: border-box;
            position: absolute;
        }
        .factura:first-child {
            top: 0;
        }
        .invoice-container {
            padding: 0.2in;
            height: 4.8in;
            box-sizing: border-box;
        }
        .header {
            text-align: left;
            margin-bottom: 0.3in;
            color: #000;
            display: flex;
            align-items: center;
            gap: 0.2in;
        }
        .logo {
            max-height: 0.9in;
        }
        .header-text {
            flex: 1;
        }
        .company-name {
            font-size: 16px;
            font-weight: bold;
            margin-bottom: 0.05in;
            text-transform: uppercase;
            border-bottom: 1px solid #000;
            padding-bottom: 0.05in;
        }
        .company-address {
            font-size: 15px;
            line-height: 1.2;
            text-align: center;
        }
        .invoice-details {
            margin: 0.15in 0;
            font-size: 15px;
        }
        .invoice-number {
            font-weight: bold;
        }
        .details {
            width: 100%;
            margin-bottom: 0.15in;
            border-collapse: collapse;
        }
        .details td {
            padding: 0.05in;
            font-size: 15px;
            border-bottom: 1px solid #000;
        }
        .client-info {
            border: 1px solid #000;
            padding: 0.1in;
            margin: 0.1in 0;
            font-size: 15px;
            line-height: 1.2;
        }
        .payment-info {
            display: flex;
            justify-content: space-between;
            margin: 0.15in 0;
            font-size: 15px;
        }
        .staff-info {
            display: flex;
            justify-content: space-between;
            margin: 0.15in 0;
            font-size: 14px;
        }
        .footer {
            margin-top: 0.2in;
            font-style: italic;
            font-size: 15px;
            text-align: center;
        }
        .decorative-border {
            border-top: 1px solid #000;
            margin: 0.1in 0;
        }
        .control-buttons {
            text-align: left;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px 8px 0 0;
        }
        .btn {
            padding: 8px 16px;
            margin-left: 10px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        .btn-primary {
            background-color: #0066cc;
            color: white;
        }
        .btn-secondary {
            background-color: #6c757d;
            color: white;
        }
        .btn:hover {
            opacity: 0.9;
        }
        @media print {
            .no-print {
                display: none;
            }
        }
    </style>
</head>
<body>
    <div class="no-print" style="padding: 20px;">
        <h3>Total facturas a imprimir: 1</h3>
        <button onclick="window.print()" class="btn btn-primary"><i class="fas fa-print"></i> Imprimir factura</button>
        <button onclick="window.close()" class="btn btn-secondary"><i class="fas fa-times"></i> Cerrar</button>
        <?php if($tipo === 'direct'): ?>
            <script>
                window.onload = function() {
                    window.print();
                    setTimeout(function() { window.close(); }, 500);
                };
            </script>
        <?php endif; ?>
    </div>

    <div class="pagina">
        <div class="factura" style="top: 0;">
            <div class="invoice-container">
                <div class="header">
                    <?php if ($config['logo_url']): ?>
                        <img src="<?php echo htmlspecialchars($config['logo_url']); ?>" alt="Logo" class="logo">
                    <?php endif; ?>
                    <div class="header-text">
                        <br><br>
                        <div class="company-address">
                            <?php echo $config['direccion']; ?><br>
                            Teléfono: <?php echo $config['telefono']; ?> - Celular 24 Horas: <?php echo $config['celular']; ?><br>
                            RNC: <?php echo $config['rif']; ?>
                        </div>
                    </div>
                </div>

                <div class="decorative-border"></div>

                <div class="invoice-details">
                    <div style="display: flex; justify-content: space-between;">
                        <div>
                            <span class="invoice-number">FACTURA: <?php echo str_pad($factura['numero_factura'], 7, '0', STR_PAD_LEFT); ?></span>
                            <span class="status"> - <?php echo ucfirst($factura['estado']); ?><?php echo $facturaAsignada ? ' - Asignada' : ''; ?></span>
                        </div>
                        <div class="dates">
                            Fecha: <?php echo date('d/m/Y', strtotime($factura['fecha_emision'])); ?><br>
                            Vence: <?php echo !empty($factura['fecha_vencimiento']) ? date('d/m/Y', strtotime($factura['fecha_vencimiento'])) : 'No especificado'; ?><br>
                        </div>
                    </div>
                </div>

                <table class="details">
                    <tr>
                        <td>Contrato: <?php echo str_pad($factura['numero_contrato'], 6, '0', STR_PAD_LEFT); ?></td>
                        <td>
                            &nbsp;&nbsp;&nbsp;&nbsp;Cuota: <?php echo $factura['cuota']; ?>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
                            Plan: <?php echo $factura['plan_nombre']; ?>
                            <td>Mes: <?php echo mesATexto($factura['mes_factura']); ?></td>
                        </td>
                    </tr>
                </table>

                <div class="client-info">
                    <strong><div>Cliente: <?php echo strtoupper($factura['cliente_nombre'] . ' ' . $factura['cliente_apellidos']); ?></div></strong>
                    <div>Dirección: <?php echo strtoupper($factura['cliente_direccion']); ?></div>
                    <div>Referencia: <?php echo strtoupper($factura['notas'] ?? ''); ?></div>
                    <div>Teléfonos: <?php echo $factura['telefono1'] . ($factura['telefono2'] ? ' / ' . $factura['telefono2'] : ''); ?></div>
                    <div>Día cobro: <?php echo $factura['dia_cobro']; ?></div>
                </div>

                <div class="staff-info">
                    <strong><div>Total: RD$<?php echo number_format($factura['monto'], 2); ?></div></strong>
                </div>

                <div class="staff-info">
                    <div>Vendedor: <?php echo strtoupper($factura['vendedor_nombre']); ?></div>
                    <div>Cobrador: <?php echo strtoupper($factura['cobrador_nombre']); ?></div>
                </div>

                <div class="footer">
                    Nota: debe estar al día con su pago, evite suspensión del servicio.
                </div>
            </div>
        </div>
    </div>
</body>
</html>