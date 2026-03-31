<?php
require_once 'config.php';
verificarSesion();

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

// Obtener IDs de facturas seleccionadas
$facturas_ids = $_GET['facturas'] ?? [];
$tipo = $_GET['tipo'] ?? 'preview';

if (empty($facturas_ids)) {
    die('No se han seleccionado facturas');
}

// Preparar la consulta con los IDs de las facturas
$placeholders = str_repeat('?,', count($facturas_ids) - 1) . '?';
$sql = "
    SELECT f.*, c.numero_contrato, c.dia_cobro,
           cl.nombre as cliente_nombre, cl.apellidos as cliente_apellidos,
           cl.direccion as cliente_direccion, cl.telefono1, cl.telefono2,
           cl.notas as notas,
           p.nombre as plan_nombre,
           co.nombre_completo as cobrador_nombre,
           v.nombre_completo as vendedor_nombre,
           (
               SELECT COUNT(*)
               FROM asignaciones_facturas af 
               WHERE af.factura_id = f.id 
               AND af.estado = 'activa'
           ) as esta_asignada
    FROM facturas f
    JOIN contratos c ON f.contrato_id = c.id
    JOIN clientes cl ON c.cliente_id = cl.id
    JOIN planes p ON c.plan_id = p.id
    LEFT JOIN cobradores co ON cl.cobrador_id = co.id
    LEFT JOIN vendedores v ON v.id = cl.vendedor_id
    WHERE f.id IN ($placeholders)
    ORDER BY f.numero_factura ASC
";

$stmt = $conn->prepare($sql);
$stmt->execute($facturas_ids);
$facturas = $stmt->fetchAll();

// Obtener configuración del sistema
$stmtConfig = $conn->prepare("SELECT *, logo_url FROM configuracion_sistema WHERE id = 1");
$stmtConfig->execute();
$config = $stmtConfig->fetch();
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Imprimir Facturas por Lote</title>
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
        .factura:last-child {
            top: 5.5in;
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
        <h3>Total facturas a imprimir: <?php echo count($facturas); ?></h3>
        <button onclick="window.print()" class="btn btn-primary">
            <i class="fas fa-print"></i> Imprimir <?php echo count($facturas); ?> factura(s)
        </button>
        <button onclick="window.close()" class="btn btn-secondary">
            <i class="fas fa-times"></i> Cerrar
        </button>
        <?php if($tipo === 'direct'): ?>
            <script>
                window.onload = function() {
                    window.print();
                    setTimeout(function() { window.close(); }, 500);
                };
            </script>
        <?php endif; ?>
    </div>

    <?php 
    $total_facturas = count($facturas);
    for ($i = 0; $i < $total_facturas; $i += 2):
        $factura1 = $facturas[$i];
        $factura2 = ($i + 1 < $total_facturas) ? $facturas[$i + 1] : null;
    ?>
    <div class="pagina">
        <!-- Primera factura -->
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
                            <span class="invoice-number">FACTURA: <?php echo str_pad($factura1['numero_factura'], 7, '0', STR_PAD_LEFT); ?></span>
                            <span class="status"> - <?php echo ucfirst($factura1['estado']); ?><?php 
                                echo $factura1['esta_asignada'] > 0 ? ' - Asignada' : ''; 
                            ?></span>
                        </div>
                        <div class="dates">
                            Fecha: <?php echo date('d/m/Y', strtotime($factura1['fecha_emision'])); ?><br>
                            Vence: <?php echo !empty($factura1['fecha_vencimiento']) ? date('d/m/Y', strtotime($factura1['fecha_vencimiento'])) : 'No especificado'; ?><br>
                        </div>
                    </div>
                </div>

                <table class="details">
                    <tr>
                        <td>Contrato: <?php echo str_pad($factura1['numero_contrato'], 6, '0', STR_PAD_LEFT); ?></td>
                        <td>
                            &nbsp;&nbsp;&nbsp;&nbsp;Cuota: <?php echo $factura1['cuota']; ?>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
                            Plan: <?php echo $factura1['plan_nombre']; ?>
                            <td>Mes: <?php echo mesATexto($factura1['mes_factura']); ?></td>
                        </td>
                    </tr>
                </table>

                <div class="client-info">
                    <strong><div>Cliente: <?php echo strtoupper($factura1['cliente_nombre'] . ' ' . $factura1['cliente_apellidos']); ?></div></strong>
                    <div>Dirección: <?php echo strtoupper($factura1['cliente_direccion']); ?></div>
                    <div>Referencia: <?php echo strtoupper($factura1['notas'] ?? ''); ?></div>
                    <div>Teléfonos: <?php echo $factura1['telefono1'] . ($factura1['telefono2'] ? ' / ' . $factura1['telefono2'] : ''); ?></div>
                    <div>Día cobro: <?php echo $factura1['dia_cobro']; ?></div>
                </div>

                <div class="staff-info">
                    <strong><div>Total: RD$<?php echo number_format($factura1['monto'], 2); ?></div></strong>
                </div>

                <div class="staff-info">
                    <div>Vendedor: <?php echo strtoupper($factura1['vendedor_nombre']); ?></div>
                    <div>Cobrador: <?php echo strtoupper($factura1['cobrador_nombre']); ?></div>
                </div>

                <div class="footer">
                    Nota: debe estar al día con su pago, evite suspensión del servicio.
                </div>
            </div>
        </div>

        <?php if ($factura2): ?>
        <!-- Segunda factura -->
        <div class="factura" style="top: 5.5in;">
            <div class="invoice-container">
                <!-- El contenido es igual que la primera factura pero con $factura2 -->
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
                            <span class="invoice-number">FACTURA: <?php echo str_pad($factura2['numero_factura'], 7, '0', STR_PAD_LEFT); ?></span>
                            <span class="status"> - <?php echo ucfirst($factura2['estado']); ?><?php 
                echo $factura1['esta_asignada'] > 0 ? ' - Asignada' : ''; 
            ?></span>
                        </div>
                        <div class="dates">
                            Fecha: <?php echo date('d/m/Y', strtotime($factura2['fecha_emision'])); ?><br>
                            Vence: <?php echo !empty($factura2['fecha_vencimiento']) ? date('d/m/Y', strtotime($factura2['fecha_vencimiento'])) : 'No especificado'; ?><br>
                        </div>
                    </div>
                </div>

                <table class="details">
                    <tr>
                        <td>Contrato: <?php echo str_pad($factura2['numero_contrato'], 6, '0', STR_PAD_LEFT); ?></td>
                        <td>
                            &nbsp;&nbsp;&nbsp;&nbsp;Cuota: <?php echo $factura2['cuota']; ?>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
                            Plan: <?php echo $factura2['plan_nombre']; ?>
                            <td>Mes: <?php echo mesATexto($factura2['mes_factura']); ?></td>
                        </td>
                    </tr>
                </table>

                <div class="client-info">
                    <strong><div>Cliente: <?php echo strtoupper($factura2['cliente_nombre'] . ' ' . $factura2['cliente_apellidos']); ?></div></strong>
                    <div>Dirección: <?php echo strtoupper($factura2['cliente_direccion']); ?></div>
                    <div>Referencia: <?php echo strtoupper($factura2['notas'] ?? ''); ?></div>
                    <div>Teléfonos: <?php echo $factura2['telefono1'] . ($factura2['telefono2'] ? ' / ' . $factura2['telefono2'] : ''); ?></div>
                    <div>Día cobro: <?php echo $factura2['dia_cobro']; ?></div>
                </div>

                <div class="staff-info">
                    <strong><div>Total: RD$<?php echo number_format($factura2['monto'], 2); ?></div></strong>
                </div>

                <div class="staff-info">
                    <div>Vendedor: <?php echo strtoupper($factura2['vendedor_nombre']); ?></div>
                    <div>Cobrador: <?php echo strtoupper($factura2['cobrador_nombre']); ?></div>
                </div>

                <div class="footer">
                    Nota: debe estar al día con su pago, evite suspensión del servicio.
                </div>
            </div>
        </div>
        <?php endif; ?>
    </div>
    <?php endfor; ?>
</body>
</html>