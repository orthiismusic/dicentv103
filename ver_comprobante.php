<?php
require_once 'config.php';
verificarSesion();

if (!isset($_GET['id'])) {
    header('Location: pagos.php');
    exit();
}

$id = (int)$_GET['id'];

$stmt = $conn->prepare("
    SELECT p.*,
           f.numero_factura, f.mes_factura, f.monto as monto_factura,
           c.numero_contrato,
           cl.nombre as cliente_nombre, cl.apellidos as cliente_apellidos,
           cl.direccion as cliente_direccion,
           co.nombre_completo as cobrador_nombre,
           cfg.nombre_empresa, cfg.direccion as empresa_direccion, 
           cfg.telefono, cfg.celular, cfg.rif, cfg.logo_url
    FROM pagos p
    JOIN facturas f ON p.factura_id = f.id
    JOIN contratos c ON f.contrato_id = c.id
    JOIN clientes cl ON c.cliente_id = cl.id
    LEFT JOIN cobradores co ON p.cobrador_id = co.id
    CROSS JOIN configuracion_sistema cfg
    WHERE p.id = ?
");

$stmt->execute([$id]);
$pago = $stmt->fetch();

if (!$pago) {
    header('Location: pagos.php');
    exit();
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
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Comprobante de Pago</title>
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
        }
        .factura {
            width: 8.5in;
            height: 5.5in;
            padding: 0.25in;
            box-sizing: border-box;
            position: absolute;
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
        .ncf-number {
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
        .payment-history {
            margin: 0.2in 0;
        }
        .details-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 0.2in;
        }
        .details-table th,
        .details-table td {
            padding: 0.1in;
            border: 1px solid #000;
            text-align: left;
        }
        .details-table th {
            background-color: #f0f0f0;
        }
        .monto {
            text-align: right;
        }
        .payment-method {
            margin: 0.2in 0;
            font-size: 15px;
        }
        .firmas {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
            margin-top: 0.5in;
            text-align: center;
        }
        .firma .linea {
            border-top: 1px solid #000;
            margin-bottom: 0.1in;
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
    <div class="comprobante-wrapper">
    <div class="control-buttons no-print">
        <button onclick="window.print()" class="btn btn-primary"><i class="fas fa-print"></i> Imprimir comprobante</button>
        <button onclick="window.close()" class="btn btn-secondary"><i class="fas fa-times"></i> Cerrar</button>
    </div>
    </div>

    <div class="pagina">
        <div class="factura">
            <div class="invoice-container">
                <div class="header">
                    <?php if ($pago['logo_url']): ?>
                        <img src="<?php echo htmlspecialchars($pago['logo_url']); ?>" alt="Logo" class="logo">
                    <?php endif; ?>
                    <div class="header-text">
                        <br><br>
                        <div class="company-address">
                            <?php echo htmlspecialchars($pago['empresa_direccion']); ?><br>
                            Teléfono: <?php echo htmlspecialchars($pago['telefono']); ?> - 
                            Celular 24 Horas: <?php echo htmlspecialchars($pago['celular']); ?><br>
                            RNC: <?php echo htmlspecialchars($pago['rif']); ?>
                        </div>
                    </div>
                </div>

                

                <div class="invoice-details">
                    <div style="display: flex; justify-content: space-between;">
                        <div>
                            <span class="invoice-number">COMPROBANTE DE PAGO: <?php echo str_pad($pago['id'], 7, '0', STR_PAD_LEFT); ?></span>
                        </div>
                        <div class="dates">
                            <span class="ncf-number">NCF: B010000000001</span>
                        </div>
                        <div class="dates">
                            Fecha: <?php echo date('d/m/Y', strtotime($pago['fecha_pago'])); ?>
                        </div>
                    </div>
                </div>

                <table class="details">
                    <tr>
                        <td colspan="2">Contrato: <?php echo strtoupper($pago['numero_contrato'] . ' -  ' . $pago['cliente_nombre']. ' ' . $pago['cliente_apellidos']); ?></td>
                    </tr>
                    
                </table>

                <div class="payment-history">
                    <table class="details-table">
                        <thead>
                            <tr>
                                <th>Descripción</th>
                                <th>Monto</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>Pago de factura #<?php echo htmlspecialchars($pago['numero_factura']); ?> (Mes pagado: <?php echo mesATexto($pago['mes_factura']); ?>)</td>
                                <td class="monto">RD$<?php echo number_format($pago['monto'], 2); ?></td>
                            </tr>
                        </tbody>
                        <tfoot>
                            <tr>
                                <td style="text-align: right;"><strong>Total Pagado:</strong></td>
                                <td class="monto"><strong>RD$<?php echo number_format($pago['monto'], 2); ?></strong></td>
                            </tr>
                        </tfoot>
                    </table>
                </div>

                <div class="payment-method">
                    <strong>Método de pago:</strong> <?php echo ucfirst(htmlspecialchars($pago['metodo_pago'])); ?>
                    <?php if ($pago['referencia_pago']): ?>
                        <br>
                        <strong>Referencia:</strong> <?php echo htmlspecialchars($pago['referencia_pago']); ?>
                    <?php endif; ?>
                </div>

                <div class="firmas">
                    <div class="firma">
                        <div class="linea"></div>
                        <p>Cobrador: <?php echo htmlspecialchars($pago['cobrador_nombre']); ?></p>
                    </div>
                    <div class="firma">
                        <div class="linea"></div>
                        <p>Cliente</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        window.onload = function() {
            if (!window.location.search.includes('noprint')) {
                window.print();
            }
        };
    </script>
    
</body>
</html>