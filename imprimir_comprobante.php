<?php
require_once 'config.php';
verificarSesion();

if (!isset($_GET['id'])) {
    die('ID de pago no proporcionado');
}

$id = (int)$_GET['id'];

// Obtener datos del pago
$stmt = $conn->prepare("
    SELECT p.*,
           f.numero_factura,
           f.monto as monto_factura,
           c.numero_contrato,
           cl.codigo as cliente_codigo,
           cl.nombre as cliente_nombre,
           cl.apellidos as cliente_apellidos,
           cl.direccion as cliente_direccion,
           cl.telefono1 as cliente_telefono,
           co.nombre_completo as cobrador_nombre,
           cfg.nombre_empresa,
           cfg.rif,
           cfg.direccion as empresa_direccion,
           cfg.telefono as empresa_telefono,
           cfg.email as empresa_email,
           cfg.logo_url
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
    die('Pago no encontrado');
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Comprobante de Pago <?php echo $pago['referencia_pago']; ?></title>
    <style>
        /* Reseteo de estilos */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Arial', sans-serif;
            line-height: 1.6;
            background-color: #f0f2f5;
            padding: 20px;
        }

        /* Contenedor principal */
        .comprobante-wrapper {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-radius: 8px;
        }

        /* Botones de control */
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

        /* Contenido del comprobante */
        .comprobante {
            padding: 30px;
        }

        /* Cabecera de la empresa */
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #eee;
        }

        .logo {
            max-width: 150px;
            height: auto;
            margin-bottom: 15px;
        }

        .empresa-nombre {
            font-size: 24px;
            font-weight: bold;
            color: #333;
            margin-bottom: 10px;
        }

        .empresa-detalles {
            color: #666;
            font-size: 14px;
        }

        /* Título del comprobante */
        .comprobante-titulo {
            text-align: center;
            font-size: 18px;
            font-weight: bold;
            color: #0066cc;
            margin: 18px 0;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 4px;
        }

        /* Información del pago */
        .info-seccion {
            margin: 20px 0;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 4px;
        }

        .info-titulo {
            font-size: 16px;
            font-weight: bold;
            color: #333;
            margin-bottom: 10px;
            border-bottom: 1px solid #ddd;
            padding-bottom: 5px;
        }

        .info-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
        }

        .info-item {
            display: flex;
            flex-direction: column;
        }

        .info-label {
            font-weight: 600;
            color: #666;
            font-size: 14px;
        }

        .info-valor {
            color: #333;
            font-size: 15px;
        }

        /* Detalles del pago */
        .detalles-pago {
            margin: 20px 0;
            border: 1px solid #ddd;
            border-radius: 4px;
        }

        .detalles-tabla {
            width: 100%;
            border-collapse: collapse;
        }

        .detalles-tabla th,
        .detalles-tabla td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }

        .detalles-tabla th {
            background-color: #f8f9fa;
            font-weight: 600;
            color: #333;
        }

        .monto {
            font-size: 18px;
            font-weight: bold;
            color: #0066cc;
        }

        /* Total */
        .total-seccion {
            text-align: right;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 4px;
            margin: 20px 0;
        }

        .total-label {
            font-size: 16px;
            font-weight: bold;
            color: #333;
        }

        .total-valor {
            font-size: 24px;
            font-weight: bold;
            color: #0066cc;
        }

        /* Firmas */
        .firmas-seccion {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 30px;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
        }

        .firma {
            text-align: center;
        }

        .firma-linea {
            width: 80%;
            margin: 10px auto;
            border-top: 1px solid #333;
        }

        .firma-nombre {
            font-size: 14px;
            color: #666;
        }

        /* Pie de página */
        .footer {
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            border-top: 1px solid #ddd;
            color: #666;
            font-size: 12px;
        }

        /* Ajustes para impresión */
        @media print {
            body {
                background: white;
                padding: 0;
            }

            .control-buttons {
                display: none;
            }

            .comprobante-wrapper {
                box-shadow: none;
            }

            .comprobante {
                padding: 20px;
            }
        }

        /* Responsive */
        @media (max-width: 768px) {
            .info-grid {
                grid-template-columns: 1fr;
            }

            .firmas-seccion {
                grid-template-columns: 1fr;
                gap: 20px;
            }

            .comprobante {
                padding: 15px;
            }
        }
    </style>
</head>
<body>
    <div class="comprobante-wrapper">
        <div class="control-buttons no-print">
            <button onclick="window.print()" class="btn btn-primary">
                <i class="fas fa-print"></i> Imprimir
            </button>
            <button onclick="window.close()" class="btn btn-secondary">
                <i class="fas fa-times"></i> Cerrar
            </button>
        </div>

        <div class="comprobante">
            <!-- Cabecera de la empresa -->
            <div class="header">
                <?php if ($pago['logo_url']): ?>
                    <img src="<?php echo htmlspecialchars($pago['logo_url']); ?>" alt="Logo" class="logo">
                <?php endif; ?>
                <div class="empresa-detalles">
                    RIF: <?php echo htmlspecialchars($pago['rif']); ?><br>
                    <?php echo htmlspecialchars($pago['empresa_direccion']); ?><br>
                    Tel: <?php echo htmlspecialchars($pago['empresa_telefono']); ?>
                </div>
            </div>

            <div class="comprobante-titulo">COMPROBANTE DE PAGO</div>

            <!-- Información del cliente -->
            <div class="info-seccion">
                <div class="info-titulo">Información del Cliente</div>
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">Cliente:</span>
                        <span class="info-valor">
                            <?php echo htmlspecialchars($pago['cliente_nombre'] . ' ' . $pago['cliente_apellidos']); ?>
                        </span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Contrato:</span>
                        <span class="info-valor"><?php echo htmlspecialchars($pago['numero_contrato']); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Teléfono:</span>
                        <span class="info-valor"><?php echo htmlspecialchars($pago['cliente_telefono']); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Dirección:</span>
                        <span class="info-valor"><?php echo htmlspecialchars($pago['cliente_direccion']); ?></span>
                    </div>
                </div>
            </div>

            <!-- Detalles del pago -->
            <div class="detalles-pago">
                <table class="detalles-tabla">
                    <thead>
                        <tr>
                            <th>Descripción</th>
                            <th>Factura</th>
                            <th>Contrato</th>
                            <th>Método de Pago</th>
                            <th>Monto</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Pago de factura</td>
                            <td><?php echo htmlspecialchars($pago['numero_factura']); ?></td>
                            <td><?php echo htmlspecialchars($pago['numero_contrato']); ?></td>
                            <td><?php echo ucfirst($pago['metodo_pago']); ?></td>
                            <td class="monto">$<?php echo number_format($pago['monto'], 2); ?></td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <!-- Total -->
            <div class="total-seccion">
                <span class="total-label">Total Pagado:</span>
                <span class="total-valor">$<?php echo number_format($pago['monto'], 2); ?></span>
            </div>
            
            <!-- Firmas -->
            <div class="firmas-seccion">
                <div class="firma">
                    <br><br>
                    <div class="firma-linea"></div>
                    <div class="firma-nombre">
                        Cobrador: <?php echo htmlspecialchars($pago['cobrador_nombre']); ?>
                    </div>
                </div>
                <div class="firma">
                    <br><br>
                    <div class="firma-linea"></div>
                    <div class="firma-nombre">Cliente</div>
                </div>
            </div>

            <!-- Pie de página -->
            <div class="footer">
                <p>Este comprobante es válido como recibo de pago</p>
                <p>Conserve este documento para futuras referencias</p>
                <p>Fecha de emisión: <?php echo date('d/m/Y H:i', strtotime($pago['fecha_pago'])); ?></p>
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