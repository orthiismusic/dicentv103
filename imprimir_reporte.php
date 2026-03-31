<?php
require_once 'config.php';
require_once 'reporte_utils.php';

error_reporting(E_ALL);
ini_set('display_errors', 1);

// Depuración inicial
echo "<!-- Iniciando proceso de reporte -->\n";
echo "<!-- GET params: " . print_r($_GET, true) . " -->\n";

if (!isset($_GET['tipo']) || !isset($_GET['tipoReporte']) || !isset($_GET['fechaDesde']) || !isset($_GET['fechaHasta'])) {
    die('Parámetros incompletos: ' . print_r($_GET, true));
}

try {
    // Depurar parámetros recibidos
    $datos = [
        'tipo' => $_GET['tipo'],
        'tipoReporte' => $_GET['tipoReporte'],
        'fechaDesde' => $_GET['fechaDesde'],
        'fechaHasta' => $_GET['fechaHasta']
    ];
    
    echo "<!-- Datos a procesar: " . print_r($datos, true) . " -->\n";
    
    // Intentar obtener los datos
    $resultado = obtenerDatosReporte($conn, $datos);
    
    // Depurar resultado
    echo "<!-- Resultado obtenido: " . print_r($resultado, true) . " -->\n";
    
    if (empty($resultado) || !isset($resultado['registros']) || empty($resultado['registros'])) {
        die('No se encontraron datos para el reporte con los siguientes parámetros: ' . print_r($datos, true));
    }
    
    // Verificar estructura del resultado
    if (!isset($resultado['totalRegistros']) || !isset($resultado['totalMontos']) || !isset($resultado['distribucionPlanes'])) {
        die('El resultado no tiene la estructura esperada: ' . print_r($resultado, true));
    }
    
    // Obtener configuración del sistema
    $stmtConfig = $conn->prepare("SELECT * FROM configuracion_sistema WHERE id = 1");
    $stmtConfig->execute();
    $config = $stmtConfig->fetch();
    
    if (!$config) {
        die('No se pudo obtener la configuración del sistema');
    }

} catch (Exception $e) {
    die('Error al procesar el reporte: ' . $e->getMessage() . "\n" . $e->getTraceAsString());
}

// Función para formatear valores monetarios
function formatearMoneda($valor) {
    return 'RD$' . number_format($valor, 2);
}

?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Reporte - <?php echo $datos['tipo']; ?></title>
    <style>
        @page {
            size: 8.5in 11in;
            margin: 0;
        }
        body {
            margin: 0;
            padding: 0;
            font-family: Arial, sans-serif;
        }
        .pagina {
            width: 8.5in;
            height: 11in;
            padding: 0.5in;
            box-sizing: border-box;
            position: relative;
            page-break-after: always;
        }
        .header {
            text-align: left;
            margin-bottom: 0.3in;
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
            font-size: 14px;
            font-weight: bold;
            margin-bottom: 0.05in;
            text-transform: uppercase;
            border-bottom: 1px solid #000;
            padding-bottom: 0.05in;
        }
        .report-info {
            margin: 0.2in 0;
            padding: 0.1in;
            border: 1px solid #000;
            font-size: 13px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 0.2in;
            font-size: 13px;
        }
        th, td {
            border: 1px solid #000;
            padding: 0.05in;
            text-align: left;
        }
        th {
            background-color: #f4f4f4;
        }
        .totales {
            margin-top: 0.2in;
            text-align: right;
            font-size: 13px;
            font-weight: bold;
        }
        .pagina-numero {
            position: absolute;
            bottom: 0.3in;
            right: 0.5in;
            font-size: 12px;
        }
        @media print {
            .no-print { display: none; }
        }
    </style>
</head>
<body>
    <div class="no-print" style="padding: 20px;">
        <button onclick="window.print()" style="padding: 8px 14px; background: #0066cc; color: white; border: none; border-radius: 4px; cursor: pointer;">
            <i class="fas fa-print"></i> Imprimir
        </button>
        <button onclick="window.close()" style="padding: 8px 14px; background: #6c757d; color: white; border: none; border-radius: 4px; cursor: pointer; margin-left: 10px;">
            <i class="fas fa-times"></i> Cerrar
        </button>
    </div>

    <?php
    $registros_por_pagina = 20;
    $total_registros = count($resultado['registros']);
    $total_paginas = ceil($total_registros / $registros_por_pagina);
    
    for ($pagina = 0; $pagina < $total_paginas; $pagina++): 
        $inicio = $pagina * $registros_por_pagina;
        $registros_pagina = array_slice($resultado['registros'], $inicio, $registros_por_pagina);
    ?>
    <div class="pagina">
        <?php if ($config['logo_url']): ?>
            <div class="header">
                <img src="<?php echo htmlspecialchars($config['logo_url']); ?>" alt="Logo" class="logo">
            </div>
        <?php endif; ?>
        
        <div style="text-align: center; margin-bottom: 0.1in;">
            <h3 style="margin: 0;">Reporte: <?php echo $datos['tipo']; ?></h3>
            <p style="margin: 0.1in 0;">Período: <?php echo date('d/m/Y', strtotime($datos['fechaDesde'])); ?> - <?php echo date('d/m/Y', strtotime($datos['fechaHasta'])); ?></p>
        </div>

        <div class="report-info">
            <div><strong>Tipo de Reporte:</strong> <?php echo str_replace('_', ' ', ucwords($datos['tipoReporte'])); ?></div>
            <div><strong>Total Registros:</strong> <?php echo $resultado['totalRegistros']; ?></div>
            <div><strong>Monto Total:</strong> <?php echo formatearMoneda($resultado['totalMontos']); ?></div>
        </div>

        <?php if ($pagina === 0): ?>
        <div class="distribucion-planes">
            <h4>Distribución por Plan</h4>
            <table>
                <thead>
                    <tr>
                        <th>Plan</th>
                        <th>Cantidad</th>
                        <th>Total</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($resultado['distribucionPlanes'] as $plan): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($plan['nombre']); ?></td>
                        <td style="text-align: center;"><?php echo $plan['cantidad']; ?></td>
                        <td style="text-align: right;"><?php echo formatearMoneda($plan['total']); ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>

        <div class="registros">
            <h4>Registros Detallados</h4>
            <table>
                <thead>
                    <tr>
                        <?php
                        if (!empty($registros_pagina)) {
                            foreach (array_keys($registros_pagina[0]) as $columna) {
                                echo '<th>' . ucwords(str_replace('_', ' ', $columna)) . '</th>';
                            }
                        }
                        ?>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($registros_pagina as $registro): ?>
                    <tr>
                        <?php foreach ($registro as $valor): ?>
                        <td><?php 
                            if (is_numeric($valor) && strpos(strtolower(key($registro)), 'monto') !== false) {
                                echo formatearMoneda($valor);
                            } else {
                                echo htmlspecialchars($valor);
                            }
                        ?></td>
                        <?php endforeach; ?>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <div class="totales">
            <div>Subtotal Página: <?php 
                $subtotal_pagina = 0;
                foreach ($registros_pagina as $registro) {
                    foreach ($registro as $key => $valor) {
                        if (is_numeric($valor) && strpos(strtolower($key), 'monto') !== false) {
                            $subtotal_pagina += $valor;
                        }
                    }
                }
                echo formatearMoneda($subtotal_pagina);
            ?></div>
            <?php if ($pagina === $total_paginas - 1): ?>
                <div style="margin-top: 0.1in;">Total General: <?php echo formatearMoneda($resultado['totalMontos']); ?></div>
            <?php endif; ?>
        </div>

        <div class="pagina-numero">
            Página <?php echo ($pagina + 1); ?> de <?php echo $total_paginas; ?>
        </div>
    </div>
    <?php endfor; ?>
</body>
</html>