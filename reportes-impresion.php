<?php
// Habilitar reporte de errores
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Función para log
function debugLog($message) {
    $logFile = __DIR__ . '/debug_reportes.log';
    $timestamp = date('Y-m-d H:i:s');
    file_put_contents($logFile, "[$timestamp] $message\n", FILE_APPEND);
}

try {
    require_once 'config.php';
    require_once 'reporte_utils.php';
    require_once 'procesar_reportes.php';

    // Verificar método
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception('Método no permitido');
    }

    // Obtener datos de entrada
    $rawInput = file_get_contents('php://input');
    debugLog("Raw input: $rawInput");

    if (empty($rawInput)) {
        throw new Exception('No se recibieron datos');
    }

    $datos = json_decode($rawInput, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('Error decodificando JSON: ' . json_last_error_msg());
    }

    debugLog("Datos decodificados: " . print_r($datos, true));

    // Verificar campos requeridos
    $camposRequeridos = ['tipo', 'tipoReporte', 'fechaDesde', 'fechaHasta'];
    foreach ($camposRequeridos as $campo) {
        if (!isset($datos[$campo])) {
            throw new Exception("Campo requerido faltante: $campo");
        }
    }

    // Verificar conexión a la base de datos
    if (!isset($conn) || !$conn) {
        throw new Exception('Error de conexión a la base de datos');
    }

    // Obtener configuración del sistema
    $stmtConfig = $conn->prepare("SELECT * FROM configuracion_sistema WHERE id = 1");
    $stmtConfig->execute();
    $config = $stmtConfig->fetch(PDO::FETCH_ASSOC);

    // Procesar reporte según tipo
    switch ($datos['tipo']) {
        case 'General':
            $resultado = procesarReporteGeneral($conn, $datos);
            break;
        case 'Facturacion':
            $resultado = procesarReporteFacturacion($conn, $datos);
            break;
        case 'Personal':
            $resultado = procesarReportePersonal($conn, $datos);
            break;
        case 'Planes':
            $resultado = procesarReportePlanes($conn, $datos);
            break;
        default:
            throw new Exception('Tipo de reporte no válido');
    }

    // Calcular totales
    $total_registros = count($resultado['registros']);
    $total_monto = $resultado['totalMontos'] ?? 0;

    // Comenzar salida HTML
    header('Content-Type: text/html; charset=UTF-8');
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title><?php echo obtenerTituloReporte($datos['tipo'], $datos['tipoReporte']); ?></title>
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
        .company-info {
            font-size: 12px;
            line-height: 1.2;
        }
        .report-title {
            text-align: center;
            font-size: 16px;
            font-weight: bold;
            margin: 0.2in 0;
        }
        .filter-info {
            margin: 0.2in 0;
            padding: 0.1in;
            border: 1px solid #000;
            font-size: 12px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 0.2in;
            font-size: 10px;
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
            font-size: 12px;
            font-weight: bold;
        }
        .page-number {
            position: absolute;
            bottom: 0.3in;
            right: 0.5in;
            font-size: 10px;
        }
        @media print {
            .no-print { 
                display: none; 
            }
        }
        .btn {
            padding: 8px 16px;
            margin: 10px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            color: white;
            font-weight: bold;
        }
        .btn-primary {
            background-color: #4e73df;
        }
        .btn-secondary {
            background-color: #858796;
        }
    </style>
</head>
<body>
    <!-- Botones de control -->
    <div class="no-print" style="padding: 20px;">
        <button onclick="window.print()" class="btn btn-primary">
            <i class="fas fa-print"></i> Imprimir
        </button>
        <button onclick="window.close()" class="btn btn-secondary">
            <i class="fas fa-times"></i> Cerrar
        </button>
    </div>

    <?php 
    // Calcular número de registros por página
    $registros_por_pagina = 20;
    $total_paginas = ceil($total_registros / $registros_por_pagina);
    
    // Iterar sobre cada página
    for ($pagina = 0; $pagina < $total_paginas; $pagina++): 
        $inicio = $pagina * $registros_por_pagina;
        $registros_pagina = array_slice($resultado['registros'], $inicio, $registros_por_pagina);
    ?>
    <div class="pagina">
        <!-- Encabezado -->
        <div class="header">
            <?php if (!empty($config['logo_url'])): ?>
                <img src="<?php echo htmlspecialchars($config['logo_url']); ?>" alt="Logo" class="logo">
            <?php endif; ?>
            
            <div class="header-text">
                <div class="company-name"><?php echo htmlspecialchars($config['nombre_empresa']); ?></div>
                <div class="company-info">
                    <?php echo htmlspecialchars($config['direccion']); ?><br>
                    RIF: <?php echo htmlspecialchars($config['rif']); ?><br>
                    Tel: <?php echo htmlspecialchars($config['telefono']); ?>
                </div>
            </div>
        </div>

        <!-- Título del reporte -->
        <div class="report-title">
            <?php echo obtenerTituloReporte($datos['tipo'], $datos['tipoReporte']); ?>
        </div>

        <!-- Información de filtros -->
        <div class="filter-info">
            <div>Período: <?php echo formatearFecha($datos['fechaDesde']); ?> al <?php echo formatearFecha($datos['fechaHasta']); ?></div>
            <?php if (!empty($datos['estadoFactura'])): ?>
                <div>Estado: <?php echo ucfirst($datos['estadoFactura']); ?></div>
            <?php endif; ?>
            <?php if (!empty($datos['planId'])): ?>
                <div>Plan: <?php echo obtenerNombrePlan($conn, $datos['planId']); ?></div>
            <?php endif; ?>
            <div>Total Registros: <?php echo number_format($total_registros); ?></div>
            <?php if ($total_monto > 0): ?>
                <div>Monto Total: RD$<?php echo number_format($total_monto, 2); ?></div>
            <?php endif; ?>
        </div>

        <!-- Tabla de datos -->
        <table>
            <thead>
                <tr>
                    <?php 
                    $encabezados = obtenerEncabezadosReporte($datos['tipo'], $datos['tipoReporte']);
                    foreach ($encabezados as $encabezado): 
                    ?>
                        <th><?php echo htmlspecialchars($encabezado); ?></th>
                    <?php endforeach; ?>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($registros_pagina as $registro): ?>
                    <tr>
                        <?php foreach ($registro as $key => $valor): ?>
                            <td>
                                <?php
                                if (is_numeric($valor) && strpos($key, 'monto') !== false) {
                                    echo 'RD$' . number_format($valor, 2);
                                } elseif (strpos($key, 'fecha') !== false) {
                                    echo formatearFecha($valor);
                                } else {
                                    echo htmlspecialchars($valor);
                                }
                                ?>
                            </td>
                        <?php endforeach; ?>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <!-- Totales de página -->
        <div class="totales">
            <?php if (isset($registro['monto']) || isset($registro['monto_total'])): ?>
                <div>Subtotal Página: RD$<?php 
                    $subtotal = 0;
                    foreach ($registros_pagina as $registro) {
                        $subtotal += $registro['monto'] ?? $registro['monto_total'] ?? 0;
                    }
                    echo number_format($subtotal, 2);
                ?></div>
            <?php endif; ?>

            <?php if ($pagina === $total_paginas - 1 && $total_monto > 0): ?>
                <div style="margin-top: 0.1in;">Total General: RD$<?php echo number_format($total_monto, 2); ?></div>
            <?php endif; ?>
        </div>

        <!-- Número de página -->
        <div class="page-number">
            Página <?php echo ($pagina + 1); ?> de <?php echo $total_paginas; ?>
        </div>
    </div>
    <?php endfor; ?>

</body>
</html>
<?php
} catch (Exception $e) {
    debugLog("Error: " . $e->getMessage() . "\n" . $e->getTraceAsString());
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode([
        'error' => true,
        'message' => $e->getMessage(),
        'trace' => $e->getTraceAsString()
    ]);
    exit;
}
?>