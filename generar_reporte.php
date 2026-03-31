<?php
require_once 'config.php';
require_once 'reporte_utils.php';
require_once 'procesar_reportes.php';

// Habilitar manejo de errores detallado
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Configurar cabeceras
header('Content-Type: application/json');

// Función para registro de debug
function debugLog($message) {
    $logFile = __DIR__ . '/debug_reporte.log';
    $formattedMessage = date('Y-m-d H:i:s') . ' - ' . $message . "\n";
    file_put_contents($logFile, $formattedMessage, FILE_APPEND);
}

try {
    // Verificar sesión
    verificarSesion();

    // Verificar método de la petición
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception('Método no permitido');
    }

    // Obtener y validar los datos de entrada
    $rawInput = file_get_contents('php://input');
    debugLog('Raw input: ' . $rawInput);
    
    if (empty($rawInput)) {
        throw new Exception('No se recibieron datos');
    }

    $datos = json_decode($rawInput, true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('Error decodificando JSON: ' . json_last_error_msg());
    }

    // Validar los campos requeridos
    $camposRequeridos = ['tipo', 'tipoReporte', 'fechaDesde', 'fechaHasta'];
    foreach ($camposRequeridos as $campo) {
        if (!isset($datos[$campo])) {
            throw new Exception("Campo requerido faltante: {$campo}");
        }
    }

    debugLog('Datos decodificados: ' . print_r($datos, true));

    // Validar formato de fechas
    if (!validarFechasReporte($datos['fechaDesde'], $datos['fechaHasta'])) {
        throw new Exception('Fechas inválidas o rango de fechas incorrecto');
    }

    // Registrar inicio de generación del reporte
    $reporte_id = registrarGeneracionReporte(
        $conn, 
        $_SESSION['usuario_id'],
        $datos['tipo'],
        $datos
    );

    // Tiempo de inicio para medir duración
    $tiempo_inicio = microtime(true);
    
    // Determinar tipo de salida
    $formatoSalida = $datos['formato'] ?? 'preview';

    // Procesar según tipo de reporte
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

    // Verificar resultado
    if (!is_array($resultado)) {
        throw new Exception('El resultado del procesamiento no es válido');
    }

    // Calcular tiempo de procesamiento
    $tiempo_total = microtime(true) - $tiempo_inicio;

    // Preparar respuesta según formato solicitado
    switch ($formatoSalida) {
        case 'excel':
            require_once 'vendor/autoload.php';
            $excel = generarExcel($resultado, $datos);
            $nombreArchivo = generarNombreArchivo($datos['tipo'], 'xlsx');
            
            header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
            header('Content-Disposition: attachment;filename="' . $nombreArchivo . '"');
            header('Cache-Control: max-age=0');
            
            $writer = \PhpOffice\PhpSpreadsheet\IOFactory::createWriter($excel, 'Xlsx');
            $writer->save('php://output');
            exit;

        case 'pdf':
            require_once 'tcpdf/tcpdf.php';
            $pdf = generarPDF($resultado, $datos);
            $nombreArchivo = generarNombreArchivo($datos['tipo'], 'pdf');
            
            header('Content-Type: application/pdf');
            header('Content-Disposition: attachment;filename="' . $nombreArchivo . '"');
            
            echo $pdf->Output($nombreArchivo, 'S');
            exit;

        case 'preview':
        default:
            // Asegurar que todas las claves necesarias existan
            $resultado = array_merge([
                'totalRegistros' => 0,
                'totalMontos' => 0,
                'distribucionPlanes' => [],
                'registros' => [],
                'graficos' => [],
                'estadisticas' => []
            ], $resultado);

            // Actualizar estado del reporte
            actualizarEstadoReporte(
                $conn,
                $reporte_id,
                'completado',
                $tiempo_total,
                count($resultado['registros'])
            );

            // Enviar respuesta JSON
            echo json_encode([
                'success' => true,
                'data' => $resultado
            ]);
            break;
    }

} catch (Exception $e) {
    debugLog('Error: ' . $e->getMessage());
    
    if (isset($reporte_id)) {
        actualizarEstadoReporte(
            $conn,
            $reporte_id,
            'error',
            null,
            null,
            $e->getMessage()
        );
    }
    
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage(),
        'errorDetails' => [
            'file' => $e->getFile(),
            'line' => $e->getLine()
        ]
    ]);
}

/**
 * Procesa reportes generales
 */


/**
 * Procesa reportes de facturación
 */


/**
 * Procesa reportes de personal
 */


/**
 * Procesa reportes de planes
 */


/**
 * Genera datos para gráficos según el tipo de reporte
 */
function generarDatosGraficos($registros, $tipoReporte) {
    $graficos = [];

    switch ($tipoReporte) {
        case 'contratos_estado':
            $graficos['distribucion'] = [
                'type' => 'pie',
                'data' => prepararDatosGraficoPie($registros, 'estado', 'total')
            ];
            break;

        case 'clientes_contratos':
        case 'contratos_dependientes':
            $graficos['tendencia'] = [
                'type' => 'line',
                'data' => prepararDatosGraficoLinea($registros, 'fecha_inicio', 'monto_total')
            ];
            break;
    }

    return $graficos;
}

/**
 * Prepara datos para gráfico de pastel
 */
function prepararDatosGraficoPie($datos, $campoEtiqueta, $campoValor) {
    $etiquetas = [];
    $valores = [];

    foreach ($datos as $registro) {
        $etiquetas[] = $registro[$campoEtiqueta];
        $valores[] = (float)$registro[$campoValor];
    }

    return [
        'labels' => $etiquetas,
        'datasets' => [[
            'data' => $valores,
            'backgroundColor' => [
                '#4e73df', '#1cc88a', '#36b9cc', '#f6c23e', '#e74a3b', '#858796'
            ]
        ]]
    ];
}

/**
 * Prepara datos para gráfico de líneas
 */
function prepararDatosGraficoLinea($datos, $campoX, $campoY) {
    // Agrupar por mes
    $datosPorMes = [];
    foreach ($datos as $registro) {
        $mes = date('Y-m', strtotime($registro[$campoX]));
        if (!isset($datosPorMes[$mes])) {
            $datosPorMes[$mes] = 0;
        }
        $datosPorMes[$mes] += (float)$registro[$campoY];
    }

    // Tomar solo los últimos 12 meses
    $datosPorMes = array_slice($datosPorMes, -12, 12, true);

    return [
        'labels' => array_keys($datosPorMes),
        'datasets' => [[
            'label' => 'Total por mes',
            'data' => array_values($datosPorMes),
            'borderColor' => '#4e73df',
            'fill' => false
        ]]
    ];
}

/**
 * Genera nombre de archivo para exportación
 */
function generarNombreArchivo($tipo, $extension) {
    $fecha = date('Ymd_His');
    return "reporte_{$tipo}_{$fecha}.{$extension}";
}

