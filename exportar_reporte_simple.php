<?php
require_once 'config.php';
require_once 'reporte_utils.php';
require_once 'vendor/autoload.php'; // Para PhpSpreadsheet

use PhpOffice\PhpSpreadsheet\Spreadsheet;
use PhpOffice\PhpSpreadsheet\Writer\Xlsx;
use PhpOffice\PhpSpreadsheet\Style\Border;
use PhpOffice\PhpSpreadsheet\Style\Fill;

// Verificar sesión y parámetros
verificarSesion();

if (!isset($_POST['tipo']) || !isset($_POST['formato'])) {
    die('Parámetros inválidos');
}

$tipo = $_POST['tipo'];
$formato = $_POST['formato'];
$tipoReporte = $_POST['tipoReporte'];
$fechaDesde = $_POST['fechaDesde'];
$fechaHasta = $_POST['fechaHasta'];

try {
    // Registrar inicio de exportación
    registrarAuditoria($conn, $_SESSION['usuario_id'], 'exportar_reporte', [
        'tipo' => $tipo,
        'formato' => $formato,
        'parametros' => $_POST
    ]);

    // Obtener datos según el tipo de reporte
    $datos = obtenerDatosReporte($conn, $tipo, $tipoReporte, $fechaDesde, $fechaHasta);
    
    if (!$datos) {
        throw new Exception('No se encontraron datos para exportar');
    }

    // Exportar según formato seleccionado
    switch ($formato) {
        case 'xlsx':
            exportarExcel($datos, $tipo);
            break;
        case 'csv':
            exportarCSV($datos, $tipo);
            break;
        case 'txt':
            exportarTXT($datos, $tipo);
            break;
        default:
            throw new Exception('Formato no soportado');
    }

} catch (Exception $e) {
    // Registrar error
    registrarAuditoria($conn, $_SESSION['usuario_id'], 'error_exportacion', [
        'mensaje' => $e->getMessage()
    ]);
    die('Error: ' . $e->getMessage());
}

function obtenerDatosReporte($conn, $tipo, $tipoReporte, $fechaDesde, $fechaHasta) {
    $sql = '';
    $params = [$fechaDesde, $fechaHasta];

    switch ($tipo) {
        case 'General':
            switch ($tipoReporte) {
                case 'clientes_contratos':
                    $sql = "
                        SELECT 
                            c.numero_contrato,
                            cl.nombre,
                            cl.apellidos,
                            p.nombre as plan,
                            c.fecha_inicio,
                            c.monto_total,
                            c.dia_cobro,
                            c.estado
                        FROM contratos c
                        JOIN clientes cl ON c.cliente_id = cl.id
                        JOIN planes p ON c.plan_id = p.id
                        WHERE c.fecha_inicio BETWEEN ? AND ?
                    ";
                    break;
                // Agregar más casos según sea necesario
            }
            break;
        // Agregar más tipos de reportes
    }

    if (!$sql) {
        return false;
    }

    $stmt = $conn->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function exportarExcel($datos, $tipo) {
    $spreadsheet = new Spreadsheet();
    $sheet = $spreadsheet->getActiveSheet();
    
    // Configurar encabezados
    $columnas = array_keys($datos[0]);
    $col = 'A';
    foreach ($columnas as $columna) {
        $sheet->setCellValue($col . '1', ucwords(str_replace('_', ' ', $columna)));
        $col++;
    }

    // Estilo para encabezados
    $headerStyle = [
        'font' => ['bold' => true],
        'fill' => [
            'fillType' => Fill::FILL_SOLID,
            'startColor' => ['rgb' => '2563EB']
        ],
        'font' => [
            'color' => ['rgb' => 'FFFFFF']
        ]
    ];
    $sheet->getStyle('A1:' . $col . '1')->applyFromArray($headerStyle);

    // Agregar datos
    $row = 2;
    foreach ($datos as $fila) {
        $col = 'A';
        foreach ($fila as $valor) {
            $sheet->setCellValue($col . $row, $valor);
            $col++;
        }
        $row++;
    }

    // Auto-ajustar columnas
    foreach (range('A', $col) as $col) {
        $sheet->getColumnDimension($col)->setAutoSize(true);
    }

    // Configurar headers HTTP
    $fileName = generarNombreArchivo($tipo, 'xlsx');
    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="' . $fileName . '"');
    header('Cache-Control: max-age=0');

    // Guardar archivo
    $writer = new Xlsx($spreadsheet);
    $writer->save('php://output');
    exit;
}

function exportarCSV($datos, $tipo) {
    $fileName = generarNombreArchivo($tipo, 'csv');
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment;filename="' . $fileName . '"');
    
    $output = fopen('php://output', 'w');
    
    // UTF-8 BOM
    fprintf($output, chr(0xEF).chr(0xBB).chr(0xBF));
    
    // Encabezados
    fputcsv($output, array_keys($datos[0]));
    
    // Datos
    foreach ($datos as $fila) {
        fputcsv($output, $fila);
    }
    
    fclose($output);
    exit;
}

function exportarTXT($datos, $tipo) {
    $fileName = generarNombreArchivo($tipo, 'txt');
    header('Content-Type: text/plain');
    header('Content-Disposition: attachment;filename="' . $fileName . '"');
    
    // Encabezados
    echo implode('|', array_keys($datos[0])) . "\n";
    
    // Datos
    foreach ($datos as $fila) {
        echo implode('|', $fila) . "\n";
    }
    
    exit;
}
?>