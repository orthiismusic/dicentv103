<?php
require_once 'config.php';

try {
    $data = json_decode(file_get_contents('php://input'), true);
    $numero_contrato = $data['contrato_id'];
    $cantidad = intval($data['cantidad']);
    
    if ($cantidad > 12) {
        echo json_encode(['error' => 'La cantidad máxima de facturas es 12']);
        exit;
    }
    
    // Obtener información del contrato y cliente
    $stmt = $conn->prepare("
        SELECT c.*, cl.nombre, cl.apellidos 
        FROM contratos c
        JOIN clientes cl ON c.cliente_id = cl.id
        WHERE c.numero_contrato = ? AND c.estado = 'activo'
    ");
    $stmt->execute([$numero_contrato]);
    $contrato = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$contrato) {
        echo json_encode(['error' => 'Contrato no encontrado o inactivo']);
        exit;
    }

    // Obtener la última factura del contrato
    $stmt = $conn->prepare("
        SELECT f.cuota, f.fecha_emision, f.mes_factura
        FROM facturas f
        WHERE f.contrato_id = ?
        ORDER BY STR_TO_DATE(f.mes_factura, '%m/%Y') DESC, f.cuota DESC
        LIMIT 1
    ");
    $stmt->execute([$contrato['id']]);
    $ultimaFactura = $stmt->fetch(PDO::FETCH_ASSOC);

    // Determinar fecha inicial para las nuevas facturas
    if ($ultimaFactura) {
        // Si hay factura anterior, usar el siguiente mes
        list($mes, $año) = explode('/', $ultimaFactura['mes_factura']);
        $fecha = new DateTime("$año-$mes-01");
        $fecha->modify('first day of next month');
    } else {
        // Si es contrato nuevo, usar el mes siguiente a la fecha de inicio
        $fecha = new DateTime($contrato['fecha_inicio']);
        $fecha->modify('first day of next month');
    }

    // Verificar si ya existen facturas para los meses siguientes
    $facturas = [];
    $ultimaCuota = $ultimaFactura ? $ultimaFactura['cuota'] : 0;
    $fechaTemp = clone $fecha;
    
    $facturasGeneradas = 0;
    while ($facturasGeneradas < $cantidad) {
        $mesActual = $fechaTemp->format('m/Y');
        
        // Verificar si ya existe factura para este mes
        $stmt = $conn->prepare("
            SELECT COUNT(*) 
            FROM facturas 
            WHERE contrato_id = ? AND mes_factura = ?
        ");
        $stmt->execute([$contrato['id'], $mesActual]);
        $existe = $stmt->fetchColumn();

        if (!$existe) {
            // Si no existe factura para este mes, agregarla a la lista
            $fechaEmision = ajustarFechaEmision(clone $fechaTemp, $contrato['dia_cobro']);
            
            // Calcular fecha de vencimiento
            $fechaVencimiento = clone $fechaEmision;
            $mes_emision = (int)$fechaEmision->format('m');
            $year_emision = (int)$fechaEmision->format('Y');
            
            $fechaVencimiento->modify('+1 month');
            
            if ($mes_emision == 1 && (int)$fechaEmision->format('d') >= 30) {
                $esBisiesto = date('L', mktime(0, 0, 0, 1, 1, $year_emision)) == 1;
                $ultimoDiaFebrero = $esBisiesto ? 29 : 28;
                $fechaVencimiento->setDate($year_emision, 2, $ultimoDiaFebrero);
            } else {
                $fechaVencimiento->modify('-1 day');
            }

            $facturas[] = [
                'contrato' => $contrato['numero_contrato'],
                'mes' => $mesActual,
                'monto' => $contrato['monto_mensual'],
                'cuota' => $ultimaCuota + $facturasGeneradas + 1,
                'fecha_emision' => $fechaEmision->format('Y-m-d'),
                'fecha_vencimiento' => $fechaVencimiento->format('Y-m-d')
            ];
            
            $facturasGeneradas++;
        }

        $fechaTemp->modify('first day of next month');
    }

    if (empty($facturas)) {
        echo json_encode(['error' => 'No hay meses disponibles para generar nuevas facturas']);
        exit;
    }

    echo json_encode([
        'success' => true,
        'facturas' => $facturas,
        'contrato_id' => $contrato['id']
    ]);
    
} catch(PDOException $e) {
    error_log("Error en pre_generar_facturas.php: " . $e->getMessage());
    echo json_encode(['error' => 'Error de base de datos: ' . $e->getMessage()]);
} catch(Exception $e) {
    error_log("Error general en pre_generar_facturas.php: " . $e->getMessage());
    echo json_encode(['error' => 'Error general: ' . $e->getMessage()]);
}

function ajustarFechaEmision($fecha, $dia_cobro) {
    $year = (int)$fecha->format('Y');
    $month = (int)$fecha->format('m');
    
    // Crear una nueva fecha con el primer día del mes para evitar problemas
    $fechaAjustada = new DateTime("$year-$month-01");
    
    // Obtener el último día del mes
    $ultimoDiaMes = (int)$fechaAjustada->format('t');
    
    // Determinar el día ajustado según el mes
    $diaAjustado = $dia_cobro;
    
    // Ajustes especiales por mes
    if ($month == 2) { // Febrero
        if ($dia_cobro >= 29) {
            $esBisiesto = date('L', mktime(0, 0, 0, 1, 1, $year)) == 1;
            $diaAjustado = $esBisiesto ? 29 : 28;
        }
    } elseif ($ultimoDiaMes == 30 && $dia_cobro > 30) {
        $diaAjustado = 30;
    } elseif ($dia_cobro > $ultimoDiaMes) {
        $diaAjustado = $ultimoDiaMes;
    }
    
    // Establecer el día ajustado
    $fechaAjustada->setDate($year, $month, $diaAjustado);
    
    return $fechaAjustada;
}
?>