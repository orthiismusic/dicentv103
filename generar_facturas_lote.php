<?php
require_once 'config.php';

try {
    $data = json_decode(file_get_contents('php://input'), true);
    $facturas = $data['facturas'];
    $contrato_id = $data['contrato_id'];
    
    $conn->beginTransaction();
    
    foreach ($facturas as $factura) {
        // Generar n煤mero de factura
        $stmt = $conn->query("
            SELECT CAST(numero_factura AS UNSIGNED) as num 
            FROM facturas 
            ORDER BY num DESC 
            LIMIT 1
        ");
        $ultimo = $stmt->fetch();
        $numeroFactura = str_pad(($ultimo['num'] ?? 0) + 1, 7, '0', STR_PAD_LEFT);
        
        // Calcular fecha de vencimiento
        $fecha_emision = new DateTime($factura['fecha_emision']);
        $fecha_vencimiento = clone $fecha_emision;
        $mes_emision = (int)$fecha_emision->format('m');
        $year_emision = (int)$fecha_emision->format('Y');
        
        // Primero sumamos un mes
        $fecha_vencimiento->modify('+1 month');
        
        // Verificamos si la fecha de emisión es enero y el día es 30 o 31
        if ($mes_emision == 1 && (int)$fecha_emision->format('d') >= 30) {
            // Ajustar específicamente para febrero
            $esBisiesto = date('L', mktime(0, 0, 0, 1, 1, $year_emision)) == 1;
            $ultimoDiaFebrero = $esBisiesto ? 29 : 28;
            // Mantenemos el mismo año de la fecha de emisión
            $fecha_vencimiento->setDate($year_emision, 2, $ultimoDiaFebrero);
        } else {
            // Para todos los demás casos, simplemente restamos un día
            $fecha_vencimiento->modify('-1 day');
        }
        
        // Obtener informaci贸n de dependientes
        $stmt = $conn->prepare("
            SELECT 
                COUNT(*) as total_dependientes,
                SUM(CASE WHEN p.id = 5 THEN 1 ELSE 0 END) as total_geriatricos
            FROM dependientes d
            JOIN planes p ON d.plan_id = p.id
            WHERE d.contrato_id = ? 
            AND d.estado = 'activo'
        ");
        $stmt->execute([$contrato_id]);
        $deps = $stmt->fetch();
        
        // Insertar factura
        $stmt = $conn->prepare("
            INSERT INTO facturas (
                numero_factura, cuota, mes_factura, contrato_id,
                fecha_emision, fecha_vencimiento, monto,
                cantidad_dependientes, tiene_geriatrico, estado
            ) VALUES (
                ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, 'pendiente'
            )
        ");
        
        $stmt->execute([
            $numeroFactura,
            $factura['cuota'],
            $factura['mes'],
            $contrato_id,
            $fecha_emision->format('Y-m-d'),
            $fecha_vencimiento->format('Y-m-d'),
            $factura['monto'],
            $deps['total_dependientes'],
            $deps['total_geriatricos'] > 0 ? 1 : 0
        ]);
    }
    
    $conn->commit();
    echo json_encode(['success' => true]);
    
} catch(PDOException $e) {
    if ($conn->inTransaction()) {
        $conn->rollBack();
    }
    echo json_encode(['error' => 'Error al generar facturas: ' . $e->getMessage()]);
}
?>