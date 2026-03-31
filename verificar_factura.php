<?php
require_once 'config.php';

// Verificar si se proporcionó el número de factura
if (!isset($_GET['numero_factura'])) {
    echo json_encode([
        'success' => false,
        'message' => 'Número de factura no proporcionado'
    ]);
    exit;
}

try {
    $numero_factura = $_GET['numero_factura'];

    // Consulta para obtener los datos de la factura
    $sql = "
    SELECT 
        f.id,
        f.numero_factura,
        f.monto,
        f.estado,
        f.mes_factura,
        c.numero_contrato,
        cl.nombre as cliente_nombre,
        cl.apellidos as cliente_apellidos,
        c.dia_cobro,
        (
            SELECT COUNT(*)
            FROM asignaciones_facturas af 
            WHERE af.factura_id = f.id 
            AND af.estado = 'activa'
        ) as esta_asignada
    FROM facturas f
    JOIN contratos c ON f.contrato_id = c.id
    JOIN clientes cl ON c.cliente_id = cl.id
    WHERE f.numero_factura = ?
";

    $stmt = $conn->prepare($sql);
    $stmt->execute([$numero_factura]);
    $factura = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$factura) {
        echo json_encode([
            'success' => false,
            'message' => 'Factura no encontrada'
        ]);
        exit;
    }

    // Devolver los datos de la factura
    echo json_encode([
    'success' => true,
    'factura' => [
        'id' => $factura['id'],
        'numero_factura' => $factura['numero_factura'],
        'numero_contrato' => $factura['numero_contrato'],
        'cliente_nombre' => $factura['cliente_nombre'],
        'cliente_apellidos' => $factura['cliente_apellidos'],
        'mes_factura' => $factura['mes_factura'],
        'monto' => $factura['monto'],
        'estado' => $factura['estado'],
        'dia_cobro' => $factura['dia_cobro'],
        'esta_asignada' => $factura['esta_asignada']
    ]
]);

} catch (PDOException $e) {
    // Log del error para debugging
    error_log("Error en verificar_factura.php: " . $e->getMessage());
    
    echo json_encode([
        'success' => false,
        'message' => 'Error al verificar la factura'
    ]);
}
?>