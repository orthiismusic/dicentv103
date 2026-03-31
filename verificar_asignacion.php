<?php
require_once 'config.php';
header('Content-Type: application/json; charset=utf-8');

if (!isset($_GET['numero_factura'])) {
    echo json_encode(['success' => false, 'message' => 'Número de factura no proporcionado.']);
    exit;
}

try {
    $numero = trim($_GET['numero_factura']);

    /* 1. ¿Existe la factura? */
    $stmt = $conn->prepare("
        SELECT f.id, f.numero_factura, f.monto, f.estado, f.mes_factura,
               c.numero_contrato, c.dia_cobro,
               cl.nombre AS cliente_nombre, cl.apellidos AS cliente_apellidos
        FROM facturas f
        JOIN contratos c ON f.contrato_id = c.id
        JOIN clientes cl ON c.cliente_id  = cl.id
        WHERE f.numero_factura = ?
    ");
    $stmt->execute([$numero]);
    $factura = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$factura) {
        echo json_encode(['success' => false, 'message' => "La factura \"$numero\" no existe en el sistema."]);
        exit;
    }

    /* 2. Bloquear facturas completamente pagadas */
    if ($factura['estado'] === 'pagada') {
        echo json_encode([
            'success' => false,
            'message' => "La factura {$factura['numero_factura']} ya está pagada en su totalidad y no puede asignarse."
        ]);
        exit;
    }

    /* 3. Verificar saldo pendiente (facturas incompletas con saldo 0) */
    $stmtSaldo = $conn->prepare("
        SELECT COALESCE(SUM(p.monto), 0) AS total_pagado
        FROM pagos p
        WHERE p.factura_id = ? AND p.estado = 'procesado'
    ");
    $stmtSaldo->execute([$factura['id']]);
    $totalPagado = (float)$stmtSaldo->fetchColumn();
    $saldoPend   = round((float)$factura['monto'] - $totalPagado, 2);

    if ($saldoPend <= 0) {
        echo json_encode([
            'success' => false,
            'message' => "La factura {$factura['numero_factura']} no tiene saldo pendiente de pago."
        ]);
        exit;
    }

    /* 4. ¿Está asignada actualmente? */
    $stmtAs = $conn->prepare("
        SELECT af.id, af.fecha_asignacion, co.nombre_completo AS cobrador_nombre
        FROM asignaciones_facturas af
        JOIN cobradores co ON af.cobrador_id = co.id
        WHERE af.factura_id = ? AND af.estado = 'activa'
    ");
    $stmtAs->execute([$factura['id']]);
    $asignacion = $stmtAs->fetch(PDO::FETCH_ASSOC);

    if ($asignacion) {
        echo json_encode([
            'success'   => true,
            'asignada'  => true,
            'factura'   => $factura,
            'asignacion'=> [
                'id'               => $asignacion['id'],
                'fecha_asignacion' => $asignacion['fecha_asignacion'],
                'cobrador_nombre'  => $asignacion['cobrador_nombre']
            ]
        ]);
    } else {
        echo json_encode([
            'success'  => true,
            'asignada' => false,
            'factura'  => $factura
        ]);
    }

} catch (PDOException $e) {
    error_log("Error en verificar_asignacion: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Error interno al verificar la factura.']);
}
?>