<?php
require_once 'config.php';
verificarSesion();

// Verificar que sea un administrador
if ($_SESSION['rol'] !== 'admin') {
    echo json_encode([
        'success' => false,
        'message' => 'No tiene permisos para realizar esta acción'
    ]);
    exit;
}

header('Content-Type: application/json');

try {
    $data = json_decode(file_get_contents('php://input'), true);
    $pago_id = isset($data['id']) ? (int)$data['id'] : 0;
    $password = isset($data['password']) ? $data['password'] : '';

    if (!$pago_id) {
        throw new Exception('ID de pago no válido');
    }

    // Obtener información del pago
    $stmt = $conn->prepare("
        SELECT p.*, f.id as factura_id, f.monto as monto_factura, f.estado as estado_factura,
               u.password as user_password
        FROM pagos p
        JOIN facturas f ON p.factura_id = f.id
        JOIN usuarios u ON u.id = ?
        WHERE p.id = ? AND p.estado = 'procesado'
    ");
    $stmt->execute([$_SESSION['usuario_id'], $pago_id]);
    $pago = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$pago) {
        throw new Exception('Pago no encontrado o ya anulado');
    }

    // Verificar tiempo transcurrido
    $fecha_pago = new DateTime($pago['fecha_pago']);
    $ahora = new DateTime();
    $diferencia = $fecha_pago->diff($ahora);
    $horas_transcurridas = ($diferencia->days * 24) + $diferencia->h;

    // Si han pasado más de 24 horas, verificar contraseña
    if ($horas_transcurridas > 24) {
        if (!password_verify($password, $pago['user_password'])) {
            throw new Exception('Contraseña incorrecta');
        }
    }

    $conn->beginTransaction();

    // Anular el pago
    $stmt = $conn->prepare("
        UPDATE pagos 
        SET estado = 'anulado' 
        WHERE id = ?
    ");
    $stmt->execute([$pago_id]);

    // Recalcular total pagado de la factura
    $stmt = $conn->prepare("
        SELECT COALESCE(SUM(monto), 0) as total_pagado,
               COUNT(*) as total_pagos
        FROM pagos 
        WHERE factura_id = ? 
        AND estado = 'procesado'
    ");
    $stmt->execute([$pago['factura_id']]);
    $resultado = $stmt->fetch();
    $total_pagado = $resultado['total_pagado'];
    $total_pagos = $resultado['total_pagos'];

    // Determinar nuevo estado de la factura
    $nuevo_estado = 'pendiente';
    if ($total_pagado > 0) {
        $nuevo_estado = $total_pagado >= $pago['monto_factura'] ? 'pagada' : 'incompleta';
    }

    // Actualizar estado de la factura
    $stmt = $conn->prepare("
        UPDATE facturas 
        SET estado = ?,
            monto_pendiente = GREATEST(monto - ?, 0)
        WHERE id = ?
    ");
    $stmt->execute([$nuevo_estado, $total_pagado, $pago['factura_id']]);

    // Registrar en auditoría
    $stmt = $conn->prepare("
        INSERT INTO reportes_auditoria (
            usuario_id, accion, detalles, ip_address, fecha_hora
        ) VALUES (?, 'anulacion_pago', ?, ?, NOW())
    ");
    $detalles = json_encode([
        'pago_id' => $pago_id,
        'factura_id' => $pago['factura_id'],
        'monto' => $pago['monto'],
        'estado_anterior' => $pago['estado_factura'],
        'nuevo_estado' => $nuevo_estado
    ]);
    $stmt->execute([
        $_SESSION['usuario_id'],
        $detalles,
        $_SERVER['REMOTE_ADDR']
    ]);

    $conn->commit();

    echo json_encode([
        'success' => true,
        'message' => 'Pago anulado correctamente'
    ]);

} catch (Exception $e) {
    if ($conn->inTransaction()) {
        $conn->rollBack();
    }
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
}
?>