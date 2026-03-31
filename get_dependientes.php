<?php
require_once 'config.php';
verificarSesion();

header('Content-Type: application/json');

try {
    if (!isset($_GET['cliente_id']) && !isset($_GET['contrato_id'])) {
        throw new Exception('ID de cliente o contrato no proporcionado');
    }

    if (isset($_GET['cliente_id'])) {
        // Primero verificar si el cliente tiene contratos y cu芍ntos
        $stmt = $conn->prepare("
            SELECT id, numero_contrato 
            FROM contratos 
            WHERE cliente_id = ? 
            AND estado = 'activo'
            ORDER BY fecha_inicio DESC
        ");
        $stmt->execute([$_GET['cliente_id']]);
        $contratos = $stmt->fetchAll();

        if (empty($contratos)) {
            echo json_encode([
                'success' => false,
                'message' => 'El cliente no tiene contratos activos'
            ]);
            exit;
        }

        if (count($contratos) == 1) {
            // Si solo hay un contrato, usar ese ID
            $contrato_id = $contratos[0]['id'];
            $contrato_actual = $contratos[0];
        } else {
            // Si hay m迆ltiples contratos, devolver la lista de contratos
            echo json_encode([
                'success' => true,
                'multiple_contratos' => true,
                'contratos' => $contratos
            ]);
            exit;
        }
    } else {
        $contrato_id = $_GET['contrato_id'];
        
        // Obtener informaci車n del contrato
        $stmt = $conn->prepare("SELECT * FROM contratos WHERE id = ?");
        $stmt->execute([$contrato_id]);
        $contrato_actual = $stmt->fetch();
    }

    // Obtener los dependientes del contrato
        $stmt = $conn->prepare("
            SELECT d.*,
                   p.nombre as plan_nombre,
                   p.precio_base,
                   c.numero_contrato,
                   c.cliente_id
            FROM dependientes d
            JOIN planes p ON d.plan_id = p.id
            JOIN contratos c ON d.contrato_id = c.id
            WHERE d.contrato_id = ?
            AND d.estado = 'activo'
            ORDER BY d.nombre, d.apellidos
        ");

    $stmt->execute([$contrato_id]);
    $dependientes = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Formatear fechas y datos adicionales
    foreach ($dependientes as &$dependiente) {
        $dependiente['fecha_nacimiento'] = date('Y-m-d', strtotime($dependiente['fecha_nacimiento']));
        
        // Calcular edad
        $fecha_nacimiento = new DateTime($dependiente['fecha_nacimiento']);
        $hoy = new DateTime();
        $edad = $hoy->diff($fecha_nacimiento)->y;
        $dependiente['edad'] = $edad;
        
        // Agregar informaci車n sobre plan geri芍trico si aplica
        $dependiente['es_geriatrico'] = ($edad >= 65);

        // Obtener total de cambios de plan
        $stmt = $conn->prepare("
            SELECT COUNT(*) 
            FROM historial_cambios_plan_dependientes 
            WHERE dependiente_id = ?
        ");
        $stmt->execute([$dependiente['id']]);
        $dependiente['total_cambios_plan'] = $stmt->fetchColumn();
    }

    echo json_encode([
        'success' => true,
        'multiple_contratos' => false,
        'dependientes' => $dependientes,
        'contrato_actual' => $contrato_actual
    ]);

} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
}