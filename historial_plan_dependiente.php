<?php
/* ============================================================
   historial_plan_dependiente.php
   Endpoint JSON — Historial de cambios de plan de un dependiente
   Usado por los modales en ver_cliente.php y ver_contrato.php
   ============================================================ */
require_once 'config.php';
verificarSesion();

header('Content-Type: application/json; charset=utf-8');

try {
    // Validar ID
    if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
        throw new Exception('ID del dependiente no proporcionado o inválido.');
    }

    $dependienteId = (int)$_GET['id'];

    // Verificar que el dependiente existe y obtener sus datos básicos
    $stmt = $conn->prepare("
        SELECT d.id, d.nombre, d.apellidos, d.relacion,
               d.fecha_nacimiento, d.plan_id,
               p.nombre as plan_actual,
               c.numero_contrato
        FROM dependientes d
        JOIN planes p ON d.plan_id = p.id
        JOIN contratos c ON d.contrato_id = c.id
        WHERE d.id = ?
    ");
    $stmt->execute([$dependienteId]);
    $dependiente = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$dependiente) {
        throw new Exception('Dependiente no encontrado en el sistema.');
    }

    // Obtener historial de cambios de plan
    $stmt = $conn->prepare("
        SELECT 
            h.id,
            h.dependiente_id,
            h.fecha_cambio,
            h.motivo,
            h.created_at,
            p1.id          AS plan_anterior_id,
            p1.nombre      AS plan_anterior_nombre,
            p1.precio_base AS plan_anterior_precio,
            p2.id          AS plan_nuevo_id,
            p2.nombre      AS plan_nuevo_nombre,
            p2.precio_base AS plan_nuevo_precio,
            u.nombre       AS usuario_nombre,
            u.usuario      AS usuario_login
        FROM historial_cambios_plan_dependientes h
        JOIN planes   p1 ON h.plan_anterior_id = p1.id
        JOIN planes   p2 ON h.plan_nuevo_id    = p2.id
        JOIN usuarios u  ON h.usuario_id       = u.id
        WHERE h.dependiente_id = ?
        ORDER BY h.fecha_cambio DESC
    ");
    $stmt->execute([$dependienteId]);
    $historial = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Procesar y enriquecer cada entrada del historial
    foreach ($historial as &$cambio) {
        // Formatear fecha de cambio
        $cambio['fecha_cambio'] = $cambio['fecha_cambio'];

        // Calcular diferencia de precio
        $cambio['diferencia_precio'] = (float)$cambio['plan_nuevo_precio'] - (float)$cambio['plan_anterior_precio'];

        // Indicar si el nuevo plan es geriátrico (plan_id = 5)
        $cambio['es_cambio_geriatrico'] = ((int)$cambio['plan_nuevo_id'] === 5);

        // Indicar si salió del geriátrico
        $cambio['salio_geriatrico'] = ((int)$cambio['plan_anterior_id'] === 5 && (int)$cambio['plan_nuevo_id'] !== 5);

        // Normalizar motivo vacío
        if (empty(trim($cambio['motivo'] ?? ''))) {
            $cambio['motivo'] = 'No especificado';
        }

        // Tipo de cambio: subida, bajada o lateral
        if ($cambio['diferencia_precio'] > 0) {
            $cambio['tipo_cambio'] = 'upgrade';
        } elseif ($cambio['diferencia_precio'] < 0) {
            $cambio['tipo_cambio'] = 'downgrade';
        } else {
            $cambio['tipo_cambio'] = 'lateral';
        }

        // Limpiar campos internos que no deben exponerse
        unset($cambio['plan_anterior_id']);
        unset($cambio['plan_nuevo_id']);
    }
    unset($cambio);

    // Respuesta exitosa
    echo json_encode([
        'success'     => true,
        'dependiente' => [
            'id'             => $dependiente['id'],
            'nombre_completo'=> $dependiente['nombre'] . ' ' . $dependiente['apellidos'],
            'relacion'       => $dependiente['relacion'],
            'plan_actual'    => $dependiente['plan_actual'],
            'contrato'       => $dependiente['numero_contrato'],
        ],
        'total'       => count($historial),
        'data'        => $historial
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);

} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'Error de base de datos: ' . $e->getMessage()
    ], JSON_UNESCAPED_UNICODE);

} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ], JSON_UNESCAPED_UNICODE);
}
?>