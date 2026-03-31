<?php
require_once 'config.php';
verificarSesion();

header('Content-Type: application/json');

try {
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        // Si es una solicitud POST con JSON
        if (isset($_SERVER["CONTENT_TYPE"]) && strpos($_SERVER["CONTENT_TYPE"], "application/json") !== false) {
            $_POST = json_decode(file_get_contents("php://input"), true);
        }

        // Verificar la acción requerida
        switch ($_POST['action'] ?? '') {
            case 'eliminar':
                if (!isset($_POST['id'])) {
                    throw new Exception('ID de dependiente no proporcionado');
                }

                $stmt = $conn->prepare("UPDATE dependientes SET estado = 'inactivo' WHERE id = ?");
                $stmt->execute([$_POST['id']]);

                echo json_encode([
                    'success' => true,
                    'message' => 'Dependiente eliminado exitosamente'
                ]);
                break;

            default: // Crear o actualizar dependiente
                $conn->beginTransaction();

                // Validar edad mínima (1 año)
                $fechaNacimiento = new DateTime($_POST['fecha_nacimiento']);
                $hoy = new DateTime();
                $edad = $hoy->diff($fechaNacimiento)->y;
                
                if ($fechaNacimiento > $hoy) {
                    throw new Exception('La fecha de nacimiento no puede ser futura');
                }

                if ($edad < 1) {
                    throw new Exception('El dependiente debe tener al menos 1 año de edad');
                }

                // Validar que la identificación no esté duplicada
                $stmt = $conn->prepare("
                    SELECT id FROM dependientes 
                    WHERE identificacion = ? AND id != ? AND estado = 'activo'
                ");
                $stmt->execute([
                    $_POST['identificacion'], 
                    $_POST['id'] ?? 0
                ]);
                
                if ($stmt->fetchColumn()) {
                    throw new Exception('Ya existe un dependiente con esta identificación');
                }

                // Verificar que el contrato existe y está activo
                $stmt = $conn->prepare("
                    SELECT id FROM contratos 
                    WHERE id = ? AND estado = 'activo'
                ");
                $stmt->execute([$_POST['contrato_id']]);
                if (!$stmt->fetch()) {
                    throw new Exception('El contrato especificado no existe o no está activo');
                }

                // Determinar el plan basado en la edad
                $planId = $_POST['plan_id'];
                if ($edad >= 65) {
                    $planId = 5; // ID del plan geriátrico
                }

                if (empty($_POST['id'])) {
                    // Crear nuevo dependiente
                    $stmt = $conn->prepare("
                        INSERT INTO dependientes (
                            contrato_id, nombre, apellidos, relacion,
                            identificacion, fecha_nacimiento, telefono,
                            fecha_registro, email, plan_id, estado, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'activo', NOW())
                    ");

                    $stmt->execute([
                        $_POST['contrato_id'],
                        $_POST['nombre'],
                        $_POST['apellidos'],
                        $_POST['relacion'],
                        $_POST['identificacion'],
                        $_POST['fecha_nacimiento'],
                        $_POST['telefono'],
                        $_POST['fecha_registro'],
                        $_POST['email'],
                        $planId
                    ]);

                    $dependienteId = $conn->lastInsertId();
                    $mensaje = "Dependiente creado exitosamente";
                } else {
                    // Actualizar dependiente existente
                    $stmt = $conn->prepare("
                        UPDATE dependientes SET
                            contrato_id = ?,
                            nombre = ?,
                            apellidos = ?,
                            relacion = ?,
                            identificacion = ?,
                            fecha_nacimiento = ?,
                            telefono = ?,
                            fecha_registro = ?,
                            email = ?,
                            plan_id = ?,
                            estado = ?
                        WHERE id = ?
                    ");
                    
                    $stmt->execute([
                        $_POST['contrato_id'],
                        $_POST['nombre'],
                        $_POST['apellidos'],
                        $_POST['relacion'],
                        $_POST['identificacion'],
                        $_POST['fecha_nacimiento'],
                        $_POST['telefono'],
                        $_POST['fecha_registro'],
                        $_POST['email'],
                        $planId,
                        $_POST['estado'],
                        $_POST['id']
                    ]);

                    $dependienteId = $_POST['id'];
                    $mensaje = "Dependiente actualizado exitosamente";
                }

                // Registrar el cambio de plan si es necesario
                if (!empty($_POST['id']) && $_POST['plan_id'] != $planId) {
                    $stmt = $conn->prepare("
                        INSERT INTO historial_cambios_plan_dependientes (
                            dependiente_id, plan_anterior_id, plan_nuevo_id,
                            fecha_cambio, motivo, usuario_id
                        ) VALUES (?, ?, ?, NOW(), ?, ?)
                    ");
                    
                    $stmt->execute([
                        $dependienteId,
                        $_POST['plan_id'],
                        $planId,
                        'Cambio automático por edad' . ($edad >= 65 ? ' (Plan Geriátrico)' : ''),
                        $_SESSION['usuario_id']
                    ]);
                }

                $conn->commit();

                echo json_encode([
                    'success' => true,
                    'message' => $mensaje,
                    'dependiente_id' => $dependienteId
                ]);
                break;
        }
    } else {
        throw new Exception('Método no permitido');
    }
} catch (Exception $e) {
    if (isset($conn) && $conn->inTransaction()) {
        $conn->rollBack();
    }
    
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
}