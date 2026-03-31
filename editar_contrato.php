<?php
require_once 'header.php';

$stmt->execute([$id]);
$facturas = $stmt->fetchAll();

if (!isset($_GET['id'])) {
    header('Location: contratos.php');
    exit();
}

$id = (int)$_GET['id'];

// Procesar formulario de actualización
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    try {
        $conn->beginTransaction();

        // Obtener datos actuales del contrato
        $stmt = $conn->prepare("SELECT cliente_id, plan_id FROM contratos WHERE id = ?");
        $stmt->execute([$id]);
        $contratoActual = $stmt->fetch();

        // Calcular monto total
        $monto_base = $_POST['monto_mensual'];
        $monto_total = $monto_base;

        // Obtener dependientes activos
        $stmt = $conn->prepare("
            SELECT d.*, p.precio_base
            FROM dependientes d
            JOIN planes p ON d.plan_id = p.id
            WHERE d.cliente_id = ? AND d.estado = 'activo'
        ");
        $stmt->execute([$contratoActual['cliente_id']]);
        $dependientes = $stmt->fetchAll();

        foreach ($dependientes as $dependiente) {
            $monto_total += $dependiente['precio_base'];
        }

        // Actualizar contrato
        $stmt = $conn->prepare("
            UPDATE contratos SET
                plan_id = ?,
                monto_mensual = ?,
                monto_total = ?,
                dia_cobro = ?,
                estado = ?
            WHERE id = ?
        ");

        $stmt->execute([
            $_POST['plan_id'],
            $monto_base,
            $monto_total,
            $_POST['dia_cobro'],
            $_POST['estado'],
            $id
        ]);

        // Registrar cambio de plan si es necesario
        if ($_POST['plan_id'] != $contratoActual['plan_id']) {
            $stmt = $conn->prepare("
                INSERT INTO historial_cambios_plan (
                    contrato_id, plan_anterior_id, plan_nuevo_id,
                    fecha_cambio, motivo, usuario_id
                ) VALUES (?, ?, ?, NOW(), ?, ?)
            ");
            $stmt->execute([
                $id,
                $contratoActual['plan_id'],
                $_POST['plan_id'],
                $_POST['motivo_cambio'],
                $_SESSION['usuario_id']
            ]);
        }

        // Actualizar beneficiarios
        if (isset($_POST['beneficiarios'])) {
            // Eliminar beneficiarios existentes
            $stmt = $conn->prepare("DELETE FROM beneficiarios WHERE contrato_id = ?");
            $stmt->execute([$id]);

            // Insertar nuevos beneficiarios
            foreach ($_POST['beneficiarios'] as $beneficiario) {
                $stmt = $conn->prepare("
                    INSERT INTO beneficiarios (
                        contrato_id, nombre, apellidos,
                        parentesco, porcentaje, fecha_nacimiento
                    ) VALUES (?, ?, ?, ?, ?, ?)
                ");
                $stmt->execute([
                    $id,
                    $beneficiario['nombre'],
                    $beneficiario['apellidos'],
                    $beneficiario['parentesco'],
                    $beneficiario['porcentaje'],
                    $beneficiario['fecha_nacimiento']
                ]);
            }
        }

        $conn->commit();
        $mensaje = "Contrato actualizado exitosamente.";
        $tipo_mensaje = "success";

    } catch(PDOException $e) {
        $conn->rollBack();
        $mensaje = "Error al actualizar el contrato: " . $e->getMessage();
        $tipo_mensaje = "error";
    }
}
// Obtener datos del contrato
$stmt = $conn->prepare("
    SELECT c.*,
           cl.codigo as cliente_codigo,
           cl.nombre as cliente_nombre,
           cl.apellidos as cliente_apellidos,
           p.nombre as plan_nombre,
           p.descripcion as plan_descripcion,
           (SELECT COUNT(*) FROM dependientes d 
            WHERE d.cliente_id = cl.id AND d.estado = 'activo') as total_dependientes
    FROM contratos c
    JOIN clientes cl ON c.cliente_id = cl.id
    JOIN planes p ON c.plan_id = p.id
    WHERE c.id = ?
");
$stmt->execute([$id]);
$contrato = $stmt->fetch();

if (!$contrato) {
    header('Location: contratos.php');
    exit();
}

// Obtener beneficiarios
$stmt = $conn->prepare("SELECT * FROM beneficiarios WHERE contrato_id = ?");
$stmt->execute([$id]);
$beneficiarios = $stmt->fetchAll();

// Obtener planes disponibles
$stmt = $conn->query("SELECT id, codigo, nombre, precio_base FROM planes WHERE estado = 'activo' ORDER BY nombre");
$planes = $stmt->fetchAll();

// Obtener dependientes del cliente
$stmt = $conn->prepare("
    SELECT d.*, p.nombre as plan_nombre, p.precio_base
    FROM dependientes d
    JOIN planes p ON d.plan_id = p.id
    WHERE d.cliente_id = ? AND d.estado = 'activo'
    ORDER BY d.nombre, d.apellidos
");
$stmt->execute([$contrato['cliente_id']]);
$dependientes = $stmt->fetchAll();
?>

<div class="contrato-edicion">
    <?php if (isset($mensaje)): ?>
        <div class="alert alert-<?php echo $tipo_mensaje; ?>">
            <?php echo $mensaje; ?>
        </div>
    <?php endif; ?>

    <div class="card">
        <div class="card-header">
            <div class="header-content">
                <h2>Editar Contrato</h2>
                <div class="header-actions">
                    <a href="ver_contrato.php?id=<?php echo $id; ?>" class="btn btn-secondary">
                        <i class="fas fa-eye"></i> Ver Contrato
                    </a>
                    <a href="contratos.php" class="btn btn-secondary">
                        <i class="fas fa-arrow-left"></i> Volver
                    </a>
                </div>
            </div>
        </div>

        <form method="POST" class="form-grid" id="editarContratoForm">
            <!-- Información del Cliente -->
            <div class="info-section">
                <h3>Información del Cliente</h3>
                <div class="info-content">
                    <div class="info-item">
                        <span class="label">Cliente:</span>
                        <span class="value">
                            <?php echo htmlspecialchars($contrato['cliente_codigo'] . ' - ' . 
                                   $contrato['cliente_nombre'] . ' ' . $contrato['cliente_apellidos']); ?>
                        </span>
                    </div>
                    <div class="info-item">
                        <span class="label">Número de Contrato:</span>
                        <span class="value"><?php echo htmlspecialchars($contrato['numero_contrato']); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="label">Fecha de Inicio:</span>
                        <span class="value"><?php echo date('d/m/Y', strtotime($contrato['fecha_inicio'])); ?></span>
                    </div>
                </div>
            </div>
            <!-- Formulario de Edición -->
            <div class="form-section">
                <h3>Detalles del Contrato</h3>

                <input type="hidden" name="plan_id_actual" value="<?php echo $contrato['plan_id']; ?>">

                <div class="form-group">
                    <label for="plan_id">Plan</label>
                    <select id="plan_id" name="plan_id" class="form-control" required onchange="verificarCambioPlan()">
                        <?php foreach ($planes as $plan): ?>
                            <option value="<?php echo $plan['id']; ?>" 
                                    data-precio="<?php echo $plan['precio_base']; ?>"
                                    <?php echo $plan['id'] == $contrato['plan_id'] ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($plan['codigo'] . ' - ' . $plan['nombre']); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div class="form-group">
                    <label for="monto_mensual">Monto Base Mensual</label>
                    <input type="number" id="monto_mensual" name="monto_mensual" step="0.01" 
                           class="form-control" value="<?php echo $contrato['monto_mensual']; ?>" required>
                </div>

                <div class="form-group">
                    <label for="monto_total">Monto Total (incluye dependientes)</label>
                    <input type="number" id="monto_total" name="monto_total" step="0.01" 
                           class="form-control" value="<?php echo $contrato['monto_total']; ?>" readonly>
                </div>

                <div class="form-group">
                    <label for="dia_cobro">Día de Cobro</label>
                    <input type="number" id="dia_cobro" name="dia_cobro" min="1" max="31" 
                           class="form-control" value="<?php echo $contrato['dia_cobro']; ?>" required>
                </div>

                <div class="form-group">
                    <label for="estado">Estado</label>
                    <select id="estado" name="estado" class="form-control" required>
                        <option value="activo" <?php echo $contrato['estado'] == 'activo' ? 'selected' : ''; ?>>Activo</option>
                        <option value="suspendido" <?php echo $contrato['estado'] == 'suspendido' ? 'selected' : ''; ?>>Suspendido</option>
                        <option value="cancelado" <?php echo $contrato['estado'] == 'cancelado' ? 'selected' : ''; ?>>Cancelado</option>
                    </select>
                </div>

                <div id="motivoCambioGroup" class="form-group" style="display: none;">
                    <label for="motivo_cambio">Motivo del Cambio de Plan</label>
                    <textarea id="motivo_cambio" name="motivo_cambio" class="form-control"></textarea>
                </div>
            </div>

            <!-- Resumen de Dependientes -->
            <div class="dependientes-section">
                <h3>Dependientes Asociados</h3>
                <?php if (empty($dependientes)): ?>
                    <p class="text-muted">No hay dependientes registrados</p>
                <?php else: ?>
                    <div class="dependientes-grid">
                        <?php foreach ($dependientes as $dependiente):
                            $edad = date_diff(date_create($dependiente['fecha_nacimiento']), date_create('today'))->y;
                        ?>
                            <div class="dependiente-card">
                                <div class="dependiente-header">
                                    <h4><?php echo htmlspecialchars($dependiente['nombre'] . ' ' . $dependiente['apellidos']); ?></h4>
                                    <span class="badge badge-<?php echo $edad >= 65 ? 'warning' : 'info'; ?>">
                                        <?php echo $edad; ?> años
                                    </span>
                                </div>
                                <div class="dependiente-info">
                                    <p><strong>Relación:</strong> <?php echo htmlspecialchars($dependiente['relacion']); ?></p>
                                    <p><strong>Plan:</strong> <?php echo htmlspecialchars($dependiente['plan_nombre']); ?></p>
                                    <p><strong>Costo:</strong> $<?php echo number_format($dependiente['precio_base'], 2); ?></p>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>
            <!-- Beneficiarios -->
            <div class="beneficiarios-section">
                <h3>Beneficiarios</h3>
                <div id="beneficiarios-container">
                    <?php foreach ($beneficiarios as $index => $beneficiario): ?>
                        <div class="beneficiario-form">
                            <i class="fas fa-times remove-beneficiario" onclick="removeBeneficiario(this)"></i>
                            
                            <div class="form-group">
                                <label>Nombre</label>
                                <input type="text" name="beneficiarios[<?php echo $index; ?>][nombre]" 
                                       class="form-control" value="<?php echo htmlspecialchars($beneficiario['nombre']); ?>" required>
                            </div>
                            
                            <div class="form-group">
                                <label>Apellidos</label>
                                <input type="text" name="beneficiarios[<?php echo $index; ?>][apellidos]" 
                                       class="form-control" value="<?php echo htmlspecialchars($beneficiario['apellidos']); ?>" required>
                            </div>
                            
                            <div class="form-group">
                                <label>Parentesco</label>
                                <input type="text" name="beneficiarios[<?php echo $index; ?>][parentesco]" 
                                       class="form-control" value="<?php echo htmlspecialchars($beneficiario['parentesco']); ?>" required>
                            </div>
                            
                            <div class="form-group">
                                <label>Porcentaje</label>
                                <input type="number" name="beneficiarios[<?php echo $index; ?>][porcentaje]" 
                                       min="0" max="100" class="form-control" 
                                       value="<?php echo $beneficiario['porcentaje']; ?>" required 
                                       onchange="validarPorcentajeTotal()">
                            </div>
                            
                            <div class="form-group">
                                <label>Fecha de Nacimiento</label>
                                <input type="date" name="beneficiarios[<?php echo $index; ?>][fecha_nacimiento]" 
                                       class="form-control" value="<?php echo $beneficiario['fecha_nacimiento']; ?>" required>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
                <button type="button" class="btn btn-secondary mt-3" onclick="agregarBeneficiario()">
                    <i class="fas fa-plus"></i> Agregar Beneficiario
                </button>
            </div>

            <div class="form-actions">
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-save"></i> Guardar Cambios
                </button>
                <a href="ver_contrato.php?id=<?php echo $id; ?>" class="btn btn-secondary">
                    <i class="fas fa-times"></i> Cancelar
                </a>
            </div>
        </form>
    </div>
</div>

<style>
.contrato-edicion {
    max-width: 1200px;
    margin: 0 auto;
    padding: 1rem;
}

.header-content {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.header-actions {
    display: flex;
    gap: 1rem;
}

.info-section {
    background: #f8f9fa;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
}

.form-section,
.dependientes-section,
.beneficiarios-section {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}
.dependientes-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 1rem;
}

.dependiente-card {
    background: #f8f9fa;
    border-radius: 8px;
    padding: 1rem;
    border: 1px solid #dee2e6;
}

.dependiente-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.beneficiario-form {
    position: relative;
    background: #f8f9fa;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1rem;
    border: 1px solid #dee2e6;
}

.remove-beneficiario {
    position: absolute;
    top: 0.5rem;
    right: 0.5rem;
    cursor: pointer;
    color: var(--danger-color);
}

.mt-3 {
    margin-top: 1rem;
}

@media (max-width: 768px) {
    .header-content {
        flex-direction: column;
        gap: 1rem;
    }

    .header-actions {
        flex-direction: column;
        width: 100%;
    }

    .dependientes-grid {
        grid-template-columns: 1fr;
    }
}
</style>

<script>
let beneficiarioCount = <?php echo count($beneficiarios); ?>;
let dependientesData = <?php echo json_encode($dependientes); ?>;

function agregarBeneficiario() {
    const container = document.getElementById('beneficiarios-container');
    const beneficiarioHtml = `
        <div class="beneficiario-form">
            <i class="fas fa-times remove-beneficiario" onclick="removeBeneficiario(this)"></i>
            
            <div class="form-group">
                <label>Nombre</label>
                <input type="text" name="beneficiarios[${beneficiarioCount}][nombre]" 
                       class="form-control" required>
            </div>
            
            <div class="form-group">
                <label>Apellidos</label>
                <input type="text" name="beneficiarios[${beneficiarioCount}][apellidos]" 
                       class="form-control" required>
            </div>
            
            <div class="form-group">
                <label>Parentesco</label>
                <input type="text" name="beneficiarios[${beneficiarioCount}][parentesco]" 
                       class="form-control" required>
            </div>
            
            <div class="form-group">
                <label>Porcentaje</label>
                <input type="number" name="beneficiarios[${beneficiarioCount}][porcentaje]" 
                       min="0" max="100" class="form-control" required onchange="validarPorcentajeTotal()">
            </div>
            
            <div class="form-group">
                <label>Fecha de Nacimiento</label>
                <input type="date" name="beneficiarios[${beneficiarioCount}][fecha_nacimiento]" 
                       class="form-control" required>
            </div>
        </div>
    `;
    
    container.insertAdjacentHTML('beforeend', beneficiarioHtml);
    beneficiarioCount++;
}

function removeBeneficiario(element) {
    element.closest('.beneficiario-form').remove();
    validarPorcentajeTotal();
}

function validarPorcentajeTotal() {
    const beneficiarios = document.querySelectorAll('.beneficiario-form');
    let total = 0;
    
    beneficiarios.forEach(beneficiario => {
        const porcentaje = parseFloat(beneficiario.querySelector('input[name*="[porcentaje]"]').value || 0);
        total += porcentaje;
    });

    if (total !== 100) {
        alert(`El porcentaje total actual es ${total}%. La suma debe ser exactamente 100%`);
        return false;
    }
    return true;
}

function verificarCambioPlan() {
    const planActual = document.querySelector('input[name="plan_id_actual"]').value;
    const planNuevo = document.getElementById('plan_id').value;
    const motivoGroup = document.getElementById('motivoCambioGroup');
    
    if (planActual !== planNuevo) {
        motivoGroup.style.display = 'block';
        document.getElementById('motivo_cambio').required = true;
        actualizarMonto();
    } else {
        motivoGroup.style.display = 'none';
        document.getElementById('motivo_cambio').required = false;
    }
}

function actualizarMonto() {
    const planSelect = document.getElementById('plan_id');
    const montoInput = document.getElementById('monto_mensual');
    const selectedOption = planSelect.options[planSelect.selectedIndex];
    
    if (selectedOption.value) {
        const montoBase = parseFloat(selectedOption.dataset.precio);
        montoInput.value = montoBase;
        calcularMontoTotal();
    }
}

function calcularMontoTotal() {
    const montoBase = parseFloat(document.getElementById('monto_mensual').value) || 0;
    let montoTotal = montoBase;

    dependientesData.forEach(dependiente => {
        montoTotal += parseFloat(dependiente.precio_base);
    });

    document.getElementById('monto_total').value = montoTotal.toFixed(2);
}

document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('editarContratoForm').addEventListener('submit', function(e) {
        if (!validarPorcentajeTotal()) {
            e.preventDefault();
        }
    });
});
</script>

<?php require_once 'footer.php'; ?>