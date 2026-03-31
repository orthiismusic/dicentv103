<?php
require_once 'header.php';

if (!isset($_GET['id'])) {
    header('Location: clientes.php');
    exit();
}

$id = (int)$_GET['id'];

// Procesar formulario de edición
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    try {
        $stmt = $conn->prepare("
            UPDATE clientes SET 
                codigo = ?,
                nombre = ?,
                apellidos = ?,
                telefono1 = ?,
                telefono2 = ?,
                telefono3 = ?,
                direccion = ?,
                email = ?,
                fecha_nacimiento = ?,
                estado = ?
            WHERE id = ?
        ");
        
        $stmt->execute([
            $_POST['codigo'],
            $_POST['nombre'],
            $_POST['apellidos'],
            $_POST['telefono1'],
            $_POST['telefono2'],
            $_POST['telefono3'],
            $_POST['direccion'],
            $_POST['email'],
            $_POST['fecha_nacimiento'],
            $_POST['estado'],
            $id
        ]);
        
        $mensaje = "Cliente actualizado exitosamente.";
        $tipo_mensaje = "success";
    } catch(PDOException $e) {
        $mensaje = "Error al actualizar el cliente: " . $e->getMessage();
        $tipo_mensaje = "error";
    }
}

// Obtener datos del cliente
$stmt = $conn->prepare("SELECT * FROM clientes WHERE id = ?");
$stmt->execute([$id]);
$cliente = $stmt->fetch();

if (!$cliente) {
    header('Location: clientes.php');
    exit();
}
?>

<div class="card">
    <div class="card-header">
        <div class="header-content">
            <h2>Editar Cliente</h2>
            <a href="clientes.php" class="btn btn-secondary">
                <i class="fas fa-arrow-left"></i> Volver
            </a>
        </div>
    </div>

    <?php if (isset($mensaje)): ?>
        <div class="alert alert-<?php echo $tipo_mensaje; ?>">
            <?php echo $mensaje; ?>
        </div>
    <?php endif; ?>

    <form method="POST" class="form-grid">
        <div class="form-group">
            <label for="codigo">Código</label>
            <input type="text" id="codigo" name="codigo" class="form-control" 
                   value="<?php echo htmlspecialchars($cliente['codigo']); ?>" required>
        </div>

        <div class="form-group">
            <label for="nombre">Nombre</label>
            <input type="text" id="nombre" name="nombre" class="form-control" 
                   value="<?php echo htmlspecialchars($cliente['nombre']); ?>" required>
        </div>

        <div class="form-group">
            <label for="apellidos">Apellidos</label>
            <input type="text" id="apellidos" name="apellidos" class="form-control" 
                   value="<?php echo htmlspecialchars($cliente['apellidos']); ?>" required>
        </div>

        <div class="form-group">
            <label for="telefono1">Teléfono Principal</label>
            <input type="tel" id="telefono1" name="telefono1" class="form-control" 
                   value="<?php echo htmlspecialchars($cliente['telefono1']); ?>" required>
        </div>

        <div class="form-group">
            <label for="telefono2">Teléfono Secundario</label>
            <input type="tel" id="telefono2" name="telefono2" class="form-control" 
                   value="<?php echo htmlspecialchars($cliente['telefono2']); ?>">
        </div>

        <div class="form-group">
            <label for="telefono3">Teléfono Adicional</label>
            <input type="tel" id="telefono3" name="telefono3" class="form-control" 
                   value="<?php echo htmlspecialchars($cliente['telefono3']); ?>">
        </div>

        <div class="form-group">
            <label for="email">Email</label>
            <input type="email" id="email" name="email" class="form-control" 
                   value="<?php echo htmlspecialchars($cliente['email']); ?>" required>
        </div>

        <div class="form-group">
            <label for="fecha_nacimiento">Fecha de Nacimiento</label>
            <input type="date" id="fecha_nacimiento" name="fecha_nacimiento" class="form-control" 
                   value="<?php echo htmlspecialchars($cliente['fecha_nacimiento']); ?>" required>
        </div>

        <div class="form-group">
            <label for="direccion">Dirección</label>
            <textarea id="direccion" name="direccion" class="form-control" 
                      required><?php echo htmlspecialchars($cliente['direccion']); ?></textarea>
        </div>

        <div class="form-group">
            <label for="estado">Estado</label>
            <select id="estado" name="estado" class="form-control" required>
                <option value="activo" <?php echo $cliente['estado'] == 'activo' ? 'selected' : ''; ?>>Activo</option>
                <option value="inactivo" <?php echo $cliente['estado'] == 'inactivo' ? 'selected' : ''; ?>>Inactivo</option>
            </select>
        </div>

        <div class="form-actions">
            <button type="submit" class="btn btn-primary">
                <i class="fas fa-save"></i> Guardar Cambios
            </button>
        </div>
    </form>
</div>

<style>
.header-content {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.form-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1.5rem;
    padding: 1.5rem;
}

.form-group {
    margin-bottom: 1rem;
}

.form-actions {
    grid-column: 1 / -1;
    display: flex;
    justify-content: flex-end;
    gap: 1rem;
}

.alert {
    padding: 1rem;
    margin: 1rem;
    border-radius: 6px;
}

.alert-success {
    background-color: #d1fae5;
    color: #065f46;
    border: 1px solid #34d399;
}

.alert-error {
    background-color: #fee2e2;
    color: #991b1b;
    border: 1px solid #f87171;
}

@media (max-width: 768px) {
    .form-grid {
        grid-template-columns: 1fr;
    }
}
</style>

<?php require_once 'footer.php'; ?>