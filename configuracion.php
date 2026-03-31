<?php
require_once 'header.php';

// Verificar permisos de administrador
if ($_SESSION['rol'] !== 'admin') {
    header('Location: dashboard.php');
    exit();
}

// Procesar formulario
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    try {
        // Manejo de upload del logo
        $logo_url = null;
        if (isset($_FILES['logo']) && $_FILES['logo']['error'] == 0) {
            $allowed = ['jpg', 'jpeg', 'png', 'gif'];
            $filename = $_FILES['logo']['name'];
            $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
            
            if (in_array($ext, $allowed)) {
                $upload_path = 'uploads/';
                $new_filename = 'logo_' . time() . '.' . $ext;
                
                if (!is_dir($upload_path)) {
                    mkdir($upload_path, 0777, true);
                }
                
                if (move_uploaded_file($_FILES['logo']['tmp_name'], $upload_path . $new_filename)) {
                    $logo_url = $upload_path . $new_filename;
                }
            }
        }

        // Actualizar configuración
        $stmt = $conn->prepare("
            UPDATE configuracion_sistema SET 
                nombre_empresa = ?,
                rif = ?,
                direccion = ?,
                telefono = ?,
                email = ?,
                moneda = ?,
                dias_gracia_pago = ?,
                formato_factura = ?
                " . ($logo_url ? ", logo_url = ?" : "") . "
            WHERE id = 1
        ");

        $params = [
            $_POST['nombre_empresa'],
            $_POST['rif'],
            $_POST['direccion'],
            $_POST['telefono'],
            $_POST['email'],
            $_POST['moneda'],
            $_POST['dias_gracia_pago'],
            $_POST['formato_factura']
        ];

        if ($logo_url) {
            $params[] = $logo_url;
        }

        $stmt->execute($params);
        $mensaje = "Configuración actualizada exitosamente.";
        $tipo_mensaje = "success";

    } catch(PDOException $e) {
        $mensaje = "Error al actualizar la configuración: " . $e->getMessage();
        $tipo_mensaje = "error";
    }
}

// Obtener configuración actual
$stmt = $conn->query("SELECT * FROM configuracion_sistema WHERE id = 1");
$config = $stmt->fetch();
?>

<div class="configuracion-container">
    <?php if (isset($mensaje)): ?>
        <div class="alert alert-<?php echo $tipo_mensaje; ?>">
            <?php echo $mensaje; ?>
        </div>
    <?php endif; ?>

    <div class="card">
        <div class="card-header">
            <h2>Configuración del Sistema</h2>
        </div>

        <form method="POST" enctype="multipart/form-data" class="config-form">
            <!-- Información de la Empresa -->
            <div class="form-section">
                <h3>Información de la Empresa</h3>
                
                <div class="logo-preview">
                    <?php if ($config['logo_url']): ?>
                        <img src="<?php echo htmlspecialchars($config['logo_url']); ?>" alt="Logo actual">
                    <?php endif; ?>
                </div>

                <div class="form-group">
                    <label for="logo">Logo de la Empresa</label>
                    <input type="file" id="logo" name="logo" class="form-control" accept="image/*">
                    <small class="form-text text-muted">Formatos permitidos: JPG, PNG, GIF</small>
                </div>

                <div class="form-group">
                    <label for="nombre_empresa">Nombre de la Empresa</label>
                    <input type="text" id="nombre_empresa" name="nombre_empresa" 
                           class="form-control" value="<?php echo htmlspecialchars($config['nombre_empresa']); ?>" required>
                </div>

                <div class="form-group">
                    <label for="rif">RNC</label>
                    <input type="text" id="rif" name="rif" 
                           class="form-control" value="<?php echo htmlspecialchars($config['rif']); ?>" required>
                </div>

                <div class="form-group">
                    <label for="direccion">Dirección</label>
                    <textarea id="direccion" name="direccion" class="form-control" required><?php echo htmlspecialchars($config['direccion']); ?></textarea>
                </div>

                <div class="form-group">
                    <label for="telefono">Teléfono</label>
                    <input type="text" id="telefono" name="telefono" 
                           class="form-control" value="<?php echo htmlspecialchars($config['telefono']); ?>" required>
                </div>

                <div class="form-group">
                    <label for="email">Email</label>
                    <input type="email" id="email" name="email" 
                           class="form-control" value="<?php echo htmlspecialchars($config['email']); ?>" required>
                </div>
            </div>

            <!-- Configuración del Sistema -->
            <div class="form-section">
                <h3>Configuración General</h3>

                <div class="form-group">
                    <label for="moneda">Moneda</label>
                    <select id="moneda" name="moneda" class="form-control" required>
                        <option value="USD" <?php echo $config['moneda'] == 'USD' ? 'selected' : ''; ?>>Dólar (USD)</option>
                        <option value="EUR" <?php echo $config['moneda'] == 'EUR' ? 'selected' : ''; ?>>Euro (EUR)</option>
                        <option value="VES" <?php echo $config['moneda'] == 'VES' ? 'selected' : ''; ?>>Bolívar (VES)</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="dias_gracia_pago">Días de Gracia para Pagos</label>
                    <input type="number" id="dias_gracia_pago" name="dias_gracia_pago" 
                           class="form-control" value="<?php echo htmlspecialchars($config['dias_gracia_pago']); ?>" required>
                </div>

                <div class="form-group">
                    <label for="formato_factura">Formato de Factura</label>
                    <textarea id="formato_factura" name="formato_factura" class="form-control" 
                              rows="5"><?php echo htmlspecialchars($config['formato_factura']); ?></textarea>
                    <small class="form-text text-muted">
                        Variables disponibles: {numero_factura}, {fecha}, {cliente}, {monto}, etc.
                    </small>
                </div>
            </div>

            <!-- Botones de acción -->
            <div class="form-actions">
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-save"></i> Guardar Configuración
                </button>
                <button type="reset" class="btn btn-secondary">
                    <i class="fas fa-undo"></i> Restaurar Cambios
                </button>
            </div>
        </form>
    </div>

    <!-- Respaldo del Sistema -->
    <div class="card mt-4">
        <div class="card-header">
            <h3>Respaldo del Sistema</h3>
        </div>
        <div class="backup-section">
            <div class="backup-info">
                <p>Último respaldo: <?php echo isset($config['ultimo_respaldo']) ? date('d/m/Y H:i', strtotime($config['ultimo_respaldo'])) : 'Nunca'; ?></p>
            </div>
            <div class="backup-actions">
                <button onclick="generarRespaldo()" class="btn btn-primary">
                    <i class="fas fa-download"></i> Generar Respaldo
                </button>
                <button onclick="restaurarRespaldo()" class="btn btn-warning">
                    <i class="fas fa-upload"></i> Restaurar Respaldo
                </button>
            </div>
        </div>
    </div>
    
    
    
    <!-- Gestión de Bloqueos de Generación por Lote -->
<div class="card mt-4">
    <div class="card-header">
        <h3>Gestión de Bloqueos - Generación de Facturas por Lote</h3>
    </div>
    <div class="table-responsive">
        <?php
        // Obtener solo registros activos
        $stmt = $conn->prepare("
            SELECT gl.*, u.nombre as nombre_usuario, u.usuario as nombre_login
            FROM generacion_lote_lock gl
            JOIN usuarios u ON gl.usuario_id = u.id
            WHERE gl.estado = 'activo'
            ORDER BY gl.id DESC
        ");
        $stmt->execute();
        $bloqueos = $stmt->fetchAll();
        ?>
        
        <?php if (count($bloqueos) > 0): ?>
            <table class="table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Usuario</th>
                        <th>Login</th>
                        <th>Fecha/Hora</th>
                        <th>Estado</th>
                        <th>Acciones</th>
                    </tr>
                </thead>
                <tbody id="tabla-bloqueos">
                    <?php foreach ($bloqueos as $bloqueo): ?>
                        <tr id="fila-<?php echo $bloqueo['id']; ?>">
                            <td><?php echo $bloqueo['id']; ?></td>
                            <td><?php echo htmlspecialchars($bloqueo['nombre_usuario']); ?></td>
                            <td><?php echo htmlspecialchars($bloqueo['nombre_login']); ?></td>
                            <td><?php echo date('d/m/Y H:i:s', strtotime($bloqueo['timestamp'])); ?></td>
                            <td>
                                <span class="badge badge-danger">Activo</span>
                            </td>
                            <td>
                                <button class="btn btn-warning btn-sm" 
                                        onclick="desbloquearRegistro(<?php echo $bloqueo['id']; ?>)">
                                    <i class="fas fa-unlock"></i> Desbloquear
                                </button>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php else: ?>
            <div class="alert alert-info m-3">
                No hay registros bloqueados actualmente.
            </div>
        <?php endif; ?>
    </div>
</div>
    


<!-- Gestión de Bloqueos de Generación Automática de Facturas -->
<div class="card mt-4">
    <div class="card-header">
        <h3>Gestión de Bloqueos - Generación Automática de Facturas</h3>
    </div>
    <div class="table-responsive">
        <?php
        // Obtener solo registros activos
        $stmt = $conn->prepare("
            SELECT gf.*, u.nombre as nombre_usuario, u.usuario as nombre_login
            FROM generacion_facturas_lock gf
            JOIN usuarios u ON gf.usuario_id = u.id
            WHERE gf.estado = 'activo'
            ORDER BY gf.id DESC
        ");
        $stmt->execute();
        $bloqueos_facturas = $stmt->fetchAll();
        ?>
        
        <?php if (count($bloqueos_facturas) > 0): ?>
            <table class="table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Usuario</th>
                        <th>Login</th>
                        <th>Fecha/Hora</th>
                        <th>Estado</th>
                        <th>Acciones</th>
                    </tr>
                </thead>
                <tbody id="tabla-bloqueos-facturas">
                    <?php foreach ($bloqueos_facturas as $bloqueo): ?>
                        <tr id="fila-factura-<?php echo $bloqueo['id']; ?>">
                            <td><?php echo $bloqueo['id']; ?></td>
                            <td><?php echo htmlspecialchars($bloqueo['nombre_usuario']); ?></td>
                            <td><?php echo htmlspecialchars($bloqueo['nombre_login']); ?></td>
                            <td><?php echo date('d/m/Y H:i:s', strtotime($bloqueo['timestamp'])); ?></td>
                            <td>
                                <span class="badge badge-danger">Activo</span>
                            </td>
                            <td>
                                <button class="btn btn-warning btn-sm" 
                                        onclick="desbloquearRegistroFactura(<?php echo $bloqueo['id']; ?>)">
                                    <i class="fas fa-unlock"></i> Desbloquear
                                </button>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php else: ?>
            <div class="alert alert-info m-3">
                No hay registros bloqueados actualmente.
            </div>
        <?php endif; ?>
    </div>
</div>

    
    
    
</div>


<style>
.configuracion-container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 1.5rem;
}

.config-form {
    padding: 1.5rem;
}

.form-section {
    background: #f8f9fa;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 2rem;
}

.form-section h3 {
    color: var(--primary-color);
    margin-bottom: 1.5rem;
    padding-bottom: 0.5rem;
    border-bottom: 2px solid var(--primary-color);
}

.logo-preview {
    text-align: center;
    margin-bottom: 1rem;
}

.logo-preview img {
    max-width: 200px;
    height: auto;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.form-group {
    margin-bottom: 1.5rem;
}

.form-actions {
    display: flex;
    gap: 1rem;
    justify-content: flex-end;
    padding: 1rem 0;
}

.backup-section {
    padding: 1.5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.backup-actions {
    display: flex;
    gap: 1rem;
}

@media (max-width: 768px) {
    .backup-section {
        flex-direction: column;
        gap: 1rem;
    }

    .backup-actions {
        flex-direction: column;
        width: 100%;
    }

    .form-actions {
        flex-direction: column;
    }

    .form-actions button {
        width: 100%;
    }
}
</style>

<script>
// Previsualización de logo
document.getElementById('logo').addEventListener('change', function(e) {
    const file = e.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = function(e) {
            const preview = document.querySelector('.logo-preview');
            preview.innerHTML = `<img src="${e.target.result}" alt="Vista previa del logo">`;
        }
        reader.readAsDataURL(file);
    }
});

function generarRespaldo() {
    if (confirm('¿Está seguro de que desea generar un respaldo del sistema?')) {
        window.location.href = 'generar_respaldo.php';
    }
}

function restaurarRespaldo() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.sql';
    
    input.onchange = function(e) {
        const file = e.target.files[0];
        if (file) {
            if (confirm('¿Está seguro de que desea restaurar el sistema con este respaldo? Esta acción no se puede deshacer.')) {
                const formData = new FormData();
                formData.append('backup_file', file);
                
                fetch('restaurar_respaldo.php', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('Respaldo restaurado exitosamente');
                        location.reload();
                    } else {
                        alert('Error al restaurar el respaldo: ' + data.message);
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Error al procesar la solicitud');
                });
            }
        }
    };
    
    input.click();
}



//funcion para eliminar los registro del bloqueo y desbloqueo del modal de generacion por lote
function desbloquearRegistro(id) {
    fetch('desbloquear_registro.php', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ id: id })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Remover la fila de la tabla
            const fila = document.getElementById(`fila-${id}`);
            if (fila) {
                fila.remove();
            }
            
            // Si no quedan más filas, mostrar mensaje
            const tabla = document.getElementById('tabla-bloqueos');
            if (tabla && tabla.rows.length === 0) {
                document.querySelector('.table-responsive').innerHTML = `
                    <div class="alert alert-info m-3">
                        No hay registros bloqueados actualmente.
                    </div>
                `;
            }
        } else {
            alert('Error al desbloquear el registro: ' + data.error);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Error al procesar la solicitud');
    });
}








//funcion para eliminar los registro del bloqueo y desbloqueo la generacion de las facturas automatizadas (todas las facturas pendientes)
function desbloquearRegistroFactura(id) {
    fetch('desbloquear_registro_factura.php', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ id: id })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Remover la fila de la tabla
            const fila = document.getElementById(`fila-factura-${id}`);
            if (fila) {
                fila.remove();
            }
            
            // Si no quedan más filas, mostrar mensaje
            const tabla = document.getElementById('tabla-bloqueos-facturas');
            if (tabla && tabla.rows.length === 0) {
                tabla.closest('.table-responsive').innerHTML = `
                    <div class="alert alert-info m-3">
                        No hay registros bloqueados actualmente.
                    </div>
                `;
            }
        } else {
            alert('Error al desbloquear el registro: ' + data.error);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Error al procesar la solicitud');
    });
}



// Validación del formulario
document.querySelector('form').addEventListener('submit', function(e) {
    const telefono = document.getElementById('telefono').value;
    const email = document.getElementById('email').value;
    
    // Validar formato de teléfono
    const telefonoRegex = /^\+?[\d\s-]{8,}$/;
    if (!telefonoRegex.test(telefono)) {
        e.preventDefault();
        alert('Por favor, ingrese un número de teléfono válido');
        return;
    }
    
    // Validar formato de email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        e.preventDefault();
        alert('Por favor, ingrese un email válido');
        return;
    }
});
</script>

<?php require_once 'footer.php'; ?>