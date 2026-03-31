<?php
require_once 'config.php';
verificarSesion();

// Obtener configuración del sistema para el logo
$stmt = $conn->query("SELECT * FROM configuracion_sistema LIMIT 1");
$config = $stmt->fetch();

// Procesar búsqueda
$buscar = isset($_GET['buscar']) ? trim($_GET['buscar']) : '';
$contratos_buscar = [];

// Si hay búsqueda, procesar los contratos
if (!empty($buscar)) {
    // Separar por comas y limpiar espacios
    $contratos_input = explode(',', $buscar);
    foreach ($contratos_input as $contrato) {
        $contrato = trim($contrato);
        if (!empty($contrato)) {
            // Asegurar formato de 5 dígitos
            $contratos_buscar[] = str_pad($contrato, 5, '0', STR_PAD_LEFT);
        }
    }
}

// Construir consulta SQL
$sql = "
    SELECT 
        c.id as cliente_id,
        c.codigo,
        c.nombre,
        c.apellidos,
        GROUP_CONCAT(DISTINCT co.numero_contrato ORDER BY co.numero_contrato SEPARATOR ', ') as contratos
    FROM clientes c
    INNER JOIN contratos co ON c.id = co.cliente_id
    WHERE c.estado = 'activo'
    AND co.estado = 'activo'
";

$params = [];

// Agregar filtro de búsqueda
if (!empty($contratos_buscar)) {
    $placeholders = implode(',', array_fill(0, count($contratos_buscar), '?'));
    $sql .= " AND co.numero_contrato IN ($placeholders)";
    $params = $contratos_buscar;
} elseif (!empty($buscar)) {
    // Búsqueda por nombre, apellido o contrato
    $sql .= " AND (
        c.nombre LIKE ? OR 
        c.apellidos LIKE ? OR 
        co.numero_contrato LIKE ? OR
        c.codigo LIKE ?
    )";
    $termino = "%$buscar%";
    $params = [$termino, $termino, $termino, $termino];
}

$sql .= " GROUP BY c.id, c.codigo, c.nombre, c.apellidos";
$sql .= " ORDER BY c.codigo ASC";

$stmt = $conn->prepare($sql);
$stmt->execute($params);
$clientes = $stmt->fetchAll();

// Calcular páginas necesarias (3 formularios por página)
$total_clientes = count($clientes);
$total_paginas = ceil($total_clientes / 3);
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Actualización de Datos de Contacto - <?php echo htmlspecialchars($config['nombre_empresa']); ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: Arial, sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }

        /* Estilos para pantalla */
        .screen-only {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }

        .header-screen {
            text-align: center;
            margin-bottom: 30px;
        }

        .header-screen img {
            max-height: 80px;
            margin-bottom: 15px;
        }

        .header-screen h1 {
            color: #333;
            font-size: 24px;
            margin-bottom: 10px;
        }

        .search-section {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }

        .search-box {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
        }

        .search-input {
            flex: 1;
            padding: 12px 15px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 15px;
        }

        .search-input:focus {
            outline: none;
            border-color: #007bff;
        }

        .btn {
            padding: 12px 25px;
            border: none;
            border-radius: 5px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }

        .btn-primary {
            background: #007bff;
            color: white;
        }

        .btn-primary:hover {
            background: #0056b3;
        }

        .btn-secondary {
            background: #6c757d;
            color: white;
        }

        .btn-secondary:hover {
            background: #545b62;
        }

        .btn-success {
            background: #28a745;
            color: white;
            font-size: 16px;
            padding: 15px 30px;
        }

        .btn-success:hover {
            background: #218838;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(40, 167, 69, 0.3);
        }

        .search-help {
            font-size: 13px;
            color: #666;
            text-align: center;
        }

        .results-info {
            text-align: center;
            padding: 20px;
            background: #e7f3ff;
            border-radius: 5px;
            margin-bottom: 20px;
            border-left: 4px solid #007bff;
        }

        .results-info h3 {
            color: #333;
            margin-bottom: 10px;
            font-size: 20px;
        }

        .results-info p {
            color: #666;
            font-size: 14px;
        }

        .results-info .stats {
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-top: 15px;
            flex-wrap: wrap;
        }

        .stat-item {
            background: white;
            padding: 10px 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }

        .stat-number {
            font-size: 24px;
            font-weight: bold;
            color: #007bff;
        }

        .stat-label {
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
        }

        .print-button-container {
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(40, 167, 69, 0.2);
        }

        .print-button-container p {
            color: white;
            margin-bottom: 15px;
            font-size: 14px;
        }

        /* Estilos para impresión */
        .formulario {
            border: 2px solid #000;
            padding: 12px;
            margin-bottom: 20px;
            background: white;
            font-family: Arial, sans-serif;
            page-break-inside: avoid;
            position: relative;
        }

        .formulario-logo {
            position: absolute;
            top: 10px;
            right: 10px;
            max-height: 50px;
            max-width: 120px;
        }

        .formulario-header {
            margin-bottom: 8px;
        }

        .formulario-row {
            margin-bottom: 8px;
            font-size: 13px;
            line-height: 1.5;
        }

        .formulario-row-telefono {
            margin-bottom: 8px;
            font-size: 13px;
            line-height: 1.5;
            white-space: nowrap;
        }

        .formulario-label {
            font-weight: bold;
            display: inline-block;
            min-width: 90px;
        }

        .formulario-line {
            border-bottom: 1px solid #000;
            display: inline-block;
            min-width: 300px;
            margin-left: 10px;
        }

        .formulario-line-telefono {
            border-bottom: 1px solid #000;
            display: inline-block;
            width: 200px;
            margin-left: 10px;
        }

        .formulario-nota {
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px solid #000;
            font-size: 11px;
            line-height: 1.4;
        }

        /* Estilos para imprimir */
        @media print {
            body {
                background: white;
                padding: 0;
                margin: 0;
            }

            .screen-only {
                display: none !important;
            }

            .formulario {
                border: 2px solid #000;
                padding: 12px;
                margin: 0 0 0.25in 0;
                page-break-inside: avoid;
                position: relative;
            }

            .formulario-logo {
                position: absolute;
                top: 10px;
                right: 10px;
                max-height: 50px;
                max-width: 120px;
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }

            .formulario-row-telefono {
                white-space: nowrap;
            }

            /* 3 formularios por página */
            .formulario:nth-child(3n) {
                page-break-after: always;
                margin-bottom: 0;
            }

            @page {
                size: 8.5in 11in;
                margin: 0.4in 0.5in;
            }
        }

        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #6c757d;
        }

        .empty-state i {
            font-size: 64px;
            color: #dee2e6;
            margin-bottom: 20px;
        }

        .empty-state h3 {
            font-size: 24px;
            margin-bottom: 10px;
        }

        .alert {
            padding: 15px 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            border-left: 4px solid;
        }

        .alert-warning {
            background: #fff3cd;
            border-color: #ffc107;
            color: #856404;
        }

        .alert-info {
            background: #d1ecf1;
            border-color: #17a2b8;
            color: #0c5460;
        }
    </style>
</head>
<body>
    <!-- Sección visible solo en pantalla -->
    <div class="screen-only">
        <div class="header-screen">
            <?php if (!empty($config['logo_url'])): ?>
                <img src="<?php echo htmlspecialchars($config['logo_url']); ?>" alt="<?php echo htmlspecialchars($config['nombre_empresa']); ?>">
            <?php endif; ?>
            <h1>Formulario de Actualización de Datos de Contacto</h1>
        </div>

        <div class="search-section">
            <form method="GET" action="">
                <div class="search-box">
                    <input 
                        type="text" 
                        name="buscar" 
                        class="search-input" 
                        placeholder="Buscar por nombre, apellido, código de cliente o número de contrato..."
                        value="<?php echo htmlspecialchars($buscar); ?>"
                    >
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-search"></i> Buscar
                    </button>
                    <?php if (!empty($buscar)): ?>
                        <a href="direccion.php" class="btn btn-secondary">
                            <i class="fas fa-times"></i> Limpiar
                        </a>
                    <?php endif; ?>
                </div>
            </form>
            <div class="search-help">
                <i class="fas fa-info-circle"></i>
                <strong>Búsqueda múltiple:</strong> Para buscar varios contratos, sepárelos con comas. Ejemplo: 00001,00002,00003
            </div>
        </div>

        <?php if ($total_clientes > 0): ?>
            <div class="results-info">
                <?php if (!empty($buscar)): ?>
                    <h3><i class="fas fa-check-circle"></i> Resultados de Búsqueda</h3>
                    <p>Se encontraron <?php echo $total_clientes; ?> cliente(s) que coinciden con su búsqueda</p>
                <?php else: ?>
                    <h3><i class="fas fa-users"></i> Todos los Clientes Activos</h3>
                    <p>Mostrando todos los clientes activos con contratos vigentes</p>
                <?php endif; ?>
                
                <div class="stats">
                    <div class="stat-item">
                        <div class="stat-number"><?php echo $total_clientes; ?></div>
                        <div class="stat-label">Formularios</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number"><?php echo $total_paginas; ?></div>
                        <div class="stat-label">Páginas</div>
                    </div>
                </div>
            </div>

            <div class="print-button-container">
                <p><i class="fas fa-info-circle"></i> Haga clic en el botón para imprimir los formularios (3 por página)</p>
                <button onclick="window.print()" class="btn btn-success">
                    <i class="fas fa-print"></i> Imprimir <?php echo $total_clientes; ?> Formulario<?php echo $total_clientes != 1 ? 's' : ''; ?> (<?php echo $total_paginas; ?> página<?php echo $total_paginas != 1 ? 's' : ''; ?>)
                </button>
            </div>

            <?php if ($total_clientes > 50): ?>
                <div class="alert alert-warning">
                    <i class="fas fa-exclamation-triangle"></i>
                    <strong>Atención:</strong> Está a punto de imprimir <?php echo $total_clientes; ?> formularios (<?php echo $total_paginas; ?> páginas). 
                    Si desea imprimir menos formularios, utilice el buscador para filtrar los clientes específicos.
                </div>
            <?php endif; ?>

        <?php else: ?>
            <div class="empty-state">
                <i class="fas fa-exclamation-circle"></i>
                <h3>No se encontraron resultados</h3>
                <p>No hay clientes activos<?php echo !empty($buscar) ? ' que coincidan con su búsqueda' : ''; ?></p>
            </div>
        <?php endif; ?>
    </div>

    <!-- Formularios para imprimir -->
    <?php if (!empty($clientes)): ?>
        <?php foreach ($clientes as $cliente): ?>
            <div class="formulario">
                <?php if (!empty($config['logo_url'])): ?>
                    <img src="<?php echo htmlspecialchars($config['logo_url']); ?>" alt="Logo" class="formulario-logo">
                <?php endif; ?>
                
                <div class="formulario-header">
                    <div class="formulario-row">
                        <span class="formulario-label">CONTRATO:</span>
                        <?php echo htmlspecialchars($cliente['contratos']); ?>
                    </div>
                </div>

                <div class="formulario-row">
                    <span class="formulario-label">NOMBRE:</span>
                    <?php echo strtoupper(htmlspecialchars($cliente['nombre'] . ' ' . $cliente['apellidos'])); ?>
                </div>

                <div class="formulario-row-telefono">
                    <span class="formulario-label">TELEFONO:</span>
                    <span class="formulario-line-telefono"></span>
                    <span class="formulario-label" style="margin-left: 15px;">CELULAR:</span>
                    <span class="formulario-line-telefono"></span>
                </div>

                <div class="formulario-row">
                    <span class="formulario-label">DIRECCION:</span>
                    <span class="formulario-line" style="min-width: 500px;"></span>
                </div>

                <div class="formulario-row">
                    <span class="formulario-label">REFERENCIA:</span>
                    <span class="formulario-line" style="min-width: 500px;"></span>
                </div>

                <div class="formulario-nota">
                    <strong>NOTA:</strong> Estimado(a) cliente, necesitamos que actualice sus datos de contacto (dirección, teléfono y celular) para mantener nuestros registros al día y poder brindarle un mejor servicio. Por favor, complete este formulario con su información actual y entréguelo a su cobrador o en nuestras oficinas. <strong>¡Gracias por su colaboración!</strong>
                </div>
            </div>
        <?php endforeach; ?>
    <?php endif; ?>
</body>
</html>