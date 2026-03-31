<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Configuración de la base de datos
$servername = "localhost";
$username = "xygfyvca_disen";
$password = "*Camil7172*";
$dbname = "xygfyvca_disen";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Conexión fallida: " . $conn->connect_error);
}

// Obtener el parámetro de búsqueda si existe
$search_query = isset($_GET['search']) ? $_GET['search'] : '';
$modo = isset($_GET['modo']) ? $_GET['modo'] : 'todos';
$selected_ids = [];

if ($modo === 'individual' && isset($_GET['ids'])) {
    $selected_ids = explode(',', $_GET['ids']);
}

// Consulta SQL base
$sql_base = "
    SELECT
        c.id as contrato_id,
        c.numero_contrato,
        c.fecha_inicio,
        cl.id as cliente_id,
        cl.nombre as cliente_nombre,
        cl.apellidos as cliente_apellidos,
        cl.cedula,
        cl.codigo as cliente_codigo,
        cl.fecha_nacimiento as cliente_fecha_nacimiento,
        p.nombre as plan_nombre,
        d.id as dependiente_id,
        d.nombre as dependiente_nombre,
        d.apellidos as dependiente_apellidos,
        d.identificacion as dependiente_cedula,
        d.fecha_nacimiento as dependiente_fecha_nacimiento,
        d.fecha_registro as dependiente_fecha_registro
    FROM contratos c
    JOIN clientes cl ON c.cliente_id = cl.id
    JOIN planes p ON c.plan_id = p.id
    LEFT JOIN dependientes d ON c.id = d.contrato_id AND d.estado = 'activo'
    WHERE c.estado = 'activo'
";

// Agregar condiciones según el modo
if ($modo === 'todos') {
    // Modo todos: filtrar solo por búsqueda
    $sql = $sql_base . " AND (c.numero_contrato LIKE ? OR cl.nombre LIKE ? OR cl.apellidos LIKE ? OR d.nombre LIKE ? OR d.apellidos LIKE ?)";
    $stmt = $conn->prepare($sql);
    $search_param = "%$search_query%";
    $stmt->bind_param("sssss", $search_param, $search_param, $search_param, $search_param, $search_param);
} else {
    // Modo individual: filtrar por IDs seleccionados
    $titular_ids = [];
    $dependiente_ids = [];
    
    foreach ($selected_ids as $id) {
        if (strpos($id, 'T_') === 0) {
            $titular_ids[] = substr($id, 2); // Quitar el prefijo T_
        } elseif (strpos($id, 'D_') === 0) {
            $dependiente_ids[] = substr($id, 2); // Quitar el prefijo D_
        }
    }
    
    $conditions = [];
    $params = [];
    $types = '';
    
    // Agregar condición de búsqueda si existe
    if (!empty($search_query)) {
        $conditions[] = "(c.numero_contrato LIKE ? OR cl.nombre LIKE ? OR cl.apellidos LIKE ? OR d.nombre LIKE ? OR d.apellidos LIKE ?)";
        $params[] = "%$search_query%";
        $params[] = "%$search_query%";
        $params[] = "%$search_query%";
        $params[] = "%$search_query%";
        $params[] = "%$search_query%";
        $types .= 'sssss';
    }
    
    // Agregar condición para titulares seleccionados
    if (!empty($titular_ids)) {
        $placeholders = str_repeat('?,', count($titular_ids) - 1) . '?';
        $conditions[] = "c.id IN ($placeholders)";
        foreach ($titular_ids as $id) {
            $params[] = $id;
            $types .= 'i';
        }
    }
    
    // Agregar condición para dependientes seleccionados
    if (!empty($dependiente_ids)) {
        $placeholders = str_repeat('?,', count($dependiente_ids) - 1) . '?';
        $conditions[] = "d.id IN ($placeholders)";
        foreach ($dependiente_ids as $id) {
            $params[] = $id;
            $types .= 'i';
        }
    }
    
    // Si no hay condiciones, mostrar al menos algo
    if (empty($conditions)) {
        $conditions[] = "1=0"; // No mostrar nada si no hay filtros
    }
    
    // Combinar condiciones
    $sql = $sql_base . " AND (" . implode(' OR ', $conditions) . ")";
    
    $stmt = $conn->prepare($sql);
    if (!empty($params)) {
        $stmt->bind_param($types, ...$params);
    }
}

if (!$stmt) {
    die("Error en la preparación de la consulta: " . $conn->error);
}

if (!$stmt->execute()) {
    die("Error al ejecutar la consulta: " . $stmt->error);
}

$result = $stmt->get_result();
$registros = $result->fetch_all(MYSQLI_ASSOC);

// Agrupar por contrato y cliente
$carnets = [];
foreach ($registros as $row) {
    $contrato_id = $row['contrato_id'];
    
    // Para modo individual, verificamos si este carnet fue seleccionado
    $incluir_titular = $modo === 'todos' || in_array('T_' . $row['contrato_id'], $selected_ids);
    $incluir_dependiente = $row['dependiente_id'] && ($modo === 'todos' || in_array('D_' . $row['dependiente_id'], $selected_ids));
    
    if ($incluir_titular && !isset($carnets[$contrato_id])) {
        $carnets[$contrato_id] = [
            'titular' => $row,
            'dependientes' => []
        ];
    }
    
    if ($incluir_dependiente) {
        if (!isset($carnets[$contrato_id])) {
            // Si el dependiente está seleccionado pero el titular no, creamos un registro para el contrato de todos modos
            $carnets[$contrato_id] = [
                'titular' => null,
                'dependientes' => []
            ];
        }
        $carnets[$contrato_id]['dependientes'][] = $row;
    }
}

// Función para formatear fecha con meses en español
function formatearFecha($fecha) {
    $meses_es = [
        'Jan' => 'Ene',
        'Feb' => 'Feb',
        'Mar' => 'Mar',
        'Apr' => 'Abr',
        'May' => 'May',
        'Jun' => 'Jun',
        'Jul' => 'Jul',
        'Aug' => 'Ago',
        'Sep' => 'Sep',
        'Oct' => 'Oct',
        'Nov' => 'Nov',
        'Dec' => 'Dic'
    ];
    
    $fecha_formateada = date('d/M/Y', strtotime($fecha));
    
    // Reemplazar el nombre del mes en inglés por su equivalente en español
    foreach ($meses_es as $mes_en => $mes_es) {
        $fecha_formateada = str_replace($mes_en, $mes_es, $fecha_formateada);
    }
    
    return $fecha_formateada;
}

// Función para generar HTML del carnet
function generarCarnetHtml($datos, $es_titular) {
    $numero_contrato = $datos['numero_contrato'];
    
    // CAMBIO PRINCIPAL: Determinar qué fecha usar según el tipo de usuario
    if ($es_titular) {
        $fecha_inicio = formatearFecha($datos['fecha_inicio']); // Titulares usan fecha_inicio del contrato
    } else {
        // Dependientes usan fecha_registro, pero si está vacía o es 0000-00-00, usar fecha_inicio como respaldo
        if (!empty($datos['dependiente_fecha_registro']) && $datos['dependiente_fecha_registro'] !== '0000-00-00') {
            $fecha_inicio = formatearFecha($datos['dependiente_fecha_registro']);
        } else {
            $fecha_inicio = formatearFecha($datos['fecha_inicio']); // Respaldo si no hay fecha_registro válida
        }
    }
    
    $plan = $datos['plan_nombre'];

    if ($es_titular) {
        $nombre = $datos['cliente_nombre'] . ' ' . $datos['cliente_apellidos'];
        $tipo = 'CONTRATANTE';
        $fecha_nacimiento = formatearFecha($datos['cliente_fecha_nacimiento']);
    } else {
        $nombre = $datos['dependiente_nombre'] . ' ' . $datos['dependiente_apellidos'];
        $tipo = 'DEPENDIENTE';
        $fecha_nacimiento = formatearFecha($datos['dependiente_fecha_nacimiento']);
    }

    return '
    <div class="carnet">
        <div class="carnet-left">
            <div class="carnet-info">
                <div class="nombre">'.htmlspecialchars($nombre).'</div>
                <div class="tipo">'.htmlspecialchars($tipo).'</div>
                <div class="contrato">Contrato: '.htmlspecialchars($numero_contrato).'</div>
                <div class="fecha">Fecha de nacimiento: '.htmlspecialchars($fecha_nacimiento).'</div>
                <div class="fecha">Fecha de inicio: '.htmlspecialchars($fecha_inicio).'</div>
                <div class="plan">Plan: '.htmlspecialchars($plan).'</div>
            </div>
        </div>
        <div class="carnet-right"></div>
    </div>';
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Imprimir Carnets</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Forzar el modo de color en la impresión -->
    <meta name="color-scheme" content="light">
    <meta name="forced-colors" content="none">
    <style>
    @page {
        size: letter;
        margin: 0.5cm;
    }

    body {
        margin: 0;
        padding: 0;
        background: white;
    }

    /* Estilos generales */
    .carnet-container {
        display: flex;
        flex-wrap: wrap;
        gap: 20px;
        padding: 20px;
    }

    .carnet {
        display: flex;
        width: 17cm;
        height: 5.5cm;
        position: relative;
        border: 1px solid #ddd;
        page-break-inside: avoid;
    }

    /* Estilos específicos para impresión */
    @media print {
        .carnet-left {
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
            color-adjust: exact !important;
        }

        .carnet-right {
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
            color-adjust: exact !important;
        }

        .page-break {
            page-break-after: always;
            break-after: page;
        }
    }

    .carnet-left {
        width: 50%;
        background-image: url('assets/carnets/Carnet1-cover.png');
        background-size: cover;
        background-repeat: no-repeat;
        background-position: center;
        position: relative;
    }

    .carnet-right {
        width: 50%;
        background-image: url('assets/carnets/Carnet2-cover.png');
        background-size: cover;
        background-repeat: no-repeat;
        background-position: center;
    }

    .carnet-info {
        position: absolute;
        bottom: 10px;
        left: 15px;
        color: black;
        font-family: Arial, sans-serif;
    }

    .nombre {
        font-size: 12px;
        font-weight: bold;
        margin-bottom: 3px;
    }

    .tipo {
        font-size: 12px;
        font-weight: bold;
        margin-bottom: 5px;
    }

    .contrato, .fecha, .plan {
        font-size: 10px;
    }
</style>
</head>
<body>
    <div class="carnet-container">
        <?php
        if (empty($carnets)) {
            echo "<p>No se encontraron carnets para mostrar.</p>";
        } else {
            $contador = 0;
            foreach ($carnets as $contrato_id => $data) {
                // Imprimir titular si existe y debe incluirse
                if (!empty($data['titular'])) {
                    echo generarCarnetHtml($data['titular'], true);
                    $contador++;
                }

                // Dependientes
                foreach ($data['dependientes'] as $dependiente) {
                    echo generarCarnetHtml($dependiente, false);
                    $contador++;
                }

                // Salto de página cada 5 carnets
                if ($contador % 5 === 0) {
                    echo '<div class="page-break"></div>';
                }
            }
        }
        ?>
    </div>

    <script>
        // Esperar a que todo se cargue antes de imprimir
        window.onload = function() {
            window.print();
        }
    </script>
</body>
</html>