<?php
require_once 'header.php';

error_reporting(E_ALL);
ini_set('display_errors', 1);

// Asegúrate de que la conexión a la base de datos esté configurada
$servername = "localhost";
$username = "xygfyvca_disen";
$password = "*Camil7172*";
$dbname = "xygfyvca_disen";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Conexión fallida: " . $conn->connect_error);
}

// Procesar el formulario de búsqueda
$search_query = '';
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['search'])) {
    $search_query = $_POST['search'];
}

// 1. Obtener todos los contratos activos con sus clientes y dependientes
$stmt = $conn->prepare("
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
    AND (c.numero_contrato LIKE ? OR cl.nombre LIKE ? OR cl.apellidos LIKE ? OR d.nombre LIKE ? OR d.apellidos LIKE ?)
    ORDER BY c.id, d.id
");
$search_param = "%$search_query%";
$stmt->bind_param("sssss", $search_param, $search_param, $search_param, $search_param, $search_param);
$stmt->execute();
$registros = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

// 2. Agrupar por contrato y cliente
$carnets = [];
foreach ($registros as $row) {
    $contrato_id = $row['contrato_id'];

    if (!isset($carnets[$contrato_id])) {
        // Agregar titular
        $carnets[$contrato_id] = [
            'titular' => $row,
            'dependientes' => []
        ];
    }

    // Agregar dependientes si existen
    if ($row['dependiente_id']) {
        $carnets[$contrato_id]['dependientes'][] = $row;
    }
}

// 3. Configurar paginación para impresión
$carnets_por_pagina = 5;
$total_carnets = count($carnets);
$total_paginas = ceil($total_carnets / $carnets_por_pagina);
?>

<style>
    /* Estilos para el contenedor de búsqueda */
    .search-container {
        display: flex;
        justify-content: center;
        align-items: center;
        margin-bottom: 10px;
        padding: 10px;
        background-color: #f8f9fa;
        border-radius: 8px;
    }
    
    .search-container form {
        display: flex;
        align-items: center;
        width: 100%;
        justify-content: center;
        margin-bottom: 0;
    }
    
    /* Estilo común para todos los elementos interactivos */
    .search-container input[type="text"],
    .search-container button {
        height: 42px;
        box-sizing: border-box;
        vertical-align: middle;
    }
    
    .search-container input[type="text"] {
        padding: 10px;
        width: 400px;
        font-size: 16px;
        border: 1px solid #ced4da;
        border-radius: 4px 0 0 4px;
    }
    
    .search-container button[type="submit"] {
        padding: 0 20px;
        font-size: 16px;
        background-color: #2196F3;
        color: white;
        border: none;
        border-radius: 0 4px 4px 0;
        cursor: pointer;
        margin-right: 15px;
    }

    /* Estilos para el switch de modo de impresión */
    .print-mode-switch {
        display: flex;
        align-items: center;
        margin: 0 15px;
        height: 42px;
    }
    
    .switch-label {
        display: flex;
        align-items: center;
        cursor: pointer;
    }
    
    .switch {
        position: relative;
        display: inline-block;
        width: 60px;
        height: 30px;
        margin: 0 10px;
    }
    
    .switch input {
        opacity: 0;
        width: 0;
        height: 0;
    }
    
    .slider {
        position: absolute;
        cursor: pointer;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background-color: #2196F3;
        transition: .4s;
    }
    
    .slider:before {
        position: absolute;
        content: "";
        height: 22px;
        width: 22px;
        left: 4px;
        bottom: 4px;
        background-color: white;
        transition: .4s;
    }
    
    input:checked + .slider {
        background-color: #9e9e9e;
    }
    
    input:checked + .slider:before {
        transform: translateX(30px);
    }
    
    .slider.round {
        border-radius: 34px;
    }
    
    .slider.round:before {
        border-radius: 50%;
    }
    
    .modo-todos, .modo-individual {
        font-weight: bold;
    }
    
    .modo-todos.active, .modo-individual.active {
        color: #2196F3;
    }
    
    /* Nuevo estilo para el botón flotante de imprimir carnets */
    #btnImprimirCarnets {
        position: fixed;
        bottom: 30px;
        right: 30px;
        width: auto;
        padding: 10px 20px;
        font-size: 16px;
        background-color: #2196F3;
        color: white;
        border: none;
        border-radius: 50px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
        cursor: pointer;
        z-index: 1000;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: background-color 0.3s, transform 0.2s;
    }
    
    #btnImprimirCarnets:hover {
        background-color: #0d8aee;
        transform: scale(1.05);
    }
    
    #btnImprimirCarnets i {
        margin-right: 8px;
    }
    
    /* El resto de los estilos permanecen igual */
    .select-checkbox {
        position: absolute;
        top: 10px;
        right: 10px;
        z-index: 10;
        transform: scale(1.5);
        display: none; /* Oculto por defecto */
    }
    
    .carnet {
        position: relative; /* Para posicionar el checkbox */
    }

    /* Estilos para impresión */
    @media print {
        @page {
            size: letter; /* Tamaño carta 8.5x11 pulgadas */
            margin: 0.5cm;
        }

        .page-break {
            page-break-after: always;
            break-after: page;
        }

        .carnet-container {
            background-color: white !important;
            -webkit-print-color-adjust: exact;
        }

        /* Ocultar elementos que no se deben imprimir */
        .search-container, .btn-primary, header, footer, nav, #btnImprimirCarnets {
            display: none;
        }
    }

    /* Contenedor principal - reduciendo el espacio superior */
    .carnet-container {
        display: flex;
        flex-wrap: wrap;
        gap: 20px;
        padding: 10px 20px;
        margin-top: 0;
    }

    /* Estilo individual del carnet */
    .carnet {
        display: flex;
        width: 17cm;
        height: 5.5cm;
        position: relative;
        border: 1px solid #ddd;
        page-break-inside: avoid;
    }

    /* Imagen 1 */
    .carnet-left {
        width: 50%;
        background-image: url('assets/carnets/Carnet1-cover.png');
        background-size: cover;
        background-repeat: no-repeat;
        background-position: center;
        position: relative;
    }

    /* Imagen 2 */
    .carnet-right {
        width: 50%;
        background-image: url('assets/carnets/Carnet2-cover.png');
        background-size: cover;
        background-repeat: no-repeat;
        background-position: center;
    }

    /* Posicionamiento de datos */
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

<div class="search-container">
    <form method="post" action="carnet.php">
        <input type="text" name="search" placeholder="Buscar por contrato o nombre..." value="<?php echo htmlspecialchars($search_query); ?>">
        <button type="submit">Buscar</button>
    </form>
    
    <div class="print-mode-switch mt-3">
        <label class="switch-label">
            <span class="modo-todos active">Todos</span>
            <label class="switch">
                <input type="checkbox" id="printModeSwitch">
                <span class="slider round"></span>
            </label>
            <span class="modo-individual">Individual</span>
        </label>
    </div>
</div>
    
    <div class="text-center mb-4">
    <div class="text-center mb-4">
    <button id="btnImprimirCarnets" class="btn btn-primary">
        <i class="fas fa-print"></i> Imprimir Carnets
    </button>


<script>
    document.addEventListener('DOMContentLoaded', function() {
        const switchBtn = document.getElementById('printModeSwitch');
        const modoTodos = document.querySelector('.modo-todos');
        const modoIndividual = document.querySelector('.modo-individual');
        const checkboxes = document.querySelectorAll('.select-checkbox');
        const btnImprimir = document.getElementById('btnImprimirCarnets');
        
        // Estado inicial
        let modoSeleccion = 'todos';
        
        // Función para cambiar el modo
        switchBtn.addEventListener('change', function() {
            if (this.checked) {
                // Modo individual
                modoSeleccion = 'individual';
                modoTodos.classList.remove('active');
                modoIndividual.classList.add('active');
                checkboxes.forEach(cb => {
                    cb.style.display = 'block';
                });
            } else {
                // Modo todos
                modoSeleccion = 'todos';
                modoIndividual.classList.remove('active');
                modoTodos.classList.add('active');
                checkboxes.forEach(cb => {
                    cb.style.display = 'none';
                });
            }
        });
        
        // Función para imprimir
        btnImprimir.addEventListener('click', function() {
            if (modoSeleccion === 'todos') {
                // Imprimir todos los carnets
                window.open('imprimir_carnets.php<?php echo $search_query ? "?search=".urlencode($search_query) : ""; ?>', '_blank');
            } else {
                // Imprimir carnets seleccionados
                const seleccionados = Array.from(document.querySelectorAll('.select-checkbox:checked')).map(cb => cb.value);
                
                if (seleccionados.length === 0) {
                    Swal.fire({
                        title: '¡Atención!',
                        text: 'Debe seleccionar al menos un carnet para imprimir.',
                        icon: 'warning',
                        confirmButtonColor: '#2563eb',
                        confirmButtonText: 'Entendido'
                    });
                    return;
                }
                
                const url = 'imprimir_carnets.php?modo=individual&ids=' + seleccionados.join(',') + 
                            '<?php echo $search_query ? "&search=".urlencode($search_query) : ""; ?>';
                window.open(url, '_blank');
            }
        });
    });
</script>

</div>
    
    
    
    
</div>

<div class="carnet-container">
    <?php
    $contador = 0;
    foreach ($carnets as $contrato_id => $data):
        $contador++;

        // Titular
        echo generarCarnetHtml($data['titular'], true);

        // Dependientes
        foreach ($data['dependientes'] as $dependiente) {
            echo generarCarnetHtml($dependiente, false);
            $contador++;
        }

        // Salto de página cada 5 carnets
        if ($contador % $carnets_por_pagina === 0) {
            echo '<div class="page-break"></div>';
        }
    endforeach;
    ?>
</div>






<?php

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


// Función para generar HTML de cada carnet
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
    $carnet_id = $es_titular ? 'T_'.$datos['contrato_id'] : 'D_'.$datos['dependiente_id'];

    if ($es_titular) {
        $nombre = $datos['cliente_nombre'] . ' ' . $datos['cliente_apellidos'];
        $tipo = 'CONTRATANTE';
        $fecha_nacimiento = formatearFecha($datos['cliente_fecha_nacimiento']);
    } else {
        $nombre = $datos['dependiente_nombre'] . ' ' . $datos['dependiente_apellidos'];
        $tipo = 'DEPENDIENTE';
        $fecha_nacimiento = formatearFecha($datos['dependiente_fecha_nacimiento']);
    }

    $info_html = '
    <div class="carnet-info">
        <div class="nombre">'.htmlspecialchars($nombre).'</div>
        <div class="tipo">'.htmlspecialchars($tipo).'</div>
        <div class="contrato">Contrato: '.htmlspecialchars($numero_contrato).'</div>
        <div class="fecha">Fecha de nacimiento: '.htmlspecialchars($fecha_nacimiento).'</div>
        <div class="fecha">Fecha de inicio: '.htmlspecialchars($fecha_inicio).'</div>
        <div class="plan">Plan: '.htmlspecialchars($plan).'</div>
    </div>';

    return '
    <div class="carnet" data-id="'.$carnet_id.'">
        <input type="checkbox" class="select-checkbox" value="'.$carnet_id.'">
        <div class="carnet-left">
            '.$info_html.'
        </div>
        <div class="carnet-right"></div>
    </div>';
}


require_once 'footer.php';
?>