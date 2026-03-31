<?php
require_once 'config.php';
verificarSesion();

header('Content-Type: application/json');

try {
    $where = "1=1";
    $params = [];

    // Filtro por estado
    if (!empty($_GET['estado']) && $_GET['estado'] !== 'todas') {
        $where .= " AND f.estado = ?";
        $params[] = $_GET['estado'];
    }

    // Filtro por contrato
    if (!empty($_GET['contrato'])) {
        $where .= " AND c.numero_contrato = ?";
        $params[] = $_GET['contrato'];
    }

    // Filtro por día de cobro desde
    if (!empty($_GET['dia_cobro_desde'])) {
        $where .= " AND c.dia_cobro >= ?";
        $params[] = $_GET['dia_cobro_desde'];
    }

    // Filtro por día de cobro hasta
    if (!empty($_GET['dia_cobro_hasta'])) {
        $where .= " AND c.dia_cobro <= ?";
        $params[] = $_GET['dia_cobro_hasta'];
    }

    // Filtro por fecha de emisión
    if (!empty($_GET['fecha_desde'])) {
        $where .= " AND f.fecha_emision >= ?";
        $params[] = $_GET['fecha_desde'];
    }

    if (!empty($_GET['fecha_hasta'])) {
        $where .= " AND f.fecha_emision <= ?";
        $params[] = $_GET['fecha_hasta'];
    }

    // Filtro por mes de factura
    if (!empty($_GET['mes_hasta'])) {
        // Convertir el formato HTML month (yyyy-mm) a fecha
        $fecha_hasta = DateTime::createFromFormat('Y-m', $_GET['mes_hasta']);
        $mes_hasta = $fecha_hasta->format('m/Y');
        
        // Extraer año y mes para comparación
        list($mes_hasta_num, $año_hasta) = explode('/', $mes_hasta);
        $fecha_hasta_comp = sprintf("%04d%02d", $año_hasta, $mes_hasta_num);
        
        $where .= " AND CONCAT(
            SUBSTRING_INDEX(f.mes_factura, '/', -1),
            LPAD(SUBSTRING_INDEX(f.mes_factura, '/', 1), 2, '0')
        ) <= ?";
        $params[] = $fecha_hasta_comp;
    }

    // Filtro por estatus del contrato
    if (!empty($_GET['estatus_contrato'])) {
        $where .= " AND c.estado = ?";
        $params[] = $_GET['estatus_contrato'];
    }

    if (!empty($_GET['mes_hasta'])) {
        // Convertir el formato HTML month (yyyy-mm) a fecha
        $fecha_hasta = DateTime::createFromFormat('Y-m', $_GET['mes_hasta']);
        $mes_hasta = $fecha_hasta->format('m/Y');
        
        // Extraer año y mes para comparación
        list($mes_hasta_num, $año_hasta) = explode('/', $mes_hasta);
        $fecha_hasta_comp = sprintf("%04d%02d", $año_hasta, $mes_hasta_num);
        
        $where .= " AND CONCAT(
            SUBSTRING_INDEX(f.mes_factura, '/', -1),
            LPAD(SUBSTRING_INDEX(f.mes_factura, '/', 1), 2, '0')
        ) <= ?";
        $params[] = $fecha_hasta_comp;
    }

    $sql = "
    SELECT f.*, 
           c.numero_contrato,
           c.dia_cobro,
           cl.nombre as cliente_nombre, 
           cl.apellidos as cliente_apellidos,
           (
               SELECT COUNT(*)
               FROM asignaciones_facturas af 
               WHERE af.factura_id = f.id 
               AND af.estado = 'activa'
           ) as esta_asignada
    FROM facturas f
    JOIN contratos c ON f.contrato_id = c.id
    JOIN clientes cl ON c.cliente_id = cl.id
    WHERE $where
    ORDER BY CAST(f.numero_factura AS UNSIGNED) DESC
";

    $stmt = $conn->prepare($sql);
    $stmt->execute($params);
    $facturas = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode($facturas);

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'error' => true,
        'mensaje' => $e->getMessage()
    ]);
}
?>