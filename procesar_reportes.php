<?php
/**
 * procesar_reportes.php
 * Contiene todas las funciones de procesamiento de reportes
 */

/**
 * Procesa reportes generales
 */
function procesarReporteGeneral($conn, $datos) {
    $resultado = [
        'totalRegistros' => 0,
        'totalMontos' => 0,
        'distribucionPlanes' => [],
        'registros' => []
    ];

    try {
        $params = [
            ':fecha_desde' => $datos['fechaDesde'],
            ':fecha_hasta' => $datos['fechaHasta']
        ];

        switch ($datos['tipoReporte']) {
            case 'clientes_contratos':
                $sql = "
                    SELECT 
                        c.numero_contrato,
                        cl.nombre,
                        cl.apellidos,
                        p.nombre as plan,
                        c.fecha_inicio,
                        c.monto_total,
                        c.dia_cobro,
                        c.estado
                    FROM contratos c
                    JOIN clientes cl ON c.cliente_id = cl.id
                    JOIN planes p ON c.plan_id = p.id
                    WHERE c.fecha_inicio BETWEEN :fecha_desde AND :fecha_hasta
                    ORDER BY c.fecha_inicio DESC
                ";
                break;

            case 'contratos_dependientes':
                $sql = "
                    SELECT 
                        c.numero_contrato,
                        cl.nombre as titular_nombre,
                        cl.apellidos as titular_apellidos,
                        d.nombre as dependiente_nombre,
                        d.apellidos as dependiente_apellidos,
                        d.relacion,
                        p.nombre as plan
                    FROM contratos c
                    JOIN clientes cl ON c.cliente_id = cl.id
                    JOIN dependientes d ON c.id = d.contrato_id
                    JOIN planes p ON d.plan_id = p.id
                    WHERE c.fecha_inicio BETWEEN :fecha_desde AND :fecha_hasta
                    AND d.estado = 'activo'
                    ORDER BY c.numero_contrato, d.id
                ";
                break;

            case 'contratos_estado':
                $sql = "
                    SELECT 
                        c.estado,
                        COUNT(*) as total,
                        SUM(c.monto_total) as monto_total
                    FROM contratos c
                    WHERE c.fecha_inicio BETWEEN :fecha_desde AND :fecha_hasta
                    GROUP BY c.estado
                ";
                break;

            case 'contratos_vencidos':
                $sql = "
                    SELECT 
                        c.numero_contrato,
                        cl.nombre,
                        cl.apellidos,
                        p.nombre as plan,
                        c.fecha_inicio,
                        c.fecha_fin,
                        DATEDIFF(CURRENT_DATE, c.fecha_fin) as dias_vencido,
                        c.monto_total
                    FROM contratos c
                    JOIN clientes cl ON c.cliente_id = cl.id
                    JOIN planes p ON c.plan_id = p.id
                    WHERE c.fecha_fin < CURRENT_DATE
                    AND c.fecha_inicio BETWEEN :fecha_desde AND :fecha_hasta
                    ORDER BY c.fecha_fin DESC
                ";
                break;
                
                case 'clientes_estado':
                    $sql = "
                        SELECT 
                            c.estado,
                            COUNT(DISTINCT c.cliente_id) as total_clientes,
                            COUNT(c.id) as total_contratos,
                            SUM(c.monto_total) as monto_total,
                            COUNT(d.id) as total_dependientes
                        FROM clientes cl
                        LEFT JOIN contratos c ON cl.id = c.cliente_id
                        LEFT JOIN dependientes d ON c.id = d.contrato_id
                        WHERE c.fecha_inicio BETWEEN :fecha_desde AND :fecha_hasta
                        GROUP BY c.estado
                        ORDER BY total_clientes DESC
                    ";
                    break;

            default:
                throw new Exception('Tipo de reporte general no válido');
        }

        // Ejecutar consulta principal
        $stmt = $conn->prepare($sql);
        $stmt->execute($params);
        $resultado['registros'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $resultado['totalRegistros'] = count($resultado['registros']);

        // Calcular totales y métricas adicionales
        if (isset($resultado['registros'][0]['monto_total'])) {
            $resultado['totalMontos'] = array_sum(array_column($resultado['registros'], 'monto_total'));
        }

        // Obtener distribución por planes si es necesario
        if (in_array($datos['tipoReporte'], ['clientes_contratos', 'contratos_dependientes'])) {
            $sqlPlanes = "
                SELECT 
                    p.nombre,
                    COUNT(*) as cantidad,
                    SUM(c.monto_total) as total
                FROM contratos c
                JOIN planes p ON c.plan_id = p.id
                WHERE c.fecha_inicio BETWEEN :fecha_desde AND :fecha_hasta
                GROUP BY p.id, p.nombre
            ";
            
            $stmt = $conn->prepare($sqlPlanes);
            $stmt->execute($params);
            $resultado['distribucionPlanes'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        }

        return $resultado;

    } catch (PDOException $e) {
        throw new Exception("Error procesando reporte general: " . $e->getMessage());
    }
}


/**
 * Procesa reportes de facturación
 */
function procesarReporteFacturacion($conn, $datos) {
    $resultado = [
        'totalRegistros' => 0,
        'totalMontos' => 0,
        'distribucionPlanes' => [],
        'registros' => []
    ];

    try {
        $params = [
            ':fecha_desde' => $datos['fechaDesde'],
            ':fecha_hasta' => $datos['fechaHasta']
        ];

        switch ($datos['tipoReporte']) {
            case 'facturas_contratos':
                $sql = "
                    SELECT 
                        f.numero_factura,
                        c.numero_contrato,
                        cl.nombre,
                        cl.apellidos,
                        f.monto,
                        f.fecha_emision,
                        f.fecha_vencimiento,
                        f.estado,
                        p.nombre as plan
                    FROM facturas f
                    JOIN contratos c ON f.contrato_id = c.id
                    JOIN clientes cl ON c.cliente_id = cl.id
                    JOIN planes p ON c.plan_id = p.id
                    WHERE f.fecha_emision BETWEEN :fecha_desde AND :fecha_hasta
                ";
                break;

            case 'facturas_vencidas':
                $sql = "
                    SELECT 
                        f.numero_factura,
                        c.numero_contrato,
                        cl.nombre,
                        cl.apellidos,
                        f.monto,
                        f.fecha_vencimiento,
                        DATEDIFF(CURRENT_DATE, f.fecha_vencimiento) as dias_vencido,
                        p.nombre as plan
                    FROM facturas f
                    JOIN contratos c ON f.contrato_id = c.id
                    JOIN clientes cl ON c.cliente_id = cl.id
                    JOIN planes p ON c.plan_id = p.id
                    WHERE f.estado = 'vencida'
                    AND f.fecha_vencimiento BETWEEN :fecha_desde AND :fecha_hasta
                ";
                break;

            case 'pagos_recibidos':
                $sql = "
                    SELECT 
                        f.numero_factura,
                        p.fecha_pago,
                        p.monto,
                        p.metodo_pago,
                        p.referencia_pago,
                        cb.nombre_completo as cobrador,
                        cl.nombre,
                        cl.apellidos,
                        c.numero_contrato
                    FROM pagos p
                    JOIN facturas f ON p.factura_id = f.id
                    JOIN contratos c ON f.contrato_id = c.id
                    JOIN clientes cl ON c.cliente_id = cl.id
                    LEFT JOIN cobradores cb ON p.cobrador_id = cb.id
                    WHERE p.fecha_pago BETWEEN :fecha_desde AND :fecha_hasta
                    AND p.estado = 'procesado'
                ";
                break;

            case 'ingresos_plan':
                $sql = "
                    SELECT 
                        pl.nombre as plan,
                        COUNT(DISTINCT c.id) as total_contratos,
                        COUNT(f.id) as total_facturas,
                        SUM(f.monto) as monto_total,
                        ROUND(AVG(f.monto), 2) as promedio_factura
                    FROM planes pl
                    LEFT JOIN contratos c ON pl.id = c.plan_id
                    LEFT JOIN facturas f ON c.id = f.contrato_id
                    WHERE f.fecha_emision BETWEEN :fecha_desde AND :fecha_hasta
                    GROUP BY pl.id, pl.nombre
                ";
                break;

            default:
                throw new Exception('Tipo de reporte de facturación no válido');
        }

        // Agregar filtros adicionales si existen
        if (!empty($datos['estadoFactura'])) {
            $sql .= " AND f.estado = :estado";
            $params[':estado'] = $datos['estadoFactura'];
        }

        if (!empty($datos['planId'])) {
            $sql .= " AND c.plan_id = :plan_id";
            $params[':plan_id'] = $datos['planId'];
        }

        // Agregar ordenamiento
        if ($datos['tipoReporte'] != 'ingresos_plan') {
            $sql .= " ORDER BY ";
            switch ($datos['tipoReporte']) {
                case 'facturas_contratos':
                    $sql .= "f.fecha_emision DESC";
                    break;
                case 'facturas_vencidas':
                    $sql .= "f.fecha_vencimiento DESC";
                    break;
                case 'pagos_recibidos':
                    $sql .= "p.fecha_pago DESC";
                    break;
            }
        }

        // Ejecutar consulta principal
        $stmt = $conn->prepare($sql);
        $stmt->execute($params);
        $resultado['registros'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $resultado['totalRegistros'] = count($resultado['registros']);

        // Calcular totales
        if ($datos['tipoReporte'] != 'ingresos_plan') {
            $resultado['totalMontos'] = array_sum(array_column($resultado['registros'], 'monto'));
        } else {
            $resultado['totalMontos'] = array_sum(array_column($resultado['registros'], 'monto_total'));
        }

        // Obtener estadísticas adicionales si es necesario
        if ($datos['tipoReporte'] == 'facturas_vencidas') {
            $resultado['estadisticas'] = obtenerEstadisticasFacturasVencidas($conn, $params);
        }

        return $resultado;

    } catch (PDOException $e) {
        throw new Exception("Error procesando reporte de facturación: " . $e->getMessage());
    }
}


/**
 * Procesa reportes de personal
 */
function procesarReportePersonal($conn, $datos) {
    $resultado = [
        'totalRegistros' => 0,
        'totalMontos' => 0,
        'estadisticas' => [],
        'registros' => []
    ];

    try {
        $params = [
            ':fecha_desde' => $datos['fechaDesde'],
            ':fecha_hasta' => $datos['fechaHasta']
        ];

        switch ($datos['tipoReporte']) {
            case 'ventas_vendedor':
                // Agregar filtro por vendedor específico si se proporciona
                if (!empty($datos['personalId'])) {
                    $params[':vendedor_id'] = $datos['personalId'];
                    $whereVendedor = "AND v.id = :vendedor_id";
                } else {
                    $whereVendedor = "";
                }

                $sql = "
                    SELECT 
                        v.nombre_completo as vendedor,
                        COUNT(c.id) as total_contratos,
                        COUNT(DISTINCT c.cliente_id) as total_clientes,
                        SUM(c.monto_total) as monto_total,
                        p.nombre as plan,
                        COUNT(d.id) as total_dependientes,
                        AVG(c.monto_total) as promedio_contrato
                    FROM vendedores v
                    LEFT JOIN contratos c ON v.id = c.vendedor_id
                    LEFT JOIN planes p ON c.plan_id = p.id
                    LEFT JOIN dependientes d ON c.id = d.contrato_id
                    WHERE c.fecha_inicio BETWEEN :fecha_desde AND :fecha_hasta
                    $whereVendedor
                    GROUP BY v.id, v.nombre_completo, p.id, p.nombre
                    ORDER BY total_contratos DESC
                ";

                // Obtener métricas de eficiencia
                $sqlMetricas = "
                    SELECT 
                        v.id,
                        v.nombre_completo,
                        COUNT(DISTINCT c.id) as total_contratos,
                        SUM(c.monto_total) as total_ventas,
                        COUNT(DISTINCT CASE WHEN c.estado = 'activo' THEN c.id END) * 100.0 / 
                            NULLIF(COUNT(DISTINCT c.id), 0) as tasa_exito,
                        AVG(DATEDIFF(c.fecha_inicio, c.fecha_fin)) as promedio_duracion
                    FROM vendedores v
                    LEFT JOIN contratos c ON v.id = c.vendedor_id
                    WHERE c.fecha_inicio BETWEEN :fecha_desde AND :fecha_hasta
                    GROUP BY v.id, v.nombre_completo
                ";
                break;

            case 'cobros_cobrador':
                // Agregar filtro por cobrador específico si se proporciona
                if (!empty($datos['personalId'])) {
                    $params[':cobrador_id'] = $datos['personalId'];
                    $whereCobrador = "AND cb.id = :cobrador_id";
                } else {
                    $whereCobrador = "";
                }

                $sql = "
                    SELECT 
                        cb.nombre_completo as cobrador,
                        COUNT(p.id) as total_pagos,
                        SUM(p.monto) as monto_total,
                        p.metodo_pago,
                        COUNT(DISTINCT f.contrato_id) as total_contratos,
                        AVG(DATEDIFF(p.fecha_pago, f.fecha_emision)) as promedio_dias_cobro,
                        COUNT(CASE WHEN p.fecha_pago <= f.fecha_vencimiento THEN 1 END) * 100.0 / 
                            COUNT(*) as porcentaje_a_tiempo
                    FROM cobradores cb
                    JOIN pagos p ON cb.id = p.cobrador_id
                    JOIN facturas f ON p.factura_id = f.id
                    WHERE p.fecha_pago BETWEEN :fecha_desde AND :fecha_hasta
                    AND p.estado = 'procesado'
                    $whereCobrador
                    GROUP BY cb.id, cb.nombre_completo, p.metodo_pago
                    ORDER BY monto_total DESC
                ";

                // Obtener métricas de eficiencia de cobro
                $sqlMetricas = "
                    SELECT 
                        cb.id,
                        cb.nombre_completo,
                        COUNT(p.id) as total_cobros,
                        SUM(p.monto) as total_cobrado,
                        COUNT(CASE WHEN p.fecha_pago <= f.fecha_vencimiento THEN 1 END) * 100.0 / 
                            COUNT(*) as eficiencia_cobro,
                        AVG(DATEDIFF(p.fecha_pago, f.fecha_emision)) as tiempo_promedio_cobro
                    FROM cobradores cb
                    JOIN pagos p ON cb.id = p.cobrador_id
                    JOIN facturas f ON p.factura_id = f.id
                    WHERE p.fecha_pago BETWEEN :fecha_desde AND :fecha_hasta
                    GROUP BY cb.id, cb.nombre_completo
                ";
                break;

            default:
                throw new Exception('Tipo de reporte de personal no válido');
        }

        // Ejecutar consulta principal
        $stmt = $conn->prepare($sql);
        $stmt->execute($params);
        $resultado['registros'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $resultado['totalRegistros'] = count($resultado['registros']);

        // Obtener métricas adicionales
        $stmt = $conn->prepare($sqlMetricas);
        $stmt->execute($params);
        $resultado['estadisticas'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Calcular totales generales
        if (isset($resultado['registros'][0]['monto_total'])) {
            $resultado['totalMontos'] = array_sum(array_column($resultado['registros'], 'monto_total'));
        }

        return $resultado;

    } catch (PDOException $e) {
        throw new Exception("Error procesando reporte de personal: " . $e->getMessage());
    }
}



/**
 * Procesa reportes de planes
 */
function procesarReportePlanes($conn, $datos) {
    $resultado = [
        'totalRegistros' => 0,
        'totalMontos' => 0,
        'distribucionPlanes' => [],
        'registros' => []
    ];

    try {
        $params = [
            ':fecha_desde' => $datos['fechaDesde'],
            ':fecha_hasta' => $datos['fechaHasta']
        ];

        // Agregar filtro por plan específico si se proporciona
        $wherePlan = "";
        if (!empty($datos['planId'])) {
            $params[':plan_id'] = $datos['planId'];
            $wherePlan = "AND p.id = :plan_id";
        }

        switch ($datos['tipoReporte']) {
            case 'contratos_plan':
                $sql = "
                    SELECT 
                        p.nombre as plan,
                        COUNT(c.id) as total_contratos,
                        COUNT(DISTINCT c.cliente_id) as total_clientes,
                        COUNT(d.id) as total_dependientes,
                        SUM(c.monto_total) as monto_total,
                        AVG(c.monto_mensual) as promedio_mensual,
                        SUM(CASE WHEN c.estado = 'activo' THEN 1 ELSE 0 END) as contratos_activos,
                        SUM(CASE WHEN c.estado = 'cancelado' THEN 1 ELSE 0 END) as contratos_cancelados
                    FROM planes p
                    LEFT JOIN contratos c ON p.id = c.plan_id
                    LEFT JOIN dependientes d ON c.id = d.contrato_id
                    WHERE c.fecha_inicio BETWEEN :fecha_desde AND :fecha_hasta
                    $wherePlan
                    GROUP BY p.id, p.nombre
                    ORDER BY total_contratos DESC
                ";

                // Consulta adicional para métricas por plan
                $sqlMetricas = "
                    SELECT 
                        p.nombre,
                        AVG(DATEDIFF(CURRENT_DATE, c.fecha_inicio)) as promedio_duracion,
                        COUNT(DISTINCT c.cliente_id) * 100.0 / 
                            (SELECT COUNT(DISTINCT cliente_id) FROM contratos) as porcentaje_mercado
                    FROM planes p
                    JOIN contratos c ON p.id = c.plan_id
                    WHERE c.fecha_inicio BETWEEN :fecha_desde AND :fecha_hasta
                    $wherePlan
                    GROUP BY p.id, p.nombre
                ";
                break;

            case 'planes_populares':
                $sql = "
                    SELECT 
                        p.nombre as plan,
                        COUNT(c.id) as total_contratos,
                        SUM(c.monto_total) as monto_total,
                        COUNT(d.id) as total_dependientes,
                        DATE_FORMAT(c.fecha_inicio, '%Y-%m') as periodo,
                        COUNT(DISTINCT c.cliente_id) as clientes_unicos,
                        AVG(c.monto_mensual) as promedio_mensual,
                        SUM(c.monto_total) / COUNT(c.id) as ingreso_promedio_contrato
                    FROM planes p
                    LEFT JOIN contratos c ON p.id = c.plan_id
                    LEFT JOIN dependientes d ON c.id = d.contrato_id
                    WHERE c.fecha_inicio BETWEEN :fecha_desde AND :fecha_hasta
                    $wherePlan
                    GROUP BY 
                        p.id, 
                        p.nombre, 
                        DATE_FORMAT(c.fecha_inicio, '%Y-%m')
                    ORDER BY 
                        periodo ASC,
                        total_contratos DESC
                ";

                // Consulta para tendencia mensual
                $sqlTendencia = "
                    SELECT 
                        DATE_FORMAT(c.fecha_inicio, '%Y-%m') as mes,
                        p.nombre as plan,
                        COUNT(*) as cantidad_contratos,
                        SUM(c.monto_total) as monto_total
                    FROM contratos c
                    JOIN planes p ON c.plan_id = p.id
                    WHERE c.fecha_inicio BETWEEN :fecha_desde AND :fecha_hasta
                    $wherePlan
                    GROUP BY 
                        DATE_FORMAT(c.fecha_inicio, '%Y-%m'),
                        p.id, 
                        p.nombre
                    ORDER BY mes ASC
                ";
                break;

            default:
                throw new Exception('Tipo de reporte de planes no válido');
        }

        // Ejecutar consulta principal
        $stmt = $conn->prepare($sql);
        $stmt->execute($params);
        $resultado['registros'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $resultado['totalRegistros'] = count($resultado['registros']);

        // Obtener métricas adicionales
        if ($datos['tipoReporte'] == 'contratos_plan') {
            $stmt = $conn->prepare($sqlMetricas);
            $stmt->execute($params);
            $resultado['estadisticas'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        } elseif ($datos['tipoReporte'] == 'planes_populares') {
            $stmt = $conn->prepare($sqlTendencia);
            $stmt->execute($params);
            $resultado['tendencia'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        }

        // Calcular totales
        if (isset($resultado['registros'][0]['monto_total'])) {
            $resultado['totalMontos'] = array_sum(array_column($resultado['registros'], 'monto_total'));
        }

        // Preparar datos para gráficos
        $resultado['graficos'] = prepararDatosGraficosPlanes($resultado['registros'], $datos['tipoReporte']);

        return $resultado;

    } catch (PDOException $e) {
        throw new Exception("Error procesando reporte de planes: " . $e->getMessage());
    }
}

/**
 * Función auxiliar para preparar datos de gráficos
 */
function prepararDatosGraficosPlanes($registros, $tipoReporte) {
    $graficos = [];

    if ($tipoReporte == 'contratos_plan') {
        // Preparar datos para gráfico de distribución
        $graficos['distribucion'] = [
            'labels' => array_column($registros, 'plan'),
            'datasets' => [[
                'data' => array_column($registros, 'total_contratos'),
                'backgroundColor' => [
                    '#4e73df', '#1cc88a', '#36b9cc', '#f6c23e', '#e74a3b',
                    '#858796', '#f8f9fc', '#5a5c69', '#e3e6f0', '#d1d3e2'
                ]
            ]]
        ];
    } elseif ($tipoReporte == 'planes_populares') {
        // Preparar datos para gráfico de tendencia
        $periodos = array_unique(array_column($registros, 'periodo'));
        sort($periodos);
        // Limitar a los últimos 12 meses
        $periodos = array_slice($periodos, -12);

        $planes = array_unique(array_column($registros, 'plan'));
        $datasets = [];

        foreach ($planes as $plan) {
            $datos = [];
            foreach ($periodos as $periodo) {
                $valor = 0;
                foreach ($registros as $registro) {
                    if ($registro['plan'] == $plan && $registro['periodo'] == $periodo) {
                        $valor = $registro['total_contratos'];
                        break;
                    }
                }
                $datos[] = $valor;
            }
            $datasets[] = [
                'label' => $plan,
                'data' => $datos,
                'fill' => false
            ];
        }

        $graficos['tendencia'] = [
            'labels' => $periodos,
            'datasets' => $datasets
        ];
    }

    return $graficos;
}



