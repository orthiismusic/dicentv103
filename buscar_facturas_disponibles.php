<?php
require_once 'config.php';
header('Content-Type: application/json; charset=utf-8');

if (!isset($_GET['cobrador_id'], $_GET['fecha'])) {
    echo json_encode(['success' => false, 'message' => 'Parámetros requeridos: cobrador_id y fecha.']);
    exit;
}

try {
    $sql = "
        SELECT
            f.id, f.numero_factura, f.monto, f.estado, f.mes_factura,
            c.numero_contrato, c.dia_cobro,
            cl.nombre AS cliente_nombre, cl.apellidos AS cliente_apellidos,
            af.fecha_asignacion
        FROM asignaciones_facturas af
        JOIN facturas  f  ON af.factura_id  = f.id
        JOIN contratos c  ON f.contrato_id  = c.id
        JOIN clientes  cl ON c.cliente_id   = cl.id
        WHERE af.cobrador_id    = ?
          AND af.fecha_asignacion = ?
          AND af.estado          = 'activa'
    ";
    $params = [$_GET['cobrador_id'], $_GET['fecha']];

    if (!empty($_GET['estado'])) {
        $sql .= " AND f.estado = ?";
        $params[] = $_GET['estado'];
    }

    $sql .= " ORDER BY c.dia_cobro ASC, cl.nombre ASC";

    $stmt = $conn->prepare($sql);
    $stmt->execute($params);
    $facturas = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode([
        'success'  => true,
        'facturas' => $facturas,
        'totales'  => [
            'cantidad' => count($facturas),
            'monto'    => array_sum(array_column($facturas, 'monto'))
        ]
    ]);

} catch (PDOException $e) {
    error_log("Error en buscar_facturas_disponibles: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Error al buscar las facturas.']);
}
?>