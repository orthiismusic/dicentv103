<?php
require_once 'config.php';
header('Content-Type: application/json; charset=utf-8');

if (!isset($_GET['id'])) {
    echo json_encode(['success' => false, 'message' => 'ID no proporcionado.']);
    exit;
}

try {
    $stmt = $conn->prepare("
        SELECT
            af.id, af.fecha_asignacion, af.estado,
            f.id AS factura_id, f.numero_factura, f.monto, f.estado AS factura_estado,
            c.numero_contrato,
            cl.nombre AS cliente_nombre, cl.apellidos AS cliente_apellidos,
            co.id AS cobrador_id, co.codigo AS cobrador_codigo,
            co.nombre_completo AS cobrador_nombre
        FROM asignaciones_facturas af
        JOIN facturas  f  ON af.factura_id  = f.id
        JOIN contratos c  ON f.contrato_id  = c.id
        JOIN clientes  cl ON c.cliente_id   = cl.id
        JOIN cobradores co ON af.cobrador_id = co.id
        WHERE af.id = ?
    ");
    $stmt->execute([$_GET['id']]);
    $a = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$a) {
        echo json_encode(['success' => false, 'message' => 'Asignación no encontrada.']);
        exit;
    }

    echo json_encode([
        'success' => true,
        'asignacion' => [
            'id'                       => $a['id'],
            'fecha_asignacion'         => $a['fecha_asignacion'],
            'fecha_asignacion_formatted'=> date('d/m/Y', strtotime($a['fecha_asignacion'])),
            'estado'                   => $a['estado'],
            'factura' => [
                'id'             => $a['factura_id'],
                'numero_factura' => $a['numero_factura'],
                'monto'          => $a['monto'],
                'estado'         => $a['factura_estado'],
                'contrato'       => $a['numero_contrato'],
                'cliente'        => $a['cliente_nombre'] . ' ' . $a['cliente_apellidos']
            ],
            'cobrador' => [
                'id'     => $a['cobrador_id'],
                'codigo' => $a['cobrador_codigo'],
                'nombre' => $a['cobrador_nombre']
            ]
        ]
    ]);

} catch (PDOException $e) {
    error_log("Error en obtener_asignacion: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Error interno del servidor.']);
}
?>