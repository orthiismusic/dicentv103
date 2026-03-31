<?php
/* ============================================================
   buscar_global.php — Búsqueda global AJAX
   Sistema ORTHIIS — Seguros de Vida
   Recibe: GET ?q=TERMINO
   Devuelve: JSON { resultados: [], tipo: '' }
   ============================================================ */
require_once 'config.php';
verificarSesion();

header('Content-Type: application/json; charset=utf-8');

$q = trim($_GET['q'] ?? '');
$resultados = [];

if (strlen($q) < 2) {
    echo json_encode(['resultados' => [], 'tipo' => 'vacio']);
    exit;
}

$esSoloNumero = ctype_digit($q);

/* ----------------------------------------------------------
   PRIORIDAD 1: Buscar por número de factura exacto
   (solo números, entre 5 y 7 dígitos)
   ---------------------------------------------------------- */
if ($esSoloNumero && strlen($q) >= 5 && strlen($q) <= 7) {
    $numFacturaPad = str_pad($q, 7, '0', STR_PAD_LEFT);
    $stmtF = $conn->prepare(
        "SELECT f.id, f.numero_factura, f.estado, f.monto, f.mes_factura,
                cl.nombre, cl.apellidos, c.numero_contrato
         FROM facturas f
         JOIN contratos c ON f.contrato_id = c.id
         JOIN clientes cl ON c.cliente_id = cl.id
         WHERE f.numero_factura = ? OR f.numero_factura = ?
         LIMIT 1"
    );
    $stmtF->execute([$numFacturaPad, $q]);
    $factura = $stmtF->fetch(PDO::FETCH_ASSOC);

    if ($factura) {
        $resultados[] = [
            'tipo'   => 'factura',
            'id'     => (int)$factura['id'],
            'titulo' => 'Factura #' . $factura['numero_factura'],
            'sub'    => $factura['nombre'] . ' ' . $factura['apellidos']
                        . ' — Contrato ' . $factura['numero_contrato']
                        . ' — ' . strtoupper($factura['estado']),
            'url'    => 'registrar_pago.php?factura_id=' . $factura['id'],
            'badge'  => isset($factura['monto']) ? 'RD$' . number_format((float)$factura['monto'], 2) : '',
        ];
        echo json_encode(['resultados' => $resultados, 'tipo' => 'factura']);
        exit;
    }
}

/* ----------------------------------------------------------
   PRIORIDAD 2: Buscar por número de contrato exacto
   (solo números, entre 3 y 6 dígitos)
   ---------------------------------------------------------- */
if ($esSoloNumero && strlen($q) >= 3 && strlen($q) <= 6) {
    $numContratoPad = str_pad($q, 5, '0', STR_PAD_LEFT);
    $stmtC = $conn->prepare(
        "SELECT c.id, c.numero_contrato, c.estado, cl.nombre, cl.apellidos
         FROM contratos c
         JOIN clientes cl ON c.cliente_id = cl.id
         WHERE c.numero_contrato = ? OR c.numero_contrato = ?
         LIMIT 1"
    );
    $stmtC->execute([$numContratoPad, $q]);
    $contrato = $stmtC->fetch(PDO::FETCH_ASSOC);

    if ($contrato) {
        $resultados[] = [
            'tipo'   => 'contrato',
            'id'     => (int)$contrato['id'],
            'titulo' => 'Contrato #' . $contrato['numero_contrato'],
            'sub'    => $contrato['nombre'] . ' ' . $contrato['apellidos']
                        . ' — ' . strtoupper($contrato['estado']),
            'url'    => 'contratos.php?buscar=' . urlencode($contrato['numero_contrato'])
                        . '&estado=all&vendedor=all',
            'badge'  => ucfirst($contrato['estado']),
        ];
    }
}

/* ----------------------------------------------------------
   PRIORIDAD 3: Búsqueda por nombre, apellido o número parcial
   ---------------------------------------------------------- */
$t = '%' . $q . '%';
$stmtB = $conn->prepare(
    "SELECT c.id, c.numero_contrato, c.estado, cl.nombre, cl.apellidos
     FROM contratos c
     JOIN clientes cl ON c.cliente_id = cl.id
     WHERE cl.nombre LIKE ? OR cl.apellidos LIKE ?
        OR CONCAT(cl.nombre,' ',cl.apellidos) LIKE ?
        OR c.numero_contrato LIKE ?
     ORDER BY c.id DESC
     LIMIT 5"
);
$stmtB->execute([$t, $t, $t, $t]);
$encontrados = $stmtB->fetchAll(PDO::FETCH_ASSOC);

foreach ($encontrados as $row) {
    // Evitar duplicados si ya fue añadido en prioridad 2
    $yaExiste = false;
    foreach ($resultados as $r) {
        if ($r['tipo'] === 'contrato' && $r['id'] === (int)$row['id']) {
            $yaExiste = true;
            break;
        }
    }
    if (!$yaExiste) {
        $resultados[] = [
            'tipo'   => 'contrato',
            'id'     => (int)$row['id'],
            'titulo' => $row['nombre'] . ' ' . $row['apellidos'],
            'sub'    => 'Contrato #' . $row['numero_contrato']
                        . ' — ' . strtoupper($row['estado']),
            'url'    => 'contratos.php?buscar=' . urlencode($q)
                        . '&estado=all&vendedor=all',
            'badge'  => ucfirst($row['estado']),
        ];
    }
}

/* ----------------------------------------------------------
   Si no hay resultados → ofrecer búsqueda general en contratos
   ---------------------------------------------------------- */
if (empty($resultados)) {
    $resultados[] = [
        'tipo'   => 'buscar',
        'id'     => 0,
        'titulo' => 'Buscar "' . htmlspecialchars($q, ENT_QUOTES, 'UTF-8') . '" en Contratos',
        'sub'    => 'Ver todos los resultados relacionados',
        'url'    => 'contratos.php?buscar=' . urlencode($q) . '&estado=all&vendedor=all',
        'badge'  => '',
    ];
}

echo json_encode(['resultados' => $resultados, 'tipo' => 'general']);
