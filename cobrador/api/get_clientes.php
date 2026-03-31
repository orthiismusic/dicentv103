<?php
/* ============================================================
   cobrador/api/get_clientes.php
   FIX: LIMIT/OFFSET se pasan directo como int en el SQL
   (MariaDB no acepta placeholders ? para LIMIT con PDO emulado)
   ============================================================ */
ob_start();
if (!defined('DB_HOST')) require_once __DIR__ . '/../../config.php';
ob_clean();

require_once __DIR__ . '/../config_cobrador.php';
verificarSesionCobradorAjax();

header('Content-Type: application/json; charset=utf-8');

$cobradorId = (int)$_SESSION['cobrador_portal_id'];
$q          = trim($_GET['q'] ?? '');
$offset     = max(0, (int)($_GET['offset'] ?? 0));
$porPagina  = 20;

try {
    /* ── Paso 1: IDs de clientes por número de contrato ── */
    $idsContrato = [];
    if ($q !== '') {
        $s = $conn->prepare("
            SELECT DISTINCT c.cliente_id
            FROM contratos c
            JOIN clientes cl ON cl.id = c.cliente_id
            WHERE cl.cobrador_id = ?
              AND c.numero_contrato LIKE ?
            LIMIT 300
        ");
        $s->execute([$cobradorId, "%$q%"]);
        $idsContrato = $s->fetchAll(PDO::FETCH_COLUMN);
    }

    /* ── Paso 2: Condición WHERE ── */
    $condiciones  = "cl.cobrador_id = ?";
    $bindParams   = [$cobradorId];

    if ($q !== '') {
        $like = "%$q%";
        if (!empty($idsContrato)) {
            $ph = implode(',', array_fill(0, count($idsContrato), '?'));
            $condiciones .= " AND (
                cl.nombre LIKE ? OR cl.apellidos LIKE ?
                OR CONCAT(cl.nombre,' ',cl.apellidos) LIKE ?
                OR cl.codigo LIKE ?
                OR cl.id IN ($ph)
            )";
            $bindParams[] = $like;
            $bindParams[] = $like;
            $bindParams[] = $like;
            $bindParams[] = $like;
            foreach ($idsContrato as $cid) $bindParams[] = (int)$cid;
        } else {
            $condiciones .= " AND (
                cl.nombre LIKE ? OR cl.apellidos LIKE ?
                OR CONCAT(cl.nombre,' ',cl.apellidos) LIKE ?
                OR cl.codigo LIKE ?
            )";
            $bindParams[] = $like;
            $bindParams[] = $like;
            $bindParams[] = $like;
            $bindParams[] = $like;
        }
    }

    /* ── Paso 3: Total ── */
    $stmtT = $conn->prepare("SELECT COUNT(*) FROM clientes cl WHERE $condiciones");
    $stmtT->execute($bindParams);
    $total = (int)$stmtT->fetchColumn();

    /* ── Paso 4: Listado — LIMIT/OFFSET directo como int en el SQL ── */
    $limitInt  = (int)$porPagina;
    $offsetInt = (int)$offset;

    $stmtL = $conn->prepare("
        SELECT cl.id, cl.codigo, cl.nombre, cl.apellidos,
               cl.telefono1, cl.telefono2, cl.telefono3,
               cl.direccion, cl.estado
        FROM clientes cl
        WHERE $condiciones
        ORDER BY cl.nombre ASC, cl.apellidos ASC
        LIMIT $limitInt OFFSET $offsetInt
    ");
    $stmtL->execute($bindParams);
    $clientes = $stmtL->fetchAll(PDO::FETCH_ASSOC);

    /* ── Paso 5: Contratos y referencias por cliente ── */
    $stmtC = $conn->prepare("
        SELECT c.numero_contrato, c.dia_cobro, c.estado, p.nombre AS plan_nombre
        FROM contratos c
        JOIN planes p ON p.id = c.plan_id
        WHERE c.cliente_id = ? AND c.estado = 'activo'
        ORDER BY c.numero_contrato ASC LIMIT 5
    ");
    $stmtR = $conn->prepare("
        SELECT nombre, relacion, telefono, direccion
        FROM referencias_clientes
        WHERE cliente_id = ? ORDER BY id ASC LIMIT 3
    ");

    foreach ($clientes as &$cl) {
        $stmtC->execute([$cl['id']]);
        $cl['contratos']   = $stmtC->fetchAll(PDO::FETCH_ASSOC);
        $stmtR->execute([$cl['id']]);
        $cl['referencias'] = $stmtR->fetchAll(PDO::FETCH_ASSOC);
        $cl['telefono1']   = $cl['telefono1'] ?? '';
        $cl['telefono2']   = $cl['telefono2'] ?? '';
        $cl['telefono3']   = $cl['telefono3'] ?? '';
    }
    unset($cl);

    echo json_encode([
        'success'    => true,
        'clientes'   => $clientes,
        'total'      => $total,
        'offset'     => $offset,
        'por_pagina' => $porPagina,
    ], JSON_UNESCAPED_UNICODE);

} catch (PDOException $e) {
    error_log('get_clientes cobrador PDO: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'success'  => false,
        'message'  => 'Error: ' . $e->getMessage(),
        'clientes' => [], 'total' => 0,
    ]);
}