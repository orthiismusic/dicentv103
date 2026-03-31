<?php
/* ============================================================
   ajax_buscar_cliente.php
   Búsqueda AJAX de clientes para el modal de contratos
   ============================================================ */
require_once 'config.php';
verificarSesion();
header('Content-Type: application/json; charset=utf-8');

$q = trim($_GET['q'] ?? '');

if (mb_strlen($q) < 2) {
    echo json_encode([]);
    exit;
}

$t = "%$q%";

$stmt = $conn->prepare("
    SELECT id, codigo, nombre, apellidos, cedula
    FROM clientes
    WHERE estado = 'activo'
      AND (
          nombre     LIKE ?
       OR apellidos  LIKE ?
       OR cedula     LIKE ?
       OR codigo     LIKE ?
       OR CONCAT(nombre,' ',apellidos) LIKE ?
      )
    ORDER BY nombre, apellidos
    LIMIT 10
");

$stmt->execute([$t, $t, $t, $t, $t]);
echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));