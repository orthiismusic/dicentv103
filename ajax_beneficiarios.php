<?php
/* ajax_beneficiarios.php — Devuelve beneficiarios de un contrato */
require_once 'config.php';
verificarSesion();
header('Content-Type: application/json');

$contrato_id = intval($_GET['contrato_id'] ?? 0);
if (!$contrato_id) { echo json_encode([]); exit; }

$stmt = $conn->prepare("
    SELECT id, nombre, apellidos, parentesco, porcentaje,
           DATE_FORMAT(fecha_nacimiento, '%Y-%m-%d') AS fecha_nacimiento
    FROM beneficiarios
    WHERE contrato_id = ?
    ORDER BY nombre
");
$stmt->execute([$contrato_id]);
echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));