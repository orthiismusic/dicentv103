<?php
require_once 'config.php';
verificarSesion();

if (!isset($_GET['plan_id'])) {
    echo json_encode([]);
    exit();
}

$plan_id = (int)$_GET['plan_id'];

try {
    $stmt = $conn->prepare("
        SELECT * FROM beneficios_planes 
        WHERE plan_id = ? 
        ORDER BY id
    ");
    $stmt->execute([$plan_id]);
    $beneficios = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo json_encode($beneficios);
} catch(PDOException $e) {
    echo json_encode(['error' => $e->getMessage()]);
}
?>