<?php
require_once 'config.php';
verificarSesion();

header('Content-Type: application/json');

try {
    $pago_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;

    if (!$pago_id) {
        throw new Exception('ID de pago no válido');
    }

    $stmt = $conn->prepare("
        SELECT fecha_pago
        FROM pagos
        WHERE id = ?
    ");
    $stmt->execute([$pago_id]);
    $pago = $stmt->fetch();

    if (!$pago) {
        throw new Exception('Pago no encontrado');
    }

    $fecha_pago = new DateTime($pago['fecha_pago']);
    $ahora = new DateTime();
    $diferencia = $fecha_pago->diff($ahora);
    
    //EN CASO DE BAJAR EL TIEMPO A 24 HORAS
    //$horas_transcurridas = ($diferencia->days * 24) + $diferencia->h;
    
    //EN CASO DE BAJAR EL TIEMPO A 5 MINUTOS
    $minutos_transcurridos = ($diferencia->days * 24 * 60) + ($diferencia->h * 60) + $diferencia->i;

    echo json_encode([
        'success' => true,
        //EN CASO DE BAJAR EL TIEMPO A 24 HORAS
        //'requiere_password' => $horas_transcurridas > 24
        
        //EN CASO DE BAJAR EL TIEMPO A 5 MINUTOS
        'requiere_password' => $minutos_transcurridos > 5
        
    ]);

} catch (Exception $e) {
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
}
?>