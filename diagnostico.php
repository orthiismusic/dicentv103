<?php
// Este script ayuda a identificar problemas con la salida de PHP
header('Content-Type: text/plain');

echo "=== INICIO DEL DIAGNÓSTICO ===\n\n";

// 1. Verificar phpinfo básico
echo "Versión de PHP: " . phpversion() . "\n";
echo "Zona horaria: " . date_default_timezone_get() . "\n\n";

// 2. Probar inclusión del archivo config
echo "Intentando incluir config.php...\n";
$config_output = ob_start();
include_once 'config.php';
$config_result = ob_get_clean();

if (empty($config_result)) {
    echo "✓ config.php se incluyó sin errores visibles\n";
} else {
    echo "✗ config.php produjo la siguiente salida:\n";
    echo $config_result;
}

// 3. Probar conexión a base de datos 
echo "\nProbando conexión a la base de datos...\n";
if (isset($conn)) {
    try {
        $test = $conn->query("SELECT 1")->fetch();
        echo "✓ Conexión exitosa a la base de datos\n";
    } catch (Exception $e) {
        echo "✗ Error de conexión: " . $e->getMessage() . "\n";
    }
} else {
    echo "✗ Variable \$conn no está definida después de incluir config.php\n";
}

// 4. Verificar permisos de escritura
echo "\nVerificando permisos de escritura en el directorio actual...\n";
$test_file = "test_write_" . time() . ".tmp";
if (file_put_contents($test_file, "test")) {
    echo "✓ Permisos de escritura correctos\n";
    unlink($test_file);
} else {
    echo "✗ No hay permisos de escritura en el directorio\n";
}

echo "\n=== FIN DEL DIAGNÓSTICO ===\n";