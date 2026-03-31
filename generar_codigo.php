<?php
require_once 'config.php';
verificarSesion();

if (!isset($_GET['texto'])) {
    die('No se proporcionó texto para generar el código');
}

// Aquí puedes implementar la generación de códigos de barras o QR
// usando librerías como php-qrcode o php-barcode

// Ejemplo usando php-qrcode (necesitas instalar la librería)
/*
require_once 'phpqrcode/qrlib.php';

$texto = $_GET['texto'];
$size = 5;
$level = 'L';
$frameSize = 2;

header('Content-Type: image/png');
QRcode::png($texto, false, $level, $size, $frameSize);
*/

// Por ahora, generamos una imagen de placeholder
header('Content-Type: image/png');
$im = imagecreatetruecolor(100, 30);
$bg = imagecolorallocate($im, 255, 255, 255);
$fg = imagecolorallocate($im, 0, 0, 0);
imagefill($im, 0, 0, $bg);
imagestring($im, 2, 5, 5, $_GET['texto'], $fg);
imagepng($im);
imagedestroy($im);
?>