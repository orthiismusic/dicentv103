<?php
/* ============================================================
   cobrador/diagnostico.php
   Ejecuta este archivo primero para ver el error exacto.
   ELIMINAR después de resolver el problema.
   ============================================================ */

// Mostrar TODOS los errores
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Diagnóstico Portal Cobrador</title>
<style>
  body { font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px; }
  h2   { color: #60a5fa; }
  .ok  { color: #4ade80; }
  .err { color: #f87171; }
  .warn{ color: #fbbf24; }
  .box { background: #16213e; border-left: 3px solid #60a5fa; padding: 10px 14px;
         margin: 8px 0; border-radius: 4px; font-size: 13px; line-height: 1.6; }
  .sql { background: #0f3460; border-left-color: #a78bfa; }
  pre  { white-space: pre-wrap; word-break: break-all; margin: 0; }
</style>
</head>
<body>
<h2>🔍 Diagnóstico — Portal del Cobrador</h2>

<?php

/* ══════════════════════════════════════════════
   1. PHP Y SESIÓN
══════════════════════════════════════════════ */
echo '<h2>1. PHP y Sesión</h2>';

echo '<div class="box"><pre>';
echo '✓ PHP: ' . phpversion() . "\n";
echo '✓ Zona horaria: ' . date_default_timezone_get() . "\n";
echo '✓ Servidor: ' . ($_SERVER['SERVER_SOFTWARE'] ?? 'desconocido') . "\n";
echo '✓ HTTPS: ' . (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'SÍ' : 'NO (HTTP)') . "\n";
echo '</pre></div>';

/* Probar session_start sin llamar a config.php todavía */
$sesionEstado = session_status();
if ($sesionEstado === PHP_SESSION_NONE) {
    // Iniciar sesión con parámetros compatibles
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'secure'   => false, // forzar false para diagnóstico
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    $iniciada = session_start();
    echo '<div class="box ' . ($iniciada ? 'ok' : 'err') . '">';
    echo $iniciada ? '✓ session_start() exitoso. Session ID: ' . session_id() : '✗ session_start() FALLÓ';
    echo '</div>';
} else {
    echo '<div class="box warn">⚠ La sesión ya estaba activa (estado: ' . $sesionEstado . ')</div>';
}


/* ══════════════════════════════════════════════
   2. INCLUDE DE CONFIG.PHP
══════════════════════════════════════════════ */
echo '<h2>2. Inclusión de config.php</h2>';

$configPath = __DIR__ . '/../config.php';
if (!file_exists($configPath)) {
    echo '<div class="box err">✗ config.php NO encontrado en: ' . $configPath . '</div>';
} else {
    echo '<div class="box ok">✓ config.php encontrado en: ' . $configPath . '</div>';

    try {
        // Capturar cualquier salida o error
        ob_start();
        require_once $configPath;
        $salida = ob_get_clean();

        if (!empty($salida)) {
            echo '<div class="box err">✗ config.php generó esta salida inesperada:<pre>' . htmlspecialchars($salida) . '</pre></div>';
        } else {
            echo '<div class="box ok">✓ config.php incluido sin salida inesperada</div>';
        }

        if (isset($conn)) {
            echo '<div class="box ok">✓ Variable $conn definida después de config.php</div>';
        } else {
            echo '<div class="box err">✗ Variable $conn NO definida — revisar config.php</div>';
        }
    } catch (Throwable $e) {
        ob_end_clean();
        echo '<div class="box err">✗ ERROR al incluir config.php:<pre>' . htmlspecialchars($e->getMessage()) . '</pre></div>';
    }
}


/* ══════════════════════════════════════════════
   3. CONEXIÓN A LA BASE DE DATOS
══════════════════════════════════════════════ */
echo '<h2>3. Conexión a la Base de Datos</h2>';

if (!isset($conn)) {
    // Intentar conexión directa
    try {
        $connTest = new PDO('mysql:host=localhost;dbname=xygfyvca_disen;charset=utf8mb3',
                           'xygfyvca_disen', '*Camil7172*');
        $connTest->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $conn = $connTest;
        echo '<div class="box ok">✓ Conexión PDO exitosa (directa)</div>';
    } catch (PDOException $e) {
        echo '<div class="box err">✗ Conexión PDO FALLÓ: ' . htmlspecialchars($e->getMessage()) . '</div>';
    }
} else {
    try {
        $conn->query("SELECT 1");
        echo '<div class="box ok">✓ Conexión PDO activa y funcional</div>';
    } catch (PDOException $e) {
        echo '<div class="box err">✗ $conn existe pero no responde: ' . htmlspecialchars($e->getMessage()) . '</div>';
    }
}


/* ══════════════════════════════════════════════
   4. VERIFICAR COLUMNAS EN TABLA cobradores
══════════════════════════════════════════════ */
echo '<h2>4. Estructura de la tabla <code>cobradores</code></h2>';

if (isset($conn)) {
    try {
        $cols = $conn->query("SHOW COLUMNS FROM cobradores")->fetchAll(PDO::FETCH_ASSOC);
        $colNames = array_column($cols, 'Field');

        echo '<div class="box"><pre>';
        echo 'Columnas encontradas: ' . implode(', ', $colNames) . "\n\n";

        $check = [
            'usuario_id' => 'Vinculación con tabla usuarios (NUEVA)',
            'telefono'   => 'Teléfono del cobrador (NUEVA)',
            'email'      => 'Email del cobrador (NUEVA)',
        ];
        foreach ($check as $col => $desc) {
            $existe = in_array($col, $colNames);
            echo ($existe ? '✓' : '✗') . " $col — $desc" . ($existe ? '' : ' ← COLUMNA FALTANTE') . "\n";
        }
        echo '</pre></div>';

        // Datos actuales de cobradores
        $cobs = $conn->query("SELECT id, codigo, nombre_completo, estado, usuario_id FROM cobradores LIMIT 10")->fetchAll(PDO::FETCH_ASSOC);
        echo '<div class="box sql"><pre>Cobradores en BD:' . "\n";
        foreach ($cobs as $c) {
            echo "  ID:{$c['id']} | {$c['codigo']} | {$c['nombre_completo']} | {$c['estado']} | usuario_id:" . ($c['usuario_id'] ?? 'NULL') . "\n";
        }
        echo '</pre></div>';

    } catch (PDOException $e) {
        echo '<div class="box err">✗ Error al leer cobradores: ' . htmlspecialchars($e->getMessage()) . '</div>';
    }
}


/* ══════════════════════════════════════════════
   5. VERIFICAR NUEVAS TABLAS DEL MÓDULO
══════════════════════════════════════════════ */
echo '<h2>5. Tablas del módulo cobrador</h2>';

if (isset($conn)) {
    $tablasNuevas = [
        'cobrador_mensajes',
        'cobrador_facturas_autorizadas',
        'cobrador_rutas',
        'cobrador_sesiones_log',
    ];

    echo '<div class="box"><pre>';
    foreach ($tablasNuevas as $tabla) {
        try {
            $conn->query("SELECT 1 FROM `$tabla` LIMIT 1");
            $cnt = $conn->query("SELECT COUNT(*) FROM `$tabla`")->fetchColumn();
            echo "✓ $tabla — existe ($cnt registros)\n";
        } catch (PDOException $e) {
            echo "✗ $tabla — NO EXISTE ← ejecutar script SQL\n";
        }
    }
    echo '</pre></div>';
}


/* ══════════════════════════════════════════════
   6. USUARIOS CON ROL COBRADOR
══════════════════════════════════════════════ */
echo '<h2>6. Usuarios con rol = cobrador</h2>';

if (isset($conn)) {
    try {
        $users = $conn->query("
            SELECT id, usuario, nombre, estado, rol, ultimo_acceso
            FROM usuarios
            WHERE rol = 'cobrador'
        ")->fetchAll(PDO::FETCH_ASSOC);

        if (empty($users)) {
            echo '<div class="box err">✗ No hay usuarios con rol = cobrador en la base de datos</div>';
        } else {
            echo '<div class="box sql"><pre>';
            foreach ($users as $u) {
                echo "ID:{$u['id']} | usuario:{$u['usuario']} | nombre:{$u['nombre']} | estado:{$u['estado']}\n";
            }
            echo '</pre></div>';
        }
    } catch (PDOException $e) {
        echo '<div class="box err">✗ Error: ' . htmlspecialchars($e->getMessage()) . '</div>';
    }
}


/* ══════════════════════════════════════════════
   7. SIMULACIÓN DEL LOGIN
══════════════════════════════════════════════ */
echo '<h2>7. Simulación del proceso de login</h2>';

if (isset($conn)) {
    // Intentar el QUERY SIMPLIFICADO que usará el nuevo login
    $testUsuario = 'cobrador1'; // ajustar si el username es diferente

    echo '<div class="box"><pre>Probando con usuario: "' . $testUsuario . '"</pre></div>';

    // Query simple (sin depender de usuario_id en cobradores)
    try {
        $stmt = $conn->prepare("SELECT id, usuario, password, nombre, estado, rol FROM usuarios WHERE usuario = ? AND rol = 'cobrador' LIMIT 1");
        $stmt->execute([$testUsuario]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            echo '<div class="box ok">✓ Usuario encontrado: ' . htmlspecialchars($user['nombre']) . ' (estado: ' . $user['estado'] . ')</div>';

            // Buscar cobrador vinculado por nombre
            $cols = $conn->query("SHOW COLUMNS FROM cobradores LIKE 'usuario_id'")->fetch();
            if ($cols) {
                // Buscar por usuario_id primero
                $stmt2 = $conn->prepare("SELECT id, nombre_completo, codigo, estado FROM cobradores WHERE usuario_id = ? OR LOWER(nombre_completo) LIKE ? LIMIT 1");
                $stmt2->execute([$user['id'], '%' . strtolower($user['nombre']) . '%']);
            } else {
                // Sin columna usuario_id
                $stmt2 = $conn->prepare("SELECT id, nombre_completo, codigo, estado FROM cobradores WHERE LOWER(nombre_completo) LIKE ? LIMIT 1");
                $stmt2->execute(['%' . strtolower($user['nombre']) . '%']);
            }
            $cobrador = $stmt2->fetch(PDO::FETCH_ASSOC);

            if ($cobrador) {
                echo '<div class="box ok">✓ Cobrador vinculado: ' . htmlspecialchars($cobrador['nombre_completo']) . ' | Cód: ' . $cobrador['codigo'] . ' | Estado: ' . $cobrador['estado'] . '</div>';
            } else {
                echo '<div class="box err">✗ No se encontró cobrador vinculado al usuario "' . $testUsuario . '"<br>→ Verifica que el nombre en `usuarios.nombre` coincida con `cobradores.nombre_completo`<br>→ O ejecuta el script SQL para agregar `usuario_id` y vincularlo manualmente.</div>';
            }
        } else {
            echo '<div class="box err">✗ Usuario "' . $testUsuario . '" no encontrado con rol cobrador<br>→ Revisa la sección 6 de este diagnóstico para ver los usuarios cobrador disponibles</div>';
        }
    } catch (PDOException $e) {
        echo '<div class="box err">✗ Error en la simulación: ' . htmlspecialchars($e->getMessage()) . '</div>';
    }
}


/* ══════════════════════════════════════════════
   8. VERIFICAR RUTAS DE ARCHIVOS
══════════════════════════════════════════════ */
echo '<h2>8. Archivos del módulo</h2>';

$archivos = [
    __DIR__ . '/config_cobrador.php',
    __DIR__ . '/header_cobrador.php',
    __DIR__ . '/dashboard.php',
    __DIR__ . '/css/cobrador.css',
    __DIR__ . '/api/get_clientes.php',
    __DIR__ . '/api/get_facturas.php',
];

echo '<div class="box"><pre>';
foreach ($archivos as $arch) {
    $existe = file_exists($arch);
    echo ($existe ? '✓' : '✗') . ' ' . str_replace(__DIR__, '.', $arch) . "\n";
}
echo '</pre></div>';

echo '<hr style="border-color:#444;margin:24px 0;">';
echo '<div class="box ok">✓ Diagnóstico completado — ' . date('d/m/Y H:i:s') . '</div>';
echo '<p style="color:#94a3b8;font-size:12px;">⚠ Elimina este archivo después de resolver el problema.</p>';
?>
</body>
</html>