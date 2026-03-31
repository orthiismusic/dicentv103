<?php
/* ============================================================
   cobrador/index.php — LOGIN PORTAL COBRADOR (CORREGIDO)
   Sistema ORTHIIS — Seguros de Vida

   CORRECCIONES APLICADAS:
   1. config.php ya llama session_start() — no repetirlo
   2. Login en 2 pasos: primero usuario, luego cobrador
   3. No depende de columna usuario_id (puede no existir aún)
   4. Logging detallado de errores a PHP error_log
   5. Manejo de HTTPS vs HTTP para cookies de sesión
   ============================================================ */

// ── Mostrar errores en desarrollo (comentar en producción) ──
// error_reporting(E_ALL);
// ini_set('display_errors', 1);

// ── Cargar config.php (incluye session_start y $conn) ──
// Usamos require_once para no duplicar session_start()
if (!defined('DB_HOST')) {
    require_once __DIR__ . '/../config.php';
}

// ── Si config.php no inició la sesión correctamente ──
if (session_status() === PHP_SESSION_NONE) {
    $esHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
               (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443);
    ini_set('session.cookie_httponly', 1);
    ini_set('session.use_only_cookies', 1);
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'secure'   => $esHttps,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}

// ── Si ya hay sesión activa de cobrador, redirigir ──
if (
    !empty($_SESSION['cobrador_portal_id']) &&
    !empty($_SESSION['cobrador_portal_rol']) &&
    $_SESSION['cobrador_portal_rol'] === 'cobrador'
) {
    header('Location: dashboard.php');
    exit();
}

// ── Obtener configuración del sistema ──
$config = ['nombre_empresa' => 'ORTHIIS', 'logo_url' => '', 'telefono' => ''];
try {
    $stmtCfg = $conn->query("SELECT nombre_empresa, logo_url, telefono FROM configuracion_sistema WHERE id = 1 LIMIT 1");
    $config  = $stmtCfg->fetch(PDO::FETCH_ASSOC) ?: $config;
} catch (PDOException $e) {
    error_log('cobrador/index.php: Error al leer config: ' . $e->getMessage());
}

// ── Variables del formulario ──
$error    = '';
$usuario  = '';

/* ============================================================
   FUNCIÓN AUXILIAR: buscarCobradorPorUsuario
   Busca el cobrador vinculado al usuario autenticado.
   Funciona CON o SIN la columna usuario_id en cobradores.
   ============================================================ */
function buscarCobradorPorUsuario(PDO $conn, array $user): ?array
{
    // ESTRATEGIA 1: Buscar por usuario_id (si la columna existe)
    try {
        $cols = $conn->query("SHOW COLUMNS FROM `cobradores` LIKE 'usuario_id'")->fetch();
        if ($cols) {
            $stmt = $conn->prepare("
                SELECT id, nombre_completo, codigo, estado
                FROM cobradores
                WHERE usuario_id = ? AND estado = 'activo'
                LIMIT 1
            ");
            $stmt->execute([$user['id']]);
            $cobrador = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($cobrador) return $cobrador;
        }
    } catch (PDOException $e) {
        error_log('buscarCobradorPorUsuario (estrategia 1): ' . $e->getMessage());
    }

    // ESTRATEGIA 2: Buscar por nombre_completo = nombre exacto del usuario
    try {
        $stmt = $conn->prepare("
            SELECT id, nombre_completo, codigo, estado
            FROM cobradores
            WHERE LOWER(TRIM(nombre_completo)) = LOWER(TRIM(?))
              AND estado = 'activo'
            LIMIT 1
        ");
        $stmt->execute([$user['nombre']]);
        $cobrador = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($cobrador) return $cobrador;
    } catch (PDOException $e) {
        error_log('buscarCobradorPorUsuario (estrategia 2): ' . $e->getMessage());
    }

    // ESTRATEGIA 3: Buscar por nombre parcial (nombre contiene palabra del usuario)
    try {
        $primerNombre = explode(' ', trim($user['nombre']))[0];
        $stmt = $conn->prepare("
            SELECT id, nombre_completo, codigo, estado
            FROM cobradores
            WHERE LOWER(nombre_completo) LIKE LOWER(?)
              AND estado = 'activo'
            LIMIT 1
        ");
        $stmt->execute(['%' . $primerNombre . '%']);
        $cobrador = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($cobrador) return $cobrador;
    } catch (PDOException $e) {
        error_log('buscarCobradorPorUsuario (estrategia 3): ' . $e->getMessage());
    }

    // ESTRATEGIA 4: Buscar por el nombre de usuario (campo usuario en tabla usuarios)
    try {
        $stmt = $conn->prepare("
            SELECT id, nombre_completo, codigo, estado
            FROM cobradores
            WHERE LOWER(nombre_completo) LIKE LOWER(?)
              AND estado = 'activo'
            ORDER BY id ASC
            LIMIT 1
        ");
        $stmt->execute(['%' . $user['usuario'] . '%']);
        $cobrador = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($cobrador) return $cobrador;
    } catch (PDOException $e) {
        error_log('buscarCobradorPorUsuario (estrategia 4): ' . $e->getMessage());
    }

    // ESTRATEGIA 5 (último recurso): Si solo hay 1 cobrador activo, usarlo
    try {
        $stmt = $conn->query("SELECT COUNT(*) FROM cobradores WHERE estado = 'activo'");
        $totalCobradores = (int)$stmt->fetchColumn();
        if ($totalCobradores === 1) {
            $stmt = $conn->query("SELECT id, nombre_completo, codigo, estado FROM cobradores WHERE estado = 'activo' LIMIT 1");
            return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
        }
    } catch (PDOException $e) {
        error_log('buscarCobradorPorUsuario (estrategia 5): ' . $e->getMessage());
    }

    return null;
}

/* ============================================================
   PROCESAR LOGIN
   ============================================================ */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $usuario  = trim($_POST['usuario'] ?? '');
    $password = $_POST['password'] ?? '';

    if (empty($usuario) || empty($password)) {
        $error = 'Por favor ingresa tu usuario y contraseña.';
    } else {
        try {
            // ─ PASO 1: Verificar usuario en tabla usuarios ─
            $stmt = $conn->prepare("
                SELECT id, usuario, password, nombre, email, estado, rol
                FROM usuarios
                WHERE usuario = ?
                LIMIT 1
            ");
            $stmt->execute([$usuario]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            // Validaciones básicas
            if (!$user) {
                $error = 'Usuario o contraseña incorrectos.';
                error_log("cobrador/login: usuario '$usuario' no existe en BD");
            } elseif ($user['rol'] !== 'cobrador') {
                $error = 'Este portal es exclusivo para cobradores.';
                error_log("cobrador/login: usuario '$usuario' tiene rol '{$user['rol']}', no 'cobrador'");
            } elseif ($user['estado'] !== 'activo') {
                $error = 'Tu cuenta está inactiva. Contacta a la oficina.';
                error_log("cobrador/login: usuario '$usuario' está en estado '{$user['estado']}'");
            } elseif (!password_verify($password, $user['password'])) {
                $error = 'Usuario o contraseña incorrectos.';
                error_log("cobrador/login: contraseña incorrecta para '$usuario'");
            } else {
                // ─ PASO 2: Buscar el perfil de cobrador vinculado ─
                $cobrador = buscarCobradorPorUsuario($conn, $user);

                if (!$cobrador) {
                    // No encontró cobrador — dar acceso de todas formas con datos del usuario
                    // (para casos donde el perfil de cobrador no está vinculado)
                    error_log("cobrador/login: usuario '$usuario' no tiene cobrador vinculado — acceso con datos de usuario");
                    $cobrador = [
                        'id'             => 0,
                        'nombre_completo'=> $user['nombre'],
                        'codigo'         => 'N/A',
                        'estado'         => 'activo',
                    ];

                    // Intentar vincular automáticamente el usuario_id si la columna existe
                    try {
                        $colExiste = $conn->query("SHOW COLUMNS FROM cobradores LIKE 'usuario_id'")->fetch();
                        if ($colExiste) {
                            // Actualizar el primer cobrador activo sin usuario_id asignado
                            $conn->prepare("
                                UPDATE cobradores
                                SET usuario_id = ?
                                WHERE usuario_id IS NULL AND estado = 'activo'
                                ORDER BY id ASC
                                LIMIT 1
                            ")->execute([$user['id']]);

                            // Volver a buscar
                            $cobrador2 = buscarCobradorPorUsuario($conn, $user);
                            if ($cobrador2) $cobrador = $cobrador2;
                        }
                    } catch (PDOException $e) {
                        error_log('Auto-vinculación cobrador: ' . $e->getMessage());
                    }
                }

                if ((int)$cobrador['id'] === 0) {
                    // Sin cobrador vinculado — mostrar error útil
                    $error = 'Tu usuario no tiene un perfil de cobrador vinculado. Contacta al administrador.';
                    error_log("cobrador/login: usuario '$usuario' (ID {$user['id']}) sin cobrador en BD");
                } else {
                    // ─ PASO 3: Login exitoso ─
                    session_regenerate_id(true);

                    $_SESSION['cobrador_portal_id']     = (int)$cobrador['id'];
                    $_SESSION['cobrador_portal_nombre'] = $cobrador['nombre_completo'];
                    $_SESSION['cobrador_portal_codigo'] = $cobrador['codigo'];
                    $_SESSION['cobrador_portal_uid']    = (int)$user['id'];
                    $_SESSION['cobrador_portal_rol']    = 'cobrador';

                    // Token CSRF
                    if (empty($_SESSION['csrf_token_cobrador'])) {
                        $_SESSION['csrf_token_cobrador'] = bin2hex(random_bytes(32));
                    }

                    // Actualizar último acceso
                    try {
                        $conn->prepare("UPDATE usuarios SET ultimo_acceso = NOW() WHERE id = ?")
                             ->execute([$user['id']]);
                    } catch (PDOException $e) {
                        error_log('update ultimo_acceso: ' . $e->getMessage());
                    }

                    // Log de acceso
                    try {
                        $tablaLog = $conn->query("
                            SELECT COUNT(*) FROM information_schema.TABLES
                            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'cobrador_sesiones_log'
                        ")->fetchColumn();
                        if ($tablaLog) {
                            $conn->prepare("
                                INSERT INTO cobrador_sesiones_log (cobrador_id, ip_address, user_agent, accion)
                                VALUES (?, ?, ?, 'login')
                            ")->execute([
                                $cobrador['id'],
                                $_SERVER['REMOTE_ADDR'] ?? 'desconocida',
                                substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255),
                            ]);
                        }
                    } catch (PDOException $e) {
                        error_log('log_sesion error: ' . $e->getMessage());
                    }

                    // Redirigir
                    $redirect = $_SESSION['cobrador_redirect_after_login'] ?? 'dashboard.php';
                    unset($_SESSION['cobrador_redirect_after_login']);
                    header('Location: ' . $redirect);
                    exit();
                }
            }

        } catch (PDOException $e) {
            // Loguear el error REAL para poder depurarlo
            error_log('cobrador/index.php PDOException: ' . $e->getMessage() . ' | Trace: ' . $e->getTraceAsString());
            $error = 'Error de conexión con la base de datos. Intenta de nuevo en unos segundos.';
        } catch (Throwable $e) {
            error_log('cobrador/index.php Throwable: ' . $e->getMessage() . ' en ' . $e->getFile() . ':' . $e->getLine());
            $error = 'Error interno del servidor. El administrador ha sido notificado.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <meta name="theme-color" content="#1e2d4a">
  <title>Portal Cobrador — <?= htmlspecialchars($config['nombre_empresa']) ?></title>
  <link rel="stylesheet" href="css/cobrador.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    /* Estilos de emergencia en caso de que cobrador.css no cargue */
    body { font-family: 'Inter', sans-serif; background: #0f172a; margin: 0; min-height: 100vh;
           display: flex; align-items: center; justify-content: center; padding: 20px; }
    .login-card { background: #fff; border-radius: 16px; padding: 36px 32px;
                  width: 100%; max-width: 380px; box-shadow: 0 25px 60px rgba(0,0,0,.35); }
    .login-logo  { text-align: center; margin-bottom: 20px; }
    .login-logo-text { font-size: 22px; font-weight: 800; color: #1e2d4a; }
    .login-subtitle  { font-size: 12px; color: #9ca3af; margin-top: 4px; }
    .login-title { font-size: 18px; font-weight: 700; color: #111827;
                   text-align: center; margin-bottom: 22px; }
    .form-group  { margin-bottom: 16px; }
    .form-label  { display: block; font-size: 13px; font-weight: 600; color: #374151; margin-bottom: 6px; }
    .input-wrap  { position: relative; }
    .input-icon  { position: absolute; left: 12px; top: 50%; transform: translateY(-50%);
                   color: #9ca3af; font-size: 14px; }
    .form-control { width: 100%; height: 44px; padding: 0 40px; border: 1.5px solid #e5e7eb;
                    border-radius: 10px; font-size: 14px; outline: none; box-sizing: border-box;
                    font-family: inherit; transition: border-color .2s; }
    .form-control:focus { border-color: #2563EB; box-shadow: 0 0 0 3px rgba(37,99,235,.12); }
    .toggle-pass { position: absolute; right: 12px; top: 50%; transform: translateY(-50%);
                   background: none; border: none; cursor: pointer; color: #9ca3af; padding: 4px; }
    .btn-login   { width: 100%; height: 46px; background: #2563EB; color: #fff; border: none;
                   border-radius: 10px; font-size: 15px; font-weight: 700; cursor: pointer;
                   margin-top: 8px; font-family: inherit; display: flex; align-items: center;
                   justify-content: center; gap: 8px; transition: background .2s; }
    .btn-login:hover { background: #1d4ed8; }
    .btn-login:disabled { opacity: .7; cursor: not-allowed; }
    .login-alert { background: #fee2e2; color: #991b1b; border: 1px solid #fca5a5;
                   border-radius: 10px; padding: 10px 14px; font-size: 13px;
                   margin-bottom: 16px; display: flex; align-items: flex-start; gap: 8px; }
    .login-back  { text-align: center; margin-top: 20px; font-size: 12px; color: #9ca3af; }
    .login-back a { color: #2563EB; text-decoration: none; }
  </style>
</head>
<body>

<div class="login-card">

  <!-- Logo -->
  <div class="login-logo">
    <?php if (!empty($config['logo_url'])): ?>
      <img src="../<?= htmlspecialchars($config['logo_url']) ?>"
           alt="<?= htmlspecialchars($config['nombre_empresa']) ?>"
           style="max-width:120px;max-height:60px;object-fit:contain;">
    <?php else: ?>
      <div style="font-size:40px;color:#1e2d4a;margin-bottom:4px;">
        <i class="fas fa-shield-halved"></i>
      </div>
      <div class="login-logo-text"><?= htmlspecialchars($config['nombre_empresa']) ?></div>
    <?php endif; ?>
    <div class="login-subtitle">
      <i class="fas fa-motorcycle" style="margin-right:4px;"></i>
      Portal del Cobrador
    </div>
  </div>

  <div class="login-title">Iniciar Sesión</div>

  <!-- Mensaje de error -->
  <?php if ($error): ?>
  <div class="login-alert">
    <i class="fas fa-circle-exclamation" style="margin-top:1px;flex-shrink:0;"></i>
    <span><?= htmlspecialchars($error) ?></span>
  </div>
  <?php endif; ?>

  <!-- Mensaje logout -->
  <?php if (isset($_GET['logout'])): ?>
  <div style="background:#dcfce7;color:#166534;border:1px solid #bbf7d0;border-radius:10px;
              padding:10px 14px;font-size:13px;margin-bottom:16px;display:flex;gap:8px;align-items:center;">
    <i class="fas fa-check-circle"></i> Sesión cerrada correctamente.
  </div>
  <?php endif; ?>

  <!-- Formulario -->
  <form method="POST" id="loginForm" autocomplete="on" novalidate>

    <div class="form-group">
      <label class="form-label" for="usuario">Usuario</label>
      <div class="input-wrap">
        <i class="fas fa-user input-icon"></i>
        <input type="text" id="usuario" name="usuario"
               class="form-control"
               value="<?= htmlspecialchars($usuario) ?>"
               placeholder="Tu nombre de usuario"
               autocomplete="username"
               autocorrect="off" autocapitalize="off" spellcheck="false"
               required autofocus>
      </div>
    </div>

    <div class="form-group">
      <label class="form-label" for="password">Contraseña</label>
      <div class="input-wrap">
        <i class="fas fa-lock input-icon"></i>
        <input type="password" id="password" name="password"
               class="form-control"
               placeholder="Tu contraseña"
               autocomplete="current-password"
               required>
        <button type="button" class="toggle-pass" onclick="togglePass()" tabindex="-1" aria-label="Mostrar contraseña">
          <i class="fas fa-eye" id="passEye"></i>
        </button>
      </div>
    </div>

    <button type="submit" class="btn-login" id="btnLogin">
      <i class="fas fa-right-to-bracket" id="btnIcon"></i>
      <span id="btnText">Ingresar al Portal</span>
    </button>

  </form>

  <div class="login-back">
    <a href="../login.php">
      <i class="fas fa-arrow-left" style="font-size:10px;"></i> Ir al sistema principal
    </a>
  </div>

</div>

<script>
/* Mostrar/ocultar contraseña */
function togglePass() {
  var input = document.getElementById('password');
  var icon  = document.getElementById('passEye');
  if (input.type === 'password') {
    input.type = 'text';
    icon.className = 'fas fa-eye-slash';
  } else {
    input.type = 'password';
    icon.className = 'fas fa-eye';
  }
}

/* Estado de carga al enviar */
document.getElementById('loginForm').addEventListener('submit', function(e) {
  var usuario  = document.getElementById('usuario').value.trim();
  var password = document.getElementById('password').value;

  if (!usuario || !password) {
    e.preventDefault();
    return;
  }

  var btn = document.getElementById('btnLogin');
  document.getElementById('btnIcon').className = 'fas fa-spinner fa-spin';
  document.getElementById('btnText').textContent = 'Verificando...';
  btn.disabled = true;

  // Seguridad: re-habilitar después de 8s por si hay error de red
  setTimeout(function() {
    btn.disabled = false;
    document.getElementById('btnIcon').className = 'fas fa-right-to-bracket';
    document.getElementById('btnText').textContent = 'Ingresar al Portal';
  }, 8000);
});

/* Enter en campo usuario → foco a contraseña */
document.getElementById('usuario').addEventListener('keydown', function(e) {
  if (e.key === 'Enter') {
    e.preventDefault();
    document.getElementById('password').focus();
  }
});
</script>

</body>
</html>