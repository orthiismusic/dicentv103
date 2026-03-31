<?php
// login.php — ORTHIIS Sistema de Seguros
require_once 'config.php';

// Si ya hay sesión activa → redirigir al dashboard
if (isset($_SESSION['usuario_id']) && !empty($_SESSION['usuario_id'])) {
    header('Location: dashboard.php');
    exit();
}

// Variables de control
$error   = '';
$mensaje = '';
$campo_usuario = '';

// Mensaje de logout o sesión expirada
if (isset($_GET['mensaje'])) {
    switch ($_GET['mensaje']) {
        case 'sesion_expirada':
            $mensaje = "La sesión ha expirado por inactividad";
            break;
        case 'logout_exitoso':
            $mensaje = "Ha cerrado sesión correctamente";
            break;
    }
}

// Procesar formulario POST
if (isset($_POST['login'])) {
    $campo_usuario = trim($_POST['usuario'] ?? '');
    $password      = $_POST['password'] ?? '';

    if (empty($campo_usuario) || empty($password)) {
        $error = "Por favor complete usuario y contraseña.";
    } else {
        $stmt = $conn->prepare("SELECT id, usuario, password, rol FROM usuarios WHERE usuario = ?");
        $stmt->execute([$campo_usuario]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['usuario_id']     = $user['id'];
            $_SESSION['usuario_nombre'] = $user['usuario'];
            $_SESSION['rol']            = $user['rol'];
            $_SESSION['ultima_actividad'] = time();
            header('Location: dashboard.php');
            exit();
        } else {
            $error = "Usuario o contraseña incorrectos.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Iniciar Sesión — ORTHIIS Sistema de Seguros</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <style>
        /* ============================================================
           VARIABLES GLOBALES
        ============================================================ */
        :root {
            --primary:        #0f4c75;
            --primary-light:  #1b6ca8;
            --primary-dark:   #08304b;
            --accent:         #3282b8;
            --accent-light:   #5da8d6;
            --accent-glow:    rgba(50, 130, 184, 0.3);
            --success:        #10b981;
            --success-light:  #34d399;
            --warning:        #f59e0b;
            --warning-light:  #fbbf24;
            --danger:         #ef4444;
            --danger-light:   #f87171;
            --info:           #06b6d4;
            --bg-body:        #f0f4f8;
            --bg-card:        #ffffff;
            --text-primary:   #1e293b;
            --text-secondary: #64748b;
            --text-muted:     #94a3b8;
            --border-color:   #e2e8f0;
            --shadow-sm:      0 1px 3px rgba(0,0,0,.08);
            --shadow-md:      0 4px 12px rgba(0,0,0,.10);
            --shadow-lg:      0 10px 30px rgba(0,0,0,.12);
            --shadow-xl:      0 20px 50px rgba(0,0,0,.15);
            --radius-sm:      8px;
            --radius-md:      12px;
            --radius-lg:      16px;
            --radius-xl:      20px;
            --transition:     all .3s cubic-bezier(.4, 0, .2, 1);
        }

        [data-theme="dark"] {
            --primary:        #0f4c75;
            --primary-light:  #1b6ca8;
            --primary-dark:   #061a2b;
            --bg-body:        #0f172a;
            --bg-card:        #1e293b;
            --text-primary:   #f1f5f9;
            --text-secondary: #94a3b8;
            --text-muted:     #64748b;
            --border-color:   #334155;
            --shadow-sm:      0 1px 3px rgba(0,0,0,.30);
            --shadow-md:      0 4px 12px rgba(0,0,0,.40);
        }

        /* ============================================================
           RESET & BASE
        ============================================================ */
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-body);
            color: var(--text-primary);
            overflow-x: hidden;
            -webkit-font-smoothing: antialiased;
            min-height: 100vh;
        }

        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: var(--text-muted); border-radius: 10px; }

        /* ============================================================
           LAYOUT: DOS COLUMNAS
        ============================================================ */
        .login-wrapper {
            display: flex;
            min-height: 100vh;
        }

        /* ---- PANEL IZQUIERDO — BRANDING ---- */
        .login-left {
            flex: 1;
            background: linear-gradient(135deg, var(--primary-dark) 0%, var(--primary) 50%, var(--primary-light) 100%);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 60px 50px;
            position: relative;
            overflow: hidden;
        }

        .login-left::before {
            content: '';
            position: absolute;
            inset: 0;
            background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
            pointer-events: none;
        }

        .login-left::after {
            content: '';
            position: absolute;
            width: 500px;
            height: 500px;
            background: radial-gradient(circle, rgba(50,130,184,0.15) 0%, transparent 70%);
            bottom: -150px;
            right: -150px;
            pointer-events: none;
        }

        /* ---- MARCA / LOGO ---- */
        .login-brand {
            text-align: center;
            margin-bottom: 60px;
            position: relative;
            z-index: 1;
        }

        .login-brand-logo {
            width: 80px;
            height: 80px;
            background: rgba(255,255,255,0.1);
            border: 2px solid rgba(255,255,255,0.2);
            border-radius: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 36px;
            color: #ffffff;
            margin: 0 auto 20px;
            backdrop-filter: blur(10px);
        }

        .login-brand h1 {
            font-size: 28px;
            font-weight: 800;
            color: #ffffff;
            line-height: 1.3;
            margin-bottom: 8px;
        }

        .login-brand p {
            font-size: 14px;
            color: rgba(255,255,255,0.6);
        }

        /* ---- CARACTERÍSTICAS ---- */
        .login-features {
            width: 100%;
            max-width: 380px;
            position: relative;
            z-index: 1;
        }

        .login-feature-item {
            display: flex;
            align-items: center;
            gap: 16px;
            padding: 16px 0;
            border-bottom: 1px solid rgba(255,255,255,0.08);
        }

        .login-feature-item:last-child { border-bottom: none; }

        .login-feature-icon {
            width: 44px;
            height: 44px;
            background: rgba(255,255,255,0.1);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
            color: rgba(255,255,255,0.85);
            flex-shrink: 0;
        }

        .login-feature-text h4 {
            font-size: 14px;
            font-weight: 600;
            color: #ffffff;
            margin-bottom: 3px;
        }

        .login-feature-text p {
            font-size: 12px;
            color: rgba(255,255,255,0.5);
        }

        .login-left-footer {
            position: absolute;
            bottom: 30px;
            left: 0;
            right: 0;
            text-align: center;
            font-size: 12px;
            color: rgba(255,255,255,0.35);
            z-index: 1;
        }

        /* ---- PANEL DERECHO — FORMULARIO ---- */
        .login-right {
            width: 480px;
            min-width: 480px;
            background: var(--bg-card);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 50px 50px;
            position: relative;
        }

        .login-form-container {
            width: 100%;
            max-width: 380px;
        }

        .login-form-header { margin-bottom: 32px; }

        .login-form-header .welcome-tag {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(50,130,184,0.08);
            color: var(--accent);
            border: 1px solid rgba(50,130,184,0.2);
            border-radius: 20px;
            padding: 4px 12px;
            font-size: 12px;
            font-weight: 600;
            margin-bottom: 12px;
        }

        .login-form-header h2 {
            font-size: 26px;
            font-weight: 800;
            color: var(--text-primary);
            margin-bottom: 6px;
        }

        .login-form-header p {
            font-size: 14px;
            color: var(--text-secondary);
        }

        /* ---- ALERTAS ---- */
        .alert {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            border-radius: var(--radius-md);
            padding: 14px 16px;
            margin-bottom: 24px;
            font-size: 13.5px;
            font-weight: 500;
            line-height: 1.5;
        }

        .alert i {
            font-size: 16px;
            flex-shrink: 0;
            margin-top: 1px;
        }

        .alert-danger {
            background: rgba(239,68,68,0.08);
            border: 1px solid rgba(239,68,68,0.25);
            color: var(--danger);
        }

        .alert-success {
            background: rgba(16,185,129,0.08);
            border: 1px solid rgba(16,185,129,0.25);
            color: var(--success);
        }

        .alert-warning {
            background: rgba(245,158,11,0.08);
            border: 1px solid rgba(245,158,11,0.25);
            color: var(--warning);
        }

        /* ---- FORM ---- */
        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            font-size: 13px;
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 8px;
        }

        .input-wrapper { position: relative; }

        .input-wrapper .input-icon {
            position: absolute;
            left: 14px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
            font-size: 15px;
            pointer-events: none;
            transition: var(--transition);
        }

        .input-wrapper .input-icon-right {
            position: absolute;
            right: 14px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
            font-size: 15px;
            cursor: pointer;
            transition: var(--transition);
            background: none;
            border: none;
            padding: 0;
            display: flex;
            align-items: center;
        }

        .input-wrapper .input-icon-right:hover { color: var(--accent); }

        .form-control {
            width: 100%;
            padding: 12px 14px 12px 44px;
            border: 1.5px solid var(--border-color);
            border-radius: var(--radius-md);
            background: var(--bg-body);
            font-size: 14px;
            font-family: inherit;
            color: var(--text-primary);
            outline: none;
            transition: var(--transition);
        }

        .form-control:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-glow);
            background: var(--bg-card);
        }

        .form-control::placeholder { color: var(--text-muted); }
        .form-control.has-right-icon { padding-right: 44px; }

        .form-control.is-invalid {
            border-color: var(--danger);
            box-shadow: 0 0 0 3px rgba(239,68,68,0.15);
        }

        /* ---- OPCIONES EXTRA ---- */
        .form-options {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 24px;
        }

        .checkbox-wrapper {
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
            font-size: 13px;
            color: var(--text-secondary);
            user-select: none;
        }

        .checkbox-wrapper input[type="checkbox"] {
            width: 16px;
            height: 16px;
            accent-color: var(--accent);
            cursor: pointer;
        }

        .forgot-link {
            font-size: 13px;
            color: var(--accent);
            text-decoration: none;
            font-weight: 500;
            transition: var(--transition);
        }

        .forgot-link:hover {
            color: var(--accent-light);
            text-decoration: underline;
        }

        /* ---- BOTÓN PRINCIPAL ---- */
        .btn-login {
            width: 100%;
            padding: 14px 24px;
            background: linear-gradient(135deg, var(--accent) 0%, var(--primary-light) 100%);
            color: #ffffff;
            border: none;
            border-radius: var(--radius-md);
            font-size: 15px;
            font-weight: 700;
            font-family: inherit;
            cursor: pointer;
            transition: var(--transition);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            position: relative;
            overflow: hidden;
        }

        .btn-login::before {
            content: '';
            position: absolute;
            inset: 0;
            background: rgba(255,255,255,0);
            transition: var(--transition);
        }

        .btn-login:hover::before { background: rgba(255,255,255,0.1); }

        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(50,130,184,0.4);
        }

        .btn-login:active { transform: translateY(0); }

        .btn-login:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        .btn-login .spinner {
            display: none;
            width: 18px;
            height: 18px;
            border: 2px solid rgba(255,255,255,0.3);
            border-top-color: #ffffff;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }

        @keyframes spin { to { transform: rotate(360deg); } }

        /* ---- DIVISOR ---- */
        .divider {
            display: flex;
            align-items: center;
            gap: 12px;
            margin: 24px 0;
        }

        .divider::before,
        .divider::after {
            content: '';
            flex: 1;
            height: 1px;
            background: var(--border-color);
        }

        .divider span {
            font-size: 12px;
            color: var(--text-muted);
            font-weight: 500;
            white-space: nowrap;
        }

        /* ---- CREDENCIALES DEMO ---- */
        .demo-credentials {
            background: rgba(50,130,184,0.04);
            border: 1px solid rgba(50,130,184,0.15);
            border-radius: var(--radius-md);
            padding: 14px 16px;
            font-size: 12.5px;
            color: var(--text-secondary);
        }

        .demo-credentials strong {
            color: var(--accent);
            font-weight: 700;
        }

        .demo-credentials .demo-title {
            font-size: 13px;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .demo-credentials .demo-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 6px;
            padding: 6px 8px;
            border-radius: var(--radius-sm);
            transition: var(--transition);
        }

        .demo-credentials .demo-row:last-child { margin-bottom: 0; }

        .demo-credentials .demo-row:hover {
            background: rgba(50,130,184,0.06);
        }

        .demo-credentials .demo-row-info {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .demo-credentials .demo-row-info .role-badge {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .role-badge.admin {
            background: rgba(239,68,68,0.1);
            color: var(--danger);
        }

        .role-badge.vendedor {
            background: rgba(16,185,129,0.1);
            color: var(--success);
        }

        .role-badge.cobrador {
            background: rgba(245,158,11,0.1);
            color: var(--warning);
        }

        .role-badge.supervisor {
            background: rgba(139,92,246,0.1);
            color: #8b5cf6;
        }

        .demo-credentials .use-btn {
            background: rgba(50,130,184,0.1);
            border: 1px solid rgba(50,130,184,0.2);
            color: var(--accent);
            cursor: pointer;
            font-size: 11px;
            font-weight: 600;
            padding: 4px 10px;
            border-radius: 6px;
            transition: var(--transition);
            font-family: inherit;
            display: flex;
            align-items: center;
            gap: 4px;
        }

        .demo-credentials .use-btn:hover {
            background: var(--accent);
            color: #fff;
            border-color: var(--accent);
        }

        /* ---- THEME TOGGLE ---- */
        .theme-toggle {
            position: absolute;
            top: 20px;
            right: 20px;
            width: 38px;
            height: 38px;
            background: var(--bg-body);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-sm);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            color: var(--text-secondary);
            font-size: 15px;
            transition: var(--transition);
        }

        .theme-toggle:hover {
            background: var(--accent);
            color: #ffffff;
            border-color: var(--accent);
        }

        /* ---- FOOTER ---- */
        .login-right-footer {
            position: absolute;
            bottom: 24px;
            left: 0;
            right: 0;
            text-align: center;
            font-size: 12px;
            color: var(--text-muted);
        }

        .login-right-footer a {
            color: var(--accent);
            text-decoration: none;
        }

        /* ---- RESPONSIVE ---- */
        @media (max-width: 900px) {
            .login-left { display: none; }
            .login-right { width: 100%; min-width: unset; }
        }

        @media (max-width: 480px) {
            .login-right { padding: 40px 24px; }
            .login-form-header h2 { font-size: 22px; }
        }
    </style>
</head>
<body>

<div class="login-wrapper">

    <!-- ========== COLUMNA IZQUIERDA — BRANDING ========== -->
    <div class="login-left">

        <div class="login-brand">
            <div class="login-brand-logo">
                <i class="fas fa-shield-halved"></i>
            </div>
            <h1>ORTHIIS<br>Sistema de Seguros</h1>
            <p>Plataforma integral de gestión de seguros de vida</p>
        </div>

        <div class="login-features">

            <div class="login-feature-item">
                <div class="login-feature-icon">
                    <i class="fas fa-users"></i>
                </div>
                <div class="login-feature-text">
                    <h4>Gestión de Clientes y Contratos</h4>
                    <p>Registro completo de clientes, dependientes y beneficiarios</p>
                </div>
            </div>

            <div class="login-feature-item">
                <div class="login-feature-icon">
                    <i class="fas fa-file-invoice-dollar"></i>
                </div>
                <div class="login-feature-text">
                    <h4>Facturación y Cobros</h4>
                    <p>Generación automática de facturas y control de pagos</p>
                </div>
            </div>

            <div class="login-feature-item">
                <div class="login-feature-icon">
                    <i class="fas fa-chart-bar"></i>
                </div>
                <div class="login-feature-text">
                    <h4>Reportes e Indicadores</h4>
                    <p>Dashboard en tiempo real y reportes exportables</p>
                </div>
            </div>

            <div class="login-feature-item">
                <div class="login-feature-icon">
                    <i class="fas fa-umbrella"></i>
                </div>
                <div class="login-feature-text">
                    <h4>Planes de Seguro</h4>
                    <p>Administración de planes Básico, Familiar, Premium y Geriátrico</p>
                </div>
            </div>

            <div class="login-feature-item">
                <div class="login-feature-icon">
                    <i class="fas fa-motorcycle"></i>
                </div>
                <div class="login-feature-text">
                    <h4>Vendedores y Cobradores</h4>
                    <p>Asignación de facturas y seguimiento del equipo de campo</p>
                </div>
            </div>

        </div>

        <div class="login-left-footer">
            &copy; <?php echo date('Y'); ?> ORTHIIS — Sistema de Seguros de Vida. Todos los derechos reservados.
        </div>

    </div>

    <!-- ========== COLUMNA DERECHA — FORMULARIO ========== -->
    <div class="login-right">

        <button class="theme-toggle" onclick="toggleTheme()" title="Cambiar tema">
            <i class="fas fa-moon" id="themeIcon"></i>
        </button>

        <div class="login-form-container">

            <div class="login-form-header">
                <div class="welcome-tag">
                    <i class="fas fa-lock-open"></i>
                    Acceso al sistema
                </div>
                <h2>Bienvenido a ORTHIIS</h2>
                <p>Ingrese sus credenciales para acceder al sistema.</p>
            </div>

            <?php if (!empty($error)) : ?>
            <div class="alert alert-danger" role="alert">
                <i class="fas fa-exclamation-triangle"></i>
                <div><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
            </div>
            <?php endif; ?>

            <?php if (!empty($mensaje)) : ?>
            <div class="alert alert-<?php echo ($_GET['mensaje'] ?? '') === 'logout_exitoso' ? 'success' : 'warning'; ?>" role="alert">
                <i class="fas fa-<?php echo ($_GET['mensaje'] ?? '') === 'logout_exitoso' ? 'check-circle' : 'exclamation-triangle'; ?>"></i>
                <div><?php echo htmlspecialchars($mensaje, ENT_QUOTES, 'UTF-8'); ?></div>
            </div>
            <?php endif; ?>

            <!-- ============================================================
                 FORMULARIO DE INICIO DE SESIÓN
            ============================================================ -->
            <form method="POST" action="login.php" id="loginForm" novalidate autocomplete="off">

                <div class="form-group">
                    <label for="usuario">
                        <i class="fas fa-user" style="margin-right:4px; color:var(--accent);"></i>
                        Usuario
                    </label>
                    <div class="input-wrapper">
                        <i class="fas fa-user input-icon"></i>
                        <input
                            type="text"
                            id="usuario"
                            name="usuario"
                            class="form-control<?php echo (!empty($error) && !empty($campo_usuario)) ? ' is-invalid' : ''; ?>"
                            placeholder="Ingrese su usuario"
                            value="<?php echo htmlspecialchars($campo_usuario, ENT_QUOTES, 'UTF-8'); ?>"
                            autocomplete="username"
                            autofocus
                            required
                        >
                    </div>
                </div>

                <div class="form-group">
                    <label for="password">
                        <i class="fas fa-lock" style="margin-right:4px; color:var(--accent);"></i>
                        Contraseña
                    </label>
                    <div class="input-wrapper">
                        <i class="fas fa-lock input-icon"></i>
                        <input
                            type="password"
                            id="password"
                            name="password"
                            class="form-control has-right-icon<?php echo (!empty($error)) ? ' is-invalid' : ''; ?>"
                            placeholder="••••••••••••"
                            autocomplete="current-password"
                            required
                        >
                        <button
                            type="button"
                            class="input-icon-right"
                            onclick="togglePassword()"
                            title="Mostrar/ocultar contraseña"
                            tabindex="-1"
                        >
                            <i class="fas fa-eye" id="eyeIcon"></i>
                        </button>
                    </div>
                </div>

                <div class="form-options">
                    <label class="checkbox-wrapper">
                        <input type="checkbox" name="recordar" id="recordar" value="1">
                        Recordar sesión
                    </label>
                    <a href="register.php" class="forgot-link">
                        Crear una cuenta
                    </a>
                </div>

                <button type="submit" name="login" class="btn-login" id="btnLogin">
                    <span class="spinner" id="loginSpinner"></span>
                    <i class="fas fa-sign-in-alt" id="loginIcon"></i>
                    <span id="loginText">Iniciar Sesión</span>
                </button>

            </form>

            <!-- ---- DIVISOR ---- -->
            <div class="divider">
                <span>Información de acceso</span>
            </div>

            <!-- ---- CREDENCIALES DE PRUEBA ---- -->
            <div class="demo-credentials">
                <div class="demo-title">
                    <i class="fas fa-key" style="color:var(--accent);"></i>
                    Cuentas de prueba disponibles
                </div>

                <div class="demo-row">
                    <div class="demo-row-info">
                        <span class="role-badge admin"><i class="fas fa-crown"></i> Admin</span>
                        <span><strong>orthiis</strong></span>
                    </div>
                    <button class="use-btn" onclick="fillCredentials('orthiis','123456')" title="Usar estas credenciales">
                        <i class="fas fa-arrow-right"></i> Usar
                    </button>
                </div>

                <div class="demo-row">
                    <div class="demo-row-info">
                        <span class="role-badge vendedor"><i class="fas fa-briefcase"></i> Vendedor</span>
                        <span><strong>vendedor1</strong></span>
                    </div>
                    <button class="use-btn" onclick="fillCredentials('vendedor1','123456')" title="Usar estas credenciales">
                        <i class="fas fa-arrow-right"></i> Usar
                    </button>
                </div>

                <div class="demo-row">
                    <div class="demo-row-info">
                        <span class="role-badge cobrador"><i class="fas fa-motorcycle"></i> Cobrador</span>
                        <span><strong>cobrador1</strong></span>
                    </div>
                    <button class="use-btn" onclick="fillCredentials('cobrador1','123456')" title="Usar estas credenciales">
                        <i class="fas fa-arrow-right"></i> Usar
                    </button>
                </div>

                <div class="demo-row">
                    <div class="demo-row-info">
                        <span class="role-badge supervisor"><i class="fas fa-eye"></i> Supervisor</span>
                        <span><strong>supervisor1</strong></span>
                    </div>
                    <button class="use-btn" onclick="fillCredentials('supervisor1','123456')" title="Usar estas credenciales">
                        <i class="fas fa-arrow-right"></i> Usar
                    </button>
                </div>

            </div>

        </div>

        <div class="login-right-footer">
            ORTHIIS — Sistema de Seguros de Vida &mdash; Versión 2.0
        </div>

    </div>

</div>

<!-- ============================================================
     SCRIPTS
============================================================ -->
<script>

/* ---- Aplicar tema guardado ---- */
(function () {
    const saved = localStorage.getItem('sefure_theme') || 'light';
    if (saved === 'dark') {
        document.body.setAttribute('data-theme', 'dark');
        const icon = document.getElementById('themeIcon');
        if (icon) icon.className = 'fas fa-sun';
    }
})();

/* ---- Toggle tema oscuro/claro ---- */
function toggleTheme() {
    const body   = document.body;
    const icon   = document.getElementById('themeIcon');
    const isDark = body.getAttribute('data-theme') === 'dark';
    if (isDark) {
        body.removeAttribute('data-theme');
        icon.className = 'fas fa-moon';
        localStorage.setItem('sefure_theme', 'light');
    } else {
        body.setAttribute('data-theme', 'dark');
        icon.className = 'fas fa-sun';
        localStorage.setItem('sefure_theme', 'dark');
    }
}

/* ---- Mostrar/ocultar contraseña ---- */
function togglePassword() {
    const input = document.getElementById('password');
    const icon  = document.getElementById('eyeIcon');
    if (!input) return;
    if (input.type === 'password') {
        input.type     = 'text';
        icon.className = 'fas fa-eye-slash';
    } else {
        input.type     = 'password';
        icon.className = 'fas fa-eye';
    }
}

/* ---- Spinner en el submit ---- */
document.getElementById('loginForm').addEventListener('submit', function (e) {
    const btn   = document.getElementById('btnLogin');
    const spin  = document.getElementById('loginSpinner');
    const lIcon = document.getElementById('loginIcon');
    const lText = document.getElementById('loginText');
    const user  = document.getElementById('usuario');
    const pass  = document.getElementById('password');

    if (!user.value.trim() || !pass.value.trim()) return;

    spin.style.display  = 'block';
    lIcon.style.display = 'none';
    lText.textContent   = 'Verificando...';

    setTimeout(function () { btn.disabled = true; }, 10);

    setTimeout(function () {
        btn.disabled        = false;
        spin.style.display  = 'none';
        lIcon.style.display = 'block';
        lText.textContent   = 'Iniciar Sesión';
    }, 15000);
});

/* ---- Rellenar credenciales demo ---- */
function fillCredentials(user, pass) {
    const uInput = document.getElementById('usuario');
    const pInput = document.getElementById('password');
    if (uInput) uInput.value = user;
    if (pInput) pInput.value = pass;
    uInput.focus();
    showToast('Credenciales de ' + user + ' cargadas', 'success');
}

/* ---- Toast de notificaciones ---- */
function showToast(message, type) {
    type = type || 'info';
    const colors = {
        success: { bg: 'rgba(16,185,129,.95)',  icon: 'fa-check-circle' },
        danger:  { bg: 'rgba(239,68,68,.95)',    icon: 'fa-exclamation-circle' },
        warning: { bg: 'rgba(245,158,11,.95)',   icon: 'fa-exclamation-triangle' },
        info:    { bg: 'rgba(50,130,184,.95)',    icon: 'fa-info-circle' },
    };
    const conf = colors[type] || colors.info;

    const toast = document.createElement('div');
    toast.style.cssText = [
        'position:fixed', 'bottom:24px', 'right:24px',
        'background:' + conf.bg, 'color:#ffffff',
        'padding:14px 20px', 'border-radius:12px',
        'font-size:14px', 'font-weight:600',
        'display:flex', 'align-items:center', 'gap:10px',
        'z-index:99999', 'box-shadow:0 8px 24px rgba(0,0,0,.25)',
        'animation:slideInToast .3s ease', 'max-width:340px',
        'font-family:Inter,sans-serif'
    ].join(';');

    toast.innerHTML = '<i class="fas ' + conf.icon + '"></i><span>' + message + '</span>';
    document.body.appendChild(toast);

    if (!document.getElementById('toastAnim')) {
        const style = document.createElement('style');
        style.id = 'toastAnim';
        style.textContent = '@keyframes slideInToast{from{transform:translateX(120%);opacity:0}to{transform:translateX(0);opacity:1}}';
        document.head.appendChild(style);
    }

    setTimeout(function () {
        toast.style.animation  = 'none';
        toast.style.opacity    = '0';
        toast.style.transition = 'opacity .3s ease';
        setTimeout(function () { toast.remove(); }, 300);
    }, 3500);
}

/* ---- Enter en usuario → foco en contraseña ---- */
(function () {
    const uInput = document.getElementById('usuario');
    const pInput = document.getElementById('password');
    if (uInput && pInput) {
        uInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                pInput.focus();
            }
        });
    }
})();

/* ---- Highlight del icono al hacer foco ---- */
(function () {
    const inputs = document.querySelectorAll('.form-control');
    inputs.forEach(function (inp) {
        inp.addEventListener('focus', function () {
            const wrapper = inp.closest('.input-wrapper');
            if (wrapper) {
                const icon = wrapper.querySelector('.input-icon');
                if (icon) icon.style.color = 'var(--accent)';
            }
        });
        inp.addEventListener('blur', function () {
            const wrapper = inp.closest('.input-wrapper');
            if (wrapper) {
                const icon = wrapper.querySelector('.input-icon');
                if (icon) icon.style.color = 'var(--text-muted)';
            }
        });
    });
})();

</script>

</body>
</html>