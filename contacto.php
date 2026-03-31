<?php
require_once 'config.php';

$mensaje_estado = '';
$tipo_mensaje = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    try {
        $stmt = $conn->prepare("
            INSERT INTO contactos (
                nombre, 
                email, 
                telefono, 
                asunto, 
                mensaje, 
                fecha_contacto
            ) VALUES (?, ?, ?, ?, ?, NOW())
        ");
        
        $stmt->execute([
            $_POST['nombre'],
            $_POST['email'],
            $_POST['telefono'],
            $_POST['asunto'],
            $_POST['mensaje']
        ]);
        
        $mensaje_estado = "Mensaje enviado exitosamente. Nos pondremos en contacto pronto.";
        $tipo_mensaje = "success";
        
        // Enviar email de notificación (opcional)
        $to = "info@segurosbonao.com";
        $subject = "Nuevo mensaje de contacto: " . $_POST['asunto'];
        $message = "Nuevo mensaje de: " . $_POST['nombre'] . "\n";
        $message .= "Email: " . $_POST['email'] . "\n";
        $message .= "Teléfono: " . $_POST['telefono'] . "\n";
        $message .= "Mensaje: " . $_POST['mensaje'];
        
        mail($to, $subject, $message);
        
    } catch(PDOException $e) {
        $mensaje_estado = "Error al enviar el mensaje: " . $e->getMessage();
        $tipo_mensaje = "error";
    }
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Contacto - Seguros Bonao</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #2563eb;
            --secondary-color: #1d4ed8;
            --success-color: #16a34a;
            --danger-color: #dc2626;
            --dark-color: #1f2937;
            --light-color: #f3f4f6;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Poppins', sans-serif;
            background-color: var(--light-color);
            line-height: 1.6;
        }

        .header {
            background-color: white;
            padding: 1rem 2rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .nav-container {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo {
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--primary-color);
            text-decoration: none;
        }

        .contact-container {
            max-width: 800px;
            margin: 2rem auto;
            padding: 0 1rem;
        }

        .contact-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
            margin-top: 2rem;
        }

        .contact-info {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .contact-form {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: var(--dark-color);
        }

        .form-control {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-family: inherit;
        }

        .form-control:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 2px rgba(37,99,235,0.2);
        }

        .btn {
            display: inline-block;
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 6px;
            background-color: var(--primary-color);
            color: white;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .btn:hover {
            background-color: var(--secondary-color);
        }

        .alert {
            padding: 1rem;
            border-radius: 6px;
            margin-bottom: 1rem;
        }

        .alert-success {
            background-color: #dcfce7;
            color: var(--success-color);
            border: 1px solid #86efac;
        }

        .alert-error {
            background-color: #fee2e2;
            color: var(--danger-color);
            border: 1px solid #fca5a5;
        }

        .contact-method {
            display: flex;
            align-items: center;
            margin-bottom: 1rem;
        }

        .contact-method i {
            width: 30px;
            color: var(--primary-color);
        }

        .map-container {
            margin-top: 1rem;
            border-radius: 8px;
            overflow: hidden;
        }

        .map-container iframe {
            width: 100%;
            height: 250px;
            border: 0;
        }

        @media (max-width: 768px) {
            .contact-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="nav-container">
            <a href="index.php" class="logo">Seguros Bonao</a>
            <a href="login.php" class="btn">Iniciar Sesión</a>
        </div>
    </header>

    <div class="contact-container">
        <h1>Contáctanos</h1>
        
        <?php if ($mensaje_estado): ?>
            <div class="alert alert-<?php echo $tipo_mensaje; ?>">
                <?php echo $mensaje_estado; ?>
            </div>
        <?php endif; ?>

        <div class="contact-grid">
            <div class="contact-info">
                <h2>Información de Contacto</h2>
                <div class="contact-method">
                    <i class="fas fa-map-marker-alt"></i>
                    <p>Calle Principal #123, Bonao, República Dominicana</p>
                </div>
                <div class="contact-method">
                    <i class="fas fa-phone"></i>
                    <p>+1 (809) 555-0123</p>
                </div>
                <div class="contact-method">
                    <i class="fas fa-envelope"></i>
                    <p>info@segurosbonao.com</p>
                </div>
                <div class="contact-method">
                    <i class="fas fa-clock"></i>
                    <p>Lunes a Viernes: 8:00 AM - 5:00 PM</p>
                </div>

                <div class="map-container">
                    <iframe 
                        src="https://www.google.com/maps/embed?pb=YOUR_GOOGLE_MAPS_EMBED_CODE"
                        allowfullscreen=""
                        loading="lazy">
                    </iframe>
                </div>
            </div>

            <div class="contact-form">
                <h2>Envíanos un Mensaje</h2>
                <form method="POST">
                    <div class="form-group">
                        <label for="nombre">Nombre Completo</label>
                        <input type="text" id="nombre" name="nombre" class="form-control" required>
                    </div>

                    <div class="form-group">
                        <label for="email">Correo Electrónico</label>
                        <input type="email" id="email" name="email" class="form-control" required>
                    </div>

                    <div class="form-group">
                        <label for="telefono">Teléfono</label>
                        <input type="tel" id="telefono" name="telefono" class="form-control" required>
                    </div>

                    <div class="form-group">
                        <label for="asunto">Asunto</label>
                        <input type="text" id="asunto" name="asunto" class="form-control" required>
                    </div>

                    <div class="form-group">
                        <label for="mensaje">Mensaje</label>
                        <textarea id="mensaje" name="mensaje" class="form-control" rows="5" required></textarea>
                    </div>

                    <button type="submit" class="btn">
                        <i class="fas fa-paper-plane"></i> Enviar Mensaje
                    </button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>