<?php
// register.php
require_once 'config.php';

if (isset($_POST['register'])) {
   $admin_password = "ana123ana";
   $entered_password = $_POST['admin_password'] ?? '';
   
   if ($entered_password !== $admin_password) {
       $errors[] = "Contraseña de administrador incorrecta";
   } else {
       $usuario = trim($_POST['usuario']);
       $password = $_POST['password'];
       $confirm_password = $_POST['confirm_password'];
       $nombre = trim($_POST['nombre']);
       $email = trim($_POST['email']);
       $rol = $_POST['rol'];
       
       $errors = [];
       
       // Validaciones
       if (empty($usuario)) {
           $errors[] = "El usuario es requerido";
       }
       
       if (empty($password)) {
           $errors[] = "La contraseña es requerida";
       } elseif (strlen($password) < 6) {
           $errors[] = "La contraseña debe tener al menos 6 caracteres";
       } elseif ($password !== $confirm_password) {
           $errors[] = "Las contraseñas no coinciden";
       }
       
       if (empty($email)) {
           $errors[] = "El email es requerido";
       } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
           $errors[] = "El formato del email no es válido";
       }
       
       // Verificar si el usuario ya existe
       $stmt = $conn->prepare("SELECT id FROM usuarios WHERE usuario = ? OR email = ?");
       $stmt->execute([$usuario, $email]);
       if ($stmt->fetch()) {
           $errors[] = "El usuario o email ya está registrado";
       }
       
       if (empty($errors)) {
           try {
               $hashed_password = password_hash($password, PASSWORD_DEFAULT);
               $stmt = $conn->prepare("INSERT INTO usuarios (usuario, password, nombre, email, rol) VALUES (?, ?, ?, ?, ?)");
               $stmt->execute([$usuario, $hashed_password, $nombre, $email, $rol]);
               
               $_SESSION['success_message'] = "Usuario registrado exitosamente";
               header('Location: login.php');
               exit();
           } catch (PDOException $e) {
               $errors[] = "Error al registrar el usuario";
           }
       }
   }
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
   <meta charset="UTF-8">
   <meta name="viewport" content="width=device-width, initial-scale=1.0">
   <title>Registar - Sistema de Seguros</title>
   <style>
       body {
           font-family: Arial, sans-serif;
           margin: 0;
           padding: 0;
           display: flex;
           justify-content: center;
           align-items: center;
           min-height: 100vh;
           background-color: #f5f5f5;
       }
       .register-container {
           background: white;
           padding: 2.5rem;
           border-radius: 12px;
           box-shadow: 0 0 20px rgba(0,0,0,0.1);
           width: 100%;
           max-width: 400px;
       }
       .title {
           text-align: center;
           margin-bottom: 2rem;
           color: #333;
       }
       .form-group {
           margin-bottom: 1.5rem;
       }
       label {
           display: block;
           margin-bottom: 0.5rem;
           color: #555;
           font-weight: 500;
       }
       input, select {
           width: 100%;
           padding: 0.75rem;
           border: 1px solid #ddd;
           border-radius: 6px;
           font-size: 1rem;
       }
       .submit-button {
           width: 100%;
           padding: 0.75rem;
           background-color: #007bff;
           color: white;
           border: none;
           border-radius: 6px;
           cursor: pointer;
           font-size: 1rem;
           font-weight: 500;
           margin-bottom: 1.5rem;
       }
       .submit-button:hover {
           background-color: #0056b3;
       }
       .social-login {
           text-align: center;
           margin: 1.5rem 0;
       }
       .social-login-text {
           color: #666;
           margin-bottom: 1rem;
       }
       .social-icons {
           display: flex;
           justify-content: center;
           gap: 1rem;
       }
       .social-icon {
           width: 40px;
           height: 40px;
           border: 1px solid #ddd;
           border-radius: 50%;
           display: flex;
           align-items: center;
           justify-content: center;
           cursor: pointer;
       }
       .social-icon img {
           width: 20px;
           height: 20px;
       }
       .login-link {
           text-align: center;
           margin-top: 1.5rem;
           color: #666;
       }
       .login-link a {
           color: #007bff;
           text-decoration: none;
       }
       .error {
           color: #dc3545;
           text-align: center;
           margin-bottom: 1rem;
           padding: 0.5rem;
           background-color: #fde8e8;
           border-radius: 4px;
       }
       .errors-list {
           list-style: none;
           padding: 0;
           margin: 0 0 1rem 0;
       }
       .errors-list li {
           color: #dc3545;
           font-size: 0.9rem;
           margin-bottom: 0.5rem;
       }
   </style>
</head>
<body>
   <div class="register-container">
       <h2 class="title">Crear una Cuenta</h2>
       
       <?php if (!empty($errors)): ?>
           <ul class="errors-list">
               <?php foreach ($errors as $error): ?>
                   <li><?php echo htmlspecialchars($error); ?></li>
               <?php endforeach; ?>
           </ul>
       <?php endif; ?>

       <form method="POST">
           <div class="form-group">
               <label for="usuario">Usuario</label>
               <input type="text" id="usuario" name="usuario" required 
                      value="<?php echo isset($_POST['usuario']) ? htmlspecialchars($_POST['usuario']) : ''; ?>">
           </div>
           
           <div class="form-group">
               <label for="nombre">Nombre Completo</label>
               <input type="text" id="nombre" name="nombre" required
                      value="<?php echo isset($_POST['nombre']) ? htmlspecialchars($_POST['nombre']) : ''; ?>">
           </div>
           
           <div class="form-group">
               <label for="email">Email</label>
               <input type="email" id="email" name="email" required
                      value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>">
           </div>
           
           <div class="form-group">
               <label for="password">Contraseña</label>
               <input type="password" id="password" name="password" required>
           </div>
           
           <div class="form-group">
               <label for="confirm_password">Confirmar Contraseña</label>
               <input type="password" id="confirm_password" name="confirm_password" required>
           </div>
           
           <div class="form-group">
               <label for="rol">Tipo de cuenta</label>
               <select id="rol" name="rol" required>
                   <option value="">seleccionar el tipo de cuenta</option>
                   <option value="admin">Administrador</option>
                   <option value="vendedor">Vendedor</option>
                   <option value="cobrador">Cobrador</option>
                   <option value="supervisor">Supervisor</option>
               </select>
           </div>

           <div class="form-group">
               <label for="admin_password">Contraseña de Administrador</label>
               <input type="password" id="admin_password" name="admin_password" required>
           </div>

           <button type="submit" name="register" class="submit-button">Crear Una Cuenta</button>
       </form>
       
       <div class="login-link">
           Ya tienes una cuenta? <a href="login.php">Iniciar sesión</a>
       </div>
   </div>
</body>
</html>