<?php
// Asegurarse de que no haya salida antes de verificar la sesión
class Toast {
    private static $messages = [];

    // Método para agregar un mensaje a la cola
    public static function add($message, $type = 'info', $duration = 4000) {
        self::$messages[] = [
            'message' => $message,
            'type' => $type,
            'duration' => $duration
        ];
    }

    // Método para obtener todos los mensajes
    public static function getMessages() {
        return self::$messages;
    }

    // Método para limpiar los mensajes
    public static function clear() {
        self::$messages = [];
    }

    // Método para obtener el HTML y JavaScript necesario
    public static function render() {
        ob_start();
        ?>
        <!-- Incluir Toastify CSS -->
        <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/toastify-js/src/toastify.min.css">

        <!-- Incluir Toastify JS -->
        <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/toastify-js"></script>

        <!-- Estilos personalizados para los toast -->
        <style>
        .toastify {
            font-family: 'Arial', sans-serif;
            padding: 12px 20px;
            color: white;
            border-radius: 6px;
            cursor: pointer;
            max-width: 400px;
            box-shadow: 0 3px 6px rgba(0,0,0,0.16);
        }

        .toastify.success {
            background: linear-gradient(to right, #28a745, #218838);
        }

        .toastify.error {
            background: linear-gradient(to right, #dc3545, #c82333);
        }

        .toastify.warning {
            background: linear-gradient(to right, #ffc107, #e0a800);
            color: #000;
        }

        .toastify.info {
            background: linear-gradient(to right, #17a2b8, #138496);
        }
        </style>

        <script>
        function mostrarToast(mensaje, tipo = 'info', duracion = 4000) {
            const backgroundColor = {
                success: 'linear-gradient(to right, #28a745, #218838)',
                error: 'linear-gradient(to right, #dc3545, #c82333)',
                warning: 'linear-gradient(to right, #ffc107, #e0a800)',
                info: 'linear-gradient(to right, #17a2b8, #138496)'
            };

            Toastify({
                text: mensaje,
                duration: duracion,
                close: true,
                gravity: "top",
                position: "right",
                backgroundColor: backgroundColor[tipo] || backgroundColor.info,
                stopOnFocus: true,
                className: tipo,
                onClick: function(){} // Callback después de hacer clic
            }).showToast();
        }

        function mostrarMultipleToast(mensajes) {
            let delay = 0;
            mensajes.forEach(toast => {
                setTimeout(() => {
                    mostrarToast(toast.message, toast.type, toast.duration);
                }, delay);
                delay += 300;
            });
        }

        <?php if (!empty(self::getMessages())): ?>
        document.addEventListener('DOMContentLoaded', function() {
            const mensajes = <?php echo json_encode(self::getMessages()); ?>;
            mostrarMultipleToast(mensajes);
        });
        <?php endif; ?>
        </script>
        <?php
        $output = ob_get_clean();
        self::clear();
        return $output;
    }
}

// NO agregar mensajes de ejemplo aquí
// Toast::add('Mensaje de éxito', 'success');
?>