<?php
/* ============================================================
   cobrador/config_cobrador.php — VERSIÓN FINAL CORREGIDA
   
   REGLA CRÍTICA: config.php del sistema ya llama session_start().
   Esta versión NO lo llama antes. Solo lo requiere y luego
   verifica que la sesión esté activa.
   ============================================================ */

// Capturar cualquier output inesperado (warnings de config.php)
// para que no corrompan el HTML
if (!ob_get_level()) {
    ob_start();
}

// Incluir config.php del sistema principal PRIMERO
// Él se encarga de session_start() y la conexión $conn
if (!defined('DB_HOST')) {
    require_once __DIR__ . '/../config.php';
}

// Descartar cualquier warning que config.php haya podido generar
// (solo si no hay contenido útil en el buffer)
$bufferActual = ob_get_contents();
if ($bufferActual && str_contains($bufferActual, 'Warning')) {
    ob_clean();
}

// Verificar que la sesión está activa (config.php la inicia)
// Si por alguna razón no lo está, iniciarla de forma segura
if (session_status() !== PHP_SESSION_ACTIVE) {
    @session_start();
}

// Token CSRF exclusivo del portal cobrador
if (empty($_SESSION['csrf_token_cobrador'])) {
    $_SESSION['csrf_token_cobrador'] = bin2hex(random_bytes(32));
}

/* ============================================================
   verificarSesionCobrador()
   Verifica sesión activa de cobrador. Si no hay sesión,
   redirige al login. Para usar en páginas normales.
   ============================================================ */
function verificarSesionCobrador(): void
{
    if (
        empty($_SESSION['cobrador_portal_id']) ||
        empty($_SESSION['cobrador_portal_rol']) ||
        $_SESSION['cobrador_portal_rol'] !== 'cobrador'
    ) {
        // Guardar URL para redirigir después del login
        if (
            !isset($_SESSION['cobrador_redirect_after_login']) &&
            !str_contains($_SERVER['REQUEST_URI'] ?? '', 'index.php')
        ) {
            $_SESSION['cobrador_redirect_after_login'] = $_SERVER['REQUEST_URI'];
        }
        header('Location: index.php');
        exit();
    }
}

/* ============================================================
   verificarSesionCobradorAjax()
   Para endpoints API — responde JSON en lugar de redirigir
   ============================================================ */
function verificarSesionCobradorAjax(): void
{
    if (
        empty($_SESSION['cobrador_portal_id']) ||
        ($_SESSION['cobrador_portal_rol'] ?? '') !== 'cobrador'
    ) {
        // Limpiar cualquier output antes de responder JSON
        if (ob_get_level()) ob_clean();
        header('Content-Type: application/json; charset=utf-8');
        http_response_code(401);
        echo json_encode(['success' => false, 'message' => 'Sesión expirada. Por favor inicia sesión nuevamente.']);
        exit();
    }
}

/* ============================================================
   getCobradorActual()
   Retorna datos del cobrador autenticado desde la BD
   ============================================================ */
function getCobradorActual(): array
{
    global $conn;
    $id = (int)($_SESSION['cobrador_portal_id'] ?? 0);
    if (!$id) return [];
    try {
        $stmt = $conn->prepare("SELECT * FROM cobradores WHERE id = ? AND estado = 'activo' LIMIT 1");
        $stmt->execute([$id]);
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
    } catch (PDOException $e) {
        error_log('getCobradorActual: ' . $e->getMessage());
        return [];
    }
}

/* ============================================================
   getMensajesNoLeidos()
   Retorna cantidad de mensajes sin leer. Seguro si tabla no existe.
   ============================================================ */
function getMensajesNoLeidos(): int
{
    global $conn;
    $id = (int)($_SESSION['cobrador_portal_id'] ?? 0);
    if (!$id) return 0;
    try {
        $stmt = $conn->prepare("
            SELECT COUNT(*) FROM cobrador_mensajes
            WHERE cobrador_id = ? AND leido = 0
        ");
        $stmt->execute([$id]);
        return (int)$stmt->fetchColumn();
    } catch (PDOException $e) {
        return 0;
    }
}

/* ============================================================
   FUNCIÓN: verificarAccesoFactura
   El cobrador puede acceder a facturas de 3 formas:
   1. La factura pertenece a un cliente asignado a él (cl.cobrador_id)
   2. La factura está en asignaciones_facturas para él
   3. La factura está en cobrador_facturas_autorizadas para él
   ============================================================ */
function verificarAccesoFactura(int $facturaId, int $cobradorId): bool
{
    global $conn;

    try {
        // ── VERIFICACIÓN PRINCIPAL: ¿El cliente de la factura está asignado a este cobrador? ──
        $stmt = $conn->prepare("
            SELECT COUNT(*)
            FROM facturas f
            JOIN contratos c  ON f.contrato_id = c.id
            JOIN clientes  cl ON c.cliente_id  = cl.id
            WHERE f.id          = ?
              AND cl.cobrador_id = ?
        ");
        $stmt->execute([$facturaId, $cobradorId]);
        if ((int)$stmt->fetchColumn() > 0) return true;

        // ── VERIFICACIÓN 2: ¿Está en asignaciones_facturas para este cobrador? ──
        $stmt = $conn->prepare("
            SELECT COUNT(*)
            FROM asignaciones_facturas
            WHERE factura_id  = ?
              AND cobrador_id = ?
              AND estado      = 'activa'
        ");
        $stmt->execute([$facturaId, $cobradorId]);
        if ((int)$stmt->fetchColumn() > 0) return true;

        // ── VERIFICACIÓN 3: ¿Tiene autorización especial? ──
        $stmt = $conn->prepare("
            SELECT COUNT(*)
            FROM cobrador_facturas_autorizadas
            WHERE factura_id  = ?
              AND cobrador_id = ?
              AND estado      = 'activa'
              AND (fecha_expiracion IS NULL OR fecha_expiracion > NOW())
        ");
        $stmt->execute([$facturaId, $cobradorId]);
        if ((int)$stmt->fetchColumn() > 0) return true;

        return false;

    } catch (PDOException $e) {
        error_log('verificarAccesoFactura: ' . $e->getMessage());
        return false;
    }
}

/* ============================================================
   registrarLogCobrador()
   Registra accesos en el log. Silencioso si tabla no existe.
   ============================================================ */
function registrarLogCobrador(int $cobradorId, string $accion): void
{
    global $conn;
    try {
        $conn->prepare("
            INSERT INTO cobrador_sesiones_log (cobrador_id, ip_address, user_agent, accion)
            VALUES (?, ?, ?, ?)
        ")->execute([
            $cobradorId,
            $_SERVER['REMOTE_ADDR'] ?? null,
            substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255),
            $accion,
        ]);
    } catch (PDOException $e) {
        error_log('registrarLogCobrador: ' . $e->getMessage());
    }
}