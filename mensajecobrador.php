<?php
/* ============================================================
   mensajecobrador.php — Comunicación de oficina con cobradores
   Sistema ORTHIIS — Solo admin y supervisor
   CORRECCIÓN: El procesamiento POST va ANTES de header.php
   ============================================================ */

// ── Cargar config ANTES de header.php para poder redirigir ──
require_once 'config.php';
verificarSesion();

// Solo admin y supervisor pueden acceder
if (!in_array($_SESSION['rol'], ['admin', 'supervisor'])) {
    header('Location: dashboard.php');
    exit();
}

// ── Procesar envío de mensaje ANTES de cualquier output HTML ──
$msgSuccess = '';
$msgError   = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if ($_POST['action'] === 'enviar_mensaje') {
        $destCobrador  = (int)($_POST['cobrador_id']      ?? 0);
        $asunto        = trim($_POST['asunto']             ?? '');
        $mensaje       = trim($_POST['mensaje']            ?? '');
        $prioridad     = in_array($_POST['prioridad'] ?? '', ['normal','urgente','informativo'])
                         ? $_POST['prioridad'] : 'normal';
        $clienteVisita = (int)($_POST['cliente_visita_id'] ?? 0);

        if (!$destCobrador || $asunto === '' || $mensaje === '') {
            $msgError = 'Completa todos los campos obligatorios (asunto y mensaje).';
        } else {
            try {
                $stmt = $conn->prepare("
                    INSERT INTO cobrador_mensajes
                        (cobrador_id, usuario_id, asunto, mensaje,
                         prioridad, cliente_visita_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                ");
                $stmt->execute([
                    $destCobrador,
                    $_SESSION['usuario_id'],
                    $asunto,
                    $mensaje,
                    $prioridad,
                    $clienteVisita ?: null,
                ]);

                // Redirigir ANTES de que se envíe cualquier HTML
                header("Location: mensajecobrador.php?cobrador_id={$destCobrador}&sent=1");
                exit();

            } catch (PDOException $e) {
                error_log('mensajecobrador enviar: ' . $e->getMessage());
                $msgError = 'Error al enviar el mensaje. Intenta de nuevo.';
            }
        }
    }
}

// ── Leer mensaje de éxito si viene de la redirección ──
if (isset($_GET['sent']) && $_GET['sent'] === '1') {
    $msgSuccess = 'Mensaje enviado correctamente al cobrador.';
}

// ── Ahora sí cargar el header (genera el HTML) ──
require_once 'header.php';

// ── Datos de cobradores ──
$cobradores = [];
try {
    $cobradores = $conn->query("
        SELECT c.id, c.codigo, c.nombre_completo,
               (SELECT COUNT(*) FROM cobrador_mensajes m
                WHERE m.cobrador_id = c.id) AS total_mensajes,
               (SELECT COUNT(*) FROM cobrador_mensajes m
                WHERE m.cobrador_id = c.id AND m.leido = 1) AS total_leidos,
               (SELECT COUNT(*) FROM clientes cl
                WHERE cl.cobrador_id = c.id AND cl.estado = 'activo') AS total_clientes
        FROM cobradores c
        WHERE c.estado = 'activo'
        ORDER BY c.nombre_completo ASC
    ")->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log('mensajecobrador cobradores: ' . $e->getMessage());
}

// ── Cobrador seleccionado ──
$cobradorSel      = (int)($_GET['cobrador_id'] ?? 0);
$cobradorSelData  = null;
$mensajesChat     = [];
$clientesCobrador = [];

if ($cobradorSel > 0) {
    try {
        $s = $conn->prepare("SELECT * FROM cobradores WHERE id = ? AND estado = 'activo' LIMIT 1");
        $s->execute([$cobradorSel]);
        $cobradorSelData = $s->fetch(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log('mensajecobrador cobrador sel: ' . $e->getMessage());
    }

    if ($cobradorSelData) {
        // Historial de mensajes del chat
        try {
            $s = $conn->prepare("
                SELECT m.*,
                       u.nombre AS remitente_nombre,
                       u.rol    AS remitente_rol,
                       cl.nombre    AS cv_nombre,
                       cl.apellidos AS cv_apellidos,
                       cl.direccion AS cv_dir,
                       cl.id        AS cv_id_real
                FROM cobrador_mensajes m
                JOIN usuarios u ON m.usuario_id = u.id
                LEFT JOIN clientes cl ON cl.id = m.cliente_visita_id
                WHERE m.cobrador_id = ?
                ORDER BY m.fecha_envio ASC
                LIMIT 80
            ");
            $s->execute([$cobradorSel]);
            $mensajesChat = $s->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log('mensajecobrador mensajes: ' . $e->getMessage());
        }

        // Clientes del cobrador para el selector de "visitar"
        try {
            $s = $conn->prepare("
                SELECT cl.id, cl.nombre, cl.apellidos,
                       cl.direccion, cl.telefono1,
                       (SELECT c2.numero_contrato
                        FROM contratos c2
                        WHERE c2.cliente_id = cl.id AND c2.estado = 'activo'
                        ORDER BY c2.id ASC LIMIT 1) AS numero_contrato
                FROM clientes cl
                WHERE cl.cobrador_id = ? AND cl.estado = 'activo'
                ORDER BY cl.nombre ASC, cl.apellidos ASC
                LIMIT 300
            ");
            $s->execute([$cobradorSel]);
            $clientesCobrador = $s->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log('mensajecobrador clientes: ' . $e->getMessage());
        }
    }
}

function tiempoRelO(string $fecha): string {
    $diff = time() - strtotime($fecha);
    if ($diff < 60)     return 'Ahora';
    if ($diff < 3600)   return floor($diff / 60) . ' min';
    if ($diff < 86400)  return floor($diff / 3600) . ' h';
    if ($diff < 172800) return 'Ayer';
    return date('d/m/Y H:i', strtotime($fecha));
}
?>

<style>
/* ════════════════════════════════════════════
   ESTILOS mensajecobrador.php
════════════════════════════════════════════ */
.mc-layout {
    display: grid;
    grid-template-columns: 270px 1fr;
    gap: 20px;
    height: calc(100vh - 140px);
    min-height: 520px;
    max-width: 1200px;
    margin: 0 auto;
}

/* ── Sidebar de cobradores ── */
.mc-sidebar {
    background: var(--white);
    border-radius: var(--radius);
    border: 1px solid var(--border);
    box-shadow: var(--shadow-sm);
    display: flex;
    flex-direction: column;
    overflow: hidden;
}

.mc-sidebar-hdr {
    padding: 13px 15px;
    border-bottom: 1px solid var(--border);
    background: var(--gray-50);
    font-size: 13px;
    font-weight: 700;
    color: var(--gray-700);
    display: flex;
    align-items: center;
    gap: 6px;
    flex-shrink: 0;
}

.mc-sidebar-search {
    padding: 9px 11px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
}

.mc-sidebar-search input {
    width: 100%;
    height: 32px;
    border: 1.5px solid var(--gray-200);
    border-radius: 16px;
    padding: 0 12px;
    font-size: 12px;
    outline: none;
    box-sizing: border-box;
    transition: border-color .2s;
    background: var(--white);
    color: var(--text);
}

.mc-sidebar-search input:focus { border-color: var(--accent); }

.mc-cobrador-list {
    flex: 1;
    overflow-y: auto;
}

.mc-cobrador-item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 11px 13px;
    border-bottom: 1px solid var(--gray-100);
    cursor: pointer;
    text-decoration: none;
    color: inherit;
    transition: background .15s;
}

.mc-cobrador-item:hover { background: var(--gray-50); }

.mc-cobrador-item.active {
    background: var(--accent-light);
    border-left: 3px solid var(--accent);
}

.mc-cobrador-avatar {
    width: 36px;
    height: 36px;
    border-radius: 50%;
    background: var(--primary);
    color: #fff;
    font-size: 13px;
    font-weight: 700;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
}

/* ── Panel principal (chat) ── */
.mc-main {
    background: var(--white);
    border-radius: var(--radius);
    border: 1px solid var(--border);
    box-shadow: var(--shadow-sm);
    display: flex;
    flex-direction: column;
    overflow: hidden;
}

.mc-main-hdr {
    padding: 13px 17px;
    border-bottom: 1px solid var(--border);
    background: var(--gray-50);
    display: flex;
    align-items: center;
    gap: 12px;
    flex-shrink: 0;
    flex-wrap: wrap;
}

/* ── Área de chat ── */
.mc-chat-area {
    flex: 1;
    overflow-y: auto;
    padding: 16px;
    display: flex;
    flex-direction: column;
    gap: 10px;
    background: var(--gray-50);
    scroll-behavior: smooth;
}

.mc-burbuja {
    display: flex;
    flex-direction: column;
    max-width: 78%;
}

.mc-burbuja.enviado {
    align-self: flex-end;
    align-items: flex-end;
}

.mc-burbuja-cuerpo {
    padding: 10px 13px;
    border-radius: 16px;
    font-size: 13px;
    line-height: 1.6;
    word-break: break-word;
    white-space: pre-wrap;
    background: var(--accent);
    color: #fff;
    border-bottom-right-radius: 4px;
}

.mc-burbuja-asunto {
    font-size: 10px;
    font-weight: 700;
    opacity: .8;
    text-transform: uppercase;
    letter-spacing: .5px;
    margin-bottom: 5px;
    display: flex;
    align-items: center;
    gap: 5px;
}

.mc-burbuja-meta {
    font-size: 10px;
    color: var(--gray-400);
    margin-top: 4px;
    padding: 0 4px;
    display: flex;
    align-items: center;
    gap: 5px;
}

.mc-burbuja-meta.leido { color: var(--accent); }

.mc-visita-card {
    background: #fffbeb;
    border: 1px solid #fde68a;
    border-radius: 10px;
    padding: 10px 12px;
    margin-top: 6px;
    font-size: 12px;
    color: #78350f;
    max-width: 100%;
}

.mc-visita-card-titulo {
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: .4px;
    color: #92400e;
    margin-bottom: 5px;
    display: flex;
    align-items: center;
    gap: 4px;
}

.mc-empty-chat {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    color: var(--gray-400);
    text-align: center;
    padding: 40px;
}

.mc-empty-chat i {
    font-size: 44px;
    opacity: .2;
    display: block;
    margin-bottom: 12px;
}

/* ── Formulario de envío ── */
.mc-form-area {
    padding: 13px 15px;
    border-top: 1px solid var(--border);
    background: var(--white);
    flex-shrink: 0;
}

.mc-label {
    display: block;
    font-size: 10px;
    font-weight: 700;
    color: var(--gray-500);
    text-transform: uppercase;
    letter-spacing: .5px;
    margin-bottom: 4px;
}

.mc-input,
.mc-select {
    width: 100%;
    height: 36px;
    border: 1.5px solid var(--gray-200);
    border-radius: var(--radius-sm);
    padding: 0 10px;
    font-size: 13px;
    outline: none;
    transition: border-color .2s;
    background: var(--white);
    color: var(--text);
    font-family: inherit;
    box-sizing: border-box;
}

.mc-input:focus,
.mc-select:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(37,99,235,.08);
}

.mc-select { cursor: pointer; }

.mc-textarea {
    width: 100%;
    border: 1.5px solid var(--gray-200);
    border-radius: var(--radius-sm);
    padding: 8px 11px;
    font-size: 13px;
    outline: none;
    resize: none;
    transition: border-color .2s;
    background: var(--white);
    color: var(--text);
    font-family: inherit;
    line-height: 1.5;
    box-sizing: border-box;
}

.mc-textarea:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(37,99,235,.08);
}

/* Responsive */
@media (max-width: 768px) {
    .mc-layout {
        grid-template-columns: 1fr;
        height: auto;
    }
    .mc-sidebar  { max-height: 260px; }
    .mc-main     { min-height: 500px; }
    .mc-form-grid { grid-template-columns: 1fr !important; }
}
</style>

<div class="page-content">
<div style="max-width:1200px;margin:0 auto;">

  <!-- ── Título de página ── -->
  <div style="display:flex;align-items:center;justify-content:space-between;
              margin-bottom:18px;flex-wrap:wrap;gap:10px;">
    <div>
      <div class="page-title" style="font-size:20px;font-weight:700;
           color:var(--gray-800);display:flex;align-items:center;gap:8px;">
        <i class="fas fa-comments" style="color:var(--accent);"></i>
        Mensajes a Cobradores
      </div>
      <div style="font-size:13px;color:var(--text-muted);margin-top:3px;">
        Envía mensajes y notificaciones de visita a tu equipo de cobradores
      </div>
    </div>
  </div>

  <!-- ── Alertas ── -->
  <?php if ($msgSuccess): ?>
  <div style="background:var(--success-light);color:var(--success-text);
       border:1px solid #bbf7d0;border-radius:var(--radius);
       padding:11px 15px;margin-bottom:14px;
       display:flex;align-items:center;gap:8px;font-size:13px;">
    <i class="fas fa-check-circle"></i>
    <?= htmlspecialchars($msgSuccess) ?>
  </div>
  <?php endif; ?>

  <?php if ($msgError): ?>
  <div style="background:var(--danger-light);color:var(--danger-text);
       border:1px solid #fca5a5;border-radius:var(--radius);
       padding:11px 15px;margin-bottom:14px;
       display:flex;align-items:center;gap:8px;font-size:13px;">
    <i class="fas fa-circle-exclamation"></i>
    <?= htmlspecialchars($msgError) ?>
  </div>
  <?php endif; ?>

  <!-- ════════════════════════════════════
       LAYOUT: Sidebar + Panel principal
  ════════════════════════════════════ -->
  <div class="mc-layout">

    <!-- ── Sidebar: lista de cobradores ── -->
    <div class="mc-sidebar">
      <div class="mc-sidebar-hdr">
        <i class="fas fa-motorcycle" style="color:var(--accent);font-size:14px;"></i>
        Cobradores (<?= count($cobradores) ?>)
      </div>
      <div class="mc-sidebar-search">
        <input type="text" id="buscarCobrador"
               placeholder="Buscar cobrador..."
               oninput="filtrarCobradores(this.value)">
      </div>
      <div class="mc-cobrador-list" id="listaCobradoresMC">
        <?php if (empty($cobradores)): ?>
          <div style="padding:20px;text-align:center;font-size:13px;
                      color:var(--gray-400);">
            Sin cobradores activos
          </div>
        <?php else: ?>
        <?php foreach ($cobradores as $cob):
            $ini      = strtoupper(substr($cob['nombre_completo'], 0, 1));
            $sinLeer  = max(0, (int)$cob['total_mensajes'] - (int)$cob['total_leidos']);
            $isActive = ((int)$cob['id'] === $cobradorSel);
        ?>
        <a href="mensajecobrador.php?cobrador_id=<?= $cob['id'] ?>"
           class="mc-cobrador-item <?= $isActive ? 'active' : '' ?>"
           data-nombre="<?= htmlspecialchars(mb_strtolower($cob['nombre_completo'])) ?>">
          <div class="mc-cobrador-avatar"><?= htmlspecialchars($ini) ?></div>
          <div style="flex:1;min-width:0;">
            <div style="font-size:13px;font-weight:600;color:var(--gray-800);
                        white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
              <?= htmlspecialchars($cob['nombre_completo']) ?>
            </div>
            <div style="font-size:11px;color:var(--text-muted);margin-top:1px;">
              Cód. <?= htmlspecialchars($cob['codigo']) ?>
              &bull; <?= (int)$cob['total_clientes'] ?> clientes
              &bull; <?= (int)$cob['total_mensajes'] ?> msgs
            </div>
          </div>
          <?php if ($sinLeer > 0): ?>
          <span style="background:var(--accent);color:#fff;border-radius:10px;
                       font-size:10px;font-weight:700;padding:1px 7px;
                       flex-shrink:0;white-space:nowrap;">
            <?= $sinLeer ?>
          </span>
          <?php endif; ?>
        </a>
        <?php endforeach; ?>
        <?php endif; ?>
      </div>
    </div><!-- /.mc-sidebar -->

    <!-- ── Panel principal ── -->
    <div class="mc-main">

      <?php if (!$cobradorSelData): ?>
      <!-- Sin cobrador seleccionado -->
      <div class="mc-empty-chat">
        <i class="fas fa-comments"></i>
        <h3 style="font-size:16px;font-weight:600;color:var(--gray-500);
                   margin-bottom:6px;">
          Selecciona un cobrador
        </h3>
        <p style="font-size:13px;">
          Elige un cobrador de la lista de la izquierda para ver su
          historial de mensajes y enviarle una notificación.
        </p>
      </div>

      <?php else: ?>
      <!-- ── Encabezado del chat ── -->
      <div class="mc-main-hdr">
        <div class="mc-cobrador-avatar" style="width:40px;height:40px;font-size:15px;">
          <?= strtoupper(substr($cobradorSelData['nombre_completo'], 0, 1)) ?>
        </div>
        <div style="flex:1;min-width:0;">
          <div style="font-size:15px;font-weight:700;color:var(--gray-800);">
            <?= htmlspecialchars($cobradorSelData['nombre_completo']) ?>
          </div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:1px;">
            Código: <?= htmlspecialchars($cobradorSelData['codigo']) ?>
            &bull; <?= count($clientesCobrador) ?> clientes activos
            &bull; <?= count($mensajesChat) ?> mensajes en historial
          </div>
        </div>
        <span style="background:var(--success-light);color:var(--success-text);
                     font-size:11px;font-weight:700;padding:3px 10px;
                     border-radius:12px;">
          <i class="fas fa-circle" style="font-size:8px;margin-right:3px;"></i>
          Activo
        </span>
      </div>

      <!-- ── Área de chat (mensajes) ── -->
      <div class="mc-chat-area" id="chatArea">
        <?php if (empty($mensajesChat)): ?>
        <div style="margin:auto;text-align:center;color:var(--gray-400);
                    font-size:13px;padding:30px;">
          <i class="fas fa-comment-slash"
             style="font-size:36px;display:block;margin-bottom:10px;opacity:.25;"></i>
          Sin mensajes aún. Envía el primero usando el formulario de abajo.
        </div>
        <?php else: ?>
        <?php foreach ($mensajesChat as $msg):
            $tieneVisita = !empty($msg['cv_id_real']);
            $esLeido     = (bool)$msg['leido'];
            $esUrgente   = $msg['prioridad'] === 'urgente';
        ?>
        <div class="mc-burbuja enviado">
          <div class="mc-burbuja-cuerpo">
            <!-- Asunto como encabezado -->
            <div class="mc-burbuja-asunto">
              <?php if ($esUrgente): ?>
                <span style="background:rgba(255,255,255,.2);border-radius:8px;
                             padding:1px 6px;">🚨 URGENTE</span>
              <?php elseif ($msg['prioridad'] === 'informativo'): ?>
                <span style="opacity:.7;">ℹ INFO</span>
              <?php endif; ?>
              <?= htmlspecialchars($msg['asunto']) ?>
            </div>
            <!-- Texto del mensaje -->
            <?= nl2br(htmlspecialchars($msg['mensaje'])) ?>
          </div>

          <!-- Tarjeta de visita si aplica -->
          <?php if ($tieneVisita): ?>
          <div class="mc-visita-card">
            <div class="mc-visita-card-titulo">
              <i class="fas fa-location-dot"></i>
              Visitar cliente
            </div>
            <div style="font-weight:600;">
              <?= htmlspecialchars($msg['cv_nombre'] . ' ' . $msg['cv_apellidos']) ?>
            </div>
            <?php if ($msg['cv_dir']): ?>
            <div style="margin-top:3px;opacity:.8;font-size:11px;">
              <i class="fas fa-map-marker-alt" style="font-size:9px;"></i>
              <?= htmlspecialchars(mb_substr($msg['cv_dir'], 0, 55)) ?>
            </div>
            <?php endif; ?>
          </div>
          <?php endif; ?>

          <!-- Meta: quién envió + hora + estado lectura -->
          <div class="mc-burbuja-meta">
            <i class="fas fa-user" style="font-size:9px;"></i>
            <?= htmlspecialchars($msg['remitente_nombre']) ?>
            &bull;
            <?= htmlspecialchars(tiempoRelO($msg['fecha_envio'])) ?>
          </div>
          <div class="mc-burbuja-meta <?= $esLeido ? 'leido' : '' ?>">
            <i class="fas fa-check<?= $esLeido ? '-double' : '' ?>"
               style="font-size:10px;"></i>
            <?php if ($esLeido && $msg['fecha_leido']): ?>
              Leído <?= date('d/m H:i', strtotime($msg['fecha_leido'])) ?>
            <?php elseif ($esLeido): ?>
              Leído
            <?php else: ?>
              Enviado · sin leer
            <?php endif; ?>
          </div>
        </div>
        <?php endforeach; ?>
        <?php endif; ?>
      </div><!-- /.mc-chat-area -->

      <!-- ── Formulario de envío de mensaje ── -->
      <div class="mc-form-area">
        <form method="POST"
              action="mensajecobrador.php?cobrador_id=<?= $cobradorSel ?>"
              id="formEnviarMensaje"
              onsubmit="bloquearEnvio()">
          <input type="hidden" name="action"      value="enviar_mensaje">
          <input type="hidden" name="cobrador_id" value="<?= $cobradorSel ?>">

          <!-- Fila: Asunto + Prioridad -->
          <div class="mc-form-grid"
               style="display:grid;grid-template-columns:1fr 180px;gap:10px;
                      margin-bottom:10px;">
            <div>
              <label class="mc-label">
                Asunto <span style="color:var(--danger);">*</span>
              </label>
              <input type="text" name="asunto"
                     class="mc-input"
                     placeholder="Ej: Recordatorio de cobro"
                     required maxlength="150"
                     value="<?= isset($_POST['asunto'])
                        ? htmlspecialchars($_POST['asunto']) : '' ?>">
            </div>
            <div>
              <label class="mc-label">Prioridad</label>
              <select name="prioridad" class="mc-select">
                <option value="normal"     <?= ($_POST['prioridad'] ?? '') === 'normal'     ? 'selected' : '' ?>>Normal</option>
                <option value="urgente"    <?= ($_POST['prioridad'] ?? '') === 'urgente'    ? 'selected' : '' ?>>🚨 Urgente</option>
                <option value="informativo"<?= ($_POST['prioridad'] ?? '') === 'informativo'? 'selected' : '' ?>>ℹ Informativo</option>
              </select>
            </div>
          </div>

          <!-- Selector: Cliente a visitar -->
          <?php if (!empty($clientesCobrador)): ?>
          <div style="margin-bottom:10px;">
            <label class="mc-label">
              <i class="fas fa-location-dot"
                 style="color:var(--warning);margin-right:3px;"></i>
              Cliente a visitar
              <span style="font-weight:400;color:var(--gray-400);
                           text-transform:none;font-size:10px;">
                (opcional)
              </span>
            </label>
            <select name="cliente_visita_id" class="mc-select">
              <option value="">— Sin cliente específico —</option>
              <?php foreach ($clientesCobrador as $cl): ?>
              <option value="<?= (int)$cl['id'] ?>">
                <?= htmlspecialchars($cl['nombre'] . ' ' . $cl['apellidos']) ?>
                <?= $cl['numero_contrato'] ? ' | ' . htmlspecialchars($cl['numero_contrato']) : '' ?>
                <?= $cl['direccion'] ? ' | ' . htmlspecialchars(mb_substr($cl['direccion'], 0, 28)) : '' ?>
              </option>
              <?php endforeach; ?>
            </select>
          </div>
          <?php endif; ?>

          <!-- Mensaje + botón enviar -->
          <div style="display:flex;gap:10px;align-items:flex-end;">
            <div style="flex:1;">
              <label class="mc-label">
                Mensaje <span style="color:var(--danger);">*</span>
                <span id="charCountWrap"
                      style="float:right;font-weight:400;color:var(--gray-400);
                             text-transform:none;font-size:10px;">
                  <span id="charCount">0</span>/1000
                </span>
              </label>
              <textarea name="mensaje"
                        class="mc-textarea"
                        rows="3"
                        placeholder="Escribe el mensaje para el cobrador... (Ctrl+Enter para enviar)"
                        required
                        maxlength="1000"
                        id="txtMensaje"
                        oninput="actualizarContador(this)"><?= isset($_POST['mensaje'])
                            ? htmlspecialchars($_POST['mensaje']) : '' ?></textarea>
            </div>
            <button type="submit"
                    id="btnEnviarMsg"
                    class="btn btn-primary"
                    style="min-height:90px;padding:0 22px;flex-shrink:0;
                           font-size:13px;flex-direction:column;gap:6px;">
              <i class="fas fa-paper-plane"
                 style="font-size:18px;display:block;"></i>
              Enviar
            </button>
          </div>
        </form>
      </div><!-- /.mc-form-area -->

      <?php endif; // fin $cobradorSelData ?>
    </div><!-- /.mc-main -->

  </div><!-- /.mc-layout -->
</div>
</div><!-- /.page-content -->

<script>
/* ── Filtrar cobradores en sidebar ── */
function filtrarCobradores(q) {
    q = (q || '').toLowerCase().trim();
    document.querySelectorAll('#listaCobradoresMC .mc-cobrador-item')
        .forEach(function(item) {
            var nombre = (item.dataset.nombre || '');
            item.style.display = (!q || nombre.includes(q)) ? '' : 'none';
        });
}

/* ── Contador de caracteres ── */
function actualizarContador(el) {
    var cnt = document.getElementById('charCount');
    if (cnt) cnt.textContent = el.value.length;
}

/* ── Bloquear botón al enviar ── */
function bloquearEnvio() {
    var btn = document.getElementById('btnEnviarMsg');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML =
            '<i class="fas fa-spinner fa-spin" ' +
            'style="font-size:18px;display:block;"></i>Enviando...';
    }
}

/* ── Ctrl+Enter para enviar ── */
var txtArea = document.getElementById('txtMensaje');
if (txtArea) {
    txtArea.addEventListener('keydown', function(e) {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            var form = document.getElementById('formEnviarMensaje');
            if (form) { bloquearEnvio(); form.submit(); }
        }
    });
}

/* ── Scroll al final del chat al cargar ── */
(function() {
    var chat = document.getElementById('chatArea');
    if (chat) {
        chat.scrollTop = chat.scrollHeight;
    }
})();
</script>

<?php require_once 'footer.php'; ?>