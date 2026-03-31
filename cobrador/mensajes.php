<?php
/* ============================================================
   cobrador/mensajes.php — Bandeja de mensajes del cobrador
   ============================================================ */
$paginaActualTitulo = 'Mensajes';
require_once __DIR__ . '/header_cobrador.php';

$cobradorId = (int)$_SESSION['cobrador_portal_id'];

// Obtener todos los mensajes del cobrador
$mensajes = [];
try {
    $stmt = $conn->prepare("
        SELECT m.*,
               u.nombre AS remitente_nombre,
               u.rol    AS remitente_rol,
               cl.nombre      AS cliente_visita_nombre,
               cl.apellidos   AS cliente_visita_apellidos,
               cl.direccion   AS cliente_visita_dir,
               cl.telefono1   AS cliente_visita_tel,
               cl.id          AS cliente_visita_id_real
        FROM cobrador_mensajes m
        JOIN usuarios u ON m.usuario_id = u.id
        LEFT JOIN clientes cl ON cl.id = m.cliente_visita_id
        WHERE m.cobrador_id = ?
        ORDER BY m.fecha_envio DESC
        LIMIT 80
    ");
    $stmt->execute([$cobradorId]);
    $mensajes = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log('mensajes.php: ' . $e->getMessage());
}

$totalNoLeidos = count(array_filter($mensajes, fn($m) => !$m['leido']));

function tiempoRel(string $fecha): string {
    $diff = time() - strtotime($fecha);
    if ($diff < 60)     return 'Ahora mismo';
    if ($diff < 3600)   return 'Hace ' . floor($diff / 60) . ' min';
    if ($diff < 86400)  return 'Hace ' . floor($diff / 3600) . ' h';
    if ($diff < 172800) return 'Ayer';
    return date('d/m/Y', strtotime($fecha));
}
?>
<style>
/* ── Estilos específicos de mensajes ── */
.bandeja-wrap {
    max-width: 680px;
    margin: 0 auto;
}

.bandeja-header-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 16px;
    flex-wrap: wrap;
    gap: 8px;
}

.msg-list-item {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 14px 16px;
    background: var(--white);
    border-bottom: 1px solid var(--border);
    cursor: pointer;
    transition: background .15s;
    text-decoration: none;
    color: inherit;
    position: relative;
}

.msg-list-item:first-child {
    border-radius: var(--radius) var(--radius) 0 0;
}

.msg-list-item:last-child {
    border-bottom: none;
    border-radius: 0 0 var(--radius) var(--radius);
}

.msg-list-item:only-child {
    border-radius: var(--radius);
}

.msg-list-item:hover { background: var(--gray-50); }

.msg-list-item.unread {
    background: #eff6ff;
    border-left: 3px solid var(--accent);
}

.msg-list-item.unread:hover { background: #dbeafe; }

.msg-avatar {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 14px;
    font-weight: 700;
    color: #fff;
    flex-shrink: 0;
}

.msg-dot-unread {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    background: var(--accent);
    flex-shrink: 0;
    margin-top: 5px;
}

.msg-dot-read {
    width: 9px;
    height: 9px;
    flex-shrink: 0;
}

.msg-asunto-text {
    font-size: 13px;
    font-weight: 700;
    color: var(--gray-800);
    line-height: 1.3;
}

.msg-preview {
    font-size: 12px;
    color: var(--text-muted);
    margin-top: 3px;
    overflow: hidden;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
    line-height: 1.4;
}

.msg-time {
    font-size: 11px;
    color: var(--gray-400);
    white-space: nowrap;
    flex-shrink: 0;
    margin-left: auto;
}

.tag-visita {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    background: #fef3c7;
    color: #92400e;
    border: 1px solid #fde68a;
    border-radius: 12px;
    font-size: 10px;
    font-weight: 700;
    padding: 2px 8px;
    margin-top: 4px;
}

.tag-urgente {
    display: inline-flex;
    align-items: center;
    gap: 3px;
    background: var(--danger-light);
    color: var(--danger-text);
    border-radius: 12px;
    font-size: 10px;
    font-weight: 700;
    padding: 2px 7px;
    margin-left: 5px;
}

/* ── Modal de mensaje ── */
.modal-msg-overlay {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,.55);
    z-index: 2000;
    overflow-y: auto;
    padding: 20px;
}

.modal-msg-box {
    background: var(--white);
    border-radius: var(--radius-lg);
    width: 100%;
    max-width: 520px;
    margin: 50px auto 30px;
    overflow: hidden;
    box-shadow: var(--shadow-lg);
}

.modal-msg-hdr {
    padding: 16px 18px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 8px;
}

.modal-msg-body {
    padding: 18px;
    font-size: 14px;
    color: var(--gray-700);
    line-height: 1.75;
    white-space: pre-wrap;
    word-break: break-word;
}

.modal-msg-visita {
    margin: 12px 18px;
    background: #fffbeb;
    border: 1px solid #fde68a;
    border-radius: var(--radius);
    padding: 12px 14px;
}

.modal-msg-visita-titulo {
    font-size: 11px;
    font-weight: 700;
    color: #92400e;
    text-transform: uppercase;
    letter-spacing: .5px;
    margin-bottom: 8px;
    display: flex;
    align-items: center;
    gap: 5px;
}

.modal-msg-ftr {
    padding: 12px 18px;
    border-top: 1px solid var(--border);
    font-size: 11px;
    color: var(--gray-400);
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 6px;
}

.marcar-leido-btn {
    font-size: 12px;
    color: var(--accent);
    background: none;
    border: none;
    cursor: pointer;
    padding: 0;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 4px;
}

.marcar-leido-btn:hover { text-decoration: underline; }
</style>

<div class="app-content">
<div class="bandeja-wrap">

  <!-- ── Encabezado ── -->
  <div class="bandeja-header-bar">
    <div>
      <div class="page-title">
        Mensajes de Oficina
        <?php if ($totalNoLeidos > 0): ?>
          <span style="font-size:13px;font-weight:600;color:var(--accent);
                       margin-left:8px;background:var(--accent-light);
                       padding:2px 9px;border-radius:12px;">
            <?= $totalNoLeidos ?> nuevo<?= $totalNoLeidos > 1 ? 's' : '' ?>
          </span>
        <?php endif; ?>
      </div>
      <div class="page-subtitle">
        <?= count($mensajes) ?> mensaje(s) en total
      </div>
    </div>
    <?php if ($totalNoLeidos > 0): ?>
    <button class="btn btn-secondary btn-sm" onclick="marcarTodosLeidos()">
      <i class="fas fa-check-double"></i> Marcar todos leídos
    </button>
    <?php endif; ?>
  </div>

  <!-- ── Lista de mensajes ── -->
  <?php if (empty($mensajes)): ?>
  <div class="empty-state">
    <i class="fas fa-comments"></i>
    <h3>Sin mensajes</h3>
    <p>Aún no tienes mensajes del personal de oficina.</p>
  </div>

  <?php else: ?>
  <div class="card" style="overflow:hidden;" id="listaMensajes">
    <?php foreach ($mensajes as $msg):
        $esAdmin    = $msg['remitente_rol'] === 'admin';
        $iniciales  = strtoupper(substr($msg['remitente_nombre'], 0, 1));
        $bgAvatar   = $esAdmin ? 'var(--primary)' : 'var(--accent)';
        $tieneVisita= !empty($msg['cliente_visita_id']);
        $esUrgente  = $msg['prioridad'] === 'urgente';
        $noLeido    = !$msg['leido'];
    ?>
    <div class="msg-list-item <?= $noLeido ? 'unread' : '' ?>"
         id="msgItem<?= $msg['id'] ?>"
         onclick="abrirMensaje(<?= $msg['id'] ?>)">

      <!-- Punto / indicador -->
      <?php if ($noLeido): ?>
        <div class="msg-dot-unread"></div>
      <?php else: ?>
        <div class="msg-dot-read"></div>
      <?php endif; ?>

      <!-- Avatar -->
      <div class="msg-avatar" style="background:<?= $bgAvatar ?>;">
        <?= htmlspecialchars($iniciales) ?>
      </div>

      <!-- Contenido -->
      <div style="flex:1;min-width:0;">
        <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
          <span class="msg-asunto-text"><?= htmlspecialchars($msg['asunto']) ?></span>
          <?php if ($esUrgente): ?>
            <span class="tag-urgente">
              <i class="fas fa-circle-exclamation" style="font-size:9px;"></i>
              Urgente
            </span>
          <?php endif; ?>
          <?php if ($msg['prioridad'] === 'informativo'): ?>
            <span style="font-size:10px;background:var(--info-light);color:var(--info-text);
                         border-radius:10px;padding:1px 7px;font-weight:700;">
              Info
            </span>
          <?php endif; ?>
        </div>

        <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">
          <?= htmlspecialchars($msg['remitente_nombre']) ?>
          &bull; <?= ucfirst($msg['remitente_rol']) ?>
        </div>

        <div class="msg-preview"><?= htmlspecialchars($msg['mensaje']) ?></div>

        <?php if ($tieneVisita): ?>
        <div class="tag-visita">
          <i class="fas fa-location-dot" style="font-size:10px;"></i>
          Visitar: <?= htmlspecialchars($msg['cliente_visita_nombre'] . ' ' . $msg['cliente_visita_apellidos']) ?>
        </div>
        <?php endif; ?>
      </div>

      <!-- Fecha -->
      <div class="msg-time"><?= tiempoRel($msg['fecha_envio']) ?></div>
    </div>
    <?php endforeach; ?>
  </div>
  <?php endif; ?>

</div>
</div><!-- /.app-content -->

<!-- ════════════════════════════
     MODAL LEER MENSAJE
════════════════════════════ -->
<div class="modal-msg-overlay" id="modalMensaje">
  <div class="modal-msg-box" id="modalMensajeBox">
    <div id="modalMensajeCuerpo">
      <div class="loading-overlay" style="padding:40px;">
        <div class="spinner"></div>
      </div>
    </div>
  </div>
</div>

<script>
/* ════════════════════════════════════════
   ABRIR MENSAJE
════════════════════════════════════════ */
function abrirMensaje(id) {
    var overlay = document.getElementById('modalMensaje');
    var cuerpo  = document.getElementById('modalMensajeCuerpo');

    cuerpo.innerHTML =
        '<div class="loading-overlay" style="padding:40px;">' +
        '<div class="spinner"></div></div>';

    overlay.style.display = 'block';
    document.body.style.overflow = 'hidden';

    // Marcar como leído en background
    var item = document.getElementById('msgItem' + id);
    if (item && item.classList.contains('unread')) {
        fetch('api/marcar_leido.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': CSRF_TOKEN
            },
            body: JSON.stringify({ mensaje_id: id }),
            credentials: 'same-origin',
        })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            if (d.success) {
                item.classList.remove('unread');
                // Actualizar dot
                var dot = item.querySelector('.msg-dot-unread');
                if (dot) dot.className = 'msg-dot-read';
                // Actualizar badge del menú
                actualizarBadgeMensajes();
            }
        });
    }

    // Obtener datos completos del mensaje
    fetch('api/get_mensaje.php?id=' + id, { credentials: 'same-origin' })
        .then(function(r) { return r.text(); })
        .then(function(txt) {
            var data;
            try { data = JSON.parse(txt); }
            catch(e) {
                cuerpo.innerHTML =
                    '<div class="alert alert-danger" style="margin:20px;">' +
                    'Error al cargar el mensaje.</div>';
                return;
            }

            if (!data.success) {
                cuerpo.innerHTML =
                    '<div class="alert alert-danger" style="margin:20px;">' +
                    esc(data.message) + '</div>';
                return;
            }

            var m = data.mensaje;
            var esAdmin = m.remitente_rol === 'admin';
            var bgAv = esAdmin ? 'var(--primary)' : 'var(--accent)';
            var prioBadge = '';
            if (m.prioridad === 'urgente') {
                prioBadge = '<span class="tag-urgente">' +
                    '<i class="fas fa-circle-exclamation" style="font-size:9px;"></i>' +
                    ' Urgente</span>';
            }

            var h = '';

            /* Cabecera modal */
            h += '<div class="modal-msg-hdr">';
            h += '<div style="display:flex;align-items:center;gap:10px;flex:1;min-width:0;">';
            h += '<div class="msg-avatar" style="background:' + bgAv + ';flex-shrink:0;">' +
                 esc(m.remitente_nombre ? m.remitente_nombre[0].toUpperCase() : 'O') + '</div>';
            h += '<div style="min-width:0;">';
            h += '<div style="font-size:14px;font-weight:700;color:var(--gray-800);' +
                 'display:flex;align-items:center;gap:6px;flex-wrap:wrap;">' +
                 esc(m.asunto) + prioBadge + '</div>';
            h += '<div style="font-size:12px;color:var(--text-muted);margin-top:2px;">' +
                 esc(m.remitente_nombre) + ' &bull; ' + ucfirstJs(m.remitente_rol) +
                 ' &bull; ' + esc(m.tiempo_relativo) + '</div>';
            h += '</div></div>';
            h += '<button onclick="cerrarModalMensaje()" ' +
                 'class="btn btn-secondary btn-sm" style="flex-shrink:0;">' +
                 '<i class="fas fa-times"></i></button>';
            h += '</div>';

            /* Bloque "Visitar cliente" */
            if (m.cliente_visita_id) {
                h += '<div class="modal-msg-visita">';
                h += '<div class="modal-msg-visita-titulo">' +
                     '<i class="fas fa-location-dot"></i> Cliente a visitar</div>';
                h += '<div style="font-size:14px;font-weight:700;color:var(--gray-800);">' +
                     esc((m.cliente_visita_nombre || '') + ' ' +
                         (m.cliente_visita_apellidos || '')) + '</div>';
                if (m.cliente_visita_dir) {
                    h += '<div style="font-size:12px;color:var(--text-muted);margin-top:4px;">' +
                         '<i class="fas fa-map-marker-alt" style="font-size:10px;' +
                         'margin-right:3px;"></i>' +
                         esc(m.cliente_visita_dir) + '</div>';
                }
                h += '<div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap;">';
                if (m.cliente_visita_dir) {
                    h += '<a href="https://maps.google.com/?q=' +
                         encodeURIComponent(m.cliente_visita_dir + ', República Dominicana') +
                         '" target="_blank" rel="noopener" ' +
                         'class="btn btn-success btn-sm">' +
                         '<i class="fas fa-navigation"></i> Cómo llegar</a>';
                }
                if (m.cliente_visita_tel) {
                    var t = String(m.cliente_visita_tel).replace(/\D/g, '');
                    h += '<a href="tel:' + esc(t) + '" class="btn btn-sm" ' +
                         'style="background:var(--accent-light);color:var(--accent);">' +
                         '<i class="fas fa-phone"></i> Llamar</a>';
                }
                h += '<a href="facturas.php?cliente_id=' + m.cliente_visita_id +
                     '" class="btn btn-primary btn-sm">' +
                     '<i class="fas fa-file-invoice"></i> Ver facturas</a>';
                h += '</div></div>';
            }

            /* Cuerpo del mensaje */
            h += '<div class="modal-msg-body">' + esc(m.mensaje) + '</div>';

            /* Pie */
            h += '<div class="modal-msg-ftr">';
            h += '<span>Recibido: ' + esc(m.fecha_envio_formateada) + '</span>';
            if (m.fecha_leido_formateada) {
                h += '<span style="color:var(--success);">' +
                     '<i class="fas fa-check-double" style="margin-right:3px;"></i>' +
                     'Leído: ' + esc(m.fecha_leido_formateada) + '</span>';
            }
            h += '</div>';

            cuerpo.innerHTML = h;
        })
        .catch(function(err) {
            cuerpo.innerHTML =
                '<div class="alert alert-danger" style="margin:20px;">' +
                'Error de conexión.</div>';
            console.error('abrirMensaje:', err);
        });
}

function cerrarModalMensaje() {
    document.getElementById('modalMensaje').style.display = 'none';
    document.body.style.overflow = '';
}

document.getElementById('modalMensaje').addEventListener('click', function(e) {
    if (e.target === this) cerrarModalMensaje();
});

document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') cerrarModalMensaje();
});

/* ════════════════════════════════════════
   MARCAR TODOS COMO LEÍDOS
════════════════════════════════════════ */
function marcarTodosLeidos() {
    var noLeidos = document.querySelectorAll('.msg-list-item.unread');
    if (!noLeidos.length) return;

    var promesas = [];
    noLeidos.forEach(function(item) {
        var id = parseInt(item.id.replace('msgItem', ''), 10);
        if (!id) return;
        promesas.push(
            fetch('api/marcar_leido.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': CSRF_TOKEN
                },
                body: JSON.stringify({ mensaje_id: id }),
                credentials: 'same-origin',
            }).then(function(r) { return r.json(); })
        );
    });

    Promise.all(promesas).then(function() {
        noLeidos.forEach(function(item) {
            item.classList.remove('unread');
            var dot = item.querySelector('.msg-dot-unread');
            if (dot) dot.className = 'msg-dot-read';
        });
        actualizarBadgeMensajes();
        showToast('Todos los mensajes marcados como leídos', 'success');
        // Ocultar botón "Marcar todos"
        var btn = document.querySelector('[onclick="marcarTodosLeidos()"]');
        if (btn) btn.style.display = 'none';
    });
}

/* ════════════════════════════════════════
   UTILIDADES
════════════════════════════════════════ */
function esc(v) {
    return String(v == null ? '' : v)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;')
        .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function ucfirstJs(s) {
    s = String(s || '');
    return s ? s[0].toUpperCase() + s.slice(1) : '';
}
</script>

</body>
</html>