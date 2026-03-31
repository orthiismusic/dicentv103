<?php
/* ============================================================
   cobrador/facturas.php
   Sistema ORTHIIS — Portal del Cobrador
   ============================================================ */
$paginaActualTitulo = 'Facturas Pendientes';
require_once __DIR__ . '/header_cobrador.php';

$cobradorId   = (int)$_SESSION['cobrador_portal_id'];
$vistaInicial = $_GET['vista'] ?? 'lista';

// ── Filtro por cliente específico (viene de clientes.php) ──
$filtroClienteId     = (int)($_GET['cliente_id'] ?? 0);
$filtroClienteNombre = '';

if ($filtroClienteId > 0) {
    try {
        $sCliente = $conn->prepare("
            SELECT CONCAT(nombre, ' ', apellidos) AS nombre_completo
            FROM clientes
            WHERE id = ? AND cobrador_id = ?
            LIMIT 1
        ");
        $sCliente->execute([$filtroClienteId, $cobradorId]);
        $filtroClienteNombre = $sCliente->fetchColumn() ?: '';
    } catch (PDOException $e) {
        error_log('filtro_cliente_nombre: ' . $e->getMessage());
    }
}

// ── Totales para los chips (solo en vista general) ──
$totales = ['todos' => 0, 'pendiente' => 0, 'vencida' => 0, 'incompleta' => 0];
if (!$filtroClienteId) {
    try {
        $sT = $conn->prepare("
            SELECT f.estado, COUNT(*) AS cnt
            FROM facturas f
            JOIN contratos c  ON f.contrato_id = c.id
            JOIN clientes  cl ON c.cliente_id  = cl.id
            WHERE cl.cobrador_id = ?
              AND f.estado IN ('pendiente','vencida','incompleta')
            GROUP BY f.estado
        ");
        $sT->execute([$cobradorId]);
        foreach ($sT->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $totales[$row['estado']] = (int)$row['cnt'];
            $totales['todos']       += (int)$row['cnt'];
        }
    } catch (PDOException $e) {
        error_log('facturas totales: ' . $e->getMessage());
    }
} else {
    // Totales solo del cliente filtrado
    try {
        $sT = $conn->prepare("
            SELECT f.estado, COUNT(*) AS cnt
            FROM facturas f
            JOIN contratos c  ON f.contrato_id = c.id
            JOIN clientes  cl ON c.cliente_id  = cl.id
            WHERE cl.cobrador_id = ?
              AND cl.id = ?
              AND f.estado IN ('pendiente','vencida','incompleta')
            GROUP BY f.estado
        ");
        $sT->execute([$cobradorId, $filtroClienteId]);
        foreach ($sT->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $totales[$row['estado']] = (int)$row['cnt'];
            $totales['todos']       += (int)$row['cnt'];
        }
    } catch (PDOException $e) {
        error_log('facturas totales cliente: ' . $e->getMessage());
    }
}
?>

<div class="app-content">

  <!-- ════════════════════════════════════════
       ENCABEZADO
  ════════════════════════════════════════ -->
  <div class="page-header" style="display:flex;align-items:flex-start;
       justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:16px;">

    <div style="min-width:0;">
      <?php if ($filtroClienteId > 0 && $filtroClienteNombre): ?>
        <!-- Vista filtrada por cliente específico -->
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
          <a href="facturas.php" class="btn btn-secondary btn-sm"
             style="min-height:30px;padding:0 12px;flex-shrink:0;">
            <i class="fas fa-arrow-left"></i> Volver
          </a>
          <span style="font-size:12px;color:var(--text-muted);">
            Facturas pendientes de:
          </span>
        </div>
        <div class="page-title" style="font-size:17px;line-height:1.3;">
          <?= htmlspecialchars($filtroClienteNombre) ?>
        </div>
        <div class="page-subtitle">
          <?= number_format($totales['todos']) ?> factura(s) pendiente(s)
          de este cliente
        </div>

      <?php else: ?>
        <!-- Vista general — todas las facturas del cobrador -->
        <div class="page-title">Facturas Pendientes</div>
        <div class="page-subtitle">
          <?= number_format($totales['todos']) ?> factura(s) por cobrar
        </div>
      <?php endif; ?>
    </div>

    <!-- Toggle vista (solo en vista general, sin filtro de cliente) -->
    <?php if (!$filtroClienteId): ?>
    <div class="view-toggle" id="vistaToggle" style="flex-shrink:0;">
      <button class="view-btn<?= $vistaInicial === 'lista' ? ' active' : '' ?>"
              id="btnVistaLista" onclick="cambiarVista('lista')">
        <i class="fas fa-list"></i> Lista
      </button>
      <button class="view-btn<?= $vistaInicial === 'mapa' ? ' active' : '' ?>"
              id="btnVistaMapa" onclick="cambiarVista('mapa')">
        <i class="fas fa-map-marker-alt"></i> Mapa
      </button>
      <button class="view-btn<?= $vistaInicial === 'ruta' ? ' active' : '' ?>"
              id="btnVistaRuta" onclick="cambiarVista('ruta')">
        <i class="fas fa-route"></i> Ruta
      </button>
    </div>
    <?php endif; ?>

  </div><!-- /.page-header -->

  <!-- ════════════════════════════════════════
       SECCIÓN: LISTA DE FACTURAS
  ════════════════════════════════════════ -->
  <div id="seccionLista"
       style="display:<?= ($vistaInicial === 'lista' || $filtroClienteId) ? 'block' : 'none' ?>;">

    <!-- Buscador sticky -->
    <div class="search-sticky">
      <div class="search-bar">
        <i class="fas fa-search"></i>
        <input type="text" id="searchFacturas"
               placeholder="<?= $filtroClienteId
                   ? 'Buscar por N° factura o mes...'
                   : 'Nombre, apellido o N° contrato...' ?>"
               autocomplete="off" autocorrect="off"
               autocapitalize="off" spellcheck="false">
        <div class="spinner" id="factSpinner" style="display:none;"></div>
      </div>
      <div id="factCount" class="search-count"></div>
    </div>

    <!-- Chips de filtro por estado -->
    <div class="filter-chips" id="filterChips" style="margin-bottom:14px;">
      <button class="chip active" id="chipTodos"
              onclick="filtrarEstado('')">
        Todos
        <span style="margin-left:3px;opacity:.7;">(<?= $totales['todos'] ?>)</span>
      </button>
      <button class="chip" id="chipPendiente"
              onclick="filtrarEstado('pendiente')">
        <i class="fas fa-clock" style="font-size:10px;"></i>
        Pendiente
        <span style="margin-left:3px;opacity:.7;">(<?= $totales['pendiente'] ?>)</span>
      </button>
      <button class="chip" id="chipVencida"
              onclick="filtrarEstado('vencida')">
        <i class="fas fa-fire" style="font-size:10px;"></i>
        Vencida
        <span style="margin-left:3px;opacity:.7;">(<?= $totales['vencida'] ?>)</span>
      </button>
      <button class="chip" id="chipIncompleta"
              onclick="filtrarEstado('incompleta')">
        <i class="fas fa-circle-half-stroke" style="font-size:10px;"></i>
        Incompleta
        <span style="margin-left:3px;opacity:.7;">(<?= $totales['incompleta'] ?>)</span>
      </button>
    </div>

    <!-- Contenedor de tarjetas -->
    <div id="facturasContainer"></div>

    <!-- Estado vacío -->
    <div class="empty-state" id="emptyFacturas" style="display:none;">
      <i class="fas fa-file-invoice"></i>
      <h3>Sin facturas pendientes</h3>
      <p>
        <?= $filtroClienteId
            ? 'Este cliente no tiene facturas pendientes.'
            : 'No hay facturas que coincidan con el filtro seleccionado.' ?>
      </p>
      <?php if ($filtroClienteId): ?>
      <a href="facturas.php" class="btn btn-secondary btn-sm" style="margin-top:12px;">
        <i class="fas fa-arrow-left"></i> Ver todas las facturas
      </a>
      <?php endif; ?>
    </div>

    <!-- Botón cargar más -->
    <div id="btnMasFacturasWrap"
         style="text-align:center;padding:14px 0;display:none;">
      <button class="btn btn-secondary" onclick="cargarMasFacturas()">
        <i class="fas fa-plus"></i> Cargar más facturas
      </button>
    </div>

  </div><!-- /#seccionLista -->

  <!-- ════════════════════════════════════════
       SECCIÓN: MAPA (solo vista general)
  ════════════════════════════════════════ -->
  <?php if (!$filtroClienteId): ?>
  <div id="seccionMapa"
       style="display:<?= $vistaInicial === 'mapa' ? 'block' : 'none' ?>;">

    <div class="alert alert-info" style="margin-bottom:12px;">
      <i class="fas fa-info-circle"></i>
      <span>
        Activa tu ubicación para verte en el mapa.
        Toca un marcador para ver el cliente y navegar.
      </span>
    </div>

    <div id="mapa-ruta"
         style="height:380px;border-radius:var(--radius);
                border:1px solid var(--border);overflow:hidden;"></div>

    <div id="mapaInfo"
         style="margin-top:8px;font-size:12px;color:var(--text-muted);
                text-align:center;"></div>

  </div><!-- /#seccionMapa -->

  <!-- ════════════════════════════════════════
       SECCIÓN: RUTA (solo vista general)
  ════════════════════════════════════════ -->
  <div id="seccionRuta"
       style="display:<?= $vistaInicial === 'ruta' ? 'block' : 'none' ?>;">

    <div class="alert alert-info" style="margin-bottom:12px;">
      <i class="fas fa-grip-vertical"></i>
      <span>
        Arrastra las tarjetas para ordenar tu ruta del día.
        El orden se guarda para hoy.
      </span>
    </div>

    <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;">
      <button class="btn btn-secondary btn-sm" onclick="guardarRuta()">
        <i class="fas fa-save"></i> Guardar orden
      </button>
      <button class="btn btn-secondary btn-sm" onclick="cargarRuta()">
        <i class="fas fa-undo"></i> Restablecer
      </button>
    </div>

    <div id="rutaContainer">
      <div class="loading-overlay"><div class="spinner"></div></div>
    </div>

    <div class="empty-state" id="emptyRuta" style="display:none;">
      <i class="fas fa-route"></i>
      <h3>Sin clientes en ruta</h3>
      <p>No tienes clientes con facturas pendientes.</p>
    </div>

  </div><!-- /#seccionRuta -->
  <?php endif; ?>

</div><!-- /.app-content -->

<!-- ════════════════════════════════════════
     MODAL DETALLE FACTURA
     IMPORTANTE: display:none aquí.
     El JS lo muestra con display:block.
════════════════════════════════════════ -->
<div id="modalFactura"
     style="display:none;
            position:fixed;
            inset:0;
            background:rgba(0,0,0,.52);
            z-index:2000;
            overflow-y:auto;
            padding:20px;">
  <div style="display:flex;
              align-items:flex-start;
              justify-content:center;
              min-height:100%;">
    <div id="modalFacturaBox"
         style="background:var(--white);
                border-radius:var(--radius-lg);
                width:100%;
                max-width:500px;
                overflow:hidden;
                box-shadow:var(--shadow-lg);
                margin-top:50px;
                margin-bottom:30px;">
      <div id="modalFacturaBody">
        <div class="loading-overlay"><div class="spinner"></div></div>
      </div>
    </div>
  </div>
</div>

<!-- Leaflet CSS/JS -->
<?php if (!$filtroClienteId): ?>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<!-- SortableJS -->
<script src="https://cdn.jsdelivr.net/npm/sortablejs@1.15.0/Sortable.min.js"></script>
<?php endif; ?>

<script>
/* ══════════════════════════════════════════════════════
   ESTADO GLOBAL
══════════════════════════════════════════════════════ */
var estadoActivo      = '';
var queryActiva       = '';
var offsetF           = 0;
var cargandoF         = false;
var hayMasF           = false;
var POR_PAGINA_F      = 25;
var mapaLeaflet       = null;
var sortableInst      = null;

// cliente_id pasado desde PHP — 0 = sin filtro
var FILTRO_CLIENTE_ID = <?= $filtroClienteId ?>;

/* ══════════════════════════════════════════════════════
   UTILIDADES
══════════════════════════════════════════════════════ */
function esc(v) {
    return String(v == null ? '' : v)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function ucfirst(s) {
    s = String(s || '');
    return s ? s[0].toUpperCase() + s.slice(1) : '';
}

function fmtMonto(v) {
    return parseFloat(v || 0).toLocaleString('es-DO', {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
    });
}

function fmtFecha(f) {
    if (!f) return '—';
    var d = new Date(String(f).replace(' ', 'T'));
    if (isNaN(d.getTime())) return String(f);
    return ('0' + d.getDate()).slice(-2)   + '/' +
           ('0' + (d.getMonth() + 1)).slice(-2) + '/' +
           d.getFullYear();
}

/* ══════════════════════════════════════════════════════
   CAMBIAR VISTA (lista / mapa / ruta)
   Solo disponible en vista general (sin filtro cliente)
══════════════════════════════════════════════════════ */
function cambiarVista(v) {
    ['lista', 'mapa', 'ruta'].forEach(function(s) {
        var secEl = document.getElementById(
            'seccion' + s.charAt(0).toUpperCase() + s.slice(1)
        );
        var btnEl = document.getElementById(
            'btnVista' + s.charAt(0).toUpperCase() + s.slice(1)
        );
        if (secEl) secEl.style.display = (s === v) ? 'block' : 'none';
        if (btnEl) btnEl.classList.toggle('active', s === v);
    });

    if (v === 'mapa' && !mapaLeaflet) iniciarMapa();
    if (v === 'ruta')                  cargarRuta();

    history.replaceState(null, '', location.pathname + '?vista=' + v);
}

/* ══════════════════════════════════════════════════════
   FILTRAR POR ESTADO
══════════════════════════════════════════════════════ */
function filtrarEstado(estado) {
    estadoActivo = estado;

    var chipMap = {
        '':           'chipTodos',
        'pendiente':  'chipPendiente',
        'vencida':    'chipVencida',
        'incompleta': 'chipIncompleta'
    };

    document.querySelectorAll('#filterChips .chip').forEach(function(c) {
        c.classList.remove('active');
    });

    var chipEl = document.getElementById(chipMap[estado] || 'chipTodos');
    if (chipEl) chipEl.classList.add('active');

    cargarFacturas(true);
}

/* ══════════════════════════════════════════════════════
   CREAR TARJETA DE FACTURA (DOM puro, sin innerHTML con datos)
══════════════════════════════════════════════════════ */
function crearTarjetaFactura(f) {

    var badgeClsMap = {
        pendiente:  'badge-pendiente',
        vencida:    'badge-vencida',
        incompleta: 'badge-incompleta'
    };
    var badgeCls = badgeClsMap[f.estado] || 'badge-normal';

    /* ── Card ── */
    var card = document.createElement('div');
    card.className = 'invoice-card';
    card.dataset.id = f.id;

    /* ── Header ── */
    var hdr = document.createElement('div');
    hdr.className = 'invoice-card-header';
    hdr.style.cursor = 'pointer';

    /* Fila superior: número factura + badge estado */
    var topRow = document.createElement('div');
    topRow.className = 'invoice-top-row';

    var numEl = document.createElement('span');
    numEl.className = 'invoice-num';
    numEl.textContent = f.numero_factura || '';
    topRow.appendChild(numEl);

    var badgeEl = document.createElement('span');
    badgeEl.className = 'badge ' + badgeCls;
    badgeEl.textContent = ucfirst(f.estado || '');
    topRow.appendChild(badgeEl);

    hdr.appendChild(topRow);

    /* Nombre del cliente (solo si es vista general) */
    if (!FILTRO_CLIENTE_ID) {
        var clienteEl = document.createElement('div');
        clienteEl.className = 'invoice-client-name';
        clienteEl.textContent = ((f.nombre || '') + ' ' + (f.apellidos || '')).trim();
        hdr.appendChild(clienteEl);
    }

    /* Fila meta: contrato · mes · vencimiento | monto */
    var metaWrap = document.createElement('div');
    metaWrap.style.cssText =
        'display:flex;align-items:center;justify-content:space-between;' +
        'flex-wrap:wrap;gap:4px;margin-top:4px;';

    var metaInfo = document.createElement('div');
    metaInfo.className = 'invoice-meta';
    metaInfo.innerHTML =
        '<i class="fas fa-file-contract" style="font-size:10px;margin-right:2px;"></i>' +
        esc(f.numero_contrato || '') +
        ' &bull; Mes: <strong>' + esc(f.mes_factura || '—') + '</strong>' +
        ' &bull; Vence: ' + fmtFecha(f.fecha_vencimiento);
    metaWrap.appendChild(metaInfo);

    var montoEl = document.createElement('div');
    montoEl.className = 'invoice-amount';
    montoEl.textContent = 'RD$' + fmtMonto(f.monto);
    metaWrap.appendChild(montoEl);

    hdr.appendChild(metaWrap);

    /* Toggle expandir/colapsar */
    hdr.addEventListener('click', function() {
        var open = card.classList.toggle('expanded');
        body.style.display = open ? 'block' : 'none';
    });

    card.appendChild(hdr);

    /* ── Body (detalle, oculto por defecto) ── */
    var body = document.createElement('div');
    body.className = 'invoice-card-body';
    body.style.display = 'none';

    /* Dirección */
    var dirDiv = document.createElement('div');
    dirDiv.style.cssText =
        'font-size:12px;color:var(--text-muted);line-height:1.9;padding:2px 0;';
    dirDiv.innerHTML =
        '<i class="fas fa-map-marker-alt" style="width:14px;"></i> ';
    dirDiv.appendChild(
        document.createTextNode(f.direccion || 'Dirección no registrada')
    );
    body.appendChild(dirDiv);

    /* Día cobro + Cuota + Plan */
    var detDiv = document.createElement('div');
    detDiv.style.cssText =
        'font-size:12px;color:var(--text-muted);line-height:1.9;';
    var detHtml =
        '<i class="fas fa-calendar-day" style="width:14px;"></i> ' +
        'Día cobro: <strong>' + esc(f.dia_cobro || '—') + '</strong>';
    if (f.cuota) {
        detHtml += ' &bull; Cuota N° <strong>' + esc(f.cuota) + '</strong>';
    }
    if (f.plan_nombre) {
        detHtml += ' &bull; <i class="fas fa-umbrella" style="font-size:10px;"></i> ' +
                   esc(f.plan_nombre);
    }
    detDiv.innerHTML = detHtml;
    body.appendChild(detDiv);

    card.appendChild(body);

    /* ── Acciones ── */
    var actions = document.createElement('div');
    actions.className = 'invoice-card-actions';
    actions.style.cssText =
        'display:flex;gap:8px;padding:10px 14px;flex-wrap:wrap;' +
        'border-top:1px solid var(--gray-100);background:var(--gray-50);';

    /* Botón: Ver detalle */
    var btnVer = document.createElement('button');
    btnVer.className = 'btn btn-primary btn-sm';
    btnVer.style.flex = '1';
    btnVer.innerHTML = '<i class="fas fa-eye"></i> Ver';
    btnVer.addEventListener('click', function(e) {
        e.stopPropagation();
        abrirDetalleFactura(f.id);
    });
    actions.appendChild(btnVer);

    /* Botón: Imprimir */
    var btnPrint = document.createElement('a');
    btnPrint.className = 'btn btn-secondary btn-sm';
    btnPrint.style.flex = '1';
    btnPrint.href = 'imprimir.php?factura_id=' + f.id;
    btnPrint.target = '_blank';
    btnPrint.rel = 'noopener noreferrer';
    btnPrint.innerHTML = '<i class="fas fa-print"></i> Imprimir';
    actions.appendChild(btnPrint);

    /* Botón: Llamar (si hay teléfono) */
    if (f.telefono1 && String(f.telefono1).trim()) {
        var telLimpio = String(f.telefono1).replace(/\D/g, '');

        var btnCall = document.createElement('a');
        btnCall.className = 'btn btn-success btn-sm';
        btnCall.href = 'tel:' + telLimpio;
        btnCall.innerHTML = '<i class="fas fa-phone"></i>';
        btnCall.title = 'Llamar a ' + String(f.telefono1);
        actions.appendChild(btnCall);

        /* Botón: WhatsApp */
        var nombreCliente = ((f.nombre || '') + ' ' + (f.apellidos || '')).trim();
        var msgWa =
            'Hola ' + nombreCliente + ', le contactamos de ORTHIIS Seguros' +
            ' respecto a su factura ' + (f.numero_factura || '') + '.';

        var btnWa = document.createElement('a');
        btnWa.className = 'btn btn-sm';
        btnWa.style.cssText = 'background:#16a34a;color:#fff;';
        btnWa.href =
            'https://wa.me/1' + telLimpio +
            '?text=' + encodeURIComponent(msgWa);
        btnWa.target = '_blank';
        btnWa.rel = 'noopener noreferrer';
        btnWa.innerHTML = '<i class="fab fa-whatsapp"></i>';
        btnWa.title = 'WhatsApp';
        actions.appendChild(btnWa);
    }

    card.appendChild(actions);
    return card;
}

/* ══════════════════════════════════════════════════════
   CARGAR FACTURAS — fetch al API
══════════════════════════════════════════════════════ */
function cargarFacturas(reset) {
    if (cargandoF && !reset) return;
    reset = !!reset;

    var cont  = document.getElementById('facturasContainer');
    var empty = document.getElementById('emptyFacturas');
    var btnM  = document.getElementById('btnMasFacturasWrap');
    var cnt   = document.getElementById('factCount');

    if (reset) {
        offsetF = 0;
        hayMasF = false;
        while (cont.firstChild) cont.removeChild(cont.firstChild);
        empty.style.display = 'none';
        btnM.style.display  = 'none';

        /* Spinner de carga inicial */
        var spinDiv = document.createElement('div');
        spinDiv.className = 'loading-overlay';
        spinDiv.id = 'factSpinMain';
        spinDiv.innerHTML = '<div class="spinner"></div>';
        cont.appendChild(spinDiv);
    }

    cargandoF = true;
    document.getElementById('factSpinner').style.display = '';

    /* ── URL del API con cliente_id incluido ── */
    var url = 'api/get_facturas.php'
            + '?q='          + encodeURIComponent(queryActiva)
            + '&estado='     + encodeURIComponent(estadoActivo)
            + '&offset='     + offsetF
            + '&cliente_id=' + FILTRO_CLIENTE_ID;

    fetch(url, { credentials: 'same-origin' })
        .then(function(resp) {
            return resp.text(); // texto primero para detectar errores PHP
        })
        .then(function(txt) {
            /* Quitar spinner principal */
            var sp = document.getElementById('factSpinMain');
            if (sp && sp.parentNode) sp.parentNode.removeChild(sp);

            /* Parsear JSON */
            var data;
            try {
                data = JSON.parse(txt);
            } catch (e) {
                console.error('Respuesta no es JSON válido:', txt.substring(0, 500));
                showToast('Error del servidor. Ver consola para detalles.', 'error');
                return;
            }

            if (!data.success) {
                console.error('get_facturas API error:', data.message);
                showToast('Error: ' + (data.message || 'No se pudieron cargar las facturas'), 'error');
                return;
            }

            var facturas = data.facturas || [];
            var total    = data.total    || 0;

            /* Sin resultados */
            if (facturas.length === 0) {
                if (reset) {
                    empty.style.display = 'block';
                    cnt.textContent     = 'Sin resultados';
                }
                btnM.style.display = 'none';
                return;
            }

            empty.style.display = 'none';

            /* Insertar tarjetas con DocumentFragment */
            var frag = document.createDocumentFragment();
            facturas.forEach(function(f) {
                try {
                    frag.appendChild(crearTarjetaFactura(f));
                } catch (err) {
                    console.error('Error creando tarjeta factura ID=' + f.id, err);
                }
            });
            cont.appendChild(frag);

            /* Actualizar paginación */
            offsetF  += facturas.length;
            hayMasF   = facturas.length >= POR_PAGINA_F;
            btnM.style.display = hayMasF ? 'block' : 'none';

            /* Contador */
            var sufijo = FILTRO_CLIENTE_ID > 0 ? ' de este cliente' : '';
            cnt.textContent =
                'Mostrando ' + offsetF + ' de ' + total +
                ' factura(s)' + sufijo;
        })
        .catch(function(err) {
            var sp = document.getElementById('factSpinMain');
            if (sp && sp.parentNode) sp.parentNode.removeChild(sp);
            console.error('Fetch facturas error:', err);
            showToast('Error de conexión al cargar facturas.', 'error');
        })
        .finally(function() {
            cargandoF = false;
            document.getElementById('factSpinner').style.display = 'none';
        });
}

function cargarMasFacturas() {
    if (hayMasF && !cargandoF) cargarFacturas(false);
}

/* ══════════════════════════════════════════════════════
   BÚSQUEDA CON DEBOUNCE
══════════════════════════════════════════════════════ */
var debF;
document.getElementById('searchFacturas').addEventListener('input', function() {
    clearTimeout(debF);
    queryActiva = this.value.trim();
    debF = setTimeout(function() { cargarFacturas(true); }, 380);
});

document.getElementById('searchFacturas').addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        this.value = '';
        queryActiva = '';
        cargarFacturas(true);
    }
});

/* ══════════════════════════════════════════════════════
   MODAL DETALLE FACTURA
══════════════════════════════════════════════════════ */
function abrirDetalleFactura(facturaId) {
    var modal = document.getElementById('modalFactura');
    var body  = document.getElementById('modalFacturaBody');

    body.innerHTML =
        '<div class="loading-overlay" style="padding:48px;">' +
        '<div class="spinner"></div></div>';

    modal.style.display = 'block';
    document.body.style.overflow = 'hidden';

    fetch('api/get_factura_det.php?id=' + facturaId, { credentials: 'same-origin' })
        .then(function(r) { return r.text(); })
        .then(function(txt) {
            var data;
            try { data = JSON.parse(txt); }
            catch (e) {
                body.innerHTML =
                    '<div class="alert alert-danger" style="margin:20px;">' +
                    'Error al leer la respuesta del servidor.</div>';
                return;
            }

            if (!data.success) {
                body.innerHTML =
                    '<div class="alert alert-danger" style="margin:20px;">' +
                    esc(data.message || 'Error desconocido') + '</div>';
                return;
            }

            var f     = data.factura;
            var pagos = data.pagos   || [];
            var pend  = parseFloat(f.monto_pendiente || 0);
            var total = parseFloat(f.monto || 0);
            var pct   = total > 0 ? Math.round((total - pend) / total * 100) : 0;

            /* ── Construir HTML del modal ── */
            var h = '';

            /* Cabecera modal */
            h += '<div style="padding:16px;border-bottom:1px solid var(--border);' +
                 'display:flex;align-items:flex-start;justify-content:space-between;gap:8px;">' +
                 '<div>' +
                 '<div style="font-size:15px;font-weight:700;color:var(--gray-800);">' +
                 esc(f.numero_factura) + '</div>' +
                 '<div style="font-size:12px;color:var(--text-muted);margin-top:2px;">' +
                 esc(((f.nombre || '') + ' ' + (f.apellidos || '')).trim()) +
                 '</div></div>' +
                 '<button onclick="cerrarModal()" class="btn btn-secondary btn-sm"' +
                 ' style="flex-shrink:0;"><i class="fas fa-times"></i></button>' +
                 '</div>';

            /* Tarjetas de monto */
            h += '<div style="display:grid;grid-template-columns:1fr 1fr;' +
                 'gap:10px;padding:14px;">';

            h += '<div style="background:var(--gray-50);padding:12px;' +
                 'border-radius:var(--radius-sm);text-align:center;">' +
                 '<div style="font-size:10px;color:var(--text-muted);' +
                 'text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;">' +
                 'Total Factura</div>' +
                 '<div style="font-size:18px;font-weight:700;color:var(--gray-900);">' +
                 'RD$' + fmtMonto(f.monto) + '</div></div>';

            h += '<div style="background:var(--warning-light);padding:12px;' +
                 'border-radius:var(--radius-sm);text-align:center;">' +
                 '<div style="font-size:10px;color:var(--warning-text);' +
                 'text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;">' +
                 'Pendiente</div>' +
                 '<div style="font-size:18px;font-weight:700;color:var(--warning-text);">' +
                 'RD$' + fmtMonto(pend) + '</div></div>';

            h += '</div>';

            /* Barra de progreso (si hay abonos) */
            if (pct > 0 && pct < 100) {
                h += '<div style="padding:0 14px 12px;">' +
                     '<div style="display:flex;justify-content:space-between;' +
                     'font-size:11px;color:var(--text-muted);margin-bottom:5px;">' +
                     '<span>Pagado: ' + pct + '%</span>' +
                     '<span>Pendiente: ' + (100 - pct) + '%</span></div>' +
                     '<div style="height:7px;background:var(--gray-200);border-radius:4px;">' +
                     '<div style="height:7px;border-radius:4px;background:var(--success);' +
                     'width:' + pct + '%;transition:width .4s ease;"></div></div></div>';
            }

            /* Detalles en tabla */
            function fila(label, valor) {
                return '<div style="display:flex;justify-content:space-between;' +
                       'align-items:flex-start;padding:8px 0;' +
                       'border-bottom:1px solid var(--gray-100);font-size:13px;">' +
                       '<span style="color:var(--text-muted);flex-shrink:0;' +
                       'margin-right:10px;">' + label + '</span>' +
                       '<span style="font-weight:600;text-align:right;">' +
                       valor + '</span></div>';
            }

            h += '<div style="padding:0 14px 4px;">';
            h += fila('Contrato',    esc(f.numero_contrato || '—'));
            h += fila('Mes',         esc(f.mes_factura     || '—'));
            h += fila('Plan',        esc(f.plan_nombre     || '—'));
            if (f.cuota) h += fila('Cuota', 'N° ' + esc(f.cuota));
            h += fila('Vencimiento', fmtFecha(f.fecha_vencimiento));
            h += fila('Día de cobro', esc(f.dia_cobro || '—'));

            if (f.direccion) {
                h += fila('Dirección',
                    '<span style="max-width:220px;word-break:break-word;display:block;' +
                    'text-align:right;">' + esc(f.direccion) + '</span>');
            }

            if (f.telefono1) {
                var t1 = String(f.telefono1).replace(/\D/g, '');
                h += '<div style="display:flex;justify-content:space-between;' +
                     'align-items:center;padding:8px 0;' +
                     'border-bottom:1px solid var(--gray-100);font-size:13px;">' +
                     '<span style="color:var(--text-muted);">Teléfono</span>' +
                     '<a href="tel:' + esc(t1) + '" ' +
                     'style="font-weight:600;color:var(--accent);text-decoration:none;">' +
                     '<i class="fas fa-phone" style="font-size:10px;margin-right:3px;"></i>' +
                     esc(f.telefono1) + '</a></div>';
            }

            h += '</div>';

            /* Historial de abonos */
            if (pagos.length > 0) {
                h += '<div style="padding:12px 14px;">' +
                     '<div style="font-size:11px;font-weight:700;color:var(--gray-500);' +
                     'text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;">' +
                     '<i class="fas fa-coins" style="color:var(--accent);margin-right:5px;"></i>' +
                     'Historial de abonos</div>';

                pagos.forEach(function(p) {
                    h += '<div style="display:flex;justify-content:space-between;' +
                         'padding:6px 0;border-bottom:1px solid var(--gray-100);' +
                         'font-size:12px;">' +
                         '<span style="color:var(--text-muted);">' +
                         fmtFecha(p.fecha_pago) +
                         (p.metodo_pago ? ' · ' + esc(p.metodo_pago) : '') +
                         '</span>' +
                         '<span style="font-weight:700;color:var(--success);">' +
                         'RD$' + fmtMonto(p.monto) + '</span></div>';
                });

                h += '</div>';
            }

            /* Botones del modal */
            h += '<div style="padding:12px 14px;border-top:1px solid var(--border);' +
                 'display:flex;gap:8px;flex-wrap:wrap;">';

            h += '<a href="imprimir.php?factura_id=' + f.id +
                 '" target="_blank" rel="noopener" ' +
                 'class="btn btn-primary" style="flex:1;min-width:130px;">' +
                 '<i class="fas fa-print"></i> Imprimir Recibo</a>';

            if (f.telefono1) {
                var t1wa   = String(f.telefono1).replace(/\D/g, '');
                var nomCl  = ((f.nombre || '') + ' ' + (f.apellidos || '')).trim();
                var msgWa2 = 'Hola ' + nomCl + ', le contactamos de ORTHIIS Seguros ' +
                             'respecto a su factura ' + (f.numero_factura || '') + '.';
                h += '<a href="https://wa.me/1' + esc(t1wa) +
                     '?text=' + encodeURIComponent(msgWa2) +
                     '" target="_blank" rel="noopener" ' +
                     'class="btn btn-sm" ' +
                     'style="background:#16a34a;color:#fff;flex-shrink:0;padding:0 14px;">' +
                     '<i class="fab fa-whatsapp"></i></a>';
            }

            h += '</div>';

            body.innerHTML = h;
        })
        .catch(function(err) {
            body.innerHTML =
                '<div class="alert alert-danger" style="margin:20px;">' +
                'Error de conexión. Intenta de nuevo.</div>';
            console.error('abrirDetalleFactura error:', err);
        });
}

function cerrarModal() {
    document.getElementById('modalFactura').style.display = 'none';
    document.body.style.overflow = '';
}

/* Cerrar al clic en el fondo oscuro */
document.getElementById('modalFactura').addEventListener('click', function(e) {
    if (e.target === this) cerrarModal();
});

/* Cerrar con Escape */
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') cerrarModal();
});

/* ══════════════════════════════════════════════════════
   MAPA (Leaflet) — solo vista general
══════════════════════════════════════════════════════ */
<?php if (!$filtroClienteId): ?>
function iniciarMapa() {
    mapaLeaflet = L.map('mapa-ruta').setView([18.8038, -70.1626], 13);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap contributors',
        maxZoom: 19,
    }).addTo(mapaLeaflet);

    /* Posición del cobrador */
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function(pos) {
            var lat = pos.coords.latitude;
            var lng = pos.coords.longitude;
            var iconYo = L.divIcon({
                className: '',
                html: '<div style="background:#2563EB;width:18px;height:18px;' +
                      'border-radius:50%;border:3px solid #fff;' +
                      'box-shadow:0 2px 6px rgba(0,0,0,.4);"></div>',
                iconSize: [18, 18], iconAnchor: [9, 9],
            });
            L.marker([lat, lng], { icon: iconYo })
             .addTo(mapaLeaflet)
             .bindPopup('<strong>Tu ubicación actual</strong>');
            mapaLeaflet.setView([lat, lng], 14);
        }, function() {});
    }

    /* Clientes con facturas pendientes */
    fetch('api/get_ruta.php', { credentials: 'same-origin' })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            var clientes = d.clientes || [];
            var infoEl   = document.getElementById('mapaInfo');
            if (infoEl) {
                infoEl.textContent =
                    clientes.length + ' cliente(s) con facturas pendientes. ' +
                    'Toca un marcador para ver detalles.';
            }

            clientes.forEach(function(cl) {
                var popupHtml =
                    '<strong>' + esc(cl.nombre) + ' ' + esc(cl.apellidos) + '</strong><br>' +
                    '<small>' + esc(cl.direccion || 'Sin dirección') + '</small><br>' +
                    '<small>Pendiente: <strong>RD$' + fmtMonto(cl.monto_pendiente) + '</strong></small><br>' +
                    '<div style="display:flex;gap:6px;margin-top:4px;">' +
                    '<a href="https://maps.google.com/?q=' +
                    encodeURIComponent((cl.direccion || cl.nombre) + ', República Dominicana') +
                    '" target="_blank" style="color:#16a34a;font-size:12px;">' +
                    '<i class="fas fa-navigation"></i> Navegar</a>' +
                    ' &nbsp; ' +
                    '<a href="facturas.php?cliente_id=' + cl.id +
                    '" style="color:#2563EB;font-size:12px;">' +
                    '<i class="fas fa-file-invoice"></i> Facturas</a>' +
                    '</div>';

                if (cl.lat && cl.lng) {
                    L.marker([cl.lat, cl.lng])
                     .addTo(mapaLeaflet)
                     .bindPopup(popupHtml);
                }
            });
        })
        .catch(function(err) { console.error('get_ruta mapa:', err); });
}
<?php endif; ?>

/* ══════════════════════════════════════════════════════
   RUTA (drag & drop con SortableJS) — solo vista general
══════════════════════════════════════════════════════ */
<?php if (!$filtroClienteId): ?>
function cargarRuta() {
    var rc = document.getElementById('rutaContainer');
    var em = document.getElementById('emptyRuta');

    while (rc.firstChild) rc.removeChild(rc.firstChild);
    em.style.display = 'none';

    var sp = document.createElement('div');
    sp.className = 'loading-overlay';
    sp.innerHTML = '<div class="spinner"></div>';
    rc.appendChild(sp);

    fetch('api/get_ruta.php', { credentials: 'same-origin' })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            while (rc.firstChild) rc.removeChild(rc.firstChild);
            var clientes = d.clientes || [];

            if (!clientes.length) {
                em.style.display = 'block';
                return;
            }

            var frag = document.createDocumentFragment();

            clientes.forEach(function(cl, i) {
                var item = document.createElement('div');
                item.className = 'ruta-item';
                item.dataset.clienteId = cl.id;

                var tel = (cl.telefono1 || '').replace(/\D/g, '');

                /* Orden */
                var ord = document.createElement('div');
                ord.className = 'ruta-orden';
                ord.textContent = i + 1;
                item.appendChild(ord);

                /* Handle arrastre */
                var handle = document.createElement('div');
                handle.className = 'drag-handle';
                handle.innerHTML = '<i class="fas fa-grip-vertical"></i>';
                item.appendChild(handle);

                /* Info del cliente */
                var info = document.createElement('div');
                info.style.cssText = 'flex:1;min-width:0;';

                var nomDiv = document.createElement('div');
                nomDiv.style.cssText =
                    'font-size:13px;font-weight:700;color:var(--gray-800);';
                nomDiv.textContent =
                    ((cl.nombre || '') + ' ' + (cl.apellidos || '')).trim();
                info.appendChild(nomDiv);

                var dirDiv2 = document.createElement('div');
                dirDiv2.style.cssText =
                    'font-size:11px;color:var(--text-muted);' +
                    'overflow:hidden;text-overflow:ellipsis;white-space:nowrap;';
                dirDiv2.innerHTML =
                    '<i class="fas fa-map-marker-alt" style="font-size:9px;' +
                    'margin-right:2px;"></i>';
                dirDiv2.appendChild(
                    document.createTextNode(cl.direccion || 'Sin dirección')
                );
                info.appendChild(dirDiv2);

                var pendDiv = document.createElement('div');
                pendDiv.style.cssText =
                    'font-size:11px;color:var(--orange);font-weight:700;';
                pendDiv.textContent =
                    'RD$' + fmtMonto(cl.monto_pendiente) + ' pendiente' +
                    (cl.total_facturas ? ' · ' + cl.total_facturas + ' fact.' : '');
                info.appendChild(pendDiv);

                item.appendChild(info);

                /* Botones de acción */
                var btns = document.createElement('div');
                btns.style.cssText =
                    'display:flex;flex-direction:column;gap:5px;flex-shrink:0;';

                var btnNav = document.createElement('a');
                btnNav.href =
                    'https://maps.google.com/?q=' +
                    encodeURIComponent(
                        (cl.direccion || cl.nombre || '') + ', República Dominicana'
                    );
                btnNav.target = '_blank';
                btnNav.rel = 'noopener noreferrer';
                btnNav.className = 'btn btn-success btn-sm';
                btnNav.style.cssText = 'min-height:30px;padding:0 8px;font-size:11px;';
                btnNav.innerHTML = '<i class="fas fa-navigation"></i>';
                btnNav.title = 'Navegar con Google Maps';
                btns.appendChild(btnNav);

                if (tel) {
                    var btnTel = document.createElement('a');
                    btnTel.href = 'tel:' + tel;
                    btnTel.className = 'btn btn-sm';
                    btnTel.style.cssText =
                        'background:var(--accent-light);color:var(--accent);' +
                        'min-height:30px;padding:0 8px;font-size:11px;';
                    btnTel.innerHTML = '<i class="fas fa-phone"></i>';
                    btns.appendChild(btnTel);
                }

                item.appendChild(btns);
                frag.appendChild(item);
            });

            rc.appendChild(frag);

            /* Inicializar SortableJS */
            if (sortableInst) sortableInst.destroy();
            sortableInst = new Sortable(rc, {
                handle: '.drag-handle',
                animation: 180,
                ghostClass: 'sortable-ghost',
                chosenClass: 'sortable-chosen',
                onEnd: function() {
                    rc.querySelectorAll('.ruta-orden').forEach(function(el, idx) {
                        el.textContent = idx + 1;
                    });
                },
            });
        })
        .catch(function(err) {
            console.error('cargarRuta error:', err);
            showToast('Error al cargar la ruta.', 'error');
        });
}

function guardarRuta() {
    var items = Array.from(
        document.querySelectorAll('#rutaContainer .ruta-item')
    );
    var orden = items.map(function(el, i) {
        return { cliente_id: parseInt(el.dataset.clienteId, 10), orden: i };
    });

    fetch('api/guardar_ruta.php', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': CSRF_TOKEN,
        },
        body: JSON.stringify({ orden: orden }),
        credentials: 'same-origin',
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        showToast(
            d.message || (d.success ? 'Ruta guardada' : 'Error al guardar'),
            d.success ? 'success' : 'error'
        );
    })
    .catch(function() {
        showToast('Error al guardar la ruta.', 'error');
    });
}
<?php endif; ?>

/* ══════════════════════════════════════════════════════
   INICIALIZACIÓN AL CARGAR LA PÁGINA
══════════════════════════════════════════════════════ */
(function init() {
    <?php if ($filtroClienteId): ?>
    /* Vista filtrada por cliente — cargar solo lista */
    cargarFacturas(true);

    <?php elseif ($vistaInicial === 'mapa'): ?>
    /* Vista mapa */
    iniciarMapa();
    /* Pre-cargar lista en background */
    setTimeout(function() { cargarFacturas(true); }, 600);

    <?php elseif ($vistaInicial === 'ruta'): ?>
    /* Vista ruta */
    cargarRuta();
    /* Pre-cargar lista en background */
    setTimeout(function() { cargarFacturas(true); }, 600);

    <?php else: ?>
    /* Vista lista (default) */
    cargarFacturas(true);
    <?php endif; ?>
})();
</script>

</body>
</html>