<?php
/*
 * footer.php
 * Cierra .page-content, agrega el pie de página, scripts globales
 * y cierra .main-wrapper, </body>, </html>.
 * Se incluye al final de cada módulo con: require_once 'footer.php';
 */
?>

    </div>
    <!-- /page-content -->

    <!-- ============================================================
         PIE DE PÁGINA
         ============================================================ -->
    <footer class="page-footer">
        <span>
            &copy; <?php echo date('Y'); ?>
            <strong style="color:var(--accent);">ORTHIIS</strong>
            — Servicios Funerarios. Todos los derechos reservados.
        </span>
        <span style="color:var(--gray-400);">
            Diseñado por <strong>MM Lab Studio</strong>
        </span>
    </footer>

</div>
<!-- /main-wrapper -->


<!-- ============================================================
     SCRIPTS GLOBALES
     ============================================================ -->
<script src="scripts.js"></script>

<script>
/* ============================================================
   SIDEBAR TOGGLE — funciona en mobile, tablet y desktop
   ============================================================ */
(function () {
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebar       = document.getElementById('sidebar');
    const body          = document.body;

    // Restaurar estado guardado en localStorage
    const estadoGuardado = localStorage.getItem('orthiis_sidebar_collapsed');
    if (estadoGuardado === '1' && window.innerWidth > 768) {
        body.classList.add('sidebar-collapsed');
    }

    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener('click', function (e) {
            e.stopPropagation();
            if (window.innerWidth <= 768) {
                // Comportamiento MOBILE: toggle clase .open en sidebar
                sidebar.classList.toggle('open');
            } else {
                // Comportamiento DESKTOP/TABLET: toggle clase en body
                body.classList.toggle('sidebar-collapsed');
                const collapsed = body.classList.contains('sidebar-collapsed');
                localStorage.setItem('orthiis_sidebar_collapsed', collapsed ? '1' : '0');
            }
        });

        // Cerrar sidebar al hacer clic fuera en mobile
        document.addEventListener('click', function (e) {
            if (
                window.innerWidth <= 768 &&
                sidebar.classList.contains('open') &&
                !sidebar.contains(e.target) &&
                !sidebarToggle.contains(e.target)
            ) {
                sidebar.classList.remove('open');
            }
        });
    }

    // Responsive: al redimensionar ventana, limpiar estado mobile si pasa a desktop
    window.addEventListener('resize', function () {
        if (window.innerWidth > 768) {
            sidebar && sidebar.classList.remove('open');
        } else {
            body.classList.remove('sidebar-collapsed');
        }
    });
})();


/* ============================================================
   BUSCADOR GLOBAL INTELIGENTE
   ============================================================ */
(function () {
    const searchInput  = document.getElementById('topbarSearchInput');
    const dropdown     = document.getElementById('tsgDropdown');
    const resultsBox   = document.getElementById('tsgResultsContainer');
    const loadingBox   = document.getElementById('tsgLoading');
    const clearBtn     = document.getElementById('tsgClear');

    if (!searchInput) return;

    let debounceTimer = null;
    let ultimaQuery   = '';

    // Iconos según tipo
    function getIcon(tipo) {
        if (tipo === 'factura')  return '<span class="tsg-result-icon tipo-factura"><i class="fas fa-file-invoice-dollar"></i></span>';
        if (tipo === 'contrato') return '<span class="tsg-result-icon tipo-contrato"><i class="fas fa-file-contract"></i></span>';
        return '<span class="tsg-result-icon tipo-buscar"><i class="fas fa-search"></i></span>';
    }

    function mostrarDropdown() { dropdown.classList.add('active'); }
    function ocultarDropdown() { dropdown.classList.remove('active'); }

    function escHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function renderResultados(data) {
        loadingBox.style.display = 'none';
        resultsBox.innerHTML = '';

        if (!data.resultados || data.resultados.length === 0) {
            resultsBox.innerHTML = '<div class="tsg-no-results">'
                + '<i class="fas fa-search" style="display:block;font-size:24px;margin-bottom:8px;opacity:.3;"></i>'
                + 'Sin resultados para "' + escHtml(ultimaQuery) + '"</div>';
            mostrarDropdown();
            return;
        }

        // Header con contador
        const header = document.createElement('div');
        header.className = 'tsg-dropdown-header';
        const n = data.resultados.length;
        header.textContent = n + ' resultado' + (n !== 1 ? 's' : '') + ' encontrado' + (n !== 1 ? 's' : '');
        resultsBox.appendChild(header);

        data.resultados.forEach(function (item) {
            const a = document.createElement('a');
            a.className = 'tsg-result-item';
            a.href      = item.url;
            a.innerHTML = getIcon(item.tipo)
                + '<div class="tsg-result-text">'
                +   '<div class="tsg-result-title">' + escHtml(item.titulo) + '</div>'
                +   '<div class="tsg-result-sub">'   + escHtml(item.sub)   + '</div>'
                + '</div>'
                + (item.badge ? '<span class="tsg-result-badge">' + escHtml(item.badge) + '</span>' : '');
            resultsBox.appendChild(a);
        });

        mostrarDropdown();
    }

    function buscar(q) {
        if (q.trim().length < 2) { ocultarDropdown(); return; }
        ultimaQuery = q;
        resultsBox.innerHTML = '';
        loadingBox.style.display = 'block';
        mostrarDropdown();

        fetch('buscar_global.php?q=' + encodeURIComponent(q))
            .then(function (r) { return r.json(); })
            .then(function (data) { renderResultados(data); })
            .catch(function () {
                loadingBox.style.display = 'none';
                resultsBox.innerHTML = '<div class="tsg-no-results">Error al buscar. Intenta de nuevo.</div>';
            });
    }

    // Evento: escribir en el buscador
    searchInput.addEventListener('input', function () {
        const q = this.value.trim();
        clearBtn && clearBtn.classList.toggle('visible', q.length > 0);
        clearTimeout(debounceTimer);
        if (q.length < 2) { ocultarDropdown(); return; }
        debounceTimer = setTimeout(function () { buscar(q); }, 320);
    });

    // Evento: Enter → navegar al primer resultado
    searchInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            const primer = resultsBox.querySelector('.tsg-result-item');
            if (primer) {
                window.location.href = primer.href;
            } else {
                const q = this.value.trim();
                if (q) window.location.href = 'contratos.php?buscar=' + encodeURIComponent(q) + '&estado=all&vendedor=all';
            }
        }
        if (e.key === 'Escape') { ocultarDropdown(); searchInput.blur(); }
    });

    // Botón limpiar
    if (clearBtn) {
        clearBtn.addEventListener('click', function () {
            searchInput.value = '';
            clearBtn.classList.remove('visible');
            ocultarDropdown();
            searchInput.focus();
        });
    }

    // Cerrar dropdown al hacer clic fuera
    document.addEventListener('click', function (e) {
        const wrapper = document.getElementById('topbarSearchGlobal');
        if (wrapper && !wrapper.contains(e.target)) {
            ocultarDropdown();
        }
    });
})();


/* ============================================================
   DROPDOWN USUARIO (topbar)
   ============================================================ */
(function () {
    const topbarUser  = document.getElementById('topbarUser');
    const userDropdown = document.getElementById('userDropdown');

    if (topbarUser && userDropdown) {
        topbarUser.addEventListener('click', function (e) {
            e.stopPropagation();
            userDropdown.classList.toggle('active');
        });

        // Cerrar al hacer clic fuera
        document.addEventListener('click', function () {
            userDropdown.classList.remove('active');
        });

        // Evitar que se cierre al hacer clic dentro del dropdown
        userDropdown.addEventListener('click', function (e) {
            e.stopPropagation();
        });
    }
})();


/* ============================================================
   FUNCIÓN GLOBAL: mostrarToast
   (disponible en todos los módulos)
   ============================================================ */
function mostrarToast(mensaje, tipo = 'info', duracion = 4000) {
    const colores = {
        success : 'linear-gradient(135deg, #2E7D32, #388E3C)',
        error   : 'linear-gradient(135deg, #C62828, #D32F2F)',
        warning : 'linear-gradient(135deg, #F57F17, #F9A825)',
        info    : 'linear-gradient(135deg, #1565C0, #2196F3)'
    };

    Toastify({
        text        : mensaje,
        duration    : duracion,
        close       : true,
        gravity     : 'top',
        position    : 'right',
        style       : { background: colores[tipo] || colores.info },
        stopOnFocus : true
    }).showToast();
}


/* ============================================================
   CERRAR MODALES CON TECLA ESCAPE
   ============================================================ */
document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
        // Modales propios del sistema (clase modal-overlay con clase open)
        document.querySelectorAll('.modal-overlay.open').forEach(function (modal) {
            modal.classList.remove('open');
        });
    }
});


/* ============================================================
   CERRAR MODALES PROPIOS AL HACER CLIC EN EL OVERLAY
   ============================================================ */
document.querySelectorAll('.modal-overlay').forEach(function (overlay) {
    overlay.addEventListener('click', function (e) {
        if (e.target === overlay) {
            overlay.classList.remove('open');
        }
    });
});
</script>

</body>
</html>