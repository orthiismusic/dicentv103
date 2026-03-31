<?php
require_once 'header.php';
require_once 'reporte_utils.php';

// Verificar permisos
verificarSesion();

// Obtener datos para filtros
try {
    // Obtener planes activos
    $stmt = $conn->prepare("SELECT id, nombre FROM planes WHERE estado = 'activo'");
    $stmt->execute();
    $planes = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Obtener vendedores activos
    $stmt = $conn->prepare("SELECT id, nombre_completo FROM vendedores WHERE estado = 'activo'");
    $stmt->execute();
    $vendedores = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Obtener cobradores activos
    $stmt = $conn->prepare("SELECT id, nombre_completo FROM cobradores WHERE estado = 'activo'");
    $stmt->execute();
    $cobradores = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Obtener KPIs iniciales
    $kpis = obtenerKPIs($conn);
} catch (PDOException $e) {
    error_log("Error obteniendo datos para filtros: " . $e->getMessage());
    $planes = [];
    $vendedores = [];
    $cobradores = [];
    $kpis = [];
}

// Obtener configuración del sistema
$stmtConfig = $conn->prepare("SELECT * FROM configuracion_sistema WHERE id = 1");
$stmtConfig->execute();
$config = $stmtConfig->fetch(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Reportes - <?php echo htmlspecialchars($config['nombre_empresa']); ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
    
    
        /* Estilos para el modal de carga */
        
        
        .progress-bar-container .chart-card {
            width: 500px;
            max-width: 90%;
            background-color: white;
            border-radius: var(--border-radius-md);
        }
        
        .pulse-loader {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            background-color: var(--primary-color);
            animation: pulse 1.2s infinite;
        }
        
        @keyframes pulse {
            0% {
                transform: scale(0.95);
                box-shadow: 0 0 0 0 rgba(26, 115, 232, 0.7);
            }
            70% {
                transform: scale(1);
                box-shadow: 0 0 0 10px rgba(26, 115, 232, 0);
            }
            100% {
                transform: scale(0.95);
                box-shadow: 0 0 0 0 rgba(26, 115, 232, 0);
            }
        }
        
        /* Estilos para las pestañas */
        .nav-tabs {
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 20px;
        }
        
        .nav-tabs .nav-link {
            color: var(--text-secondary);
            font-weight: 500;
            padding: 12px 20px;
            border: none;
            position: relative;
            transition: all 0.2s ease;
        }
        
        .nav-tabs .nav-link.active {
            color: var(--primary-color);
            background-color: transparent;
            border: none;
            font-weight: 600;
        }
        
        .nav-tabs .nav-link.active::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            width: 100%;
            height: 3px;
            background-color: var(--primary-color);
        }
        
        .nav-tabs .nav-link:hover:not(.active) {
            color: var(--primary-color);
            border: none;
        }
        
        /* Estilos para los formularios */
        .form-label {
            font-weight: 500;
            color: var(--text-secondary);
            margin-bottom: 6px;
        }
        
        .form-select, .form-control {
            border-radius: var(--border-radius-sm);
            border: 1px solid var(--border-color);
            padding: 8px 12px;
            transition: border-color 0.2s ease;
        }
        
        .form-select:focus, .form-control:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(26, 115, 232, 0.1);
        }
        
        /* Estilos para los botones */
        .btn {
            border-radius: var(--border-radius-sm);
            font-weight: 500;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 8px 16px;
            transition: all 0.2s ease;
        }
        
        .btn i {
            margin-right: 8px;
        }
        
        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }
        
        .btn-primary:hover {
            background-color: var(--primary-dark);
            border-color: var(--primary-dark);
            transform: translateY(-2px);
            box-shadow: 0 4px 6px rgba(26, 115, 232, 0.2);
        }
        
        .btn-success {
            background-color: var(--success-color);
            border-color: var(--success-color);
        }
        
        .btn-success:hover {
            background-color: #2b8a44;
            border-color: #2b8a44;
            transform: translateY(-2px);
            box-shadow: 0 4px 6px rgba(52, 168, 83, 0.2);
        }
        
        .btn-danger {
            background-color: var(--error-color);
            border-color: var(--error-color);
        }
        
        .btn-danger:hover {
            background-color: #d03b2d;
            border-color: #d03b2d;
            transform: translateY(-2px);
            box-shadow: 0 4px 6px rgba(234, 67, 53, 0.2);
        }
        
        .btn-outline {
            background-color: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
        }
        
        .btn-outline:hover {
            background-color: var(--hover-bg);
            color: var(--primary-color);
        }
        
        /* Estilos para los resultados */
        #resultadosGeneral, #resultadosFacturacion, #resultadosPersonal, #resultadosPlanes {
            margin-top: 20px;
        }
    
    
        /* Estilos para las 6 tarjetas en línea */
        .dashboard-stats {
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 15px;
            margin-bottom: 25px;
        }
        
        .stat-card {
            padding: 10px;
        }
        
        .stat-icon {
            width: 40px;
            height: 40px;
        }
        
        .stat-value {
            font-size: 1rem;
            font-weight: 600;
            margin-bottom: 2px;
        }
        
        .stat-label {
            font-size: 0.7rem;
        }
        
        @media (max-width: 1400px) {
            .dashboard-stats {
                grid-template-columns: repeat(3, 1fr);
            }
        }
        
        @media (max-width: 768px) {
            .dashboard-stats {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        @media (max-width: 576px) {
            .dashboard-stats {
                grid-template-columns: 1fr;
            }
        }
    
    
        /* Estilos para el contenedor principal */
        .container-fluid {
            padding: 20px 30px;
        }

        /* Estilos para las tarjetas KPI */
        .kpi-card {
            border-left: 4px solid;
            transition: transform 0.2s;
            box-shadow: 0 0.15rem 1.75rem 0 rgba(58, 59, 69, 0.15);
        }
        .kpi-card:hover {
            transform: translateY(-5px);
        }
        .border-left-primary { border-left-color: #4e73df; }
        .border-left-success { border-left-color: #1cc88a; }
        .border-left-info { border-left-color: #36b9cc; }
        .border-left-warning { border-left-color: #f6c23e; }
        .border-left-danger { border-left-color: #e74a3b; }
        .border-left-secondary { border-left-color: #858796; }

        /* Estilos para la barra de progreso */
        .progress-bar-container {
            display: none;
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            width: 50%;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 15px rgba(0,0,0,0.2);
            z-index: 1000;
        }

        /* Estilos para las pestañas y contenido */
        .nav-tabs .nav-link {
            color: #4e73df;
            font-weight: 500;
            padding: 0.75rem 1rem;
        }
        .nav-tabs .nav-link.active {
            color: #224abe;
            font-weight: 600;
            border-bottom: 3px solid #4e73df;
        }
        .tab-content {
            background: #ffffff;
            padding: 20px;
            border: 1px solid #e3e6f0;
            border-top: none;
            border-radius: 0 0 0.35rem 0.35rem;
        }

        /* Estilos para los filtros */
        .filter-section {
            background-color: #f8f9fc;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
        }

        /* Estilos para tablas de resultados */
        .table-responsive {
            margin-top: 20px;
        }
        .table {
            width: 100%;
            margin-bottom: 1rem;
            color: #858796;
        }
        .table th {
            background-color: #f8f9fc;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.9rem;
        }
        .table td {
            vertical-align: middle;
        }

        /* Estilos para gráficos */
        .chart-container {
            position: relative;
            margin: 20px 0;
            height: 300px;
        }

        /* Estilos para botones */
        .btn-group {
            margin-top: 15px;
        }
        .btn {
            margin-right: 10px;
        }
        .btn i {
            margin-right: 5px;
        }

        /* Estilos para estados */
        .badge {
            padding: 0.5em 0.8em;
            font-size: 0.75em;
            font-weight: 600;
            border-radius: 0.25rem;
        }
        .badge-pendiente { background-color: #f6c23e; color: #fff; }
        .badge-pagada { background-color: #1cc88a; color: #fff; }
        .badge-vencida { background-color: #e74a3b; color: #fff; }


        .main-content-inner {
            padding: 1.5rem;
            background-color: #f8f9fc;
            min-height: calc(100vh - 60px);
        }


        /* Estilos responsivos */
        @media (max-width: 768px) {
            .container-fluid {
                padding: 15px;
            }
            .kpi-card {
                margin-bottom: 15px;
            }
            .filter-section {
                padding: 15px;
            }
        }
    </style>
</head>
<body>

<!-- Contenedor de barra de progreso -->
<div id="progressContainer" class="progress-bar-container">
    <h5>Generando reporte...</h5>
    <div class="progress">
        <div id="progressBar" class="progress-bar progress-bar-striped progress-bar-animated" 
             role="progressbar" style="width: 0%"></div>
    </div>
    <p id="progressText" class="mt-2 text-center">Procesando registros: 0/0</p>
</div>
<!-- Contenedor principal -->
<div class="main-content-inner">
    <h1 class="h3 mb-4 text-gray-800">Reportes del Sistema</h1>
    
    <!-- Sección de KPIs -->
    <div class="dashboard-stats">
        <div class="stat-card clients">
            <div class="stat-content">
                <div class="stat-icon">
                    <i class="fas fa-file-contract"></i>
                </div>
                <div class="stat-info">
                    <h3>Contratos Activos</h3>
                    <p class="stat-value"><?php echo number_format($kpis['contratos_activos'] ?? 0); ?></p>
                    <p class="stat-label">Total activos</p>
                </div>
            </div>
            <div class="stat-trend up">
                <i class="fas fa-arrow-up"></i>
                <span>5%</span>
            </div>
        </div>
    
        <div class="stat-card payments">
            <div class="stat-content">
                <div class="stat-icon">
                    <i class="fas fa-clock"></i>
                </div>
                <div class="stat-info">
                    <h3>Facturas Pendientes</h3>
                    <p class="stat-value"><?php echo number_format($kpis['facturas_pendientes'] ?? 0); ?></p>
                    <p class="stat-label">Por cobrar</p>
                </div>
            </div>
            <div class="stat-trend down">
                <i class="fas fa-arrow-down"></i>
                <span>2%</span>
            </div>
        </div>
    
        <div class="stat-card income">
            <div class="stat-content">
                <div class="stat-icon">
                    <i class="fas fa-dollar-sign"></i>
                </div>
                <div class="stat-info">
                    <h3>Monto por Cobrar</h3>
                    <p class="stat-value">RD$<?php echo number_format($kpis['monto_por_cobrar'] ?? 0, 2); ?></p>
                    <p class="stat-label">Pendiente</p>
                </div>
            </div>
            <div class="stat-trend up">
                <i class="fas fa-arrow-up"></i>
                <span>3.2%</span>
            </div>
        </div>
    
        <div class="stat-card contracts">
            <div class="stat-content">
                <div class="stat-icon">
                    <i class="fas fa-chart-line"></i>
                </div>
                <div class="stat-info">
                    <h3>Tasa de Morosidad</h3>
                    <p class="stat-value"><?php echo number_format($kpis['tasa_morosidad'] ?? 0, 2); ?>%</p>
                    <p class="stat-label">Promedio</p>
                </div>
            </div>
            <div class="stat-trend down">
                <i class="fas fa-arrow-down"></i>
                <span>1.5%</span>
            </div>
        </div>
    
        <div class="stat-card income">
            <div class="stat-content">
                <div class="stat-icon">
                    <i class="fas fa-chart-bar"></i>
                </div>
                <div class="stat-info">
                    <h3>Proyección de Ingresos</h3>
                    <p class="stat-value">RD$<?php echo number_format($kpis['proyeccion_ingresos'] ?? 0, 2); ?></p>
                    <p class="stat-label">Estimado</p>
                </div>
            </div>
            <div class="stat-trend up">
                <i class="fas fa-arrow-up"></i>
                <span>4.5%</span>
            </div>
        </div>
    
        <div class="stat-card clients">
            <div class="stat-content">
                <div class="stat-icon">
                    <i class="fas fa-users"></i>
                </div>
                <div class="stat-info">
                    <h3>Dependientes Activos</h3>
                    <p class="stat-value"><?php echo number_format($kpis['dependientes_activos'] ?? 0); ?></p>
                    <p class="stat-label">Registrados</p>
                </div>
            </div>
            <div class="stat-trend up">
                <i class="fas fa-arrow-up"></i>
                <span>3%</span>
            </div>
        </div>
    </div>

    <!-- Pestañas de Reportes -->
    <div class="chart-card">
        <div class="chart-header">
            <h3>Reportes del Sistema</h3>
        </div>
        <ul class="nav nav-tabs" id="reporteTabs" role="tablist">
            <li class="nav-item">
                <a class="nav-link active" id="general-tab" data-bs-toggle="tab" href="#general" role="tab">
                    <i class="fas fa-file-alt"></i> Reportes Generales
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link" id="facturacion-tab" data-bs-toggle="tab" href="#facturacion" role="tab">
                    <i class="fas fa-file-invoice-dollar"></i> Facturación
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link" id="personal-tab" data-bs-toggle="tab" href="#personal" role="tab">
                    <i class="fas fa-users"></i> Personal
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link" id="planes-tab" data-bs-toggle="tab" href="#planes" role="tab">
                    <i class="fas fa-chart-pie"></i> Planes
                </a>
            </li>
        </ul>
        <div class="tab-content" id="reporteTabsContent">
            <!-- Contenido Reportes Generales -->
                <div class="tab-pane fade show active" id="general" role="tabpanel">
                    <div class="filter-section">
                        <form id="formReporteGeneral" class="row g-3">
                            <div class="col-md-3">
                                <label class="form-label">Tipo de Reporte</label>
                                <select class="form-select" id="tipoReporteGeneral" required>
                                    <option value="">Seleccione un tipo...</option>
                                    <option value="clientes_contratos">Clientes con Contratos</option>
                                    <option value="contratos_dependientes">Contratos con Dependientes</option>
                                    <option value="clientes_estado">Clientes por Estado</option>
                                    <option value="contratos_vencidos">Contratos Vencidos</option>
                                    <option value="contratos_estado">Contratos por Estado</option>
                                </select>
                            </div>
                            <div class="col-md-3">
                                <label class="form-label">Período</label>
                                <select class="form-select" id="periodoReporteGeneral">
                                    <option value="ultimo_mes">Último Mes</option>
                                    <option value="ultimo_trimestre">Último Trimestre</option>
                                    <option value="ultimo_anio">Último Año</option>
                                    <option value="personalizado">Personalizado</option>
                                </select>
                            </div>
                            <div class="col-md-3">
                                <label class="form-label">Fecha Desde</label>
                                <input type="date" class="form-control" id="fechaDesdeGeneral">
                            </div>
                            <div class="col-md-3">
                                <label class="form-label">Fecha Hasta</label>
                                <input type="date" class="form-control" id="fechaHastaGeneral">
                            </div>
                            <div class="col-12">
                                <div class="d-flex justify-content-end gap-2">
                                    <button type="button" class="btn btn-primary" onclick="generarVistaPrevia('General')">
                                        <i class="fas fa-eye"></i> Vista Previa
                                    </button>
                                    <button type="button" class="btn btn-success" onclick="exportarReporte('General', 'xlsx')">
                                        <i class="fas fa-file-excel"></i> Exportar Excel
                                    </button>
                                    <button type="button" class="btn btn-danger" onclick="exportarReporte('General', 'pdf')">
                                        <i class="fas fa-file-pdf"></i> Exportar PDF
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                    <div id="resultadosGeneral"></div>
                </div>

                <!-- Contenido Reportes de Facturación -->
                <div class="tab-pane fade" id="facturacion" role="tabpanel">
                    <div class="filter-section">
                        <form id="formReporteFacturacion" class="row g-3">
                            <div class="col-md-3">
                                <label class="form-label">Tipo de Reporte</label>
                                <select class="form-select" id="tipoReporteFacturacion" required>
                                    <option value="">Seleccione un tipo...</option>
                                    <option value="facturas_contratos">Facturas por Contrato</option>
                                    <option value="facturas_vencidas">Facturas Vencidas</option>
                                    <option value="facturacion_periodo">Facturación por Período</option>
                                    <option value="pagos_recibidos">Pagos Recibidos</option>
                                    <option value="ingresos_plan">Ingresos por Plan</option>
                                </select>
                            </div>
                            <div class="col-md-3">
                                <label class="form-label">Estado de Factura</label>
                                <select class="form-select" id="estadoFactura">
                                    <option value="">Todos</option>
                                    <option value="pendiente">Pendiente</option>
                                    <option value="pagada">Pagada</option>
                                    <option value="vencida">Vencida</option>
                                    <option value="anulada">Anulada</option>
                                </select>
                            </div>
                            <div class="col-md-2">
                                <label class="form-label">Plan</label>
                                <select class="form-select" id="planFacturacion">
                                    <option value="">Todos los planes</option>
                                    <?php foreach ($planes as $plan): ?>
                                        <option value="<?php echo $plan['id']; ?>">
                                            <?php echo htmlspecialchars($plan['nombre']); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="col-md-2">
                                <label class="form-label">Fecha Desde</label>
                                <input type="date" class="form-control" id="fechaDesdeFacturacion">
                            </div>
                            <div class="col-md-2">
                                <label class="form-label">Fecha Hasta</label>
                                <input type="date" class="form-control" id="fechaHastaFacturacion">
                            </div>
                            <div class="col-12">
                                <div class="d-flex justify-content-end gap-2">
                                    <button type="button" class="btn btn-primary" onclick="generarVistaPrevia('Facturacion')">
                                        <i class="fas fa-eye"></i> Vista Previa
                                    </button>
                                    <button type="button" class="btn btn-success" onclick="exportarReporte('Facturacion', 'xlsx')">
                                        <i class="fas fa-file-excel"></i> Exportar Excel
                                    </button>
                                    <button type="button" class="btn btn-danger" onclick="exportarReporte('Facturacion', 'pdf')">
                                        <i class="fas fa-file-pdf"></i> Exportar PDF
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                    <div id="resultadosFacturacion"></div>
                </div>
                <!-- Contenido Reportes de Personal -->
                <div class="tab-pane fade" id="personal" role="tabpanel">
                    <div class="filter-section">
                        <form id="formReportePersonal" class="row g-3">
                            <div class="col-md-3">
                                <label class="form-label">Tipo de Reporte</label>
                                <select class="form-select" id="tipoReportePersonal" required>
                                    <option value="">Seleccione un tipo...</option>
                                    <option value="ventas_vendedor">Ventas por Vendedor</option>
                                    <option value="cobros_cobrador">Cobros por Cobrador</option>
                                </select>
                            </div>
                            <div class="col-md-3">
                                <label class="form-label">Personal</label>
                                <select class="form-select" id="personalSeleccionado">
                                    <option value="">Todos</option>
                                    <!-- Se llenará dinámicamente según el tipo de reporte -->
                                </select>
                            </div>
                            <div class="col-md-3">
                                <label class="form-label">Fecha Desde</label>
                                <input type="date" class="form-control" id="fechaDesdePersonal">
                            </div>
                            <div class="col-md-3">
                                <label class="form-label">Fecha Hasta</label>
                                <input type="date" class="form-control" id="fechaHastaPersonal">
                            </div>
                            <div class="col-12">
                                <div class="d-flex justify-content-end gap-2">
                                    <button type="button" class="btn btn-primary" onclick="generarVistaPrevia('Personal')">
                                        <i class="fas fa-eye"></i> Vista Previa
                                    </button>
                                    <button type="button" class="btn btn-success" onclick="exportarReporte('Personal', 'excel')">
                                        <i class="fas fa-file-excel"></i> Exportar Excel
                                    </button>
                                    <button type="button" class="btn btn-danger" onclick="exportarReporte('Personal', 'pdf')">
                                        <i class="fas fa-file-pdf"></i> Exportar PDF
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                    <div id="resultadosPersonal"></div>
                </div>

                <!-- Contenido Reportes de Planes -->
                <div class="tab-pane fade" id="planes" role="tabpanel">
                    <div class="filter-section">
                        <form id="formReportePlanes" class="row g-3">
                            <div class="col-md-3">
                                <label class="form-label">Tipo de Reporte</label>
                                <select class="form-select" id="tipoReportePlanes" required>
                                    <option value="">Seleccione un tipo...</option>
                                    <option value="contratos_plan">Contratos por Plan</option>
                                    <option value="planes_populares">Planes Más Contratados</option>
                                </select>
                            </div>
                            <div class="col-md-3">
                                <label class="form-label">Plan Específico</label>
                                <select class="form-select" id="planEspecifico">
                                    <option value="">Todos los planes</option>
                                    <?php foreach ($planes as $plan): ?>
                                        <option value="<?php echo $plan['id']; ?>">
                                            <?php echo htmlspecialchars($plan['nombre']); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="col-md-3">
                                <label class="form-label">Fecha Desde</label>
                                <input type="date" class="form-control" id="fechaDesdePlanes">
                            </div>
                            <div class="col-md-3">
                                <label class="form-label">Fecha Hasta</label>
                                <input type="date" class="form-control" id="fechaHastaPlanes">
                            </div>
                            <div class="col-12">
                                <div class="d-flex justify-content-end gap-2">
                                    <button type="button" class="btn btn-primary" onclick="generarVistaPrevia('Planes')">
                                        <i class="fas fa-eye"></i> Vista Previa
                                    </button>
                                    <button type="button" class="btn btn-success" onclick="exportarReporte('Planes', 'excel')">
                                        <i class="fas fa-file-excel"></i> Exportar Excel
                                    </button>
                                    <button type="button" class="btn btn-danger" onclick="exportarReporte('Planes', 'pdf')">
                                        <i class="fas fa-file-pdf"></i> Exportar PDF
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                    <div id="resultadosPlanes"></div>
                </div>
            </div>
        </div>
    </div>
</div>
<!-- Scripts -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
// Variables globales
let currentCharts = {};
let currentAjaxRequest = null;

// Inicialización
document.addEventListener('DOMContentLoaded', function() {
    initializeTabs();
    initializeFilterEvents();
    setInterval(updateKPIs, 60000); // Actualizar KPIs cada minuto
    setDefaultDates();
});

function initializeTabs() {
    const triggerTabList = [].slice.call(document.querySelectorAll('#reporteTabs a'));
    triggerTabList.forEach(function(triggerEl) {
        triggerEl.addEventListener('shown.bs.tab', function(event) {
            const tipo = event.target.getAttribute('href').replace('#', '');
            resetVistaPrevia(tipo);
        });
    });
}

function initializeFilterEvents() {
    // Manejar cambios en tipo de reporte personal
    document.getElementById('tipoReportePersonal').addEventListener('change', function(e) {
        actualizarSelectPersonal(e.target.value);
    });

    // Manejar cambios en períodos
    const periodosSelects = document.querySelectorAll('select[id$="Reporte"]');
    periodosSelects.forEach(select => {
        select.addEventListener('change', function(e) {
            const tipo = e.target.id.replace('tipoReporte', '');
            actualizarFechasPeriodo(tipo, this.value);
        });
    });
}

function setDefaultDates() {
    const hoy = new Date();
    const primerDiaMes = new Date(hoy.getFullYear(), hoy.getMonth(), 1);
    
    document.querySelectorAll('input[id^="fechaHasta"]').forEach(input => {
        input.value = hoy.toISOString().split('T')[0];
    });
    
    document.querySelectorAll('input[id^="fechaDesde"]').forEach(input => {
        input.value = primerDiaMes.toISOString().split('T')[0];
    });
}

function actualizarFechasPeriodo(tipo, periodo) {
    const fechaHasta = new Date();
    let fechaDesde = new Date();

    switch(periodo) {
        case 'ultimo_mes':
            fechaDesde.setMonth(fechaDesde.getMonth() - 1);
            break;
        case 'ultimo_trimestre':
            fechaDesde.setMonth(fechaDesde.getMonth() - 3);
            break;
        case 'ultimo_anio':
            fechaDesde.setFullYear(fechaDesde.getFullYear() - 1);
            break;
    }

    if (periodo !== 'personalizado') {
        document.getElementById(`fechaDesde${tipo}`).value = fechaDesde.toISOString().split('T')[0];
        document.getElementById(`fechaHasta${tipo}`).value = fechaHasta.toISOString().split('T')[0];
    }
}

async function generarVistaPrevia(tipo) {
    try {
        mostrarCargando();
        
        if (currentAjaxRequest) {
            currentAjaxRequest.abort();
        }

        const parametros = obtenerParametrosReporte(tipo);
        console.log('Enviando parámetros:', parametros);

        // Usar fetch con mejor manejo de errores
        const response = await fetch('reportes-impresion.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify(parametros)
        });

        // Imprimir headers de respuesta para depuración
        console.log('Headers de respuesta:', Object.fromEntries(response.headers.entries()));
        console.log('Status:', response.status);

        const texto = await response.text();
        console.log('Respuesta del servidor:', texto);

        if (!response.ok) {
            throw new Error(`Error del servidor: ${texto}`);
        }

        // Intentar abrir en nueva ventana
        const ventanaReporte = window.open('', '_blank');
        if (!ventanaReporte) {
            throw new Error('El navegador bloqueó la ventana emergente. Por favor, permita las ventanas emergentes para este sitio.');
        }
        
        ventanaReporte.document.write(texto);
        ventanaReporte.document.close();

    } catch (error) {
        console.error('Error completo:', error);
        alert('Error al generar la vista previa: ' + error.message);
    } finally {
        ocultarCargando();
    }
}

async function exportarReporte(tipo, formato) {
    try {
        mostrarCargando();
        
        const parametros = obtenerParametrosReporte(tipo);
        parametros.formato = formato;

        const response = await fetch('generar_reporte.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(parametros)
        });

        if (!response.ok) throw new Error('Error en la respuesta del servidor');

        const blob = await response.blob();
        const downloadUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = `reporte_${tipo.toLowerCase()}_${new Date().toISOString().slice(0,10)}.${formato}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(downloadUrl);

    } catch (error) {
        console.error('Error:', error);
        mostrarError('Error al exportar el reporte');
    } finally {
        ocultarCargando();
    }
}

function obtenerParametrosReporte(tipo) {
    const params = {
        tipo: tipo,
        tipoReporte: document.getElementById(`tipoReporte${tipo}`).value,
        fechaDesde: document.getElementById(`fechaDesde${tipo}`).value,
        fechaHasta: document.getElementById(`fechaHasta${tipo}`).value
    };

    // Agregar parámetros específicos según el tipo
    switch (tipo) {
        case 'Facturacion':
            params.estadoFactura = document.getElementById('estadoFactura').value;
            params.planId = document.getElementById('planFacturacion').value;
            break;
        case 'Personal':
            params.personalId = document.getElementById('personalSeleccionado').value;
            break;
        case 'Planes':
            params.planId = document.getElementById('planEspecifico').value;
            break;
    }

    return params;
}

async function actualizarSelectPersonal(tipoReporte) {
    const select = document.getElementById('personalSeleccionado');
    select.innerHTML = '<option value="">Todos</option>';

    try {
        const response = await fetch(`obtener_personal.php?tipo=${tipoReporte}`);
        const data = await response.json();

        if (data.success) {
            data.personal.forEach(persona => {
                const option = document.createElement('option');
                option.value = persona.id;
                option.textContent = persona.nombre_completo;
                select.appendChild(option);
            });
        }
    } catch (error) {
        console.error('Error:', error);
    }
}

function mostrarCargando() {
    document.getElementById('progressContainer').style.display = 'flex';
}

function ocultarCargando() {
    document.getElementById('progressContainer').style.display = 'none';
    document.getElementById('progressBar').style.width = '0%';
    document.getElementById('progressText').textContent = 'Procesando registros: 0/0';
}

function mostrarError(mensaje) {
    alert(mensaje);
}

async function updateKPIs() {
    try {
        const response = await fetch('obtener_kpis.php');
        const data = await response.json();
        
        if (data.success) {
            Object.keys(data.kpis).forEach(key => {
                const elemento = document.querySelector(`[data-kpi="${key}"]`);
                if (elemento) {
                    if (key.includes('monto') || key.includes('ingresos')) {
                        elemento.textContent = formatearMoneda(data.kpis[key]);
                    } else if (key.includes('tasa') || key.includes('porcentaje')) {
                        elemento.textContent = `${data.kpis[key].toFixed(2)}%`;
                    } else {
                        elemento.textContent = data.kpis[key].toLocaleString();
                    }
                }
            });
        }
    } catch (error) {
        console.error('Error actualizando KPIs:', error);
    }
}

function formatearMoneda(valor) {
    return new Intl.NumberFormat('es-DO', {
        style: 'currency',
        currency: 'DOP'
    }).format(valor);
}

function resetVistaPrevia(tipo) {
    const contenedor = document.getElementById(`resultados${tipo}`);
    if (contenedor) {
        contenedor.innerHTML = '';
    }

    // Destruir gráficos existentes
    if (currentCharts[tipo]) {
        Object.values(currentCharts[tipo]).forEach(chart => {
            if (chart && typeof chart.destroy === 'function') {
                chart.destroy();
            }
        });
        currentCharts[tipo] = {};
    }
}

// Inicializar el menú desplegable del usuario
document.addEventListener('DOMContentLoaded', function() {
    const profileUsername = document.getElementById('profileUsername');
    const profileDropdown = document.getElementById('profileDropdown');
    
    if (profileUsername && profileDropdown) {
        profileUsername.addEventListener('click', function(e) {
            e.stopPropagation();
            profileDropdown.classList.toggle('active');
        });
        
        // Cerrar dropdown al hacer clic fuera
        document.addEventListener('click', function() {
            if (profileDropdown.classList.contains('active')) {
                profileDropdown.classList.remove('active');
            }
        });
        
        // Evitar que el dropdown se cierre al hacer clic dentro
        profileDropdown.addEventListener('click', function(e) {
            e.stopPropagation();
        });
    }
});

</script>
</body>


<?php require_once 'footer.php'; ?>
</html>