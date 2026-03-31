<?php
/**
 * reporte_utils.php
 * Funciones auxiliares para el sistema de reportes
 */

/**
 * Obtiene los KPIs principales del sistema
 */
function obtenerKPIs($conn) {
    try {
        $kpis = [];
        
        // Total de contratos activos
        $stmt = $conn->query("
            SELECT COUNT(*) as total 
            FROM contratos 
            WHERE estado = 'activo'
        ");
        $kpis['contratos_activos'] = $stmt->fetchColumn();
        
        // Total de facturas pendientes y monto por cobrar
        $stmt = $conn->query("
            SELECT 
                COUNT(*) as total_facturas,
                SUM(monto) as monto_total 
            FROM facturas 
            WHERE estado = 'pendiente'
        ");
        $facturas = $stmt->fetch(PDO::FETCH_ASSOC);
        $kpis['facturas_pendientes'] = $facturas['total_facturas'];
        $kpis['monto_por_cobrar'] = $facturas['monto_total'];
        
        // Tasa de morosidad
        $stmt = $conn->query("
            SELECT 
                (SELECT COUNT(*) FROM facturas WHERE estado = 'vencida') * 100.0 / 
                COUNT(*) as tasa_morosidad 
            FROM facturas 
            WHERE estado IN ('pagada', 'vencida')
        ");
        $kpis['tasa_morosidad'] = round($stmt->fetchColumn(), 2);
        
        // Proyección de ingresos del mes actual
        $stmt = $conn->query("
            SELECT SUM(monto) as proyeccion 
            FROM facturas 
            WHERE MONTH(fecha_emision) = MONTH(CURRENT_DATE()) 
            AND YEAR(fecha_emision) = YEAR(CURRENT_DATE())
            AND estado IN ('pendiente', 'pagada')
        ");
        $kpis['proyeccion_ingresos'] = $stmt->fetchColumn();
        
        // Total de dependientes activos
        $stmt = $conn->query("
            SELECT COUNT(*) as total 
            FROM dependientes 
            WHERE estado = 'activo'
        ");
        $kpis['dependientes_activos'] = $stmt->fetchColumn();
        
        return $kpis;
    } catch (PDOException $e) {
        error_log("Error obteniendo KPIs: " . $e->getMessage());
        return [];
    }
}

/**
 * Registra el inicio de generación de un reporte
 */
function registrarGeneracionReporte($conn, $usuario_id, $tipo_reporte, $parametros) {
    try {
        $stmt = $conn->prepare("
            INSERT INTO reportes_historial (
                usuario_id, 
                tipo_reporte, 
                parametros, 
                fecha_generacion,
                estado
            ) VALUES (?, ?, ?, NOW(), 'en_proceso')
        ");
        
        $stmt->execute([
            $usuario_id,
            $tipo_reporte,
            json_encode($parametros)
        ]);
        
        return $conn->lastInsertId();
    } catch (PDOException $e) {
        error_log("Error al registrar generación de reporte: " . $e->getMessage());
        return false;
    }
}

/**
 * Actualiza el estado de un reporte
 */
function actualizarEstadoReporte($conn, $reporte_id, $estado, $tiempo = null, $registros = null, $error = null) {
    try {
        $sql = "UPDATE reportes_historial 
                SET estado = ?, 
                    tiempo_generacion = ?, 
                    registros_procesados = ?, 
                    mensaje_error = ?,
                    updated_at = CURRENT_TIMESTAMP 
                WHERE id = ?";
                
        $stmt = $conn->prepare($sql);
        $stmt->execute([$estado, $tiempo, $registros, $error, $reporte_id]);
        return true;
    } catch (PDOException $e) {
        error_log("Error actualizando estado de reporte: " . $e->getMessage());
        return false;
    }
}

/**
 * Registra una entrada en la auditoría
 */
function registrarAuditoria($conn, $usuario_id, $accion, $detalles) {
    try {
        $stmt = $conn->prepare("
            INSERT INTO reportes_auditoria (
                usuario_id, 
                accion, 
                detalles, 
                ip_address, 
                fecha_hora
            ) VALUES (?, ?, ?, ?, NOW())
        ");
        
        $stmt->execute([
            $usuario_id,
            $accion,
            json_encode($detalles),
            $_SERVER['REMOTE_ADDR']
        ]);
        
        return true;
    } catch (PDOException $e) {
        error_log("Error registrando auditoría: " . $e->getMessage());
        return false;
    }
}

/**
 * Formatea valores monetarios
 */
function formatearMoneda($valor, $simbolo = 'RD$') {
    return $simbolo . number_format($valor, 2, '.', ',');
}

/**
 * Formatea fechas al formato deseado
 */
function formatearFecha($fecha, $formato = 'd/m/Y') {
    return date($formato, strtotime($fecha));
}

/**
 * Valida el rango de fechas para reportes
 */
function validarFechasReporte($fechaDesde, $fechaHasta) {
    $desde = strtotime($fechaDesde);
    $hasta = strtotime($fechaHasta);
    
    if (!$desde || !$hasta) {
        return false;
    }
    
    // Verificar que la fecha desde no sea mayor que la fecha hasta
    if ($desde > $hasta) {
        return false;
    }
    
    // Verificar que el rango no sea mayor a 5 años
    $diff = ($hasta - $desde) / (60 * 60 * 24 * 365);
    if ($diff > 5) {
        return false;
    }
    
    return true;
}

/**
 * Genera el encabezado estándar para reportes
 */
function generarEncabezadoReporte($conn, $titulo, $subtitulo = '') {
    // Obtener configuración de la empresa
    $stmt = $conn->prepare("SELECT * FROM configuracion_sistema WHERE id = 1");
    $stmt->execute();
    $config = $stmt->fetch(PDO::FETCH_ASSOC);
    
    $html = '<div class="reporte-header">';
    
    // Logo si existe
    if (!empty($config['logo_url'])) {
        $html .= '<img src="' . htmlspecialchars($config['logo_url']) . '" class="logo" alt="Logo">';
    }
    
    $html .= '<h1>' . htmlspecialchars($config['nombre_empresa']) . '</h1>';
    $html .= '<h2>' . htmlspecialchars($titulo) . '</h2>';
    
    if (!empty($subtitulo)) {
        $html .= '<h3>' . htmlspecialchars($subtitulo) . '</h3>';
    }
    
    $html .= '<p>Fecha de generación: ' . date('d/m/Y H:i:s') . '</p>';
    $html .= '</div>';
    
    return $html;
}

/**
 * Genera archivo Excel a partir de los datos del reporte
 */
function generarExcel($datos, $parametros) {
    require_once 'vendor/autoload.php';
    
    $spreadsheet = new \PhpOffice\PhpSpreadsheet\Spreadsheet();
    $sheet = $spreadsheet->getActiveSheet();
    
    // Configurar estilo del encabezado
    $headerStyle = [
        'font' => [
            'bold' => true,
            'color' => ['rgb' => 'FFFFFF'],
        ],
        'fill' => [
            'fillType' => \PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID,
            'startColor' => ['rgb' => '4472C4']
        ],
        'alignment' => [
            'horizontal' => \PhpOffice\PhpSpreadsheet\Style\Alignment::HORIZONTAL_CENTER
        ]
    ];
    
    // Configurar estilo de las celdas de datos
    $dataStyle = [
        'borders' => [
            'allBorders' => [
                'borderStyle' => \PhpOffice\PhpSpreadsheet\Style\Border::BORDER_THIN
            ]
        ]
    ];

    // Establecer encabezados de columna según el tipo de reporte
    $encabezados = obtenerEncabezadosReporte($parametros['tipo'], $parametros['tipoReporte']);
    $columna = 'A';
    $fila = 1;

    // Agregar título del reporte
    $sheet->setCellValue('A1', obtenerTituloReporte($parametros['tipo'], $parametros['tipoReporte']));
    $sheet->mergeCells('A1:' . chr(65 + count($encabezados) - 1) . '1');
    
    $fila++;

    // Agregar filtros aplicados
    $sheet->setCellValue('A2', 'Período: ' . formatearFecha($parametros['fechaDesde']) . 
                         ' al ' . formatearFecha($parametros['fechaHasta']));
    $sheet->mergeCells('A2:' . chr(65 + count($encabezados) - 1) . '2');
    
    $fila += 2;

    // Escribir encabezados
    foreach ($encabezados as $encabezado) {
        $sheet->setCellValue($columna . $fila, $encabezado);
        $sheet->getColumnDimension($columna)->setAutoSize(true);
        $columna++;
    }
    $sheet->getStyle('A'.$fila.':'.chr(64 + count($encabezados)).$fila)->applyFromArray($headerStyle);

    // Escribir datos
    $fila++;
    foreach ($datos['registros'] as $registro) {
        $columna = 'A';
        foreach ($registro as $valor) {
            if (is_numeric($valor) && strpos($columna, 'monto') !== false) {
                $sheet->setCellValue($columna . $fila, $valor);
                $sheet->getStyle($columna . $fila)->getNumberFormat()
                      ->setFormatCode(\PhpOffice\PhpSpreadsheet\Style\NumberFormat::FORMAT_CURRENCY_USD_SIMPLE);
            } else {
                $sheet->setCellValue($columna . $fila, $valor);
            }
            $columna++;
        }
        $fila++;
    }

    // Aplicar estilo a todas las celdas de datos
    $sheet->getStyle('A4:'.chr(64 + count($encabezados)).($fila-1))->applyFromArray($dataStyle);

    // Agregar totales si existen
    if (isset($datos['totalMontos']) && $datos['totalMontos'] > 0) {
        $fila++;
        $sheet->setCellValue('A' . $fila, 'Total General:');
        $sheet->setCellValue('B' . $fila, $datos['totalMontos']);
        $sheet->getStyle('B' . $fila)->getNumberFormat()
              ->setFormatCode(\PhpOffice\PhpSpreadsheet\Style\NumberFormat::FORMAT_CURRENCY_USD_SIMPLE);
        $sheet->getStyle('A'.$fila.':B'.$fila)->getFont()->setBold(true);
    }

    return $spreadsheet;
}

/**
 * Genera archivo PDF a partir de los datos del reporte
 */
function generarPDF($datos, $parametros) {
    require_once 'tcpdf/tcpdf.php';

    // Crear nuevo documento PDF
    $pdf = new TCPDF('P', 'mm', 'LETTER', true, 'UTF-8');

    // Establecer información del documento
    $pdf->SetCreator('Sistema de Reportes');
    $pdf->SetAuthor('ORTHIIS');
    $pdf->SetTitle(obtenerTituloReporte($parametros['tipo'], $parametros['tipoReporte']));

    // Eliminar encabezado y pie de página predeterminados
    $pdf->setPrintHeader(false);
    $pdf->setPrintFooter(false);

    // Agregar página
    $pdf->AddPage();

    // Establecer fuente
    $pdf->SetFont('helvetica', '', 10);

    // Agregar logo y encabezado
    agregarEncabezadoPDF($pdf, $parametros);

    // Agregar tabla de datos
    agregarTablaDatosPDF($pdf, $datos, $parametros);

    // Agregar totales y pie de página
    agregarPiePaginaPDF($pdf, $datos);

    return $pdf;
}

/**
 * Funciones auxiliares para la generación de PDF
 */
function agregarEncabezadoPDF($pdf, $parametros) {
    try {
        // Obtener configuración de la empresa
        global $conn;
        $stmt = $conn->prepare("SELECT * FROM configuracion_sistema WHERE id = 1");
        $stmt->execute();
        $config = $stmt->fetch(PDO::FETCH_ASSOC);

        // Agregar logo si existe
        if (!empty($config['logo_url']) && file_exists($config['logo_url'])) {
            $pdf->Image($config['logo_url'], 10, 10, 30);
        }

        // Información de la empresa
        $pdf->SetXY(45, 10);
        $pdf->SetFont('helvetica', 'B', 14);
        $pdf->Cell(0, 7, $config['nombre_empresa'], 0, 1, 'L');
        
        $pdf->SetFont('helvetica', '', 10);
        $pdf->SetXY(45, 18);
        $pdf->MultiCell(0, 5, $config['direccion'] . "\n" . 
                              "RIF: " . $config['rif'] . "\n" . 
                              "Tel: " . $config['telefono'], 0, 'L');

        // Título del reporte
        $pdf->SetXY(10, 40);
        $pdf->SetFont('helvetica', 'B', 12);
        $pdf->Cell(0, 10, obtenerTituloReporte($parametros['tipo'], $parametros['tipoReporte']), 0, 1, 'C');

        // Período del reporte
        $pdf->SetFont('helvetica', '', 10);
        $pdf->Cell(0, 10, 'Período: ' . formatearFecha($parametros['fechaDesde']) . 
                         ' al ' . formatearFecha($parametros['fechaHasta']), 0, 1, 'C');

        $pdf->Ln(5);
    } catch (Exception $e) {
        error_log("Error en agregarEncabezadoPDF: " . $e->getMessage());
    }
}

function agregarTablaDatosPDF($pdf, $datos, $parametros) {
    try {
        // Configurar encabezados según tipo de reporte
        $encabezados = obtenerEncabezadosReporte($parametros['tipo'], $parametros['tipoReporte']);
        
        // Calcular anchos de columna
        $anchos = calcularAnchosColumnasPDF($encabezados);
        
        // Estilo de encabezados
        $pdf->SetFillColor(68, 114, 196);
        $pdf->SetTextColor(255);
        $pdf->SetFont('helvetica', 'B', 9);

        // Imprimir encabezados
        foreach ($encabezados as $i => $encabezado) {
            $pdf->Cell($anchos[$i], 7, $encabezado, 1, 0, 'C', true);
        }
        $pdf->Ln();

        // Estilo de datos
        $pdf->SetFillColor(255);
        $pdf->SetTextColor(0);
        $pdf->SetFont('helvetica', '', 8);

        // Imprimir datos
        foreach ($datos['registros'] as $registro) {
            $alturaFila = 6;
            $x = $pdf->GetX();
            $y = $pdf->GetY();
            
            foreach ($registro as $i => $valor) {
                // Formatear valor según tipo
                if (is_numeric($valor) && strpos($encabezados[$i], 'monto') !== false) {
                    $valor = formatearMoneda($valor);
                } elseif (strpos($encabezados[$i], 'fecha') !== false) {
                    $valor = formatearFecha($valor);
                }

                $pdf->MultiCell($anchos[$i], $alturaFila, $valor, 1, 'L');
                $pdf->SetXY($x + $anchos[$i], $y);
                $x = $pdf->GetX();
            }
            $pdf->Ln($alturaFila);

            // Verificar si necesitamos nueva página
            if ($pdf->GetY() > 250) {
                $pdf->AddPage();
                
                // Reimprimir encabezados
                $pdf->SetFillColor(68, 114, 196);
                $pdf->SetTextColor(255);
                $pdf->SetFont('helvetica', 'B', 9);
                
                foreach ($encabezados as $i => $encabezado) {
                    $pdf->Cell($anchos[$i], 7, $encabezado, 1, 0, 'C', true);
                }
                $pdf->Ln();
                
                $pdf->SetFillColor(255);
                $pdf->SetTextColor(0);
                $pdf->SetFont('helvetica', '', 8);
            }
        }
    } catch (Exception $e) {
        error_log("Error en agregarTablaDatosPDF: " . $e->getMessage());
    }
}

function agregarPiePaginaPDF($pdf, $datos) {
    try {
        $pdf->Ln(10);
        $pdf->SetFont('helvetica', 'B', 10);

        // Agregar totales si existen
        if (isset($datos['totalMontos']) && $datos['totalMontos'] > 0) {
            $pdf->Cell(0, 10, 'Total General: ' . formatearMoneda($datos['totalMontos']), 0, 1, 'R');
        }

        // Agregar número de página
        $pdf->SetY(-15);
        $pdf->SetFont('helvetica', 'I', 8);
        $pdf->Cell(0, 10, 'Página ' . $pdf->PageNo() . ' de {nb}', 0, 0, 'C');
    } catch (Exception $e) {
        error_log("Error en agregarPiePaginaPDF: " . $e->getMessage());
    }
}

function calcularAnchosColumnasPDF($encabezados) {
    $totalColumnas = count($encabezados);
    $anchoDisponible = 190; // Ancho total disponible en mm
    $anchos = [];

    // Definir anchos específicos según el tipo de columna
    foreach ($encabezados as $encabezado) {
        if (strpos(strtolower($encabezado), 'fecha') !== false) {
            $anchos[] = 25;
            $anchoDisponible -= 25;
        } elseif (strpos(strtolower($encabezado), 'monto') !== false) {
            $anchos[] = 30;
            $anchoDisponible -= 30;
        } elseif (strpos(strtolower($encabezado), 'numero') !== false) {
            $anchos[] = 20;
            $anchoDisponible -= 20;
        } else {
            $anchos[] = 0; // Se calculará después
        }
    }

    // Distribuir el ancho restante entre las columnas sin ancho específico
    $columnasRestantes = count(array_filter($anchos, function($ancho) { return $ancho === 0; }));
    if ($columnasRestantes > 0) {
        $anchoRestante = $anchoDisponible / $columnasRestantes;
        $anchos = array_map(function($ancho) use ($anchoRestante) {
            return $ancho === 0 ? $anchoRestante : $ancho;
        }, $anchos);
    }

    return $anchos;
}

/**
 * Obtiene los encabezados según el tipo de reporte
 */
function obtenerEncabezadosReporte($tipo, $tipoReporte) {
    $encabezados = [
        'General' => [
            'clientes_contratos' => [
                'No. Contrato', 
                'Nombre', 
                'Apellidos', 
                'Plan', 
                'Fecha Inicio', 
                'Monto Total', 
                'Día Cobro', 
                'Estado'
            ],
            'contratos_dependientes' => [
                'No. Contrato',
                'Nombre Titular',
                'Apellidos Titular',
                'Nombre Dependiente',
                'Apellidos Dependiente',
                'Relación',
                'Plan'
            ],
            'contratos_estado' => [
                'Estado',
                'Total Contratos',
                'Monto Total'
            ],
            'contratos_vencidos' => [
                'No. Contrato',
                'Nombre',
                'Apellidos',
                'Plan',
                'Fecha Inicio',
                'Fecha Fin',
                'Días Vencido',
                'Monto Total'
            ],
            'clientes_estado' => [
                'Estado',
                'Total Clientes',
                'Total Contratos',
                'Monto Total',
                'Total Dependientes'
            ]
        ],
        'Facturacion' => [
            'facturas_contratos' => [
                'No. Factura',
                'No. Contrato',
                'Nombre',
                'Apellidos',
                'Monto',
                'Fecha Emisión',
                'Fecha Vencimiento',
                'Estado',
                'Plan'
            ],
            'facturas_vencidas' => [
                'No. Factura',
                'No. Contrato',
                'Nombre',
                'Apellidos',
                'Monto',
                'Fecha Vencimiento',
                'Días Vencido',
                'Plan'
            ],
            'pagos_recibidos' => [
                'No. Factura',
                'No. Contrato',
                'Nombre',
                'Apellidos',
                'Fecha Pago',
                'Monto',
                'Método Pago',
                'Referencia',
                'Cobrador'
            ],
            'ingresos_plan' => [
                'Plan',
                'Total Contratos',
                'Total Facturas',
                'Monto Total',
                'Promedio Factura'
            ]
        ],
        'Personal' => [
            'ventas_vendedor' => [
                'Vendedor',
                'Total Contratos',
                'Total Clientes',
                'Monto Total',
                'Plan',
                'Total Dependientes',
                'Promedio Contrato'
            ],
            'cobros_cobrador' => [
                'Cobrador',
                'Total Pagos',
                'Monto Total',
                'Método Pago',
                'Total Contratos',
                'Promedio Días Cobro',
                'Porcentaje a Tiempo'
            ]
        ],
        'Planes' => [
            'contratos_plan' => [
                'Plan',
                'Total Contratos',
                'Total Clientes',
                'Total Dependientes',
                'Monto Total',
                'Promedio Mensual',
                'Contratos Activos',
                'Contratos Cancelados'
            ],
            'planes_populares' => [
                'Plan',
                'Total Contratos',
                'Monto Total',
                'Total Dependientes',
                'Período',
                'Clientes Únicos',
                'Promedio Mensual',
                'Ingreso Promedio'
            ]
        ]
    ];

    return $encabezados[$tipo][$tipoReporte] ?? [];
}

/**
 * Obtiene el título según el tipo de reporte
 */
function obtenerTituloReporte($tipo, $tipoReporte) {
    $titulos = [
        'General' => [
            'clientes_contratos' => 'Reporte de Clientes y Contratos',
            'contratos_dependientes' => 'Reporte de Contratos y Dependientes',
            'contratos_estado' => 'Reporte de Contratos por Estado'
        ],
        'Facturacion' => [
            'facturas_contratos' => 'Reporte de Facturas por Contrato',
            'facturas_vencidas' => 'Reporte de Facturas Vencidas',
            'pagos_recibidos' => 'Reporte de Pagos Recibidos'
        ],
        'Personal' => [
            'ventas_vendedor' => 'Reporte de Ventas por Vendedor',
            'cobros_cobrador' => 'Reporte de Cobros por Cobrador'
        ],
        'Planes' => [
            'contratos_plan' => 'Reporte de Contratos por Plan',
            'planes_populares' => 'Reporte de Planes más Contratados'
        ]
    ];

    return $titulos[$tipo][$tipoReporte] ?? 'Reporte General';
}