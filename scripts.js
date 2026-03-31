// Al inicio del archivo
document.addEventListener('DOMContentLoaded', function() {
    // Estas funciones se llamarán desde cada página según las necesite
    if (document.getElementById('monthlyIncomeChart')) {
        initializeMonthlyIncomeChart();
    }
    if (document.getElementById('plansDistributionChart')) {
        initializePlansDistributionChart();
    }
    if (document.getElementById('ageDistributionChart')) {
        initializeAgeDistributionChart();
    }
    
    // Add any event listeners or interactive elements
    setupInteractions();
});

// Función para verificar si la variable existe antes de usarla
function safeGetData(variable, defaultValue = []) {
    return typeof window[variable] !== 'undefined' ? window[variable] : defaultValue;
}

// Corregir la función initializeMonthlyIncomeChart
function initializeMonthlyIncomeChart(year = '2023') {
    const ctx = document.getElementById('monthlyIncomeChart');
    if (!ctx) return;
    
    // Usar datos seguros
    const data = safeGetData('ingresosMensualesData', {
        procesados: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        anulados: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    });
    
    // Check if the chart already exists and destroy it
    if (window.monthlyIncomeChart instanceof Chart) {
        window.monthlyIncomeChart.destroy();
    }
    
    // Create new chart instance
    window.monthlyIncomeChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['Ene', 'Feb', 'Mar', 'Abr', 'May', 'Jun', 'Jul', 'Ago', 'Sep', 'Oct', 'Nov', 'Dic'],
            datasets: [
                {
                    label: 'Pagos Proyectados',
                    data: data.procesados,
                    borderColor: '#34a853',
                    backgroundColor: 'rgba(52, 168, 83, 0.1)',
                    borderWidth: 2,
                    tension: 0.3,
                    fill: true
                },
                {
                    label: 'Pagos Recibidos',
                    data: data.anulados,
                    borderColor: '#ea4335',
                    backgroundColor: 'rgba(234, 67, 53, 0.1)',
                    borderWidth: 2,
                    tension: 0.3,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    callbacks: {
                        label: function(context) {
                            let label = context.dataset.label || '';
                            if (label) {
                                label += ': ';
                            }
                            if (context.parsed.y !== null) {
                                label += new Intl.NumberFormat('es-DO', {
                                    style: 'currency',
                                    currency: 'USD'
                                }).format(context.parsed.y);
                            }
                            return label;
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: {
                        display: false
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(0, 0, 0, 0.05)'
                    },
                    ticks: {
                        callback: function(value) {
                            return '$' + value.toLocaleString();
                        }
                    }
                }
            }
        }
    });
}

// Corregir la función initializePlansDistributionChart
function initializePlansDistributionChart() {
    const ctx = document.getElementById('plansDistributionChart');
    if (!ctx) return;
    
    // Usar datos seguros
    const labels = safeGetData('planesLabels', ['Plan A', 'Plan B', 'Plan C']);
    const data = safeGetData('planesData', [70, 20, 10]);
    
    // Create chart
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: [
                    '#1a73e8',  // Blue
                    '#34a853',  // Green
                    '#fbbc05'   // Yellow
                ],
                borderColor: '#fff',
                borderWidth: 2,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '70%',
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return context.label;
                        }
                    }
                }
            }
        }
    });
}

// Corregir la función initializeAgeDistributionChart
function initializeAgeDistributionChart() {
    const ctx = document.getElementById('ageDistributionChart');
    if (!ctx) return;
    
    // Usar datos seguros
    const labels = safeGetData('edadesLabels', ['18-24 años', '25-34 años', '35-49 años']);
    const data = safeGetData('edadesData', [20, 40, 40]);
    
    // Create chart
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: [
                    '#1a73e8',  // Blue
                    '#34a853',  // Green
                    '#fbbc05'   // Yellow
                ],
                borderColor: '#fff',
                borderWidth: 2,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '70%',
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return context.label;
                        }
                    }
                }
            }
        }
    });
}