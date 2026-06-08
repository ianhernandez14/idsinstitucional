import os
from flask import Flask, render_template_string, request

app = Flask(__name__)
ruta_actual = os.path.dirname(os.path.abspath(__file__))

#1
def obtener_fechas():
    carpetas = []
    for nombre in os.listdir(ruta_actual):
        ruta_elemento = os.path.join(ruta_actual, nombre)
        if(os.path.isdir(ruta_elemento) and len(nombre) == 10 and nombre.count("-") == 2):
            carpetas.append(nombre)
    carpetas.sort(reverse=True)
    return carpetas

plantilla_html = """
<!DOCTYPE html>
<html lang="es" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <title>Dashboard IDS SOC</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { background-color: #121212; color: #e0e0e0; font-family: Arial, sans-serif; }
        .card { background-color: #1e1e1e; border: none; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        .card-title { color: #a0a0a0; font-weight: bold; }
        .table-dark th { background-color: #2c2c2c; border-color: #444; color: #4af626; }
        .table td { border-color: #444; vertical-align: middle; }
    </style>
    <meta http-equiv="refresh" content="10">
</head>
<body>
    <div class="container mt-4">
        <h2 class="mb-4 text-center text-info fw-bold">Centro de Operaciones de Seguridad (SOC)</h2>
        
        <div class="row mb-3">
            <div class="col-md-4">
                <form method="GET">
                    <div class="input-group">
                        <span class="input-group-text bg-dark text-white border-secondary">Fecha:</span>
                        <select name="fecha" class="form-select bg-dark text-white border-secondary" onchange="this.form.submit()">
                            {% if not fechas %}
                            <option value="">Sin registros</option>
                            {% endif %}
                            {% for f in fechas %}
                            <option value="{{ f }}" {% if f == fecha_actual %}selected{% endif %}>{{ f }}</option>
                            {% endfor %}
                        </select>
                    </div>
                </form>
            </div>
        </div>
        
        <div class="row mb-4">
            <div class="col-md-4">
                <div class="card p-3 text-center">
                    <h6 class="card-title">Total de Peticiones DNS</h6>
                    <h3 class="text-primary fw-bold">{{ total_peticiones }}</h3>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card p-3 text-center">
                    <h6 class="card-title">Última IP Activa</h6>
                    <h3 class="text-warning fw-bold">{{ ultima_ip }}</h3>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card p-3 text-center">
                    <h6 class="card-title">Tamaño Evidencia (PCAP)</h6>
                    <h3 class="text-danger fw-bold">{{ tamano_pcap }} KB</h3>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-8">
                <div class="card p-3">
                    <h5 class="mb-3 text-white">Últimos Sitios Visitados</h5>
                    <div class="table-responsive" style="max-height: 400px; overflow-y: auto;">
                        <table class="table table-dark table-striped table-sm mb-0">
                            <thead>
                                <tr>
                                    <th>Fecha y Hora</th>
                                    <th>IP Origen</th>
                                    <th>Sitio Destino</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for fila in registros %}
                                <tr>
                                    <td>{{ fila.fecha }}</td>
                                    <td><span class="badge bg-secondary">{{ fila.ip }}</span></td>
                                    <td>{{ fila.sitio }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card p-3">
                    <h5 class="mb-3 text-center text-white">Top IPs Activas</h5>
                    <canvas id="graficaIps"></canvas>
                </div>
            </div>
        </div>
    </div>

    <script>
        const ctx = document.getElementById('graficaIps').getContext('2d');
        new Chart(ctx, 
        {
            type: 'doughnut',
            data: 
            {
                labels: {{ etiquetas_grafica | safe }},
                datasets: [
                {
                    data: {{ datos_grafica | safe }},
                    backgroundColor: ['#0d6efd', '#ffc107', '#dc3545', '#198754', '#0dcaf0'],
                    borderWidth: 0
                }]
            },
            options: 
            {
                responsive: true,
                plugins: 
                {
                    legend: 
                    { 
                        position: 'bottom', 
                        labels: 
                        { 
                            color: '#e0e0e0' 
                        } 
                    }
                }
            }
        });
    </script>
</body>
</html>
"""

@app.route("/")
def renderizar_inicio():
    fechas_disponibles = obtener_fechas()
    fecha_seleccionada = request.args.get("fecha")
    
    if(not fecha_seleccionada and fechas_disponibles):
        fecha_seleccionada = fechas_disponibles[0]

    total_peticiones = 0
    ultima_ip = "Ninguna"
    tamano_pcap = 0
    registros_procesados = []
    
    conteo_ips = {}
    
    etiquetas_grafica = []
    datos_grafica = []

    if(fecha_seleccionada):
        ruta_carpeta = os.path.join(ruta_actual, fecha_seleccionada)
        ruta_reporte = os.path.join(ruta_carpeta, "reporte_sitios.txt")
        ruta_pcap = os.path.join(ruta_carpeta, "evidencia_ataques.pcap")

        #2
        if(os.path.exists(ruta_pcap)):
            tamano_pcap = round(os.path.getsize(ruta_pcap) / 1024, 2)

        #3
        if(os.path.exists(ruta_reporte)):
            with open(ruta_reporte, "r") as archivo:
                lineas = archivo.readlines()
                total_peticiones = len(lineas)
                
                for linea in reversed(lineas[-50:]):
                    try:
                        partes = linea.split("] ")
                        if(len(partes) == 2):
                            fecha = partes[0].replace("[", "")
                            resto = partes[1]
                            ip_extraida = resto.split("IP: ")[1].split(" visito")[0]
                            sitio_extraido = resto.split("sitio: ")[1].strip()
                            
                            registros_procesados.append(
                            {
                                "fecha": fecha, "ip": ip_extraida, "sitio": sitio_extraido
                            })
                    except Exception:
                        pass
                
                for linea in lineas:
                    try:
                        ip = linea.split("IP: ")[1].split(" visito")[0]
                        if(ip in conteo_ips):
                            conteo_ips[ip] += 1
                        else:
                            conteo_ips[ip] = 1
                    except Exception:
                        pass
                        
                if(registros_procesados):
                    ultima_ip = registros_procesados[0]["ip"]

        ips_ordenadas = sorted(conteo_ips.items(), key=lambda x: x[1], reverse=True)[:5]
        etiquetas_grafica = [item[0] for item in ips_ordenadas]
        datos_grafica = [item[1] for item in ips_ordenadas]

    return render_template_string(
        plantilla_html, 
        fechas=fechas_disponibles,
        fecha_actual=fecha_seleccionada,
        total_peticiones=total_peticiones,
        ultima_ip=ultima_ip,
        tamano_pcap=tamano_pcap,
        registros=registros_procesados,
        etiquetas_grafica=etiquetas_grafica,
        datos_grafica=datos_grafica
    )

if(__name__ == "__main__"):
    app.run(host="127.0.0.1", port=5000)
