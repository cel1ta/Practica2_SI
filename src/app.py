from flask import Flask, render_template, request
import sqlite3
import requests

app = Flask(__name__)

def get_db_connection():
    conn = sqlite3.connect('../dataBase.db')
    conn.row_factory = sqlite3.Row
    return conn

def get_malware(page=1, page_size=2):
    # Se consulta a la API de Malware Bazaar los ultimos 5 malwares detectados
    data = {
        'query': 'get_recent',
        'selector': 'time'
    }
    try:
        response = requests.post('https://mb-api.abuse.ch/api/v1/', data=data)
        response.raise_for_status()
        return [{
            'sha256': sample['sha256_hash'],
            'file_type': sample['file_type'],
            'signature': sample['signature'],
            'tags': sample['tags'],
            'first_seen': sample['first_seen'],
            'file_name': sample['file_name']
        } for sample in response.json()['data'][:5]]
    except requests.RequestException as e:
        print(f"Error al consultar CSIRT API: {e}")
        return []

def get_latest_cves():
    try:
        # Solicitud a la API de cve.circl.lu
        response = requests.get('https://cve.circl.lu/api/last', timeout=5)
        response.raise_for_status()  # lanza excepción si la solicitud falla
        cves = response.json()

        vulnerabilities = []
        for cve in cves[:10]:  # ultimas 10 vulnerabilidades
            # Extraer campos anidados
            cve_id = cve.get('cveMetadata', {}).get('cveId', 'N/A')

            # Descripción
            description = 'Sin descripción'
            descriptions = cve.get('containers', {}).get('cna', {}).get('descriptions', [])
            if descriptions and isinstance(descriptions, list) and len(descriptions) > 0:
                description = descriptions[0].get('value', 'Sin descripción')

            # Fecha de publicacion y actualizacion
            published_date = cve.get('cveMetadata', {}).get('datePublished', 'N/A')
            updated_date = cve.get('cveMetadata', {}).get('dateUpdated', 'N/A')

            # Puntaje CVE
            cve_score = 'N/A'
            metrics = cve.get('containers', {}).get('cna', {}).get('metrics', [])
            if metrics and isinstance(metrics, list) and len(metrics) > 0:
                cvss_v3_1 = metrics[0].get('cvssV3_1', {})
                cve_score = cvss_v3_1.get('baseScore', 'N/A')
            else:
                # Si no está en cna, buscar en containers.adp
                adp_list = cve.get('containers', {}).get('adp', [])
                for adp in adp_list:
                    metrics = adp.get('metrics', [])
                    if metrics and isinstance(metrics, list) and len(metrics) > 0:
                        cvss_v3_1 = metrics[0].get('cvssV3_1', {})
                        cve_score = cvss_v3_1.get('baseScore', 'N/A')
                        break  # Salir del bucle una vez que se encuentra la puntuac

            vulnerabilities.append({
                'cve_id': cve_id,
                'description': description,
                'published_date': published_date,
                'updated_date': updated_date,
                'cve_score': cve_score
            })

        return vulnerabilities
    except requests.RequestException as e:
        print(f"Error al consultar la API: {e}")
        return []  #  lista vacía en caso de error

@app.route('/', methods=['GET', 'POST'])
def index():
    # Obtener valores del form
    top_x = int(request.form.get('top_x', 5))  # Default: 5
    show_employees = 'show_employees' in request.form

    conn = get_db_connection()

    # Consulta : el top X de clientes con más incidencias reportadas
    top_clients = conn.execute('''
        SELECT cliente, COUNT(*) as incident_count
        FROM Tickets
        GROUP BY cliente
        ORDER BY incident_count DESC
        LIMIT ?
    ''', (top_x,)).fetchall()

    # Consulta : el top X de tipos de incidencias que han requerido el mayor tiempo de resolución
    top_incident_types = conn.execute('''
        SELECT tipo_incidencia, 
               AVG(julianday(fecha_cierre) - julianday(fecha_apertura)) as avg_resolution_days
        FROM Tickets
        GROUP BY tipo_incidencia
        ORDER BY avg_resolution_days DESC
        LIMIT ?
    ''', (top_x,)).fetchall()

    # Consulta : el top X de empleados que mas timpo han emprleado en la resolucion de incidentes (si se desea)
    top_employees = []
    if show_employees:
        top_employees = conn.execute('''
            SELECT id_emp, SUM(tiempo) as total_time
            FROM Contactos_con_Empleados
            GROUP BY id_emp
            ORDER BY total_time DESC
            LIMIT ?
        ''', (top_x,)).fetchall()

    conn.close()

    #  ultimas 10 vulnerabilidades
    latest_cves = get_latest_cves()

    # Ultimas dos noticias de ciberseguridad
    latest_malware = get_malware()

    return render_template('index.html',
                           top_clients=top_clients,
                           top_incident_types=top_incident_types,
                           top_employees=top_employees,
                           latest_cves=latest_cves,
                           latest_malware= latest_malware,
                           top_x=top_x,
                           show_employees=show_employees)

if __name__ == '__main__':
    csirt_news = get_csirt_news()
    app.run(debug=True)
