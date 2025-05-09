import requests
from flask import Flask, render_template, request, make_response, send_file
import sqlite3
from requests import get, RequestException
from fpdf import FPDF
import io
from ejer5 import entrenar_modelo_regresion, obtener_datos_entrenamiento, entrenar_modelo_arbol_decision, visualizar_arbol_decision, generar_grafico_regresion
from datetime import datetime
import pandas as pd

app = Flask(__name__)

class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(80)
        self.cell(30, 10, 'Informe del Cuadro de Mando Integral', 0, 0, 'C')
        self.ln(20)

    # Page footer
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, 'Page ' + str(self.page_no()), 0, 0, 'C')

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
        response = get('https://cve.circl.lu/api/last', timeout=5)
        response.raise_for_status()
        cves = response.json()

        vulnerabilities = []
        count = 0
        index = 0

        while count < 10 and index < len(cves):
            cve = cves[index]
            index += 1

            # Validar que sea un registro CVE válido
            if cve.get('dataType') != 'CVE_RECORD' or 'cveMetadata' not in cve:
                continue

            cve_id = cve.get('cveMetadata', {}).get('cveId', 'N/A')
            description = 'Sin descripción'
            descriptions = cve.get('containers', {}).get('cna', {}).get('descriptions', [])

            if isinstance(descriptions, list) and descriptions:
                description = descriptions[0].get('value', 'Sin descripción')

            published_date = cve.get('cveMetadata', {}).get('datePublished', 'N/A')
            updated_date = cve.get('cveMetadata', {}).get('dateUpdated', 'N/A')

            vulnerabilities.append({
                'cve_id': cve_id,
                'description': description,
                'published_date': published_date,
                'updated_date': updated_date,
            })

            count += 1

        return vulnerabilities

    except Exception as e:
        print(f"Error al obtener los CVEs: {e}")
        return []


        return vulnerabilities
    except RequestException as e:
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

    file_type_count = {}
    for m in latest_malware:
        ft = m.get('file_type','Unknown')
        file_type_count[ft] = file_type_count.get(ft,0) + 1

    if 'generate_pdf' in request.form:
        # Crear PDF
        # Instantiation of inherited class
        pdf = PDF()
        pdf.add_page()
        pdf.set_font('Arial', '', 12)

        # Sección Clientes
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, f'Top {top_x} Clientes', 0, 1)
        pdf.set_font('Arial', '', 12)
        for client in top_clients:
            pdf.cell(0, 8, f"-ID cliente: {client['cliente']}: {client['incident_count']} incidencias", 0, 1)
        pdf.ln(5)

        # Sección Tipos de Incidencia
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, f'Top {top_x} Tipos de Incidencia', 0, 1)
        pdf.set_font('Arial', '', 12)
        for incident in top_incident_types:
            pdf.cell(0, 8, f"- ID de incidente:{incident['tipo_incidencia']}: {incident['avg_resolution_days']:.2f} días promedio", 0, 1)
        pdf.ln(5)

        # Sección Empleados (si está activada)
        if show_employees and top_employees:
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, f'Top {top_x} Empleados', 0, 1)
            pdf.set_font('Arial', '', 12)
            for emp in top_employees:
                pdf.cell(0, 8, f"- Empleado {emp['id_emp']}: {emp['total_time']} horas totales", 0, 1)
            pdf.ln(5)

        # Sección Vulnerabilidades
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, 'Últimas Vulnerabilidades', 0, 1)
        pdf.set_font('Arial', '', 10)
        for cve in latest_cves:
            text = f"- {cve['cve_id']} ({cve['published_date']}) - Score: {cve['cve_score']}\nDescription: {cve['description']}"
            sanitized_text = text.encode('latin-1', 'replace').decode('latin-1')
            pdf.multi_cell(0, 6, sanitized_text)
            pdf.ln(3)


        if latest_malware:  # Solo si hay datos
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, 'Últimas Amenazas de Malware', 0, 1)
            pdf.set_font('Arial', '', 10)

            for malware in latest_malware:
                # Formatear los datos
                texto = (
                    f"SHA256: {malware['sha256']}\n"
                    f"Nombre: {malware['file_name']}\n"
                    f"Tipo: {malware['file_type']} | "
                    f"Primera detección: {malware['first_seen']}\n"
                    f"Firma: {malware['signature']}\n"
                    f"Etiquetas: {malware['tags']}"
                )

                # Sanitizar texto si es necesario
                texto_safe = texto.encode('latin-1', 'replace').decode('latin-1')

                pdf.multi_cell(0, 6, texto_safe)
                pdf.ln(3)  # Espacio entre muestras

        pdf_bytes = pdf.output(dest='S').encode('latin-1')
        buf = io.BytesIO(pdf_bytes)
        buf.seek(0)

        return send_file(
            buf,
            as_attachment=True,
            download_name='reporte.pdf',
            mimetype='application/pdf'
        )

    return render_template('index.html',
                           top_clients=top_clients,
                           top_incident_types=top_incident_types,
                           top_employees=top_employees,
                           latest_cves=latest_cves,
                           latest_malware= latest_malware,
                           file_type_count=file_type_count,
                           top_x=top_x,
                           show_employees=show_employees)
@app.route('/prediccion_criticidad', methods=['GET', 'POST'])
def analizar_ticket():
    if request.method == 'POST':
        try:
            # Procesar datos del formulario
            datos_form = {
                'cliente': int(request.form['cliente']),
                'fecha_apertura': datetime.fromisoformat(request.form['fecha_apertura']),
                'fecha_cierre': datetime.fromisoformat(request.form['fecha_cierre']),
                'es_mantenimiento': request.form['es_mantenimiento'] == 'true',
                'satisfaccion_cliente': int(request.form['satisfaccion_cliente']),
                'tipo_incidencia': int(request.form['tipo_incidencia'])
            }

            dias_resolucion = (datos_form['fecha_cierre'] - datos_form['fecha_apertura']).days
            nuevo_ticket = pd.DataFrame([{
                'dias_resolucion': dias_resolucion,
                'es_mantenimiento': int(datos_form['es_mantenimiento']),
                'satisfaccion_cliente': datos_form['satisfaccion_cliente'],
                'tipo_incidencia': datos_form['tipo_incidencia']
            }])

            # Obtener y preparar datos
            df = obtener_datos_entrenamiento()
            if df.empty:
                raise ValueError("No hay datos históricos para entrenar el modelo")

            metodo = request.form['metodo']

            # Entrenar modelo 
            if metodo == 'regresion':
                modelo = entrenar_modelo_regresion(df)
                prediccion = modelo.predict(nuevo_ticket)[0]
                es_critico = prediccion > 0.5
                grafico = generar_grafico_regresion(modelo, df, nuevo_ticket.iloc[0], prediccion)
                arbol_img = None

            elif metodo == 'arbol_decision':
                modelo = entrenar_modelo_arbol_decision(df)
                prediccion = modelo.predict(nuevo_ticket)[0]
                es_critico = bool(prediccion)
                grafico = None
                arbol_img = visualizar_arbol_decision(modelo)

            return render_template('resultado.html',
                                   es_critico=es_critico,
                                   probabilidad=f"{prediccion:.2f}",
                                   grafico=grafico,
                                   metodo=metodo,
                                   arbol_img=arbol_img)

        except Exception as e:
            print(f"Error en el proceso: {e}")
            return render_template('error.html', mensaje=str(e))

    try:
        conn = get_db_connection()
        clientes = conn.execute('SELECT DISTINCT cliente FROM Tickets').fetchall()
        conn.close()
        return render_template('formulario.html', clientes=clientes)
    except Exception as e:
        return render_template('error.html', mensaje=f"Error accediendo a la base de datos: {e}")
        
if __name__ == '__main__':

    app.run(debug=True)
