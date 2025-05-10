import os
from sklearn.linear_model import LinearRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from io import BytesIO
import base64
from datetime import datetime
import sqlite3
from sklearn.tree import DecisionTreeClassifier, export_graphviz
import graphviz

def get_db_connection():
    conn = sqlite3.connect('../dataBase.db')
    conn.row_factory = sqlite3.Row
    return conn

def obtener_datos_entrenamiento():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT fecha_apertura, fecha_cierre, es_mantenimiento,
                   satisfaccion_cliente, tipo_incidencia, es_critico
            FROM Tickets
        ''')

        datos = cursor.fetchall()
        conn.close()

        data = []
        for registro in datos:
            # Calcular días de resolución
            fecha_apertura = datetime.fromisoformat(registro['fecha_apertura'])
            fecha_cierre = datetime.fromisoformat(registro['fecha_cierre']) if registro['fecha_cierre'] else None

            dias_resolucion = (fecha_cierre - fecha_apertura).days if fecha_cierre else 30

            data.append({
                'dias_resolucion': dias_resolucion,
                'es_mantenimiento': int(registro['es_mantenimiento']),
                'satisfaccion_cliente': registro['satisfaccion_cliente'],
                'tipo_incidencia': registro['tipo_incidencia'],
                'es_critico': int(registro['es_critico'])  # Variable objetivo
            })

        return pd.DataFrame(data)

    except Exception as e:
        print(f"Error obteniendo datos: {e}")
        return pd.DataFrame()

def entrenar_modelo_regresion(df):
    try:
        if df.empty:
            raise ValueError("No hay datos para entrenamiento")

        preprocesador = ColumnTransformer(
            transformers=[
                ('num', StandardScaler(), ['dias_resolucion', 'satisfaccion_cliente']),
                ('cat', OneHotEncoder(), ['tipo_incidencia', 'es_mantenimiento'])
            ])

        modelo = Pipeline(steps=[
            ('preprocesador', preprocesador),
            ('regresor', LinearRegression())
        ])

        X = df.drop('es_critico', axis=1)
        y = df['es_critico']

        modelo.fit(X, y)
        return modelo

    except Exception as e:
        print(f"Error entrenando modelo: {e}")
        return None

def generar_grafico_regresion(modelo, df, nuevo_punto, prediccion):
    try:
        plt.figure(figsize=(10, 6))
        plt.clf()

        # Configurar ejes
        x_values = df['satisfaccion_cliente']
        y_values = df['es_critico']

        # Datos reales
        plt.scatter(x_values, y_values, alpha=0.5, label='Datos Históricos')

        # Línea de regresión
        x_range = np.linspace(df['satisfaccion_cliente'].min(),
                              df['satisfaccion_cliente'].max(), 100)
        datos_sinteticos = pd.DataFrame({
            'dias_resolucion': df['dias_resolucion'].mean(),
            'satisfaccion_cliente': x_range,
            'tipo_incidencia': df['tipo_incidencia'].mode()[0],
            'es_mantenimiento': df['es_mantenimiento'].mode()[0]
        })

        predicciones = modelo.predict(datos_sinteticos)
        plt.plot(x_range, predicciones, color='red', label='Tendencia Regresión')

        # Nuevo punto
        plt.scatter([nuevo_punto['satisfaccion_cliente']], [prediccion],
                    color='green', s=100, marker='X', label='Nuevo Ticket')

        plt.xlabel('Satisfacción del Cliente (1-10)')
        plt.ylabel('Probabilidad de ser Crítico')
        plt.title('Análisis de Tickets Críticos')
        plt.legend()
        plt.grid(True)

        # Convertir a imagen base64
        buf = BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight')
        buf.seek(0)
        return base64.b64encode(buf.getvalue()).decode('utf-8')

    except Exception as e:
        print(f"Error generando gráfico: {e}")
        return None

# Nueva función para el árbol de decisión
def entrenar_modelo_arbol_decision(df):
    try:
        if df.empty:
            raise ValueError("No hay datos para entrenamiento")

        preprocesador = ColumnTransformer(
            transformers=[
                ('num', StandardScaler(), ['dias_resolucion', 'satisfaccion_cliente']),
                ('cat', OneHotEncoder(), ['tipo_incidencia', 'es_mantenimiento'])
            ])

        modelo = Pipeline(steps=[
            ('preprocesador', preprocesador),
            ('clasificador', DecisionTreeClassifier(max_depth=3, random_state=42))
        ])

        X = df.drop('es_critico', axis=1)
        y = df['es_critico']

        modelo.fit(X, y)
        return modelo

    except Exception as e:
        print(f"Error entrenando árbol de decisión: {e}")
        return None

# Función para visualizar el árbol
def visualizar_arbol_decision(modelo, nombre_archivo='arbol_decision'):
    try:
        # Configurar ruta de Graphviz (solo Windows)
        if os.name == 'nt':
            os.environ["PATH"] += os.pathsep + 'C:/Program Files/Graphviz/bin/'

        arbol = modelo.named_steps['clasificador']

        dot_data = export_graphviz(
            arbol,
            feature_names=modelo.named_steps['preprocesador'].get_feature_names_out(),
            class_names=['No Crítico', 'Crítico'],
            filled=True,
            rounded=True,
            special_characters=True
        )

        graph = graphviz.Source(dot_data)
        img_path = f'static/{nombre_archivo}'
        graph.render(img_path, format='png', cleanup=True)

        return f'{img_path}.png'

    except Exception as e:
        print(f"Error generando árbol: {e}")
        return None


def entrenar_modelo_random_forest(df):
    try:
        if df.empty:
            raise ValueError("No hay datos para entrenamiento")

        preprocesador = ColumnTransformer(
            transformers=[
                ('num', StandardScaler(), ['dias_resolucion', 'satisfaccion_cliente']),
                ('cat', OneHotEncoder(), ['tipo_incidencia', 'es_mantenimiento'])
            ])

        modelo = Pipeline(steps=[
            ('preprocesador', preprocesador),
            ('clasificador', RandomForestClassifier(n_estimators=100, random_state=42))
        ])

        X = df.drop('es_critico', axis=1)
        y = df['es_critico']

        modelo.fit(X, y)
        return modelo

    except Exception as e:
        print(f"Error entrenando Random Forest: {e}")
        return None



def generar_grafico_random_forest(modelo):
    try:
        importances = modelo.named_steps['clasificador'].feature_importances_
        feature_names = modelo.named_steps['preprocesador'].get_feature_names_out()

        # Sort feature importances in descending order
        indices = np.argsort(importances)[::-1]
        sorted_feature_names = [feature_names[i] for i in indices]
        sorted_importances = importances[indices]

        plt.figure(figsize=(10, 6))
        plt.barh(range(len(sorted_importances)), sorted_importances, align='center')
        plt.yticks(range(len(sorted_importances)), sorted_feature_names)
        plt.xlabel('Importancia')
        plt.title('Importancia de Características - Random Forest')
        plt.tight_layout()

        buf = BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight')
        buf.seek(0)
        return base64.b64encode(buf.getvalue()).decode('utf-8')

    except Exception as e:
        print(f"Error generando gráfico de Random Forest: {e}")
        return None
