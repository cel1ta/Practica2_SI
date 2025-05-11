import json
import sqlite3
import os

def crear_tablas(con):
    cursor = con.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Tickets (
            ticket_id INTEGER PRIMARY KEY AUTOINCREMENT,
            cliente TEXT,
            fecha_apertura DATE,
            fecha_cierre DATE,
            es_mantenimiento BOOLEAN,
            satisfaccion_cliente INTEGER,
            tipo_incidencia INTEGER,
            es_critico BOOLEAN
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Contactos_con_Empleados (
            contact_id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER,
            id_emp TEXT,
            fecha DATE,
            tiempo REAL,
            FOREIGN KEY (ticket_id) REFERENCES Tickets(ticket_id)
        )
    """)
    con.commit()

def insertar_datos(con):
    cursor = con.cursor()
    file = open('data_clasified.json', 'r')
    datos = json.load(file)

    tickets = datos['tickets_emitidos']

    for ticket in tickets:
        cursor.execute("""
            INSERT INTO Tickets (
                cliente, fecha_apertura, fecha_cierre,
                es_mantenimiento, satisfaccion_cliente,
                tipo_incidencia, es_critico
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            ticket['cliente'],
            ticket['fecha_apertura'],
            ticket['fecha_cierre'],
            ticket['es_mantenimiento'],
            ticket['satisfaccion_cliente'],
            ticket['tipo_incidencia'],
            ticket['es_critico']
        ))

        ticket_id = cursor.lastrowid  #devuelve el ticket_id generado automaticamete porr AUTOINCREMENT

        for contacto in ticket['contactos_con_empleados']:
            cursor.execute("""
                INSERT INTO Contactos_con_Empleados (
                    ticket_id, id_emp, fecha, tiempo
                ) VALUES (?, ?, ?, ?)
            """, (
                ticket_id,
                contacto['id_emp'],
                contacto['fecha'],
                contacto['tiempo']
            ))

    con.commit()

# Ejecutar
con = sqlite3.connect('dataBase.db')
crear_tablas(con)
insertar_datos(con)
con.close()