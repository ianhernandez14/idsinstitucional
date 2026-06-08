import os
import smtplib
import threading
import time
import subprocess
import re
import socket
import requests
import tkinter as tk
import webbrowser
import sys
from tkinter import scrolledtext, simpledialog
import customtkinter as ctk
from dotenv import load_dotenv
from scapy.all import sniff, IP, Ether, DNS, DNSQR, TCP, UDP, ARP, Raw, wrpcap

load_dotenv()

correo_remitente = os.getenv("EMAIL_USER")
contrasena_remitente = os.getenv("EMAIL_PASSWORD")
correo_admin = os.getenv("ADMIN_EMAIL")
api_key_vt = os.getenv("VT_API_KEY")

dominios_escaneados = set()
amenazas_reportadas = set()
registros_escaneo = {}

limite_puertos = 20
ventana_tiempo = 5
esta_monitoreando = False
lote_alertas = []
tabla_arp = {}
registro_dos = {}
limite_dos = 100

#4
def obtener_ruta_base():
    if(getattr(sys, 'frozen', False)):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

#5
def enviar_correo(asunto, mensaje):
    if(not correo_remitente or not contrasena_remitente or not correo_admin):
        return
        
    try:
        servidor = smtplib.SMTP("smtp.gmail.com", 587)
        servidor.starttls()
        servidor.login(correo_remitente, contrasena_remitente)
        
        formato_correo = f"Subject: {asunto}\nContent-Type: text/plain; charset=utf-8\n\n{mensaje}"
        servidor.sendmail(correo_remitente, correo_admin, formato_correo.encode("utf-8"))
        servidor.quit()
    except Exception:
        pass

#6
def procesar_lote_alertas():
    global lote_alertas
    while True:
        time.sleep(10)
        if(len(lote_alertas) > 0 and esta_monitoreando):
            fecha_hora = time.strftime("%Y-%m-%d %H:%M:%S")
            cuerpo_lote = "Sistema de Detección de Intrusos (IDS) - Reporte de Monitoreo\n\n"
            cuerpo_lote += f"Fecha y Hora: {fecha_hora}\n\n"
            cuerpo_lote += "Durante los últimos 10 segundos, se han detectado los siguientes dispositivos intentando comunicarse en la red local sin estar registrados en la lista blanca:\n\n"
            cuerpo_lote += "\n".join(lote_alertas)
            cuerpo_lote += "\n\nPor favor, verifique si estos dispositivos pertenecen a personal autorizado.\n"
            cuerpo_lote += "---\nGenerado automáticamente por el IDS Network Monitor."
            
            enviar_correo("⚠️ [IDS REPORTE] Dispositivos No Autorizados", cuerpo_lote)
            lote_alertas.clear()

#7
threading.Thread(target=procesar_lote_alertas, daemon=True).start()

#8
def cargar_lista_blanca():
    lista_blanca = set()
    if(os.path.exists("lista_blanca.txt")):
        with open("lista_blanca.txt", "r") as archivo:
            for linea in archivo:
                linea_limpia = linea.strip().lower()
                if(linea_limpia):
                    lista_blanca.add(linea_limpia)
    return lista_blanca

#9
def cargar_lista_negra():
    lista_negra = {}
    if(os.path.exists("lista_negra.txt")):
        with open("lista_negra.txt", "r") as archivo:
            for linea in archivo:
                linea_limpia = linea.strip()
                if(linea_limpia and not linea_limpia.startswith("#")):
                    partes = linea_limpia.split(",")
                    if(len(partes) == 2):
                        direccion_ip = partes[0].strip()
                        tipo_riesgo = partes[1].strip()
                        lista_negra[direccion_ip] = tipo_riesgo
    return lista_negra

direcciones_lista_blanca = cargar_lista_blanca()
direcciones_lista_negra = cargar_lista_negra()

#10
def obtener_contacto_abuso(direccion_ip):
    try:
        resultado = subprocess.check_output(["whois", direccion_ip], universal_newlines=True)
        correos = re.findall(r"[\w\.-]+@[\w\.-]+", resultado)
        correos_abuso = set()
        for correo in correos:
            if("abuse" in correo.lower()):
                correos_abuso.add(correo)
        if(correos_abuso):
            return ", ".join(correos_abuso)
        return "No encontrado"
    except Exception:
        return "Error en consulta"

#11
def revisar_virustotal(nombre_dominio):
    if(nombre_dominio in dominios_escaneados):
        return
    dominios_escaneados.add(nombre_dominio)
    
    url_api = f"https://www.virustotal.com/api/v3/domains/{nombre_dominio}"
    cabeceras = {
        "x-apikey": api_key_vt
    }
    
    try:
        respuesta = requests.get(url_api, headers=cabeceras)
        
        #12
        if(respuesta.status_code == 429):
            registrar_en_gui("[SISTEMA] Limite de VirusTotal excedido (4 por minuto). Espera 60 segundos.")
            dominios_escaneados.remove(nombre_dominio)
            return
        elif(respuesta.status_code == 401):
            registrar_en_gui("[SISTEMA] Error: Tu API Key de VirusTotal es invalida.")
            return
            
        if(respuesta.status_code == 200):
            datos = respuesta.json()
            atributos = datos["data"]["attributes"]
            conteo_malicioso = atributos["last_analysis_stats"]["malicious"]
            
            registrador = atributos.get("registrar", "Desconocido")
            reputacion = atributos.get("reputation", "0")
            diccionario_categorias = atributos.get("categories", {})
            categorias = ", ".join(list(diccionario_categorias.values())[:2]) if diccionario_categorias else "Sin clasificar"
            
            if(conteo_malicioso > 0):
                mensaje_alerta = f"[ALERTA VIRUSTOTAL] Dominio: {nombre_dominio} | Detecciones: {conteo_malicioso} | Registrador: {registrador} | Tipos: {categorias} | Rep: {reputacion}"
                registrar_en_gui(mensaje_alerta)
                registrar_emergencia(mensaje_alerta)
                
                #13
                fecha_hora = time.strftime("%Y-%m-%d %H:%M:%S")
                cuerpo_vt = "Sistema de Detección de Intrusos (IDS) - Reporte de Inteligencia de Amenazas\n\n"
                cuerpo_vt += "El motor de VirusTotal ha detectado que un dispositivo de la red local intento acceder a un dominio clasificado como malicioso.\n\n"
                cuerpo_vt += "DETALLES DE LA AMENAZA:\n"
                cuerpo_vt += f"- Dominio Solicitado: {nombre_dominio}\n"
                cuerpo_vt += f"- Tasa de Deteccion: {conteo_malicioso} motores lo marcan como peligroso\n"
                cuerpo_vt += f"- Categorias: {categorias}\n"
                cuerpo_vt += f"- Empresa Registradora: {registrador}\n"
                cuerpo_vt += f"- Puntuacion de Reputacion: {reputacion}\n"
                cuerpo_vt += f"- Hora de Consulta: {fecha_hora}\n\n"
                cuerpo_vt += "Se recomienda investigar que dispositivo genero esta peticion DNS.\n"
                cuerpo_vt += "---\nGenerado automaticamente por el IDS Network Monitor."
                
                enviar_correo("🚨 [IDS ALERTA VIRUSTOTAL] Dominio Malicioso Detectado", cuerpo_vt)
    except Exception as e:
        registrar_en_gui(f"[ERROR VIRUSTOTAL] Problema al conectar: {e}")

def registrar_en_gui(texto_mensaje):
    marca_tiempo = time.strftime("[%Y-%m-%d %H:%M:%S] ")
    
    #14
    esta_al_fondo = area_registro.yview()[1] == 1.0
    area_registro.insert(tk.END, marca_tiempo + texto_mensaje + "\n")
    if(esta_al_fondo):
        area_registro.see(tk.END)

#15
def registrar_emergencia(mensaje):
    marca_tiempo = time.strftime("[%Y-%m-%d %H:%M:%S] ")
    esta_al_fondo = area_emergencias.yview()[1] == 1.0
    area_emergencias.insert(tk.END, marca_tiempo + mensaje + "\n")
    if(esta_al_fondo):
        area_emergencias.see(tk.END)

#16
def procesar_paquete(paquete):
    if(not esta_monitoreando):
        return
        
    #17
    if(paquete.haslayer(ARP) and paquete[ARP].op == 2):
        ip_respuesta = paquete[ARP].psrc
        mac_respuesta = paquete[ARP].hwsrc
        if(ip_respuesta != "0.0.0.0"):
            if(ip_respuesta in tabla_arp and tabla_arp[ip_respuesta] != mac_respuesta):
                mensaje_arp = f"[ALERTA CRITICA] Posible ARP Spoofing. IP {ip_respuesta} cambio MAC a {mac_respuesta}"
                registrar_en_gui(mensaje_arp)
                registrar_emergencia(mensaje_arp)
                carpeta = obtener_carpeta_diaria()
                ruta_pcap = os.path.join(carpeta, "evidencia_ataques.pcap")
                wrpcap(ruta_pcap, paquete, append=True)
            else:
                tabla_arp[ip_respuesta] = mac_respuesta

    if(paquete.haslayer(Ether)):
        mac_origen = paquete[Ether].src.lower()
        if(mac_origen not in direcciones_lista_blanca):
            registrar_en_gui(f"[ALERTA MAC] {mac_origen}")
            lote_alertas.append(f"Intruso MAC: {mac_origen}")
            direcciones_lista_blanca.add(mac_origen)

    if(paquete.haslayer(IP)):
        ip_origen = paquete[IP].src
        ip_destino = paquete[IP].dst
        
        #18
        tiempo_actual = time.time()
        if(ip_origen not in registro_dos):
            registro_dos[ip_origen] = {
                "conteo": 0, "tiempo": tiempo_actual
            }
            
        if(tiempo_actual - registro_dos[ip_origen]["tiempo"] > 1.0):
            registro_dos[ip_origen] = {
                "conteo": 0, "tiempo": tiempo_actual
            }
            
        registro_dos[ip_origen]["conteo"] += 1
        
        if(registro_dos[ip_origen]["conteo"] > limite_dos):
            mensaje_dos = f"[ALERTA SEGURIDAD] Posible ataque DoS o Inundacion desde IP: {ip_origen}"
            registrar_en_gui(mensaje_dos)
            carpeta = obtener_carpeta_diaria()
            ruta_pcap = os.path.join(carpeta, "evidencia_ataques.pcap")
            wrpcap(ruta_pcap, paquete, append=True)
            registro_dos[ip_origen]["conteo"] = 0
            
        #19
        if(paquete.haslayer(Raw)):
            try:
                carga_util = paquete[Raw].load.decode("utf-8", errors="ignore").lower()
                if("password=" in carga_util or "select * from" in carga_util):
                    mensaje_payload = f"[ALERTA PAYLOAD] Trafico sensible (Credenciales/SQLi) desde IP: {ip_origen}"
                    registrar_en_gui(mensaje_payload)
                    carpeta = obtener_carpeta_diaria()
                    ruta_pcap = os.path.join(carpeta, "evidencia_ataques.pcap")
                    wrpcap(ruta_pcap, paquete, append=True)
            except Exception:
                pass

        if(ip_origen.startswith("10.") or ip_origen.startswith("192.168.")):
            if(ip_origen not in direcciones_lista_blanca):
                registrar_en_gui(f"[ALERTA IP] {ip_origen}")
                lote_alertas.append(f"Intruso IP: {ip_origen}")
                direcciones_lista_blanca.add(ip_origen)

        if(ip_destino in direcciones_lista_negra):
            if(ip_destino not in amenazas_reportadas):
                tipo_riesgo = direcciones_lista_negra[ip_destino]
                contacto_abuso = obtener_contacto_abuso(ip_destino)
                fecha_hora = time.strftime("%Y-%m-%d %H:%M:%S")
                
                mensaje_emergencia = f"[ALERTA EMERGENCIA] IP: {ip_destino} Riesgo: {tipo_riesgo} Abuse: {contacto_abuso}"
                registrar_en_gui(mensaje_emergencia)
                registrar_emergencia(mensaje_emergencia)
                
                cuerpo_critico = "Sistema de Detección de Intrusos (IDS) - Reporte de Seguridad\n\n"
                cuerpo_critico += "Se ha detectado una conexión hacia una dirección IP catalogada en la lista negra. Se recomienda bloquear el tráfico hacia este destino en el firewall perimetral.\n\n"
                cuerpo_critico += "DETALLES DE LA AMENAZA:\n"
                cuerpo_critico += f"- IP Destino: {ip_destino}\n"
                cuerpo_critico += f"- Tipo de Riesgo: {tipo_riesgo}\n"
                cuerpo_critico += f"- Contacto de Abuso: {contacto_abuso}\n"
                cuerpo_critico += f"- Hora de Detección: {fecha_hora}\n\n"
                cuerpo_critico += "Por favor, tome las acciones correspondientes.\n"
                cuerpo_critico += "---\nGenerado automáticamente por el IDS Network Monitor."
                
                enviar_correo("🚨 [IDS ALERTA CRITICA] Tráfico Malicioso Detectado", cuerpo_critico)
                amenazas_reportadas.add(ip_destino)
                
        if(paquete.haslayer(TCP) or paquete.haslayer(UDP)):
            if(paquete.haslayer(TCP)):
                puerto_destino = paquete[TCP].dport
            else:
                puerto_destino = paquete[UDP].dport
                
            tiempo_actual = time.time()
            
            if(ip_origen not in registros_escaneo):
                registros_escaneo[ip_origen] = {
                    "puertos": set(), "tiempo_inicio": tiempo_actual
                }
                
            if(tiempo_actual - registros_escaneo[ip_origen]["tiempo_inicio"] > ventana_tiempo):
                registros_escaneo[ip_origen] = {
                    "puertos": set(), "tiempo_inicio": tiempo_actual
                }
                
            registros_escaneo[ip_origen]["puertos"].add(puerto_destino)
            
            if(len(registros_escaneo[ip_origen]["puertos"]) > limite_puertos):
                registrar_en_gui(f"[ALERTA SEGURIDAD] Posible escaneo de puertos desde IP: {ip_origen}")
                registros_escaneo[ip_origen]["puertos"].clear()

    if(paquete.haslayer(DNS) and paquete.haslayer(DNSQR)):
        if(paquete[DNS].opcode == 0 and paquete[DNS].qr == 0):
            nombre_sitio = paquete[DNSQR].qname.decode("utf-8", errors="ignore")
            if(nombre_sitio.endswith(".")):
                nombre_sitio = nombre_sitio[:-1]
            
            if(nombre_sitio and not nombre_sitio.endswith(".arpa")):
                mensaje_registro = f"IP: {paquete[IP].src} visito el sitio: {nombre_sitio}"
                registrar_en_gui(f"[MONITOREO] {mensaje_registro}")
                
                #20
                marca_tiempo = time.strftime("[%Y-%m-%d %H:%M:%S] ")
                carpeta = obtener_carpeta_diaria()
                ruta_reporte = os.path.join(carpeta, "reporte_sitios.txt")
                
                #21
                with open(ruta_reporte, "a") as archivo_registro:
                    archivo_registro.write(f"{marca_tiempo}{mensaje_registro}\n")
                
                #22
                threading.Thread(target=revisar_virustotal, args=(nombre_sitio,)).start()

#23
def ejecutar_monitoreo():
    sniff(prn=procesar_paquete, store=0, stop_filter=lambda x: not esta_monitoreando)

#24
def iniciar_ids():
    global esta_monitoreando
    if(not esta_monitoreando):
        esta_monitoreando = True
        registrar_en_gui("Iniciando monitoreo de red...")
        hilo_monitoreo = threading.Thread(target=ejecutar_monitoreo, daemon=True)
        hilo_monitoreo.start()
        
#25
def obtener_carpeta_diaria():
    ruta_base = obtener_ruta_base()
    fecha_actual = time.strftime("%Y-%m-%d")
    ruta_carpeta = os.path.join(ruta_base, fecha_actual)
    if(not os.path.exists(ruta_carpeta)):
        os.makedirs(ruta_carpeta)
    return ruta_carpeta

#26
def detener_ids():
    global esta_monitoreando
    esta_monitoreando = False
    registrar_en_gui("Monitoreo detenido.")
    
def buscar_registros(evento=None):
    consulta = simpledialog.askstring("Buscar", "Ingresa el texto a buscar:")
    if(consulta):
        area_registro.tag_remove("resaltado", "1.0", tk.END)
        indice_inicio = "1.0"
        while True:
            indice_inicio = area_registro.search(consulta, indice_inicio, stopindex=tk.END, nocase=True)
            if(not indice_inicio):
                break
            indice_fin = f"{indice_inicio}+{len(consulta)}c"
            area_registro.tag_add("resaltado", indice_inicio, indice_fin)
            indice_inicio = indice_fin
        
        area_registro.tag_config("resaltado", background="yellow", foreground="black")

def limpiar_registros():
    area_registro.delete("1.0", tk.END)
    
#27
def agregar_a_lista():
    ventana = ctk.CTkToplevel(ventana_principal)
    ventana.title("Gestión de Listas")
    ventana.geometry("350x300")
    ventana.resizable(False, False)
    ventana.attributes("-topmost", True)
    
    ctk.CTkLabel(ventana, text="Ingrese IP o MAC:").pack(pady=(10, 0))
    entrada_dato = ctk.CTkEntry(ventana, width=250)
    entrada_dato.pack(pady=5)
    
    opcion_lista = tk.StringVar(value="blanca")
    
    ctk.CTkRadioButton(ventana, text="Lista Blanca (Permitir)", variable=opcion_lista, value="blanca").pack(pady=5)
    ctk.CTkRadioButton(ventana, text="Lista Negra (Bloquear)", variable=opcion_lista, value="negra").pack(pady=5)
    
    ctk.CTkLabel(ventana, text="Tipo de Riesgo (Solo Lista Negra):").pack(pady=(10, 0))
    
    #28
    categorias_riesgo = ["Manual", "Malware", "Phishing", "Spam", "Botnet", "Ataque DoS", "Escaneo de Puertos"]
    combo_riesgo = ctk.CTkComboBox(ventana, width=250, values=categorias_riesgo)
    combo_riesgo.pack(pady=5)
    
    def guardar():
        dato = entrada_dato.get().strip().lower()
        riesgo = combo_riesgo.get().strip()
        lista = opcion_lista.get()
        
        #29
        if(not dato):
            return
            
        #30
        patron_ip = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        patron_mac = r"^([0-9a-f]{2}[:-]){5}([0-9a-f]{2})$"
        
        if(not re.match(patron_ip, dato) and not re.match(patron_mac, dato)):
            registrar_en_gui(f"[ERROR] '{dato}' no es valido. Ingresa una IP o MAC real.")
            ventana.destroy()
            return
            
        #31
        if(lista == "blanca"):
            if(dato not in direcciones_lista_blanca):
                direcciones_lista_blanca.add(dato)
                with open("lista_blanca.txt", "a") as archivo:
                    archivo.write(f"{dato}\n")
                registrar_en_gui(f"[SISTEMA] {dato} se agrego a la lista blanca.")
            else:
                registrar_en_gui(f"[SISTEMA] {dato} ya estaba en la lista blanca.")
        else:
            if(dato not in direcciones_lista_negra):
                direcciones_lista_negra[dato] = riesgo
                with open("lista_negra.txt", "a") as archivo:
                    archivo.write(f"{dato},{riesgo}\n")
                registrar_en_gui(f"[SISTEMA] {dato} se agrego a la lista negra.")
            else:
                registrar_en_gui(f"[SISTEMA] {dato} ya estaba en la lista negra.")
        ventana.destroy()
            
    ctk.CTkButton(ventana, text="Guardar", command=guardar, fg_color="#17a2b8", hover_color="#138496").pack(pady=15)
    
proceso_web = None

#32
def obtener_ip_local():
    try:
        conexion = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        conexion.connect(("8.8.8.8", 80))
        ip_red = conexion.getsockname()[0]
        conexion.close()
        return ip_red
    except Exception:
        return "127.0.0.1"

#33
def iniciar_servidor_web():
    global proceso_web
    if(proceso_web is None):
        try:
            ruta_base = obtener_ruta_base()
            ruta_script = os.path.join(ruta_base, "dashboard_web.py")
            proceso_web = subprocess.Popen(["python3", ruta_script])
            
            registrar_en_gui("[SISTEMA] Dashboard web activo.")
            registrar_en_gui("[SISTEMA] Acceso local: http://127.0.0.1:5000")
        except Exception as error_servidor:
            registrar_en_gui(f"[ERROR SERVIDOR] Fallo al iniciar: {error_servidor}")

#34
def cerrar_aplicacion():
    global proceso_web
    if(proceso_web is not None):
        proceso_web.terminate()
    ventana_principal.destroy()

#35
def ver_reporte():
    carpeta = obtener_carpeta_diaria()
    ruta_reporte = os.path.join(carpeta, "reporte_sitios.txt")
    
    if(not os.path.exists(ruta_reporte)):
        registrar_en_gui("[SISTEMA] El reporte de sitios de hoy aun no existe.")
        return
        
    ventana_reporte = ctk.CTkToplevel(ventana_principal)
    ventana_reporte.title(f"Reporte de Sitios - {carpeta}")
    ventana_reporte.geometry("700x450")
    ventana_reporte.resizable(True, True)
    
    caja_texto = ctk.CTkTextbox(ventana_reporte, font=("Consolas", 15), fg_color="#1e1e1e", text_color="white")
    caja_texto.pack(pady=20, padx=20, fill="both", expand=True)
    
    with open(ruta_reporte, "r") as archivo:
        contenido = archivo.read()
        caja_texto.insert("0.0", contenido)
    
    caja_texto.configure(state="disabled")

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

ventana_principal = ctk.CTk()
ventana_principal.title("IDS Network Monitor")
ventana_principal.geometry("900x650")
ventana_principal.resizable(True, True)

marco_botones = ctk.CTkFrame(ventana_principal, fg_color="transparent")
marco_botones.pack(pady=15)

boton_inicio = ctk.CTkButton(marco_botones, text="Iniciar IDS", command=iniciar_ids, fg_color="#28a745", hover_color="#218838", text_color="white", width=150)
boton_inicio.grid(row=0, column=0, padx=20)

boton_detener = ctk.CTkButton(marco_botones, text="Detener IDS", command=detener_ids, fg_color="#dc3545", hover_color="#c82333", text_color="white", width=150)
boton_detener.grid(row=0, column=1, padx=20)

boton_limpiar = ctk.CTkButton(marco_botones, text="Limpiar Consola", command=limpiar_registros, fg_color="#6c757d", hover_color="#5a6268", text_color="white", width=150)
boton_limpiar.grid(row=0, column=2, padx=20)

boton_listas = ctk.CTkButton(marco_botones, text="Gestión de Listas", command=agregar_a_lista, fg_color="#17a2b8", hover_color="#138496", text_color="white", width=150)
boton_listas.grid(row=1, column=0, padx=20, pady=10)

boton_reporte = ctk.CTkButton(marco_botones, text="Ver Reporte DNS", command=ver_reporte, fg_color="#ffc107", hover_color="#e0a800", text_color="black", width=150)
boton_reporte.grid(row=1, column=1, padx=20, pady=10)

ventana_principal.bind("<Control-f>", buscar_registros)

area_registro = scrolledtext.ScrolledText(ventana_principal, width=105, height=18, bg="#1e1e1e", fg="#4af626", font=("Consolas", 14), borderwidth=0, highlightthickness=0)
area_registro.pack(pady=10, padx=20, fill="both", expand=True)

ctk.CTkLabel(ventana_principal, text="Alertas Criticas / Emergencias", text_color="#ff4d4d", font=("Arial", 14, "bold")).pack()

area_emergencias = scrolledtext.ScrolledText(ventana_principal, width=105, height=7, bg="#3b0000", fg="white", font=("Consolas", 14), borderwidth=0, highlightthickness=0)
area_emergencias.pack(pady=5, padx=20, fill="both", expand=True)

ventana_principal.protocol("WM_DELETE_WINDOW", cerrar_aplicacion)
iniciar_servidor_web()
ventana_principal.mainloop()
