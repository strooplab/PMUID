#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Biemvenido a PMUID! Este es un software de administración de contraseñas
que permite almacenar y recuperar contraseñas de forma segura. Para
utilizarlo, primero debes crear una cuenta ingresando un nombre de usuario y 
una contraseña, esta es la unica contraseña que deberas memorizar, guardala
en un lugar seguro! Una vez que hayas creado una cuenta, podrás comenzar 
a almacenar tus contraseñas. Espero disfrutes esta nueva opción para guardar
tus contraseñas en tu propio entorno!
"""

import tkinter as tk
import json, hashlib, os, string, random, stat, platform, sqlite3, base64, \
        shutil, sys, tempfile, win32crypt
from tkinter import messagebox, ttk, PhotoImage
from Cryptodome.Cipher import AES
from pyfiglet import Figlet
from termcolor import colored
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
from version import __version__

#Clase contenedora de las interfaces y funciones del programa
class PasswordManager:

    """
    Definicion de la pantalla principal, con funciones para registrar un unico 
    usuario, ingresar al archivo de contraseñas encriptadas, cambiar la 
    contraseña del usuario y salir del programa
    """

    #Funcion madre (__init__)
    def __init__(self, master):
        super().__init__()
        self.set_icon()
        welcome_t = 'Welcome To:'
        pmuid_t ='PMUID'
        modes = ['slant']

        try:
            mode_fig = random.choice(modes)
            welcome_banner = Figlet(font='slant')
            welcome_text = welcome_banner.renderText(welcome_t)
            pmuid_banner = Figlet(font=mode_fig)
            pmuid_text = pmuid_banner.renderText(pmuid_t)
            print(colored(welcome_text, 'cyan'))
            print(colored(pmuid_text, 'cyan'))
        except Exception:
            print(welcome_t)
            print(pmuid_t)

        gen_dir = os.path.join(os.path.dirname(__file__), 'gen')
        media_dir = os.path.join(os.path.dirname(__file__), 'media')
        if not os.path.exists(gen_dir):
            os.makedirs(gen_dir)
        if not os.path.exists(media_dir):
            os.makedirs(media_dir)
        elif os.path.exists(media_dir):
            pass

        data_dir = os.path.join(os.path.dirname(__file__), 'gen')  
        self.passwords_file = os.path.join(data_dir, 'passwords.json')
        self.user_file = os.path.join(data_dir, 'user_data.json')
        self.fernet_file = os.path.join(data_dir, 'fernet_key.key')
        self.service_listbox = None
        self.cipher = self.encrypted_key()

        self.master = master
        self.master.title("PMUID")
        self.master.geometry("400x300")
        self.master.configure(bg="#121212")

        self.password_manager_frame = tk.Frame(self.master, bg="#1A1A1A")
        self.password_manager_frame.pack(expand=True, fill="both")

        self.init_ui()

    """
    1. Interfaces para el registro e inicio de sesion del usuario
    """
    #Interfaz principal
    def init_ui(self):
        self.clear_frame()
        self.master.title("PMUID")

        self.register_button = tk.Button(self.password_manager_frame, 
            text="Registrar", bg="#2A2A2A", fg="white", 
            command=self.register)
        self.register_button.pack(pady=(30,10), padx=10, fill="both")
        
        self.login_button = tk.Button(self.password_manager_frame, 
            text="Ingresar", bg="#2A2A2A", fg="white", 
            command=self.login)
        self.login_button.pack(pady=10, padx=10, fill="both")

        self.change_pass_button = tk.Button(self.password_manager_frame, 
            text="Cambiar Contraseña", bg="#2A2A2A", fg="white", 
            command=self.change_password)
        self.change_pass_button.pack(pady=10, padx=10, fill="both")

        self.about_button = tk.Button(self.password_manager_frame, 
            text="Acerca de", bg="#2A2A2A", fg="white", 
            command=self.show_about)
        self.about_button.pack(pady=10, padx=10, fill="both")

        self.quit_button = tk.Button(self.password_manager_frame, 
            text="Salir", bg="#2A2A2A", fg="white", 
            command=self.quit)
        self.quit_button.pack(pady=10, padx=10, fill="both")

    #Interfaz de registro 
    def register(self):
        self.clear_frame()
        self.master.title("Registrar Usuario")
        
        self.username_label = tk.Label(self.password_manager_frame, 
            text="Usuario:", bg="#2A2A2A", fg="white") #Parametros
        self.username_label.pack(pady=5)

        self.username_entry = tk.Entry(self.password_manager_frame)
        self.username_entry.pack(pady=5)
        
        self.password_label = tk.Label(self.password_manager_frame, 
            text="Contraseña:", bg="#2A2A2A", fg="white")
        self.password_label.pack(pady=5)

        self.password_entry = tk.Entry(self.password_manager_frame, show="*")
        self.password_entry.pack(pady=5)
        
        self.register_button = tk.Button(self.password_manager_frame, 
            text="Registrar", bg="#2A2A5A", fg="white", command=self.save_user)
        self.register_button.pack(pady=10)

        self.back_button = tk.Button(self.password_manager_frame, 
            text="Volver", bg="#2A2A2A", fg="white", command=self.init_ui)
        self.back_button.pack(pady=10)

    #Interfaz de inicio de sesion
    def login(self):
        self.clear_frame()
        self.master.title("Ingresar")
        
        self.username_label = tk.Label(self.password_manager_frame, 
                        text="Usuario:", bg="#2A2A2A", fg="white")
        
        self.username_label.pack(pady=5)
        self.username_entry = tk.Entry(self.password_manager_frame)
        self.username_entry.pack(pady=5)
        
        self.password_label = tk.Label(self.password_manager_frame, 
                        text="Contraseña:", bg="#2A2A2A", fg="white")
        self.password_label.pack(pady=5)

        self.password_entry = tk.Entry(self.password_manager_frame, show="*")
        self.password_entry.pack(pady=5)
        
        self.login_button = tk.Button(self.password_manager_frame, 
        text="Ingresar", bg="#2A2A5A", fg="white", command=self.authenticate)
        self.login_button.pack(pady=10)

        self.back_button = tk.Button(self.password_manager_frame, 
        text="Volver", bg="#2A2A2A", fg="white", command=self.init_ui)

        self.back_button.pack(pady=10)

    #Interfaz de cambio de contraseña
    def change_password(self):
        self.clear_frame()
        self.master.title("Cambiar Contraseña")
        
        self.old_password_label = tk.Label(self.password_manager_frame, 
                    text="Contraseña antigua:", bg="#2A2A2A", fg="white")
        self.old_password_label.pack(pady=5)

        self.old_password_entry = tk.Entry(self.password_manager_frame, 
                                           show="*")
        self.old_password_entry.pack(pady=5)

        self.new_password_label = tk.Label(self.password_manager_frame, 
                    text="Contraseña nueva:", bg="#2A2A2A", fg="white")
        self.new_password_label.pack(pady=5)

        self.new_password_entry = tk.Entry(self.password_manager_frame, 
                                           show="*")
        self.new_password_entry.pack(pady=5)
        
        self.change_button = tk.Button(self.password_manager_frame, 
            text="Cambiar", bg="#2A2A5A", fg="white", command=self.change_pass)
        self.change_button.pack(pady=10)

        self.back_button = tk.Button(self.password_manager_frame, 
            text="Volver", bg="#2A2A2A", fg="white", command=self.init_ui)
        self.back_button.pack(pady=10)

    """
    1.1. Funciones para el registro e inicio de sesion del usuario
    """

    #Función para guardar el usuario
    def save_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        hashed_password = self.hash_password(password)
        
        user_data = {'Username': username, 
                     'UPassword': hashed_password}
        file_name = self.user_file
        
        if os.path.exists(file_name):
            with open(file_name, 'r') as file:
                try:
                    user_data = json.load(file)
                except json.JSONDecodeError:
                    user_data = {'Username': username, 
                                 'UPassword': hashed_password}


        with open(file_name, 'w+') as file:
            json.dump(user_data, file)
            messagebox.showinfo("Registro Completado", 
                                "Usuario registrado exitosamente")
            self.init_ui()
    
    #Funcion para autenticar al usuario a 
    #la hora de intentar ingresar al programa
    def authenticate(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        hashed_password = self.hash_password(password)
        file_name = self.user_file
        
        if os.path.exists(file_name):
            with open(file_name, 'r') as file:
                user_data = json.load(file)
                stored_password = user_data.get('UPassword')
                
                if hashed_password == stored_password and \
                username == user_data.get('Username'):
                    self.username = username
                    messagebox.showinfo("Acceso Permitido", 
                                        "Inicio de sesión exitoso")
                    self.password_management()
                else:
                    messagebox.showerror("Error", "Error en la autenticación")
        else:
            messagebox.showerror("Error", "Usuario no registrado")

    #Funcion para cambiar la contraseña registrada del unico usuario
    def change_pass(self):
        old_password = self.old_password_entry.get()
        new_password = self.new_password_entry.get()

        if old_password == new_password:
            messagebox.showerror("Error", (
                "La contraseña nueva"
                "es identica a la ingresada."
                ))
            return
        
        hashed_password = self.hash_password(old_password)
        hashed_new_password = self.hash_password(new_password)
        file_name = self.user_file
        
        """
        Si el archivo existe, se procede a leerlo para comprobar la que la
        #contraseña actual es la misma que la que se ingreso en el programa
        """
        if os.path.exists(file_name):
            with open(file_name, 'r') as file:
                user_data = json.load(file)
                stored_password = user_data.get('UPassword')

                """Si coincide la contraseña actual, 
                se procede a cambiar la contraseña"""
                if hashed_password == stored_password: 
                    user_data['UPassword'] = hashed_new_password
                    with open(file_name, 'w') as file:
                        json.dump(user_data, file)
                    messagebox.showinfo("Éxito", (
                        "Contraseña guardada"
                        "exitosamente"
                        ))
                    self.init_ui()
                else:
                    messagebox.showerror("Error", (
                        "Error al intentar cambiar la contraseña"
                        ))
        else:
            messagebox.showerror("Error", (
                "Aún no existe un usuario para hacer un cambio de contraseña"
                ))
    
    #Función para definir el icono del programa (depende el sistema operativo)
    def set_icon(self):
        logo_path = self.resource_path(os.path.join('media', 'pyramid.ico'))
        try:
            if platform.system() == 'Windows':
                self.master.iconbitmap(logo_path)
            else:
                logo = PhotoImage(file=logo_path)
                self.master.call('wm', 'iconphoto', self.master._w, logo)
        except Exception:
            pass
    
    """
    2. Interfaces para la administracion de contraseñas principal
    """
    #Apartado de interfaces numero 2
    def password_management(self):
        self.clear_frame()
        self.master.title(f"Welcome, {self.username}")
        self.master.geometry("400x300")
        self.master.configure(bg='#121212')
        
        self.add_password_button = tk.Button(self.password_manager_frame, 
            text="Añadir Contraseña", bg="#2A2A2A", fg="white", 
            command=self.add_password)
        self.add_password_button.pack(pady=(30,10), padx=10, fill="both")
        
        self.get_password_button = tk.Button(self.password_manager_frame, 
            text="Obtener Contraseña", bg="#2A2A2A", fg="white", 
            command=self.view_services)
        self.get_password_button.pack(pady=10, padx=10, fill="both")

        self.import_pass_button = tk.Button(self.password_manager_frame, 
            text="Importar Contraseñas", bg="#2A2A2A", fg="white", 
            command=self.import_password)
        self.import_pass_button.pack(pady=10, padx=10, fill="both")

        self.view_services_button = tk.Button(self.password_manager_frame, 
            text="Ver Servicios", bg="#2A2A2A", fg="white", 
            command=self.view_services)
        self.view_services_button.pack(pady=10, padx=10, fill="both")

        self.return_button = tk.Button(self.password_manager_frame, 
            text="Volver", bg="#2A2A2A", fg="white", 
            command=self.init_ui)
        self.return_button.pack(pady=10, padx=10, fill="both")

    #Interfaz para añadir nuevas contraseñas
    def add_password(self):
        self.clear_frame()
        self.master.title("Añadir Contraseña")
        self.gen_pass = None
        
        self.service_label = tk.Label(self.password_manager_frame, 
            text="Servicio:", bg="#2A2A2A", fg="white") 
        self.service_label.pack(pady=5)

        self.service_entry = tk.Entry(self.password_manager_frame)
        self.service_entry.pack(pady=5)
        
        self.password_label = tk.Label(self.password_manager_frame, 
            text="Contraseña:", bg="#2A2A2A", fg="white") 
        self.password_label.pack(pady=5)

        self.password_entry = tk.Entry(self.password_manager_frame, show="*")
        self.password_entry.pack(pady=5)
        
        self.add_password_button = tk.Button(self.password_manager_frame, 
            text="Añadir Contraseña", bg="#2A2A5A", fg="white", 
            command=self.save_password)
        self.add_password_button.pack(pady=10)

        self.gen_password_button = tk.Button(self.password_manager_frame, 
            text="Generar Contraseña", bg="#6A2A2A", fg="white", 
            command=self.generate_password)
        self.gen_password_button.pack(pady=10)

        self.back_button = tk.Button(self.password_manager_frame, 
            text="Volver", bg="#2A2A2A", fg="white", 
            command=self.password_management)
        self.back_button.pack(pady=10)
    
    #Interfaz para generar nuevas contraseñas
    def generate_password(self):
        self.clear_frame()
        self.master.title("Generar contraseña")

        self.service_label = tk.Label(self.password_manager_frame, 
            text="Servicio:", bg="#2A2A2A", fg="white") 
        self.service_label.pack(pady=5)

        self.service_entry = tk.Entry(self.password_manager_frame)
        self.service_entry.pack(pady=5)
        
        self.gen_label = tk.Label(self.password_manager_frame, 
            text="Ingrese el numero de carácteres en la contraseña:", 
            bg="#2A2A2A", fg="white")
        self.gen_label.pack(pady=5)

        self.gen_entry = tk.Entry(self.password_manager_frame)
        self.gen_entry.pack(pady=5)

        self.gen_password_button = tk.Button(self.password_manager_frame, 
            text="Generar Contraseña", bg="#6A2A2A", fg="white", 
            command=self.gen_password)
        self.gen_password_button.pack(pady=10)

        self.back_button = tk.Button(self.password_manager_frame, 
            text="Volver", bg="#2A2A2A", fg="white", 
            command=self.password_management)
        self.back_button.pack(pady=10)

    #Interfaz para obtener la contraseña guardada
    def get_password(self):
        self.clear_frame()
        self.master.title("Obtener Contraseña")
        
        self.service_label = tk.Label(self.password_manager_frame, 
            text="Servicio:", bg="#2A2A2A", fg="white")
        self.service_label.pack(pady=5)
        self.service_entry = tk.Entry(self.password_manager_frame)
        self.service_entry.pack(pady=5)
        
        self.get_password_button = tk.Button(self.password_manager_frame, 
            text="Obtener Contraseña", bg="#2A2A5A", fg="white", 
            command=self.retrieve_password)
        self.get_password_button.pack(pady=10)

        self.back_button = tk.Button(self.password_manager_frame, 
            text="Volver", bg="#2A2A2A", fg="white", 
            command=self.password_management)
        self.back_button.pack(pady=10)
    
    #Interfaz para importar contraseñas desde firefox o chrome
    def import_password(self):
        self.clear_frame()
        self.master.title("Importar Contraseñas")

        self.chrome_button = tk.Button(self.password_manager_frame, 
            text="Importar desde Chrome", bg="#2A2A2A", fg="white", 
            command=self.import_chrome)       
        self.chrome_button.pack(pady=5) 

        self.back_button = tk.Button(self.password_manager_frame, 
            text="Volver", bg="#2A2A2A", fg="white", 
            command=self.password_management)
        self.back_button.pack(pady=10)

    """
    2.2. Funciones para la administracion de contraseñas principal
    """
    #Función para guardar la contraseña ingresada junto con su servicio
    def save_password(self):
        if self.gen_pass != None:
            password = self.gen_pass
        else:
            password = self.password_entry.get()
        service = self.service_entry.get()
        cipher = self.cipher    
        encrypted_password = self.encrypt_password(cipher, password)
        file_name = self.passwords_file
        
        if not os.path.exists(file_name) or os.stat(file_name).st_size <= 0:
            data = []
        else:
            with open(file_name, 'r') as file:
                data = json.load(file)
        
        new_password = {'Servicio': service, 'Contraseña': encrypted_password}
        data.append(new_password)
        
        with open(file_name,'w') as file:
            json.dump(data, file, indent=4)
        self.master.clipboard_clear()
        self.master.clipboard_append(password)
        self.master.update()
        messagebox.showinfo("Contraseña Añadida", (
            "Contraseña añadida exitosamente y copiada al portapapeles"
            ))
        self.password_management()

    #Función para generar una contraseña
    def gen_password(self):
        length = int(self.gen_entry.get())
        if length != 0 and length <= 20:
            pass
        else:
            messagebox.showerror("Error", (
                "La longitud de la contraseña debe ser de máximo 20 caracteres."
            ))
            return
        characters = string.ascii_letters + string.digits + string.punctuation
        password = "".join(random.choice(characters) for i in range(length))
        self.gen_pass = password
        self.save_password()
    
    #Función para obtener una contraseña
    def retrieve_password(self):
        selected_index = self.service_listbox.curselection()
        if selected_index:
            index = selected_index[0]
            service = self.service_listbox.get(index)
            cipher = self.cipher
            file_name = self.passwords_file
            try:
                with open(file_name, 'r') as file:
                    data = json.load(file)
            except json.decoder.JSONDecodeError:
                data = {}
                messagebox.showerror("Error", "Contraseñas sin formato válido")
                return
            
        for i in data:
            if i['Servicio'] == service:
                decrypted_password = self.decrypt_password(cipher, \
                                                           i['Contraseña'])
                if decrypted_password is None:
                    messagebox.showerror("Error", (
                        "No se pudo desencriptar la contraseña"
                        ))
                    return
                self.master.clipboard_clear()
                self.master.clipboard_append(decrypted_password)
                self.master.update()
                messagebox.showinfo("Contraseña Obtenida", (
                    f"{service}\nContraseña copiada al portapapeles"
                    ))

    #Función para borrar una contraseña
    def delete_password(self):
        selected_index = self.service_listbox.curselection()
        if selected_index:
            index = selected_index[0]
            try:
                with open(self.passwords_file, 'r') as file:
                    data = json.load(file)
            except json.decoder.JSONDecodeError:
                data = {}
                messagebox.showerror("Error", "Contraseñas sin formato válido")
                return
            if index < len(data):
                del data[index]
                with open(self.passwords_file, 'w') as file:
                    json.dump(data, file, indent=4)
                messagebox.showinfo("Contraseña borrada", (
                    f"Contraseña borrada:{index}\n"
                    ))
                self.view_services()
            else:
                messagebox.showerror("Error", (
                    "Índice fuera de rango, No existe esa contraseña"
                    ))
        else:
            messagebox.showerror("Error", (
                "Seleccione una contraseña para eliminar"
                ))
    
    #Función para extraer la hora de la contraseña
    def chrome_date(self, chrome_data):
        return datetime(1601, 1,1) + timedelta(microseconds=chrome_data)

    #Función para importar una contraseña desde chrome (main)
    def import_chrome(self):
        file_name = self.passwords_file
        cipher = self.cipher
        messagebox.showinfo("Warning", (
            "Experimental Function, only available on Windows"
            ))
        key = self.get_chrome_decryption_key()

        if key is None:
            return

        way = tempfile.gettempdir()
        os.chdir(path=way)
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", 
            "Google", "Chrome", "User Data", "default", "Login Data")
        filename = "ChromeData.txt"
        shutil.copyfile(db_path, filename)
        db = sqlite3.connect(filename)
        cursor = db.cursor()
        cursor.execute((
            "select origin_url, username_value, password_value, date_created," 
            "date_last_used from logins order by date_created"
            ))
        data = []
        existing_services = set()  # Conjunto para mantener servicios únicos

        for index, row in enumerate(cursor.fetchall()):
            url = row[0]
            user = row[1]
            decrypted_password = self.decrypt_chrome_password(row[2], key)

            if decrypted_password == None:
                messagebox.showerror("error", "Contraseña vacia encontrada") 
                continue  

            existing_services.add(user)

            if user in existing_services or user == '':
                user += ''.join(random.choices(string.ascii_letters + 
                                               string.digits, k=5))

            encrypted_password = self.encrypt_password(cipher, 
                                                       decrypted_password)
            password_entry = {'Servicio': user, 
                              'Contraseña': encrypted_password}
            data.append(password_entry)

        cursor.close()
        db.close()
        try:
            os.remove(filename)
        except:
            pass
        self.save_chrome_passwords(data)
        self.password_management()

    def save_chrome_passwords(self, passwords):
        file_name = self.passwords_file
        if not os.path.exists(file_name) or os.stat(file_name).st_size <= 0:
            data = []
        else:
            with open(file_name, 'r') as file:
                data = json.load(file)
            
        data.extend(passwords)

        with open(file_name, 'w') as file:
            json.dump(data, file, indent=4)
        messagebox.showinfo("Exito", "Contraseñas guardadas de Chrome")

    def decrypt_chrome_password(self, password, key):
        try:
            iv = password[3:15]
            password = password[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            return cipher.decrypt(password)[:-16].decode()
        except:
            try:
                return str(win32crypt.CryptUnprotectData(password, None, 
                                                         None, None, 0)[1])
            except:
                return ""

    def get_chrome_decryption_key(self):
        local_state_path = self.resource_path(os.path.join(
            os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", 
            "User Data", "Local State"))

        try:
            with open(local_state_path, "r", encoding="utf-8") as f:
                local_state = f.read()
                local_state = json.loads(local_state)
        except:
            messagebox.showerror("Error", (
            "'Local State' no encontrado\n"
            "Chrome esta instalado en tu sistema?"
            ))
            return

        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        key = key[5:]
        return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
                
    #Funcion e interfaz para ver y buscar servicios
    def view_services(self):
        self.clear_frame()
        self.master.title("Servicios Guardados")
        self.master.geometry("400x400")
        file_name = self.passwords_file

        #Scrollbar para navegar a través de una libreria extensa
        scrollbar = ttk.Scrollbar(self.password_manager_frame, 
            orient=tk.VERTICAL) 
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        try:
            with open(file_name) as file:
                view = json.load(file)
                services_label = tk.Label(self.password_manager_frame, 
                    text="Servicios Guardados:", bg="#1A1A1A", fg="white")
                services_label.pack(pady=5)
                
                self.service_listbox= tk.Listbox(self.password_manager_frame, 
                    yscrollcommand=scrollbar.set, bg="#1A1A1A", fg="white")
                for x in view:
                    self.service_listbox.insert(tk.END, f"{x['Servicio']}")
                self.service_listbox.pack(fill=tk.BOTH, expand=True)

                scrollbar.config(command=self.service_listbox.yview)
        except FileNotFoundError:
            messagebox.showerror("Error", (
                "No se ha encontrado ninguna "
                "contraseña ni ningún servicio asociado"
                ))
            self.password_management()
            return
        
        self.search_entry = ttk.Entry(self.password_manager_frame)
        self.search_entry.pack(pady=5)
        self.search_entry.bind("<KeyRelease>", self.filter_services) 

        """
        Con ayuda del keyrelease y un sistema de filtrado, 
        puedes buscar la contraseña que quieras a tiempo real
        """
        self.retrieve_password_button = tk.Button(self.password_manager_frame, 
            text="Obtener Contraseña", bg="#2A2A2A", fg="white", 
            command=self.retrieve_password)
        self.retrieve_password_button.pack(pady=10, padx=10, fill="both")

        self.delete_password_button = tk.Button(self.password_manager_frame, 
            text="Borrar Contraseña", bg="#2A1111", fg="white", 
            command=self.delete_password)
        self.delete_password_button.pack(pady=10, padx=10, fill="both")

        self.back_button = tk.Button(self.password_manager_frame, 
            text="Volver", bg="#2A2A2A", fg="white", 
            command=self.password_management)
        self.back_button.pack(pady=10, padx=10, fill="both")

    #Función para la busqueda activa de contraseñas
    def filter_services(self, event):
        search_term = self.search_entry.get().lower()
        self.service_listbox.delete(0, tk.END) 
        file_name = self.passwords_file

        with open(file_name) as file:
            view = json.load(file)
            for x in view:
                if search_term in x['Servicio'].lower():
                    self.service_listbox.insert(tk.END, f"{x['Servicio']}")

    """
    3. Funciones 'encriptadores, formato y salida del programa'
    """
    #Funcion para encriptar las contraseñas
    def hash_password(self, password):
        sha256 = hashlib.sha256()
        sha256.update(password.encode())
        return sha256.hexdigest()
    
    #Encriptacion de contraseñas
    def encrypt_password(self, cipher, password):
        encrypted_password = cipher.encrypt(password.encode())
        return encrypted_password.hex()
    
    #Decriptación de contraseñas
    def decrypt_password(self, cipher, encrypted_password):
        try:
            encrypted_password_bytes = bytes.fromhex(encrypted_password)
            return cipher.decrypt(encrypted_password_bytes).decode()
        except Exception as e:
            print(f"Error decrypting password: {e}")
            return None
    
    #Generación de una llave Fernet unica para poder desencriptar o 
    #encriptar las contraseñas
    def gen_key(self):
        return Fernet.generate_key()
    
    #Inicialización del cifrado para encriptar la llave generada
    def initialize_cypher(self, key):
        return Fernet(key)

    #Encriptar la llave generada
    def encrypted_key(self):
        key_file = self.fernet_file
        if os.path.exists(key_file):
            if os.stat(key_file).st_size > 0:
                with open(key_file, 'rb') as f:
                    key = f.read()
            else:
                key = self.gen_key()
                with open(key_file, 'wb') as file:
                    file.write(key)
                    os.chmod(key_file, stat.S_IRUSR | stat.S_IWUSR)
        else:
            key = self.gen_key()
            with open(key_file, 'wb') as file:
                file.write(key)
                os.chmod(key_file, stat.S_IRUSR | stat.S_IWUSR)
        cipher = self.initialize_cypher(key)
        return cipher

    #Volver a el inicio de sesión
    def quit(self):
        self.master.destroy()
    
    #Convertir una ruta absoluta a una ruta relativa
    def resource_path(self, relative_path):
        try:
            base_path = sys._MEIPASS
        except Exception:
            base_path = os.path.abspath(".")     
        return os.path.join(base_path, relative_path)
    
    #Version
    def show_about(self):
        messagebox.showinfo("Acerca de", 
            f"PMUID versión {__version__}\n\
            Desarrollado por Stroop Lab")

    #Eliminar el contenido de la anterior ventana
    def clear_frame(self):
        for widget in self.password_manager_frame.winfo_children():
            widget.destroy()

#Funcion principal (Verifica y realiza acciones dependiendo del OS)
def main():
    system = platform.system()
    os.system('cls')
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('\n[*] Abortado')
        exit(0)
    except Exception as e:
        print('[!] ERROR: ' + str(e))
