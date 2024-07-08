#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter as tk
import json, hashlib, os, string, random, stat, platform, sqlite3, base64, shutil, subprocess, time
from tkinter import messagebox, ttk
from pyfiglet import Figlet
from termcolor import cprint
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from version import __version__

"""
Biemvenido a PMUID! Este es un software de administración de contraseñas
que permite almacenar y recuperar contraseñas de forma segura. Para
utilizarlo, primero debes crear una cuenta ingresando un nombre de usuario y 
una contraseña, esta es la unica contraseña que deberas memorizar, guardala
en un lugar seguro! Una vez que hayas creado una cuenta, podrás comenzar 
a almacenar tus contraseñas. Espero disfrutes esta nueva opción para guardar
tus contraseñas en tu propio entorno!
"""

#Clase contenedora de las interfaces y funciones del programa
class PasswordManager:

    #Definicion de la pantalla principal, con funciones para registrar un unico 
    #usuario, ingresar al archivo de contraseñas encriptadas, cambiar la 
    #contraseña del usuario y salir del programa

    def __init__(self, master):
        modes = ['big_money-ne', 'cosmic', 'slant']
        mode_fig = random.choice(modes)
        welcome_banner = Figlet(font='slant')
        welcome_text = welcome_banner.renderText('Welcome To:')
        pmuid_banner = Figlet(font=mode_fig)
        pmuid_text = pmuid_banner.renderText('PMUID')
        cprint(welcome_text, 'cyan')
        cprint(pmuid_text, 'cyan')
        self.cipher = self.encrypted_key()
        self.passwords = []
        self.master = master
        self.set_icon()
        self.master.title("P4ssw0rd_M4n4g3R")
        self.master.geometry("400x300")
        self.master.configure(bg="#121212")

        self.password_manager_frame = tk.Frame(self.master, bg="#1A1A1A")
        self.password_manager_frame.pack(expand=True, fill="both")
        
        self.register_button = tk.Button(self.password_manager_frame, text="Registrar", bg="#2A2A2A", fg="white", command=self.register)
        
        self.register_button.pack(pady=(30,10), padx=10, fill="both")
        
        self.login_button = tk.Button(self.password_manager_frame, text="Ingresar", bg="#2A2A2A", fg="white", command=self.login)
        self.login_button.pack(pady=10, padx=10, fill="both")

        self.change_pass_button = tk.Button(self.password_manager_frame, text="Cambiar Contraseña", bg="#2A2A2A", fg="white", command=self.change_password)
        self.change_pass_button.pack(pady=10, padx=10, fill="both")

        self.about_button = tk.Button(self.password_manager_frame, text="Acerca de", bg="#2A2A2A", fg="white", command=self.show_about)
        self.about_button.pack(pady=10, padx=10, fill="both")

        self.quit_button = tk.Button(self.password_manager_frame, text="Salir", bg="#2A2A2A", fg="white", command=self.quit)
        self.quit_button.pack(pady=10, padx=10, fill="both")

    #Apartado de interfaces numero 1
    #Interfaz de registro
    
    def register(self):
        self.register_window = tk.Toplevel(self.master)
        self.register_window.title("Registrar Usuario")
        self.register_window.geometry("400x200")
        self.register_window.configure(bg="#1A1A1A")
        
        self.username_label = tk.Label(self.register_window, text="Usuario:", bg="#2A2A2A", fg="white")
        self.username_label.pack(pady=5)
        self.username_entry = tk.Entry(self.register_window)
        self.username_entry.pack(pady=5)
        
        self.password_label = tk.Label(self.register_window, text="Contraseña:", bg="#2A2A2A", fg="white")
        self.password_label.pack(pady=5)
        self.password_entry = tk.Entry(self.register_window, show="*")
        self.password_entry.pack(pady=5)
        
        self.register_button = tk.Button(self.register_window, text="Registrar", bg="#2A2A5A", fg="white", command=self.save_user)
        self.register_button.pack(pady=10)

    #Interfaz de inicio de sesion

    def login(self):
        self.login_window = tk.Toplevel(self.master)
        self.login_window.title("Ingresar")
        self.login_window.geometry("400x200")
        self.login_window.configure(bg="#1A1A1A")
        
        self.username_label = tk.Label(self.login_window, text="Usuario:", bg="#2A2A2A", fg="white")
        self.username_label.pack(pady=5)
        self.username_entry = tk.Entry(self.login_window)
        self.username_entry.pack(pady=5)
        
        self.password_label = tk.Label(self.login_window, text="Contraseña:", bg="#2A2A2A", fg="white")
        self.password_label.pack(pady=5)
        self.password_entry = tk.Entry(self.login_window, show="*")
        self.password_entry.pack(pady=5)
        
        self.login_button = tk.Button(self.login_window, text="Ingresar", bg="#2A2A5A", fg="white", command=self.authenticate)
        self.login_button.pack(pady=10)

    #Interfaz de cambio de contraseña

    def change_password(self):
        self.change_window = tk.Toplevel(self.master)
        self.change_window.title("Ingresar")
        self.change_window.geometry("400x200")
        self.change_window.configure(bg="#1A1A1A")
        
        self.old_password_label = tk.Label(self.change_window, text="Contraseña antigua:", bg="#2A2A2A", fg="white")
        self.old_password_label.pack(pady=5)
        self.old_password_entry = tk.Entry(self.change_window, show="*")
        self.old_password_entry.pack(pady=5)

        self.new_password_label = tk.Label(self.change_window, text="Contraseña nueva:", bg="#2A2A2A", fg="white")
        self.new_password_label.pack(pady=5)
        self.new_password_entry = tk.Entry(self.change_window, show="*")
        self.new_password_entry.pack(pady=5)
        
        self.change_button = tk.Button(self.change_window, text="Ingresar", bg="#2A2A5A", fg="white", command=self.change_pass)
        self.change_button.pack(pady=10)

    #Apartado de funciones numero 1
    #Función para guardar el usuario
    
    def save_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        hashed_password = self.hash_password(password)
        
        user_data = {'Username': username, 'UPassword': hashed_password}
        file_name = 'user_data.json'
        
        if os.path.exists(file_name):
            with open(file_name, 'r') as file:
                try:
                    user_data = json.load(file)
                except json.JSONDecodeError:
                    user_data = {'Username': username, 'UPassword': hashed_password}

        with open(file_name, 'w+') as file:
            json.dump(user_data, file)
            messagebox.showinfo("Registro Completado", "Usuario registrado exitosamente")
            self.register_window.destroy()
    
    #Funcion para autenticar al usuario a la hora de intentar ingresar al programa
    
    def authenticate(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        hashed_password = self.hash_password(password)
        
        file_name = 'user_data.json'
        
        if os.path.exists(file_name):
            with open(file_name, 'r') as file:
                user_data = json.load(file)
                stored_password = user_data.get('UPassword')
                
                if hashed_password == stored_password and username == user_data.get('Username'):
                    messagebox.showinfo("Acceso Permitido", "Inicio de sesión exitoso")
                    self.password_management()
                    self.login_window.destroy()
                else:
                    messagebox.showerror("Error", "Error en la autenticación")
        else:
            messagebox.showerror("Error", "Usuario no registrado")

    #Funcion para cambiar la contraseña registrada del unico usuario
    
    def change_pass(self):
        old_password = self.old_password_entry.get()
        new_password = self.new_password_entry.get()

        if old_password != new_password:
            pass
        else:
            messagebox.showerror("Error", "La contraseña nueva es identica a la ingresada.")
            return
        
        hashed_password = self.hash_password(old_password)
        hashed_new_password = self.hash_password(new_password)
        
        file_name = 'user_data.json'

        #Si el archivo existe, se procede a leerlo para comprobar la que la
        #contraseña actual es la misma que la que se ingreso en el programa
        
        if os.path.exists(file_name):
            with open(file_name, 'r') as file:
                user_data = json.load(file)
                stored_password = user_data.get('UPassword')
                
                if hashed_password == stored_password: #Si coincide la contraseña actual, se procede a cambiar la contraseña
                    user_data['UPassword'] = hashed_new_password
                    with open(file_name, 'w') as file:
                        json.dump(user_data, file)
                    messagebox.showinfo("Éxito", "Contraseña guardada exitosamente")
                    file.close()
                    self.change_window.destroy()
                else:
                    messagebox.showerror("Error", "Error al intentar cambiar la contraseña") 
        else:
            messagebox.showerror("Error", "Aún no existe un usuario para hacer un cambio de contraseña")
    
    #Función para definir el icono del programa (depende el sistema operativo)

    def set_icon(self):
        system = platform.system()
        system_banner = Figlet(font='sub-zero')
        text = system_banner.renderText(system)
        cprint(text, 'blue')
        if system == 'Windows':
            file = r'src\pyramid.ico'
            icon_file = self.resource_path(file)
        elif system == 'Linux':
            file = 'src/pyramid.png'
            icon_file = self.resource_path(file)
        else:
            print("Unsupported operating system. Defaulting to no icon.")
            return

        try:
            icon = tk.PhotoImage(file=icon_file)
            self.master.call('wm', 'iconphoto', self.master._w, icon)
        except tk.TclError:
            print(f"Icon file '{icon_file}' not found. Continuing without it.")
    
    
    #Inicio de las interfaces y funciones principales del programa
    #Apartado de interfaces numero 2
    
    def password_management(self):
        self.password_window = tk.Toplevel(self.master)
        self.password_window.title("Welcome")
        self.password_window.geometry("400x350")
        self.password_window.configure(bg="#1A1A1A")
        
        self.add_password_button = tk.Button(self.password_window, text="Añadir Contraseña", bg="#2A2A2A", fg="white", command=self.add_password)
        self.add_password_button.pack(pady=(30,10), padx=10, fill="both")
        
        self.get_password_button = tk.Button(self.password_window, text="Obtener Contraseña", bg="#2A2A2A", fg="white", command=self.get_password)
        self.get_password_button.pack(pady=10, padx=10, fill="both")
        
        self.delete_password_button = tk.Button(self.password_window, text="Borrar Contraseña", bg="#2A1111", fg="white", command=self.delete_password)
        self.delete_password_button.pack(pady=10, padx=10, fill="both")

        self.import_pass_button = tk.Button(self.password_window, text="Importar Contraseñas", bg="#2A2A2A", fg="white", command=self.import_password)
        self.import_pass_button.pack(pady=10, padx=10, fill="both")

        self.view_services_button = tk.Button(self.password_window, text="Ver Servicios", bg="#2A2A2A", fg="white", command=self.view_services)
        self.view_services_button.pack(pady=10, padx=10, fill="both")

        self.return_button = tk.Button(self.password_window, text="Volver", bg="#2A2A2A", fg="white", command=self.return_function)
        self.return_button.pack(pady=10, padx=10, fill="both")

    #Interfaz para añadir nuevas contraseñas
    
    def add_password(self):
        self.add_password_window = tk.Toplevel(self.master)
        self.add_password_window.title("Añadir Contraseña")
        self.add_password_window.geometry("400x250")
        self.add_password_window.configure(bg="#1A1A1A")
        self.gen_pass = None
        
        self.service_label = tk.Label(self.add_password_window, text="Servicio:", bg="#2A2A2A", fg="white") #Importante ingresar el servicio como primera acción
        self.service_label.pack(pady=5)
        self.service_entry = tk.Entry(self.add_password_window)
        self.service_entry.pack(pady=5)
        
        self.password_label = tk.Label(self.add_password_window, text="Contraseña:", bg="#2A2A2A", fg="white") #Dejar este espacio en blanco si solo deseas generar una contraseña nueva
        self.password_label.pack(pady=5)
        self.password_entry = tk.Entry(self.add_password_window, show="*")
        self.password_entry.pack(pady=5)
        
        self.add_password_button = tk.Button(self.add_password_window, text="Añadir Contraseña", bg="#2A2A5A", fg="white", command=self.save_password)
        self.add_password_button.pack(pady=10)

        #Si deseas generar una contraseña aleatoria, debes primero ingresar el nombre del servicio que le pondrás para identificarlo en la libreria JSON

        self.gen_password_button = tk.Button(self.add_password_window, text="Generar Contraseña", bg="#6A2A2A", fg="white", command=self.generate_password)
        self.gen_password_button.pack(pady=10)
    
    #Interfaz para generar contraseña (Esta interfaz se genera a travez de la interfaz "add_password")
    #El maximo de caracteres a escoger es 20
    
    def generate_password(self):
        self.gen_password_window = tk.Toplevel(self.master)
        self.gen_password_window.title("Generar contraseña")
        self.gen_password_window.geometry("500x200")
        self.gen_password_window.configure(bg="#1A1A1A")
        
        self.gen_label = tk.Label(self.gen_password_window, text="Ingrese el numero de carácteres en la contraseña:", bg="#2A2A2A", fg="white")
        self.gen_label.pack(pady=5)
        self.gen_entry = tk.Entry(self.gen_password_window)
        self.gen_entry.pack(pady=5)

        self.gen_password_button = tk.Button(self.gen_password_window, text="Generar Contraseña", bg="#6A2A2A", fg="white", command=self.gen_password)
        self.gen_password_button.pack(pady=10)

    #Interfaz para obtener la contraseña guardada

    def get_password(self):
        self.get_password_window = tk.Toplevel(self.master)
        self.get_password_window.title("Obtener Contraseña")
        self.get_password_window.geometry("400x200")
        self.get_password_window.configure(bg="#1A1A1A")
        
        self.service_label = tk.Label(self.get_password_window, text="Servicio:", bg="#2A2A2A", fg="white")
        self.service_label.pack(pady=5)
        self.service_entry = tk.Entry(self.get_password_window)
        self.service_entry.pack(pady=5)
        
        self.get_password_button = tk.Button(self.get_password_window, text="Obtener Contraseña", bg="#2A2A5A", fg="white", command=self.retrieve_password)
        self.get_password_button.pack(pady=10)
    
    #Interfaz para borrar una contraseña guardada
    
    def delete_password(self):
        self.delete_password_window = tk.Toplevel(self.master)
        self.delete_password_window.title("Eliminar Contraseña")
        self.delete_password_window.geometry("400x200")
        self.delete_password_window.configure(bg='#BB3333')

        self.service_label = tk.Label(self.delete_password_window, text= "Servicio:", bg="#BB3333", fg="white")
        self.service_label.pack(pady=5)
        self.service_entry = tk.Entry(self.delete_password_window)
        self.service_entry.pack(pady=5)

        self.delete_password_button = tk.Button(self.delete_password_window, text="Borrar contraseña", bg="#AA1111", fg="white", command=self.deleted_password)
        self.delete_password_button.pack(pady=10)
    
    #Interfaz para importar contraseñas desde firefox o chrome

    def import_password(self):
        self.import_password_window = tk.Toplevel(self.master)
        self.import_password_window.title("Importar Contraseñas")
        self.import_password_window.geometry("400x200")
        self.import_password_window.configure(bg="#1A1A1A")

        # self.firefox_button = tk.Button(self.import_password_window, text="Importar desde Firefox", bg="#2A2A2A", fg="white", command=self.importar_firefox)  
        # self.firefox_button.pack(pady=5)  
        self.chrome_button = tk.Button(self.import_password_window, text="Importar desde Chrome", bg="#2A2A2A", fg="white", command=self.import_chrome)       
        self.chrome_button.pack(pady=5) 

    #Apartado de funciones numero 2
    #Función para guardar la contraseña ingresada junto con su servicio
    
    def save_password(self):
        if self.gen_pass != None:
            password = self.gen_pass
        else:
            password = self.password_entry.get()
        service = self.service_entry.get()
        cipher = self.encrypted_key()
        encrypted_password = self.encrypt_password(cipher, password)
        file_name = 'passwords.json'
        
        if not os.path.exists(file_name) or os.stat(file_name).st_size <= 0:
            data = []
        else:
            with open('passwords.json', 'r') as file:
                data = json.load(file)
        
        new_password = {'Servicio': service, 'Contraseña': encrypted_password}
        data.append(new_password)
        
        with open('passwords.json','w') as file:
            json.dump(data, file, indent=4)
        self.master.clipboard_clear()
        self.master.clipboard_append(password)
        self.master.update()
        messagebox.showinfo("Contraseña Añadida", "Contraseña añadida exitosamente y copiada al portapapeles")
        self.add_password_window.destroy()

    #Función para generar una contraseña

    def gen_password(self):
        length = int(self.gen_entry.get())
        if length != 0 and length <= 20:
            pass
        else:
            messagebox.showerror("Error", "La longitud de la contraseña debe ser de máximo 20 caracteres.")
            return
        characters = string.ascii_letters + string.digits + string.punctuation
        password = "".join(random.choice(characters) for i in range(length))
        self.gen_pass = password
        self.gen_password_window.destroy()
        self.save_password()
    
    #Función para obtener una contraseña

    def retrieve_password(self):
        service = self.service_entry.get()
        cipher = self.encrypted_key()
        file_name = 'passwords.json'
        
        if not os.path.exists(file_name) or os.stat(file_name).st_size <= 0:
            messagebox.showerror("Error", "No hay contraseñas almacenadas")
            return
        try:
            with open(file_name, 'r' ) as file:
                data = json.load(file)
        except json.decoder.JSONDecodeError:
            data = {}
            messagebox.showerror("Error", "Contraseñas sin formato válido")
            return
        
        for i in data:
            if i['Servicio'] == service:
                decrypted_password = self.decrypt_password(cipher, i['Contraseña'])
                self.master.clipboard_clear()
                self.master.clipboard_append(decrypted_password)
                self.master.update()
                messagebox.showinfo("Contraseña Obtenida", f"{service}\nContraseña copiada al portapapeles")
                self.get_password_window.destroy()
                return
        messagebox.showerror("Error", "Contraseña no encontrada.")

    #Función para borrar una contraseña
 
    def deleted_password(self):
        service = self.service_entry.get()
        file_name = 'passwords.json'

        if not os.path.exists(file_name) or os.stat(file_name).st_size == 0:
            messagebox.showinfo("Info","Sin contraseñas por eliminar.")
            self.delete_password_window.destroy()
        try:
            with open('passwords.json', 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            messagebox.showerror("Error", "Contraseña no encontrada")
            return
        
        password_E = False
        for i, item in enumerate(data):
            if item['Servicio'] == service:
                del data[i]
                password_E = True
                break

        if password_E:
            with open(file_name, 'w') as file:
                json.dump(data, file, indent=4)
            messagebox.showinfo("Contraseña borrada", f"Contraseña borrada: {service}\n")
            self.view_services()
            self.view_services_window.destroy()
            self.delete_password_window.destroy()
        else:
            messagebox.showinfo("Info", "No se encontraron contraseñas")
            self.delete_password_window.destroy()

    
    #Función para importar una contraseña desde chrome

    """
    ***FUNCION EXPERIMENTAL***
    ***AUN EN DESARROLLO (FEDORA 40)***
    ***PROXIMAMENTE EN WINDOWS***
    """

    def import_chrome(self):
        cipher = self.encrypted_key()
        messagebox.showinfo("Warning", "Experimental Function, only available on Fedora 40")
        print("Starting Chrome passwords import...")

        key = self.get_chrome_decryption_key()
        print(key)
        if key is None:
            print("Failed to retrieve encryption key.")
            return

        USER = os.environ.get("USER")
        chrome_password_file = f"/home/{USER}/.config/google-chrome/Default/Login Data"

        if not os.path.exists(chrome_password_file):
            messagebox.showerror("Error", "No saved passwords found")
            print("Password file not found:", chrome_password_file)
            return

        filename = "./Loginvault.db"
        shutil.copy2(chrome_password_file, filename)
        print("Password file copied to Loginvault.db")

        db = sqlite3.connect(filename)
        cursor = db.cursor()
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        passwords = cursor.fetchall()
        print(f"Passwords found in database: {len(passwords)}")

        if not passwords:
            messagebox.showerror("Error", "No passwords found in database.")
            return

        all_passwords = []
        existing_services = set()  # Conjunto para mantener servicios únicos

        for index, login in enumerate(passwords):
            if len(login) < 3:
                print(f"Skipping incomplete entry at index {index}: {login}")
                continue

            url = login[0]
            service = login[1].strip()
            encrypted_chrome_password = login[2]
            print(f"password encrypted: {encrypted_chrome_password}")
            decrypted_password = self.decrypt_chrome_password(encrypted_chrome_password, key)
            print(f"Decrypted password for {url} {service}: {decrypted_password}")

            if not url and not service in existing_services:
                continue  

            existing_services.add(service)

            if service == '':
                service = ''.join(random.choices(string.ascii_letters + string.digits, k=10))

            if not decrypted_password:
                continue
            encrypted_password = self.encrypt_password(cipher, decrypted_password)
            password_entry = {'Url': url, 'Servicio': service, 'Contraseña': encrypted_password}
            all_passwords.append(password_entry)

        cursor.close()
        db.close()
        self.save_passwords(all_passwords)
        if self.import_password_window:
            self.import_password_window.destroy()
        print("Password import completed.")

    def save_passwords(self, passwords):
        file_name = 'passwords.json'
        if not os.path.exists(file_name) or os.stat(file_name).st_size <= 0:
            data = []
        else:
            with open(file_name, 'r') as file:
                data = json.load(file)

        data.extend(passwords)

        with open(file_name, 'w') as file:
            json.dump(data, file, indent=4)
        print("Passwords saved to passwords.json")

    def decrypt_chrome_password(self, encrypted_password, key):
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'saltysalt',
                iterations=1003,
                backend=default_backend()
            )
            aes_key = kdf.derive(key)
            iv = encrypted_password[:12]
            encrypted_password = encrypted_password[12:]
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()

            return decrypted_password.decode('utf-8')
        
        except Exception as e:
            print(f"Error decrypting password: {e}")
            return None

    def get_chrome_decryption_key(self):
        entries = [
            ('application', 'chrome')
        ]

        for entry in entries:
            try:
                result = subprocess.run(
                    ['secret-tool', 'lookup', entry[0], entry[1]],
                    capture_output=True,
                    text=True
                )

                if result.returncode == 0:
                    return base64.b64decode(result.stdout.strip())
                else:
                    print(f"Failed to retrieve encryption key from {entry}. Return code: {result.returncode}")
                    print("Error output:", result.stderr)
            except Exception as e:
                print(f"Error retrieving encryption key from {entry}: {e}")

        print("Failed to retrieve encryption key from any known entry.")
        return None
    
    #Funcion e interfaz para ver y buscar servicios

    def view_services(self):
        self.view_services_window = tk.Toplevel(self.master)
        self.view_services_window.title("Servicios Guardados")
        self.view_services_window.geometry("400x300")
        self.view_services_window.configure(bg="#1A1A1A")

        scrollbar = ttk.Scrollbar(self.view_services_window, orient=tk.VERTICAL) #Scrollbar para navegar a través de una libreria extensa
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        try:
            with open('passwords.json') as file:
                view = json.load(file)
                services_label = tk.Label(self.view_services_window, text="Servicios Guardados:", bg="#1A1A1A", fg="white")
                services_label.pack(pady=5)
                
                self.service_listbox= tk.Listbox(self.view_services_window, yscrollcommand=scrollbar.set, bg="#1A1A1A", fg="white")
                for x in view:
                    self.service_listbox.insert(tk.END, f"- {x['Servicio']}")
                self.service_listbox.pack(fill=tk.BOTH, expand=True)

                scrollbar.config(command=self.service_listbox.yview)
        
        except FileNotFoundError:
            messagebox.showerror("Error", "No se ha encontrado ninguna contraseña ni ningún servicio asociado")
            self.view_services_window.destroy()
        
        self.search_entry = ttk.Entry(self.view_services_window)
        self.search_entry.pack(pady=5)
        self.search_entry.bind("<KeyRelease>", self.filter_services) 

        """
        Con ayuda del keyrelease y un sistema de filtrado, 
        puedes buscar la contraseña que quieras a tiempo real
        
        """

    #Función para la busqueda activa de contraseñas

    def filter_services(self, event):
        search_term = self.search_entry.get().lower()
        self.service_listbox.delete(0, tk.END) 

        with open('passwords.json') as file:
            view = json.load(file)
            for x in view:
                if search_term in x['Servicio'].lower():
                    self.service_listbox.insert(tk.END, f"- {x['Servicio']}")

    #Apartado de funciones 3
    #Este apartado sirve para pasar un valor, decodificarlo o encriptarlo, para al final ser insertado en un objeto

    #Funcion para encriptar las contraseñas
    
    def hash_password(self, password):
        sha256 = hashlib.sha256()
        sha256.update(password.encode('utf-8'))
        return sha256.hexdigest()
    
    #Encriptacion de contraseñas
    
    def encrypt_password(self, cipher, password):
        return cipher.encrypt(password.encode()).decode()
    
    #Decriptación de contraseñas
    
    def decrypt_password(self, cipher, encrypted_password):
        return cipher.decrypt(encrypted_password.encode()).decode()
    
    #Generación de una llave Fernet unica para poder desencriptar o encriptar las contraseñas

    def gen_key(self):
        return Fernet.generate_key()
    
    #Inicialización del cifrado para encriptar la llave generada

    def initialize_cypher(self, key):
        return Fernet(key)

    #Encriptar la llave generada
    
    def encrypted_key(self):
        key_file = 'fernet_key.key'
        if os.path.exists(key_file):
            if os.stat(key_file).st_size > 0:
                with open(key_file,'rb') as f:
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
    
    #Función para finalizar el programa
    
    def return_function(self):
        self.password_window.destroy()

    #Volver a el inicio de sesión
    
    def quit(self):
        self.master.destroy()
    
    #Convertir una ruta absoluta a una ruta relativa

    def resource_path(self, relative_path):
        base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)
    
    #Version
    
    def show_about(self):
        messagebox.showinfo("Acerca de", f"PMUID versión {__version__}\nDesarrollado por Stroop Lab")


#Inicialización del programa

def cargando():
    frames = [
        "[      ]",
        "[*     ]",
        "[**    ]",
        "[ ***  ]",
        "[  *** ]",
        "[   ***]",
        "[    **]",
        "[     *]",
    ]

    duration = 3  
    interval = 0.2  

    start_time = time.time()
    end_time = start_time + duration

    while time.time() < end_time:
        for frame in frames:
            print(frame, end="\r")
            time.sleep(interval)

    print("[ Bienvenido ]")
    time.sleep(1)
    os.system('clear')

def main():
    cprint("Cargando...", "cyan")
    cargando()
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()

if __name__ == "__main__":
    try:
        os.system('clear')
        main()
    except KeyboardInterrupt:
        print('\n[*] Abortado')
        exit(0)
    except Exception as e:
        print('[!] ERROR: ' + str(e))
