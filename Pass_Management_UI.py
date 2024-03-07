import tkinter as tk
from tkinter import messagebox
import json, hashlib, os, pyperclip, string, random, sys
from cryptography.fernet import Fernet

class PasswordManager:
    def __init__(self, master):
        self.master = master
        file = "src\pyramid.ico"
        icon_file = self.resource_path(file)
        print("Icon File Path: ",icon_file)
        self.master.iconbitmap(True , default=icon_file)  # Set
        self.master.title("P4ssw0rd_M4n4g3R")
        self.master.geometry("400x300")
        self.master.configure(bg="#121212")
        
        self.password_manager_frame = tk.Frame(self.master, bg="#1A1A1A")
        self.password_manager_frame.pack(expand=True, fill="both")
        
        self.register_button = tk.Button(self.password_manager_frame, text="Registrar", bg="#2A2A2A", fg="white", command=self.register)
        self.register_button.pack(pady=(70,10), padx=10, fill="both")
        
        self.login_button = tk.Button(self.password_manager_frame, text="Ingresar", bg="#2A2A2A", fg="white", command=self.login)
        self.login_button.pack(pady=10, padx=10, fill="both")

        self.change_pass_button = tk.Button(self.password_manager_frame, text="Cambiar Contraseña", bg="#2A2A2A", fg="white", command=self.change_password)
        self.change_pass_button.pack(pady=10, padx=10, fill="both")

        self.quit_button = tk.Button(self.password_manager_frame, text="Salir", bg="#2A2A2A", fg="white", command=self.quit)
        self.quit_button.pack(pady=10, padx=10, fill="both")

    
    def hash_password(self, password):
        sha256 = hashlib.sha256()
        sha256.update(password.encode('utf-8'))
        return sha256.hexdigest()

    
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
        
        if os.path.exists(file_name):
            with open(file_name, 'r') as file:
                user_data = json.load(file)
                stored_password = user_data.get('UPassword')
                
                if hashed_password == stored_password:
                    user_data['UPassword'] = hashed_new_password
                    with open(file_name, 'w') as file:
                        json.dump(user_data, file)
                    messagebox.showinfo("Éxito", "Contraseña guardada exitosamente")
                    file.close()
                    self.change_window.destroy()
                else:
                    messagebox.showerror("Error", "Error al intentar cambiar la contraseña")
        else:
            messagebox.showerror("Error", "Usuario no registrado")
        
    def save_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        hashed_password = self.hash_password(password)
        
        user_data = {'Username': username, 'UPassword': hashed_password}
        file_name = 'user_data.json'
        
        if os.path.exists(file_name):
            messagebox.showerror("Error", "Usuario ya registrado")
        else:
            with open(file_name, 'w+') as file:
                json.dump(user_data, file)
                messagebox.showinfo("Registro Completado", "Usuario registrado exitosamente")
                self.register_window.destroy()
    
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
    
    def password_management(self):
        self.password_window = tk.Toplevel(self.master)
        self.password_window.title("P4ssw0rd_M4n4g3R")
        self.password_window.geometry("400x300")
        self.password_window.configure(bg="#1A1A1A")
        
        self.add_password_button = tk.Button(self.password_window, text="Añadir Contraseña", bg="#2A2A2A", fg="white", command=self.add_password)
        self.add_password_button.pack(pady=(50,10), padx=10, fill="both")
        
        self.get_password_button = tk.Button(self.password_window, text="Obtener Contraseña", bg="#2A2A2A", fg="white", command=self.get_password)
        self.get_password_button.pack(pady=10, padx=10, fill="both")
        
        self.delete_password_button = tk.Button(self.password_window, text="Borrar Contraseña", bg="#2A1111", fg="white", command=self.delete_password)
        self.delete_password_button.pack(pady=10, padx=10, fill="both")

        self.view_services_button = tk.Button(self.password_window, text="Ver Servicios", bg="#2A2A2A", fg="white", command=self.view_services)
        self.view_services_button.pack(pady=10, padx=10, fill="both")

        self.return_button = tk.Button(self.password_window, text="Volver", bg="#2A2A2A", fg="white", command=self.return_function)
        self.return_button.pack(pady=10, padx=10, fill="both")
    
    def add_password(self):
        self.add_password_window = tk.Toplevel(self.master)
        self.add_password_window.title("Añadir Contraseña")
        self.add_password_window.geometry("400x200")
        self.add_password_window.configure(bg="#1A1A1A")
        
        self.service_label = tk.Label(self.add_password_window, text="Servicio:", bg="#2A2A2A", fg="white")
        self.service_label.pack(pady=5)
        self.service_entry = tk.Entry(self.add_password_window)
        self.service_entry.pack(pady=5)
        
        self.password_label = tk.Label(self.add_password_window, text="Contraseña:", bg="#2A2A2A", fg="white")
        self.password_label.pack(pady=5)
        self.password_entry = tk.Entry(self.add_password_window, show="*")
        self.password_entry.pack(pady=5)
        
        self.add_password_button = tk.Button(self.add_password_window, text="Añadir Contraseña", bg="#2A2A5A", fg="white", command=self.save_password)
        self.add_password_button.pack(pady=10)

        self.gen_password_button = tk.Button(self.add_password_window, text="Generar Contraseña", bg="#6A2A2A", fg="white", command=self.generate_password)
        self.gen_password_button.pack(pady=10)
    
    def save_password(self):
        if self.gen_pass != '':
            password = self.gen_pass
        else:
            password = self.password_entry.get()
        service = self.service_entry.get()
        cipher = self.encrypted_key()
        encrypted_password = self.encrypt_password(cipher, password)
        
        if not os.path.exists('passwords.json'):
            data = []
        else:
            with open('passwords.json', 'r') as file:
                data = json.load(file)
        
        new_password = {'Servicio': service, 'Contraseña': encrypted_password}
        data.append(new_password)
        
        with open('passwords.json','w') as file:
            json.dump(data, file, indent=4)
        
        messagebox.showinfo("Contraseña Añadida", "Contraseña añadida exitosamente")
        self.add_password_window.destroy()

    def generate_password(self):
        self.gen_password_window = tk.Toplevel(self.master)
        self.gen_password_window.title("Generar contraseña")
        self.gen_password_window.geometry("400x200")
        self.gen_password_window.configure(bg="#1A1A1A")
        
        self.gen_label = tk.Label(self.gen_password_window, text="Ingrese el numero de carácteres en la contraseña:", bg="#2A2A2A", fg="white")
        self.gen_label.pack(pady=5)
        self.gen_entry = tk.Entry(self.gen_password_window)
        self.gen_entry.pack(pady=5)

        self.gen_password_button = tk.Button(self.gen_password_window, text="Generar Contraseña", bg="#6A2A2A", fg="white", command=self.gen_password)
        self.gen_password_button.pack(pady=10)

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

    def retrieve_password(self):
        service = self.service_entry.get()
        cipher = self.encrypted_key()
        
        if not os.path.exists('passwords.json'):
            messagebox.showerror("Error", "No hay contraseñas almacenadas")
            return
        
        with open('passwords.json', 'r') as file:
            data = json.load(file)
        
        for i in data:
            if i['Servicio'] == service:
                decrypted_password = self.decrypt_password(cipher, i['Contraseña'])
                pyperclip.copy(decrypted_password)
                messagebox.showinfo("Contraseña Obtenida", f"{service}: {decrypted_password}\nContraseña copiada al portapapeles")
                self.get_password_window.destroy()
                return
        
        messagebox.showerror("Error", "Contraseña no encontrada.")

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
 
    def deleted_password(self):
        service = self.service_entry.get()

        if not os.path.exists('passwords.json'):
            messagebox.showinfo("Info","La contraseña no ha sido guardada.")
            return
        try:
            with open('passwords.json', 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            data = []
            messagebox.showerror("Error", "Contraseña no encontrada")
        for i, item in enumerate(data):
            if item['Servicio'] == service:
                del data[i]
                messagebox.showinfo("Contraseña borrada", f"Contraseña borrada: {service}\n")
                self.delete_password_window.destroy()
                break 
        with open('passwords.json', 'w') as file:
            json.dump(data, file, indent=4)
        self.view_services()
        self.view_services_window.destroy()
    
    def view_services(self):
        self.view_services_window = tk.Toplevel(self.master)
        self.view_services_window.title("Servicios Guardados")
        self.view_services_window.geometry("400x300")
        self.view_services_window.configure(bg="#1A1A1A")
        
        try:
            with open('passwords.json') as file:
                view = json.load(file)
                services_label = tk.Label(self.view_services_window, text="Servicios Guardados:", bg="#1A1A1A", fg="white")
                services_label.pack(pady=5)
                
                for x in view:
                    service_label = tk.Label(self.view_services_window, text=f"- {x['Servicio']}", bg="#1A1A1A", fg="white")
                    service_label.pack()
        
        except FileNotFoundError:
            messagebox.showerror("Error", "No se ha encontrado ninguna contraseña ni ningún servicio asociado")
            self.view_services_window.destroy()
    
    def encrypt_password(self, cipher, password):
        return cipher.encrypt(password.encode()).decode()
    
    def decrypt_password(self, cipher, encrypted_password):
        return cipher.decrypt(encrypted_password.encode()).decode()

    def gen_key(self):
        return Fernet.generate_key()
    
    def initialize_cypher(self, key):
        return Fernet(key)
    
    def encrypted_key(self):
        key_file = 'fernet_key.key'
        if os.path.exists(key_file):
            with open(key_file,'rb') as f:
                key = f.read()
        else:
            key = self.gen_key()
            with open(key_file, 'wb') as file:
                file.write(key)
        
        cipher = self.initialize_cypher(key)
        return cipher
    
    def return_function(self):
        self.password_window.destroy()
    
    def quit(self):
        self.master.destroy()

    def resource_path(self,relative_path):
        
        base_path = os.path.abspath(".")
        return os.path.join(base_path,relative_path)

def main():
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()

if __name__ == "__main__":
    main()
