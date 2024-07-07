# PMUID - Password Manager

Bienvenido a PMUID! Este es un software de administración de contraseñas que permite almacenar y recuperar contraseñas de forma segura. Para utilizarlo, primero debes crear una cuenta ingresando un nombre de usuario y una contraseña. Esta es la única contraseña que deberás memorizar, ¡guárdala en un lugar seguro! Una vez que hayas creado una cuenta, podrás comenzar a almacenar tus contraseñas. ¡Espero disfrutes esta nueva opción para guardar tus contraseñas en tu propio entorno!

## Versión

Versión actual: 1.1

## Requisitos

- Python 3.6 o superior
- Tkinter
- PyFiglet
- Termcolor
- Cryptography

## Instalación

Para instalar las dependencias necesarias, ejecuta:

```bash
pip install tk pyfiglet termcolor cryptography
```

## Uso

Para iniciar el programa, simplemente ejecuta el script PMUID.py:

```bash
./password_manager.py
```

## Disponible en Windows y Linux

El ejecutable .exe de windows se encuentra dentro de la carpeta "dist"

Para linux esta el archivo Python "PMUID.py" ejecutable dentro de bash, zsh o cualquier shell

## Funciones Principales

## 1. Registro de Usuario


- Al iniciar el programa, haz clic en Registrar.
- Ingresa un nombre de usuario y una contraseña.
- Haz clic en Registrar para guardar tus datos. Esta será la única contraseña que necesitarás recordar.

***IMPORTANTE***

Esta contraseña no puede ser olvidada, ya que dentro del programa se crea una clave unica
para poder encriptar las contraseñas, debes conservar todos los datos devueltos
por la aplicación

## 2. Iniciar Sesión

- Haz clic en Ingresar.
- Ingresa tu nombre de usuario y contraseña.
- Haz clic en Ingresar para acceder al gestor de contraseñas.

## 3. Añadir Contraseña

- Haz clic en Añadir Contraseña.
- Ingresa el nombre del servicio y la contraseña. Si deseas generar una contraseña aleatoria, 
    primero debes ingresar el nombre del servicio, luego
    haz clic en Generar Contraseña e ingresa el número de caracteres (máximo 20).
- Haz clic en Añadir Contraseña para guardar la contraseña.

## 4. Obtener Contraseña

- Haz clic en Obtener Contraseña.
- Ingresa el nombre del servicio.
- Haz clic en Obtener Contraseña para que pueda ser copiada al portapapeles.

Si no estas seguro del nombre de tu servicio, puedes verificar en el boton
"Ver Servicios"

## 5. Borrar Contraseña

- Haz clic en Borrar Contraseña.
- Ingresa el nombre del servicio.
- Haz clic en Borrar Contraseña para eliminar la contraseña. Facil y sencillo


## 6. Importar Contraseñas 

***FUNCION EXPERIMENTAL (DISPONIBLE SOLO EN FEDORA 40)***

- Haz clic en Importar Contraseñas.
- Selecciona el navegador desde el cual deseas importar las contraseñas (actualmente soportado: Chrome).

## 7. Ver Servicios

- Haz clic en Ver Servicios para listar todos los servicios con contraseñas almacenadas.

## 8. Salir del Programa

- Haz clic en Salir para cerrar el programa.

## Contribuciones

Las contribuciones son bienvenidas. Si encuentras algún problema o tienes una mejora que te gustaría sugerir, por favor abre un issue o un pull request.
Licencia

## Este proyecto está bajo la Licencia MIT.


Este archivo README.md proporciona una guía completa sobre cómo instalar, usar y contribuir al programa PMUID.

