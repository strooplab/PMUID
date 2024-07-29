import os, platform
from setuptools import setup, find_packages
from setuptools.command.install import install
from shutil import copytree
from src.version import __version__

def package_files(directory):
    paths = []
    for (path, directories, filenames) in os.walk(directory):
        for filename in filenames:
            paths.append(os.path.join('gen', os.path.relpath(os.path.join(path, filename), directory)))
    return paths

class PostInstallCommand(install):
    """Post-installation for installation mode."""
    def run(self):
        install.run(self)
        self.create_desktop_entry()
        self.create_required_directories()
        self.copy_media_files()
        
    def create_desktop_entry(self):
        desktop_entry = """[Desktop Entry]
        Name=pmuid
        Comment=PMUID
        Exec=python3 /usr/local/bin/pmuid
        Icon=~/PMUID/src/media/pyramid.png
        Terminal=True
        Type=Application
        Categories=Utility;
        """
        desktop_entry_path = os.path.expanduser('~/.local/share/applications/pmuid.desktop')
        with open(desktop_entry_path, 'w') as f:
            f.write(desktop_entry)
    
    def create_required_directories(self):
        install_lib = self.install_lib
        if install_lib is None:
            return

        gen_dir = os.path.join(install_lib, 'gen')
        media_dir = os.path.join(install_lib, 'media')

        for directory in [gen_dir, media_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory)
    
    def copy_media_files(self):
        install_lib = self.install_lib
        if install_lib is None:
            return

        media_src = os.path.join(os.path.dirname(__file__), 'src', 'media') 
        media_dest = os.path.join(install_lib, 'media')
        gen_src = os.path.join(os.path.dirname(__file__), 'src', 'gen') 
        gen_dest = os.path.join(install_lib, 'gen')

        try:
            copytree(media_src, media_dest, dirs_exist_ok=True)
            copytree(gen_src, gen_dest, dirs_exist_ok=True)
        except FileNotFoundError as e:
            print(f"Warning: {e}")

install_requires=[
        'certifi',
        'cffi',
        'charset-normalizer',
        'cryptography',
        'idna',
        'pycparser',
        'pyfiglet',
        'requests',
        'setuptools',
        'termcolor',
        'tk',
        'urllib3',
    ]

if platform.system() == 'Linux':
    install_requires.extend([
        'library-linux-only',
    ])
elif platform.system() == 'Windows':
    install_requires.extend([
        'library-windows-only',
    ])

setup(
    name="pmuid",
    version=__version__,
    packages=find_packages(where='src'),
    install_requires=install_requires,
    package_dir={'': 'src'},
    package_data={
        '': package_files('src/gen') + ['media/*'],
    },
    py_modules=['pmuid', 'version'],
    
    entry_points={
        'console_scripts': [
            'pmuid = pmuid:main'
        ]
    },
    cmdclass={
        'install': PostInstallCommand,
    }
)
