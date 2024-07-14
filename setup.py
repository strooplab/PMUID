import os
from setuptools import setup, find_packages
from setuptools.command.install import install
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

    def create_desktop_entry(self):
        desktop_entry = """[Desktop Entry]
        Name=pmuid
        Comment=PMUID
        Exec=python3 /usr/local/bin/pmuid
        Icon=/usr/local/share/pmuid/icon.png
        Terminal=false
        Type=Application
        Categories=Utility;
        """
        desktop_entry_path = os.path.expanduser('~/.local/share/applications/pmuid.desktop')
        with open(desktop_entry_path, 'w') as f:
            f.write(desktop_entry)

setup(
    name="pmuid",
    version=__version__,
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    package_data={
        '': package_files('src/gen') + ['media/*'],
    },
    py_modules=['pmuid', 'version'],
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
    ],
    entry_points={
        'console_scripts': [
            'pmuid = pmuid:main'
        ]
    },
    cmdclass={
        'install': PostInstallCommand,
    }
)
