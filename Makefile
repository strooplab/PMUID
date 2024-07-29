.PHONY:

help:
	@echo "Comandos disponibles:"
	@echo "make install   - Instalacion del proyecto"
	@echo "make clean     - Limpia los archivos temporales"

install:
	@echo "Instalando dependencias necesarias..."
    @pip install -r requirements.txt
    @if [ "$(shell uname)" = "Linux" ]; then \
        pip install -r requirements.txt; \
    elif [ "$(shell uname -o)" = "Msys" ]; then \
        pip install -r requirements-windows.txt; \
    fi
clean:
	rm -rf build dist *.egg-info