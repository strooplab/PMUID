.PHONY:

help:
	@echo "Comandos disponibles:"
	@echo "make install   - Instalacion del proyecto"
	@echo "make clean     - Limpia los archivos temporales"

install:
	pip install .
clean:
	rm -rf build dist *.egg-info