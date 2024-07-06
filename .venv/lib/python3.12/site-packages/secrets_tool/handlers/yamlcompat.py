"""
Classes to encrypt and decrypt YAML files.

This 'compatibility' handler doesn't need additional tags in the YAML files. Instead, the desired paths
to en- and decrypt are given in the .gitignore file

The desired paths for encryption MUST refer to a string field.
"""
from pathlib import Path
from typing import List

import ruamel.yaml

from .. import cipher


def getitem(obj, path: str):
    if len(path) == 0:
        return obj

    path_parts = path.split('.', maxsplit=1)
    key = path_parts[0]
    remainder = path_parts[1] if len(path_parts) > 1 else ''

    if isinstance(obj, dict):
        return getitem(obj[key], remainder)
    if isinstance(obj, list):
        return getitem(obj[int(key)], remainder)
    else:
        ValueError('Cant read object', obj)


def setitem(root, path, value):
    if path.find('.') < 0:
        obj = root
        key = path
    else:
        obj = getitem(root, path.rsplit('.', maxsplit=1)[0])
        key = path.rsplit('.', maxsplit=1)[1]

    if isinstance(obj, dict):
        obj[key] = value
    elif isinstance(obj, list):
        obj[int(key)] = value
    else:
        ValueError('Cant write object', obj)


class YamlCompatFileHandler:
    def __init__(self, filepath: Path, data: List[str]):
        self.yaml = ruamel.yaml.YAML()

        self.filepath = filepath
        self.data = data

    def dump_decrypted(self, target: Path, key: bytes):
        tree = self.yaml.load(self.filepath)

        for path in self.data:
            encrypted = getitem(tree, path)
            decrypted = cipher.decrypt(encrypted.encode('ascii'), key).decode('utf8')

            setitem(tree, path, decrypted)

        self.yaml.dump(tree, target)

    def dump_encrypted(self, target: Path, key: bytes):
        tree = self.yaml.load(self.filepath)

        for path in self.data:
            decrypted = getitem(tree, path)
            encrypted = cipher.encrypt(decrypted.encode('utf8'), key, path.encode('ascii')).decode('ascii')

            setitem(tree, path, encrypted)

        self.yaml.dump(tree, target)
