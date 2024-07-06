"""
Classes to encrypt and decrypt YAML files

- Encryption operation will look for fields with the "!decrypted" hint and replace them with an encrypted version of
  their content. This will be marked with the "!encrypted" hint
- Decryption operation will look for fields with the "!encrypted" hint and replace them with a decrypted version of
  their content. This will be marked with the "!decrypted" hint
"""
from pathlib import Path
from typing import List

import ruamel.yaml

from .. import cipher


class DecryptedString:
    yaml_tag = '!decrypted'

    def __init__(self, data: str):
        self.data = data

    @classmethod
    def from_encrypted(cls, data: str, key):
        return cls(cipher.decrypt(data.encode('ascii'), key).decode('utf8'))

    @classmethod
    def from_yaml(cls, constructor, node):
        return cls(node.value)

    @classmethod
    def to_yaml(cls, representer, node):
        return representer.represent_scalar(cls.yaml_tag, node.data)


class EncryptedString:
    yaml_tag = '!encrypted'

    def __init__(self, data: str):
        self.data = data

    @classmethod
    def from_decrypted(cls, data: str, key: bytes, iv: bytes):
        return cls(cipher.encrypt(data.encode('utf8'), key, iv).decode('ascii'))

    @classmethod
    def from_yaml(cls, constructor, node):
        return cls(node.value)

    @classmethod
    def to_yaml(cls, representer, node):
        return representer.represent_scalar(cls.yaml_tag, node.data)


class YamlFileHandler:
    def __init__(self, filepath: Path, data: List[str]):
        self.yaml = ruamel.yaml.YAML()
        self.yaml.register_class(DecryptedString)
        self.yaml.register_class(EncryptedString)

        self.filepath = filepath

    def dump_decrypted(self, target: Path, key: bytes):
        tree = self.yaml.load(self.filepath)

        self._walk_item(tree, EncryptedString,
                        lambda enc_string, iv: DecryptedString.from_encrypted(enc_string.data, key))

        self.yaml.dump(tree, target)

    def dump_encrypted(self, target: Path, key: bytes):
        tree = self.yaml.load(self.filepath)

        self._walk_item(tree, DecryptedString,
                        lambda dec_string, iv: EncryptedString.from_decrypted(dec_string.data, key, iv.encode('utf8')))

        self.yaml.dump(tree, target)

    def _walk_item(self, item, type_, callback, path=''):
        if isinstance(item, dict):
            for key in item.keys():
                if isinstance(item[key], type_):
                    item[key] = callback(item[key], path + f'.{key}')
                else:
                    self._walk_item(item[key], type_, callback, path=path + f'.{key}')
        elif isinstance(item, list):
            for i in range(len(item)):
                if isinstance(item[i], type_):
                    item[i] = callback(item[i], path + f'.{i}')
                else:
                    self._walk_item(item[i], type_, callback, path=path + f'.{i}')
