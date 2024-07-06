from pathlib import Path
from typing import List

from .. import cipher


class GenericFileHandler:
    def __init__(self, filepath: Path, data: List[str]):
        self.filepath = filepath

    def dump_decrypted(self, target: Path, key: bytes):
        target.write_bytes(cipher.decrypt(self.filepath.read_bytes(), key))

    def dump_encrypted(self, target: Path, key: bytes):
        target.write_bytes(cipher.encrypt(self.filepath.read_bytes(), key, str(self.filepath).encode('utf8')))
