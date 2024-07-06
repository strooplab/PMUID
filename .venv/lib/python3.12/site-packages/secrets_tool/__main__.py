import argparse
import re
from pathlib import Path

from .handlers.generic import GenericFileHandler
from .handlers.yaml import YamlFileHandler
from .handlers.yamlcompat import YamlCompatFileHandler


HANDLERS = {
    'yaml': YamlFileHandler,
    'yamlcompat': YamlCompatFileHandler,
    'generic': GenericFileHandler,
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('filename')
    parser.add_argument('command', choices=('e', 'encrypt', 'd', 'decrypt'))

    args = parser.parse_args()

    secrets_file_locations = (
        Path(Path.home(), '.tap-rubik-key'),
        Path(Path.home(), '.secrets-tool-key'),
    )

    for path in secrets_file_locations:
        if path.exists():
            key = path.read_bytes().strip()[:32]
            break
    else:
        raise Exception('Could not find file with your secret key.')

    gitignore_filepath = Path(args.filename)
    base_path = gitignore_filepath.parent

    gi_content = gitignore_filepath.read_text('ascii')
    gi_content_match = re.search(r'(?s)# BEGIN ENCRYPTED\n(.*)\n# END ENCRYPTED', gi_content)

    if gi_content_match is None:
        raise Exception("Couldn't find a # BEGIN/END ENCRYPTED section in the provided .gitignore file")
    gi_content_match = gi_content_match.group(1)

    statement_expr = r'^(?:# type: (?P<type>\w+)\n(?P<data_raw>(?:# data: .+\n)*))?^(?P<filepath>[^#\n].*)$'
    for statement in re.finditer(statement_expr, gi_content_match, flags=re.MULTILINE):
        data_raw = statement.group('data_raw')
        data = [raw.strip() for raw in data_raw.split('# data: ') if len(raw) > 0] if data_raw is not None else None

        filepath = base_path / statement.group('filepath')

        type_ = statement.group('type')
        if type_ is None:
            if filepath.suffix in ('.yml', '.yaml'):
                type_ = 'yaml'
            else:
                type_ = 'generic'
        handler = HANDLERS[type_]

        if args.command in ('e', 'encrypt'):
            target_path = Path(str(filepath) + '.enc')

            handler(filepath, data).dump_encrypted(target_path, key)
            print(f'ENCRYPTED {filepath.resolve()} (into {target_path.resolve()})')
        elif args.command in ('d', 'decrypt'):
            source_path = Path(str(filepath) + '.enc')

            handler(source_path, data).dump_decrypted(filepath, key)
            print(f'DECRYPTED {source_path.resolve()} (into {filepath.resolve()})')


if __name__ == '__main__':
    main()
