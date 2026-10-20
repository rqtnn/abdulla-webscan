"""Create WS-R source archives without logs, results, credentials or caches."""
import hashlib
from pathlib import Path
import zipfile
from brand import VERSION


def build():
    root = Path(__file__).resolve().parent
    files = sorted(root.glob('*.py')) + [root / name for name in
        ('README.md', 'CHANGELOG.md', 'requirements.txt', '.gitignore')]
    for directory in ('docs', 'assets', 'wordlists', 'examples', 'webscan', 'benchmarks'):
        files += sorted(path for path in (root / directory).rglob('*') if path.is_file()
                        and '__pycache__' not in path.parts and path.suffix != '.pyc')
    files += sorted((root / 'scripts').glob('*.sh')) + sorted((root / 'tests').glob('*.cjs'))
    files += sorted((root / 'tests').glob('*.py')) + [root / 'tests' / 'README.md']
    files += [root / '.github' / 'workflows' / 'python-tests.yml']
    output = root / 'releases' / f'the-world-is-yours-{VERSION}.zip'
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest = []
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for file in files:
            relative = file.relative_to(root).as_posix()
            data = file.read_bytes()
            manifest.append(hashlib.sha256(data).hexdigest() + '  ' + relative)
            archive.writestr('ws-r/' + relative, data)
        archive.writestr('ws-r/MANIFEST.sha256', '\n'.join(manifest) + '\n')
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix('.zip.sha256').write_text(digest + '  ' + output.name + '\n')
    return output


if __name__ == '__main__':
    print(build())
