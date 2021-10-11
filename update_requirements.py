import os
import subprocess
from configparser import ConfigParser

print('*** Generate requirements.lock ***')
subprocess.run('pip freeze >requirements.lock', shell=True, check=True)
with open('requirements.lock') as f:
    requirements = [
        line for line in f.read().strip().splitlines()
        if not line.startswith('pre-commit')
    ]
    print('\n'.join(requirements))

os.remove('requirements.lock')
print()

# Read setup.cfg, replace install_requires value with requirements.lock, and
# write setup.cfg
parser = ConfigParser()
parser.read('setup.cfg')
requirements_str = ''.join(f'\n{requirement}' for requirement in requirements)
parser.set('options', 'install_requires', requirements_str)
with open('setup.cfg', 'w') as f:
    parser.write(f)

# Clean up setup.cfg
with open('setup.cfg') as f:
    setup_cfg = [
        line.replace('\t', '    ').rstrip()
        for line in f.read().splitlines()
    ]


with open('setup.cfg', 'w') as f:
    f.write('\n'.join(setup_cfg))

print('setup.cfg has been updated. Please commit this change')
