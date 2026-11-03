"""Run the standalone verifier suite against rendered synthetic configuration."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from render import render

root = Path(__file__).resolve().parent
scratch = root / '.test-run'
scratch.mkdir(exist_ok=True)
node = Path(shutil.which('node')).resolve()
with tempfile.TemporaryDirectory(prefix='proof-', dir=scratch) as temporary:
    temporary = Path(temporary)
    config = json.loads((root / 'config.example.json').read_text())
    config.update(node_path=str(node), node_sha256=hashlib.sha256(node.read_bytes()).hexdigest(),
                  codex_path='/fixture/codex',
                  tinfoil_sdk_source=os.environ.get('T3_TINFOIL_SDK_SOURCE', str(root / 'vendor/tinfoil-js')))
    output = temporary / 'runtime'
    render(config, output, test_only=True)
    environment = {**os.environ, 'TMPDIR': str(temporary)}
    subprocess.run([str(node), '--test', 'gate.node-test.mjs', 'endpoint-binding.node-test.mjs',
                    'vm-proof-server.node-test.mjs', 'release-approvals.node-test.mjs',
                    'verifier/google-firmware.node-test.mjs', 'device-approval-store.node-test.mjs'],
                   cwd=output / 'attestation', env=environment, check=True)
    subprocess.run(['python3', '-m', 'unittest', 'test_snp_collect.py'],
                   cwd=output / 'attestation', env=environment, check=True)
