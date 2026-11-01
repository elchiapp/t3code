"""Render reviewed source templates into a separate, machine-local runtime."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent


def render(config, output, *, test_only=False):
    if output.exists():
        raise ValueError("Choose a fresh output directory; existing runtimes are not overwritten")
    host = config["vm_host"]
    if not re.fullmatch(r"[a-z0-9.-]+", host):
        raise ValueError("Invalid VM host")
    ip = ipaddress.ip_address(config["vm_tailscale_ip"])
    if ip not in ipaddress.ip_network("100.64.0.0/10"):
        raise ValueError("Use the VM's Tailscale IPv4 address")
    if not re.fullmatch(r"[a-f0-9]{64}", config["node_sha256"]):
        raise ValueError("An explicit reviewed Node SHA256 is required")
    node = Path(config["node_path"]).resolve(strict=True)
    if hashlib.sha256(node.read_bytes()).hexdigest() != config["node_sha256"]:
        raise ValueError("Node does not match the reviewed runtime pin")
    source_lock = json.loads((ROOT / "source-lock.json").read_text())
    for name, item in source_lock["files"].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != item["template_sha256"]:
            raise ValueError("Source template changed; review and refresh its source lock first")
    values = {
        "ATTESTATION_ROOT": str(output / "attestation"),
        "LOCAL_T3_ROOT": str(output / "local-proxy/local"),
        "T3_SOURCE_ROOT": str(ROOT.parents[1]),
        "TINFOIL_SDK_ROOT": str(Path(config["tinfoil_sdk_source"]).resolve()),
        "LAUNCH_AGENT_DIR": str(Path.home() / "Library/LaunchAgents"),
        "NODE_PATH": str(node), "PYTHON_PATH": config["python_path"],
        "CODEX_PATH": config["codex_path"], "USER_HOME": str(Path.home()),
        "MODEL_ORIGIN": "https://" + host + ":8447",
        "VM_T3_ORIGIN": "https://" + host + ":8446",
        "VM_ORIGIN": "https://" + host,
        "EVIDENCE_ORIGIN": "https://evidence." + host,
        "PRIVACY_ORIGIN": "https://privacy." + host,
        "PROOF_ORIGIN": "http://" + str(ip) + ":3430",
        "VM_TAILSCALE_IP": str(ip), "VM_HOST": host,
        "TAILNET_OWNER": config["tailnet_owner"],
        "VM_NODE_PATH": config["vm_node_path"],
        "VM_ATTESTATION_ROOT": config["vm_attestation_root"],
        "VM_T3_ROOT": config["vm_t3_root"],
        "VM_LOCAL_PROXY_ROOT": config["vm_local_proxy_root"],
        "VM_GATEWAY_ROOT": config["vm_gateway_root"],
    }
    if config.get("evidence_origin"):
        values["EVIDENCE_ORIGIN"] = config["evidence_origin"]
    for value in values.values():
        if any(char in value for char in ["'", '"', "\\", "\n", "\r", "\0"]):
            raise ValueError("Configuration values must be safe literal strings")
    output.mkdir(parents=True, mode=0o700)
    for source in (ROOT / "templates").rglob("*"):
        if not source.is_file():
            continue
        relative = source.relative_to(ROOT / "templates")
        target = output / relative.with_name(relative.name.removesuffix(".template"))
        text = source.read_text()
        local_values = {**values, "RECIPE_ROOT": str(target.parent)}
        for key, value in local_values.items():
            text = text.replace("{{" + key + "}}", value)
        if re.search(r"\{\{[A-Z_]+\}\}", text):
            raise ValueError("Unresolved template value in " + str(source.relative_to(ROOT)))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        target.chmod(0o600)
    verifier = output / "attestation/verifier"
    inputs = json.loads((verifier / "inputs.json").read_text())
    for name, key in [("verifier-core.mjs", "coreSha256"), ("vcek-bindings.mjs", "vcekBindingSha256"), ("policy.json", "publicPolicySha256")]:
        inputs[key] = hashlib.sha256((verifier / name).read_bytes()).hexdigest()
    (verifier / "inputs.json").write_text(json.dumps(inputs, indent=2) + "\n")
    (output / "attestation/activation-plan.json").write_text(json.dumps({"node_path": str(node), "node_sha256": config["node_sha256"]}, indent=2) + "\n")
    client_policy = {
        "verifierOrigin": "http://127.0.0.1:3420",
        "modelOrigin": values["MODEL_ORIGIN"],
        "allowedEnvironmentOrigins": [config["local_t3_origin"], values["VM_T3_ORIGIN"]],
    }
    (output / "attestation-client.json").write_text(json.dumps(client_policy, indent=2) + "\n")
    (output / "attestation-client.json").chmod(0o600)
    return {"rendered": True, "output": str(output), "credentials_included": False, "owner_release_approval_included": False, "test_only": test_only}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(render(json.loads(args.config.read_text()), args.output.resolve()), indent=2))
