require("./compileCache.cjs");
if (require("electron").app.isPackaged) {
  const fs = require("node:fs");
  const path = require("node:path");
  const configurationPath = path.join(process.resourcesPath, "t3-attested-launch.json");
  const configuration = fs.existsSync(configurationPath)
    ? JSON.parse(fs.readFileSync(configurationPath, "utf8"))
    : { home: path.join(require("node:os").homedir(), ".t3-attested"), port: 3773 };
  require("./attestation/launchDefaults.cjs").applyAttestedLaunchDefaults(
    configuration,
    process.env,
  );
}
require("./main.cjs");
