import { resolve } from "node:path";
import { loadConfigFile } from "./config.ts";
import { createGatewayServer } from "./server.ts";

function getConfigPath(): string {
  const args = process.argv.slice(2);
  const configIdx = args.indexOf("--config");
  if (configIdx !== -1 && args[configIdx + 1]) {
    return resolve(process.cwd(), args[configIdx + 1]);
  }
  if (process.env.FIELDSCOPE_CONFIG) {
    return resolve(process.cwd(), process.env.FIELDSCOPE_CONFIG);
  }
  return resolve(process.cwd(), "examples/fieldscope.json");
}

async function main() {
  const configPath = getConfigPath();
  const config = loadConfigFile(configPath);
  const gateway = createGatewayServer({ config });
  const url = await gateway.listen(config.server.host, config.server.port);
  console.log(`FieldScope Gateway listening on ${url} (config: ${configPath})`);
}

main().catch((err) => {
  console.error("Failed to start FieldScope Gateway:", err);
  process.exit(1);
});
