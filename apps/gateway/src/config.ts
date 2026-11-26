import { readFileSync } from "node:fs";
import { validateGatewayConfig, type GatewayConfig } from "@fieldscope/core";

const ENV_VAR_REGEX = /\$\{([A-Z0-9_]+)(?::-(.*?))?\}/g;

function interpolateEnv(raw: string, env: NodeJS.ProcessEnv): string {
  return raw.replace(
    ENV_VAR_REGEX,
    (_match, key: string, defaultVal?: string) => {
      const val = env[key];
      if (val !== undefined) return val;
      if (defaultVal !== undefined) return defaultVal;
      throw new Error(`Missing required environment variable: ${key}`);
    }
  );
}

export function loadConfigFromJson(
  jsonContent: string,
  env: NodeJS.ProcessEnv = process.env
): GatewayConfig {
  const interpolated = interpolateEnv(jsonContent, env);
  const parsed: unknown = JSON.parse(interpolated);
  return validateGatewayConfig(parsed);
}

export function loadConfigFile(
  filePath: string,
  env: NodeJS.ProcessEnv = process.env
): GatewayConfig {
  const content = readFileSync(filePath, "utf-8");
  return loadConfigFromJson(content, env);
}
