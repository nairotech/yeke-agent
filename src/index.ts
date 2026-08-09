import { loadConfig } from "./config.js";
import { TunnelClient } from "./tunnel-client.js";

async function main(): Promise<void> {
  const config = loadConfig();
  const client = new TunnelClient(config);

  const shutdown = async (signal: string) => {
    console.log(`[agent] received ${signal}, shutting down`);
    await client.stop();
    process.exit(0);
  };
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));

  await client.start();
}

main().catch((err) => {
  console.error(`[agent] failed to start: ${(err as Error).message}`);
  process.exit(1);
});
