import { cp, mkdir, rm } from "node:fs/promises";

await rm("dist", { recursive: true, force: true });
await mkdir("dist/server", { recursive: true });
await mkdir("dist/client", { recursive: true });
await cp("static", "dist/client", { recursive: true });
await cp("worker/index.js", "dist/server/index.js");
await cp(".openai", "dist/.openai", { recursive: true });
console.log("Cloud dashboard built in dist/");
