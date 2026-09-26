const { execFileSync } = require("node:child_process");

async function start() {
  console.log("Emergency Delivery: Warte auf PostgreSQL...");

  const bootstrap = require("./bootstrap-db.js");

  let lastError = null;

  for (let attempt = 1; attempt <= 60; attempt++) {
    try {
      console.log(`Datenbank-Initialisierung Versuch ${attempt}/60...`);

      await bootstrap();

      console.log("Emergency Delivery: Datenbank bereit.");
      console.log("Emergency Delivery: Server wird gestartet...");

      execFileSync(process.execPath, ["server.js"], {
        stdio: "inherit"
      });

      return;
    } catch (err) {
      lastError = err;
      console.error(
        `Datenbank noch nicht erreichbar (Versuch ${attempt}/60):`,
        err.message
      );

      if (attempt < 60) {
        await new Promise(resolve => setTimeout(resolve, 5000));
      }
    }
  }

  console.error("Online-Start fehlgeschlagen:", lastError);
  process.exit(1);
}

start().catch(err => {
  console.error("Online-Start fehlgeschlagen:", err);
  process.exit(1);
});
