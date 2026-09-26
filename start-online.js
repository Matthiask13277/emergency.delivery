const { execFileSync } = require("node:child_process");

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function start() {
  console.log("Emergency Delivery: Warte auf PostgreSQL...");

  const bootstrap = require("./bootstrap-db.js");

  let lastError = null;

  for (let attempt = 1; attempt <= 60; attempt++) {
    try {
      console.log(`Datenbank-Initialisierung Versuch ${attempt}/60...`);

      await bootstrap();

      console.log("Emergency Delivery: Datenbank bereit.");
      lastError = null;
      break;
    } catch (err) {
      lastError = err;

      console.error(
        `Datenbank noch nicht bereit: ${err.message || err}`
      );

      if (attempt === 60) {
        throw lastError;
      }

      await sleep(5000);
    }
  }

  console.log("Emergency Delivery: Server wird gestartet...");

  execFileSync(process.execPath, ["server.js"], {
    stdio: "inherit"
  });
}

start().catch(err => {
  console.error("Online-Start fehlgeschlagen:", err);
  process.exit(1);
});
