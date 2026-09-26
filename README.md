# Emergency Delivery V215

Online-Server für blitz.cloud.

Der Haupt-Dockerfile läuft als nicht privilegierter Benutzer auf Port 8080.
Bei gesetztem `DATABASE_URL` verwendet der Server Managed PostgreSQL; ohne diese Variable bleibt der lokale PGlite-Betrieb für Desktop erhalten.
