# WP Monitor

Panel central para vigilar sitios WordPress: actualizaciones, respaldos (Backuply), cuota de disco, SSL y señales de seguridad.

- **server/**: panel (Flask + SQLite) con página *Sitios* para generar un código por sitio y la API que recibe los reportes.
- **plugin/**: plugin de WordPress que envía el reporte al panel usando su código.

Cada sitio se conecta con dos datos: **servidor** y **código**. No se necesita SSH ni acceso al hosting del cliente.

Licencia: GPL-2.0-or-later.
