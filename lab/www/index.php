<?php
// ============================================================================
//  PHP2Shell Lab — "NovaDocs", portal de gestión documental
//  ----------------------------------------------------------------------------
//  Punto clave del CVE-2026-109618: el fallo ocurre durante la INICIALIZACIÓN
//  del request (parseo del POST), ANTES de que se ejecute ninguna línea de
//  esta aplicación. Ni autenticación ni validación a nivel de aplicación
//  pueden impedirlo. Esta página simula una app real de subida de documentos
//  (el escenario donde multipart/form-data vive en producción).
//
//  API interna (formatos estables, consumidos por las herramientas del lab):
//    GET /whoami.php -> "worker=<pid> php=<version> memory_limit=<limit>"
//  El POST multipart del trigger se procesa igual con esta página que con la
//  mínima: el bug vive en el core, no aquí.
// ============================================================================
header('Content-Type: text/html; charset=utf-8');
$php   = PHP_VERSION;
$pid   = getmypid();
$mem   = ini_get('memory_limit');
$sapi  = PHP_SAPI;
$host  = $_SERVER['HTTP_HOST'] ?? 'localhost';
?>
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NovaDocs · Portal documental</title>
<link rel="icon" href="data:,">
<style>
  :root{
    --bg:#0f1420; --panel:#161d2e; --panel2:#1c2540; --line:#28324e;
    --txt:#e8ecf6; --mut:#8b95ad; --acc:#4f8cff; --acc2:#7aa5ff;
    --ok:#3ecf8e; --warn:#ffb454; --bad:#ff6b6b; --rad:14px;
  }
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
       background:radial-gradient(1200px 600px at 80% -10%,#1b2b55 0%,var(--bg) 55%);
       color:var(--txt);min-height:100vh;display:flex;flex-direction:column}
  .ribbon{background:linear-gradient(90deg,#ff6b6b33,#ffb45433);border-bottom:1px solid var(--line);
          text-align:center;padding:.45rem;font-size:.78rem;color:var(--mut);letter-spacing:.04em}
  .ribbon b{color:var(--warn)}
  header{display:flex;align-items:center;justify-content:space-between;
         padding:1.1rem 2.2rem;border-bottom:1px solid var(--line);backdrop-filter:blur(6px)}
  .logo{display:flex;align-items:center;gap:.7rem;font-weight:700;font-size:1.15rem;letter-spacing:.02em}
  .logo .mark{width:34px;height:34px;border-radius:9px;display:grid;place-items:center;
              background:linear-gradient(135deg,var(--acc),#8a63ff);font-size:1.05rem}
  nav a{color:var(--mut);text-decoration:none;margin-left:1.6rem;font-size:.92rem}
  nav a:hover,nav a.on{color:var(--txt)}
  main{flex:1;width:min(1120px,94%);margin:0 auto;padding:2.4rem 0 3rem}
  .hero{display:grid;grid-template-columns:1.15fr .85fr;gap:2.2rem;align-items:center;margin-bottom:2.6rem}
  .hero h1{font-size:2.15rem;line-height:1.15;letter-spacing:-.02em}
  .hero h1 span{background:linear-gradient(90deg,var(--acc),#a06bff);-webkit-background-clip:text;background-clip:text;color:transparent}
  .hero p{color:var(--mut);margin:.9rem 0 1.4rem;max-width:52ch;line-height:1.6}
  .cta{display:inline-flex;gap:.8rem}
  .btn{padding:.7rem 1.3rem;border-radius:10px;font-weight:600;font-size:.95rem;text-decoration:none;border:1px solid var(--line);color:var(--txt)}
  .btn.pri{background:var(--acc);border-color:transparent}
  .btn.pri:hover{background:var(--acc2)}
  .drop{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px dashed #3d4a75;
        border-radius:var(--rad);padding:2rem;text-align:center;transition:.2s}
  .drop:hover{border-color:var(--acc);transform:translateY(-2px)}
  .drop .ic{font-size:2.2rem;margin-bottom:.6rem}
  .drop b{display:block;margin-bottom:.3rem}
  .drop small{color:var(--mut)}
  .cards{display:grid;grid-template-columns:repeat(3,1fr);gap:1.2rem;margin-bottom:2.4rem}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:var(--rad);padding:1.3rem 1.4rem}
  .card h3{font-size:.78rem;text-transform:uppercase;letter-spacing:.09em;color:var(--mut);margin-bottom:.55rem}
  .card .v{font-size:1.5rem;font-weight:700;letter-spacing:-.01em}
  .card .s{font-size:.8rem;color:var(--mut);margin-top:.35rem}
  .badge{display:inline-block;padding:.15rem .6rem;border-radius:99px;font-size:.72rem;font-weight:700;letter-spacing:.03em}
  .b-ok{background:#3ecf8e22;color:var(--ok);border:1px solid #3ecf8e55}
  .b-warn{background:#ffb45422;color:var(--warn);border:1px solid #ffb45455}
  .sec{background:var(--panel);border:1px solid var(--line);border-radius:var(--rad);padding:1.6rem 1.7rem;margin-bottom:1.4rem}
  .sec h2{font-size:1.05rem;margin-bottom:.8rem}
  .sec p{color:var(--mut);font-size:.92rem;line-height:1.65}
  table{width:100%;border-collapse:collapse;font-size:.88rem}
  th{color:var(--mut);text-align:left;font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.07em;padding:.55rem .6rem;border-bottom:1px solid var(--line)}
  td{padding:.65rem .6rem;border-bottom:1px solid #20294460}
  tr:last-child td{border-bottom:0}
  footer{border-top:1px solid var(--line);padding:1.3rem 2.2rem;display:flex;justify-content:space-between;
         font-size:.78rem;color:var(--mut)}
  @media(max-width:860px){.hero{grid-template-columns:1fr}.cards{grid-template-columns:1fr}}
</style>
</head>
<body>
  <div class="ribbon">ENTORNO DE <b>LABORATORIO</b> · uso aislado y autorizado · demostración CVE-2026-109618/109619</div>

  <header>
    <div class="logo"><span class="mark">◈</span> NovaDocs</div>
    <nav>
      <a class="on" href="#">Documentos</a>
      <a href="#">Plantillas</a>
      <a href="#">Firmas</a>
      <a href="#">Auditoría</a>
      <a href="#">Soporte</a>
    </nav>
  </header>

  <main>
    <section class="hero">
      <div>
        <h1>Sube, firma y archiva tus documentos <span>sin fricción</span></h1>
        <p>NovaDocs centraliza el ciclo documental de tu organización: carga masiva de facturas,
           contratos y justificantes con sellado temporal, firma electrónica y trazabilidad completa
           de cada operación.</p>
        <div class="cta">
          <a class="btn pri" href="#subir">Subir documento</a>
          <a class="btn" href="#estado">Estado del servicio</a>
        </div>
      </div>
      <div class="drop" id="subir">
        <div class="ic">📤</div>
        <b>Arrastra tus ficheros aquí</b>
        <small>PDF · DOCX · XLSX · PNG — hasta 2 MB por fichero<br>
        multipart/form-data · RFC 1867</small>
      </div>
    </section>

    <section class="cards" id="estado">
      <div class="card">
        <h3>Runtime PHP</h3>
        <div class="v"><?= htmlspecialchars($php) ?></div>
        <div class="s">SAPI <?= htmlspecialchars($sapi) ?></div>
      </div>
      <div class="card">
        <h3>Worker activo</h3>
        <div class="v">#<?= (int)$pid ?></div>
        <div class="s">proceso prefork que atiende tu request</div>
      </div>
      <div class="card">
        <h3>Límite de memoria</h3>
        <div class="v"><?= htmlspecialchars($mem) ?></div>
        <div class="s">memory_limit — postureño del parseo multipart</div>
      </div>
    </section>

    <section class="sec">
      <h2>Actividad reciente</h2>
      <table>
        <tr><th>Documento</th><th>Estado</th><th>Sellado</th></tr>
        <tr><td>factura_2026-10-prestaplatos.pdf</td><td><span class="badge b-ok">ARCHIVADO</span></td><td>hace 4 min</td></tr>
        <tr><td>contrato-servicios-draft.docx</td><td><span class="badge b-warn">PENDIENTE FIRMA</span></td><td>hace 26 min</td></tr>
        <tr><td>justificante-viaje-114.xlsx</td><td><span class="badge b-ok">ARCHIVADO</span></td><td>hace 1 h</td></tr>
        <tr><td>anexo-seguridad-v3.pdf</td><td><span class="badge b-ok">SELLADO</span></td><td>ayer</td></tr>
      </table>
    </section>

    <section class="sec">
      <h2>Seguridad del upload</h2>
      <p>Los ficheros se validan por extensión y tipo MIME declarado por el cliente, se almacenan
         fuera del webroot y se registran en la cola de antivirus. El límite por fichero es
         <code>upload_max_filesize=2M</code> y el cuerpo completo del POST está sujeto a
         <code>post_max_size</code>. NovaDocs confía en las garantías de aislamiento del runtime PHP
         para el procesado del cuerpo multipart — <b>el parseo ocurre antes de que esta aplicación
         pueda ejercer ningún control</b>, y ahí es exactamente donde viven los CVE-2026-109618/109619.</p>
    </section>
  </main>

  <footer>
    <div>© 2026 NovaDocs S.L. — todos los derechos reservados</div>
    <div>v3.2.1 · build <?= htmlspecialchars($php) ?> · <?= htmlspecialchars($host) ?></div>
  </footer>
</body>
</html>
