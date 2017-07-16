<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Guía de Proxy Inverso - Servidor HTTP Apache Versión 2.5</title>
<link href="../style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="../style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="../style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" /><link rel="stylesheet" type="text/css" href="../style/css/prettify.css" />
<script src="../style/scripts/prettify.min.js" type="text/javascript">
</script>

<link href="../images/favicon.ico" rel="shortcut icon" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="../mod/">Módulos</a> | <a href="../mod/quickreference.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a></p>
<p class="apache">Versión 2.5 del Servidor HTTP Apache</p>
<img alt="" src="../images/feather.png" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="../images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentación</a> &gt; <a href="../">Versión 2.5</a> &gt; <a href="./">How-To / Tutoriales</a></div><div id="page-content"><div id="preamble"><h1>Guía de Proxy Inverso</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/reverse_proxy.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/reverse_proxy.html" title="Español">&nbsp;es&nbsp;</a></p>
</div>

    <p>Además de ser un servidor web "básico", y proveer contenido estático y 
      dinámico a los usuarios finales, Apache HTTPD (al igual que la mayoría de  
      servidores http) puede también actuar como proxy inverso, también conocido 
      como "servidor de paso" o gateway.
    </p>

    <p>En tales escenarios, el propio httpd no genera contenido o aloja datos,
      en su lugar el contenido se obtiene de uno o varios servidores backend, que 
      normalmente no tienen conexión directa con redes externas. Cuando httpd 
      recibe una petición de un cliente, se hace <em>proxy</em> de esta petición 
      a uno de estos servidores backend, que gestiona la petición, genera el 
      contenido y entonces envía este contenido de vuelta a httpd, que 
      entonces genera la respuesta HTTP definitiva que se envía de vuelta al cliente.
    </p>

    <p>Existen muchas razones para usar esta implementación, pero generalmente 
      las razones típicas se deben a seguridad, alta disponibilidad, balanceo 
      de carga, y centralización de autenticación/autorización. Es crítico en 
      estas implementaciones que la arquitectura y el diseño de la infraestructura 
      de los backend (esos servidores que son los que acaban gestionando las peticiones) 
      estén aislados y protegidos del exterior; en cuanto al cliente se refiere, 
      el proxy inverso <em>és</em> la única fuente de todo el contenido.</p>

    <p>Ejemplo de implementación típica:</p>
    <p class="centered"><img src="../images/reverse-proxy-arch.png" alt="reverse-proxy-arch" /></p>

  </div>
<div id="quickview"><ul id="toc"><li><img alt="" src="../images/down.gif" /> <a href="#related">Proxy Inverso</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#simple">Proxy inverso sencillo</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#cluster">Clusters y Balanceadores</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#config">Configuración de Balanceador y BalancerMember</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#failover">Tolerancia a fallos</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#manager">Gestor del Balanceador</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#health-check">Comprobaciones de estado dinámicas</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#status">Marcas de estado de los Miembros del Balanceador</a></li>
</ul><h3>Consulte también</h3><ul class="seealso"><li><a href="#comments_section">Comentarios</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="related" id="related">Proxy Inverso</a></h2>
  
  <table class="related"><tr><th>Módulos Relacionados</th><th>Directivas Relacionadas</th></tr><tr><td><ul><li><code class="module"><a href="../mod/mod_proxy.html">mod_proxy</a></code></li><li><code class="module"><a href="../mod/mod_proxy_balancer.html">mod_proxy_balancer</a></code></li><li><code class="module"><a href="../mod/mod_proxy_hcheck.html">mod_proxy_hcheck</a></code></li></ul></td><td><ul><li><code class="directive"><a href="../mod/mod_proxy.html#proxypass">ProxyPass</a></code></li><li><code class="directive"><a href="../mod/mod_proxy.html#balancermember">BalancerMember</a></code></li></ul></td></tr></table>
  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="simple" id="simple">Proxy inverso sencillo</a></h2>
    

    <p>
      La directiva <code class="directive"><a href="../mod/mod_proxy.html#proxypass">ProxyPass</a></code>
      especifica el mapeo de peticiones entrantes al servidor backend (o un cluster 
      de servidores conocido como grupo de <code>Balanceo</code>). El ejemplo 
      más sencillo hace proxy de todas las solicitudes (<code>"/"</code>) a un solo backend:
    </p>

    <pre class="prettyprint lang-config">ProxyPass "/"  "http://www.example.com/"</pre>


    <p>
      Para asegurarse de ello y que las cabeceras <code>Location:</code> 
      generadas en el backend se modifican para apuntar al proxy inverso, 
      en lugar del propio backend, la directiva <code class="directive"><a href="../mod/mod_proxy.html#proxypassreverse">
      ProxyPassReverse</a></code> suele ser necesaria a menudo:
    </p>

    <pre class="prettyprint lang-config">ProxyPass "/"  "http://www.example.com/"
ProxyPassReverse "/"  "http://www.example.com/"</pre>


    <p>Sólo se hará proxy de ciertas URIs, como se muestra en este ejemplo:</p>

    <pre class="prettyprint lang-config">ProxyPass "/images/"  "http://www.example.com/"
ProxyPassReverse "/images/"  "http://www.example.com/"</pre>


    <p>En este ejemplo, se hará proxy al backend especificado,
    de cualquier solicitud que comience con la ruta <code>/images/</code>, si 
    no se gestionarán localmente.
    </p>
  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="cluster" id="cluster">Clusters y Balanceadores</a></h2>
    

    <p>
      Aunque los ejemplos de más arriba son útiles, tienen la deficiencia en la 
      que si el backend se cae, o recibe mucha carga, hacer proxy de esas solicitudes 
      no aporta grandes beneficios. Lo que se necesita es la habilidad de definir un 
      grupo de servidores backend que puedan gestionar esas peticiones y que el proxy 
      inverso pueda balancear la carga y aplicar la tolerancia a fallos entre los backend. 
      A veces a este grupo se le llama <em>cluster</em>, pero el término para Apache httpd
      es <em>balanceador</em>. Se puede definir un balanceador usando las directivas
      <code class="directive"><a href="../mod/mod_proxy.html#proxy">&lt;Proxy&gt;</a></code> and
      <code class="directive"><a href="../mod/mod_proxy.html#balancermember">BalancerMember</a></code> como se muestra 
      a continuación:
    </p>

    <pre class="prettyprint lang-config">&lt;Proxy balancer://myset&gt;
    BalancerMember http://www2.example.com:8080
    BalancerMember http://www3.example.com:8080
    ProxySet lbmethod=bytraffic
&lt;/Proxy&gt;

ProxyPass "/images/"  "balancer://myset/"
ProxyPassReverse "/images/"  "balancer://myset/"</pre>


    <p>
      El esquema <code>balancer://</code> es lo que le dice a httpd que estamos 
      generando un grupo de balanceo, con el nombre <em>myset</em>. Incluye 2 
      servidores backend, que httpd llama <em>BalancerMember</em>. En este caso, 
      se hará proxy inverso de cualquier petición para <code>/images/</code> 
      hacia <em>uno</em> de los dos backend.
      La directiva <code class="directive"><a href="../mod/mod_proxy.html#proxyset">ProxySet</a></code> especifica que 
      el Balanceador <em>myset</em> usa un algoritmo que balancea basado en los 
      bytes de entrada/salida (I/O).
    </p>

    <div class="note"><h3>Información adicional</h3>
      <p>
      	También se refiere a los Miembros del Balanceador <em>BalancerMember</em> 
        como <em>workers</em> (trabajadores).
      </p>
   </div>

  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="config" id="config">Configuración de Balanceador y BalancerMember</a></h2>
    

    <p>
      Puede ajustar numerosos parámetros de los <em>balanceadores</em>
      y los <em>workers</em> definiéndolos a través de la directiva
      <code class="directive"><a href="../mod/mod_proxy.html#proxypass">ProxyPass</a></code>. Por ejemplo,
      asumiendo que quisiéramos que <code>http://www3.example.com:8080</code> gestionara 
      3 veces más tráfico con un "timeout" de 1 segundo, ajustaríamos la configuración como sigue:
    </p>

    <pre class="prettyprint lang-config">&lt;Proxy balancer://myset&gt;
    BalancerMember http://www2.example.com:8080
    BalancerMember http://www3.example.com:8080 loadfactor=3 timeout=1
    ProxySet lbmethod=bytraffic
&lt;/Proxy&gt;

ProxyPass "/images/"  "balancer://myset/"
ProxyPassReverse "/images/"  "balancer://myset/"</pre>


  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="failover" id="failover">Tolerancia a fallos</a></h2>
    

    <p>
      Puede también ajustar varios escenarios de tolerancia a fallos, detallando 
      qué workers, e incluso balanceadores, deberían usarse en tales casos. 
      Por ejemplo, la siguiente configuración implementa dos casos de tolerancia 
      a fallos: En el primero, sólo se envía tráfico a 
      <code>http://hstandby.example.com:8080</code> si todos los demás workers en 
      el balanceador <em>myset</em> no están disponibles. Si ese worker tampoco está 
      disponible, sólo entonces los workers de <code>http://bkup1.example.com:8080</code> 
      y <code>http://bkup2.example.com:8080</code> serán incluidos en la rotación:
    </p>

    <pre class="prettyprint lang-config">&lt;Proxy balancer://myset&gt;
    BalancerMember http://www2.example.com:8080
    BalancerMember http://www3.example.com:8080 loadfactor=3 timeout=1
    BalancerMember http://hstandby.example.com:8080 status=+H
    BalancerMember http://bkup1.example.com:8080 lbset=1
    BalancerMember http://bkup2.example.com:8080 lbset=1
    ProxySet lbmethod=byrequests
&lt;/Proxy&gt;

ProxyPass "/images/"  "balancer://myset/"
ProxyPassReverse "/images/"  "balancer://myset/"</pre>


    <p>
      La "magia" de ésta configuración de tolerancia a fallos es configurar 
      <code>http://hstandby.example.com:8080</code> con la marca de estado 
      <code>+H</code>, que lo pone en modo <em>hot standby</em> (en reserva), 
      y hacen que los 2 servidores <code>bkup#</code> sean parte del set nº 1 del balanceo de carga (el valor por defecto es 0); para tolerancia a fallos, los "hot standby" (si existen) se usan primero cuando todos los workers estándar no están disponibles; los set de balanceo con el número inferior se intentan usar siempre primero.
    </p>

  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="manager" id="manager">Gestor del Balanceador</a></h2>
    

    <p>
      Una de las características más útiles y única del proxy inverso de Apache 
      httpd es la aplicación embebida <em>balancer-manager</em> (gestor de balanceo). 
      wSimilar a <code class="module"><a href="../mod/mod_status.html">mod_status</a></code>, <em>balancer-manager</em> muestra
      la configuración actual que está funcionando, el estado de los balanceadores 
      activados y workers que están en uso en ese momento. Aun así, no sólo muestra 
      estos parámetros, también permite reconfiguración dinámica, en tiempo real, de 
      prácticamente todos ellos, incluido añadir nuevos <em>BalancerMember</em> (workers) 
      a un balanceo existente. Para activar esta prestación, se tiene que añadir lo siguiente a la configuración:
    </p>

    <pre class="prettyprint lang-config">&lt;Location "/balancer-manager"&gt;
    SetHandler balancer-manager
    Require host localhost
&lt;/Location&gt;</pre>


    <div class="warning"><h3>Atención</h3>
      <p>No active el <em>balancer-manager</em> hasta que haya <a href="../mod/mod_proxy.html#access">securizado su servidor</a>. En particular, 
      asegúrese de que el acceso a ésta URL (la de configuración del balanceador) 
      esté altamente restringido.</p>
    </div>

    <p>
      Cuando se accede al proxy inverso en la url
      (p.e: <code>http://rproxy.example.com/balancer-manager/</code>, verá una 
      página similar a la siguiente:
    </p>
    <p class="centered"><img src="../images/bal-man.png" alt="balancer-manager page" /></p>

    <p>
      Este formulario permite al administrador ajustar varios parámetros, desactivar 
      workers, cambiar los métodos de balanceo de carga y añadir nuevos workers. 
      Por ejemplo, haciendo clic en el balanceador, verá la siguiente página:
    </p>
    <p class="centered"><img src="../images/bal-man-b.png" alt="balancer-manager page" /></p>

    <p>
      Y haciendo clic en el worker, mostrará esta página:
    </p>
    <p class="centered"><img src="../images/bal-man-w.png" alt="balancer-manager page" /></p>

    <p>
      Para hacer que estos cambios sean persistentes en los reinicios del proxy 
      inverso, asegúrese de que <code class="directive"><a href="../mod/mod_proxy.html#balancerpersist">BalancerPersist</a></code> está activado.
    </p>

  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="health-check" id="health-check">Comprobaciones de estado dinámicas</a></h2>
    

    <p>
      Antes de que httpd haga proxy de una petición a un worker, puede <em>"comprobar"</em> 
      si ese worker está disponible mediante el parámetro de configuración <code>ping</code> 
      para ese worker usando <code class="directive"><a href="../mod/mod_proxy.html#proxypass">ProxyPass</a></code>. 
      A menudo es más útil comprobar el estado de los workers <em>no disponibles</em>, 
      con un método dinámico. Esto se consigue con el módulo <code class="module"><a href="../mod/mod_proxy_hcheck.html">mod_proxy_hcheck</a></code>.
    </p>

  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="status" id="status">Marcas de estado de los Miembros del Balanceador</a></h2>
    

    <p>
      En el <em>balancer-manager</em> el estado actual, o <em>status</em>, de un worker 
      se muestra y puede ser configurado/reseteado. El significado de estos estados es el siguiente:
    </p>
      <table class="bordered">
      	<tr><th>Marca</th><th>Cadena</th><th>Descripción</th></tr>
      	<tr><td>&nbsp;</td><td><em>Ok</em></td><td>El Worker está disponible</td></tr>
      	<tr><td>&nbsp;</td><td><em>Init</em></td><td>El Worker ha sido inicializado</td></tr>
        <tr><td><code>D</code></td><td><em>Dis</em></td><td>El Worker está 
        desactivado y no aceptará peticiones; se intentará reutilizar automáticamente.</td></tr>
        <tr><td><code>S</code></td><td><em>Stop</em></td><td>El Worker ha sido desactivado por el 
        administrador; no aceptará peticiones y no se reintentará utilizar automáticamente</td></tr>
        <tr><td><code>I</code></td><td><em>Ign</em></td><td>El Worker está en modo "ignore-errors" (obviar-errores) y estará siempre en modo disponible.</td></tr>
        <tr><td><code>H</code></td><td><em>Stby</em></td><td>El Worker está en modo "hot-standby" y sólo se usará si no hay otros workers disponibles.</td></tr>
        <tr><td><code>E</code></td><td><em>Err</em></td><td>El Worker está en estado de error, 
        generalmente debido a fallos de comprobación antes de enviar peticiones; no se hará 
        proxy de peticiones a este worker, pero se reintentará el uso de este worker 
        dependiendo de la configuración del parámetro <code>retry</code>.</td></tr>
        <tr><td><code>N</code></td><td><em>Drn</em></td><td>El Worker está en modo vaciado y sólo aceptará 
        sesiones activas previamente destinadas a él mismo y obviará el resto de peticiones.</td></tr>
        <tr><td><code>C</code></td><td><em>HcFl</em></td><td>La comprobación dinámica del estado del Worker
        ha fallado y no se usará hasta que pase las comprobaciones de estado posteriores.</td></tr>
      </table>
  </div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/reverse_proxy.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/reverse_proxy.html" title="Español">&nbsp;es&nbsp;</a></p>
</div><div class="top"><a href="#page-header"><img src="../images/up.gif" alt="top" /></a></div><div class="section"><h2><a id="comments_section" name="comments_section">Comentarios</a></h2><div class="warning"><strong>Notice:</strong><br />This is not a Q&amp;A section. Comments placed here should be pointed towards suggestions on improving the documentation or server, and may be removed again by our moderators if they are either implemented or considered invalid/off-topic. Questions on how to manage the Apache HTTP Server should be directed at either our IRC channel, #httpd, on Freenode, or sent to our <a href="http://httpd.apache.org/lists.html">mailing lists</a>.</div>
<script type="text/javascript"><!--//--><![CDATA[//><!--
var comments_shortname = 'httpd';
var comments_identifier = 'http://httpd.apache.org/docs/trunk/howto/reverse_proxy.html';
(function(w, d) {
    if (w.location.hostname.toLowerCase() == "httpd.apache.org") {
        d.write('<div id="comments_thread"><\/div>');
        var s = d.createElement('script');
        s.type = 'text/javascript';
        s.async = true;
        s.src = 'https://comments.apache.org/show_comments.lua?site=' + comments_shortname + '&page=' + comments_identifier;
        (d.getElementsByTagName('head')[0] || d.getElementsByTagName('body')[0]).appendChild(s);
    }
    else {
        d.write('<div id="comments_thread">Comments are disabled for this page at the moment.<\/div>');
    }
})(window, document);
//--><!]]></script></div><div id="footer">
<p class="apache">Copyright 2017 The Apache Software Foundation.<br />Licencia bajo los términos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="../mod/">Módulos</a> | <a href="../mod/quickreference.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a></p></div><script type="text/javascript"><!--//--><![CDATA[//><!--
if (typeof(prettyPrint) !== 'undefined') {
    prettyPrint();
}
//--><!]]></script>
</body></html>