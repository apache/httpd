<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Gu&#237;a de Proxy Inverso - Servidor HTTP Apache Versi&#243;n 2.5</title>
<link href="../style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="../style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="../style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" /><link rel="stylesheet" type="text/css" href="../style/css/prettify.css" />
<script src="../style/scripts/prettify.min.js" type="text/javascript">
</script>

<link href="../images/favicon.ico" rel="shortcut icon" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="../mod/">M&#243;dulos</a> | <a href="../mod/quickreference.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a></p>
<p class="apache">Versi&#243;n 2.5 del Servidor HTTP Apache</p>
<img alt="" src="../images/feather.png" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="../images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentaci&#243;n</a> &gt; <a href="../">Versi&#243;n 2.5</a> &gt; <a href="./">How-To / Tutoriales</a></div><div id="page-content"><div id="preamble"><h1>Gu&#237;a de Proxy Inverso</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/reverse_proxy.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/reverse_proxy.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a></p>
</div>

    <p>Adem&#225;s de ser un servidor web "b&#225;sico", y proveer contenido est&#225;tico y 
      din&#225;mico a los usuarios finales, Apache HTTPD (al igual que la mayor&#237;a de  
      servidores http) puede tambi&#233;n actuar como proxy inverso, tambi&#233;n conocido 
      como "servidor de paso" o gateway.
    </p>

    <p>En tales escenarios, el propio httpd no genera contenido o aloja datos,
      en su lugar el contenido se obtiene de uno o varios servidores backend, que 
      normalmente no tienen conexi&#243;n directa con redes externas. Cuando httpd 
      recibe una petici&#243;n de un cliente, se hace <em>proxy</em> de esta petici&#243;n 
      a uno de estos servidores backend, que gestiona la petici&#243;n, genera el 
      contenido y entonces env&#237;a este contenido de vuelta a httpd, que 
      entonces genera la respuesta HTTP definitiva que se env&#237;a de vuelta al cliente.
    </p>

    <p>Existen muchas razones para usar esta implementaci&#243;n, pero generalmente 
      las razones t&#237;picas se deben a seguridad, alta disponibilidad, balanceo 
      de carga, y centralizaci&#243;n de autenticaci&#243;n/autorizaci&#243;n. Es cr&#237;tico en 
      estas implementaciones que la arquitectura y el dise&#241;o de la infraestructura 
      de los backend (esos servidores que son los que acaban gestionando las peticiones) 
      est&#233;n aislados y protegidos del exterior; en cuanto al cliente se refiere, 
      el proxy inverso <em>&#233;s</em> la &#250;nica fuente de todo el contenido.</p>

    <p>Ejemplo de implementaci&#243;n t&#237;pica:</p>
    <p class="centered"><img src="../images/reverse-proxy-arch.png" alt="reverse-proxy-arch" /></p>

  </div>
<div id="quickview"><ul id="toc"><li><img alt="" src="../images/down.gif" /> <a href="#related">Proxy Inverso</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#simple">Proxy inverso sencillo</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#cluster">Clusters y Balanceadores</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#config">Configuraci&#243;n de Balanceador y BalancerMember</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#failover">Tolerancia a fallos</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#manager">Gestor del Balanceador</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#health-check">Comprobaciones de estado din&#225;micas</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#status">Marcas de estado de los Miembros del Balanceador</a></li>
</ul><h3>Consulte tambi&#233;n</h3><ul class="seealso"><li><a href="#comments_section">Comentarios</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="related" id="related">Proxy Inverso</a></h2>
  
  <table class="related"><tr><th>M&#243;dulos Relacionados</th><th>Directivas Relacionadas</th></tr><tr><td><ul><li><code class="module"><a href="../mod/mod_proxy.html">mod_proxy</a></code></li><li><code class="module"><a href="../mod/mod_proxy_balancer.html">mod_proxy_balancer</a></code></li><li><code class="module"><a href="../mod/mod_proxy_hcheck.html">mod_proxy_hcheck</a></code></li></ul></td><td><ul><li><code class="directive"><a href="../mod/mod_proxy.html#proxypass">ProxyPass</a></code></li><li><code class="directive"><a href="../mod/mod_proxy.html#balancermember">BalancerMember</a></code></li></ul></td></tr></table>
  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="simple" id="simple">Proxy inverso sencillo</a></h2>
    

    <p>
      La directiva <code class="directive"><a href="../mod/mod_proxy.html#proxypass">ProxyPass</a></code>
      especifica el mapeo de peticiones entrantes al servidor backend (o un cluster 
      de servidores conocido como grupo de <code>Balanceo</code>). El ejemplo 
      m&#225;s sencillo hace proxy de todas las solicitudes (<code>"/"</code>) a un solo backend:
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


    <p>S&#243;lo se har&#225; proxy de ciertas URIs, como se muestra en este ejemplo:</p>

    <pre class="prettyprint lang-config">ProxyPass "/images/"  "http://www.example.com/"
ProxyPassReverse "/images/"  "http://www.example.com/"</pre>


    <p>En este ejemplo, se har&#225; proxy al backend especificado,
    de cualquier solicitud que comience con la ruta <code>/images/</code>, si 
    no se gestionar&#225;n localmente.
    </p>
  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="cluster" id="cluster">Clusters y Balanceadores</a></h2>
    

    <p>
      Aunque los ejemplos de m&#225;s arriba son &#250;tiles, tienen la deficiencia en la 
      que si el backend se cae, o recibe mucha carga, hacer proxy de esas solicitudes 
      no aporta grandes beneficios. Lo que se necesita es la habilidad de definir un 
      grupo de servidores backend que puedan gestionar esas peticiones y que el proxy 
      inverso pueda balancear la carga y aplicar la tolerancia a fallos entre los backend. 
      A veces a este grupo se le llama <em>cluster</em>, pero el t&#233;rmino para Apache httpd
      es <em>balanceador</em>. Se puede definir un balanceador usando las directivas
      <code class="directive"><a href="../mod/mod_proxy.html#proxy">&lt;Proxy&gt;</a></code> and
      <code class="directive"><a href="../mod/mod_proxy.html#balancermember">BalancerMember</a></code> como se muestra 
      a continuaci&#243;n:
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
      se har&#225; proxy inverso de cualquier petici&#243;n para <code>/images/</code> 
      hacia <em>uno</em> de los dos backend.
      La directiva <code class="directive"><a href="../mod/mod_proxy.html#proxyset">ProxySet</a></code> especifica que 
      el Balanceador <em>myset</em> usa un algoritmo que balancea basado en los 
      bytes de entrada/salida (I/O).
    </p>

    <div class="note"><h3>Informaci&#243;n adicional</h3>
      <p>
      	Tambi&#233;n se refiere a los Miembros del Balanceador <em>BalancerMember</em> 
        como <em>workers</em> (trabajadores).
      </p>
   </div>

  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="config" id="config">Configuraci&#243;n de Balanceador y BalancerMember</a></h2>
    

    <p>
      Puede ajustar numerosos par&#225;metros de los <em>balanceadores</em>
      y los <em>workers</em> defini&#233;ndolos a trav&#233;s de la directiva
      <code class="directive"><a href="../mod/mod_proxy.html#proxypass">ProxyPass</a></code>. Por ejemplo,
      asumiendo que quisi&#233;ramos que <code>http://www3.example.com:8080</code> gestionara 
      3 veces m&#225;s tr&#225;fico con un "timeout" de 1 segundo, ajustar&#237;amos la configuraci&#243;n como sigue:
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
      Puede tambi&#233;n ajustar varios escenarios de tolerancia a fallos, detallando 
      qu&#233; workers, e incluso balanceadores, deber&#237;an usarse en tales casos. 
      Por ejemplo, la siguiente configuraci&#243;n implementa dos casos de tolerancia 
      a fallos: En el primero, s&#243;lo se env&#237;a tr&#225;fico a 
      <code>http://hstandby.example.com:8080</code> si todos los dem&#225;s workers en 
      el balanceador <em>myset</em> no est&#225;n disponibles. Si ese worker tampoco est&#225; 
      disponible, s&#243;lo entonces los workers de <code>http://bkup1.example.com:8080</code> 
      y <code>http://bkup2.example.com:8080</code> ser&#225;n incluidos en la rotaci&#243;n:
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
      La "magia" de &#233;sta configuraci&#243;n de tolerancia a fallos es configurar 
      <code>http://hstandby.example.com:8080</code> con la marca de estado 
      <code>+H</code>, que lo pone en modo <em>hot standby</em> (en reserva), 
      y hacen que los dos servidores <code>bkup#</code> sean parte del set n&#186; 1 del
      balanceo de carga (el valor por defecto es 0); para tolerancia a fallos, los "hot standby" (si existen) se usan primero cuando todos los workers est&#225;ndar activos no est&#225;n disponibles; los set de balanceo con n&#250;meros inferiores se usan siempre primero.
    </p>

  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="manager" id="manager">Gestor del Balanceador</a></h2>
    

    <p>
      Una de las caracter&#237;sticas m&#225;s &#250;tiles y &#250;nica del proxy inverso de Apache 
      httpd es la aplicaci&#243;n embebida <em>balancer-manager</em> (gestor de balanceo). 
      wSimilar a <code class="module"><a href="../mod/mod_status.html">mod_status</a></code>, <em>balancer-manager</em> muestra
      la configuraci&#243;n actual que est&#225; funcionando, el estado de los balanceadores 
      activados y workers que est&#225;n en uso en ese momento. Aun as&#237;, no s&#243;lo muestra 
      estos par&#225;metros, tambi&#233;n permite reconfiguraci&#243;n din&#225;mica, en tiempo real, de 
      pr&#225;cticamente todos ellos, incluido a&#241;adir nuevos <em>BalancerMember</em> (workers) 
      a un balanceo existente. Para activar esta prestaci&#243;n, se tiene que a&#241;adir lo siguiente a la configuraci&#243;n:
    </p>

    <pre class="prettyprint lang-config">&lt;Location "/balancer-manager"&gt;
    SetHandler balancer-manager
    Require host localhost
&lt;/Location&gt;</pre>


    <div class="warning"><h3>Atenci&#243;n</h3>
      <p>No active el <em>balancer-manager</em> hasta que haya <a href="../mod/mod_proxy.html#access">securizado su servidor</a>. En particular, 
      aseg&#250;rese de que el acceso a &#233;sta URL (la de configuraci&#243;n del balanceador) 
      est&#233; altamente restringido.</p>
    </div>

    <p>
      Cuando se accede al proxy inverso en la url
      (p.e: <code>http://rproxy.example.com/balancer-manager/</code>, ver&#225; una 
      p&#225;gina similar a la siguiente:
    </p>
    <p class="centered"><img src="../images/bal-man.png" alt="balancer-manager page" /></p>

    <p>
      Este formulario permite al administrador ajustar varios par&#225;metros, desactivar 
      workers, cambiar los m&#233;todos de balanceo de carga y a&#241;adir nuevos workers. 
      Por ejemplo, haciendo clic en el balanceador, ver&#225; la siguiente p&#225;gina:
    </p>
    <p class="centered"><img src="../images/bal-man-b.png" alt="balancer-manager page" /></p>

    <p>
      Y haciendo clic en el worker, mostrar&#225; esta p&#225;gina:
    </p>
    <p class="centered"><img src="../images/bal-man-w.png" alt="balancer-manager page" /></p>

    <p>
      Para hacer que estos cambios sean persistentes en los reinicios del proxy 
      inverso, aseg&#250;rese de que <code class="directive"><a href="../mod/mod_proxy.html#balancerpersist">BalancerPersist</a></code> est&#225; activado.
    </p>

  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="health-check" id="health-check">Comprobaciones de estado din&#225;micas</a></h2>
    

    <p>
      Antes de que httpd haga proxy de una petici&#243;n a un worker, puede <em>"comprobar"</em> 
      si ese worker est&#225; disponible mediante el par&#225;metro de configuraci&#243;n <code>ping</code> 
      para ese worker usando <code class="directive"><a href="../mod/mod_proxy.html#proxypass">ProxyPass</a></code>. 
      A menudo es m&#225;s &#250;til comprobar el estado de los workers <em>no disponibles</em>, 
      con un m&#233;todo din&#225;mico. Esto se consigue con el m&#243;dulo <code class="module"><a href="../mod/mod_proxy_hcheck.html">mod_proxy_hcheck</a></code>.
    </p>

  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="status" id="status">Marcas de estado de los Miembros del Balanceador</a></h2>
    

    <p>
      En el <em>balancer-manager</em> el estado actual, o <em>status</em>, de un worker 
      se muestra y puede ser configurado/reseteado. El significado de estos estados es el siguiente:
    </p>
      <table class="bordered">
      	<tr><th>Marca</th><th>Cadena</th><th>Descripci&#243;n</th></tr>
      	<tr><td>&nbsp;</td><td><em>Ok</em></td><td>El Worker est&#225; disponible</td></tr>
      	<tr><td>&nbsp;</td><td><em>Init</em></td><td>El Worker ha sido inicializado</td></tr>
        <tr><td><code>D</code></td><td><em>Dis</em></td><td>El Worker est&#225; 
        desactivado y no aceptar&#225; peticiones; se intentar&#225; reutilizar autom&#225;ticamente.</td></tr>
        <tr><td><code>S</code></td><td><em>Stop</em></td><td>El Worker ha sido desactivado por el 
        administrador; no aceptar&#225; peticiones y no se reintentar&#225; utilizar autom&#225;ticamente</td></tr>
        <tr><td><code>I</code></td><td><em>Ign</em></td><td>El Worker est&#225; en modo "ignore-errors" (obviar-errores) y estar&#225; siempre en modo disponible.</td></tr>
        <tr><td><code>H</code></td><td><em>Stby</em></td><td>El Worker est&#225; en modo "hot-standby" y s&#243;lo se usar&#225; si no hay otros workers disponibles.</td></tr>
        <tr><td><code>E</code></td><td><em>Err</em></td><td>El Worker est&#225; en estado de error, 
        generalmente debido a fallos de comprobaci&#243;n antes de enviar peticiones; no se har&#225; 
        proxy de peticiones a este worker, pero se reintentar&#225; el uso de este worker 
        dependiendo de la configuraci&#243;n del par&#225;metro <code>retry</code>.</td></tr>
        <tr><td><code>N</code></td><td><em>Drn</em></td><td>El Worker est&#225; en modo vaciado y s&#243;lo aceptar&#225; 
        sesiones activas previamente destinadas a &#233;l mismo y obviar&#225; el resto de peticiones.</td></tr>
        <tr><td><code>C</code></td><td><em>HcFl</em></td><td>La comprobaci&#243;n din&#225;mica del estado del Worker
        ha fallado y no se usar&#225; hasta que pase las comprobaciones de estado posteriores.</td></tr>
      </table>
  </div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/howto/reverse_proxy.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/howto/reverse_proxy.html" title="Espa&#241;ol">&nbsp;es&nbsp;</a></p>
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
<p class="apache">Copyright 2017 The Apache Software Foundation.<br />Licencia bajo los t&#233;rminos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="../mod/">M&#243;dulos</a> | <a href="../mod/quickreference.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a></p></div><script type="text/javascript"><!--//--><![CDATA[//><!--
if (typeof(prettyPrint) !== 'undefined') {
    prettyPrint();
}
//--><!]]></script>
</body></html>