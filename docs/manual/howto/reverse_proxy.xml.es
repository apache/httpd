<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English revision: 1754775 -->
<!-- Spanish translation : Daniel Ferradal -->
<!-- Reviewed by Luis Gil de Bernabé Pfeiffer -->

<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
 contributor license agreements.  See the NOTICE file distributed with
 this work for additional information regarding copyright ownership.
 The ASF licenses this file to You under the Apache License, Version 2.0
 (the "License"); you may not use this file except in compliance with
 the License.  You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

<manualpage metafile="reverse_proxy.xml.meta">
<parentdocument href="./">How-To / Tutoriales</parentdocument>

  <title>Guía de Proxy Inverso</title>

  <summary>
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

  </summary>


  <section id="related">
  <title>Proxy Inverso</title>
  <related>
    <modulelist>
      <module>mod_proxy</module>
      <module>mod_proxy_balancer</module>
      <module>mod_proxy_hcheck</module>
    </modulelist>
    <directivelist>
      <directive module="mod_proxy">ProxyPass</directive>
      <directive module="mod_proxy">BalancerMember</directive>
    </directivelist>
  </related>
  </section>

  <section id="simple">
    <title>Proxy inverso sencillo</title>

    <p>
      La directiva <directive module="mod_proxy">ProxyPass</directive>
      especifica el mapeo de peticiones entrantes al servidor backend (o un cluster 
      de servidores conocido como grupo de <code>Balanceo</code>). El ejemplo 
      más sencillo hace proxy de todas las solicitudes (<code>"/"</code>) a un solo backend:
    </p>

    <highlight language="config">
ProxyPass "/"  "http://www.example.com/"
    </highlight>

    <p>
      Para asegurarse de ello y que las cabeceras <code>Location:</code> 
      generadas en el backend se modifican para apuntar al proxy inverso, 
      en lugar del propio backend, la directiva <directive module="mod_proxy">
      ProxyPassReverse</directive> suele ser necesaria a menudo:
    </p>

    <highlight language="config">
ProxyPass "/"  "http://www.example.com/"
ProxyPassReverse "/"  "http://www.example.com/"
    </highlight>

    <p>Sólo se hará proxy de ciertas URIs, como se muestra en este ejemplo:</p>

    <highlight language="config">
ProxyPass "/images/"  "http://www.example.com/"
ProxyPassReverse "/images/"  "http://www.example.com/"
    </highlight>

    <p>En este ejemplo, se hará proxy al backend especificado,
    de cualquier solicitud que comience con la ruta <code>/images/</code>, si 
    no se gestionarán localmente.
    </p>
  </section>

  <section id="cluster">
    <title>Clusters y Balanceadores</title>

    <p>
      Aunque los ejemplos de más arriba son útiles, tienen la deficiencia en la 
      que si el backend se cae, o recibe mucha carga, hacer proxy de esas solicitudes 
      no aporta grandes beneficios. Lo que se necesita es la habilidad de definir un 
      grupo de servidores backend que puedan gestionar esas peticiones y que el proxy 
      inverso pueda balancear la carga y aplicar la tolerancia a fallos entre los backend. 
      A veces a este grupo se le llama <em>cluster</em>, pero el término para Apache httpd
      es <em>balanceador</em>. Se puede definir un balanceador usando las directivas
      <directive module="mod_proxy" type="section">Proxy</directive> and
      <directive module="mod_proxy">BalancerMember</directive> como se muestra 
      a continuación:
    </p>

    <highlight language="config">
&lt;Proxy balancer://myset&gt;
    BalancerMember http://www2.example.com:8080
    BalancerMember http://www3.example.com:8080
    ProxySet lbmethod=bytraffic
&lt;/Proxy&gt;

ProxyPass "/images/"  "balancer://myset/"
ProxyPassReverse "/images/"  "balancer://myset/"
    </highlight>

    <p>
      El esquema <code>balancer://</code> es lo que le dice a httpd que estamos 
      generando un grupo de balanceo, con el nombre <em>myset</em>. Incluye 2 
      servidores backend, que httpd llama <em>BalancerMember</em>. En este caso, 
      se hará proxy inverso de cualquier petición para <code>/images/</code> 
      hacia <em>uno</em> de los dos backend.
      La directiva <directive module="mod_proxy">ProxySet</directive> especifica que 
      el Balanceador <em>myset</em> usa un algoritmo que balancea basado en los 
      bytes de entrada/salida (I/O).
    </p>

    <note type="hint"><title>Información adicional</title>
      <p>
      	También se refiere a los Miembros del Balanceador <em>BalancerMember</em> 
        como <em>workers</em> (trabajadores).
      </p>
   </note>

  </section>

  <section id="config">
    <title>Configuración de Balanceador y BalancerMember</title>

    <p>
      Puede ajustar numerosos parámetros de los <em>balanceadores</em>
      y los <em>workers</em> definiéndolos a través de la directiva
      <directive module="mod_proxy">ProxyPass</directive>. Por ejemplo,
      asumiendo que quisiéramos que <code>http://www3.example.com:8080</code> gestionara 
      3 veces más tráfico con un "timeout" de 1 segundo, ajustaríamos la configuración como sigue:
    </p>

    <highlight language="config">
&lt;Proxy balancer://myset&gt;
    BalancerMember http://www2.example.com:8080
    BalancerMember http://www3.example.com:8080 loadfactor=3 timeout=1
    ProxySet lbmethod=bytraffic
&lt;/Proxy&gt;

ProxyPass "/images/"  "balancer://myset/"
ProxyPassReverse "/images/"  "balancer://myset/"
    </highlight>

  </section>

  <section id="failover">
    <title>Tolerancia a fallos</title>

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

    <highlight language="config">
&lt;Proxy balancer://myset&gt;
    BalancerMember http://www2.example.com:8080
    BalancerMember http://www3.example.com:8080 loadfactor=3 timeout=1
    BalancerMember http://hstandby.example.com:8080 status=+H
    BalancerMember http://bkup1.example.com:8080 lbset=1
    BalancerMember http://bkup2.example.com:8080 lbset=1
    ProxySet lbmethod=byrequests
&lt;/Proxy&gt;

ProxyPass "/images/"  "balancer://myset/"
ProxyPassReverse "/images/"  "balancer://myset/"
    </highlight>

    <p>
      La "magia" de ésta configuración de tolerancia a fallos es configurar 
      <code>http://hstandby.example.com:8080</code> con la marca de estado 
      <code>+H</code>, que lo pone en modo <em>hot standby</em> (en reserva), 
      y hacen que los dos servidores <code>bkup#</code> sean parte del set nº 1 del
      balanceo de carga (el valor por defecto es 0); para tolerancia a fallos, los "hot standby" (si existen) se usan primero cuando todos los workers estándar activos no están disponibles; los set de balanceo con números inferiores se usan siempre primero.
    </p>

  </section>

  <section id="manager">
    <title>Gestor del Balanceador</title>

    <p>
      Una de las características más útiles y única del proxy inverso de Apache 
      httpd es la aplicación embebida <em>balancer-manager</em> (gestor de balanceo). 
      wSimilar a <module>mod_status</module>, <em>balancer-manager</em> muestra
      la configuración actual que está funcionando, el estado de los balanceadores 
      activados y workers que están en uso en ese momento. Aun así, no sólo muestra 
      estos parámetros, también permite reconfiguración dinámica, en tiempo real, de 
      prácticamente todos ellos, incluido añadir nuevos <em>BalancerMember</em> (workers) 
      a un balanceo existente. Para activar esta prestación, se tiene que añadir lo siguiente a la configuración:
    </p>

    <highlight language="config">
&lt;Location "/balancer-manager"&gt;
    SetHandler balancer-manager
    Require host localhost
&lt;/Location&gt;
    </highlight>

    <note type="warning"><title>Atención</title>
      <p>No active el <em>balancer-manager</em> hasta que haya <a
      href="../mod/mod_proxy.html#access">securizado su servidor</a>. En particular, 
      asegúrese de que el acceso a ésta URL (la de configuración del balanceador) 
      esté altamente restringido.</p>
    </note>

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
      inverso, asegúrese de que <directive module="mod_proxy">BalancerPersist</directive> está activado.
    </p>

  </section>

  <section id="health-check">
    <title>Comprobaciones de estado dinámicas</title>

    <p>
      Antes de que httpd haga proxy de una petición a un worker, puede <em>"comprobar"</em> 
      si ese worker está disponible mediante el parámetro de configuración <code>ping</code> 
      para ese worker usando <directive module="mod_proxy">ProxyPass</directive>. 
      A menudo es más útil comprobar el estado de los workers <em>no disponibles</em>, 
      con un método dinámico. Esto se consigue con el módulo <module>mod_proxy_hcheck</module>.
    </p>

  </section>

  <section id="status">
    <title>Marcas de estado de los Miembros del Balanceador</title>

    <p>
      En el <em>balancer-manager</em> el estado actual, o <em>status</em>, de un worker 
      se muestra y puede ser configurado/reseteado. El significado de estos estados es el siguiente:
    </p>
      <table border="1">
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
  </section>

</manualpage>
