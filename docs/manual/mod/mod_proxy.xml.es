<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- Spanish Translation: Arturo Bernal <arturobernalg@gmail.com> -->

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

<modulesynopsis metafile="mod_proxy.xml.meta">

<name>mod_proxy</name>
<description>Servidor proxy/gateway multiprotocolo</description>
<status>Extension</status>
<sourcefile>mod_proxy.c</sourcefile>
<identifier>proxy_module</identifier>

<summary>
    <note type="warning"><title>Advertencia</title>
      <p>No active el proxy con <directive module="mod_proxy"
      >ProxyRequests</directive> hasta que haya <a href="#access"
      >asegurado su servidor</a>. Los servidores proxy abiertos son peligrosos
      tanto para su red como para Internet en general.</p>
    </note>

    <p><module>mod_proxy</module> y los módulos relacionados implementan un
    proxy/gateway para el servidor HTTP Apache, admitiendo varios protocolos
    populares, así como distintos algoritmos de balanceo de carga.
    Módulos de terceros pueden añadir soporte para protocolos y
    algoritmos de balanceo de carga adicionales.</p>

    <p>Debe cargarse en el servidor un conjunto de módulos para proporcionar
    las funcionalidades necesarias. Estos módulos pueden incluirse de forma
    estática en el momento de compilación o de forma dinámica mediante la
    directiva <directive module="mod_so">LoadModule</directive>.
    El conjunto debe incluir:</p>

    <ul>
      <li><module>mod_proxy</module>, que proporciona las capacidades
      básicas de proxy</li>

      <li><module>mod_proxy_balancer</module> y uno o más módulos de
      balanceador si se requiere balanceo de carga. (Consulte
      <module>mod_proxy_balancer</module> para más información.)</li>

      <li>uno o más módulos de esquema o protocolo de proxy:

        <table border="1">
        <tr><th>Protocolo</th><th>Módulo</th></tr>
        <tr><td>AJP13 (Apache JServ Protocol versión
          1.3)</td><td><module>mod_proxy_ajp</module></td></tr>
        <tr><td>CONNECT (para
          SSL)</td><td><module>mod_proxy_connect</module></td></tr>
        <tr><td>FastCGI</td><td><module>mod_proxy_fcgi</module></td></tr>
        <tr><td>ftp</td><td><module>mod_proxy_ftp</module></td></tr>
        <tr><td>HTTP/0.9, HTTP/1.0 y
          HTTP/1.1</td><td><module>mod_proxy_http</module></td></tr>
        <tr><td>HTTP/2.0</td><td><module>mod_proxy_http2</module></td></tr>
        <tr><td>SCGI</td><td><module>mod_proxy_scgi</module></td></tr>
        <tr><td>UWSGI</td><td><module>mod_proxy_uwsgi</module></td></tr>
        <tr><td>WS y WSS (Web-sockets)</td><td><module>mod_proxy_wstunnel</module></td></tr>
        </table>
      </li>
    </ul>

    <p>Además, otros módulos proporcionan funcionalidades extendidas.
    <module>mod_cache</module> y módulos relacionados proporcionan el
    caché. La capacidad de contactar con servidores remotos usando el
    protocolo SSL/TLS la proporcionan las directivas <code>SSLProxy*</code>
    de <module>mod_ssl</module>. Estos módulos adicionales deberán
    cargarse y configurarse para aprovechar estas funcionalidades.</p>
</summary>
<seealso><module>mod_cache</module></seealso>
<seealso><module>mod_proxy_ajp</module></seealso>
<seealso><module>mod_proxy_balancer</module></seealso>
<seealso><module>mod_proxy_connect</module></seealso>
<seealso><module>mod_proxy_fcgi</module></seealso>
<seealso><module>mod_proxy_ftp</module></seealso>
<seealso><module>mod_proxy_hcheck</module></seealso>
<seealso><module>mod_proxy_http</module></seealso>
<seealso><module>mod_proxy_scgi</module></seealso>
<seealso><module>mod_proxy_wstunnel</module></seealso>
<seealso><module>mod_ssl</module></seealso>

    <section id="forwardreverse"><title>Proxies directos e
       inversos/gateways</title>
      <p>El servidor HTTP Apache puede configurarse tanto en modo
      <dfn>directo</dfn> como <dfn>inverso</dfn> (también conocido como
      <dfn>gateway</dfn>).</p>

      <p>Un <dfn>proxy directo</dfn> ordinario es un servidor intermedio
      situado entre el cliente y el <em>servidor de origen</em>. Para
      obtener contenido del servidor de origen, el cliente envía una
      petición al proxy indicando el servidor de origen como destino. El
      proxy entonces solicita el contenido del servidor de origen y lo
      devuelve al cliente. El cliente debe configurarse específicamente
      para usar el proxy directo al acceder a otros sitios.</p>

      <p>Un uso típico de un proxy directo es proporcionar acceso a
      Internet a clientes internos que de otra forma están restringidos
      por un cortafuegos. El proxy directo también puede usar caché
      (proporcionado por <module>mod_cache</module>) para reducir el uso
      de la red.</p>

      <p>El proxy directo se activa usando la directiva <directive
      module="mod_proxy">ProxyRequests</directive>. Dado que los proxies
      directos permiten a los clientes acceder a sitios arbitrarios a
      través de su servidor y ocultar su origen real, es esencial que
      <a href="#access">asegure su servidor</a> para que solo los
      clientes autorizados puedan acceder al proxy antes de activar un
      proxy directo.</p>

      <p>Un <dfn>proxy inverso</dfn> (o <dfn>gateway</dfn>), por el
      contrario, aparece ante el cliente igual que un servidor web
      ordinario. No se necesita configuración especial en el cliente.
      El cliente realiza peticiones ordinarias de contenido dentro del
      espacio de nombres del proxy inverso. El proxy inverso entonces
      decide a dónde enviar esas peticiones y devuelve el contenido
      como si él mismo fuera el origen.</p>

      <p>Un uso típico de un proxy inverso es proporcionar a los
      usuarios de Internet acceso a un servidor que está detrás de un
      cortafuegos. Los proxies inversos también pueden usarse para
      balancear la carga entre varios servidores de backend o para
      proporcionar caché a un servidor de backend más lento. Además,
      los proxies inversos pueden usarse simplemente para unir varios
      servidores en el mismo espacio de URL.</p>

      <p>Un proxy inverso se activa usando la directiva <directive
      module="mod_proxy">ProxyPass</directive> o el indicador
      <code>[P]</code> de la directiva <directive
      module="mod_rewrite">RewriteRule</directive>. <strong>No</strong>
      es necesario activar <directive
      module="mod_proxy">ProxyRequests</directive> para configurar un
      proxy inverso.</p>
    </section> <!-- /forwardreverse -->

    <section id="examples"><title>Ejemplos básicos</title>

    <p>Los ejemplos siguientes son solo una idea muy básica para
    ayudarle a empezar. Lea la documentación de cada directiva
    individual.</p>

    <p>Además, si desea tener la caché habilitada, consulte la
    documentación de <module>mod_cache</module>.</p>

    <example><title>Proxy inverso</title>
    <highlight language="config">
ProxyPass        "/foo" "http://foo.example.com/bar"
ProxyPassReverse "/foo" "http://foo.example.com/bar"
    </highlight>
    </example>

    <example><title>Proxy directo</title>
    <highlight language="config">
ProxyRequests On
ProxyVia On

&lt;Proxy *&gt;
  Require host internal.example.com
&lt;/Proxy&gt;
    </highlight>
    </example>
    <example><title><a id="wsupgrade" name="wsupgrade">Upgrade de Websocket (2.4.47 y posteriores)</a></title>
    <highlight language="config">
ProxyPass "/some/ws/capable/path/" "http://example.com/some/ws/capable/path/" upgrade=websocket
    </highlight>
    </example>
    </section> <!-- /examples -->

    <section id="handler"><title>Acceso mediante Handler</title>

      <p>También puede forzar que una petición se maneje como una
        petición de proxy inverso, creando un pass-through de Handler
        adecuado. La configuración de ejemplo siguiente pasará todas las
        peticiones de scripts PHP al servidor FastCGI indicado usando
        proxy inverso:
      </p>

      <example><title>Scripts PHP en proxy inverso</title>
      <highlight language="config">
&lt;FilesMatch "\.php$"&gt;
    SetHandler  "proxy:unix:/path/to/app.sock|fcgi://localhost"
&lt;/FilesMatch&gt;
      </highlight>
      </example>

      <p>Esta funcionalidad está disponible en el servidor HTTP Apache
      2.4.10 y posteriores.</p>

    </section> <!-- /handler -->

    <section id="workers"><title>Workers</title>
      <p>El proxy gestiona la configuración de los servidores de origen
      y sus parámetros de comunicación en objetos llamados
      <dfn>workers</dfn>. Hay dos workers integrados: el worker de proxy
      directo por defecto y el worker de proxy inverso por defecto. Se
      pueden configurar workers adicionales de forma explícita.</p>

      <p>Los dos workers por defecto tienen una configuración fija y se
      usarán si ningún otro worker coincide con la petición. No usan
      HTTP Keep-Alive ni reutilización de conexiones. Las conexiones TCP
      al servidor de origen se abrirán y cerrarán en cada petición.</p>

      <p>Los workers configurados explícitamente se identifican por su
      URL. Normalmente se crean y configuran usando <directive
      module="mod_proxy">ProxyPass</directive> o <directive
      module="mod_proxy">ProxyPassMatch</directive> cuando se usan para
      un proxy inverso:</p>

      <highlight language="config">
ProxyPass "/example" "http://backend.example.com" connectiontimeout=5 timeout=30
      </highlight>

      <p>Esto creará un worker asociado a la URL del servidor de origen
      <code>http://backend.example.com</code> que usará los valores de
      timeout indicados. Todos los timeouts usan la sintaxis de
      directiva <a href="directive-dict.html#Syntax">time-interval</a>.
      Cuando se usan en un proxy directo, los workers suelen definirse
      mediante la directiva <directive module="mod_proxy">ProxySet</directive>:</p>

      <highlight language="config">
          ProxySet http://backend.example.com connectiontimeout=5 timeout=30
      </highlight>

      <p>o alternativamente usando <directive module="mod_proxy">Proxy</directive>
      y <directive module="mod_proxy">ProxySet</directive>:</p>

      <highlight language="config">
&lt;Proxy http://backend.example.com&gt;
  ProxySet connectiontimeout=5 timeout=30
&lt;/Proxy&gt;
      </highlight>

      <p>Usar workers configurados explícitamente en modo directo no es
      muy habitual, porque los proxies directos suelen comunicarse con
      muchos servidores de origen distintos. Crear workers explícitos
      para algunos de los servidores de origen puede seguir siendo útil
      si se usan muy a menudo. Los workers configurados explícitamente
      no tienen por sí mismos ningún concepto de proxy directo o
      inverso. Encapsulan un concepto común de comunicación con los
      servidores de origen. Un worker creado por <directive
      module="mod_proxy">ProxyPass</directive> para usarse en un proxy
      inverso también se usará para peticiones de proxy directo siempre
      que la URL del servidor de origen coincida con la URL del worker,
      y viceversa.</p>

      <p>La URL que identifica a un worker directo es la URL de su
      servidor de origen incluyendo cualquier componente de ruta
      indicado:</p>

     <highlight language="config">
ProxyPass "/examples" "http://backend.example.com/examples"
ProxyPass "/docs"     "http://backend.example.com/docs"
      </highlight>

      <p>Este ejemplo define dos workers distintos, cada uno con su
      propio grupo de conexiones y configuración.</p>

      <note type="warning"><title>Compartición de workers</title>
        <p>La compartición de workers ocurre si las URL de los workers
        se superponen, lo que sucede cuando la URL de algún worker es
        una subcadena inicial de la URL de otro worker definido más
        adelante en el archivo de configuración. En el siguiente
        ejemplo</p>

        <highlight language="config">
ProxyPass "/apps"     "http://backend.example.com/" timeout=60
ProxyPass "/examples" "http://backend.example.com/examples" timeout=10
        </highlight>

        <p>el segundo worker en realidad no se crea. En su lugar se usa
        el primer worker. El beneficio es que solo hay un grupo de
        conexiones, por lo que las conexiones se reutilizan más a
        menudo. Tenga en cuenta que todos los atributos de
        configuración indicados explícitamente para el segundo worker
        se ignorarán. Esto se registrará como una advertencia. En el
        ejemplo anterior, el valor de timeout resultante para la URL
        <code>/examples</code> será <code>60</code> en lugar de
        <code>10</code>.</p>

        <p>Si desea evitar la compartición de workers, ordene sus
        definiciones de worker por longitud de URL, empezando por las
        URL de worker más largas. Si desea maximizar la compartición de
        workers, use el orden inverso. Consulte también la advertencia
        relacionada sobre el orden de las directivas <directive
        module="mod_proxy">ProxyPass</directive>.</p>

      </note> <!-- /worker_sharing -->

      <note type="warning"><title>Parte de host en la URL</title>
        <p>La parte de host debe empezar por una letra [a-z]. Por
        ejemplo:</p>
        <highlight language="config">
ProxyPass "/apps"     "http://127"
        </highlight>
        <p>no es válido y provocará un error al procesar una petición
        que resuelve la ruta.</p>
      </note>

      <p>Los workers configurados explícitamente se presentan en dos
      variantes: <dfn>workers directos</dfn> y <dfn>workers
      balanceadores (de carga)</dfn>. Admiten muchos atributos de
      configuración importantes que se describen más abajo en la
      directiva <directive module="mod_proxy">ProxyPass</directive>. Los
      mismos atributos también pueden establecerse usando <directive
      module="mod_proxy">ProxySet</directive>.</p>

      <p>El conjunto de opciones disponibles para un worker directo
      depende del protocolo especificado en la URL del servidor de
      origen. Los protocolos disponibles incluyen <code>ajp</code>,
      <code>fcgi</code>, <code>ftp</code>, <code>http</code> y
      <code>scgi</code>.</p>

      <p>Los workers balanceadores son workers virtuales que usan
      workers directos conocidos como sus miembros para manejar
      realmente las peticiones. Cada balanceador puede tener varios
      miembros. Cuando maneja una petición, elige un miembro según el
      algoritmo de balanceo de carga configurado.</p>

      <p>Se crea un worker balanceador si la URL de su worker usa
      <code>balancer</code> como esquema de protocolo. La URL del
      balanceador identifica de forma única al worker balanceador. Los
      miembros se añaden a un balanceador usando <directive
      module="mod_proxy">BalancerMember</directive>.</p>

      <note><title>Resolución DNS para dominios de origen</title>
      <p>La resolución DNS ocurre cuando el socket al dominio de origen
        se crea por primera vez. Cuando la reutilización de conexiones
        está habilitada, cada dominio de backend se resuelve solo una
        vez por proceso hijo, y se cachea para todas las conexiones
        posteriores hasta que el proceso hijo se recicla. Debe tenerse
        en cuenta esta información al planificar tareas de mantenimiento
        de DNS que afecten a dominios de backend. Consulte también los
        parámetros de <directive module="mod_proxy">ProxyPass</directive>
        para más detalles sobre la reutilización de conexiones.
        </p>
      </note>

    </section> <!-- /workers -->

    <section id="access"><title>Controlar el acceso a su proxy</title>
      <p>Puede controlar quién puede acceder a su proxy mediante el
      bloque de control de sección <directive
      module="mod_proxy" type="section">Proxy</directive>, como en el
      siguiente ejemplo:</p>

      <highlight language="config">
&lt;Proxy *&gt;
  Require ip 192.168.0
&lt;/Proxy&gt;
      </highlight>

      <note><title>Peticiones HTTPS/CONNECT</title>
      <p>El comodín <code>&lt;Proxy "*"&gt;</code> anterior coincide con
      todas las peticiones, incluidas las peticiones HTTPS tunelizadas
      mediante el método CONNECT. Tenga en cuenta que el control de
      acceso para túneles CONNECT solo puede comparar el host y el
      puerto; la comparación basada en ruta (por ejemplo,
      <code>&lt;Proxy "https://example.com/path/"&gt;</code>) no
      funciona porque las peticiones CONNECT no contienen una ruta.</p></note>

      <p>Para más información sobre las directivas de control de
      acceso, consulte <module>mod_authz_host</module>.</p>

      <p>Limitar estrictamente el acceso es esencial si está usando un
      proxy directo (usando la directiva <directive
      module="mod_proxy">ProxyRequests</directive>). De lo contrario,
      cualquier cliente puede usar su servidor para acceder a hosts
      arbitrarios mientras oculta su verdadera identidad. Esto es
      peligroso tanto para su red como para Internet en general. Cuando
      se usa un proxy inverso (usando la directiva <directive
      module="mod_proxy">ProxyPass</directive> con
      <code>ProxyRequests Off</code>), el control de acceso es menos
      crítico porque los clientes solo pueden contactar con los hosts
      que usted ha configurado específicamente.</p>

      <p><strong>Vea también</strong> la variable de entorno <a href="mod_proxy_http.html#env"
      >Proxy-Chain-Auth</a>.</p>

    </section> <!-- /access -->

    <section id="startup"><title>Arranque lento</title>
      <p>Si está usando la directiva <directive module="mod_proxy"
      >ProxyBlock</directive>, las direcciones IP de los hosts se
      resuelven y se cachean durante el arranque para una prueba de
      coincidencia posterior. Esto puede tardar unos segundos (o más)
      dependiendo de la velocidad con la que se realicen las búsquedas
      de nombre de host.</p>
    </section> <!-- /startup -->

    <section id="intranet"><title>Proxy de intranet</title>
      <p>Un servidor proxy Apache httpd situado en una intranet necesita
      reenviar las peticiones externas a través del cortafuegos de la
      empresa (para ello, configure la directiva <directive
      module="mod_proxy">ProxyRemote</directive> para reenviar el
      <var>scheme</var> correspondiente al proxy del cortafuegos). Sin
      embargo, cuando tiene que acceder a recursos dentro de la
      intranet, puede evitar el cortafuegos al acceder a esos hosts. La
      directiva <directive module="mod_proxy">NoProxy</directive> es
      útil para especificar qué hosts pertenecen a la intranet y deben
      accederse directamente.</p>

      <p>Los usuarios dentro de una intranet tienden a omitir el nombre
      de dominio local en sus peticiones WWW, solicitando así
      "http://somehost/" en lugar de
      <code>http://somehost.example.com/</code>. Algunos servidores
      proxy comerciales lo permiten y simplemente sirven la petición,
      implicando un dominio local configurado. Cuando se usa la
      directiva <directive module="mod_proxy"
      >ProxyDomain</directive> y el servidor está <a
      href="#proxyrequests">configurado para servicio de proxy</a>, el
      servidor HTTP Apache puede devolver una respuesta de redirección y
      enviar al cliente a la dirección de servidor correcta y
      totalmente cualificada. Este es el método preferido, ya que los
      archivos de marcadores del usuario contendrán entonces hosts
      totalmente cualificados.</p>
    </section> <!-- /intranet -->

    <section id="envsettings"><title>Ajustes de protocolo</title>
      <p>Para las circunstancias en las que <module>mod_proxy</module>
      envía peticiones a un servidor de origen que no implementa
      correctamente keepalives o HTTP/1.1, existen dos <a
      href="../env.html">variables de entorno</a> que pueden forzar que
      la petición use HTTP/1.0 sin keepalive. Se establecen mediante la
      directiva <directive module="mod_env">SetEnv</directive>.</p>

      <p>Estas son las notas <code>force-proxy-request-1.0</code> y
      <code>proxy-nokeepalive</code>.</p>

      <highlight language="config">
&lt;Location "/buggyappserver/"&gt;
  ProxyPass "http://buggyappserver:7001/foo/"
  SetEnv force-proxy-request-1.0 1
  SetEnv proxy-nokeepalive 1
&lt;/Location&gt;
        </highlight>

      <p>Tenga en cuenta que <code>force-proxy-request-1.0</code>
      también implica <code>proxy-sendcl</code>, porque HTTP/1.0 no
      admite la codificación de transferencia por bloques (chunked). El
      reenvío del cuerpo de la petición por bloques (mediante
      <code>proxy-sendchunked</code>) se deshabilitará cuando se
      establezca esta opción.</p>

      <p> En 2.4.26 y posteriores, la variable de entorno "no-proxy"
      puede establecerse para deshabilitar el procesamiento de la
      petición actual por parte de <module>mod_proxy</module>. Esta
      variable debe establecerse con <directive module="mod_setenvif"
      >SetEnvIf</directive>, ya que <directive module="mod_env">SetEnv</directive>
      no se evalúa suficientemente pronto.</p>

    </section> <!-- /envsettings -->

    <section id="request-bodies"><title>Cuerpos de petición</title>

    <p>Algunos métodos de petición, como POST, incluyen un cuerpo de
    petición. El protocolo HTTP exige que las peticiones que incluyen
    un cuerpo usen la codificación de transferencia por bloques
    (chunked) o envíen una cabecera de petición
    <code>Content-Length</code>. Al pasar estas peticiones al servidor
    de origen, <module>mod_proxy_http</module> siempre intentará
    enviar <code>Content-Length</code>. Pero si el cuerpo es grande y
    la petición original usaba codificación por bloques, entonces la
    codificación por bloques también puede usarse en la petición hacia
    el backend. Puede controlar esta selección usando <a
    href="../env.html">variables de entorno</a>. Establecer
    <code>proxy-sendcl</code> garantiza la máxima compatibilidad con
    los servidores de backend enviando siempre
    <code>Content-Length</code>, mientras que establecer
    <code>proxy-sendchunked</code> minimiza el uso de recursos usando
    codificación por bloques.</p>

    <p>Bajo algunas circunstancias, el servidor debe almacenar en disco
    los cuerpos de petición para satisfacer el manejo solicitado de los
    cuerpos de petición. Por ejemplo, este almacenamiento ocurrirá si
    el cuerpo original se envió con codificación por bloques (y es
    grande), pero el administrador ha solicitado que las peticiones al
    backend se envíen con Content-Length o como HTTP/1.0. Este
    almacenamiento también puede ocurrir si el cuerpo de la petición ya
    tiene una cabecera Content-Length, pero el servidor está
    configurado para filtrar los cuerpos de petición entrantes.</p>

    </section> <!-- /request-bodies -->

    <section id="x-headers"><title>Cabeceras de petición del proxy
    inverso</title>

    <p>Cuando actúa en modo proxy inverso (usando la directiva
    <directive module="mod_proxy">ProxyPass</directive>, por ejemplo),
    <module>mod_proxy_http</module> añade varias cabeceras de petición
    para pasar información al servidor de origen. Estas cabeceras son:</p>

    <dl>
      <dt><code>X-Forwarded-For</code></dt>
      <dd>La dirección IP del cliente.</dd>
      <dt><code>X-Forwarded-Host</code></dt>
      <dd>El host original solicitado por el cliente en la cabecera de
       petición HTTP <code>Host</code>.</dd>
      <dt><code>X-Forwarded-Server</code></dt>
      <dd>El nombre de host del servidor proxy.</dd>
    </dl>

    <p>Tenga cuidado al usar estas cabeceras en el servidor de origen,
    ya que contendrán más de un valor (separados por comas) si la
    petición original ya contenía alguna de estas cabeceras. Por
    ejemplo, puede usar <code>%{X-Forwarded-For}i</code> en la cadena
    de formato de log del servidor de origen para registrar la
    dirección IP del cliente original, pero puede obtener más de una
    dirección si la petición pasa por varios proxies.</p>

    <p>Consulte también las directivas <directive
    module="mod_proxy">ProxyPreserveHost</directive> y <directive
    module="mod_proxy">ProxyVia</directive>, que controlan otras
    cabeceras de petición.</p>

    <p>Nota: Si necesita especificar cabeceras de petición
    personalizadas para añadirlas a la petición reenviada, use la
    directiva <directive module="mod_headers">RequestHeader</directive>.</p>

   </section> <!--/x-headers -->


<directivesynopsis type="section">
<name>Proxy</name>
<description>Contenedor para directivas aplicadas a recursos proxied</description>
<syntax>&lt;Proxy <var>wildcard-url</var>&gt; ...&lt;/Proxy&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Las directivas colocadas en secciones <directive type="section">Proxy</directive>
       se aplican solo al contenido proxied que coincida, usando una
       simple coincidencia de prefijo de cadena contra la URL. También
       se permiten comodines de estilo shell.
    </p>

    <p>Por ejemplo, lo siguiente permitirá que solo los hosts en
    <code>yournetwork.example.com</code> accedan al contenido a través
    de su servidor proxy:</p>

    <highlight language="config">
&lt;Proxy *&gt;
  Require host yournetwork.example.com
&lt;/Proxy&gt;
    </highlight>

    <p>El siguiente ejemplo procesará todos los archivos del directorio
    <code>foo</code> de <code>example.com</code> a través del filtro
    <code>INCLUDES</code> cuando se envíen a través del servidor proxy:</p>

   <highlight language="config">
&lt;Proxy http://example.com/foo/*&gt;
  SetOutputFilter INCLUDES
&lt;/Proxy&gt;
    </highlight>

    <p>El siguiente ejemplo permitirá que los clientes web de las
    direcciones IP indicadas emitan peticiones <code>CONNECT</code>
    para acceder al servidor SSL
    <code>https://www.example.com/</code> si
    <module>mod_proxy_connect</module> está habilitado.
    </p>

   <highlight language="config">
&lt;Proxy www.example.com:443&gt;
  Require ip 192.168.0.0/16
&lt;/Proxy&gt;
   </highlight>

   <note type="warning"><title>Advertencia</title>
   Esta sección de configuración no canonicaliza ninguna parte de la
   cadena con la que compara, como esquemas, nombres de host,
   direcciones IP, etc. Debe tenerse cuidado si se usa para control de
   acceso, incluyendo, entre otras cosas, denegar el acceso por defecto
   y permitir los nombres de host esperados en lugar de lo inverso,
   donde una denegación podría eludirse usando formas alternativas.
    </note>

    <note><title>Diferencias con la sección de configuración Location</title>
      <p>Una URL de backend coincide con la sección de configuración si
      comienza con la cadena <var>wildcard-url</var>, incluso si el
      último segmento de ruta de la directiva solo coincide con un
      prefijo de la URL de backend. Por ejemplo,
      &lt;Proxy http://example.com/foo&gt; coincide con todas estas:
      http://example.com/foo, http://example.com/foo/bar, y
      http://example.com/foobar. La coincidencia de la URL final
      difiere del comportamiento de la sección <directive type="section" module="core"
      >Location</directive>, que a efectos de esta nota trata el
      componente final de la ruta como si terminara en una barra.</p>
      <p>Para más control sobre la coincidencia, consulte <directive type="section"
      >ProxyMatch</directive>.</p>
    </note>

</usage>
<seealso><directive type="section" module="mod_proxy">ProxyMatch</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ProxyBadHeader</name>
<description>Determina cómo manejar líneas de cabecera incorrectas en
una respuesta</description>
<syntax>ProxyBadHeader IsError|Ignore|StartBody</syntax>
<default>ProxyBadHeader IsError</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>ProxyBadHeader</directive> determina el
    comportamiento de <module>mod_proxy</module> si recibe líneas de
    cabecera de respuesta sintácticamente no válidas (<em>es decir</em>
    sin dos puntos) del servidor de origen. Son posibles los siguientes
    argumentos:</p>

    <dl>
    <dt><code>IsError</code></dt>
    <dd>Aborta la petición y termina con una respuesta 502 (Bad
    Gateway). Este es el comportamiento por defecto.</dd>

    <dt><code>Ignore</code></dt>
    <dd>Trata las líneas de cabecera incorrectas como si no se hubieran
    enviado.</dd>

    <dt><code>StartBody</code></dt>
    <dd>Al recibir la primera línea de cabecera incorrecta, termina de
    leer las cabeceras y trata el resto como cuerpo. Esto ayuda a evitar
    problemas con servidores de backend defectuosos que olvidan
    insertar una línea vacía entre las cabeceras y el cuerpo.</dd>
    </dl>
</usage>
</directivesynopsis>

<directivesynopsis type="section">
<name>ProxyMatch</name>
<description>Contenedor para directivas aplicadas a recursos proxied
que coinciden con una expresión regular</description>
<syntax>&lt;ProxyMatch <var>regex</var>&gt; ...&lt;/ProxyMatch&gt;</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva de sección <directive type="section">ProxyMatch</directive> es
    idéntica a la directiva de sección <directive module="mod_proxy"
    type="section">Proxy</directive>, salvo que compara URL usando
    <glossary ref="regex">expresiones regulares</glossary>.</p>

   <note type="warning"><title>Advertencia</title>
   Esta sección de configuración no canonicaliza ninguna parte de la
   cadena con la que compara, como esquemas, nombres de host,
   direcciones IP, etc. Debe tenerse cuidado si se usa para control de
   acceso, incluyendo, entre otras cosas, denegar el acceso por defecto
   y permitir los nombres de host esperados en lugar de lo inverso,
   donde una denegación podría eludirse usando formas alternativas.
   </note>

    <p>A partir de 2.4.8, los grupos con nombre y las referencias
    inversas se capturan y se escriben en el entorno con el nombre
    correspondiente precedido de "MATCH_" y en mayúsculas. Esto permite
    referenciar elementos de las URL desde <a href="../expr.html">expresiones</a>
    y módulos como <module>mod_rewrite</module>. Para evitar confusión,
    las referencias inversas numeradas (sin nombre) se ignoran. Use
    grupos con nombre en su lugar.</p>

<highlight language="config">
&lt;ProxyMatch "^http://(?&lt;sitename&gt;[^/]+)"&gt;
    Require ldap-group cn=%{env:MATCH_SITENAME},ou=combined,o=Example
&lt;/ProxyMatch&gt;
</highlight>
</usage>
<seealso><directive type="section" module="mod_proxy">Proxy</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ProxyPreserveHost</name>
<description>Usa la cabecera de petición HTTP Host entrante para la
petición de proxy</description>
<syntax>ProxyPreserveHost On|Off</syntax>
<default>ProxyPreserveHost Off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context>
</contextlist>
<compatibility>Usable en contexto de directorio
en 2.3.3 y posteriores.</compatibility>

<usage>
    <p>Cuando está habilitada, esta opción pasará la línea
    <code>Host:</code> de la petición entrante al host proxied, en
    lugar del nombre de host especificado en la línea <directive
    module="mod_proxy">ProxyPass</directive>.</p>

    <p>Esta opción normalmente debería estar desactivada
    (<code>Off</code>). Es útil principalmente en configuraciones
    especiales, como alojamiento virtual masivo basado en nombre a
    través de proxy, donde la cabecera Host original necesita ser
    evaluada por el servidor de backend.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyRequests</name>
<description>Habilita peticiones de proxy directo (estándar)</description>
<syntax>ProxyRequests On|Off</syntax>
<default>ProxyRequests Off</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Esto permite o impide que el servidor HTTP Apache funcione como
    un proxy directo. (Establecer ProxyRequests en <code>Off</code> no
    deshabilita el uso de la directiva <directive module="mod_proxy">ProxyPass</directive>.)</p>

    <p>En una configuración típica de proxy inverso o gateway, esta
    opción debería establecerse en
    <code>Off</code>.</p>

    <p>Para obtener la funcionalidad de hacer proxy de sitios HTTP o
    FTP, también necesita que <module>mod_proxy_http</module> o
    <module>mod_proxy_ftp</module> (o ambos) estén presentes en el
    servidor.</p>

    <p>Para obtener la funcionalidad de hacer proxy (directo) de sitios
    HTTPS, necesita tener <module>mod_proxy_connect</module> habilitado
    en el servidor.</p>

    <note type="warning"><title>Advertencia</title>
      <p>No active el proxy con la directiva <directive
      module="mod_proxy">ProxyRequests</directive> hasta que haya <a
      href="#access">asegurado su servidor</a>. Los servidores proxy
      abiertos son peligrosos tanto para su red como para Internet en
      general.</p>
    </note>
</usage>
<seealso><a href="#forwardreverse">Proxies directos e inversos/gateways</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ProxyRemote</name>
<description>Proxy remoto usado para manejar ciertas peticiones</description>
<syntax>ProxyRemote <var>match</var> <var>remote-server</var> [<var>username:password</var>]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<compatibility>El tercer argumento opcional solo se puede usar en httpd 2.5.1 y posteriores.</compatibility>

<usage>
    <p>Esto define proxies remotos para este proxy. <var>match</var> es
    bien el nombre de un esquema de URL admitido por el servidor
    remoto, bien una URL parcial para la que debe usarse el servidor
    remoto, o <code>*</code> para indicar que el servidor debe
    contactarse para todas las peticiones. <var>remote-server</var> es
    una URL parcial para el servidor remoto. Sintaxis:</p>

    <example>
      <dfn>remote-server</dfn> =
          <var>scheme</var>://<var>hostname</var>[:<var>port</var>]
    </example>

    <p><var>scheme</var> es, en la práctica, el protocolo que debe
    usarse para comunicarse con el servidor remoto; este módulo solo
    admite <code>http</code> y <code>https</code>. Cuando se usa
    <code>https</code>, las peticiones se reenvían a través del proxy
    remoto usando el método HTTP CONNECT.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
ProxyRemote http://goodguys.example.com/ http://mirrorguys.example.com:8000
ProxyRemote * http://cleverproxy.localdomain
ProxyRemote ftp http://ftpproxy.mydomain:8080
    </highlight>
    </example>

    <p>En el último ejemplo, el proxy reenviará las peticiones FTP,
    encapsuladas como otra petición de proxy HTTP más, a otro proxy que
    pueda manejarlas.</p>

    <p>Esta opción también admite configuraciones de proxy inverso; un
    servidor web de backend puede incrustarse dentro del espacio de URL
    de un virtualhost incluso si ese servidor está oculto por otro
    proxy directo.</p>

    <p>Puede darse un tercer argumento opcional
    <var>username:password</var>, que define las credenciales de
    autenticación Basic que se pasarán al proxy remoto configurado.
    Las credenciales siempre se enviarán sin esperar primero a que el
    proxy remoto envíe un desafío de autenticación Basic. La variable
    de entorno <a
    href="mod_proxy_http.html#env">Proxy-Chain-Auth</a> no tiene efecto
    si se usa este argumento.</p>

    <note><title>Resolución DNS y proxies directos</title>
    <p>Cuando se configura un proxy directo (remoto), la resolución DNS
    del nombre de host de origen/backend solo se realiza en el proxy
    directo. Cualquier regla de <directive module="mod_proxy">ProxyBlock</directive>
    que restrinja el acceso a direcciones IP específicas debe
    configurarse en el proxy directo.</p></note>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyRemoteMatch</name>
<description>Proxy remoto usado para manejar peticiones que coinciden
mediante expresiones regulares</description>
<syntax>ProxyRemoteMatch <var>regex</var> <var>remote-server</var> [<var>username:password</var>]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<compatibility>El tercer argumento opcional solo se puede usar en httpd 2.5.1 y posteriores.</compatibility>

<usage>
    <p><directive>ProxyRemoteMatch</directive> es idéntica a la
    directiva <directive module="mod_proxy">ProxyRemote</directive>,
    salvo que el primer argumento es una coincidencia de <glossary ref="regex">expresión regular</glossary>
    contra la URL solicitada.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>BalancerGrowth</name>
<description>Número de Balanceadores adicionales que pueden añadirse tras la configuración</description>
    <syntax>BalancerGrowth <var>#</var></syntax>
    <default>BalancerGrowth 5</default>
    <contextlist><context>server config</context><context>virtual host</context></contextlist>
<compatibility>BalancerGrowth solo está disponible en el servidor HTTP Apache 2.3.13
  y posteriores.</compatibility>
<usage>
    <p>Esta directiva permite un margen de crecimiento en el número de
    Balanceadores disponibles para un virtualhost, además de los
    preconfigurados. Solo tiene efecto si hay al menos un Balanceador
    preconfigurado.</p>
    <p>El valor debe estar entre 0 y 1000.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
    <name>BalancerPersist</name>
    <description>Intenta persistir los cambios realizados por el Balancer Manager entre reinicios.</description>
    <syntax>BalancerPersist On|Off</syntax>
    <default>BalancerPersist Off</default>
    <contextlist><context>server config</context><context>virtual host</context></contextlist>
    <compatibility>BalancerPersist solo está disponible en el servidor HTTP Apache 2.4.4 y posteriores.</compatibility>
    <usage>
        <p>Esta directiva hará que el almacenamiento en memoria
        compartida asociado con los balanceadores y sus miembros se
        persista entre reinicios. Esto permite que estos cambios
        locales no se pierdan durante las transiciones normales de
        estado de reinicio/reinicio ordenado (graceful).</p>
    </usage>
</directivesynopsis>

<directivesynopsis>
    <name>ProxyPassInherit</name>
    <description>Hereda las directivas ProxyPass definidas en el servidor principal</description>
    <syntax>ProxyPassInherit On|Off</syntax>
    <default>ProxyPassInherit On</default>
    <contextlist><context>server config</context><context>virtual host</context></contextlist>
    <compatibility>ProxyPassInherit solo está disponible en el servidor HTTP Apache 2.4.5 y posteriores.
        </compatibility>
    <usage>
        <p>Esta directiva hará que el servidor/vhost actual "herede" las
            directivas <directive module="mod_proxy">ProxyPass</directive>
            definidas en el servidor principal. Esto puede causar
            problemas y comportamiento inconsistente si se usa el
            Balancer Manager para cambios dinámicos, por lo que debería
            deshabilitarse si se usa esa funcionalidad.</p>
        <p>El valor en el servidor global define el comportamiento por
            defecto para todos los vhosts.</p>
        <p>Deshabilitar ProxyPassInherit también deshabilita <directive module="mod_proxy">BalancerInherit</directive>.</p>
    </usage>
</directivesynopsis>

<directivesynopsis>
    <name>BalancerInherit</name>
    <description>Hereda los Balanceadores/Workers de proxy definidos en el servidor principal</description>
    <syntax>BalancerInherit On|Off</syntax>
    <default>BalancerInherit On</default>
    <contextlist><context>server config</context><context>virtual host</context></contextlist>
    <compatibility>BalancerInherit solo está disponible en el servidor HTTP Apache 2.4.5 y posteriores.</compatibility>
    <usage>
        <p>Esta directiva hará que el servidor/vhost actual "herede" los
            Balanceadores y Workers definidos en el servidor principal.
            Esto puede causar problemas y comportamiento inconsistente
            si se usa el Balancer Manager para cambios dinámicos, por lo
            que debería deshabilitarse si se usa esa funcionalidad.</p>
        <p>El valor en el servidor global define el comportamiento por
            defecto para todos los vhosts.</p>
        <p>Deshabilitar <directive module="mod_proxy">ProxyPassInherit</directive> también deshabilita BalancerInherit.</p>
    </usage>
</directivesynopsis>

<directivesynopsis>
    <name>BalancerMember</name>
    <description>Añade un miembro a un grupo de balanceo de carga</description>
    <syntax>BalancerMember [<var>balancerurl</var>] <var>url</var> [<var
        >key=value [key=value ...]]</var></syntax>
    <contextlist><context>directory</context>
    </contextlist>
    <usage>
        <p>Esta directiva añade un miembro a un grupo de balanceo de
            carga. Puede usarse dentro de una directiva contenedora
            <code>&lt;Proxy <var>balancer://</var>...&gt;</code> y puede
            tomar cualquiera de los parámetros clave-valor disponibles
            para las directivas <directive module="mod_proxy">ProxyPass</directive>.</p>
        <p>Hay un parámetro adicional disponible únicamente para las
            directivas <directive>BalancerMember</directive>:
            <var>loadfactor</var>. Este es el factor de carga del
            miembro: un decimal entre 1.0 (por defecto) y 100.0, que
            define la carga ponderada que se aplicará al miembro en
            cuestión.</p>
        <p>El <var>balancerurl</var> solo se necesita cuando no está
            dentro de una directiva contenedora
            <code>&lt;Proxy <var>balancer://</var>...&gt;</code>.
            Corresponde a la URL de un balanceador definido en la
            directiva <directive module="mod_proxy">ProxyPass</directive>.</p>
        <p>El componente de ruta de la URL del balanceador en cualquier
            directiva contenedora
            <code>&lt;Proxy <var>balancer://</var>...&gt;</code>
            se ignora.</p>
        <p>Normalmente deberían eliminarse las barras finales de la URL
            de un <directive>BalancerMember</directive>.</p>
    </usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxySet</name>
<description>Establece varios parámetros del balanceador o miembro de Proxy</description>
<syntax>ProxySet <var>url</var> <var>key=value [key=value ...]</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context>
</contextlist>
<usage>
    <p>Esta directiva se usa como método alternativo para establecer
    cualquiera de los parámetros disponibles para los balanceadores y
    workers de Proxy, normalmente realizado a través de la directiva
    <directive module="mod_proxy">ProxyPass</directive>. Si se usa
    dentro de una directiva contenedora
    <code>&lt;Proxy <var>balancer url|worker url</var>&gt;</code>, el
    argumento <var>url</var> no es necesario. Como efecto secundario se
    crea el balanceador o worker correspondiente. Esto puede ser útil
    al hacer proxy inverso mediante una
    <directive module="mod_rewrite">RewriteRule</directive> en lugar de
    una directiva <directive module="mod_proxy">ProxyPass</directive>.</p>

    <example>
        <highlight language="config">
&lt;Proxy balancer://hotcluster&gt;
    BalancerMember http://www2.example.com:8080 loadfactor=1
    BalancerMember http://www3.example.com:8080 loadfactor=2
    ProxySet lbmethod=bytraffic
&lt;/Proxy&gt;
      </highlight>
    </example>

    <highlight language="config">
&lt;Proxy http://backend&gt;
    ProxySet keepalive=On
&lt;/Proxy&gt;
    </highlight>

    <highlight language="config">
        ProxySet balancer://foo lbmethod=bytraffic timeout=15
    </highlight>

    <highlight language="config">
        ProxySet ajp://backend:7001 timeout=15
    </highlight>

   <note type="warning"><title>Advertencia</title>
      <p>Tenga en cuenta que la misma clave de parámetro puede tener un
      significado distinto dependiendo de si se aplica a un balanceador
      o a un worker, como muestran los dos ejemplos anteriores sobre
      timeout.</p>
   </note>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyPass</name>
<description>Mapea servidores remotos en el espacio de URL del servidor local</description>
<syntax>ProxyPass [<var>path</var>] !|<var>url</var> [<var>key=value</var>
  <var>[key=value</var> ...]] [nocanon] [interpolate] [noquery]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context>
</contextlist>
<compatibility>Soporte de Unix Domain Socket (UDS) añadido en 2.4.7</compatibility>

<usage>
    <p>Esta directiva permite mapear servidores remotos en el espacio
    del servidor local. El servidor local no actúa como proxy en el
    sentido convencional, sino que parece ser un espejo del servidor
    remoto. Al servidor local se le llama a menudo <dfn>proxy
    inverso</dfn> o <dfn>gateway</dfn>. <var>path</var> es el nombre de
    una ruta virtual local; <var>url</var> es una URL parcial para el
    servidor remoto y no puede incluir una cadena de consulta.</p>

    <note>Se recomienda encarecidamente revisar el concepto de
    <a href="#workers">Worker</a> antes de continuar con esta
    sección.</note>

    <note>Esta directiva no está admitida dentro de los contenedores
    <directive type="section" module="core">Directory</directive>,
    <directive type="section" module="core">If</directive> y
    <directive type="section" module="core">Files</directive>.
    </note>

    <note type="warning">La directiva <directive
    module="mod_proxy">ProxyRequests</directive> normalmente debería
    estar <strong>desactivada</strong> (off) cuando se usa
    <directive>ProxyPass</directive>.</note>

    <p>En 2.4.7 y posteriores, hay disponible soporte para usar un
    Unix Domain Socket anteponiendo <code>unix:/path/lis.sock|</code>
    al destino. Por ejemplo, para hacer proxy de HTTP apuntando al UDS
    en /home/www.socket, usaría
    <code>unix:/home/www.socket|http://localhost/whatever/</code>. Dado
    que el socket es local, el nombre de host usado (en este caso
    <code>localhost</code>) es irrelevante, pero se pasa como el valor
    de la cabecera Host: de la petición.</p>

    <note>La ruta asociada a la URL <code>unix:</code>
    tiene en cuenta <directive>DefaultRuntimeDir</directive>.</note>

    <note><directive>RewriteRule</directive> requiere
    la opción <code>[P,NE]</code> para evitar que el carácter
    <code>'|'</code> se escape.</note>

    <p>Cuando se usa dentro de una sección <directive type="section" module="core"
    >Location</directive>, se omite el primer argumento y el
    directorio local se obtiene de la <directive type="section" module="core"
    >Location</directive>. Cuando se usa fuera de una sección <directive type="section"
    module="core">Location</directive> o <directive type="section"
    module="core">LocationMatch</directive>, el argumento
    <var>path</var> es obligatorio. Lo mismo ocurrirá dentro de una
    sección <directive type="section" module="core">LocationMatch</directive>;
    sin embargo, ProxyPass no interpreta la expresión regular como tal,
    por lo que en esta situación es necesario usar
    <directive>ProxyPassMatch</directive> en su lugar.</p>

    <p>Suponga que el servidor local tiene la dirección
    <code>http://example.com/</code>; entonces</p>

    <highlight language="config">
&lt;Location "/mirror/foo/"&gt;
    ProxyPass "http://backend.example.com/"
&lt;/Location&gt;
    </highlight>

    <p>hará que una petición local de
    <code>http://example.com/mirror/foo/bar</code> se convierta
    internamente en una petición de proxy a
    <code>http://backend.example.com/bar</code>.</p>

    <p>Si necesita una configuración de proxy inverso más flexible,
    consulte la directiva <directive module="mod_rewrite">RewriteRule</directive>
    con el indicador <code>[P]</code>.</p>

    <p>Es posible la siguiente sintaxis alternativa; sin embargo, puede
    suponer una penalización de rendimiento cuando esté presente en
    números muy elevados. La ventaja de la sintaxis siguiente es que
    permite el control dinámico a través de la interfaz <a href="mod_proxy_balancer.html#balancer_manager">Balancer Manager</a>:</p>

    <highlight language="config">
        ProxyPass "/mirror/foo/" "http://backend.example.com/"
    </highlight>

    <note type="warning">
    <p>Si el primer argumento termina con una <strong>/</strong> final,
       el segundo argumento también debería terminar con una
       <strong>/</strong> final, y viceversa. De lo contrario, las
       peticiones resultantes al backend pueden carecer de algunas
       barras necesarias y no entregar los resultados esperados.
    </p>
    </note>

    <p>La directiva <code>!</code> es útil en situaciones en las que no
    quiere hacer proxy inverso de un subdirectorio, <em>p. ej.</em></p>

    <highlight language="config">
&lt;Location "/mirror/foo/"&gt;
    ProxyPass "http://backend.example.com/"
&lt;/Location&gt;
&lt;Location "/mirror/foo/i"&gt;
    ProxyPass "!"
&lt;/Location&gt;
    </highlight>

    <highlight language="config">
ProxyPass "/mirror/foo/i" "!"
ProxyPass "/mirror/foo"   "http://backend.example.com"
    </highlight>

    <p>hará proxy de todas las peticiones a <code>/mirror/foo</code>
    hacia <code>backend.example.com</code> <em>excepto</em> las
    peticiones hechas a <code>/mirror/foo/i</code>.</p>

    <p>Mezclar configuraciones de ProxyPass en contextos distintos no
    funciona:</p>
    <highlight language="config">
ProxyPass "/mirror/foo/i" "!"
&lt;Location "/mirror/foo/"&gt;
    ProxyPass "http://backend.example.com/"
&lt;/Location&gt;
    </highlight>
    <p>En este caso, una petición a <code>/mirror/foo/i</code> se
       proxificará, porque la directiva <directive>ProxyPass</directive>
       del bloque Location se evaluará primero. El hecho de que
       <directive>ProxyPass</directive> admita tanto el contexto de
       servidor como el de directorio no significa que su ámbito y
       posición en el archivo de configuración garanticen ningún orden
       o prioridad.</p>

    <note type="warning"><title>Orden de las directivas ProxyPass</title>
      <p>Las reglas <directive module="mod_proxy">ProxyPass</directive>
      y <directive module="mod_proxy">ProxyPassMatch</directive>
      configuradas se comprueban en el orden de configuración. Gana la
      primera regla que coincida. Por eso, normalmente debería ordenar
      las reglas <directive module="mod_proxy">ProxyPass</directive>
      en conflicto empezando por las URL más largas. De lo contrario,
      las reglas posteriores para URL más largas quedarán ocultas por
      cualquier regla anterior que use una subcadena inicial de la URL.
      Tenga en cuenta que esto tiene alguna relación con la
      compartición de workers.</p>
    </note>
    <note type="warning"><title>Orden de las directivas ProxyPass en Locations</title>
      <p>Solo se puede colocar una directiva <directive module="mod_proxy">ProxyPass</directive>
      en un bloque <directive module="core">Location</directive>, y el
      último bloque <directive module="core">Location</directive>
      coincidente tiene prioridad, siguiendo las reglas estándar de
      <a href="../sections.html#merging">fusión de secciones</a>.
      Coloque los bloques <directive module="core">Location</directive>
      más específicos <em>después</em> de los menos específicos para
      garantizar que se aplique el <directive module="mod_proxy">ProxyPass</directive>
      deseado.</p>
    </note>

    <note type="warning"><title>Exclusiones y la variable de entorno no-proxy</title>
      <p>Las exclusiones deben colocarse <em>antes</em> de las
      directivas <directive>ProxyPass</directive> generales. En 2.4.26
      y posteriores, la variable de entorno "no-proxy" es una
      alternativa a las exclusiones, y es la única forma de configurar
      una exclusión de una directiva <directive>ProxyPass</directive>
      en contexto <directive module="core">Location</directive>. Esta
      variable debe establecerse con <directive module="mod_setenvif"
      >SetEnvIf</directive>, ya que <directive module="mod_env">SetEnv</directive>
      no se evalúa suficientemente pronto.
      </p>

    </note> <!-- /ordering_proxypass -->

    <p><strong>Parámetros <code>key=value</code> de ProxyPass</strong></p>

    <p>En el servidor HTTP Apache 2.1 y posteriores, mod_proxy admite
    conexiones agrupadas a un servidor de backend. Las conexiones
    creadas a demanda pueden retenerse en un pool para uso futuro. Los
    límites del tamaño del pool y otros ajustes pueden codificarse en
    la directiva <directive>ProxyPass</directive> usando parámetros
    <code>key=value</code>, descritos en las tablas siguientes.</p>

    <note type="warning"><title>Conexiones máximas al backend</title>
    <p>Por defecto, mod_proxy permitirá y retendrá el número máximo de
    conexiones que podría usar simultáneamente ese proceso hijo del
    servidor web. Use el parámetro <code>max</code> para reducir el
    número respecto al valor por defecto. El pool de conexiones se
    mantiene por proceso hijo del servidor web, y <code>max</code> y
    otros ajustes no se coordinan entre todos los procesos hijo, salvo
    cuando la configuración o el diseño del MPM solo permiten un
    proceso hijo.</p>
    </note>

    <note><title>Agrupación de conexiones con el MPM prefork</title>
    <p>Con el MPM prefork, las conexiones a los backends no se agrupan
    (cada proceso hijo maneja una conexión a la vez). Los parámetros
    <code>acquire</code> y <code>ttl</code>, que controlan el
    comportamiento del pool de conexiones, no tienen efecto cuando se
    usa prefork. Los parámetros de tamaño de pool <code>min</code>,
    <code>smax</code> y <code>hmax</code> también se ignoran.</p>
    </note>

    <p>Use el parámetro <code>ttl</code> para establecer un tiempo de
    vida opcional; las conexiones que hayan estado inactivas durante al
    menos <code>ttl</code> segundos se cerrarán. <code>ttl</code> puede
    usarse para evitar usar una conexión que esté a punto de cerrarse
    por el timeout de keep-alive del servidor de backend.</p>

    <example><title>Ejemplo</title>
        <highlight language="config">
ProxyPass "/example" "http://backend.example.com" max=20 ttl=120 retry=300
        </highlight>
    </example>

    <table border="2"><tr><th>Parámetros de Worker|BalancerMember</th></tr></table>
    <table>
    <tr><th>Parámetro</th>
        <th>Por defecto</th>
        <th>Descripción</th></tr>
    <tr><td>min</td>
        <td>0</td>
        <td>Número mínimo de entradas del pool de conexiones, sin
    relación con el número real de conexiones. Solo es necesario
    modificar esto respecto al valor por defecto en circunstancias
    especiales en las que la memoria heap asociada a las conexiones de
    backend deba reservarse o retenerse de antemano.</td></tr>
    <tr><td>max</td>
        <td>1...n</td>
        <td>Número máximo de conexiones que se permitirán hacia el
    servidor de backend. El límite por defecto es el número de hilos
    por proceso en el MPM activo. En el MPM Prefork siempre es 1;
    mientras que con otros MPM, lo controla la directiva
    <directive>ThreadsPerChild</directive>.</td></tr>
    <tr><td>smax</td>
        <td>max</td>
        <td>Las entradas del pool de conexiones retenidas por encima de
    este límite se liberan durante ciertas operaciones si han estado
    inactivas más tiempo que el tiempo de vida, controlado por el
    parámetro <code>ttl</code>. Si la entrada del pool de conexiones
    tiene una conexión asociada, se cerrará. Solo es necesario
    modificar esto respecto al valor por defecto en circunstancias
    especiales en las que las entradas del pool de conexiones y
    cualquier conexión asociada que haya superado el tiempo de vida
    deban liberarse o cerrarse de forma más agresiva.</td></tr>
    <tr><td>acquire</td>
        <td>-</td>
        <td>Si se establece, será el tiempo máximo de espera, en
    milisegundos, por una conexión libre en el pool de conexiones. Si
    no hay conexiones libres en el pool, el servidor HTTP Apache
    devolverá el estado <code>SERVER_BUSY</code> al cliente.
    </td></tr>
    <tr><td>connectiontimeout</td>
        <td>timeout</td>
        <td>Timeout de conexión en segundos.
        El número de segundos que el servidor HTTP Apache espera a que se
        complete la creación de una conexión con el backend. Añadiendo
        el sufijo ms, el timeout también puede establecerse en
        milisegundos. Usa la sintaxis de directiva <a href="directive-dict.html#Syntax">time-interval</a>
    </td></tr>
    <tr><td>disablereuse</td>
        <td>Off</td>
        <td>Este parámetro debería usarse cuando desee forzar a
    mod_proxy a cerrar inmediatamente una conexión con el backend tras
    usarla, deshabilitando así su conexión persistente y el pool para
    ese backend. Esto ayuda en diversas situaciones en las que un
    cortafuegos entre el servidor HTTP Apache y el servidor de backend
    (independientemente del protocolo) tiende a descartar conexiones en
    silencio, o cuando los backends mismos pueden estar bajo DNS
    round-robin.
    Cuando la reutilización de conexiones está habilitada, cada dominio
    de backend se resuelve (con una consulta DNS) solo una vez por
    proceso hijo y se cachea para todas las conexiones posteriores
    hasta que el proceso hijo se recicla. Para deshabilitar la
    reutilización de conexiones, establezca este valor en
    <code>On</code>.
    </td></tr>
    <tr><td>enablereuse</td>
        <td>On</td>
        <td>Esto es lo inverso de 'disablereuse' anterior, proporcionado
        como una comodidad para los manejadores de esquema que
        requieren habilitación explícita para la reutilización de
        conexiones (como <module>mod_proxy_fcgi</module>).
    </td></tr>
    <tr><td>flushpackets</td>
        <td>off</td>
        <td>Determina si el módulo proxy vaciará automáticamente la
        brigada de salida tras cada "fragmento" de datos. 'off'
        significa que solo se vaciará cuando sea necesario; 'on'
        significa después de cada fragmento enviado; y 'auto' significa
        esperar sondeando durante un período de tiempo y vaciar si no se
        ha recibido entrada durante 'flushwait' milisegundos.
        Actualmente, esto solo tiene efecto para mod_proxy_ajp y
        mod_proxy_fcgi.
    </td></tr>
    <tr><td>flushwait</td>
        <td>10</td>
        <td>El tiempo a esperar entrada adicional, en milisegundos,
        antes de vaciar la brigada de salida si 'flushpackets' es
        'auto'. Usa la sintaxis de directiva <a href="directive-dict.html#Syntax">time-interval</a>.
    </td></tr>
    <tr><td>iobuffersize</td>
        <td>8192</td>
        <td>Ajusta el tamaño del búfer interno de E/S usado como
        espacio de trabajo. Esto le permite sobrescribir
        <directive>ProxyIOBufferSize</directive> para un worker
        concreto. Debe ser al menos 512, o 0 para el valor por defecto
        del sistema de 8192.
    </td></tr>
    <tr><td>responsefieldsize</td>
        <td>8192</td>
        <td>Ajusta el tamaño del búfer de campo de respuesta del proxy.
            El tamaño del búfer debería ser al menos el tamaño de
            cabecera más grande esperado de una respuesta proxied.
            Establecer el valor a 0 usará el valor por defecto del
            sistema de 8192 bytes.<br />
        Disponible en el servidor HTTP Apache 2.4.34 y posteriores.
    </td></tr>
    <tr><td>keepalive</td>
        <td>Off</td>
        <td><p>Este parámetro debería usarse cuando tenga un
    cortafuegos entre su servidor HTTP Apache y el servidor de backend,
    el cual tiende a cerrar conexiones inactivas. Este indicador le
    dirá al sistema operativo que envíe mensajes
    <code>KEEP_ALIVE</code> en conexiones inactivas, evitando así que
    el cortafuegos cierre la conexión.
    Para habilitar keepalive, establezca este valor en <code>On</code>. </p>
    <p>La frecuencia de las sondas TCP keepalive iniciales y
    posteriores depende de los ajustes globales del SO, y puede llegar
    a ser de hasta 2 horas. Para que sea útil, la frecuencia configurada
    en el SO debe ser menor que el umbral usado por el cortafuegos. Usa
    la sintaxis de directiva <a href="directive-dict.html#Syntax">time-interval</a>.</p>
    </td></tr>
    <tr><td>lbset</td>
        <td>0</td>
        <td>Establece el conjunto de clúster del balanceador de carga
         del que es miembro el worker. El balanceador de carga probará
         todos los miembros de un lbset de número menor antes de
         probar los de número mayor.
    </td></tr>
    <tr><td>ping</td>
        <td>0</td>
        <td>La propiedad ping indica al servidor web que "pruebe" la
        conexión con el backend antes de reenviar la petición. Para
        valores negativos, la prueba es una simple comprobación de
        socket; para valores positivos, es una comprobación más
        funcional, dependiente del protocolo. Para AJP, hace que
        <module>mod_proxy_ajp</module> envíe una petición
        <code>CPING</code> en la conexión ajp13 (implementado en Tomcat
        3.3.2+, 4.1.28+ y 5.0.13+). Para HTTP, hace que
        <module>mod_proxy_http</module> envíe un <code>100-Continue</code>
        al backend (solo válido para HTTP/1.1; para backends que no
        sean HTTP/1.1, esta propiedad no tiene efecto). En ambos casos,
        el parámetro es el retraso en segundos a esperar la respuesta.
        Esta funcionalidad se añadió para evitar problemas con backends
        colgados y ocupados.
        Esto incrementará el tráfico de red durante la operación normal,
        lo que podría ser un problema, pero reducirá el tráfico en caso
        de que alguno de los nodos del clúster esté caído u ocupado.
        Añadiendo el sufijo ms, el retraso también puede establecerse
        en milisegundos. Usa la sintaxis de directiva <a href="directive-dict.html#Syntax">time-interval</a>.
    </td></tr>
    <tr><td>receivebuffersize</td>
        <td>0</td>
        <td>Ajusta el tamaño del búfer de red explícito (TCP/IP) para
        conexiones proxied. Esto le permite sobrescribir
        <directive>ProxyReceiveBufferSize</directive> para un worker
        concreto. Debe ser al menos 512, o 0 para el valor por defecto
        del sistema.
    </td></tr>
    <tr><td>redirect</td>
        <td>-</td>
        <td>Ruta de redirección del worker. Este valor normalmente se
        establece de forma dinámica para permitir la retirada segura
        del nodo del clúster. Si se establece, todas las peticiones sin
        id de sesión se redirigirán al BalancerMember que tenga un
        parámetro route igual a este valor.
    </td></tr>
    <tr><td>retry</td>
        <td>60</td>
        <td>Timeout de reintento del worker del pool de conexiones, en
    segundos. Si el worker del pool de conexiones hacia el servidor de
    backend está en estado de error, el servidor HTTP Apache no
    reenviará ninguna petición a ese servidor hasta que expire el
    timeout. Esto permite apagar el servidor de backend para
    mantenimiento y volver a ponerlo en línea más tarde. Un valor de 0
    significa reintentar siempre los workers en estado de error sin
    timeout.
    Usa la sintaxis de directiva <a href="directive-dict.html#Syntax">time-interval</a>.
    </td></tr>
    <tr><td>route</td>
        <td>-</td>
        <td>Ruta del worker cuando se usa dentro de un balanceador de
        carga. La ruta es un valor añadido al id de sesión.
    </td></tr>
    <tr><td><a name="status_table">status</a></td>
        <td>-</td>
        <td>Valor de una sola letra que define el estado inicial de
        este worker.
        <table border="1">
         <tr><td><code>D</code></td><td>El worker está deshabilitado y
                    no aceptará ninguna petición; se reintentará
                    automáticamente.</td></tr>
         <tr><td><code>S</code></td><td>El worker está detenido
                    administrativamente; no aceptará peticiones y no se
                    reintentará automáticamente.</td></tr>
         <tr><td><code>I</code></td><td>El worker está en modo de
                    ignorar errores y siempre se considerará disponible.</td></tr>
         <tr><td><code>R</code></td><td>El worker es un repuesto
                    caliente (hot spare). Para cada worker de un
                    lbset dado que no esté usable (en drenaje, detenido,
                    en error, etc.), se usará en su lugar un repuesto
                    caliente usable con el mismo lbset. Los repuestos
                    calientes pueden ayudar a garantizar que siempre
                    haya disponible un número específico de workers
                    para que los use un balanceador.</td></tr>
         <tr><td><code>H</code></td><td>El worker está en modo de
                    espera caliente (hot-standby) y solo se usará si no
                    hay otros workers o repuestos viables disponibles en
                    el conjunto del balanceador.</td></tr>
         <tr><td><code>E</code></td><td>El worker está en estado de
                    error.</td></tr>
         <tr><td><code>N</code></td><td>El worker está en modo de
                    drenaje y solo aceptará sesiones persistentes
                    existentes destinadas a él mismo, ignorando el
                    resto de peticiones.</td></tr>
        </table>
        El estado puede establecerse (que es lo predeterminado)
        anteponiendo '+', o borrarse anteponiendo '-'.
        Así, un ajuste de 'S-E' pone este worker en Detenido y borra el
        indicador de error.
    </td></tr>
    <tr><td>timeout</td>
        <td><directive module="mod_proxy">ProxyTimeout</directive></td>
        <td>Timeout de socket en segundos.
        El número de segundos que el servidor HTTP Apache espera a
        datos enviados desde/hacia el backend.
        Usa la sintaxis de directiva <a href="directive-dict.html#Syntax">time-interval</a>.
    </td></tr>
    <tr><td>ttl</td>
        <td>-</td>
        <td>Tiempo de vida para conexiones inactivas y sus entradas de
        pool de conexiones asociadas, en segundos. Una vez alcanzado
        este límite, la conexión no se volverá a usar; se cerrará en
        algún momento posterior. Usa la sintaxis de directiva <a href="directive-dict.html#Syntax">time-interval</a>.
    </td></tr>
    <tr><td>flusher</td>
        <td>flush</td>
        <td><p>Nombre del proveedor usado por <module>mod_proxy_fdpass</module>.
        Consulte la documentación de ese módulo para más detalles.</p>
    </td></tr>
    <tr><td>secret</td>
        <td>-</td>
        <td><p>Valor del secreto usado por <module>mod_proxy_ajp</module>.
        Consulte la documentación de ese módulo para más detalles.</p>
    </td></tr>
    <tr><td><a id="upgrade" name="upgrade">upgrade</a></td>
        <td>-</td>
        <td><p>Protocolo aceptado por <module>mod_proxy_http</module> o
        <module>mod_proxy_wstunnel</module> para el mecanismo de
        Upgrade de HTTP tras su negociación por parte del cliente/
        navegador HTTP (según
        <rfc anchor="name-upgrade">9110</rfc> - Upgrade).
        Consulte la nota <a href="#protoupgrade">Protocol Upgrade</a> más abajo</p>
    </td></tr>
    <tr><td>mapping</td>
        <td>-</td>
        <td><p>Tipo de mapeo entre <var>path</var> y <var>url</var>.
        Esto determina la normalización y/o (no-)decodificación que
        <module>mod_proxy</module> aplicará al <var>uri-path</var>
        solicitado antes de comparar con <var>path</var>. Si un mapeo
        coincide, se aplica al <var>uri-path</var> de forma que todos
        los contextos de directorio que usan una ruta (como
        <code>&lt;Location&gt;</code>) se comparen usando el mismo
        mapeo.</p>
        <p><code>mapping=encoded</code> evita la decodificación-% del
        <var>uri-path</var>, de modo que se puedan usar configuraciones
        como, por ejemplo:</p>
        <highlight language="config">ProxyPass "/special%3Fsegment" "https://example.com/special%3Fsegment" mapping=encoded</highlight>
        <highlight language="config">&lt;Location "/special%3Fsegment"&gt;
  Require ip 172.17.2.0/24
&lt;/Location&gt;</highlight>
        <p><code>mapping=servlet</code> se refiere a la normalización
        definida por la especificación Servlet, que por ejemplo aplica
        Apache Tomcat para contenedores de servlets (en concreto, los
        parámetros de ruta se ignoran para el mapeo). Un
        <var>uri-path</var> como
        <code>/some;foo/path</code> se mapea entonces como
        <code>/some/path</code>, por lo que coincide con cualquiera de
        los siguientes, independientemente de los parámetros de ruta
        solicitados:</p>
        <highlight language="config">ProxyPass "/some/path" "https://servlet.example.com/some/path" mapping=servlet</highlight>
        <highlight language="config">&lt;Location "/some/path"&gt;
  Require valid-user
&lt;/Location&gt;</highlight>
        <note><title>Nota</title>
            <p>Se recomienda usar el mismo mapeo en el lado del
            servidor HTTP Apache que el usado en el lado del backend.
            Por ejemplo, al configurar autorizaciones en bloques
            <code>&lt;Location&gt;</code> para rutas mapeadas por
            <module>mod_proxy</module> hacia ciertos contenedores de
            servlets (como aplicaciones ejecutándose en Apache Tomcat),
            debería usarse el ajuste <code>mapping=servlet</code> para
            evitar que los parámetros de ruta y similares interfieran
            con las autorizaciones que debe aplicar el servidor HTTP
            Apache.</p>
        </note>
    </td></tr>
    <tr><td><a id="addressttl" name="addressttl">addressttl</a></td>
        <td>-1</td>
        <td><p>TTL en segundos durante el cual se cachean las
        resoluciones DNS de la dirección de backend.
        -1 significa hasta el reinicio del servidor HTTP Apache.</p>
    </td></tr>
    <tr><td><a id="multipathtcp" name="multipathtcp">multipathtcp</a></td>
        <td>Off</td>
        <td><p>Habilita/deshabilita el uso de <a href="https://mptcp.dev">Multipath TCP (MPTCP)</a></p>
    </td></tr>

    </table>

    <p>Si el esquema de la directiva Proxy comienza con
    <code>balancer://</code> (por ejemplo: <code>balancer://cluster</code>,
    se ignora cualquier información de ruta), se creará un worker
    virtual que en realidad no se comunica con el servidor de backend.
    En su lugar, es responsable de la gestión de varios workers
    "reales". En ese caso, puede añadirse a este worker virtual el
    conjunto especial de parámetros. Consulte <module>mod_proxy_balancer</module>
    para más información sobre cómo funciona el balanceador.
    </p>
    <table border="2"><tr><th>Parámetros del balanceador</th></tr></table>
    <table>
    <tr><th>Parámetro</th>
        <th>Por defecto</th>
        <th>Descripción</th></tr>
    <tr><td>lbmethod</td>
        <td>byrequests</td>
        <td>Método de balanceo de carga del balanceador. Selecciona el
        planificador de balanceo de carga a usar. Puede ser
        <code>byrequests</code>, para realizar un recuento ponderado de
        peticiones; <code>bytraffic</code>, para realizar balanceo
        ponderado por bytes de tráfico; o <code>bybusyness</code>, para
        realizar balanceo por peticiones pendientes. El valor por
        defecto es <code>byrequests</code>.
    </td></tr>
    <tr><td>maxattempts</td>
        <td>Uno menos que el número de workers, o 1 con un solo worker.</td>
        <td>Número máximo de intentos de failover antes de desistir.
    </td></tr>
    <tr><td>nofailover</td>
        <td>Off</td>
        <td>Si se establece en <code>On</code>, la sesión se romperá si
        el worker está en estado de error o deshabilitado. Establezca
        este valor en <code>On</code> si los servidores de backend no
        admiten replicación de sesiones.
    </td></tr>
    <tr><td>stickysession</td>
        <td>-</td>
        <td>Nombre de sesión persistente (sticky) del balanceador. El
        valor normalmente se establece a algo como
        <code>JSESSIONID</code> o <code>PHPSESSIONID</code>, y depende
        del servidor de aplicaciones de backend que admita sesiones. Si
        el servidor de aplicaciones de backend usa nombres distintos
        para la cookie y el id codificado en la url (como los
        contenedores de servlets), use | para separarlos. La primera
        parte es para la cookie; la segunda es para la ruta.<br />
        Disponible en el servidor HTTP Apache 2.4.4 y posteriores.
    </td></tr>
    <tr><td>stickysessionsep</td>
        <td>"."</td>
        <td>Establece el símbolo de separación en la cookie de sesión.
        Algunos servidores de aplicaciones de backend no usan '.' como
        símbolo. Por ejemplo, el servidor Oracle Weblogic usa '!'. El
        símbolo correcto puede establecerse usando esta opción. El
        ajuste 'Off' significa que no se usa ningún símbolo.
    </td></tr>
    <tr><td>scolonpathdelim</td>
        <td>Off</td>
        <td>Si se establece en <code>On</code>, el carácter de punto y
        coma ';' se usará como un delimitador/separador de ruta de
        sesión persistente adicional. Esto se usa principalmente para
        emular el comportamiento de mod_jk al tratar rutas como
        <code>JSESSIONID=6736bcf34;foo=aabfa</code>
    </td></tr>
    <tr><td>timeout</td>
        <td>0</td>
        <td>Timeout del balanceador en segundos. Si se establece, será
        el tiempo máximo a esperar por un worker libre. Por defecto no
        se espera.
        Usa la sintaxis de directiva <a href="directive-dict.html#Syntax">time-interval</a>.
    </td></tr>
    <tr><td>failonstatus</td>
        <td>-</td>
        <td>Un código de estado HTTP o una lista separada por comas.
        Si se establece, forzará al worker a pasar a estado de error
        cuando el backend devuelva cualquier código de estado de la
        lista. La recuperación del worker se comporta igual que para
        otros errores de worker.
    </td></tr>
    <tr><td>failontimeout</td>
        <td>Off</td>
        <td>Si se establece, un timeout de lectura de E/S tras enviar
        una petición al backend forzará al worker a pasar a estado de
        error. La recuperación del worker se comporta igual que para
        otros errores de worker.<br />
        Disponible en el servidor HTTP Apache 2.4.5 y posteriores.
    </td></tr>
    <tr><td>nonce</td>
        <td>&lt;auto&gt;</td>
        <td>El nonce protector usado en la página de aplicación
        <code>balancer-manager</code>. Por defecto se usa un nonce
        basado en UUID determinado automáticamente, para proporcionar
        protección adicional a la página. Si se establece, el nonce
        toma ese valor. Un ajuste de <code>None</code> deshabilita toda
        comprobación de nonce.
    <note><title>Nota</title>
      <p>Además del nonce, la página <code>balancer-manager</code>
      debería protegerse mediante una ACL.</p>
    </note>
     </td></tr>
    <tr><td>growth</td>
        <td>0</td>
        <td>Número de BalancerMembers adicionales que se permite
        añadir a este balanceador, además de los definidos en la
        configuración.
    </td></tr>
    <tr><td>forcerecovery</td>
        <td>On</td>
        <td>Fuerza la recuperación inmediata de todos los workers sin
        tener en cuenta el parámetro retry de los workers si todos los
        workers de un balanceador están en estado de error. Puede haber
        casos en los que un backend ya sobrecargado pueda sufrir
        problemas más graves si se fuerza la recuperación de todos los
        workers sin tener en cuenta el parámetro retry de cada worker.
        En ese caso, establezca <code>Off</code>.<br />
        Disponible en el servidor HTTP Apache 2.4.2 y posteriores.
    </td></tr>

    </table>
    <p>Un ejemplo de configuración de un balanceador:</p>
    <highlight language="config">
ProxyPass "/special-area" "http://special.example.com" smax=5 max=10
ProxyPass "/"             "balancer://mycluster/" stickysession=JSESSIONID|jsessionid nofailover=On
&lt;Proxy balancer://mycluster&gt;
    BalancerMember ajp://1.2.3.4:8009
    BalancerMember ajp://1.2.3.5:8009 loadfactor=20
    # Servidor menos potente, no le enviamos tantas peticiones,
    BalancerMember ajp://1.2.3.6:8009 loadfactor=5
&lt;/Proxy&gt;
    </highlight>

    <p>Configurar repuestos calientes puede ayudar a garantizar que
    siempre haya disponible un cierto número de workers por conjunto de
    balanceo de carga:</p>
    <highlight language="config">
ProxyPass "/" "balancer://sparecluster/"
&lt;Proxy balancer://sparecluster&gt;
    BalancerMember ajp://1.2.3.4:8009
    BalancerMember ajp://1.2.3.5:8009
    # Los servidores siguientes son repuestos calientes. Para cada servidor anterior que no sea usable
    # (en drenaje, detenido, inalcanzable, en estado de error, etc.), se usará en su lugar uno
    # de estos repuestos. Siempre habrá dos servidores disponibles para una petición
    # salvo que uno o más de los repuestos tampoco sea usable.
    BalancerMember ajp://1.2.3.6:8009 status=+R
    BalancerMember ajp://1.2.3.7:8009 status=+R
&lt;/Proxy&gt;
    </highlight>

    <p>Configurar una espera caliente (hot-standby) que solo se usará
    si no hay disponibles otros miembros (o repuestos) en el conjunto
    del balanceador de carga:</p>
    <highlight language="config">
ProxyPass "/" "balancer://hotcluster/"
&lt;Proxy balancer://hotcluster&gt;
    BalancerMember ajp://1.2.3.4:8009 loadfactor=1
    BalancerMember ajp://1.2.3.5:8009 loadfactor=2.25
    # El servidor siguiente está en espera caliente
    BalancerMember ajp://1.2.3.6:8009 status=+H
    ProxySet lbmethod=bytraffic
&lt;/Proxy&gt;
    </highlight>

    <p><strong>Palabras clave adicionales de ProxyPass</strong></p>

    <p>Normalmente, mod_proxy canonicalizará las URL pasadas a
    ProxyPass. Pero esto puede ser incompatible con algunos backends,
    particularmente aquellos que hacen uso de <var><glossary ref="pathinfo">PATH_INFO</glossary></var>.
    La palabra clave opcional <var>nocanon</var> suprime esto y pasa la
    ruta de la URL "en crudo" al backend. Tenga en cuenta que esta
    palabra clave puede afectar a la seguridad de su backend, ya que
    elimina la protección limitada habitual frente a ataques basados
    en URL que proporciona el proxy.</p>

    <p>Normalmente, mod_proxy incluirá la cadena de consulta al generar
    la variable de entorno <var>SCRIPT_FILENAME</var>. La palabra clave
    opcional <var>noquery</var> (disponible en httpd 2.4.1 y
    posteriores) evita esto.</p>

    <p>La palabra clave opcional <code>interpolate</code>, en
    combinación con <directive module="mod_proxy">ProxyPassInterpolateEnv</directive>,
    hace que ProxyPass interpole variables de entorno, usando la
    sintaxis <var>${VARNAME}</var>. Tenga en cuenta que muchas de las
    variables de entorno estándar derivadas de CGI no existirán cuando
    ocurra esta interpolación, por lo que puede seguir teniendo que
    recurrir a <module>mod_rewrite</module> para reglas complejas.
    Tenga en cuenta también que la interpolación solo se admite dentro
    de la parte de esquema/nombre de host/puerto de una URL para
    variables que estén disponibles cuando se analiza la directiva
    (como <directive module="core">Define</directive>). La
    determinación dinámica de esos campos puede lograrse con
    <module>mod_rewrite</module>. El siguiente ejemplo describe cómo
    usar <module>mod_rewrite</module> para establecer dinámicamente el
    esquema a http o https:</p>

    <highlight language="config">
RewriteEngine On

RewriteCond %{HTTPS} =off
RewriteRule . - [E=protocol:http]
RewriteCond %{HTTPS} =on
RewriteRule . - [E=protocol:https]

RewriteRule ^/mirror/foo/(.*) %{ENV:protocol}://backend.example.com/$1 [P]
ProxyPassReverse  "/mirror/foo/" "http://backend.example.com/"
ProxyPassReverse  "/mirror/foo/" "https://backend.example.com/"
    </highlight>

    <note><title><a id="protoupgrade" name="protoupgrade">Upgrade de protocolo</a></title>
      <p>Desde el servidor HTTP Apache 2.4.47, el Upgrade de protocolo
      (tunelización) puede manejarse de extremo a extremo mediante
      <module>mod_proxy_http</module> usando el parámetro
      <var><a href="#upgrade">upgrade</a></var> de <directive>ProxyPass</directive>.</p>
      <p>De extremo a extremo significa que la petición HTTP Upgrade
      del cliente/navegador primero la reenvía <module>mod_proxy_http</module>
      al servidor de origen, y la conexión se actualizará (y la
      tunelizará <module>mod_proxy_http</module>) solo si el servidor
      de origen acepta/inicia el upgrade (respuesta HTTP
      <code>101 Switching Protocols</code>). Si el servidor de origen
      responde con cualquier otra cosa, <module>mod_proxy_http</module>
      continuará reenviando (y aplicando) el protocolo HTTP de forma
      normal para esta conexión.</p>
      <p>Consulte <a href="#wsupgrade">Upgrade de Websocket (2.4.47 y posteriores)</a>
      para un ejemplo de configuración usando
      <module>mod_proxy_http</module>.</p>
      <p>Para el servidor HTTP Apache 2.4.46 y anteriores (o si
      <directive module="mod_proxy_wstunnel">ProxyWebsocketFallbackToProxyHttp</directive>
      desde 2.4.48 y posteriores deshabilita el manejo de
      <module>mod_proxy_http</module>), consulte la documentación de
      <module>mod_proxy_wstunnel</module> para saber cómo hacer proxy
      del protocolo WebSocket.</p>
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyPassMatch</name>
<description>Mapea servidores remotos en el espacio de URL del servidor local usando expresiones regulares</description>
<syntax>ProxyPassMatch [<var>regex</var>] !|<var>url</var> [<var>key=value</var>
	<var>[key=value</var> ...]]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context>
</contextlist>
<compatibility>Desde 2.4.47 los parámetros <var>key=value</var> se respetan
cuando el parámetro <var>url</var> contiene referencias inversas (vea la nota siguiente).
</compatibility>

<usage>
    <p>Esta directiva es equivalente a <directive module="mod_proxy">ProxyPass</directive>
       pero usa expresiones regulares en lugar de una simple
       coincidencia de prefijo. La expresión regular indicada se
       compara con <var>url</var>, y si coincide, el servidor
       sustituirá cualquier coincidencia entre paréntesis en la cadena
       dada y la usará como nueva <var>url</var>.</p>

    <note>Esta directiva no puede usarse dentro de un contexto
    <code>&lt;Directory&gt;</code>.</note>

    <note type="warning"><title>Coincidencia de worker con referencias inversas</title>
    <p>Cuando <directive>ProxyPassMatch</directive> contiene
    referencias inversas (por ejemplo, <code>$1</code>) en la URL de
    destino, cada petición produce una URL resuelta distinta. Dado que
    los <a href="#workers">workers</a> se emparejan por URL, estas
    peticiones no coincidirán con el worker creado por esta directiva y
    en su lugar usarán el worker de proxy inverso por defecto, el cual
    no reutiliza conexiones ni cachea búsquedas DNS. Para habilitar la
    agrupación de conexiones, defina un worker explícito por separado
    para el backend:</p>
    <highlight language="config">
ProxyPass        "/notused" "http://backend.example.com/" connectiontimeout=5 timeout=30
ProxyPassMatch   "^/(.*\.gif)$" "http://backend.example.com/$1"
    </highlight>
    <p>La definición explícita del worker <directive>ProxyPass</directive>
    garantiza que el pool de conexiones del backend esté disponible
    para su uso por las peticiones de <directive>ProxyPassMatch</directive>.</p>
    </note>

    <p>Suponga que el servidor local tiene la dirección
    <code>http://example.com/</code>; entonces</p>

    <highlight language="config">
ProxyPassMatch "^/(.*\.gif)$" "http://backend.example.com/$1"
    </highlight>

    <p>hará que una petición local de
    <code>http://example.com/foo/bar.gif</code> se convierta
    internamente en una petición de proxy a
    <code>http://backend.example.com/foo/bar.gif</code>.</p>

    <p>La directiva <code>!</code> es útil en situaciones en las que no
    quiere hacer proxy inverso de un subdirectorio.</p>

    <p>Cuando se usa dentro de una sección <directive type="section" module="core"
    >LocationMatch</directive>, se omite el primer argumento y la
    expresión regular se obtiene de la <directive type="section" module="core"
    >LocationMatch</directive>. Cuando se usa fuera de una sección
    <directive type="section"
    module="core">Location</directive> o <directive type="section"
    module="core">LocationMatch</directive>, el argumento
    <var>regex</var> es obligatorio.</p>

    <p>Si necesita una configuración de proxy inverso más flexible,
    consulte la directiva <directive module="mod_rewrite">RewriteRule</directive>
    con el indicador <code>[P]</code>.</p>

    <note>
      <title>Sustitución por defecto</title>
      <p>Cuando el parámetro URL no usa ninguna referencia inversa a la
      expresión regular, la URL original se añadirá al parámetro URL.
      </p>
    </note>
    <note>
        <title>Parámetros <code>key=value</code> frente a <var>url</var> con referencias inversas</title>
      <p>Desde el servidor HTTP Apache 2.4.47, los parámetros
      <code>key=value</code> ya no se ignoran en un
      <directive>ProxyPassMatch</directive> que use una <var>url</var>
      con referencias inversas. Sin embargo, para mantener el
      comportamiento existente respecto a la reutilización/keepalive de
      las conexiones de backend (que nunca se reutilizaban antes para
      estas URL), el parámetro <var>enablereuse</var> (o
      <var>disablereuse</var>) toma por defecto <code>off</code> (resp.
      <code>on</code>) en este caso. Establecer
      <code>enablereuse=on</code> explícitamente permite reutilizar
      conexiones <strong>salvo</strong> que alguna referencia inversa
      forme parte del componente <code>authority</code> (nombre de host
      y/o puerto) de la <var>url</var> (esta condición se exige desde el
      servidor HTTP Apache 2.4.55, y produce una advertencia en el
      arranque porque estas URL no son reutilizables por sí mismas).</p>
    </note>

    <note type="warning">
      <title>Advertencia de seguridad</title>
      <p>Tenga cuidado al construir la URL de destino de la regla,
        considerando el impacto de seguridad de permitir que el cliente
        influya en el conjunto de URL para las que su servidor actuará
        como proxy. Asegúrese de que la parte de esquema y nombre de
        host de la URL es fija o no permite al cliente una influencia
        indebida.</p>
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyPassReverse</name>
<description>Ajusta la URL en las cabeceras de respuesta HTTP enviadas
desde un servidor en proxy inverso</description>
<syntax>ProxyPassReverse [<var>path</var>] <var>url</var>
[interpolate]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context>
</contextlist>

<usage>
    <p>Esta directiva permite al servidor HTTP Apache ajustar la URL en
    las cabeceras <code>Location</code>, <code>Content-Location</code>
    y <code>URI</code> en las respuestas de redirección HTTP. Esto es
    esencial cuando el servidor HTTP Apache se usa como proxy inverso
    (o gateway) para evitar que se evite el proxy inverso debido a
    redirecciones HTTP en los servidores de backend que quedan detrás
    del proxy inverso.</p>

    <p>Solo se reescribirán las cabeceras de respuesta HTTP mencionadas
    específicamente arriba. El servidor HTTP Apache no reescribirá
    otras cabeceras de respuesta, ni por defecto reescribirá
    referencias de URL dentro de páginas HTML. Esto significa que si el
    contenido proxied contiene referencias de URL absolutas, estas
    evitarán el proxy. Para reescribir contenido HTML y que coincida
    con el proxy, debe cargar y habilitar <module>mod_proxy_html</module>.
    </p>

    <p><var>path</var> es el nombre de una ruta virtual local. Se
    combina con el esquema, host y puerto de la petición para formar el
    prefijo de sustitución de la cabecera de respuesta afectada.
    Este parámetro suele ser el mismo que el primer parámetro de la
    directiva <directive module="mod_proxy">ProxyPass</directive>.
    </p>

    <p><var>url</var> es una URL parcial para el servidor remoto.
    Cuando el servidor remoto envía las cabeceras mencionadas
    específicamente que comienzan con esta URL parcial, el prefijo del
    servidor remoto se reemplaza por un prefijo que apunta al proxy
    inverso.
    Este parámetro suele ser el mismo que el segundo parámetro de la
    directiva <directive module="mod_proxy">ProxyPass</directive>, pero
    puede diferir si el servidor remoto usa un esquema, host, puerto o
    ruta distintos en las cabeceras afectadas. En configuraciones con
    <directive module="mod_proxy">ProxyPreserveHost</directive>, el
    nombre de host en la URL parcial puede ya ser el nombre de host del
    proxy inverso, lo que impedirá la comparación y sustitución
    realizada por esta directiva.
    </p>

    <p>Por ejemplo, suponga que el servidor local tiene la dirección
    <code>http://example.com/</code>; entonces</p>

    <highlight language="config">
ProxyPass         "/mirror/foo/" "http://backend.example.com/"
ProxyPassReverse  "/mirror/foo/" "http://backend.example.com/"
ProxyPassReverseCookieDomain  backend.example.com  public.example.com
ProxyPassReverseCookiePath  "/"  "/mirror/foo/"
    </highlight>

    <p>no solo hará que una petición local a
    <code>http://example.com/mirror/foo/bar</code> se convierta
    internamente en una petición de proxy a
    <code>http://backend.example.com/bar</code>
    (la funcionalidad que <code>ProxyPass</code> proporciona aquí).
    También se encarga de las redirecciones que envía el servidor
    <code>backend.example.com</code> al redirigir
    <code>http://backend.example.com/bar</code> a
    <code>http://backend.example.com/quux</code>. El servidor HTTP
    Apache ajusta esto a
    <code>http://example.com/mirror/foo/quux</code> antes de reenviar
    la respuesta de redirección HTTP al cliente. Tenga en cuenta que el
    nombre de host usado para construir la URL se elige en función del
    ajuste de la directiva <directive
    module="core">UseCanonicalName</directive>.</p>

    <p>Tenga en cuenta que esta directiva
    <directive>ProxyPassReverse</directive> también puede usarse junto
    con la funcionalidad de proxy
    (<code>RewriteRule ...  [P]</code>) de <module>mod_rewrite</module>
    porque no depende de una directiva <directive module="mod_proxy"
    >ProxyPass</directive> correspondiente.</p>

    <p>La palabra clave opcional <code>interpolate</code>, usada junto
    con <directive module="mod_proxy">ProxyPassInterpolateEnv</directive>,
    habilita la interpolación de variables de entorno especificadas
    usando el formato <var>${VARNAME}</var>. Tenga en cuenta que la
    interpolación no se admite dentro de la parte de esquema de una
    URL.</p>

    <p>Cuando se usa dentro de una sección <directive type="section" module="core"
    >Location</directive>, se omite el primer argumento y el
    directorio local se obtiene de la <directive type="section" module="core"
    >Location</directive>. Cuando se usa fuera de una sección <directive type="section"
    module="core">Location</directive> o <directive type="section"
    module="core">LocationMatch</directive>, el argumento
    <var>path</var> es obligatorio. Lo mismo ocurre dentro de una
    sección <directive type="section"
    module="core">LocationMatch</directive>, pero probablemente no
    funcionará como se pretende, ya que ProxyPassReverse interpretará
    la expresión regular literalmente como una ruta; si se necesita en
    esta situación, especifique ProxyPassReverse fuera de la sección o
    en una sección <directive type="section" module="core"
    >Location</directive> separada.</p>

    <p>Esta directiva no está admitida en secciones <directive type="section" module="core"
    >Directory</directive> o <directive type="section" module="core"
    >Files</directive>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyPassReverseCookieDomain</name>
<description>Ajusta la cadena Domain en cabeceras Set-Cookie de un
servidor en proxy inverso</description>
<syntax>ProxyPassReverseCookieDomain <var>internal-domain</var>
<var>public-domain</var> [interpolate]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context>
</contextlist>
<usage>
<p>El uso es básicamente similar a
<directive module="mod_proxy">ProxyPassReverse</directive>, pero en
lugar de reescribir cabeceras que son una URL, reescribe la cadena
<code>domain</code> en las cabeceras <code>Set-Cookie</code>.</p>
</usage>
</directivesynopsis>


<directivesynopsis>
<name>ProxyPassReverseCookiePath</name>
<description>Ajusta la cadena Path en cabeceras Set-Cookie de un
servidor en proxy inverso</description>
<syntax>ProxyPassReverseCookiePath <var>internal-path</var>
<var>public-path</var> [interpolate]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context>
</contextlist>
<usage>
<p>
Útil junto con
<directive module="mod_proxy">ProxyPassReverse</directive>
en situaciones en las que las rutas de URL del backend se mapean a
rutas públicas en el proxy inverso. Esta directiva reescribe la cadena
<code>path</code> en las cabeceras <code>Set-Cookie</code>. Si el
principio de la ruta de la cookie coincide con
<var>internal-path</var>, la ruta de la cookie se reemplazará por
<var>public-path</var>.
</p><p>
En el ejemplo dado con
<directive module="mod_proxy">ProxyPassReverse</directive>, la directiva:
</p>
    <highlight language="config">
ProxyPassReverseCookiePath  "/"  "/mirror/foo/"
    </highlight>
<p>
reescribirá una cookie con ruta de backend <code>/</code> (o
<code>/example</code> o, de hecho, cualquiera) a
<code>/mirror/foo/</code>.
</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyBlock</name>
<description>Impide peticiones de proxy a determinados hosts</description>
<syntax>ProxyBlock *|<var>hostname</var>|<var>partial-hostname</var> [<var>hostname</var>|<var>partial-hostname</var>]...</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>ProxyBlock</directive> puede usarse para
    bloquear el acceso FTP o HTTP a determinados hosts a través del
    proxy, en función de una coincidencia total o parcial de nombre de
    host, o, si procede, de una comparación de dirección IP.</p>

    <p>Cada uno de los argumentos de la directiva
    <directive>ProxyBlock</directive> puede ser <code>*</code> o una
    cadena alfanumérica. En el arranque, el módulo intentará resolver
    cada cadena alfanumérica desde un nombre DNS a un conjunto de
    direcciones IP, pero se ignora cualquier error de DNS.</p>

    <p>Si se especifica un argumento asterisco "<code>*</code>",
    <module>mod_proxy</module> denegará el acceso a todos los sitios
    FTP o HTTP.</p>

    <p>En caso contrario, para cualquier petición de un recurso HTTP o
    FTP a través del proxy, <module>mod_proxy</module> comprobará el
    nombre de host de la URI de la petición contra cada cadena
    indicada. Si se encuentra una coincidencia parcial de cadena, se
    deniega el acceso. Si no se encuentra ninguna coincidencia contra
    los nombres de host, y hay configurado un proxy (directo) remoto
    mediante <directive>ProxyRemote</directive> o
    <directive>ProxyRemoteMatch</directive>, se permite el acceso. Si
    no hay configurado ningún proxy (directo) remoto, la dirección IP
    del nombre de host de la URI se compara contra todas las
    direcciones IP resueltas, determinadas en el arranque. Se deniega
    el acceso si se encuentra alguna coincidencia.</p>

    <p>Tenga en cuenta que las búsquedas DNS pueden ralentizar el
    tiempo de arranque del servidor.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      ProxyBlock news.example.com auctions.example.com friends.example.com
      </highlight>
    </example>

    <p>Tenga en cuenta que <code>example</code> también sería
    suficiente para coincidir con cualquiera de estos sitios.</p>

    <p>Los hosts también coincidirían si se referencian por dirección
    IP.</p>

    <p>Tenga en cuenta también que</p>

    <highlight language="config">
      ProxyBlock *
    </highlight>

    <p>bloquea las conexiones a todos los sitios.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyReceiveBufferSize</name>
<description>Tamaño del búfer de red para conexiones proxied HTTP y
FTP</description>
<syntax>ProxyReceiveBufferSize <var>bytes</var></syntax>
<default>ProxyReceiveBufferSize 0</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>ProxyReceiveBufferSize</directive>
    especifica un tamaño de búfer de red explícito (TCP/IP) para
    conexiones proxied HTTP y FTP, para aumentar el rendimiento. Debe
    ser mayor que <code>512</code> o establecerse en <code>0</code>
    para indicar que debe usarse el tamaño de búfer por defecto del
    sistema.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      ProxyReceiveBufferSize 2048
      </highlight>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyIOBufferSize</name>
<description>Determina el tamaño del búfer interno de rendimiento de datos</description>
<syntax>ProxyIOBufferSize <var>bytes</var></syntax>
<default>ProxyIOBufferSize 8192</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>ProxyIOBufferSize</directive> ajusta el
    tamaño del búfer interno usado como espacio de trabajo para los
    datos entre la entrada y la salida. El tamaño debe ser al menos
    <code>512</code>, o establecerse en <code>0</code> para indicar que
    debe usarse el tamaño de búfer por defecto del sistema.</p>

    <p>En casi todos los casos, no hay razón para cambiar ese valor.</p>

    <p>Si se usa con AJP, esta directiva establece el tamaño máximo de
    paquete AJP en bytes. Los valores mayores de 65536 se establecen en
    65536. Si lo cambia respecto al valor por defecto, ¡también debe
    cambiar el atributo <code>packetSize</code> de su conector AJP en
    el lado de Tomcat! El atributo <code>packetSize</code> solo está
    disponible en Tomcat <code>5.5.20+</code> y
    <code>6.0.2+</code></p>

    <p>Normalmente no es necesario cambiar el tamaño máximo de paquete.
    Se han reportado problemas con el valor por defecto al enviar
    certificados o cadenas de certificados.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyMaxForwards</name>
<description>Número máximo de proxies por los que puede reenviarse una
petición</description>
<syntax>ProxyMaxForwards <var>number</var></syntax>
<default>ProxyMaxForwards -1</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>ProxyMaxForwards</directive> especifica
    el número máximo de proxies por los que puede pasar una petición si
    no se proporciona ninguna cabecera <code>Max-Forwards</code> con la
    petición. Esto puede establecerse para evitar bucles infinitos de
    proxy o un ataque DoS.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      ProxyMaxForwards 15
      </highlight>
    </example>

    <p>Tenga en cuenta que establecer <directive>ProxyMaxForwards</directive>
    es una violación del protocolo HTTP/1.1 (RFC2616), que prohíbe que
    un Proxy establezca <code>Max-Forwards</code> si el cliente no lo
    estableció. Versiones anteriores del servidor HTTP Apache siempre
    lo establecían. Un valor negativo de
    <directive>ProxyMaxForwards</directive>, incluyendo el valor por
    defecto -1, le da un comportamiento conforme al protocolo, pero
    puede dejarle expuesto a bucles.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>NoProxy</name>
<description>Hosts, dominios o redes a los que se conectará
directamente</description>
<syntax>NoProxy <var>host</var> [<var>host</var>] ...</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Esta directiva solo es útil para servidores proxy Apache httpd
    dentro de intranets. La directiva <directive>NoProxy</directive>
    especifica una lista de subredes, direcciones IP, hosts y/o
    dominios, separados por espacios. Una petición a un host que
    coincide con uno o más de estos siempre se sirve directamente, sin
    reenviarla al servidor o servidores proxy configurados en
    <directive module="mod_proxy">ProxyRemote</directive>.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
ProxyRemote  *  http://firewall.example.com:81
NoProxy         .example.com 192.168.112.0/21
    </highlight>
    </example>

    <p>Los argumentos <var>host</var> de la directiva
    <directive>NoProxy</directive> son uno de los siguientes tipos de
    lista:</p>

    <dl>
    <!-- ===================== Domain ======================= -->
    <dt><var><a name="domain" id="domain">Domain</a></var></dt>
    <dd>
    <p>Un <dfn>Domain</dfn> es un nombre de dominio DNS parcialmente
    cualificado, precedido de un punto. Representa una lista de hosts
    que pertenecen lógicamente al mismo dominio o zona DNS (<em>es
    decir</em>, los sufijos de los nombres de host terminan todos en
    <var>Domain</var>).</p>

    <example><title>Ejemplos</title>
      .com .example.org.
    </example>

    <p>Para distinguir los <var>Domain</var> de los <var><a href="#hostname"
    >Hostname</a></var> (tanto sintáctica como semánticamente; ¡un
    dominio DNS también puede tener un registro A de DNS!), los
    <var>Domain</var> siempre se escriben con un punto inicial.</p>

    <note><title>Nota</title>
      <p>Las comparaciones de nombres de dominio se realizan sin
      distinguir mayúsculas y minúsculas, y los <var>Domain</var>
      siempre se asumen anclados en la raíz del árbol DNS; por tanto,
      los dos dominios <code>.ExAmple.com</code> y
      <code>.example.com.</code> (observe el punto final) se consideran
      iguales. Dado que una comparación de dominio no implica una
      búsqueda DNS, es mucho más eficiente que la comparación de
      subred.</p>
    </note></dd>

    <!-- ===================== SubNet ======================= -->
    <dt><var><a name="subnet" id="subnet">SubNet</a></var></dt>
    <dd>
    <p>Una <dfn>SubNet</dfn> es una dirección de internet parcialmente
    cualificada en forma numérica (cuarteto separado por puntos),
    seguida opcionalmente de una barra y la máscara de red,
    especificada como el número de bits significativos en la
    <var>SubNet</var>. Se usa para representar una subred de hosts
    accesibles a través de una interfaz de red común. En ausencia de
    una máscara de red explícita, se asume que los dígitos finales
    omitidos (o de valor cero) especifican la máscara. (En este caso,
    la máscara de red solo puede ser múltiplo de 8 bits de ancho.)
    Ejemplos:</p>

    <dl>
    <dt><code>192.168</code> o <code>192.168.0.0</code></dt>
    <dd>la subred 192.168.0.0 con una máscara de red implícita de 16
    bits válidos (a veces usada en la forma de máscara
    <code>255.255.0.0</code>)</dd>
    <dt><code>192.168.112.0/21</code></dt>
    <dd>la subred <code>192.168.112.0/21</code> con una máscara de red
    de 21 bits válidos (también usada en la forma
    <code>255.255.248.0</code>)</dd>
    </dl>

    <p>Como caso degenerado, una <em>SubNet</em> con 32 bits válidos es
    equivalente a un <var><a href="#ipaddr">IPAddr</a></var>, mientras
    que una <var>SubNet</var> con cero bits válidos (<em>p. ej.</em>,
    0.0.0.0/0) es igual que la constante
    <var>_Default_</var>, que coincide con cualquier dirección IP.</p></dd>

    <!-- ===================== IPAddr ======================= -->
    <dt><var><a name="ipaddr" id="ipaddr">IPAddr</a></var></dt>
    <dd>
    <p>Un <dfn>IPAddr</dfn> representa una dirección de internet
    completamente cualificada en forma numérica (cuarteto separado por
    puntos). Normalmente, esta dirección representa un host, pero no
    es necesario que haya un nombre de dominio DNS asociado con la
    dirección.</p>
    <example><title>Ejemplo</title>
      192.168.123.7
    </example>

    <note><title>Nota</title>
      <p>Un <var>IPAddr</var> no necesita ser resuelto por el sistema
      DNS, por lo que puede dar lugar a un rendimiento de apache más
      efectivo.</p>
    </note></dd>

    <!-- ===================== Hostname ======================= -->
    <dt><var><a name="hostname" id="hostname">Hostname</a></var></dt>
    <dd>
    <p>Un <dfn>Hostname</dfn> es un nombre de dominio DNS completamente
    cualificado que puede resolverse a uno o más <var><a href="#ipaddr">IPAddrs</a></var>
    mediante el servicio de nombres de dominio DNS. Representa un host
    lógico (en contraposición a los <var><a href="#domain">Domain</a></var>,
    ver más arriba) y debe poder resolverse al menos a un
    <var><a href="#ipaddr">IPAddr</a></var> (o a menudo a una lista de
    hosts con distintos <var><a href="#ipaddr">IPAddr</a></var>).</p>

    <example><title>Ejemplos</title>
      prep.ai.example.edu<br />
      www.example.org
    </example>

    <note><title>Nota</title>
      <p>En muchas situaciones, es más eficiente especificar un
      <var><a href="#ipaddr">IPAddr</a></var> en lugar de un
      <var>Hostname</var>, ya que así se evita una búsqueda DNS. La
      resolución de nombres en el servidor HTTP Apache puede llevar
      bastante tiempo cuando la conexión al servidor de nombres usa un
      enlace PPP lento.</p>
      <p>Las comparaciones de <var>Hostname</var> se realizan sin
      distinguir mayúsculas y minúsculas, y los <var>Hostname</var>
      siempre se asumen anclados en la raíz del árbol DNS; por tanto,
      los dos hosts <code>WWW.ExAmple.com</code> y
      <code>www.example.com.</code> (observe el punto final) se
      consideran iguales.</p>
     </note></dd>
    </dl>
</usage>
<seealso><a href="../dns-caveats.html">Problemas de DNS</a></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ProxyTimeout</name>
<description>Timeout de red para peticiones proxied</description>
<syntax>ProxyTimeout <var>time-interval</var>[s]</syntax>
<default>Valor de <directive module="core">Timeout</directive></default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Esta directiva permite a un usuario especificar un timeout para
    las peticiones de proxy. Esto es útil cuando tiene un servidor de
    aplicaciones lento/defectuoso que se cuelga, y prefiere simplemente
    devolver un timeout y fallar de forma controlada en lugar de
    esperar el tiempo que sea necesario hasta que el servidor
    responda.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyDomain</name>
<description>Nombre de dominio por defecto para peticiones proxied</description>
<syntax>ProxyDomain <var>Domain</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Esta directiva solo es útil para servidores proxy Apache httpd
    dentro de intranets. La directiva <directive>ProxyDomain</directive>
    especifica el dominio por defecto al que pertenecerá el servidor
    proxy apache. Si se encuentra una petición a un host sin nombre de
    dominio, se generará una respuesta de redirección al mismo host con
    el <var>Domain</var> configurado añadido. El nombre de dominio debe
    empezar con un punto.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
ProxyRemote  "*"  "http://firewall.example.com:81"
NoProxy           ".example.com" "192.168.112.0/21"
ProxyDomain       ".example.com"
      </highlight>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyVia</name>
<description>Información proporcionada en la cabecera de respuesta
HTTP <code>Via</code> para peticiones proxied</description>
<syntax>ProxyVia On|Off|Full|Block</syntax>
<default>ProxyVia Off</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Esta directiva controla el uso de la cabecera HTTP
    <code>Via:</code> por el proxy. Su uso previsto es controlar el
    flujo de las peticiones de proxy a lo largo de una cadena de
    servidores proxy. Consulte <rfc>2616</rfc> (HTTP/1.1), sección 14.45
    para una explicación de las líneas de cabecera <code>Via:</code>.</p>

    <ul>
    <li>Si se establece en <code>Off</code>, que es el valor por
    defecto, no se realiza ningún procesamiento especial. Si una
    petición o respuesta contiene una cabecera <code>Via:</code>, se
    pasa sin cambios.</li>

    <li>Si se establece en <code>On</code>, cada petición y respuesta
    recibirá una línea de cabecera <code>Via:</code> añadida para el
    host actual.</li>

    <li>Si se establece en <code>Full</code>, cada línea de cabecera
    <code>Via:</code> generada mostrará además la versión del servidor
    HTTP Apache como un campo de comentario <code>Via:</code>.</li>

    <li>Si se establece en <code>Block</code>, a cada petición de proxy
    se le eliminarán todas sus líneas de cabecera <code>Via:</code>. No
    se generará ninguna cabecera <code>Via:</code> nueva.</li>
    </ul>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyErrorOverride</name>
<description>Sobrescribe las páginas de error para contenido proxied</description>
<syntax>ProxyErrorOverride Off|On [<var>code</var> ...]</syntax>
<default>ProxyErrorOverride Off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context>
</contextlist>
<compatibility>La lista de códigos de estado se añadió en 2.5.1</compatibility>

<usage>
    <p>Esta directiva es útil para configuraciones de proxy inverso en
    las que desea tener un aspecto común en las páginas de error vistas
    por el usuario final. Esto también permite que los archivos
    incluidos (mediante SSI de <module>mod_include</module>) obtengan
    el código de error y actúen en consecuencia. (El comportamiento por
    defecto mostraría la página de error del servidor proxied.
    Activando esto se muestra el mensaje de error SSI.)</p>

    <p>Esta directiva no afecta al procesamiento de respuestas
    informativas (1xx), de éxito normal (2xx), o de redirección (3xx).</p>

    <p>Por defecto, <directive>ProxyErrorOverride</directive> afecta a
        todas las respuestas con códigos entre 400 (incluido)
        y 600 (excluido).</p>

    <example><title>Ejemplo de comportamiento por defecto</title>
        <highlight language="config">
            ProxyErrorOverride  On
        </highlight>
    </example>

    <p>Para cambiar el comportamiento por defecto, puede especificar
        los códigos de estado a tener en cuenta, separados por
        espacios. Si lo hace, se ignorarán todos los demás códigos de
        estado. Solo puede especificar códigos de estado que se
        consideren códigos de error: entre 400 (incluido)
        y 600 (excluido).</p>

    <example><title>Ejemplo con códigos de estado personalizados</title>
        <highlight language="config">
            ProxyErrorOverride  On 403 405 500 501 502 503 504
        </highlight>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyPassInterpolateEnv</name>
<description>Habilita la interpolación de variables de entorno en configuraciones de proxy inverso</description>
<syntax>ProxyPassInterpolateEnv On|Off</syntax>
<default>ProxyPassInterpolateEnv Off</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
</contextlist>

<usage>
    <p>Esta directiva, junto con el argumento <code>interpolate</code>
    de <directive>ProxyPass</directive>, <directive>ProxyPassReverse</directive>,
    <directive>ProxyPassReverseCookieDomain</directive> y
    <directive>ProxyPassReverseCookiePath</directive>,
    permite que los proxies inversos se configuren dinámicamente usando
    variables de entorno que puede establecer otro módulo, como
    <module>mod_rewrite</module>.
    Afecta a las directivas <directive>ProxyPass</directive>,
    <directive>ProxyPassReverse</directive>,
    <directive>ProxyPassReverseCookieDomain</directive> y
    <directive>ProxyPassReverseCookiePath</directive>,
    y hace que sustituyan el valor de una variable de entorno
    <code>varname</code> por la cadena <code>${varname}</code>
    en las directivas de configuración si se establece la opción
    <code>interpolate</code>.</p>
    <p>La parte de esquema/nombre de host/puerto de <directive>ProxyPass</directive>
    puede contener variables, pero solo las que estén disponibles
    cuando se analiza la directiva (por ejemplo, usando
    <directive module="core">Define</directive>).
    Para todos los demás casos de uso, considere usar
    <module>mod_rewrite</module> en su lugar.</p>
    <note type="warning"><title>Advertencia de rendimiento</title>
    <p>¡Mantenga esto desactivado a menos que lo necesite!
    Añadir variables a <directive>ProxyPass</directive>, por ejemplo,
    puede llevar al uso de los workers por defecto configurados de
    mod_proxy (que no permiten ningún ajuste fino, como la reutilización
    de conexiones, etc.).</p>
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyStatus</name>
<description>Muestra el estado del LoadBalancer del Proxy en mod_status</description>
<syntax>ProxyStatus Off|On|Full</syntax>
<default>ProxyStatus Off</default>
<contextlist><context>server config</context>
<context>virtual host</context>
</contextlist>

<usage>
    <p>Esta directiva determina si se muestran o no los datos de estado
    del balanceador de carga del proxy a través de la página
    server-status de <module>mod_status</module>.</p>
    <note><title>Nota</title>
      <p><strong>Full</strong> es sinónimo de <strong>On</strong></p>
    </note>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyAddHeaders</name>
<description>Añade información de proxy en cabeceras X-Forwarded-*</description>
<syntax>ProxyAddHeaders Off|On</syntax>
<default>ProxyAddHeaders On</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
</contextlist>
<compatibility>Disponible en la versión 2.3.10 y posteriores</compatibility>

<usage>
    <p>Esta directiva determina si debe pasarse o no al servidor de
    backend información relacionada con el proxy mediante las cabeceras
    HTTP X-Forwarded-For, X-Forwarded-Host y X-Forwarded-Server.</p>
    <note><title>Eficacia</title>
     <p>Esta opción solo es útil para el proxy HTTP, tal y como lo
     maneja <module>mod_proxy_http</module>.</p>
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>Proxy100Continue</name>
<description>Reenvía la expectativa 100-continue al servidor de origen</description>
<syntax>Proxy100Continue Off|On</syntax>
<default>Proxy100Continue On</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
</contextlist>
<compatibility>Disponible en la versión 2.4.40 y posteriores</compatibility>

<usage>
    <p>Esta directiva determina si el proxy debe reenviar la
    <em>expect</em>ación 100-continue al servidor de origen y dejar así
    que este decida cuándo/si debe leerse el cuerpo de la petición
    HTTP, o si, cuando está en <code>Off</code>, el proxy debe generar
    por sí mismo la respuesta intermedia <em>100 Continue</em> antes de
    reenviar el cuerpo de la petición.</p>
    <note><title>Eficacia</title>
     <p>Esta opción solo es útil para el proxy HTTP, tal y como lo
     maneja <module>mod_proxy_http</module>.</p>
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxySourceAddress</name>
<description>Establece la dirección IP local para las conexiones de proxy salientes</description>
<syntax>ProxySourceAddress <var>address</var></syntax>
<contextlist><context>server config</context>
<context>virtual host</context>
</contextlist>
<compatibility>Disponible en la versión 2.3.9 y posteriores</compatibility>

<usage>
    <p>Esta directiva permite establecer una dirección local específica
    a la que enlazar al conectar con un servidor de backend.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyAsyncDelay</name>
<description>Tiempo de sondeo síncrono antes de entregar una conexión
al MPM para procesamiento asíncrono</description>
<syntax>ProxyAsyncDelay <var>time</var>[s]</syntax>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
</contextlist>
<compatibility>Disponible en el servidor HTTP Apache 2.5 y posteriores</compatibility>

<usage>
    <p>Cuando se usa un MPM capaz de sondeo (polling), esta directiva
    habilita el manejo asíncrono de las conexiones de proxy. Tras
    escribir la petición al backend, el hilo worker del proxy sondeará
    una respuesta durante la duración especificada por esta directiva.
    Si el backend responde dentro de ese tiempo, la respuesta se maneja
    de forma síncrona dentro del mismo hilo. Si el backend no ha
    respondido, la conexión se entrega al bucle de eventos asíncrono
    del MPM, liberando el hilo worker para servir otras peticiones.</p>

    <p>Establecer esta directiva en <code>0</code> hace que la conexión
    se entregue al bucle de eventos inmediatamente. Establecerla en
    <code>-1</code> deshabilita por completo el manejo asíncrono (todas
    las conexiones de proxy permanecen síncronas).</p>

    <p>Esta directiva no tiene efecto a menos que el MPM admita sondeo
    (por ejemplo, <module>event</module>).</p>

    <note><title>Cuándo usar esto</title>
    <p>El manejo asíncrono de proxy es más útil para backends lentos o
    respuestas de streaming de larga duración, donde mantener ocupado
    un hilo worker esperando datos limitaría la concurrencia. Para
    backends rápidos que responden en milisegundos, la vía síncrona es
    más eficiente.</p>
    </note>
</usage>

<seealso><directive module="mod_proxy">ProxyAsyncIdleTimeout</directive></seealso>
<seealso><directive module="mod_proxy">ProxyTimeout</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ProxyAsyncIdleTimeout</name>
<description>Timeout de inactividad para conexiones de proxy asíncronas</description>
<syntax>ProxyAsyncIdleTimeout <var>time</var>[s]</syntax>
<default>Valor de <directive module="mod_proxy">ProxyTimeout</directive></default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
</contextlist>
<compatibility>Disponible en el servidor HTTP Apache 2.5 y posteriores</compatibility>

<usage>
    <p>Una vez que una conexión de proxy se ha entregado al bucle de
    eventos asíncrono del MPM (vea
    <directive module="mod_proxy">ProxyAsyncDelay</directive>), esta
    directiva establece el tiempo máximo que la conexión puede
    permanecer inactiva (sin recibir datos del backend) antes de
    cerrarse.</p>

    <p>Si no se establece explícitamente, el valor recurre al parámetro
    <code>timeout</code> del worker (si se establece mediante
    <directive module="mod_proxy">ProxyPass</directive> o
    <directive module="mod_proxy">ProxySet</directive>), luego a
    <directive module="mod_proxy">ProxyTimeout</directive>, y
    finalmente al <directive module="core">Timeout</directive> del
    servidor.</p>

    <p>Esta directiva no tiene efecto a menos que
    <directive module="mod_proxy">ProxyAsyncDelay</directive> también
    esté establecida para habilitar el manejo asíncrono.</p>
</usage>

<seealso><directive module="mod_proxy">ProxyAsyncDelay</directive></seealso>
<seealso><directive module="mod_proxy">ProxyTimeout</directive></seealso>
</directivesynopsis>

</modulesynopsis>
