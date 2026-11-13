<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933507 -->
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

<modulesynopsis metafile="mod_proxy_fcgi.xml.meta">

<name>mod_proxy_fcgi</name>
<description>Módulo de soporte de FastCGI para
<module>mod_proxy</module></description>
<status>Extension</status>
<sourcefile>mod_proxy_fcgi.c</sourcefile>
<identifier>proxy_fcgi_module</identifier>
<compatibility>Disponible en la versión 2.3 y posteriores</compatibility>

<summary>
    <p>Este módulo <em>requiere</em> los servicios de <module
    >mod_proxy</module>. Proporciona soporte para el protocolo
    <a href="https://fastcgi-archives.github.io/">FastCGI</a>.</p>

    <p>Por tanto, para poder gestionar el protocolo <code>FastCGI</code>,
    <module>mod_proxy</module> y <module>mod_proxy_fcgi</module> deben estar
    presentes en el servidor.</p>

    <p>A diferencia de <a href="http://httpd.apache.org/mod_fcgid/">mod_fcgid</a>,
    <module>mod_proxy_fcgi</module> no dispone de ningún mecanismo para
    arrancar el proceso de la aplicación; <program>fcgistarter</program> se
    proporciona (en algunas plataformas) para ese propósito. Alternativamente,
    el lanzamiento externo o la gestión de procesos puede estar disponible en
    el framework de la aplicación FastCGI que se esté usando.</p>

    <note type="warning"><title>Advertencia</title>
      <p>No active el proxy hasta que haya <a
      href="mod_proxy.html#access">asegurado su servidor</a>. Los servidores
      proxy abiertos son peligrosos tanto para su red como para Internet en
      general.</p>
    </note>
</summary>

<seealso><program>fcgistarter</program></seealso>
<seealso><module>mod_proxy</module></seealso>
<seealso><module>mod_authnz_fcgi</module></seealso>

<section id="examples"><title>Ejemplos</title>
    <p>Recuerde que, para que los siguientes ejemplos funcionen, debe activar
    <module>mod_proxy</module> y <module>mod_proxy_fcgi</module>.</p>

    <example><title>Instancia única de la aplicación</title>
    <highlight language="config">
ProxyPass "/myapp/" "fcgi://localhost:4000/"
    </highlight>
    </example>

    <p> <module>mod_proxy_fcgi</module> desactiva la reutilización de
    conexiones por defecto, de forma que, una vez completada una petición, la
    conexión NO se mantendrá abierta por ese proceso hijo de httpd y no se
    reutilizará. Si la aplicación FastCGI es capaz de gestionar conexiones
    concurrentes desde httpd, puede optar por activar la reutilización de
    conexiones como se muestra en el siguiente ejemplo:</p>

    <example><title>Instancia única de la aplicación, con reutilización de conexiones (2.4.11 y posteriores)</title>
    <highlight language="config">
ProxyPass "/myapp/" "fcgi://localhost:4000/" enablereuse=on
    </highlight>
    </example>

    <note><title>Active la reutilización de conexiones hacia un backend FCGI como PHP-FPM</title>
    <p>Tenga en cuenta que PHP-FPM (en el momento de escribir esto, febrero de
    2018) usa un modelo prefork, de forma que cada uno de sus procesos
    trabajadores puede gestionar una conexión a la vez.<br />
    Por defecto, mod_proxy (configurado con <code>enablereuse=on</code>)
    permite un pool de conexiones de
    <directive module="mpm_common">ThreadsPerChild</directive> conexiones
    hacia el backend por cada proceso httpd cuando se usa un mpm basado en
    hilos (como <module>worker</module> o <module>event</module>), por lo que
    deben tenerse en cuenta los siguientes casos de uso:</p>
    <ul>
      <li>Bajo carga HTTP/1.1, es probable que provoque la creación de hasta
      <directive module="mpm_common">MaxRequestWorkers</directive>
      conexiones hacia el backend FCGI.</li>
      <li>Bajo carga HTTP/2, debido a cómo está implementado
      <module>mod_http2</module>, existen hilos trabajadores h2 adicionales
      que pueden forzar la creación de otras conexiones hacia el backend. El
      número total de conexiones en los pools puede superar
      <directive module="mpm_common">MaxRequestWorkers</directive>.</li>
    </ul>
    <p>El número máximo de procesos trabajadores de PHP-FPM debe configurarse
    con criterio, ya que existe la posibilidad de que todos acaben "ocupados"
    gestionando conexiones persistentes inactivas, sin margen para establecer
    otras nuevas, de forma que la experiencia del usuario final consistirá en
    una acumulación de timeouts de petición HTTP.</p>
    </note>

    <p> El siguiente ejemplo pasa el URI de la petición como una ruta del
    sistema de archivos para que la ejecute el demonio PHP-FPM. La URL de la
    petición se añade implícitamente al segundo parámetro. El nombre de host
    y el puerto que siguen a fcgi:// son donde está escuchando PHP-FPM. El
    pooling/reutilización de conexiones está activado.</p>
    <example><title>PHP-FPM</title>
    <highlight language="config">
ProxyPassMatch "^/myapp/.*\.php(/.*)?$" "fcgi://localhost:9000/var/www/" enablereuse=on
    </highlight>
    </example>

    <p> El siguiente ejemplo pasa el URI de la petición como una ruta del
    sistema de archivos para que la ejecute el demonio PHP-FPM. En este caso,
    PHP-FPM está escuchando en un socket de dominio unix (UDS). Requiere la
    versión 2.4.9 o posterior. Con esta sintaxis, el nombre de host y el
    puerto opcional que siguen a fcgi:// se ignoran.</p>
    <example><title>PHP-FPM con UDS</title>
    <highlight language="config">
ProxyPassMatch "^/(.*\.php(/.*)?)$" "unix:/var/run/php5-fpm.sock|fcgi://localhost/var/www/"
    </highlight>
    </example>

    <p>La pasarela balanceada necesita <module>mod_proxy_balancer</module> y
    al menos un módulo de algoritmo de balanceo de carga, como
    <module>mod_lbmethod_byrequests</module>, además de los módulos de proxy
    indicados anteriormente. <module>mod_lbmethod_byrequests</module> es el
    valor por defecto, y se usará para este ejemplo de configuración.</p>

    <example><title>Pasarela balanceada a varias instancias de la aplicación</title>
    <highlight language="config">
ProxyPass "/myapp/" "balancer://myappcluster/"
&lt;Proxy "balancer://myappcluster/"&gt;
    BalancerMember "fcgi://localhost:4000"
    BalancerMember "fcgi://localhost:4001"
&lt;/Proxy&gt;
    </highlight>
    </example>

      <p>También puede forzar que una petición se gestione como una petición
        de proxy inverso, creando un Handler de paso adecuado. El siguiente
        ejemplo de configuración pasará todas las peticiones de scripts PHP al
        servidor FastCGI indicado mediante proxy inverso.
        Esta funcionalidad está disponible en Apache HTTP Server 2.4.10 y
        posteriores. Por motivos de rendimiento, querrá definir un
        <a href="mod_proxy.html#workers">worker</a> que represente el mismo
        backend fcgi://. La ventaja de esta forma es que permite que el
        mapeo normal de URI a nombre de archivo se produzca en el servidor, y
        el resultado del sistema de archivos local se pasa al backend. Cuando
        FastCGI se configura de esta forma, el servidor puede calcular con
        mayor precisión el PATH_INFO.
      </p>
    <example><title>Proxy mediante Handler</title>
      <highlight language="config">
&lt;FilesMatch "\.php$"&gt;
    # Nota: la única parte que varía es /path/to/app.sock
    SetHandler  "proxy:unix:/path/to/app.sock|fcgi://localhost/"
&lt;/FilesMatch&gt;

# Define un worker que coincida.
# La parte que coincide con SetHandler es la que sigue a la
# barra vertical. Si necesita distinguirlos, "localhost" puede
# ser cualquier valor único.
&lt;Proxy "fcgi://localhost/" enablereuse=on max=10&gt;
&lt;/Proxy&gt;

&lt;FilesMatch ...&gt;
    SetHandler  "proxy:fcgi://localhost:9000"
&lt;/FilesMatch&gt;

&lt;FilesMatch ...&gt;
    SetHandler  "proxy:balancer://myappcluster/"
&lt;/FilesMatch&gt;
      </highlight>
   </example>
</section>

<section id="env"><title>Variables de entorno</title>
    <p>Además de las directivas de configuración que controlan el
    comportamiento de <module>mod_proxy</module>, existen varias
    <dfn>variables de entorno</dfn> que controlan el proveedor del protocolo
    FCGI:</p>
    <dl>
        <dt>proxy-fcgi-pathinfo</dt>
        <dd>Cuando se configura mediante <directive module="mod_proxy"
        >ProxyPass</directive> o <directive module="mod_proxy"
        >ProxyPassMatch</directive>, <module>mod_proxy_fcgi</module> no
        establecerá la variable de entorno <var>PATH_INFO</var>. Esto permite
        que el servidor FCGI del backend determine correctamente
        <var>SCRIPT_NAME</var> y <var>Script-URI</var>, y cumpla con la
        sección 3.3 de la RFC 3875.
        Si en cambio necesita que <module>mod_proxy_fcgi</module> genere una
        "estimación aproximada" de <var>PATH_INFO</var>, establezca esta
        variable de entorno. Esto es una solución alternativa a un fallo en
        algunas implementaciones de FCGI. Esta variable puede establecerse con
        varios valores para ajustar cómo se calcula la estimación aproximada
        (solo en 2.4.11 y posteriores):
        <dl>
          <dt>first-dot</dt>
          <dd>PATH_INFO se separa a partir de la barra que sigue al
              <em>primer</em> "." de la URL.</dd>
          <dt>last-dot</dt>
          <dd>PATH_INFO se separa a partir de la barra que sigue al
              <em>último</em> "." de la URL.</dd>
          <dt>full</dt>
          <dd>PATH_INFO se calcula intentando mapear la URL al sistema de
              archivos local.</dd>
          <dt>unescape</dt>
          <dd>PATH_INFO es el componente de ruta de la URL, sin escapar /
              decodificado.</dd>
          <dt>cualquier otro valor</dt>
          <dd>PATH_INFO es igual al componente de ruta de la URL.
              Originalmente, esta era la única opción de proxy-fcgi-pathinfo.</dd>
         </dl>
        </dd>
    </dl>
</section>

<directivesynopsis>
<name>ProxyFCGIBackendType</name>
<description>Especifica el tipo de aplicación FastCGI del backend</description>
<syntax>ProxyFCGIBackendType FPM|GENERIC</syntax>
<default>ProxyFCGIBackendType FPM</default>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<compatibility>Disponible en la versión 2.4.26 y posteriores</compatibility>

<usage>
<p>Esta directiva permite especificar el tipo de aplicación FastCGI del
backend. Algunos servidores FastCGI, como PHP-FPM, usan peculiaridades
históricas de las variables de entorno para identificar el tipo de servidor
proxy que se está usando. Establezca esta directiva a "GENERIC" si su
aplicación que no es PHP-FPM tiene problemas interpretando variables de
entorno como SCRIPT_FILENAME o PATH_TRANSLATED tal como las establece el
servidor.</p>

<p>Un ejemplo de valores que cambian según el ajuste de esta directiva es
SCRIPT_FILENAME. Al usar <module>mod_proxy_fcgi</module>, históricamente
SCRIPT_FILENAME tenía el prefijo "proxy:fcgi://". Esta variable es lo que
algunas aplicaciones FastCGI genéricas leerían como su entrada de script,
pero PHP-FPM eliminaba el prefijo y recordaba que estaba hablando con
Apache. En las versiones 2.4.21 a 2.4.25, este prefijo se eliminaba
automáticamente en el servidor, rompiendo la capacidad de PHP-FPM para
detectar e interoperar con Apache en algunos escenarios.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyFCGISetEnvIf</name>
<description>Permite corregir las variables enviadas a los servidores FastCGI</description>
<syntax>ProxyFCGISetEnvIf <var>conditional-expression</var>
    [!]<var>environment-variable-name</var>
    [<var>value-expression</var>]</syntax>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<compatibility>Disponible en la versión 2.4.26 y posteriores</compatibility>

<usage>
<p>Justo antes de pasar una petición al servidor FastCGI configurado, el
núcleo del servidor web establece varias variables de entorno basadas en los
detalles de la petición actual. Los programas FastCGI a menudo usan estas
variables de entorno como entradas para determinar qué scripts subyacentes
van a procesar, o qué salida producen directamente.</p>
<p>Ejemplos de variables de entorno destacables son:</p>
<ul>
  <li>SCRIPT_NAME</li>
  <li>SCRIPT_FILENAME</li>
  <li>REQUEST_URI</li>
  <li>PATH_INFO</li>
  <li>PATH_TRANSLATED</li>
</ul>

<p>Esta directiva permite sobrescribir las variables de entorno anteriores, o
cualquier otra de interés. Esta directiva se evalúa después de establecerse
los valores iniciales de esas variables, de modo que pueden usarse como
entrada tanto en las expresiones de condición como en las expresiones de
valor.</p>
<p>Sintaxis de los parámetros:</p>
<dl>
<dt>conditional-expression</dt>
<dd>Especifica una expresión que controla si se modificará la variable de
   entorno que sigue. Para obtener información sobre la sintaxis de la
   expresión, consulte los ejemplos siguientes o la especificación completa
   en la documentación de <a href="../expr.html">ap_expr</a>.
   </dd>
<dt>environment-variable-name</dt>
<dd> Especifica la variable de entorno CGI que se va a cambiar,
   como PATH_INFO. Si va precedida de un signo de exclamación, la variable
   se eliminará.</dd>
<dt>value-expression</dt>
<dd>Especifica el valor de sustitución para la variable de entorno
   precedente. Pueden incluirse referencias inversas, como "$1", a partir de
   capturas de expresiones regulares en <var>conditional-expression</var>.
   Si se omite, la variable se establece (o se sobrescribe) con una cadena
   vacía &mdash; pero consulte la nota siguiente.</dd>
</dl>

<example>
   <highlight language="config">
# Una sobrescritura básica e incondicional
ProxyFCGISetEnvIf "true" PATH_INFO "/example"

# Usar una variable de entorno en el valor
ProxyFCGISetEnvIf "true" PATH_INFO "%{reqenv:SCRIPT_NAME}"

# Usar capturas en las condiciones y referencias inversas en la sustitución
ProxyFCGISetEnvIf "reqenv('PATH_TRANSLATED') =~ m|(/.*prefix)(\d+)(.*)|" PATH_TRANSLATED "$1$3"
   </highlight>
</example>

<note><title>Nota: eliminar frente a vaciar</title>
  Lo siguiente eliminará <code>VARIABLE</code>, evitando que se envíe
  al servidor FastCGI:

    <highlight language="config">ProxyFCGISetEnvIf true !VARIABLE</highlight>

  Mientras que lo siguiente borrará cualquier <em>valor</em> existente de
  <code>VARIABLE</code> (estableciéndola a una cadena vacía), pero la
  <code>VARIABLE</code> vacía seguirá enviándose al servidor:

    <highlight language="config">ProxyFCGISetEnvIf true VARIABLE</highlight>

  La especificación CGI/1.1 no distingue (<rfc section="4.1">3875</rfc>) entre
  una variable con un valor vacío y una variable que no existe. Sin embargo,
  muchas implementaciones de CGI y FastCGI distinguen (o permiten que los
  scripts distingan) entre ambos casos. La elección de cuál usar depende de su
  implementación y del motivo por el que modifica la variable.
</note>

</usage>
</directivesynopsis>

</modulesynopsis>
