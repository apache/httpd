<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1673932 -->
<!-- Spanish Translation: Daniel Ferradal -->

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

<manualpage metafile="security_tips.xml.meta">
  <parentdocument href="./">Documentación diversa</parentdocument>

  <title>Consejos de Seguridad</title>

  <summary>
    <p>Le daremos algunas pistas y consejos sobre problemas de seguridad al configurar un servidor web. Algunas de las sugerencias serán genéricas, otras específicas de Apache.</p>
  </summary>

  <section id="uptodate"><title>Mantenerse al Día</title>

    <p>El Servidor Apache HTTP tiene un buen historial de seguridad y comunidad de desarrolladores con una alta preocupación por los problemas de seguridad. Pero será inevitable que algunos problemas -- pequeños o grandes -- sean descubiertos en el software después de que éste ha sido publicado. Por esta razón, es crucial estar al tanto de las actualizaciones de software.  Si ha obtenido su versión del Servidor HTTP directamente de Apache, le recomendamos encarecidamente que se suscriba a la <a href="http://httpd.apache.org/lists.html#http-announce">Lista de Anuncios del Servidor Apache HTTP</a> donde puede estar informado de nuevas versiones y actualizaciones de seguridad. Hay servicios similares disponibles desde la mayoría de distribuidores de terceros del Software Apache.</p>

    <p>Desde luego, la mayor parte de las veces que el servidor web se ve comprometido, no es por problemas en el código del Servidor HTTP. Si no, más bien ocurre por problemas en código externo, scripts CGI, o el sistema operativo sobre el que se opera. Debe entonces estar al tanto de los problemas y actualizaciones de todo el software en su sistema.</p>

  </section>

  <section id="dos">

    <title>Ataques de Denegación de Servicio (DoS, Denial of Service)</title>

    <p>Todos los servicios de red pueden ser objeto de ataques de denegación de servicio que intentan evitar que haya respuestas a clientes mediante la limitación o bloqueo de recursos en el servidor. No es posible prevenir tales ataques completamente, pero puede hacer ciertas cosas para mitigar los problemas que generan.</p>

    <p>A menudo la herramienta más efectiva anti-DoS será un cortafuegos u otras configuraciones del sistema operativo. Por ejemplo, la mayoría de los cortafuegos pueden configurarse para restringir el número de conexiones simultáneas de una misma dirección IP o red, y de esta manera prevenir un rango de ataques sencillos. Pero desde luego esto no es de ayuda contra un Ataque Distribuido de Denegación de Servicio (DDoS).</p>

    <p>Hay ciertas configuraciones del servidor Apache HTTP que pueden ayudar a mitigar problemas:</p>

    <ul>
      <li>La directiva <directive module="mod_reqtimeout">RequestReadTimeout</directive>
      permite limitar el tiempo que un cliente tarda en enviar una petición.</li>

      <li>El valor de la directiva <directive module="core">TimeOut</directive> debería reducirse en sitios que son objeto de ataques DoS. Configurar ésta a unos segundos podría ser apropiado. Como <directive module="core">TimeOut</directive> se usa en realidad para distintas operaciones diferentes, configurar ésta a un valor muy bajo puede introducir problemas a largo plazo en scripts CGI que se ejecuten durante más de la cuenta.</li>

      <li>La directiva <directive module="core">KeepAliveTimeout</directive> también puede reducirse en sitios que son objeto de ataques DoS. Algunos sitios incluso desactivan los keepalives completamente con
      <directive module="core">KeepAlive</directive>, lo cual por supuesto genera otros inconvenientes en el rendimiento.</li>

      <li>Deberían comprobarse también los valores de las directivas de timeout facilitadas por otros módulos.</li>

      <li>Las directivas
      <directive module="core">LimitRequestBody</directive>,
      <directive module="core">LimitRequestFields</directive>,
      <directive module="core">LimitRequestFieldSize</directive>,
      <directive module="core">LimitRequestLine</directive>, y
      <directive module="core">LimitXMLRequestBody</directive>
      deberían configurarse cuidadosamente para limitar el consumo de recursos desencadenado por las entradas del cliente.</li>

      <li>En sistemas operativos que lo soporten, asegúrese de que usa la directiva <directive module="core">AcceptFilter</directive> para descargar parte del procesamiento de la petición al sistema operativo. Está activa por defecto en Apache httpd, pero puede que sea necesaria configuración en su kernel.</li>

      <li>Ajuste la directiva <directive module="mpm_common">MaxRequestWorkers</directive> para permitir al servidor gestionar el máximo número de conexiones simultáneas sin quedarse sin recursos.  También vea la <a
      href="perf-tuning.html">documentación de ajuste de rendimiento</a>.</li>

      <li>Usar un <a href="../mpm.html">mpm</a> multihilo puede permitirle gestionar más conexiones simultáneas, mitigando así ataques DoS. Incluso el mpm <module>event</module> usa procesamiento asíncrono para evitar dedicar un hilo a cada conexión.
      </li>
    </ul>
  </section>


  <section id="serverroot">

    <title>Permisos en Directorios ServerRoot</title>

    <p>Generalmente, Apache se arranca con el usuario root, y éste cambia a un usuario definido con la directiva    <directive module="mod_unixd">User</directive> para servir peticiones. Como es el caso con cualquier comando que ejecuta root, debe tener cuidado de que esté protegido de modificación por usuarios que no sean root. No solo los ficheros deben poder escribirse solo por root, pasa lo mismo con los directorios, y todos los directorios precedentes. Por ejemplo, si escoge colocar ServerRoot en <code>/usr/local/apache</code> entonces se sugiere que genere ese directorio como root, con comandos como estos:</p>

    <example>
      mkdir /usr/local/apache <br />
      cd /usr/local/apache <br />
      mkdir bin conf logs <br />
      chown 0 . bin conf logs <br />
      chgrp 0 . bin conf logs <br />
      chmod 755 . bin conf logs
    </example>

    <p>Se asume que <code>/</code>, <code>/usr</code>, y
    <code>/usr/local</code> son solo modificables por root. Cuando instala el ejecutable <program>httpd</program>, debe asegurarse de que está protegido de manera similar:</p>

    <example>
      cp httpd /usr/local/apache/bin <br />
      chown 0 /usr/local/apache/bin/httpd <br />
      chgrp 0 /usr/local/apache/bin/httpd <br />
      chmod 511 /usr/local/apache/bin/httpd
    </example>

    <p>Puede generar un subdirectorio htdocs que sea modificable por otros usuarios -- puesto que root nunca ejecuta ficheros en ese directorio y no debería estar generando ficheros ahí.</p>

    <p>Si permite a usuarios no-root modificar cualquier fichero que root ejecute o escriba, entonces está permitiendo que root sea comprometido. Por ejemplo, alquien podría reemplazar el binario <program>httpd</program> de manera que la próxima vez que lo arrancara, ejecutaría un código arbitrario. Si el directorio de logs es modificable (por un usuario no-root), alguien podría reemplazar un fichero de log con un enlace simbólico a otro fichero de sistema, y entonces root podría sobreescribir ese fichero con datos arbitrarios. Si los ficheros de log son modificables (por un usuario no-root), entonces alguien podría sobreescribir el fichero de log con datos inservibles.</p>

  </section>

  <section id="ssi">

    <title>Server Side Includes (Inclusiones en la parte Servidor)</title>

    <p>Los Server Side Includes (SSI) enfrentan a un administrador de servidores con varios riesgos de seguridad potenciales.</p>

    <p>El primer riesgo es el incremento de carga en el servidor. Todos los ficheros activados para SSI son escrutados por Apache, tengan o no tengan directivas SSI incluidas dentro del fichero. Aunque esta carga es menor, en un entorno de servidor compartido puede ser significativa.</p>

    <p>Los ficheros SSI también conllevan los mismos riesgos asociados con los scripts CGI en general. Usando el elemento <code>exec cmd</code>, los ficheros activados para SSI pueden ejecutar cualquier script CGI o programa bajo los permisos del usuario y grupo con los que se ejecuta Apache, tal y como está configurado en
    <code>httpd.conf</code>.</p>

    <p>Hay formas de mejorar la seguridad de los ficheros SSI mientras se obtienen los beneficios que proveen.</p>

    <p>Para aislar el daño que un fichero SSI caprichoso puede causar, un administrador de servidor puede habilitar <a href="../suexec.html">suexec</a> como se describe en la sección <a href="#cgi">CGI en General</a>.</p>

    <p>Activar SSI para ficheros con extensiones <code>.html</code> o <code>.htm</code> puede ser peligroso. Esto puede darse especialmente en un entorno de servidor compartido y que tenga bastante carga. Los ficheros habilitados para SSI deberían tener una extensión diferente, como la típica <code>.shtml</code>. Esto ayuda a mantener la carga de servidor al mínimo y permite una gestión más sencilla del riesgo.</p>

    <p>Otra solución es deshabilitar la capacidad de ejecutar scripts y programas desde páginas SSI. Para hacer esto sustituya <code>Includes</code> con <code>IncludesNOEXEC</code> en la directiva <directive
    module="core">Options</directive>. Tenga en cuenta que los usuarios podrían todavía usar <code>&lt;--#include virtual="..." --&gt;</code> para ejecutar scripts CGI si estos scripts están en directorios designados por la directiva <directive module="mod_alias">ScriptAlias</directive>.</p>

  </section>

  <section id="cgi">

    <title>CGI en General</title>

    <p>Primero, siempre tiene que recordar que debe confiar en los desarrolladores de scripts/programas CGI o su habilidad para localizar agujeros potenciales de seguridad en CGI, sean deliberados o accidentales. Los scripts CGI pueden ejecutar comandos de manera arbitraria en su sistema con los permisos del usuario del servidor web y pueden por tanto ser extremadamente peligrosos si no se revisan cuidadosamente.</p>

    <p>Todos los scripts CGI se ejecutarán con el mismo usuario, así que tienen potencial para el conflicto (accidental o deliberado) con otros scripts p. ej. Usuario A odia a Usuario B, así que escribe un script para borrar la base de datos CGI del usuario B. Un programa que puede usarse para permitir que scripts se ejecuten como distintos usuarios es <a href="../suexec.html">suEXEC</a> que está incluido con Apache desde la versión 1.2 y es llamado desde hooks especiales en el código del servidor Apache. Otra forma popular de hacer esto es con <a href="http://cgiwrap.sourceforge.net/">CGIWrap</a>.</p>

  </section>

  <section id="nsaliasedcgi">

    <title>CGI sin Alias de Script</title>

    <p>Permitir a usuarios ejecutar scripts CGI en cualquier directorio solo debería considerarse si:</p>

    <ul>
      <li>Confía en que los usuarios no escribirán scripts que deliberada o accidentalmente expondrán su sistema a un ataque.</li>
      <li>Considera que la seguridad de su sitio es tan débil en otras áreas, que tener un agujero potencial de seguridad sea irrelevante.</li>
      <li>No tiene usuarios, y nadie visita su servidor nunca.</li>
    </ul>

  </section>

  <section id="saliasedcgi">

    <title>CGI con Alias de Script</title>

    <p>Limitar CGI a directorios especiales le da al administrador control sobre lo que ocurre en esos directorios. Esto es indudablemente más seguro que CGI sin Alias de Script, pero solo si los usuarios con acceso de escritura a esos directorios son de fiar o el administrador comprueba cada programa/script por si tiene agujeros de seguridad potenciales.</p>

    <p>La mayor parte de los sitios eligen esta opción en lugar del método CGI sin Alias de Script.</p>

  </section>

   <section id="dynamic">

  <title>Otras fuentes de contenido dinámico</title>

  <p>Opciones de script embebido que se ejecutan como parte del mismo servidor, tales como <code>mod_php</code>, <code>mod_perl</code>, <code>mod_tcl</code>,
  y <code>mod_python</code>, se ejecutan con la misma identidad que el servidor (vea la directiva <directive module="mod_unixd">User</directive>), y por tanto scripts que se ejecuten por estos motores pueden potencialmente acceder a cualquier cosa que el servidor pueda. Algunos motores de scripting pueden proveer restricciones, pero es mejor asumir que no lo hacen.</p>

  </section>
   <section id="dynamicsec">

  <title>Seguridad de Contenido Dinámico</title>

  <p>Cuando se configura contenido dinámico, como por ejemplo <code>mod_php</code>, <code>mod_perl</code> o <code>mod_python</code>, muchas consideraciones de seguridad escapan al ámbito del mismo <code>httpd</code>, y necesita consultar la documnetación de estos módulos. Por ejemplo, PHP le permite configurar un <a
  href="http://www.php.net/manual/en/ini.sect.safe-mode.php">Modo Seguro</a>, que generalmente está deshabilitado por defecto. Otro ejemplo es <a
  href="http://www.hardened-php.net/suhosin/">Suhosin</a>, un addon PHP para más seguridad. Para más información sobre estos, consulte la documnetación de cada projecto.</p>

  <p>A nivel de Apache, un módulo que se llama <a href="http://modsecurity.org/">mod_security</a> puede ser considerado como un firewall HTTP y, asumiento que lo configura correctamente, puede ayudarle a mejorar la seguridad de su contenido dinámico.</p>

  </section>

  <section id="systemsettings">

    <title>Configuración de Protección del Sistema</title>

    <p>Para tener un sistema muy seguro, querrá impedir que los usuarios configuren ficheros <code>.htaccess</code> que pueden invalidar características de seguridad que usted haya configurado. Esta es una manera de hacerlo.</p>

    <p>En el fichero de configuración del servidor, ponga</p>

    <highlight language="config">
&lt;Directory "/"&gt;
    AllowOverride None
&lt;/Directory&gt;
    </highlight>

    <p>Esto previene el uso de ficheros <code>.htaccess</code> en todos los directorios aparte de aquellos habilitados específicamente.</p>

    <p>Tenga en cuenta que este es el valor por defecto desde Apache HTTPD 2.3.9.</p>

  </section>

  <section id="protectserverfiles">

    <title>Proteger Ficheros del Servidor por Defecto</title>

    <p>Un aspecto de Apache que ocasionalmente se malinterpreta es el acceso por defecto. Esto es, a menos que tome medidas para cambiarlo, el servidor puede encontrar su camino hacia un fichero a través reglas de mapeo de URL, que puede servir a los clientes.</p>

    <p>Considere el siguiente ejemplo:</p>

    <example>
      # cd /; ln -s / public_html <br />
      Accessing <code>http://localhost/~root/</code>
    </example>

    <p>Esto permitiría clientes navegar por el sistema de ficheros al completo. Para corregir esto, añada el siguiente bloque a la configuración del servidor:</p>

    <highlight language="config">
&lt;Directory "/"&gt;
    Require all denied
&lt;/Directory&gt;
    </highlight>

    <p>Esto prohibirá el acceso por defecto a ubicaciones del sistema de ficheros. Añada después bloques apropiados de <directive module="core">Directory</directive> para aquellas áreas a las que quiera dar acceso. Por ejemplo,</p>

    <highlight language="config">
&lt;Directory "/usr/users/*/public_html"&gt;
    Require all granted
&lt;/Directory&gt;
&lt;Directory "/usr/local/httpd"&gt;
    Require all granted
&lt;/Directory&gt;
    </highlight>

    <p>Preste atención a las interacciones de las directivas <directive module="core">Location</directive> y <directive module="core">Directory</directive>; por ejemplo, incluso si <code>&lt;Directory "/"&gt;</code> deniega el acceso, una directiva <code>&lt;Location "/"&gt;</code> puede anularlo. (Aunque tenga en cuenta que Location representa paths virtuales relativos a partir del especificado en DocumentRoot)</p>

    <p>También tenga cuidado jugando con la directiva <directive module="mod_userdir">UserDir</directive>; configurarla a algo como <code>./</code> tendría el mismo efecto, para root, como el primer ejemplo indicado previamente. Le recomendamos encarecidamente que incluya la siguiente línea en sus ficheros de configuración del servidor:</p>

    <highlight language="config">
UserDir disabled root
    </highlight>

  </section>

  <section id="watchyourlogs">

    <title>Examinando sus Logs</title>

    <p>Para estar al día en lo que está a su servidor debe examinar los <a href="../logs.html">Ficheros de Log</a>. Incluso aunque los ficheros de log solo reporten lo que ya ha pasado, le facilitarán entender qué ataques se han enviado a su servidor y comprobar si tiene configurado el nivel necesario de seguridad.</p>

    <p>Un par de ejemplos:</p>

    <example>
      grep -c "/jsp/source.jsp?/jsp/ /jsp/source.jsp??" access_log <br />
      grep "client denied" error_log | tail -n 10
    </example>

    <p>El primer ejemplo le enseñará una lista de ataques intentando explotar la
    <a href="http://online.securityfocus.com/bid/4876/info/">Vulnerabilidad de Revelado de Información de Apache Tomcat con Peticiones Malformadas Source.JSP</a>, el segundo ejemplo listará los últimos 10 clientes a los que se les ha denegado el acceso, por ejemplo:</p>

    <example>
      [Thu Jul 11 17:18:39 2002] [error] [client foo.example.com] client denied
      by server configuration: /usr/local/apache/htdocs/.htpasswd
    </example>

    <p>Como puede ver, los ficheros de log solo muestran lo que ya ha pasado, así que si el cliente ha podido acceder al fichero <code>.htpasswd</code> vería algo similar a:</p>

    <example>
      foo.example.com - - [12/Jul/2002:01:59:13 +0200] "GET /.htpasswd HTTP/1.1 200"
    </example>

    <p>en su <a href="../logs.html#accesslog">Log de Acceso</a>. Esto significa que usted probablemente deshabilitó lo siguiente en su fichero de configuración:</p>

    <highlight language="config">
&lt;Files ".ht*"&gt;
    Require all denied
&lt;/Files&gt;
    </highlight>

  </section>

  <section id="merging">

    <title>Fusión de secciones de configuración</title>

    <p>La fusión de secciones de configuración es complicada y a veces específica de ciertas directivas. Compruebe siempre sus cambios cuando genere dependencias en directivas que se fusionan.</p>

    <p>Para módulos que no implementan la lógica de fusión, tales como <directive>mod_access_compat</directive>, el comportamiento en las secciones posteriores dependen de si estas tienen alguna directiva del módulo. La configuración se hereda hasta que se realiza algún cambio, y en ese punto la configuración se <em>reemplaza</em> no se fusiona.</p>
  </section>

</manualpage>
