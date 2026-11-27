<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1934652 -->
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

<modulesynopsis metafile="mod_log_config.xml.meta">

<name>mod_log_config</name>
<description>Registro de las peticiones realizadas al servidor</description>
<status>Base</status>
<sourcefile>mod_log_config.c</sourcefile>
<identifier>log_config_module</identifier>

<summary>
    <p>Este módulo proporciona un registro flexible de las peticiones del
    cliente. Los logs se escriben en un formato personalizable y pueden
    escribirse directamente en un archivo, o a un programa externo.
    Se proporciona un registro condicional de modo que las peticiones
    individuales puedan incluirse o excluirse de los logs en función de
    las características de la petición.</p>

    <p>Este módulo proporciona tres directivas:
    <directive module="mod_log_config">TransferLog</directive> para crear
    un archivo de log, <directive module="mod_log_config">LogFormat</directive>
    para establecer un formato personalizado, y <directive module="mod_log_config"
    >CustomLog</directive> para definir un archivo de log y su formato en un
    único paso. Las directivas <directive>TransferLog</directive> y <directive
    >CustomLog</directive> pueden usarse varias veces en cada servidor para
    que cada petición se registre en varios archivos.</p>
</summary>
<seealso><a href="../logs.html">Archivos de log de Apache</a></seealso>

<section id="formats"><title>Formatos de log personalizados</title>

    <p>El argumento de formato de las directivas <directive module="mod_log_config"
    >LogFormat</directive> y <directive module="mod_log_config"
    >CustomLog</directive> es una cadena. Esta cadena se usa para registrar
    cada petición en el archivo de log. Puede contener caracteres literales
    que se copian en los archivos de log y los caracteres de control de
    estilo C "\n" y "\t" para representar saltos de línea y tabulaciones.
    Las comillas literales y las barras invertidas deben escaparse con
    barras invertidas.</p>

    <p>Las características de la propia petición se registran colocando
    directivas "<code>%</code>" en la cadena de formato, que se sustituyen
    en el archivo de log por los valores siguientes:</p>

    <table border="1" style="zebra">
    <columnspec><column width=".2"/><column width=".8"/></columnspec>
    <tr><th>Cadena&nbsp;de&nbsp;formato</th>
        <th>Descripción</th></tr>

    <tr><td><code>%%</code></td>
        <td>El signo de porcentaje.</td></tr>

    <tr><td><code>%a</code></td>
        <td>Dirección IP del cliente de la petición (ver el
        módulo <module>mod_remoteip</module>).</td></tr>

    <tr><td><code>%{c}a</code></td>
        <td>Dirección IP del extremo (peer) subyacente de la conexión (ver el
        módulo <module>mod_remoteip</module>).</td></tr>

    <tr><td><code>%A</code></td>
        <td>Dirección IP local.</td></tr>

    <tr><td><code>%B</code></td>
        <td>Tamaño de la respuesta en bytes, excluyendo las cabeceras HTTP.</td></tr>

    <tr><td><code>%b</code></td>
        <td>Tamaño de la respuesta en bytes, excluyendo las cabeceras HTTP. En formato CLF, <em>es decir</em>
        un '<code>-</code>' en lugar de un 0 cuando no se envían bytes.</td></tr>

    <tr><td><code>%{<var>VARNAME</var>}C</code></td>
        <td>El contenido de la cookie <var>VARNAME</var> en la petición enviada
        al servidor. Solo se admiten completamente las cookies de versión 0.</td></tr>

    <tr><td><code>%D</code></td>
        <td>El tiempo empleado en atender la petición, en microsegundos.</td></tr>

    <tr><td><code>%{<var>VARNAME</var>}e</code></td>
        <td>El contenido de la variable de entorno
        <var>VARNAME</var>.</td></tr>

    <tr><td><code>%f</code></td>
        <td>Nombre de archivo.</td></tr>

    <tr><td><code>%h</code></td>
        <td>Nombre de host remoto. Registrará la dirección IP si <directive
        module="core">HostnameLookups</directive> está establecida en
        <code>Off</code>, que es el valor por defecto. Si registra el nombre de
        host solo para unos pocos hosts, probablemente tenga directivas de
        control de acceso que los mencionan por su nombre. Vea <a
        href="mod_authz_host.html#reqhost">la documentación de Require host
        </a>.</td></tr>

    <tr><td><code>%{c}h</code></td>
        <td>Como <code>%h</code>, pero siempre informa del nombre de host de la
        conexión TCP subyacente y no de ninguna modificación del nombre de host
        remoto realizada por módulos como <module>mod_remoteip</module>.</td></tr>

    <tr><td><code>%H</code></td>
        <td>El protocolo de la petición.</td></tr>

    <tr><td><code>%{<var>VARNAME</var>}i</code></td>
        <td>El contenido de las líneas de cabecera <code><var>VARNAME</var>:</code>
        en la petición enviada al servidor. Los cambios realizados por otros
        módulos (por ejemplo <module>mod_headers</module>) afectan a esto. Si le
        interesa saber cuál era la cabecera de la petición antes de que la
        mayoría de los módulos la hubieran modificado, use <module>mod_setenvif</module>
        para copiar la cabecera en una variable de entorno interna y registrar
        ese valor con <code>%{<var>VARNAME</var>}e</code> descrito
        anteriormente.
        </td></tr>

    <tr><td><code>%k</code></td>
        <td>Número de peticiones keepalive gestionadas en esta conexión. Interesante si
          se está usando <directive module="core">KeepAlive</directive>, de modo que,
          por ejemplo, un '1' significa la primera petición keepalive después de la
          inicial, '2' la segunda, etc.;
          en caso contrario esto siempre es 0 (indicando la petición inicial).</td></tr>

    <tr><td><code>%l</code></td>
        <td>Nombre de usuario remoto (logname, de identd, si se suministra). Esto devolverá un
        guion a menos que <module>mod_ident</module> esté presente y <directive
        module="mod_ident">IdentityCheck</directive> esté establecida en
        <code>On</code>.</td></tr>

    <tr><td><code>%L</code></td>
        <td>El ID de log de la petición del log de errores (o '-' si no se ha
            registrado nada en el log de errores para esta petición). Busque la
            línea correspondiente del log de errores para ver qué petición causó qué error.</td></tr>

    <tr><td><code>%m</code></td>
        <td>El método de la petición.</td></tr>

    <tr><td><code>%{<var>VARNAME</var>}n</code></td>
        <td>El contenido de la nota <var>VARNAME</var> de otro
        módulo.</td></tr>

    <tr><td><code>%{<var>VARNAME</var>}o</code></td>
        <td>El contenido de las líneas de cabecera <code><var>VARNAME</var>:</code>
        en la respuesta.</td></tr>

    <tr><td><code>%p</code></td>
        <td>El puerto canónico del servidor que atiende la petición.</td></tr>

    <tr><td><code>%{<var>format</var>}p</code></td>
        <td>El puerto canónico del servidor que atiende la petición, el
        puerto real del servidor, o el puerto real del cliente. Los formatos
        válidos son <code>canonical</code>, <code>local</code>, o <code>remote</code>.
        </td></tr>

    <tr><td><code>%P</code></td>
        <td>El ID del proceso hijo que atendió la petición.</td></tr>

    <tr><td><code>%{<var>format</var>}P</code></td>
        <td>El ID del proceso o del hilo (thread) que atendió la
        petición. Los formatos válidos son <code>pid</code>, <code>tid</code>,
        y <code>hextid</code>.
        </td></tr>

    <tr><td><code>%q</code></td>
        <td>La cadena de consulta (query string) (precedida de un <code>?</code> si existe
        una cadena de consulta, o una cadena vacía en caso contrario).</td></tr>

    <tr><td><code>%r</code></td>
        <td>Primera línea de la petición. No respeta
        <directive module="core">MergeSlashes</directive>. (es decir, no fusiona
        barras aunque esté a ON)</td></tr>

    <tr><td><code>%R</code></td>
        <td>El handler que genera la respuesta (si lo hay).</td></tr>

    <tr><td><code>%s</code></td>
        <td>Estado. Para peticiones que han sido redirigidas internamente, este es
        el estado de la petición <em>original</em>. Use <code>%&gt;s</code>
        para el estado final.</td></tr>

    <tr><td><code>%t</code></td>
        <td>Momento en que se recibió la petición, en el formato <code>[18/Sep/2011:19:18:28 -0400]</code>.
        El último número indica el desfase de zona horaria respecto a GMT</td></tr>

    <tr><td><code>%{<var>format</var>}t</code></td>
        <td>La hora, en la forma indicada por el formato, que debe estar en
        un formato extendido de <code>strftime(3)</code> (potencialmente localizado).
        Si el formato comienza con <code>begin:</code> (por defecto) la hora se toma
        al comienzo del procesamiento de la petición. Si comienza con
        <code>end:</code> es el momento en que se escribe la entrada de log,
        cerca del final del procesamiento de la petición. Además de los formatos
        admitidos por <code>strftime(3)</code>, se admiten los siguientes tokens de
        formato:
        <table>
        <tr><td><code>sec</code></td><td>número de segundos desde el Epoch</td></tr>
        <tr><td><code>msec</code></td><td>número de milisegundos desde el Epoch</td></tr>
        <tr><td><code>usec</code></td><td>número de microsegundos desde el Epoch</td></tr>
        <tr><td><code>msec_frac</code></td><td>fracción de milisegundo</td></tr>
        <tr><td><code>usec_frac</code></td><td>fracción de microsegundo</td></tr>
        </table>
        Estos tokens no pueden combinarse entre sí ni con el formato de
        <code>strftime(3)</code> en la misma cadena de formato. Puede usar varios
        tokens <code>%{<var>format</var>}t</code> en su lugar.
        </td></tr>

    <tr><td><code>%T</code></td>
        <td>El tiempo empleado en atender la petición, en segundos.</td></tr>

    <tr><td><code>%{<var>UNIT</var>}T</code></td>
        <td>El tiempo empleado en atender la petición, en la unidad de tiempo indicada por
        <code>UNIT</code>. Las unidades válidas son <code>ms</code> para milisegundos,
        <code>us</code> para microsegundos, y <code>s</code> para segundos.
        Usar <code>s</code> da el mismo resultado que <code>%T</code>
        sin ningún formato; usar <code>us</code> da el mismo resultado
        que <code>%D</code>. Combinar <code>%T</code> con una unidad está
        disponible en la versión 2.4.13 y posteriores.</td></tr>

    <tr><td><code>%u</code></td>
        <td>Usuario remoto si la petición se autenticó. Puede ser incorrecto si el estado de
        retorno (<code>%s</code>) es 401 (no autorizado).</td></tr>

    <tr><td><code>%U</code></td>
        <td>La ruta URL solicitada, sin incluir ninguna cadena de consulta.
        Respeta <directive module="core">MergeSlashes</directive>.
        (es decir, las barras se fusionan si está a <code>ON</code>)</td></tr>

    <tr><td><code>%v</code></td>
        <td>El <directive module="core">ServerName</directive> canónico
        del servidor que atiende la petición.</td></tr>

    <tr><td><code>%V</code></td>
        <td>El nombre del servidor según el ajuste <directive module="core"
        >UseCanonicalName</directive>.</td></tr>

    <tr><td><code>%X</code></td>
        <td>Estado de la conexión cuando se completa la respuesta:

        <table>
        <columnspec><column width=".2"/><column width=".6"/></columnspec>
        <tr><td><code>X</code> =</td>
            <td>Conexión abortada antes de completarse la respuesta.</td></tr>
        <tr><td><code>+</code> =</td>
            <td>La conexión puede mantenerse activa después de que se
            envíe la respuesta.</td></tr>
        <tr><td><code>-</code> = </td>
            <td>La conexión se cerrará después de que se
            envíe la respuesta.</td></tr>
        </table>

        </td></tr>

    <tr><td><code>%I</code></td>
        <td>Bytes recibidos, incluyendo la petición y las cabeceras. No puede ser cero.
        Necesita habilitar <module>mod_logio</module> para usar esto.</td></tr>

    <tr><td><code>%O</code></td>
        <td>Bytes enviados, incluyendo las cabeceras. Puede ser cero en casos raros
        como cuando se aborta una petición antes de enviar una respuesta.
        Necesita habilitar <module>mod_logio</module> para usar esto.</td></tr>

    <tr><td><code>%S</code></td>
        <td>Bytes transferidos (recibidos y enviados), incluyendo la petición y las cabeceras,
        no puede ser cero. Esto es la combinación de %I y %O. Necesita
        habilitar <module>mod_logio</module> para usar esto.</td></tr>

    <tr><td><code>%{<var>VARNAME</var>}^ti</code></td>
        <td>El contenido de las líneas de trailer <code><var>VARNAME</var>:</code>
        en la petición enviada al servidor.  </td></tr>

    <tr><td><code>%{<var>VARNAME</var>}^to</code></td>
        <td>El contenido de las líneas de trailer <code><var>VARNAME</var>:</code>
        en la respuesta enviada desde el servidor.  </td></tr>

    </table>

    <section id="modifiers"><title>Modificadores</title>

      <p>Ciertos elementos pueden restringirse para que se impriman solo
      para respuestas con códigos de estado HTTP específicos, colocando una
      lista de códigos de estado separados por comas inmediatamente después
      del "%". La lista de códigos de estado puede ir precedida de un
      "<code>!</code>" para indicar negación.</p>

    <table border="1" style="zebra">
    <columnspec><column width=".2"/><column width=".8"/></columnspec>

    <tr><th>Cadena de formato</th>
    <th>Significado</th></tr>

    <tr>
    <td><code>%400,501{User-agent}i</code></td>
    <td>Registra <code>User-agent</code> solo en errores 400 y 501. Para
      otros códigos de estado, se registrará la cadena literal
      <code>"-"</code>.</td></tr>

    <tr><td><code>%!200,304,302{Referer}i</code></td>
    <td>Registra <code>Referer</code> en todas las peticiones que
    <em>no</em> devuelvan uno de los tres códigos especificados,
    "<code>-</code>" en caso contrario.
    </td></tr>

    </table>

      <p>Los modificadores "&lt;" y "&gt;" pueden usarse para peticiones que
      han sido redirigidas internamente, para elegir si debe consultarse la
      petición original o la final (respectivamente). Por
      defecto, las directivas <code>%</code> <code>%s, %U, %T,
      %D,</code> y <code>%r</code> miran a la petición original
      mientras que todas las demás miran a la petición final. Así, por
      ejemplo, <code>%&gt;s</code> puede usarse para registrar el estado
      final de la petición, y <code>%&lt;u</code> puede usarse para registrar
      el usuario autenticado original en una petición que se redirige
      internamente a un recurso no autenticado.</p>

    </section>

    <section id="format-notes"><title>Notas sobre el formato</title>

      <p>Por razones de seguridad, a partir de la versión 2.0.46,
      los caracteres no imprimibles y otros caracteres especiales en cadenas
      de formato que puedan contener datos de cadena arbitrarios se escapan
      usando secuencias <code>\x<var>hh</var></code>, donde <var>hh</var>
      representa la representación hexadecimal del byte en crudo. Las
      excepciones a esta regla son <code>"</code> y
      <code>\</code>, que se escapan añadiendo delante una barra invertida, y
      todos los caracteres de espacio en blanco, que se escriben en su
      notación de estilo C (<code>\n</code>, <code>\t</code>, etc). En
      versiones anteriores a la 2.0.46, no se realizaba ningún escapado de
      estas cadenas, así que había que ser bastante cuidadoso al tratar con
      los archivos de log en crudo.</p>

      <table>
      <columnspec><column width=".1"/><column width=".45"/><column width=".45"/></columnspec>
      <tr><th>Formato</th><th>Descripción</th><th>Escapado</th></tr>
      <tr><td><code>%C</code></td><td>Valor de cookie</td><td>Sí</td></tr>
      <tr><td><code>%e</code></td><td>Variable de entorno</td><td>Sí</td></tr>
      <tr><td><code>%f</code></td><td>Nombre de archivo de la petición</td><td>Sí</td></tr>
      <tr><td><code>%h</code></td><td>Nombre de host remoto</td><td>Sí</td></tr>
      <tr><td><code>%H</code></td><td>Protocolo de la petición</td><td>Sí</td></tr>
      <tr><td><code>%i</code></td><td>Cabecera de la petición</td><td>Sí</td></tr>
      <tr><td><code>%l</code></td><td>Logname remoto</td><td>Sí</td></tr>
      <tr><td><code>%m</code></td><td>Método de la petición</td><td>Sí</td></tr>
      <tr><td><code>%n</code></td><td>Nota</td><td>Sí</td></tr>
      <tr><td><code>%o</code></td><td>Cabecera de la respuesta</td><td>Sí</td></tr>
      <tr><td><code>%q</code></td><td>Cadena de consulta</td><td>Sí</td></tr>
      <tr><td><code>%r</code></td><td>Línea de la petición</td><td>Sí</td></tr>
      <tr><td><code>%R</code></td><td>Handler</td><td>Sí</td></tr>
      <tr><td><code>%u</code></td><td>Usuario remoto</td><td>Sí</td></tr>
      <tr><td><code>%U</code></td><td>URI de la petición</td><td>Sí</td></tr>
      <tr><td><code>%v</code></td><td>Nombre de host del servidor</td><td>Sí</td></tr>
      <tr><td><code>%V</code></td><td>Nombre canónico del servidor</td><td>Sí</td></tr>
      <tr><td><code>%^ti</code></td><td>Trailer de la petición</td><td>Sí</td></tr>
      <tr><td><code>%^to</code></td><td>Trailer de la respuesta</td><td>Sí</td></tr>
      <tr><td><code>%a</code></td><td>Dirección IP remota</td><td>No (dirección IP)</td></tr>
      <tr><td><code>%A</code></td><td>Dirección IP local</td><td>No (dirección IP)</td></tr>
      <tr><td><code>%b</code>, <code>%B</code></td><td>Bytes enviados</td><td>No (numérico)</td></tr>
      <tr><td><code>%D</code></td><td>Duración de la petición (microsegundos)</td><td>No (numérico)</td></tr>
      <tr><td><code>%k</code></td><td>Peticiones en la conexión</td><td>No (numérico)</td></tr>
      <tr><td><code>%L</code></td><td>ID de log</td><td>No (generado internamente)</td></tr>
      <tr><td><code>%p</code></td><td>Puerto del servidor</td><td>No (numérico)</td></tr>
      <tr><td><code>%P</code></td><td>PID/TID</td><td>No (numérico)</td></tr>
      <tr><td><code>%s</code></td><td>Código de estado</td><td>No (numérico)</td></tr>
      <tr><td><code>%t</code></td><td>Hora de la petición</td><td>No (hora con formato)</td></tr>
      <tr><td><code>%T</code></td><td>Duración de la petición (segundos)</td><td>No (numérico)</td></tr>
      <tr><td><code>%X</code></td><td>Estado de la conexión</td><td>No (un solo carácter)</td></tr>
      </table>

      <p>Las cadenas de formato <code>%b</code> y
      <code>%B</code> no representan el número de
      bytes enviados al cliente, sino simplemente el tamaño en bytes de la
      respuesta HTTP (que será distinto, por ejemplo, si se aborta la
      conexión, o si se usa SSL). El formato <code>%O</code>
      proporcionado por <module>mod_logio</module> registrará el
      número real de bytes enviados por la red.</p>

      <note>
      <p>Nota: <module>mod_cache</module> se implementa como un
      quick-handler y no como un handler estándar. Por lo tanto, la
      cadena de formato <code>%R</code> no devolverá ninguna información de
      handler cuando intervenga el almacenamiento en caché de contenido.</p>
      </note>

    </section>

    <section id="examples"><title>Ejemplos</title>

      <p>Algunas cadenas de formato de log de uso común son:</p>

      <dl>
        <dt>Common Log Format (CLF)</dt>
        <dd><code>"%h %l %u %t \"%r\" %&gt;s %b"</code></dd>

        <dt>Common Log Format con Virtual Host</dt>
        <dd><code>"%v %h %l %u %t \"%r\" %&gt;s %b"</code></dd>

        <dt>Formato de log extendido/combinado de NCSA</dt>
        <dd><code>"%h %l %u %t \"%r\" %&gt;s %b \"%{Referer}i\"
        \"%{User-agent}i\""</code></dd>

        <dt>Formato de log de Referer</dt>
        <dd><code>"%{Referer}i -&gt; %U"</code></dd>

        <dt>Formato de log de agente (navegador)</dt>
        <dd><code>"%{User-agent}i"</code></dd>
      </dl>

      <p>Puede usar la directiva <code>%{format}t</code> varias veces para
      construir un formato de hora usando los tokens de formato extendido
      como <code>msec_frac</code>:</p>
      <dl>
<dt>Marca de tiempo incluyendo milisegundos</dt>
<dd><code>"%{%d/%b/%Y %T}t.%{msec_frac}t %{%z}t"</code></dd>

      </dl>

    </section>
</section>

<section id="security"><title>Consideraciones de seguridad</title>
    <p>Vea el documento <a
    href="../misc/security_tips.html#serverroot">consejos de seguridad</a>
    para más detalles sobre por qué podría verse comprometida su seguridad
    si el directorio donde se almacenan los archivos de log puede ser
    escrito por alguien distinto del usuario que arranca el servidor.</p>
</section>

<directivesynopsis>
<name>BufferedLogs</name>
<description>Almacena en búfer las entradas de log en memoria antes de escribirlas en disco</description>
<syntax>BufferedLogs On|Off</syntax>
<default>BufferedLogs Off</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>La directiva <directive>BufferedLogs</directive> hace que
    <module>mod_log_config</module> almacene varias entradas de log en
    memoria y las escriba juntas en disco, en lugar de escribirlas
    después de cada petición. En algunos sistemas, esto puede resultar en
    un acceso a disco más eficiente y, por tanto, en un mejor rendimiento. Solo
    puede establecerse una vez para todo el servidor; no puede configurarse
    por cada host virtual.</p>

    <note>Esta directiva debe usarse con precaución, ya que un cuelgue podría
    provocar la pérdida de datos de registro.</note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CustomLog</name>
<description>Establece el nombre de archivo y el formato del archivo de log</description>
<syntax>CustomLog  <var>file</var>|<var>pipe</var>
<var>format</var>|<var>nickname</var>
[env=[!]<var>environment-variable</var>|
expr=<var>expression</var>]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>CustomLog</directive> se usa para
    registrar las peticiones al servidor. Se especifica un formato de log, y el
    registro puede hacerse opcionalmente condicional a las características de
    la petición usando variables de entorno.</p>

    <p>El primer argumento, que especifica la ubicación en la que
    se escribirán los logs, puede tomar uno de los dos
    tipos de valores siguientes:</p>

    <dl>
      <dt><var>file</var></dt>
      <dd>Un nombre de archivo, relativo a <directive module="core"
      >ServerRoot</directive>.</dd>

      <dt><var>pipe</var></dt>
      <dd>El carácter de tubería (pipe) "<code>|</code>", seguido de la ruta
      a un programa que recibirá la información de log por su entrada
      estándar. Vea las notas sobre <a href="../logs.html#piped">logs con tubería</a>
      para más información.

      <note type="warning"><title>Seguridad:</title>
      <p>Si se usa un programa, se ejecutará como el usuario que
      arrancó <program>httpd</program>. Esto será root si el servidor fue
      arrancado por root; asegúrese de que el programa es seguro.</p>
      </note>
      <note type="warning"><title>Nota</title>
        <p>Al introducir una ruta de archivo en plataformas no Unix, debe tenerse
        cuidado de usar solo barras hacia delante, aunque la plataforma
        pueda permitir el uso de barras invertidas. En general es buena idea
        usar siempre barras hacia delante en todos los archivos de configuración.</p>
      </note></dd>
    </dl>

    <p>El segundo argumento especifica lo que se escribirá en el
    archivo de log. Puede especificar bien un <var>nickname</var> definido por
    una directiva <directive module="mod_log_config">LogFormat</directive>
    anterior, o puede ser una cadena de <var>format</var> explícita como
    se describe en la sección <a href="#formats">formatos de log</a>.</p>

    <p>Por ejemplo, los dos siguientes conjuntos de directivas tienen
    exactamente el mismo efecto:</p>

    <highlight language="config">
# CustomLog con nickname de formato
LogFormat "%h %l %u %t \"%r\" %&gt;s %b" common
CustomLog "logs/access_log" common

# CustomLog con cadena de formato explícita
CustomLog "logs/access_log" "%h %l %u %t \"%r\" %&gt;s %b"
    </highlight>

    <p>El tercer argumento es opcional y controla si se
    registra o no una petición concreta. La condición puede ser la
    presencia o ausencia (en el caso de una cláusula
    '<code>env=!<var>name</var></code>') de una variable concreta en el
    <a href="../env.html">entorno</a> del servidor. Alternativamente, la
    condición puede expresarse como una <a href="../expr.html"
    >expresión</a> booleana arbitraria. Si no se satisface la condición, la
    petición no se registrará. Las referencias a cabeceras HTTP en la
    expresión no provocarán que los nombres de las cabeceras se añadan a la
    cabecera Vary.</p>

    <p>Las variables de entorno pueden establecerse por cada
    petición usando los módulos <module>mod_setenvif</module>
    y/o <module>mod_rewrite</module>. Por
    ejemplo, si quiere registrar las peticiones de todas las imágenes GIF
    de su servidor en un archivo de log separado pero no en su log
    principal, puede usar:</p>

    <highlight language="config">
SetEnvIf Request_URI \.gif$ gif-image
CustomLog "gif-requests.log" common env=gif-image
CustomLog "nongif-requests.log" common env=!gif-image
    </highlight>

    <p>O, para reproducir el comportamiento de la antigua directiva
    RefererIgnore, podría usar lo siguiente:</p>

    <highlight language="config">
SetEnvIf Referer example\.com localreferer
CustomLog "referer.log" referer env=!localreferer
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LogFormat</name>
<description>Describe un formato para usar en un archivo de log</description>
<syntax>LogFormat <var>format</var>|<var>nickname</var>
[<var>nickname</var>]</syntax>
<default>LogFormat "%h %l %u %t \"%r\" %>s %b"</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Esta directiva especifica el formato del archivo de log de
    acceso.</p>

    <p>La directiva <directive>LogFormat</directive> puede adoptar una de dos
    formas. En la primera forma, donde solo se especifica un argumento,
    esta directiva establece el formato de log que usarán los logs
    especificados en directivas <directive>TransferLog</directive>
    posteriores. El único argumento puede especificar un
    <var>format</var> explícito como se describe en la sección <a href="#formats">formatos
    de log personalizados</a> anterior. Alternativamente, puede usar un
    <var>nickname</var> para referirse a un formato de log definido en una
    directiva <directive>LogFormat</directive> anterior como se describe
    más abajo.</p>

    <p>La segunda forma de la directiva <directive>LogFormat</directive>
    asocia un <var>format</var> explícito con un
    <var>nickname</var>. Este <var>nickname</var> puede usarse después en
    directivas <directive>LogFormat</directive> o
    <directive module="mod_log_config">CustomLog</directive> posteriores en
    lugar de repetir toda la cadena de formato. Una directiva
    <directive>LogFormat</directive> que define un nickname
    <strong>no hace nada más</strong> -- es decir, <em>solo</em>
    define el nickname, no aplica realmente el formato ni lo convierte en
    el predeterminado. Por lo tanto, no afectará a directivas
    <directive module="mod_log_config">TransferLog</directive> posteriores.
    Además, <directive>LogFormat</directive> no puede usar un nickname
    para definir otro nickname. Observe que el nickname no debe contener
    signos de porcentaje (<code>%</code>).</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      LogFormat "%v %h %l %u %t \"%r\" %&gt;s %b" vhost_common
      </highlight>
    </example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>TransferLog</name>
<description>Especifica la ubicación de un archivo de log</description>
<syntax>TransferLog <var>file</var>|<var>pipe</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Esta directiva tiene exactamente los mismos argumentos y efecto que
    la directiva <directive module="mod_log_config">CustomLog</directive>,
    con la excepción de que no permite especificar el formato de log
    explícitamente ni el registro condicional de peticiones.
    En su lugar, el formato de log viene determinado por la directiva
    <directive module="mod_log_config">LogFormat</directive> más reciente
    que no defina un nickname. Se usa el Common Log Format si no se ha
    especificado ningún otro formato.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
LogFormat "%h %l %u %t \"%r\" %&gt;s %b \"%{Referer}i\" \"%{User-agent}i\""
TransferLog "logs/access_log"
      </highlight>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>GlobalLog</name>
<description>Establece el nombre de archivo y el formato del archivo de log</description>
<syntax>GlobalLog <var>file</var>|<var>pipe</var>
<var>format</var>|<var>nickname</var>
[env=[!]<var>environment-variable</var>|
expr=<var>expression</var>]</syntax>
<contextlist><context>server config</context>
</contextlist>
<compatibility>Disponible en Apache HTTP Server 2.4.19 y posteriores</compatibility>

<usage>

    <p>La directiva <directive>GlobalLog</directive> define un log compartido
       por la configuración del servidor principal y todos los hosts virtuales
       definidos.</p>

    <p>La directiva <directive>GlobalLog</directive> es idéntica a
    la directiva <directive>CustomLog</directive>, aparte de las siguientes
    diferencias:</p>
    <ul>
       <li><directive>GlobalLog</directive> no es válida en contexto de
            host virtual.</li>
       <li><directive>GlobalLog</directive> la usan los hosts virtuales que
           definen su propio <directive>CustomLog</directive>, a diferencia de un
           <directive>CustomLog</directive> especificado globalmente.</li>
    </ul>
</usage>
</directivesynopsis>


</modulesynopsis>
