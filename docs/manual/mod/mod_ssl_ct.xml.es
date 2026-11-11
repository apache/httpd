<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1936367 -->
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

<modulesynopsis metafile="mod_ssl_ct.xml.meta">

<name>mod_ssl_ct</name>
<description>Implementación de Certificate Transparency (RFC 6962)
</description>
<status>Deprecated</status>
<sourcefile>mod_ssl_ct.c</sourcefile>
<identifier>ssl_ct_module</identifier>

<summary>

<p>Este módulo proporciona una implementación de Certificate Transparency, junto
con <module>mod_ssl</module> y las herramientas de línea de comandos del proyecto
de código abierto <a href="https://certificate.transparency.dev/">certificate-transparency</a>.
El objetivo de Certificate Transparency es exponer el uso de certificados de
servidor en los que confían los navegadores pero que fueron emitidos por error o
de forma malintencionada. Hay más información sobre Certificate Transparency
disponible en <a href="http://www.certificate-transparency.org/">
http://www.certificate-transparency.org/</a>. Terminología clave usada en
esta documentación:</p>

<dl>
  <dt>Certificate log</dt>
  <dd>Un certificate log, al que en esta documentación se hace referencia
  simplemente como <q>log</q>, es un servicio de red al que se han enviado
  certificados de servidor. Un user agent puede confirmar que el certificado de
  un servidor al que accede se ha enviado a un log en el que confía, y que el
  propio log no ha sido manipulado.</dd>

  <dt>Signed Certificate Timestamp (SCT)</dt>
  <dd>Este es un acuse de recibo de un log de que ha aceptado un certificado
  válido. Está firmado con la clave pública del log. Se pasa uno o más SCTs a
  los clientes durante el handshake, ya sea en el ServerHello (extensión TLS),
  en una extensión del certificado, o en una respuesta OCSP stapled.</dd>
</dl>

<p>Esta implementación para Apache httpd proporciona estas funcionalidades para
servidores y proxies TLS:</p>

<ul>
  <li>Los Signed Certificate Timestamps (SCTs) se pueden obtener de los logs de
  forma automática y, junto con los SCTs configurados estáticamente, se envían a
  los clientes que los reconocen en el ServerHello (durante el handshake).</li>
  <li>El proxy puede recibir SCTs de los servidores de origen en el ServerHello,
  en una extensión del certificado o en respuestas OCSP stapled; los SCTs
  recibidos pueden validarse parcialmente en línea y, opcionalmente, quedar en
  cola para una auditoría fuera de línea.</li>
  <li>El proxy se puede configurar para que no permita la comunicación con un
  servidor de origen que no proporcione un SCT que pase la validación en
  línea.</li>
</ul>

<p>La información de configuración sobre los logs se puede definir de forma
estática en la configuración del servidor web o mantenerse en una base de datos
SQLite3. En este último caso, <module>mod_ssl_ct</module> volverá a cargar la
base de datos periódicamente, de modo que cualquier infraestructura específica
del sitio para mantener y propagar la información de configuración de los logs
no tiene que reiniciar también httpd para que surta efecto.</p>

<note>Este módulo es experimental por las siguientes razones:
<ul>
  <li>Pruebas y revisión insuficientes</li>
  <li>Dependencia de una versión de OpenSSL aún no publicada (1.0.2, Beta 3 o
  posterior) para el funcionamiento básico</li>
  <li>Capacidad de <a href="#audit">auditoría fuera de línea</a> incompleta</li>
</ul>

<p>Los mecanismos de configuración, el formato de los datos guardados para la
auditoría fuera de línea y otras características están sujetos a cambios en
función de futuros comentarios y pruebas.</p>
</note>
</summary>

<section id="server">
  <title>Resumen del procesamiento en el servidor</title>

  <p>Los servidores necesitan enviar SCTs a sus clientes. Los SCTs en una
  extensión del certificado o en una respuesta OCSP stapled se enviarán sin
  ninguna lógica de programa especial. Este módulo gestiona el envío de los SCTs
  configurados por el administrador o recibidos de los logs configurados.</p>

  <p>El número de SCTs enviados en el ServerHello (es decir, sin incluir los de
  una extensión del certificado o de una respuesta OCSP stapled) se puede
  limitar con la directiva <directive module="mod_ssl_ct">CTServerHelloSCTLimit</directive>.</p>

  <p>Para cada certificado de servidor, un proceso daemon mantiene una lista de
  SCTs para enviar en el ServerHello, creada a partir de los SCTs configurados
  estáticamente, así como de los recibidos de los logs. Los logs marcados como
  no fiables o con una marca de tiempo máxima válida anterior al momento actual
  se ignorarán. Periódicamente, el daemon enviará certificados a un log según
  sea necesario (debido a cambios en la configuración del log o por antigüedad)
  y reconstruirá la concatenación de SCTs.</p>

  <p>La lista de SCTs de un certificado de servidor se enviará a cualquier
  cliente que indique que la reconoce en el ClientHello cuando se use ese
  certificado de servidor concreto.</p>

</section>

<section id="proxy">
  <title>Resumen del procesamiento en el proxy</title>

  <p>El proxy indica que reconoce Certificate Transparency en el ClientHello
  incluyendo la extensión <em>signed_certificate_timestamp</em>. Puede
  reconocer SCTs recibidos en el ServerHello, en una extensión del certificado
  de un servidor de origen, o en una respuesta OCSP stapled.</p>

  <p>Se intenta la verificación en línea para cada SCT recibido:</p>

  <ul>
    <li>Para cualquier SCT, se puede comprobar la marca de tiempo para ver si
    aún no es válida, en función de la hora actual y de cualquier intervalo de
    tiempo válido configurado para el log.</li>
    <li>Para un SCT de un log para el que haya una clave pública configurada,
    se comprobará la firma del servidor.</li>
  </ul>

  <p>Si la verificación falla para al menos un SCT y no se ha logrado verificar
  con éxito al menos un SCT, la conexión se aborta si <directive
  module="mod_ssl_ct">CTProxyAwareness</directive> está establecida en
  <em>require</em>.</p>

  <p>Además, la cadena de certificados del servidor y los SCTs se almacenan
  para su verificación fuera de línea si está configurada la directiva
  <directive module="mod_ssl_ct">CTAuditStorage</directive>.</p>

  <p>Como optimización, la verificación en línea y el almacenamiento de los
  datos del servidor solo se realizan la primera vez que un proceso hijo del
  servidor web recibe los datos. Esto ahorra algo de tiempo de procesamiento,
  así como espacio en disco. En configuraciones de proxy inverso típicas, se
  necesitará muy poca sobrecarga de procesamiento.</p>

</section>

<section id="logconf">
  <title>Configuración de logs</title>

  <p>Los servidores y los proxies usan información distinta sobre los logs para
  su procesamiento. Esta <em>configuración de log</em> se puede establecer de
  dos formas:</p>

  <ul>
    <li>Crear una base de datos de configuración de logs con <program>ctlogconfig</program>,
    y configurar la ruta a esa base de datos con la directiva <directive module="mod_ssl_ct">
    CTLogConfig</directive>. Este método de configuración admite actualizaciones
    dinámicas; <module>mod_ssl_ct</module> volverá a leer la base de datos a
    intervalos regulares. Además, el programa de auditoría fuera de línea
    <code>ctauditscts</code> puede usar esta configuración para encontrar la URL
    de los logs.</li>

    <li>Configurar la información sobre los logs de forma estática con la
    directiva <directive module="mod_ssl_ct">CTStaticLogConfig</directive>. Como
    con todas las demás directivas, el servidor debe reiniciarse para que los
    cambios en las directivas tengan efecto.</li>
  </ul>

  <p>A continuación se describe la información que se puede configurar sobre un
  log con cualquiera de los dos mecanismos:</p>

  <dl>
    <dt>log id</dt>
    <dd>El log id es el hash SHA-256 de la clave pública del log, y forma parte
    de todos los SCTs. Es una forma práctica de identificar un log concreto al
    configurar intervalos de marca de tiempo válidos u otra información
    determinada.</dd>

    <dt>clave pública del log</dt>
    <dd>Un proxy debe tener la clave pública del log para poder comprobar la
    firma de los SCTs que recibe y que se obtuvieron del log.
    <br />
    Un servidor debe tener la clave pública del log para poder enviarle
    certificados.</dd>

    <dt>ajuste general de confianza/desconfianza</dt>
    <dd>Este es un mecanismo para dejar de confiar o restaurar la confianza en
    un log concreto, por cualquier motivo (incluido simplemente evitar la
    interacción con el log en situaciones en las que está fuera de línea).</dd>

    <dt>marcas de tiempo válidas mínima y/o máxima</dt>
    <dd>Cuando está configurado, el proxy comprobará que las marcas de tiempo de
    los SCTs estén dentro del intervalo válido.</dd>

    <dt>URL del log</dt>
    <dd>La URL del log (para su API) la necesita un servidor para poder enviarle
    certificados de servidor. El servidor enviará cada certificado de servidor
    con el fin de obtener un SCT por cada log que tenga una URL configurada,
    excepto cuando el log también esté marcado como no fiable o la hora actual
    no esté dentro de ningún intervalo de marca de tiempo válido configurado.
    <br />
    La URL del log también es necesaria para la auditoría fuera de línea de los
    SCTs recibidos por un proxy.</dd>
  </dl>

  <p>Por lo general, solo se configura un pequeño subconjunto de esta
  información para un log concreto. Consulte la documentación de la directiva
  <directive module="mod_ssl_ct">CTStaticLogConfig</directive> y del comando
  <program>ctlogconfig</program> para obtener información más específica.</p>

</section>

<section id="static">
  <title>Almacenar SCTs en un formato que pueda usar mod_ssl_ct</title>

  <p><module>mod_ssl_ct</module> permite configurar SCTs de forma estática
  usando la directiva <directive>CTStaticSCTs</directive>. Deben estar en forma
  binaria, listos para enviarse a un cliente.</p>

  <p>En el <a href="https://github.com/tomrittervg/ct-tools">repositorio
  ct-tools de Tom Ritter</a> se puede encontrar código de ejemplo en forma de un
  script de Python para construir un SCT en el formato correcto a partir de los
  datos recibidos de un log. Consulte <code>write-sct.py</code></p>
</section>

<section id="logging">
  <title>Registrar el estado de CT en el access log</title>

  <p>Los modos de proxy y de servidor establecen las variables
  <code>SSL_CT_PROXY_STATUS</code> y <code>SSL_CT_CLIENT_STATUS</code>,
  respectivamente, para indicar si el correspondiente peer reconoce CT.</p>

  <p>El modo de proxy establece la variable <code>SSL_CT_PROXY_SCT_SOURCES</code>
  para indicar si se obtuvieron SCTs y de dónde (ServerHello, extensión del
  certificado, etc.).</p>

  <p>Estas variables se pueden registrar con el formato <code>%{<em>varname</em>}e</code>
  de <module>mod_log_config</module>.</p>
</section>

<section id="audit">
  <title>Auditoría fuera de línea para el proxy</title>

  <p>El soporte experimental para esto está implementado en el comando
  <code>ctauditscts</code>, que a su vez depende de la herramienta
  <code>verify_single_proof.py</code> del proyecto de código abierto
  <em>certificate-transparency</em>. <code>ctauditscts</code> puede analizar
  datos para la auditoría fuera de línea (habilitada con la directiva <directive
  module="mod_ssl_ct">CTAuditStorage</directive>) e invocar
  <code>verify_single_proof.py</code>.
  </p>

  <p>A continuación hay unas notas generales para usar <code>ctauditscts</code>:</p>

  <ul>
    <li>Cree un <em>virtualenv</em> con el archivo <code>requirements.txt</code>
    del proyecto <em>certificate-transparency</em> y ejecute los siguientes pasos
    con ese <em>virtualenv</em> activado.</li>
    <li>Establezca <code>PYTHONPATH</code> para que incluya el directorio
    <code>python</code> dentro de las herramientas de <em>certificate-transparency</em>.</li>
    <li>Establezca <code>PATH</code> para que incluya el directorio
    <code>python/ct/client/tools</code>.</li>
    <li>Ejecute <code>ctauditscts</code>, pasando el valor de la directiva
    <directive>CTAuditStorage</directive> y, opcionalmente, la ruta a la base de
    datos de configuración de logs. Esta última se usará para buscar URLs de
    logs por log id.</li>
  </ul>

  <p>Los datos guardados para la auditoría también pueden ser usados por otros
  programas; consulte el código fuente de <code>ctauditscts</code> para obtener
  detalles sobre el procesamiento de los datos.</p>
</section>

<directivesynopsis>
<name>CTAuditStorage</name>
<description>Directorio existente donde se almacenarán los datos para la auditoría fuera de línea</description>
<syntax>CTAuditStorage <em>directory</em></syntax>
<default>none</default>
<contextlist><context>server config</context></contextlist>

<usage>
  <p>La directiva <directive>CTAuditStorage</directive> establece el nombre de
  un directorio donde se almacenarán los datos para la auditoría fuera de
  línea. Si <em>directory</em> no es absoluto, se asume que es relativo a
  <directive module="core">DefaultRuntimeDir</directive>.</p>

  <p>Si no se especifica esta directiva, los datos no se almacenarán para la
  auditoría fuera de línea.</p>

  <p>El directorio contendrá archivos llamados <code><em>PID</em>.tmp</code>
  para los procesos hijo activos y archivos llamados <code><em>PID</em>.out</code>
  para los procesos hijo que hayan finalizado. Estos archivos <code>.out</code>
  están listos para la auditoría fuera de línea. El comando experimental
  <code>ctauditscts</code> (en el árbol de fuentes de httpd, no instalado
  actualmente) se integra con las herramientas de
  <em>certificate-transparency</em> para realizar la auditoría.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CTLogClient</name>
<description>Ubicación de la herramienta cliente de log de certificate-transparency</description>
<syntax>CTLogClient <em>executable</em></syntax>
<default>none</default>
<contextlist><context>server config</context>
</contextlist>

<usage>
  <p><em>executable</em> es la ruta completa a la herramienta cliente de log,
  que normalmente es el archivo <code>cpp/client/ct</code> (o <code>ct.exe</code>)
  dentro del árbol de fuentes del proyecto de código abierto
  <a href="https://certificate.transparency.dev/">
  certificate-transparency</a>.</p>

  <p>Se podría usar una implementación alternativa para obtener SCTs de un
  certificado de servidor siempre que la interfaz de línea de comandos sea
  equivalente.</p>

  <p>Si esta directiva no está configurada, no se podrán enviar certificados de
  servidor a los logs para obtener SCTs; por lo tanto, solo se proporcionarán a
  los clientes los SCTs gestionados por el administrador o los SCTs en
  extensiones del certificado.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CTLogConfigDB</name>
<description>Base de datos de configuración de logs que admite actualizaciones dinámicas</description>
<syntax>CTLogConfigDB <em>filename</em></syntax>
<default>none</default>
<contextlist><context>server config</context></contextlist>

<usage>
  <p>La directiva <directive>CTLogConfigDB</directive> establece el nombre de
  una base de datos que contiene la configuración de los logs conocidos. Si
  <em>filename</em> no es absoluto, se asume que es relativo a
  <directive module="core">ServerRoot</directive>.</p>

  <p>Consulte la documentación del programa <program>ctlogconfig</program>, que
  gestiona la base de datos.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CTMaxSCTAge</name>
<description>Antigüedad máxima de un SCT obtenido de un log, antes de que se
renueve</description>
<syntax>CTMaxSCTAge <em>num-seconds</em></syntax>
<default>1 day</default>
<contextlist><context>server config</context></contextlist>

<usage>
  <p>Los certificados de servidor con SCTs que tengan una antigüedad mayor que
  este máximo se volverán a enviar a los logs configurados. Por lo general, el
  log devolverá el mismo SCT que antes, pero esto depende del funcionamiento del
  log. Los SCTs se renovarán según sea necesario durante el funcionamiento
  normal del servidor, devolviéndose nuevos SCTs a los clientes en cuanto estén
  disponibles.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CTProxyAwareness</name>
<description>Nivel de reconocimiento y cumplimiento de CT para un proxy
</description>
<syntax>CTProxyAwareness <em>oblivious|aware|require</em></syntax>
<default>aware</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>

<usage>
  <p>Esta directiva controla el reconocimiento y las comprobaciones de SCTs
  válidos para un proxy. Hay varias opciones disponibles:</p>

  <dl>
    <dt>oblivious</dt>
    <dd>El proxy ni pedirá ni examinará SCTs. El procesamiento de Certificate
    Transparency para el proxy está completamente desactivado.</dd>

    <dt>aware</dt>
    <dd>El proxy realizará todo el procesamiento de Certificate Transparency
    correspondiente, como pedir y examinar SCTs. Sin embargo, el proxy no
    impedirá la comunicación si el servidor de origen no proporciona ningún SCT
    válido.</dd>

    <dt>require</dt>
    <dd>El proxy abortará la comunicación con el servidor de origen si este no
    proporciona al menos un SCT que pase la validación en línea.</dd>
  </dl>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>CTSCTStorage</name>
<description>Directorio existente donde se gestionan los SCTs</description>
<syntax>CTSCTStorage <em>directory</em></syntax>
<default>none</default>
<contextlist><context>server config</context>
</contextlist>

<usage>
  <p>La directiva <directive>CTSCTStorage</directive> establece el nombre de un
  directorio donde se almacenarán los SCTs y las listas de SCTs. Si
  <em>directory</em> no es absoluto, se asume que es relativo a
  <directive module="core">DefaultRuntimeDir</directive>.</p>

  <p>Un subdirectorio para cada certificado de servidor contiene información
  relativa a ese certificado; el nombre del subdirectorio es el hash SHA-256
  del certificado.</p>

  <p>El directorio específico del certificado contiene los SCTs obtenidos de
  los logs configurados, las listas de SCTs preparadas a partir de los SCTs
  configurados estáticamente y de los SCTs obtenidos, y otra información usada
  para gestionar los SCTs.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CTServerHelloSCTLimit</name>
<description>Límite del número de SCTs que se pueden devolver en el
ServerHello</description>
<syntax>CTServerHelloSCTLimit <em>limit</em></syntax>
<default>100</default>
<contextlist><context>server config</context>
</contextlist>

<usage>
  <p>Esta directiva se puede usar para limitar el número de SCTs que un
  servidor TLS puede devolver en el ServerHello, en caso de que el número de
  logs configurados y de SCTs definidos estáticamente sea relativamente
  alto.</p>

  <p>Por lo general, solo habría disponibles unos pocos SCTs, por lo que esta
  directiva solo es necesaria en circunstancias especiales.</p>

  <p>La directiva no tiene en cuenta los SCTs que puedan proporcionarse en
  extensiones del certificado o en respuestas OCSP stapled.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CTStaticLogConfig</name>
<description>Configuración estática de información sobre un log</description>
<syntax>CTStaticLogConfig <em>log-id|-</em> <em>public-key-file|-</em>
<em>1|0|-</em> <em>min-timestamp|-</em> <em>max-timestamp|-</em>
<em>log-URL|-</em></syntax>
<default>none</default>
<contextlist><context>server config</context>
</contextlist>

<usage>
  <p>Esta directiva se usa para configurar información sobre un log concreto.
  Esta directiva es apropiada cuando la información de configuración cambia con
  poca frecuencia. Si se deben admitir actualizaciones de configuración
  dinámicas, consulte la directiva <directive module="mod_ssl_ct">CTLogConfigDB</directive>.</p>

  <p>Se deben especificar los seis campos, aunque normalmente solo se debe
  configurar una pequeña cantidad de información para cada log; use <em>-</em>
  cuando no haya información disponible para el campo. Por ejemplo, para
  configurar únicamente un servidor (es decir, sin proxy), el administrador
  podría configurar solo la URL del log que se usará al enviar certificados de
  servidor y obtener un Signed Certificate Timestamp.</p>

  <p>Los campos se definen de la siguiente manera:</p>

  <dl>
    <dt><em>log-id</em></dt>
    <dd>Este es el id del log, que es el hash SHA-256 de la clave pública del
    log, proporcionado en formato hexadecimal. Esta cadena tiene 64 caracteres
    de longitud.
    <br />
    Este campo debe omitirse cuando se proporciona <em>public-key-file</em>.</dd>

    <dt><em>public-key-file</em></dt>
    <dd>Este es el nombre de un archivo que contiene la codificación PEM de la
    clave pública del log. Si el nombre no es absoluto, se asume que es
    relativo a <directive module="core">ServerRoot</directive>.</dd>

    <dt><em>trust/distrust</em></dt>
    <dd>Establezca este campo en <em>1</em> para desconfiar de este log, o para
    evitar de cualquier otra forma usarlo para el envío de certificados de
    servidor. Establézcalo en <em>-</em> o <em>0</em> (el valor por defecto)
    para tratar el log de forma normal.</dd>

    <dt><em>min-timestamp</em> y <em>max-timestamp</em></dt>
    <dd>Una marca de tiempo es una hora expresada como el número de
    milisegundos desde la época, sin tener en cuenta los segundos
    intercalares. Esta es la forma de hora usada en los Signed Certificate
    Timestamps. Se debe proporcionar como un número decimal.
    <br />
    Especifique <strong><code>-</code></strong> para una de las marcas de
    tiempo si se desconoce. Por ejemplo, al configurar la marca de tiempo
    mínima válida para un log que sigue siendo válido, especifique
    <strong><code>-</code></strong> para <em>max-timestamp</em>.
    <br />
    Los SCTs recibidos de este log por el proxy no son válidos si la marca de
    tiempo es anterior a <em>min-timestamp</em> o posterior a <em>max-timestamp</em>.</dd>

    <dt><em>log-URL</em></dt>
    <dd>Esta es la URL del log, que se usa para enviar certificados de servidor
    y, a su vez, obtener un SCT que se enviará a los clientes.</dd>
  </dl>
</usage>

<seealso><a href="#logconf">Configuración de logs</a> contiene información más
general sobre los campos que se pueden configurar con esta directiva.</seealso>

</directivesynopsis>

<directivesynopsis>
<name>CTStaticSCTs</name>
<description>Configuración estática de uno o más SCTs para un certificado de servidor
</description>
<syntax>CTStaticSCTs <em>certificate-pem-file</em> <em>sct-directory</em></syntax>
<default>none</default>
<contextlist><context>server config</context>
</contextlist>

<usage>
  <p>Esta directiva se usa para definir estáticamente uno o más SCTs
  correspondientes a un certificado de servidor. Este mecanismo se puede usar
  en lugar de, o además de, obtener dinámicamente SCTs de los logs
  configurados. Cualquier cambio en el conjunto de SCTs de un certificado de
  servidor concreto se adoptará dinámicamente sin necesidad de reiniciar el
  servidor.</p>

  <p><em>certificate-pem-file</em> hace referencia al certificado de servidor
  en formato PEM. Si el nombre no es absoluto, se asume que es relativo a
  <directive module="core">ServerRoot</directive>.</p>

  <p><em>sct-directory</em> debe contener uno o más archivos con la extensión
  <code>.sct</code>, que representan uno o más SCTs correspondientes al
  certificado de servidor. Si <em>sct-directory</em> no es absoluto, se asume
  que es relativo a <directive module="core">ServerRoot</directive>.</p>

  <p>Si <em>sct-directory</em> está vacío, no se generará ningún error.</p>

  <p>Esta directiva se podría usar para identificar directorios de SCTs
  gestionados por otra infraestructura, siempre que se guarden en formato
  binario con la extensión de archivo <em>.sct</em></p>
</usage>
</directivesynopsis>

</modulesynopsis>
