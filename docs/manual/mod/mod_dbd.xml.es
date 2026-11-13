<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1939372 -->
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

<modulesynopsis metafile="mod_dbd.xml.meta">

<name>mod_dbd</name>
<description>Gestiona conexiones a bases de datos SQL</description>
<status>Extension</status>
<sourcefile>mod_dbd.c</sourcefile>
<identifier>dbd_module</identifier>
<compatibility>Versión 2.1 y posteriores</compatibility>

<summary>
    <p><module>mod_dbd</module> gestiona las conexiones a bases de datos SQL usando
    <glossary>APR</glossary>. Proporciona conexiones de base de datos a petición
    de los módulos que necesitan funciones de base de datos SQL, y se encarga de
    gestionar las bases de datos con una eficiencia y escalabilidad óptimas
    tanto para MPMs con hilos como sin hilos. Para más detalles, visite el
    sitio web de <a href="http://apr.apache.org/">APR</a>.</p>
</summary>

<seealso><a href="../misc/password_encryptions.html">Formatos de contraseña</a></seealso>

<section id="pooling"><title>Agrupación de conexiones</title>
    <p>Este módulo gestiona las conexiones a bases de datos de una manera
    optimizada para la plataforma. En plataformas sin hilos,
    proporciona una conexión persistente al estilo del clásico LAMP
    (Linux, Apache, MySQL, Perl/PHP/Python).
    En plataformas con hilos, proporciona un <em>pool de conexiones</em>
    mucho más escalable y eficiente, como se
    describe en <a href="http://www.apachetutor.org/dev/reslist">este
    artículo en ApacheTutor</a>. Tenga en cuenta que <module>mod_dbd</module>
    sustituye a los módulos presentados en ese artículo.</p>
</section>

<section id="connecting"><title>Conexión</title>

    <p>Para conectarse a su base de datos, necesitará especificar
    un driver y los parámetros de conexión. Estos varían de
    un motor de base de datos a otro. Por ejemplo, para conectarse
    a mysql, haga lo siguiente:</p>

<highlight language="config">
DBDriver mysql
DBDParams host=localhost,dbname=pony,user=shetland,pass=appaloosa
</highlight>

    <p>Después puede usar esta conexión en diversos otros
    módulos, incluyendo <module>mod_rewrite</module>,
    <module>mod_authn_dbd</module> y <module>mod_lua</module>.
    En la documentación de cada uno de esos módulos encontrará
    más ejemplos de uso.</p>

    <p>Consulte <directive>DBDParams</directive> para obtener información
    sobre la cadena de conexión de cada uno de los drivers de base de datos admitidos.</p>

</section>

<section id="API"><title>API DBD de Apache</title>
    <p><module>mod_dbd</module> exporta cinco funciones para que las usen
    otros módulos. La API es la siguiente:</p>

<highlight language="c">
typedef struct {
    apr_dbd_t *handle;
    apr_dbd_driver_t *driver;
    apr_hash_t *prepared;
} ap_dbd_t;

/* Export functions to access the database */

/* acquire a connection that MUST be explicitly closed.
 * Returns NULL on error
 */
AP_DECLARE(ap_dbd_t*) ap_dbd_open(apr_pool_t*, server_rec*);

/* release a connection acquired with ap_dbd_open */
AP_DECLARE(void) ap_dbd_close(server_rec*, ap_dbd_t*);

/* acquire a connection that will have the lifetime of a request
 * and MUST NOT be explicitly closed.  Return NULL on error.
 * This is the preferred function for most applications.
 */
AP_DECLARE(ap_dbd_t*) ap_dbd_acquire(request_rec*);

/* acquire a connection that will have the lifetime of a connection
 * and MUST NOT be explicitly closed.  Return NULL on error.
 */
AP_DECLARE(ap_dbd_t*) ap_dbd_cacquire(conn_rec*);

/* Prepare a statement for use by a client module */
AP_DECLARE(void) ap_dbd_prepare(server_rec*, const char*, const char*);

/* Also export them as optional functions for modules that prefer it */
APR_DECLARE_OPTIONAL_FN(ap_dbd_t*, ap_dbd_open, (apr_pool_t*, server_rec*));
APR_DECLARE_OPTIONAL_FN(void, ap_dbd_close, (server_rec*, ap_dbd_t*));
APR_DECLARE_OPTIONAL_FN(ap_dbd_t*, ap_dbd_acquire, (request_rec*));
APR_DECLARE_OPTIONAL_FN(ap_dbd_t*, ap_dbd_cacquire, (conn_rec*));
APR_DECLARE_OPTIONAL_FN(void, ap_dbd_prepare, (server_rec*, const char*, const char*));
</highlight>
</section>

<section id="prepared"><title>Sentencias preparadas SQL</title>
    <p><module>mod_dbd</module> admite sentencias preparadas SQL en nombre
    de los módulos que deseen usarlas. A cada sentencia preparada
    se le debe asignar un nombre (etiqueta), y se almacenan en un hash:
    el campo <code>prepared</code> de un <code>ap_dbd_t</code>.
    Las entradas del hash son de tipo <code>apr_dbd_prepared_t</code>
    y pueden usarse en cualquiera de los comandos de consulta o selección SQL
    de sentencias preparadas de apr_dbd.</p>

    <p>Corresponde a los módulos que usan dbd emplear las sentencias preparadas
    y documentar qué sentencias se pueden especificar en httpd.conf,
    o proporcionar sus propias directivas y usar <code>ap_dbd_prepare</code>.</p>

	<note type="warning"><title>Advertencia</title>
	Cuando se usan sentencias preparadas con una base de datos MySQL, es preferible establecer
	<code>reconnect</code> a 0 en la cadena de conexión para evitar errores que
	surgen cuando el cliente de MySQL reconecta sin restablecer correctamente las
	sentencias preparadas. Si se establece a 1, se intentará reparar cualquier conexión
	rota, pero como mod_dbd no es informado de ello, las sentencias preparadas quedarán invalidadas.
	</note>
</section>

<section id="security">
<title>ADVERTENCIA DE SEGURIDAD</title>
    <p>Toda aplicación web/base de datos necesita protegerse contra ataques de
    inyección SQL. En la mayoría de los casos, Apache DBD es seguro, porque
    las aplicaciones usan sentencias preparadas, y las entradas no confiables
    solo se usan como datos. Por supuesto, si lo usa a través de módulos
    de terceros, debe verificar qué precauciones puedan requerir.</p>
    <p>Sin embargo, el driver <var>FreeTDS</var> es intrínsecamente
    <strong>inseguro</strong>. La biblioteca subyacente no admite
    sentencias preparadas, por lo que el driver las emula, y la
    entrada no confiable se combina en la sentencia SQL.</p>
    <p>Se puede hacer seguro <em>desinfectando</em> todas las entradas:
    un proceso inspirado en la comprobación "taint" de Perl. Cada entrada
    se compara con una expresión regular, y solo se usa la coincidencia,
    según el idioma de Perl:</p>
    <example>
        <pre><code>  $untrusted =~ /([a-z]+)/;
  $trusted = $1;</code></pre>
    </example>
    <p>Para usar esto, las expresiones regulares de desinfección deben incluirse en las
    sentencias preparadas configuradas. La expresión regular va inmediatamente
    después del % en la sentencia preparada, y se encierra entre
    llaves {}. Por ejemplo, si su aplicación espera una entrada
    alfanumérica, puede usar:</p>
    <example>
       <code>"SELECT foo FROM bar WHERE input = %s"</code>
    </example>
    <p>con otros drivers, sin sufrir nada peor que una consulta fallida.
    Pero con FreeTDS necesitaría:</p>
    <example>
       <code>"SELECT foo FROM bar WHERE input = %{([A-Za-z0-9]+)}s"</code>
    </example>
    <p>Ahora cualquier cosa que no coincida con el grupo $1 de la expresión
    regular se descarta, de modo que la sentencia es segura.</p>
    <p>Una alternativa a esto puede ser el driver ODBC de terceros,
    que ofrece la seguridad de sentencias preparadas genuinas.</p>
</section>
<directivesynopsis>
<name>DBDriver</name>
<description>Especifica un driver SQL</description>
<syntax>DBDriver <var>name</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Selecciona un driver apr_dbd por nombre. El driver debe estar instalado
    en su sistema (en la mayoría de los sistemas, será un objeto compartido o dll).
    Por ejemplo, <code>DBDriver mysql</code> seleccionará el driver de MySQL
    en apr_dbd_mysql.so.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>DBDParams</name>
<description>Parámetros para la conexión a la base de datos</description>
<syntax>DBDParams
<var>param1</var>=<var>value1</var>[,<var>param2</var>=<var>value2</var>]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Según requiera el driver subyacente. Normalmente se usa para
    pasar lo que no pueda tomar un valor por defecto entre el nombre de usuario,
    la contraseña, el nombre de la base de datos, el nombre de host y el número de puerto
    para la conexión.</p>
    <p>Los parámetros de cadena de conexión para los drivers actuales incluyen:</p>
    <dl>
    <dt>FreeTDS (para MSSQL y Sybase)</dt>
    <dd>username, password, appname, dbname, host, charset, lang, server</dd>
    <dt>MySQL</dt>
    <dd>host, port, user, pass, dbname, sock, flags, fldsz, group, reconnect</dd>
    <dt>Oracle</dt>
    <dd>user, pass, dbname, server</dd>
    <dt>PostgreSQL</dt>
    <dd>La cadena de conexión se pasa directamente a <code>PQconnectdb</code></dd>
    <dt>SQLite2</dt>
    <dd>La cadena de conexión se divide por los dos puntos, y <code>part1:part2</code> se usa como <code>sqlite_open(part1, atoi(part2), NULL)</code></dd>
    <dt>SQLite3</dt>
    <dd>La cadena de conexión se pasa directamente a <code>sqlite3_open</code></dd>
    <dt>ODBC</dt>
    <dd>datasource, user, password, connect, ctimeout, stimeout, access, txmode, bufsize</dd>
    </dl>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>DBDPersist</name>
<description>Si se deben usar conexiones persistentes</description>
<syntax>DBDPersist On|Off</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Si se establece a Off, las conexiones persistentes y agrupadas se desactivan.
    Se abre una nueva conexión a la base de datos cuando la solicita un cliente,
    y se cierra inmediatamente al liberarse. Esta opción es para depuración
    y servidores de bajo uso.</p>

    <p>Por defecto se activa un pool de conexiones persistentes
    (o una única conexión persistente al estilo LAMP en el caso de un
    servidor sin hilos), y casi siempre debería usarse en producción.</p>

    <p>Antes de la versión 2.2.2, esta directiva solo aceptaba los valores
    <code>0</code> y <code>1</code> en lugar de <code>Off</code> y
    <code>On</code>, respectivamente.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>DBDPrepareSQL</name>
<description>Define una sentencia preparada SQL</description>
<syntax>DBDPrepareSQL <var>"SQL statement"</var> <var>label</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Para módulos como los de autenticación que usan repetidamente una
    única sentencia SQL, el rendimiento óptimo se consigue preparando
    la sentencia al arrancar en lugar de cada vez que se usa.
    Esta directiva prepara una sentencia SQL y le asigna una etiqueta.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>DBDMin</name>
<description>Número mínimo de conexiones</description>
<syntax>DBDMin <var>number</var></syntax>
<default>DBDMin 1</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Establece el número mínimo de conexiones por proceso (solo
    plataformas con hilos).</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>DBDKeep</name>
<description>Número máximo sostenido de conexiones</description>
<syntax>DBDKeep <var>number</var></syntax>
<default>DBDKeep 2</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Establece el número máximo de conexiones por proceso que se
    mantendrán, salvo para atender picos de demanda (solo
    plataformas con hilos).</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>DBDMax</name>
<description>Número máximo de conexiones</description>
<syntax>DBDMax <var>number</var></syntax>
<default>DBDMax 10</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Establece el número máximo absoluto de conexiones por proceso
    (solo plataformas con hilos).</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>DBDExptime</name>
<description>Tiempo de keepalive para conexiones inactivas</description>
<syntax>DBDExptime <var>time-in-seconds</var></syntax>
<default>DBDExptime 300</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Establece el tiempo que se mantienen activas las conexiones inactivas
    cuando se ha superado el número de conexiones especificado en DBDKeep
    (solo plataformas con hilos).</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>DBDInitSQL</name>
<description>Ejecuta una sentencia SQL tras conectarse a una base de datos</description>
<syntax>DBDInitSQL <var>"SQL statement"</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Los módulos que lo deseen pueden hacer que se ejecuten una o más
    sentencias SQL al crearse una conexión a una base de datos. Un ejemplo
    de uso sería inicializar ciertos valores o añadir una entrada de registro
    cuando se establece una nueva conexión a la base de datos.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
